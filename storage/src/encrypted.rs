// fjall-sgx-storage/src/encrypted.rs
//
// Encrypted storage wrapper.
//
// This wraps any storage backend (MemoryStorage, StdStorage, or a future
// OCALL-based backend) and adds transparent encryption/decryption.
//
// Architecture:
//
//   Engine (enclave, plaintext)
//       │
//       ▼
//   EncryptedStorage   ← encrypt on write, decrypt on read
//       │
//       ▼
//   Inner Storage      ← MemoryStorage / StdStorage / OcallStorage
//       │
//       ▼
//   Disk (ciphertext)
//
// The engine sees only plaintext. The inner storage sees only ciphertext.
// This is the trust boundary in the SGX model.
//
// File-level encryption strategy:
//   - Entire files are encrypted as a single blob
//   - On write: accumulate plaintext → encrypt entire blob at close_file()
//   - On read:  load entire ciphertext → decrypt → serve reads from plaintext
//   - This matches our current whole-file I/O pattern (read_all / write all at once)
//
// Future optimization: block-level encryption
//   - Encrypt each SSTable block independently
//   - Enables random-access reads without decrypting the whole file
//   - Nonce = derive(key, file_id, block_offset)
//   - Not needed yet since we always read_all() anyway

use std::collections::HashMap;

use crate::crypto::{self, CryptoError, EncryptionKey};
use crate::traits::{FileId, StorageError, StorageReader, StorageWriter};

// ─── Error conversion ───────────────────────────────────────────

impl From<CryptoError> for StorageError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::InvalidCiphertext => StorageError::Io("invalid ciphertext".to_string()),
            CryptoError::AuthenticationFailed => {
                StorageError::Io("authentication failed: data may be tampered".to_string())
            }
            CryptoError::InvalidKey => StorageError::Io("invalid encryption key".to_string()),
        }
    }
}

// ─── Encrypted Storage ──────────────────────────────────────────

/// Plaintext buffer for files being written (before encryption + flush).
struct PlaintextBuffer {
    data: Vec<u8>,
}

/// Cached decrypted file content (avoids re-decryption on repeated reads).
struct DecryptedCache {
    plaintext: Vec<u8>,
}

/// Storage wrapper that encrypts all data transparently.
///
/// `S` is the inner (untrusted) storage backend.
///
/// Usage:
/// ```ignore
/// let inner = MemoryStorage::new();
/// let key = EncryptionKey::test_key();
/// let mut storage = EncryptedStorage::new(inner, key);
///
/// // All writes are encrypted before reaching inner storage
/// let fid = storage.create_file()?;
/// storage.append(fid, b"secret data")?;
/// storage.sync(fid)?;
/// storage.close_file(fid)?;
///
/// // All reads are decrypted transparently
/// let data = storage.read_all(fid)?;
/// assert_eq!(data, b"secret data");
/// ```
pub struct EncryptedStorage<S> {
    /// The inner (untrusted) storage backend
    inner: S,

    /// Encryption key (lives only in enclave memory)
    key: EncryptionKey,

    /// Plaintext write buffers for open files.
    /// Data accumulates here until close_file() encrypts and flushes.
    write_buffers: HashMap<FileId, PlaintextBuffer>,

    /// Cache of decrypted file contents.
    /// Populated on first read, invalidated on delete.
    read_cache: HashMap<FileId, DecryptedCache>,
}

impl<S> EncryptedStorage<S> {
    /// Create a new encrypted storage wrapping the given inner backend.
    pub fn new(inner: S, key: EncryptionKey) -> Self {
        Self {
            inner,
            key,
            write_buffers: HashMap::new(),
            read_cache: HashMap::new(),
        }
    }

    /// Get a reference to the inner storage (for inspection/testing).
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner storage.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

// ─── StorageWriter ──────────────────────────────────────────────

impl<S: StorageWriter> StorageWriter for EncryptedStorage<S> {
    fn create_file(&mut self) -> Result<FileId, StorageError> {
        let file_id = self.inner.create_file()?;
        self.write_buffers
            .insert(file_id, PlaintextBuffer { data: Vec::new() });
        Ok(file_id)
    }

    fn append(&mut self, file_id: FileId, data: &[u8]) -> Result<u64, StorageError> {
        let buf = self
            .write_buffers
            .get_mut(&file_id)
            .ok_or(StorageError::NotFound)?;

        let offset = buf.data.len() as u64;
        buf.data.extend_from_slice(data);
        Ok(offset)
    }

    fn sync(&mut self, _file_id: FileId) -> Result<(), StorageError> {
        // Sync is deferred until close_file() when we encrypt+write.
        // For the inner storage, we'll sync after writing the ciphertext.
        Ok(())
    }

    fn close_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // Remove the write buffer, encrypt, and write to inner storage
        let buf = self
            .write_buffers
            .remove(&file_id)
            .ok_or(StorageError::NotFound)?;

        // Encrypt the entire plaintext blob
        // Nonce derived from (file_id, offset=0) since it's whole-file encryption
        let ciphertext = crypto::encrypt(&self.key, file_id, 0, &buf.data)?;

        // Write encrypted data to inner storage
        self.inner.append(file_id, &ciphertext)?;
        self.inner.sync(file_id)?;
        self.inner.close_file(file_id)?;

        Ok(())
    }

    fn delete_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // Remove from write buffer (if still open)
        self.write_buffers.remove(&file_id);
        // Remove from read cache
        self.read_cache.remove(&file_id);
        // Delete from inner storage
        self.inner.delete_file(file_id)
    }
}

// ─── StorageReader ──────────────────────────────────────────────

impl<S: StorageReader + StorageWriter> StorageReader for EncryptedStorage<S> {
    fn read_at(&self, file_id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        // Check write buffer first (for files still being written)
        if let Some(wb) = self.write_buffers.get(&file_id) {
            let offset = offset as usize;
            if offset >= wb.data.len() {
                return Ok(0);
            }
            let available = wb.data.len() - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&wb.data[offset..offset + to_read]);
            return Ok(to_read);
        }

        // Check read cache
        if let Some(cached) = self.read_cache.get(&file_id) {
            let offset = offset as usize;
            if offset >= cached.plaintext.len() {
                return Ok(0);
            }
            let available = cached.plaintext.len() - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&cached.plaintext[offset..offset + to_read]);
            return Ok(to_read);
        }

        // Load from inner storage, decrypt, and cache
        // We need to use read_all on inner to get the ciphertext, then decrypt
        let ciphertext = self.inner.read_all(file_id)?;
        let plaintext = crypto::decrypt(&self.key, file_id, 0, &ciphertext)?;

        let offset = offset as usize;
        if offset >= plaintext.len() {
            // Still cache it for future reads
            // Note: can't mutate self in &self method without interior mutability
            // For now, skip caching in read_at and rely on read_all caching
            return Ok(0);
        }
        let available = plaintext.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&plaintext[offset..offset + to_read]);
        Ok(to_read)
    }

    fn file_size(&self, file_id: FileId) -> Result<u64, StorageError> {
        // Check write buffer first
        if let Some(wb) = self.write_buffers.get(&file_id) {
            return Ok(wb.data.len() as u64);
        }

        // Check read cache
        if let Some(cached) = self.read_cache.get(&file_id) {
            return Ok(cached.plaintext.len() as u64);
        }

        // Must read from inner and decrypt to know plaintext size
        let ciphertext = self.inner.read_all(file_id)?;
        let plaintext = crypto::decrypt(&self.key, file_id, 0, &ciphertext)?;
        Ok(plaintext.len() as u64)
    }

    fn read_all(&self, file_id: FileId) -> Result<Vec<u8>, StorageError> {
        // Check write buffer first
        if let Some(wb) = self.write_buffers.get(&file_id) {
            return Ok(wb.data.clone());
        }

        // Check read cache
        if let Some(cached) = self.read_cache.get(&file_id) {
            return Ok(cached.plaintext.clone());
        }

        // Load from inner storage and decrypt
        let ciphertext = self.inner.read_all(file_id)?;
        let plaintext = crypto::decrypt(&self.key, file_id, 0, &ciphertext)?;

        Ok(plaintext)
    }

    fn exists(&self, file_id: FileId) -> bool {
        self.write_buffers.contains_key(&file_id) || self.inner.exists(file_id)
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;

    fn test_storage() -> EncryptedStorage<MemoryStorage> {
        EncryptedStorage::new(MemoryStorage::new(), EncryptionKey::test_key())
    }

    // ── Basic CRUD ──

    #[test]
    fn test_write_and_read() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"hello world").unwrap();
        storage.sync(fid).unwrap();
        storage.close_file(fid).unwrap();

        let data = storage.read_all(fid).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_inner_storage_sees_ciphertext() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"secret data").unwrap();
        storage.close_file(fid).unwrap();

        // Read raw from inner storage — should be ciphertext, not plaintext
        let raw = storage.inner().read_all(fid).unwrap();
        assert_ne!(raw, b"secret data");
        assert!(raw.len() > b"secret data".len()); // overhead from nonce + tag

        // But EncryptedStorage decrypts transparently
        let plain = storage.read_all(fid).unwrap();
        assert_eq!(plain, b"secret data");
    }

    #[test]
    fn test_multiple_appends() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"part1_").unwrap();
        storage.append(fid, b"part2_").unwrap();
        storage.append(fid, b"part3").unwrap();
        storage.close_file(fid).unwrap();

        let data = storage.read_all(fid).unwrap();
        assert_eq!(data, b"part1_part2_part3");
    }

    #[test]
    fn test_multiple_files() {
        let mut storage = test_storage();

        let fid1 = storage.create_file().unwrap();
        storage.append(fid1, b"file one").unwrap();
        storage.close_file(fid1).unwrap();

        let fid2 = storage.create_file().unwrap();
        storage.append(fid2, b"file two").unwrap();
        storage.close_file(fid2).unwrap();

        assert_eq!(storage.read_all(fid1).unwrap(), b"file one");
        assert_eq!(storage.read_all(fid2).unwrap(), b"file two");
    }

    #[test]
    fn test_read_at() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"0123456789").unwrap();
        storage.close_file(fid).unwrap();

        let mut buf = [0u8; 3];
        let n = storage.read_at(fid, 5, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"567");
    }

    #[test]
    fn test_file_size() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"twelve chars").unwrap();
        storage.close_file(fid).unwrap();

        assert_eq!(storage.file_size(fid).unwrap(), 12);
    }

    #[test]
    fn test_delete_file() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"data").unwrap();
        storage.close_file(fid).unwrap();

        assert!(storage.exists(fid));
        storage.delete_file(fid).unwrap();
        assert!(!storage.exists(fid));
    }

    #[test]
    fn test_read_while_writing() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"buffered").unwrap();

        // Should be able to read from the write buffer before close
        let data = storage.read_all(fid).unwrap();
        assert_eq!(data, b"buffered");

        storage.close_file(fid).unwrap();

        // After close, should read from decrypted inner storage
        let data = storage.read_all(fid).unwrap();
        assert_eq!(data, b"buffered");
    }

    #[test]
    fn test_empty_file() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.close_file(fid).unwrap();

        let data = storage.read_all(fid).unwrap();
        assert!(data.is_empty());
        assert_eq!(storage.file_size(fid).unwrap(), 0);
    }

    #[test]
    fn test_large_file() {
        let mut storage = test_storage();

        let big_data = vec![0xABu8; 256 * 1024]; // 256 KB
        let fid = storage.create_file().unwrap();
        storage.append(fid, &big_data).unwrap();
        storage.close_file(fid).unwrap();

        let result = storage.read_all(fid).unwrap();
        assert_eq!(result, big_data);
    }

    // ── Tamper detection ──

    #[test]
    fn test_tampered_inner_data_detected() {
        let mut storage = test_storage();

        let fid = storage.create_file().unwrap();
        storage.append(fid, b"important data").unwrap();
        storage.close_file(fid).unwrap();

        // Tamper with the ciphertext in inner storage
        // Access the inner MemoryStorage and corrupt a byte
        let mut raw = storage.inner().read_all(fid).unwrap();
        if raw.len() > 15 {
            raw[15] ^= 0xFF; // flip a bit
        }

        // Create a new encrypted storage with tampered inner data
        let key = EncryptionKey::test_key();
        let mut inner = MemoryStorage::new();
        // Write the tampered data as a new file (reuse same FileId concept)
        let tampered_fid = inner.create_file().unwrap();
        inner.append(tampered_fid, &raw).unwrap();
        inner.close_file(tampered_fid).unwrap();

        let tampered_storage = EncryptedStorage::new(inner, key);

        let result = tampered_storage.read_all(tampered_fid);
        assert!(result.is_err());
    }

    // ── Integration with engine patterns ──

    #[test]
    fn test_sstable_roundtrip_pattern() {
        // Simulates the sst_file::write_sstable / query_sstable pattern
        let mut storage = test_storage();

        // Simulate SSTable write (what write_sstable does)
        let fake_sst_bytes = b"[data blocks][index][bloom][trailer]".to_vec();
        let fid = storage.create_file().unwrap();
        storage.append(fid, &fake_sst_bytes).unwrap();
        storage.sync(fid).unwrap();
        storage.close_file(fid).unwrap();

        // Simulate SSTable read (what query_sstable does)
        let loaded = storage.read_all(fid).unwrap();
        assert_eq!(loaded, fake_sst_bytes);

        // File size should match plaintext size
        assert_eq!(storage.file_size(fid).unwrap(), fake_sst_bytes.len() as u64);
    }

    #[test]
    fn test_different_keys_cant_read() {
        let key1 = EncryptionKey::test_key();
        let mut key2_bytes = [0xFFu8; 32];
        key2_bytes[0] = 0x00;
        let key2 = EncryptionKey::from_bytes(key2_bytes);

        // Write with key1
        let mut s1 = EncryptedStorage::new(MemoryStorage::new(), key1);
        let fid = s1.create_file().unwrap();
        s1.append(fid, b"secret").unwrap();
        s1.close_file(fid).unwrap();

        // Get the raw ciphertext
        let raw = s1.inner().read_all(fid).unwrap();

        // Try to read with key2
        let mut inner2 = MemoryStorage::new();
        let fid2 = inner2.create_file().unwrap();
        inner2.append(fid2, &raw).unwrap();
        inner2.close_file(fid2).unwrap();

        let s2 = EncryptedStorage::new(inner2, key2);
        let result = s2.read_all(fid2);
        assert!(result.is_err());
    }
}
