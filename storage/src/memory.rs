// fjall-sgx-storage/src/memory.rs
//
// In-memory storage backend.
//
// Keeps all file data in HashMap<FileId, Vec<u8>>. Perfect for:
// - Unit tests (fast, deterministic, no filesystem)
// - SGX simulation (before wiring up real OCALLs)
// - Benchmarking core algorithms without I/O noise
//
// Not suitable for production (data lost on drop, no durability).

use crate::traits::{FileId, StorageError, StorageReader, StorageWriter};
use std::collections::HashMap;

/// State of a file in memory storage.
#[derive(Debug)]
struct MemFile {
    data: Vec<u8>,
    closed: bool,
}

/// In-memory storage backend.
///
/// Files are stored as `Vec<u8>` in a HashMap. FileIds are assigned
/// sequentially starting from 1.
#[derive(Debug)]
pub struct MemoryStorage {
    files: HashMap<FileId, MemFile>,
    next_id: FileId,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            next_id: 1,
        }
    }

    /// Get the number of files currently stored.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get total bytes stored across all files.
    pub fn total_bytes(&self) -> usize {
        self.files.values().map(|f| f.data.len()).sum()
    }

    /// List all FileIds.
    pub fn file_ids(&self) -> Vec<FileId> {
        let mut ids: Vec<_> = self.files.keys().copied().collect();
        ids.sort();
        ids
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageReader for MemoryStorage {
    fn read_at(&self, file_id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        let file = self.files.get(&file_id).ok_or(StorageError::NotFound)?;

        let offset = offset as usize;
        if offset >= file.data.len() {
            return Ok(0); // EOF
        }

        let available = file.data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&file.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn file_size(&self, file_id: FileId) -> Result<u64, StorageError> {
        let file = self.files.get(&file_id).ok_or(StorageError::NotFound)?;
        Ok(file.data.len() as u64)
    }

    fn exists(&self, file_id: FileId) -> bool {
        self.files.contains_key(&file_id)
    }
}

impl StorageWriter for MemoryStorage {
    fn create_file(&mut self) -> Result<FileId, StorageError> {
        let id = self.next_id;
        self.next_id += 1;
        self.files.insert(
            id,
            MemFile {
                data: Vec::new(),
                closed: false,
            },
        );
        Ok(id)
    }

    fn append(&mut self, file_id: FileId, data: &[u8]) -> Result<u64, StorageError> {
        let file = self.files.get_mut(&file_id).ok_or(StorageError::NotFound)?;
        if file.closed {
            return Err(StorageError::Io("file is closed".into()));
        }
        let offset = file.data.len() as u64;
        file.data.extend_from_slice(data);
        Ok(offset)
    }

    fn sync(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // No-op for in-memory storage — data is always "durable"
        if !self.files.contains_key(&file_id) {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    fn close_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        let file = self.files.get_mut(&file_id).ok_or(StorageError::NotFound)?;
        file.closed = true;
        Ok(())
    }

    fn delete_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        self.files.remove(&file_id).ok_or(StorageError::NotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_write() {
        let mut storage = MemoryStorage::new();
        let id = storage.create_file().unwrap();

        assert_eq!(storage.file_count(), 1);
        assert_eq!(storage.file_size(id).unwrap(), 0);

        let offset = storage.append(id, b"hello").unwrap();
        assert_eq!(offset, 0);

        let offset = storage.append(id, b" world").unwrap();
        assert_eq!(offset, 5);

        assert_eq!(storage.file_size(id).unwrap(), 11);
    }

    #[test]
    fn test_read_at() {
        let mut storage = MemoryStorage::new();
        let id = storage.create_file().unwrap();
        storage.append(id, b"hello world").unwrap();

        // Read from start
        let mut buf = [0u8; 5];
        let n = storage.read_at(id, 0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        // Read from offset
        let n = storage.read_at(id, 6, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"world");

        // Read past end — partial
        let mut big_buf = [0u8; 100];
        let n = storage.read_at(id, 6, &mut big_buf).unwrap();
        assert_eq!(n, 5);

        // Read at exactly EOF
        let n = storage.read_at(id, 11, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_read_all() {
        let mut storage = MemoryStorage::new();
        let id = storage.create_file().unwrap();
        storage.append(id, b"the quick brown fox").unwrap();

        let data = storage.read_all(id).unwrap();
        assert_eq!(data, b"the quick brown fox");
    }

    #[test]
    fn test_not_found() {
        let storage = MemoryStorage::new();
        assert_eq!(storage.file_size(999), Err(StorageError::NotFound));
        assert!(!storage.exists(999));
    }

    #[test]
    fn test_close_prevents_append() {
        let mut storage = MemoryStorage::new();
        let id = storage.create_file().unwrap();
        storage.append(id, b"data").unwrap();
        storage.close_file(id).unwrap();

        // Append after close should fail
        assert!(storage.append(id, b"more").is_err());

        // Read should still work
        let data = storage.read_all(id).unwrap();
        assert_eq!(data, b"data");
    }

    #[test]
    fn test_delete() {
        let mut storage = MemoryStorage::new();
        let id = storage.create_file().unwrap();
        storage.append(id, b"data").unwrap();

        assert!(storage.exists(id));
        storage.delete_file(id).unwrap();
        assert!(!storage.exists(id));

        // Double delete fails
        assert_eq!(storage.delete_file(id), Err(StorageError::NotFound));
    }

    #[test]
    fn test_multiple_files() {
        let mut storage = MemoryStorage::new();
        let id1 = storage.create_file().unwrap();
        let id2 = storage.create_file().unwrap();
        let id3 = storage.create_file().unwrap();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);

        storage.append(id1, b"file one").unwrap();
        storage.append(id2, b"file two").unwrap();
        storage.append(id3, b"file three").unwrap();

        assert_eq!(storage.read_all(id1).unwrap(), b"file one");
        assert_eq!(storage.read_all(id2).unwrap(), b"file two");
        assert_eq!(storage.read_all(id3).unwrap(), b"file three");

        assert_eq!(storage.file_count(), 3);
        assert_eq!(storage.total_bytes(), 8 + 8 + 10);
    }

    #[test]
    fn test_sequential_ids() {
        let mut storage = MemoryStorage::new();
        let id1 = storage.create_file().unwrap();
        let id2 = storage.create_file().unwrap();
        let id3 = storage.create_file().unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }
}
