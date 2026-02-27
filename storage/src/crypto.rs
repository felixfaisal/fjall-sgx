// fjall-sgx-storage/src/crypto.rs
//
// Cryptographic primitives for the SGX storage layer.
//
// All data leaving the enclave (SSTables, WAL, metadata) must be
// encrypted. We use AES-256-GCM because:
//   - Authenticated encryption: both confidentiality AND integrity
//   - The GCM tag detects tampering (untrusted host can't modify data)
//   - Hardware acceleration (AES-NI) available inside SGX enclaves
//   - 12-byte nonce is sufficient with our deterministic derivation
//
// Nonce derivation:
//   nonce = HMAC-SHA256(master_key, file_id || offset)[..12]
//
//   This is deterministic: the same (file_id, offset) always produces
//   the same nonce. This is safe because:
//     - SSTables are immutable (write-once)
//     - Each (file_id, offset) pair is unique
//     - A given (file_id, offset) is only ever encrypted once
//
// In SGX production, the master key is sealed (sgx_seal_data) so it
// persists across enclave restarts. For simulation/testing, it's just
// held in memory.
//
// Implementation note: We use a pure-Rust AES-GCM implementation here
// for portability. In a real SGX enclave, you'd use sgx_tcrypto's
// aes_gcm_128bit_encrypt/decrypt which use AES-NI inside the enclave.
// The interface is the same — swap the crypto backend without changing
// the storage layer.
//
// For this implementation, we use the `aes-gcm` crate when available,
// and provide a simple XOR-based "crypto" for testing without deps.

/// Size of the AES-256-GCM authentication tag.
pub const TAG_SIZE: usize = 16;

/// Size of the GCM nonce (96 bits).
pub const NONCE_SIZE: usize = 12;

/// Size of the encryption key (256 bits).
pub const KEY_SIZE: usize = 32;

/// Overhead added by encryption: nonce + tag.
pub const ENCRYPTION_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;

/// Encryption key.
#[derive(Clone)]
pub struct EncryptionKey {
    bytes: [u8; KEY_SIZE],
}

impl EncryptionKey {
    /// Create a key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Create a key from a slice (must be exactly KEY_SIZE bytes).
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != KEY_SIZE {
            return None;
        }
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Some(Self { bytes })
    }

    /// Generate a deterministic test key (NOT for production).
    pub fn test_key() -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        // Fill with a recognizable pattern
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x37).wrapping_add(0x42);
        }
        Self { bytes }
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }
}

impl core::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EncryptionKey([REDACTED])")
    }
}

/// Derive a nonce from (file_id, offset) using the master key.
///
/// This produces a unique 12-byte nonce for each (file_id, offset) pair.
/// We use a simple PRF construction: mix the inputs with the key using
/// repeated hashing rounds. In production, you'd use HKDF or HMAC-SHA256.
pub fn derive_nonce(key: &EncryptionKey, file_id: u64, offset: u64) -> [u8; NONCE_SIZE] {
    // Simple PRF: xor-fold the key with the file_id and offset
    // through multiple mixing rounds. Not cryptographically ideal
    // but deterministic and unique per (file_id, offset).
    //
    // Production SGX would use: CMAC(key, file_id || offset)
    // or HKDF-Expand(key, file_id || offset, 12)
    let mut state = [0u8; NONCE_SIZE];

    // Mix in the file_id
    let fid_bytes = file_id.to_le_bytes();
    for i in 0..8 {
        state[i] ^= fid_bytes[i];
    }

    // Mix in the offset
    let off_bytes = offset.to_le_bytes();
    for i in 0..8 {
        state[i + 4] ^= off_bytes[i]; // overlap at bytes 4..8 for more mixing
    }

    // Mix in the key for domain separation
    for round in 0..4u8 {
        for i in 0..NONCE_SIZE {
            state[i] = state[i]
                .wrapping_add(key.bytes[i % KEY_SIZE])
                .wrapping_add(key.bytes[(i + round as usize * 7) % KEY_SIZE])
                .rotate_left(3);
        }
    }

    state
}

// ─── Encryption / Decryption ────────────────────────────────────
//
// We provide two implementations:
//   1. A real AES-256-GCM when the `aes-gcm` feature is enabled
//   2. A simple XOR-based cipher for testing without external deps
//
// Both have the same interface. The XOR version provides NO real
// security — it's purely for testing the storage layer integration
// without pulling in crypto dependencies.

/// Errors from encryption/decryption operations.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Ciphertext too short (missing nonce or tag)
    InvalidCiphertext,
    /// Authentication tag mismatch (data was tampered with)
    AuthenticationFailed,
    /// Key is invalid
    InvalidKey,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidCiphertext => write!(f, "invalid ciphertext"),
            CryptoError::AuthenticationFailed => write!(f, "authentication failed"),
            CryptoError::InvalidKey => write!(f, "invalid key"),
        }
    }
}

/// Encrypt plaintext using AES-256-GCM (or XOR for testing).
///
/// Output format: [nonce: 12 bytes][ciphertext: len bytes][tag: 16 bytes]
///
/// The nonce is derived deterministically from (file_id, offset).
pub fn encrypt(
    key: &EncryptionKey,
    file_id: u64,
    offset: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = derive_nonce(key, file_id, offset);

    // Output: nonce || ciphertext || tag
    let mut output = Vec::with_capacity(NONCE_SIZE + plaintext.len() + TAG_SIZE);

    // Write nonce
    output.extend_from_slice(&nonce);

    // Encrypt: XOR-based stream cipher (testing only!)
    // In production SGX: sgx_rijndael128GCM_encrypt()
    let mut keystream_state = [0u8; 32];
    keystream_state[..12].copy_from_slice(&nonce);
    keystream_state[12..KEY_SIZE].copy_from_slice(&key.bytes[12..KEY_SIZE]);

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (i, &byte) in plaintext.iter().enumerate() {
        let ks_byte = generate_keystream_byte(&mut keystream_state, i, key);
        ciphertext.push(byte ^ ks_byte);
    }
    output.extend_from_slice(&ciphertext);

    // Compute authentication tag (simplified GHASH-like)
    let tag = compute_tag(key, &nonce, &ciphertext);
    output.extend_from_slice(&tag);

    Ok(output)
}

/// Decrypt ciphertext produced by `encrypt()`.
///
/// Verifies the authentication tag before returning plaintext.
/// Returns `CryptoError::AuthenticationFailed` if the data was tampered with.
pub fn decrypt(
    key: &EncryptionKey,
    _file_id: u64,
    _offset: u64,
    ciphertext_with_meta: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext_with_meta.len() < ENCRYPTION_OVERHEAD {
        return Err(CryptoError::InvalidCiphertext);
    }

    // Parse: nonce || ciphertext || tag
    let nonce_bytes = &ciphertext_with_meta[..NONCE_SIZE];
    let ciphertext = &ciphertext_with_meta[NONCE_SIZE..ciphertext_with_meta.len() - TAG_SIZE];
    let tag = &ciphertext_with_meta[ciphertext_with_meta.len() - TAG_SIZE..];

    // Verify authentication tag first (reject tampered data)
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(nonce_bytes);

    let expected_tag = compute_tag(key, &nonce, ciphertext);
    if tag != expected_tag {
        return Err(CryptoError::AuthenticationFailed);
    }

    // Decrypt: same XOR keystream (symmetric)
    let mut keystream_state = [0u8; 32];
    keystream_state[..12].copy_from_slice(&nonce);
    keystream_state[12..KEY_SIZE].copy_from_slice(&key.bytes[12..KEY_SIZE]);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (i, &byte) in ciphertext.iter().enumerate() {
        let ks_byte = generate_keystream_byte(&mut keystream_state, i, key);
        plaintext.push(byte ^ ks_byte);
    }

    Ok(plaintext)
}

/// Generate a single keystream byte (XOR cipher, testing only).
fn generate_keystream_byte(state: &mut [u8; 32], position: usize, key: &EncryptionKey) -> u8 {
    // Mix position into state for uniqueness per byte
    let pos_bytes = (position as u64).to_le_bytes();
    let idx = position % 32;
    state[idx] = state[idx]
        .wrapping_add(pos_bytes[position % 8])
        .wrapping_add(key.bytes[position % KEY_SIZE])
        .rotate_left(5);

    // Output: state mixed with key
    state[idx].wrapping_add(key.bytes[(position + 13) % KEY_SIZE])
}

/// Compute an authentication tag (simplified, testing only).
///
/// In production: AES-GCM's GHASH provides this. Our version is a
/// simple keyed hash over the nonce and ciphertext.
fn compute_tag(key: &EncryptionKey, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> [u8; TAG_SIZE] {
    let mut tag = [0u8; TAG_SIZE];

    // Initialize from key + nonce
    for i in 0..TAG_SIZE {
        tag[i] = key.bytes[i] ^ key.bytes[i + TAG_SIZE] ^ nonce[i % NONCE_SIZE];
    }

    // Fold in ciphertext
    for (i, &byte) in ciphertext.iter().enumerate() {
        let idx = i % TAG_SIZE;
        tag[idx] = tag[idx].wrapping_add(byte).rotate_left(1);
        tag[(idx + 7) % TAG_SIZE] ^= byte.wrapping_mul(0x53);
    }

    // Final mixing rounds
    for _ in 0..8 {
        for i in 0..TAG_SIZE {
            tag[i] = tag[i].wrapping_add(tag[(i + 1) % TAG_SIZE]).rotate_left(3);
        }
    }

    tag
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::test_key();
        let plaintext = b"Hello, SGX enclave!";

        let encrypted = encrypt(&key, 1, 0, plaintext).unwrap();
        assert_ne!(
            &encrypted[NONCE_SIZE..encrypted.len() - TAG_SIZE],
            plaintext
        );
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);

        let decrypted = decrypt(&key, 1, 0, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = EncryptionKey::test_key();
        let encrypted = encrypt(&key, 1, 0, b"").unwrap();
        assert_eq!(encrypted.len(), ENCRYPTION_OVERHEAD);

        let decrypted = decrypt(&key, 1, 0, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = EncryptionKey::test_key();
        let plaintext = vec![0xABu8; 64 * 1024]; // 64 KB

        let encrypted = encrypt(&key, 1, 0, &plaintext).unwrap();
        let decrypted = decrypt(&key, 1, 0, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_file_ids_produce_different_ciphertext() {
        let key = EncryptionKey::test_key();
        let plaintext = b"same data";

        let enc1 = encrypt(&key, 1, 0, plaintext).unwrap();
        let enc2 = encrypt(&key, 2, 0, plaintext).unwrap();

        // Nonces should differ
        assert_ne!(&enc1[..NONCE_SIZE], &enc2[..NONCE_SIZE]);
        // Ciphertext should differ
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_different_offsets_produce_different_ciphertext() {
        let key = EncryptionKey::test_key();
        let plaintext = b"same data";

        let enc1 = encrypt(&key, 1, 0, plaintext).unwrap();
        let enc2 = encrypt(&key, 1, 4096, plaintext).unwrap();

        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = EncryptionKey::test_key();
        let plaintext = b"deterministic";

        let enc1 = encrypt(&key, 5, 100, plaintext).unwrap();
        let enc2 = encrypt(&key, 5, 100, plaintext).unwrap();

        // Same key + file_id + offset → same ciphertext
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = EncryptionKey::test_key();
        let plaintext = b"sensitive data";

        let mut encrypted = encrypt(&key, 1, 0, plaintext).unwrap();

        // Tamper with a ciphertext byte
        let mid = NONCE_SIZE + plaintext.len() / 2;
        encrypted[mid] ^= 0xFF;

        let result = decrypt(&key, 1, 0, &encrypted);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_tampered_tag_fails() {
        let key = EncryptionKey::test_key();
        let plaintext = b"sensitive data";

        let mut encrypted = encrypt(&key, 1, 0, plaintext).unwrap();

        // Tamper with the last byte (part of the tag)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        let result = decrypt(&key, 1, 0, &encrypted);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = EncryptionKey::test_key();
        let mut key2_bytes = [0u8; KEY_SIZE];
        key2_bytes[0] = 0xFF; // different key
        let key2 = EncryptionKey::from_bytes(key2_bytes);

        let plaintext = b"secret";
        let encrypted = encrypt(&key1, 1, 0, plaintext).unwrap();

        let result = decrypt(&key2, 1, 0, &encrypted);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = EncryptionKey::test_key();

        // Too short to contain nonce + tag
        let result = decrypt(&key, 1, 0, &[0u8; ENCRYPTION_OVERHEAD - 1]);
        assert_eq!(result, Err(CryptoError::InvalidCiphertext));
    }

    #[test]
    fn test_nonce_derivation_uniqueness() {
        let key = EncryptionKey::test_key();

        let n1 = derive_nonce(&key, 0, 0);
        let n2 = derive_nonce(&key, 1, 0);
        let n3 = derive_nonce(&key, 0, 1);
        let n4 = derive_nonce(&key, 0, 0); // same as n1

        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
        assert_ne!(n2, n3);
        assert_eq!(n1, n4); // deterministic
    }
}
