// lsm-sgx/src/bloom.rs
//
// Bloom filter for probabilistic key existence checks.
//
// Each SSTable gets a bloom filter built from its keys. Before doing
// an expensive block read + binary search, we check the bloom filter.
// If it says "definitely not here," we skip the entire SSTable.
//
// False positives are possible (filter says "maybe" but key isn't there).
// False negatives are NOT possible (if key exists, filter always says "maybe").
//
// Default: ~10 bits per key → ~1% false positive rate.
// This matches what Fjall and RocksDB use by default.

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Default bits per key. 10 bits ≈ 1% FPR.
pub const DEFAULT_BITS_PER_KEY: usize = 10;

/// Number of hash functions. For 10 bits/key, optimal k ≈ 6.93 → 7.
/// Formula: k = (m/n) * ln(2), where m/n = bits_per_key.
const NUM_HASHES: u32 = 7;

/// A simple bloom filter.
///
/// Uses double hashing: h(i) = h1 + i * h2
/// where h1 and h2 are derived from a single hash of the key.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    /// The bit array, stored as bytes
    bits: Vec<u8>,

    /// Number of bits in the filter
    num_bits: usize,
}

impl BloomFilter {
    /// Create a bloom filter sized for the given number of keys.
    pub fn with_capacity(num_keys: usize, bits_per_key: usize) -> Self {
        // Minimum 64 bits to avoid degenerate cases
        let num_bits = core::cmp::max(num_keys * bits_per_key, 64);
        let num_bytes = (num_bits + 7) / 8;

        Self {
            bits: vec![0u8; num_bytes],
            num_bits,
        }
    }

    /// Create a bloom filter from existing serialized data.
    pub fn from_bytes(bits: Vec<u8>) -> Self {
        let num_bits = bits.len() * 8;
        Self { bits, num_bits }
    }

    /// Insert a key into the bloom filter.
    pub fn insert(&mut self, key: &[u8]) {
        let (h1, h2) = self.hash_pair(key);

        for i in 0..NUM_HASHES {
            let bit_pos = self.bit_index(h1, h2, i);
            self.set_bit(bit_pos);
        }
    }

    /// Check if a key might exist in the set.
    ///
    /// Returns:
    /// - `true` → key MIGHT exist (could be false positive)
    /// - `false` → key DEFINITELY does not exist
    pub fn may_contain(&self, key: &[u8]) -> bool {
        let (h1, h2) = self.hash_pair(key);

        for i in 0..NUM_HASHES {
            let bit_pos = self.bit_index(h1, h2, i);
            if !self.get_bit(bit_pos) {
                return false;
            }
        }

        true
    }

    /// Serialize the bloom filter to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Returns the size in bytes of the filter data.
    pub fn size_in_bytes(&self) -> usize {
        self.bits.len()
    }

    // ─── Internal ────────────────────────────────────────────

    /// Compute two independent hash values from a key.
    /// Uses a simple FNV-1a variant for h1 and a rotated variant for h2.
    fn hash_pair(&self, key: &[u8]) -> (u64, u64) {
        // FNV-1a hash for h1
        let mut h1: u64 = 0xcbf29ce484222325;
        for &b in key {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        }

        // Different seed for h2
        let mut h2: u64 = 0x517cc1b727220a95;
        for &b in key {
            h2 = h2.wrapping_mul(0x2127599bf4325c37);
            h2 ^= b as u64;
        }

        (h1, h2)
    }

    /// Compute the bit index for the i-th hash function using double hashing.
    fn bit_index(&self, h1: u64, h2: u64, i: u32) -> usize {
        let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (combined % self.num_bits as u64) as usize
    }

    fn set_bit(&mut self, pos: usize) {
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        self.bits[byte_idx] |= 1 << bit_idx;
    }

    fn get_bit(&self, pos: usize) -> bool {
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        (self.bits[byte_idx] >> bit_idx) & 1 == 1
    }
}

/// Builder that constructs a bloom filter from a stream of keys.
pub struct BloomFilterBuilder {
    keys: Vec<Vec<u8>>,
    bits_per_key: usize,
}

impl BloomFilterBuilder {
    pub fn new(bits_per_key: usize) -> Self {
        Self {
            keys: Vec::new(),
            bits_per_key,
        }
    }

    /// Add a key to be included in the filter.
    pub fn add_key(&mut self, key: &[u8]) {
        self.keys.push(key.to_vec());
    }

    /// Build the bloom filter from all added keys.
    pub fn build(self) -> BloomFilter {
        let mut filter = BloomFilter::with_capacity(self.keys.len(), self.bits_per_key);
        for key in &self.keys {
            filter.insert(key);
        }
        filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_no_false_negatives() {
        let mut filter = BloomFilter::with_capacity(1000, DEFAULT_BITS_PER_KEY);

        // Insert 1000 keys
        for i in 0..1000u32 {
            let key = format!("key_{:06}", i);
            filter.insert(key.as_bytes());
        }

        // ALL inserted keys must be found (no false negatives)
        for i in 0..1000u32 {
            let key = format!("key_{:06}", i);
            assert!(
                filter.may_contain(key.as_bytes()),
                "false negative for {}",
                key
            );
        }
    }

    #[test]
    fn test_bloom_false_positive_rate() {
        let num_keys = 10_000;
        let mut filter = BloomFilter::with_capacity(num_keys, DEFAULT_BITS_PER_KEY);

        // Insert keys
        for i in 0..num_keys as u32 {
            let key = format!("exist_{:08}", i);
            filter.insert(key.as_bytes());
        }

        // Test with keys that were NOT inserted
        let mut false_positives = 0;
        let test_count = 10_000;

        for i in 0..test_count as u32 {
            let key = format!("noexist_{:08}", i);
            if filter.may_contain(key.as_bytes()) {
                false_positives += 1;
            }
        }

        let fpr = false_positives as f64 / test_count as f64;
        // With 10 bits/key, FPR should be around 1%
        // Allow up to 3% to account for hash quality variance
        assert!(
            fpr < 0.03,
            "false positive rate too high: {:.2}%",
            fpr * 100.0
        );
    }

    #[test]
    fn test_bloom_empty_filter() {
        let filter = BloomFilter::with_capacity(100, DEFAULT_BITS_PER_KEY);
        assert!(!filter.may_contain(b"anything"));
    }

    #[test]
    fn test_bloom_serialization_roundtrip() {
        let mut filter = BloomFilter::with_capacity(100, DEFAULT_BITS_PER_KEY);
        filter.insert(b"hello");
        filter.insert(b"world");

        let bytes = filter.to_bytes().to_vec();
        let restored = BloomFilter::from_bytes(bytes);

        assert!(restored.may_contain(b"hello"));
        assert!(restored.may_contain(b"world"));
        assert!(!restored.may_contain(b"missing"));
    }

    #[test]
    fn test_bloom_builder() {
        let mut builder = BloomFilterBuilder::new(DEFAULT_BITS_PER_KEY);
        builder.add_key(b"apple");
        builder.add_key(b"banana");
        builder.add_key(b"cherry");

        let filter = builder.build();
        assert!(filter.may_contain(b"apple"));
        assert!(filter.may_contain(b"banana"));
        assert!(filter.may_contain(b"cherry"));
    }
}
