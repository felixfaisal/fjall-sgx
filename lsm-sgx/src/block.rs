// lsm-sgx/src/block.rs
//
// Block format for SSTable data blocks.
//
// Inspired by Fjall v3's block format: KV pairs packed together with
// restart points for binary search. Simplified from Fjall (no prefix
// truncation, no hash index) but same fundamental structure.
//
// Block layout (serialized):
// ┌──────────────────────────────────────────────────┐
// │ Entry 0 (full key)              ← restart point  │
// │ Entry 1                                          │
// │ ...                                              │
// │ Entry N-1                                        │
// │ Entry N (full key)              ← restart point  │
// │ Entry N+1                                        │
// │ ...                                              │
// ├──────────────────────────────────────────────────┤
// │ Restart offsets: [u32 BE] × num_restarts         │
// │ num_restarts: u32 BE                             │
// │ num_entries: u32 BE                              │
// │ checksum: [u8; 16] (XXH3-128 of everything above)│
// └──────────────────────────────────────────────────┘
//
// Restart points are placed every `restart_interval` entries.
// They store the full key (no prefix truncation in our simplified version).
// This allows binary search: find the restart point whose key <= target,
// then linear scan within that interval.

use crate::types::{InternalEntry, InternalKey};
use std::vec::Vec;

/// Default number of entries between restart points.
/// Fjall v3 uses 16 by default.
pub const DEFAULT_RESTART_INTERVAL: usize = 16;

/// Default target block size in bytes (before adding footer).
/// Fjall uses 4-64 KiB typically, we default to 4 KiB.
pub const DEFAULT_BLOCK_SIZE: usize = 4 * 1024;

// ─── Block Builder ───────────────────────────────────────────────

/// Builds a single data block from sorted InternalEntries.
///
/// Usage:
///   let mut builder = BlockBuilder::new(DEFAULT_RESTART_INTERVAL);
///   builder.add(&entry1);
///   builder.add(&entry2);
///   let block_bytes = builder.finish();
///
/// Entries MUST be added in sorted order (by InternalKey).
pub struct BlockBuilder {
    /// Accumulated block data (entries serialized back-to-back)
    buf: Vec<u8>,

    /// Byte offsets of each restart point in buf
    restart_offsets: Vec<u32>,

    /// How many entries between restart points
    restart_interval: usize,

    /// Number of entries added since last restart point
    entries_since_restart: usize,

    /// Total number of entries in this block
    num_entries: usize,
}

impl BlockBuilder {
    pub fn new(restart_interval: usize) -> Self {
        Self {
            buf: Vec::new(),
            restart_offsets: Vec::new(),
            restart_interval,
            entries_since_restart: restart_interval, // force first entry to be a restart
            num_entries: 0,
        }
    }

    /// Returns the current approximate size of the block in bytes.
    /// Used to decide when to cut a new block.
    pub fn approximate_size(&self) -> usize {
        self.buf.len()
            + (self.restart_offsets.len() * 4) // restart array
            + 4  // num_restarts
            + 4  // num_entries
            + 16 // checksum
    }

    /// Returns true if no entries have been added yet.
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }

    /// Returns the number of entries added.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Add an entry to the block. Entries must be added in sorted order.
    pub fn add(&mut self, entry: &InternalEntry) {
        // Check if this should be a restart point
        if self.entries_since_restart >= self.restart_interval {
            self.restart_offsets.push(self.buf.len() as u32);
            self.entries_since_restart = 0;
        }

        // Serialize the entry into the buffer
        entry.encode(&mut self.buf);
        self.entries_since_restart += 1;
        self.num_entries += 1;
    }

    /// Finalize the block and return the serialized bytes.
    ///
    /// Layout:
    ///   [entries...][restart_offsets...][num_restarts: u32][num_entries: u32][checksum: 16 bytes]
    pub fn finish(self) -> Vec<u8> {
        let mut out = self.buf;

        // Write restart offsets
        for offset in &self.restart_offsets {
            out.extend_from_slice(&offset.to_be_bytes());
        }

        // Write number of restart points
        out.extend_from_slice(&(self.restart_offsets.len() as u32).to_be_bytes());

        // Write number of entries
        out.extend_from_slice(&(self.num_entries as u32).to_be_bytes());

        // Compute and write XXH3-128 checksum over everything so far.
        // For now, we use a simple checksum. In production, use xxhash-rust.
        // We'll use a placeholder that can be swapped for real XXH3 later.
        let checksum = simple_checksum(&out);
        out.extend_from_slice(&checksum);

        out
    }
}

// ─── Block Reader ────────────────────────────────────────────────

/// Reads and searches within a serialized block.
///
/// The block is kept as a single byte slice — no deserialization of
/// all entries upfront (this is the Fjall v3 approach: parse on demand).
#[derive(Debug, PartialEq)]
pub struct BlockReader<'a> {
    /// The raw block data (everything before the checksum)
    data: &'a [u8],

    /// Parsed restart offsets
    restart_offsets: Vec<u32>,

    /// Total number of entries
    num_entries: usize,
}

/// Error type for block operations
#[derive(Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Block data is too small or corrupted
    CorruptedBlock,
    /// Checksum verification failed
    ChecksumMismatch,
}

impl<'a> BlockReader<'a> {
    /// Parse a serialized block. Verifies the checksum.
    pub fn open(raw: &'a [u8]) -> Result<Self, BlockError> {
        // Minimum size: num_restarts(4) + num_entries(4) + checksum(16) = 24
        if raw.len() < 24 {
            return Err(BlockError::CorruptedBlock);
        }

        // Read checksum (last 16 bytes)
        let checksum_start = raw.len() - 16;
        let stored_checksum = &raw[checksum_start..];
        let computed_checksum = simple_checksum(&raw[..checksum_start]);

        if stored_checksum != computed_checksum {
            return Err(BlockError::ChecksumMismatch);
        }

        // Read footer (before checksum)
        let footer_start = checksum_start;
        let num_entries = u32::from_be_bytes([
            raw[footer_start - 4],
            raw[footer_start - 3],
            raw[footer_start - 2],
            raw[footer_start - 1],
        ]) as usize;

        let num_restarts = u32::from_be_bytes([
            raw[footer_start - 8],
            raw[footer_start - 7],
            raw[footer_start - 6],
            raw[footer_start - 5],
        ]) as usize;

        // Read restart offsets
        let restarts_start = footer_start - 8 - (num_restarts * 4);
        let mut restart_offsets = Vec::with_capacity(num_restarts);
        for i in 0..num_restarts {
            let pos = restarts_start + i * 4;
            let offset = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
            restart_offsets.push(offset);
        }

        // The entry data is everything before the restart offsets
        let data = &raw[..restarts_start];

        Ok(Self {
            data,
            restart_offsets,
            num_entries,
        })
    }

    /// Returns the number of entries in this block.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Get all entries in this block (linear scan).
    /// Returns them in sorted order.
    pub fn entries(&self) -> Vec<InternalEntry> {
        let mut result = Vec::with_capacity(self.num_entries);
        let mut offset = 0;

        while offset < self.data.len() {
            if let Some((entry, consumed)) = InternalEntry::decode(&self.data[offset..]) {
                result.push(entry);
                offset += consumed;
            } else {
                break;
            }
        }

        result
    }

    /// Search for a user_key in this block.
    ///
    /// Uses restart points for binary search, then linear scan within
    /// the restart interval. Returns the newest (highest seqno) entry
    /// for the given user_key, or None if not found.
    ///
    /// If `seqno_limit` is provided, only entries with seqno <= limit
    /// are considered (for snapshot reads).
    pub fn get(&self, target_key: &[u8], seqno_limit: Option<u64>) -> Option<InternalEntry> {
        if self.restart_offsets.is_empty() {
            return None;
        }

        // Binary search over restart points to find the right interval.
        // We want the last restart point whose first key <= target_key.
        let restart_idx = self.find_restart_for_key(target_key);

        // Determine scan range
        let scan_start = self.restart_offsets[restart_idx] as usize;
        let scan_end = if restart_idx + 1 < self.restart_offsets.len() {
            self.restart_offsets[restart_idx + 1] as usize
        } else {
            self.data.len()
        };

        // Linear scan within the interval
        let mut offset = scan_start;
        while offset < scan_end {
            if let Some((entry, consumed)) = InternalEntry::decode(&self.data[offset..]) {
                if entry.key.user_key == target_key {
                    // Check seqno limit for snapshot reads
                    if let Some(limit) = seqno_limit {
                        if entry.key.seqno <= limit {
                            return Some(entry);
                        }
                    } else {
                        // No limit: return the newest (first encountered due to sort order)
                        return Some(entry);
                    }
                } else if entry.key.user_key.as_slice() > target_key {
                    // Past our target, stop scanning
                    break;
                }
                offset += consumed;
            } else {
                break;
            }
        }

        None
    }

    /// Binary search restart points to find the interval containing the target key.
    fn find_restart_for_key(&self, target_key: &[u8]) -> usize {
        // We need to find the last restart point where the first entry's
        // user_key <= target_key.
        //
        // partition_point returns the first index where the predicate is false.
        // So we check: "is the first key in this restart interval <= target?"
        let idx = self.restart_offsets.partition_point(|&offset| {
            if let Some((entry, _)) = InternalEntry::decode(&self.data[offset as usize..]) {
                entry.key.user_key.as_slice() <= target_key
            } else {
                false
            }
        });

        // partition_point returns the first index where predicate is false,
        // so the last true index is idx - 1. But clamp to 0.
        if idx == 0 {
            0
        } else {
            idx - 1
        }
    }

    /// Get the first key in this block (useful for block index).
    pub fn first_key(&self) -> Option<InternalKey> {
        InternalEntry::decode(self.data).map(|(e, _)| e.key)
    }

    /// Get the last key in this block (useful for block index).
    pub fn last_key(&self) -> Option<InternalKey> {
        let entries = self.entries();
        entries.last().map(|e| e.key.clone())
    }
}

// ─── Checksum ────────────────────────────────────────────────────

/// Simple 128-bit checksum placeholder.
///
/// In production, replace with XXH3-128 from the xxhash-rust crate.
/// This implementation uses a basic FNV-like hash doubled to 128 bits
/// for development/testing purposes. NOT cryptographically secure,
/// but sufficient for corruption detection.
fn simple_checksum(data: &[u8]) -> [u8; 16] {
    // Simple hash for development — replace with XXH3-128 in production
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x100000001b3;

    for &byte in data {
        h1 ^= byte as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
        h2 ^= byte as u64;
        h2 = h2.wrapping_mul(0xcbf29ce484222325);
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&h1.to_le_bytes());
    out[8..].copy_from_slice(&h2.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InternalEntry;

    fn make_entry(key: &str, seqno: u64, value: &str) -> InternalEntry {
        InternalEntry::put(key.as_bytes().to_vec(), seqno, value.as_bytes().to_vec())
    }

    #[test]
    fn test_block_build_and_read_single_entry() {
        let mut builder = BlockBuilder::new(DEFAULT_RESTART_INTERVAL);
        let entry = make_entry("hello", 1, "world");
        builder.add(&entry);

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();

        assert_eq!(reader.num_entries(), 1);

        let entries = reader.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.user_key, b"hello");
        assert_eq!(entries[0].value, b"world");
    }

    #[test]
    fn test_block_multiple_entries() {
        let mut builder = BlockBuilder::new(4); // restart every 4 entries
        let entries = vec![
            make_entry("aaa", 3, "val_a"),
            make_entry("bbb", 2, "val_b"),
            make_entry("ccc", 1, "val_c"),
            make_entry("ddd", 5, "val_d"),
            make_entry("eee", 4, "val_e"),
            make_entry("fff", 6, "val_f"),
        ];

        for e in &entries {
            builder.add(e);
        }

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();

        assert_eq!(reader.num_entries(), 6);

        let decoded = reader.entries();
        assert_eq!(decoded.len(), 6);

        for (i, e) in entries.iter().enumerate() {
            assert_eq!(decoded[i].key.user_key, e.key.user_key);
            assert_eq!(decoded[i].value, e.value);
        }
    }

    #[test]
    fn test_block_point_lookup() {
        let mut builder = BlockBuilder::new(2); // small interval for more restart points
        let entries = vec![
            make_entry("apple", 1, "red"),
            make_entry("banana", 2, "yellow"),
            make_entry("cherry", 3, "red"),
            make_entry("date", 4, "brown"),
            make_entry("elderberry", 5, "purple"),
            make_entry("fig", 6, "green"),
        ];

        for e in &entries {
            builder.add(e);
        }

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();

        // Find existing keys
        let result = reader.get(b"cherry", None).unwrap();
        assert_eq!(result.value, b"red");
        assert_eq!(result.key.seqno, 3);

        let result = reader.get(b"fig", None).unwrap();
        assert_eq!(result.value, b"green");

        let result = reader.get(b"apple", None).unwrap();
        assert_eq!(result.value, b"red");

        // Key not found
        assert!(reader.get(b"grape", None).is_none());
        assert!(reader.get(b"aaa", None).is_none());
        assert!(reader.get(b"zzz", None).is_none());
    }

    #[test]
    fn test_block_mvcc_multiple_versions() {
        let mut builder = BlockBuilder::new(DEFAULT_RESTART_INTERVAL);

        // Same key, multiple versions (must be added in InternalKey sort order)
        // Sort order: (user_key ASC, seqno DESC) → seqno 10 before seqno 5 before seqno 1
        let entries = vec![
            make_entry("key1", 10, "newest"),
            make_entry("key1", 5, "middle"),
            make_entry("key1", 1, "oldest"),
        ];

        for e in &entries {
            builder.add(e);
        }

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();

        // Without seqno limit: get the newest
        let result = reader.get(b"key1", None).unwrap();
        assert_eq!(result.value, b"newest");
        assert_eq!(result.key.seqno, 10);

        // With seqno limit: snapshot read at seqno 7
        let result = reader.get(b"key1", Some(7)).unwrap();
        assert_eq!(result.value, b"middle");
        assert_eq!(result.key.seqno, 5);

        // Snapshot read at seqno 1
        let result = reader.get(b"key1", Some(1)).unwrap();
        assert_eq!(result.value, b"oldest");
        assert_eq!(result.key.seqno, 1);
    }

    #[test]
    fn test_block_checksum_corruption_detected() {
        let mut builder = BlockBuilder::new(DEFAULT_RESTART_INTERVAL);
        builder.add(&make_entry("key", 1, "val"));
        let mut block = builder.finish();

        // Corrupt a byte in the data section
        if block.len() > 20 {
            block[5] ^= 0xFF;
        }

        let result = BlockReader::open(&block);
        assert_eq!(result, Err(BlockError::ChecksumMismatch));
    }

    #[test]
    fn test_block_first_and_last_key() {
        let mut builder = BlockBuilder::new(DEFAULT_RESTART_INTERVAL);
        builder.add(&make_entry("aaa", 3, "first"));
        builder.add(&make_entry("bbb", 2, "middle"));
        builder.add(&make_entry("zzz", 1, "last"));

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();

        let first = reader.first_key().unwrap();
        assert_eq!(first.user_key, b"aaa");

        let last = reader.last_key().unwrap();
        assert_eq!(last.user_key, b"zzz");
    }

    #[test]
    fn test_empty_block() {
        let builder = BlockBuilder::new(DEFAULT_RESTART_INTERVAL);
        assert!(builder.is_empty());

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();
        assert_eq!(reader.num_entries(), 0);
        assert!(reader.entries().is_empty());
    }

    #[test]
    fn test_block_restart_points() {
        // With restart_interval=2, we should get restart points at entries 0, 2, 4
        let mut builder = BlockBuilder::new(2);
        for i in 0..6 {
            let key = format!("key{:03}", i);
            builder.add(&make_entry(&key, i as u64 + 1, "v"));
        }

        let block = builder.finish();
        let reader = BlockReader::open(&block).unwrap();

        // Should have 3 restart points (entries 0, 2, 4)
        assert_eq!(reader.restart_offsets.len(), 3);

        // All entries should still be retrievable
        for i in 0..6 {
            let key = format!("key{:03}", i);
            let result = reader.get(key.as_bytes(), None);
            assert!(result.is_some(), "failed to find {}", key);
        }
    }
}
