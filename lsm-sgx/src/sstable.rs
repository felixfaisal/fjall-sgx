// lsm-sgx/src/sstable.rs
//
// SSTable (Sorted String Table) writer and reader.
//
// An SSTable is the fundamental on-disk unit of an LSM-tree: an immutable,
// sorted file of KV pairs organized into blocks for efficient lookup.
//
// File layout (inspired by Fjall v3):
//
// ┌───────────────────────────────────────┐  offset 0
// │  Data Block 0                         │
// │  Data Block 1                         │
// │  ...                                  │
// │  Data Block N                         │
// ├───────────────────────────────────────┤  index_offset
// │  Index Block                          │
// │  (last_key, block_offset, block_len)  │
// │  for each data block                  │
// ├───────────────────────────────────────┤  bloom_offset
// │  Bloom Filter Data                    │
// ├───────────────────────────────────────┤  trailer_offset
// │  Trailer (fixed TRAILER_SIZE bytes)   │
// │  - offsets to index and bloom         │
// │  - entry/block counts                 │
// │  - seqno range                        │
// │  - magic number + checksum            │
// └───────────────────────────────────────┘
//
// Read path for get(user_key):
//   1. Parse trailer (seek to end - TRAILER_SIZE)
//   2. Load bloom filter → quick "definitely not here" check
//   3. Load index → binary search for candidate data block
//   4. Load candidate data block → binary search within block
//
// This module is no_std compatible. It works with &[u8] / Vec<u8>,
// not files — the storage layer handles persistence.

use crate::block::{
    BlockBuilder, BlockError, BlockReader, DEFAULT_BLOCK_SIZE, DEFAULT_RESTART_INTERVAL,
};
use crate::bloom::{BloomFilter, DEFAULT_BITS_PER_KEY};
use crate::types::{InternalEntry, InternalKey, SeqNo, UserKey};

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// ─── Constants ──────────────────────────────────────────────────

/// Magic number to identify SSTable files: "LSGX" in ASCII
const SSTABLE_MAGIC: u32 = 0x4C534758;

/// Trailer is fixed size so we can always find it at EOF - TRAILER_SIZE.
///
/// Layout:
///   index_offset:     u64    (8)
///   index_len:        u64    (8)
///   bloom_offset:     u64    (8)
///   bloom_len:        u64    (8)
///   num_entries:      u64    (8)
///   num_data_blocks:  u32    (4)
///   min_seqno:        u64    (8)
///   max_seqno:        u64    (8)
///   magic:            u32    (4)
///   checksum:         [u8;16](16)
///   ─────────────────────────────
///   Total:                    80
const TRAILER_SIZE: usize = 80;

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum SstError {
    /// File too small to contain a valid trailer
    FileTooSmall,
    /// Magic number mismatch — not a valid SSTable
    BadMagic,
    /// Trailer checksum verification failed
    TrailerCorrupted,
    /// Index data is corrupted or out of bounds
    IndexCorrupted,
    /// Bloom filter data is out of bounds
    BloomCorrupted,
    /// A data block failed to parse or verify
    BlockError(BlockError),
    /// Offset/length points outside file bounds
    OutOfBounds,
    /// No entries were added to the writer
    EmptyTable,
}

impl From<BlockError> for SstError {
    fn from(e: BlockError) -> Self {
        SstError::BlockError(e)
    }
}

// ─── Index Entry ────────────────────────────────────────────────

/// One entry in the SSTable's block index.
///
/// Records the last key in a data block along with where to find that
/// block in the file. During lookup, we binary search these entries
/// to find which data block might contain our target key.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexEntry {
    /// Last user_key in this data block.
    /// We use user_key (not InternalKey) for the index because point
    /// lookups search by user_key — the MVCC version selection happens
    /// inside the block.
    pub last_user_key: UserKey,

    /// Byte offset of this data block within the SSTable file
    pub block_offset: u64,

    /// Length of this data block in bytes
    pub block_len: u32,
}

impl IndexEntry {
    /// Encode this index entry.
    /// Format: [key_len: u16 BE][key bytes][offset: u64 BE][len: u32 BE]
    fn encode(&self, buf: &mut Vec<u8>) {
        let key_len = self.last_user_key.len() as u16;
        buf.extend_from_slice(&key_len.to_be_bytes());
        buf.extend_from_slice(&self.last_user_key);
        buf.extend_from_slice(&self.block_offset.to_be_bytes());
        buf.extend_from_slice(&self.block_len.to_be_bytes());
    }

    /// Decode an index entry from bytes. Returns (entry, bytes_consumed).
    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let total = 2 + key_len + 8 + 4;
        if data.len() < total {
            return None;
        }

        let last_user_key = data[2..2 + key_len].to_vec();
        let offset_start = 2 + key_len;
        let block_offset = u64::from_be_bytes([
            data[offset_start],
            data[offset_start + 1],
            data[offset_start + 2],
            data[offset_start + 3],
            data[offset_start + 4],
            data[offset_start + 5],
            data[offset_start + 6],
            data[offset_start + 7],
        ]);
        let len_start = offset_start + 8;
        let block_len = u32::from_be_bytes([
            data[len_start],
            data[len_start + 1],
            data[len_start + 2],
            data[len_start + 3],
        ]);

        Some((
            IndexEntry {
                last_user_key,
                block_offset,
                block_len,
            },
            total,
        ))
    }
}

// ─── Trailer ────────────────────────────────────────────────────

/// Parsed trailer from the end of an SSTable file.
#[derive(Debug, Clone, PartialEq)]
struct Trailer {
    index_offset: u64,
    index_len: u64,
    bloom_offset: u64,
    bloom_len: u64,
    num_entries: u64,
    num_data_blocks: u32,
    min_seqno: u64,
    max_seqno: u64,
}

impl Trailer {
    fn encode(&self) -> [u8; TRAILER_SIZE] {
        let mut buf = [0u8; TRAILER_SIZE];
        let mut pos = 0;

        // Helper: write u64 BE
        macro_rules! put_u64 {
            ($val:expr) => {
                buf[pos..pos + 8].copy_from_slice(&$val.to_be_bytes());
                pos += 8;
            };
        }
        macro_rules! put_u32 {
            ($val:expr) => {
                buf[pos..pos + 4].copy_from_slice(&$val.to_be_bytes());
                pos += 4;
            };
        }

        put_u64!(self.index_offset);
        put_u64!(self.index_len);
        put_u64!(self.bloom_offset);
        put_u64!(self.bloom_len);
        put_u64!(self.num_entries);
        put_u32!(self.num_data_blocks);
        put_u64!(self.min_seqno);
        put_u64!(self.max_seqno);
        put_u32!(SSTABLE_MAGIC);

        // Checksum covers everything up to this point (pos = 64)
        let checksum = simple_checksum_128(&buf[..pos]);
        buf[pos..pos + 16].copy_from_slice(&checksum);

        buf
    }

    fn decode(data: &[u8; TRAILER_SIZE]) -> Result<Self, SstError> {
        let mut pos = 0;

        macro_rules! read_u64 {
            () => {{
                let val = u64::from_be_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                pos += 8;
                val
            }};
        }
        macro_rules! read_u32 {
            () => {{
                let val =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                val
            }};
        }

        let index_offset = read_u64!();
        let index_len = read_u64!();
        let bloom_offset = read_u64!();
        let bloom_len = read_u64!();
        let num_entries = read_u64!();
        let num_data_blocks = read_u32!();
        let min_seqno = read_u64!();
        let max_seqno = read_u64!();
        let magic = read_u32!();

        if magic != SSTABLE_MAGIC {
            return Err(SstError::BadMagic);
        }

        // Verify checksum (covers bytes 0..64, checksum at 64..80)
        let stored_checksum = &data[pos..pos + 16];
        let computed_checksum = simple_checksum_128(&data[..pos]);
        if stored_checksum != computed_checksum {
            return Err(SstError::TrailerCorrupted);
        }

        Ok(Trailer {
            index_offset,
            index_len,
            bloom_offset,
            bloom_len,
            num_entries,
            num_data_blocks,
            min_seqno,
            max_seqno,
        })
    }
}

// ─── SSTable Writer ─────────────────────────────────────────────

/// Configuration for building SSTables.
#[derive(Debug, Clone)]
pub struct SstOptions {
    /// Target size for each data block in bytes
    pub block_size: usize,

    /// Number of entries between restart points within a block
    pub restart_interval: usize,

    /// Bits per key for bloom filter (0 to disable)
    pub bloom_bits_per_key: usize,
}

impl Default for SstOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            restart_interval: DEFAULT_RESTART_INTERVAL,
            bloom_bits_per_key: DEFAULT_BITS_PER_KEY,
        }
    }
}

/// Builds an SSTable from sorted entries.
///
/// Usage:
///   let mut writer = SstWriter::new(SstOptions::default());
///   writer.add(&entry1)?;
///   writer.add(&entry2)?;
///   let sst_bytes = writer.finish()?;
///
/// Entries MUST be added in InternalKey sort order.
pub struct SstWriter {
    opts: SstOptions,

    /// The output buffer — the entire SSTable file
    output: Vec<u8>,

    /// Current block being built
    current_block: BlockBuilder,

    /// Index entries (one per completed data block)
    index_entries: Vec<IndexEntry>,

    /// All user keys seen — fed to the bloom filter at finish time
    bloom_keys: Vec<UserKey>,

    /// Track seqno range
    min_seqno: SeqNo,
    max_seqno: SeqNo,

    /// Total entry count
    num_entries: u64,

    /// Last key added (for sort-order assertion)
    last_key: Option<InternalKey>,
}

impl SstWriter {
    pub fn new(opts: SstOptions) -> Self {
        Self {
            current_block: BlockBuilder::new(opts.restart_interval),
            opts,
            output: Vec::new(),
            index_entries: Vec::new(),
            bloom_keys: Vec::new(),
            min_seqno: u64::MAX,
            max_seqno: 0,
            num_entries: 0,
            last_key: None,
        }
    }

    /// Add an entry to the SSTable. Entries must be added in InternalKey order.
    ///
    /// When the current block exceeds the target block size, it's automatically
    /// flushed and a new block is started.
    pub fn add(&mut self, entry: &InternalEntry) -> Result<(), SstError> {
        // Verify sort order in debug builds
        #[cfg(debug_assertions)]
        if let Some(ref last) = self.last_key {
            debug_assert!(
                entry.key > *last || entry.key == *last,
                "SstWriter: entries must be added in sorted order"
            );
        }

        // Track seqno range
        if entry.key.seqno < self.min_seqno {
            self.min_seqno = entry.key.seqno;
        }
        if entry.key.seqno > self.max_seqno {
            self.max_seqno = entry.key.seqno;
        }

        // Collect user key for bloom filter
        self.bloom_keys.push(entry.key.user_key.clone());

        // Check if adding this entry would exceed block size target.
        // If so, flush the current block first (but only if it's non-empty).
        if !self.current_block.is_empty()
            && self.current_block.approximate_size() + entry.encoded_size() > self.opts.block_size
        {
            self.flush_block()?;
        }

        self.current_block.add(entry);
        self.num_entries += 1;
        self.last_key = Some(entry.key.clone());

        Ok(())
    }

    /// Flush the current block to the output buffer and record it in the index.
    fn flush_block(&mut self) -> Result<(), SstError> {
        if self.current_block.is_empty() {
            return Ok(());
        }

        // Capture the last key before we consume the builder
        let last_key = self
            .last_key
            .clone()
            .expect("flush_block called but no entries added");

        let block_offset = self.output.len() as u64;

        // Finish the current block — this consumes the builder
        let old_builder = core::mem::replace(
            &mut self.current_block,
            BlockBuilder::new(self.opts.restart_interval),
        );
        let block_bytes = old_builder.finish();
        let block_len = block_bytes.len() as u32;

        // Write block bytes to output
        self.output.extend_from_slice(&block_bytes);

        // Record in index
        self.index_entries.push(IndexEntry {
            last_user_key: last_key.user_key,
            block_offset,
            block_len,
        });

        Ok(())
    }

    /// Finalize and return the complete SSTable as a byte vector.
    pub fn finish(mut self) -> Result<Vec<u8>, SstError> {
        if self.num_entries == 0 {
            return Err(SstError::EmptyTable);
        }

        // Flush the last block
        self.flush_block()?;

        let num_data_blocks = self.index_entries.len() as u32;

        // ── Write index block ──
        let index_offset = self.output.len() as u64;
        let mut index_buf = Vec::new();
        for ie in &self.index_entries {
            ie.encode(&mut index_buf);
        }
        // Write index entry count at the end of the index block
        index_buf.extend_from_slice(&num_data_blocks.to_be_bytes());
        self.output.extend_from_slice(&index_buf);
        let index_len = index_buf.len() as u64;

        // ── Write bloom filter ──
        let bloom_offset = self.output.len() as u64;
        let bloom_data = if self.opts.bloom_bits_per_key > 0 {
            let mut filter =
                BloomFilter::with_capacity(self.bloom_keys.len(), self.opts.bloom_bits_per_key);
            for key in &self.bloom_keys {
                filter.insert(key);
            }
            filter.to_bytes().to_vec()
        } else {
            Vec::new()
        };
        self.output.extend_from_slice(&bloom_data);
        let bloom_len = bloom_data.len() as u64;

        // ── Write trailer ──
        let trailer = Trailer {
            index_offset,
            index_len,
            bloom_offset,
            bloom_len,
            num_entries: self.num_entries,
            num_data_blocks,
            min_seqno: self.min_seqno,
            max_seqno: self.max_seqno,
        };
        self.output.extend_from_slice(&trailer.encode());

        Ok(self.output)
    }
}

// ─── SSTable Reader ─────────────────────────────────────────────

/// Reads an SSTable from a byte slice.
///
/// The reader eagerly parses the trailer, index, and bloom filter on open.
/// Data blocks are parsed lazily (only when a key is looked up or iterated).
///
/// Usage:
///   let reader = SstReader::open(&sst_bytes)?;
///   if let Some(entry) = reader.get(b"my_key", None)? { ... }
#[derive(Debug, PartialEq)]
pub struct SstReader<'a> {
    /// The raw SSTable bytes
    data: &'a [u8],

    /// Parsed trailer
    trailer: Trailer,

    /// Block index (sorted by last_user_key)
    index: Vec<IndexEntry>,

    /// Bloom filter (if present)
    bloom: Option<BloomFilter>,
}

impl<'a> SstReader<'a> {
    /// Open and parse an SSTable from a byte slice.
    ///
    /// This parses the trailer, loads the full index, and loads the
    /// bloom filter into memory. Data blocks are NOT loaded — they're
    /// read on demand during get()/iter() calls.
    pub fn open(data: &'a [u8]) -> Result<Self, SstError> {
        if data.len() < TRAILER_SIZE {
            return Err(SstError::FileTooSmall);
        }

        // ── Parse trailer ──
        let trailer_start = data.len() - TRAILER_SIZE;
        let trailer_bytes: &[u8; TRAILER_SIZE] = data[trailer_start..trailer_start + TRAILER_SIZE]
            .try_into()
            .map_err(|_| SstError::FileTooSmall)?;
        let trailer = Trailer::decode(trailer_bytes)?;

        // ── Validate offsets ──
        let file_len = data.len() as u64;
        if trailer.index_offset + trailer.index_len > file_len
            || trailer.bloom_offset + trailer.bloom_len > file_len
        {
            return Err(SstError::OutOfBounds);
        }

        // ── Parse index ──
        let index_data = &data
            [trailer.index_offset as usize..(trailer.index_offset + trailer.index_len) as usize];

        // The last 4 bytes of the index block are the entry count
        if index_data.len() < 4 {
            return Err(SstError::IndexCorrupted);
        }
        let index_entry_data = &index_data[..index_data.len() - 4];
        let stored_count = u32::from_be_bytes([
            index_data[index_data.len() - 4],
            index_data[index_data.len() - 3],
            index_data[index_data.len() - 2],
            index_data[index_data.len() - 1],
        ]) as usize;

        let mut index = Vec::with_capacity(stored_count);
        let mut offset = 0;
        while offset < index_entry_data.len() {
            let (entry, consumed) =
                IndexEntry::decode(&index_entry_data[offset..]).ok_or(SstError::IndexCorrupted)?;
            index.push(entry);
            offset += consumed;
        }

        if index.len() != stored_count {
            return Err(SstError::IndexCorrupted);
        }

        // ── Load bloom filter ──
        let bloom = if trailer.bloom_len > 0 {
            let bloom_data = &data[trailer.bloom_offset as usize
                ..(trailer.bloom_offset + trailer.bloom_len) as usize];
            Some(BloomFilter::from_bytes(bloom_data.to_vec()))
        } else {
            None
        };

        Ok(Self {
            data,
            trailer,
            index,
            bloom,
        })
    }

    /// Number of KV entries in this SSTable.
    pub fn num_entries(&self) -> u64 {
        self.trailer.num_entries
    }

    /// Number of data blocks.
    pub fn num_data_blocks(&self) -> u32 {
        self.trailer.num_data_blocks
    }

    /// Sequence number range [min, max] of entries in this SSTable.
    pub fn seqno_range(&self) -> (SeqNo, SeqNo) {
        (self.trailer.min_seqno, self.trailer.max_seqno)
    }

    /// First user key in the SSTable (from first index entry's block).
    /// Reads and parses the first data block to extract the first key.
    pub fn first_user_key(&self) -> Result<Option<UserKey>, SstError> {
        if self.index.is_empty() {
            return Ok(None);
        }
        let block = self.read_data_block(0)?;
        Ok(block.first_key().map(|k| k.user_key))
    }

    /// Last user key in the SSTable (from the last index entry).
    pub fn last_user_key(&self) -> Option<&UserKey> {
        self.index.last().map(|ie| &ie.last_user_key)
    }

    /// Point lookup: find the newest version of a user key.
    ///
    /// If `seqno_limit` is Some, only returns entries with seqno <= limit
    /// (snapshot read). Returns the entry with the highest seqno that
    /// satisfies the constraint.
    ///
    /// Returns Ok(None) if key is not found.
    pub fn get(
        &self,
        user_key: &[u8],
        seqno_limit: Option<SeqNo>,
    ) -> Result<Option<InternalEntry>, SstError> {
        // Step 1: Bloom filter check
        if let Some(ref bloom) = self.bloom {
            if !bloom.may_contain(user_key) {
                return Ok(None); // Definitely not in this SSTable
            }
        }

        // Step 2: Binary search the index to find candidate block.
        // We want the first block whose last_user_key >= user_key.
        // (If user_key > every block's last key, it's not here.)
        let block_idx = self.find_block_for_key(user_key);

        match block_idx {
            None => Ok(None), // Key is beyond all blocks
            Some(idx) => {
                // Step 3: Read and search the data block
                let block = self.read_data_block(idx)?;
                Ok(block.get(user_key, seqno_limit))
            }
        }
    }

    /// Read all entries from the SSTable in sorted order.
    /// Useful for compaction and debugging.
    pub fn iter(&self) -> Result<Vec<InternalEntry>, SstError> {
        let mut all = Vec::new();
        for i in 0..self.index.len() {
            let block = self.read_data_block(i)?;
            all.extend(block.entries());
        }
        Ok(all)
    }

    /// Read and parse data block at the given index.
    fn read_data_block(&self, block_idx: usize) -> Result<BlockReader<'a>, SstError> {
        if block_idx >= self.index.len() {
            return Err(SstError::OutOfBounds);
        }

        let ie = &self.index[block_idx];
        let start = ie.block_offset as usize;
        let end = start + ie.block_len as usize;

        if end > self.data.len() {
            return Err(SstError::OutOfBounds);
        }

        let block_data = &self.data[start..end];
        Ok(BlockReader::open(block_data)?)
    }

    /// Find which data block might contain the given user_key.
    ///
    /// Binary searches the index by last_user_key. We want the first
    /// block whose last_user_key >= target, since that block's key
    /// range could include our target.
    ///
    /// Returns None if target > every block's last key.
    fn find_block_for_key(&self, user_key: &[u8]) -> Option<usize> {
        // partition_point: finds the first index where predicate is FALSE.
        // We check: "is this block's last_user_key < target?"
        // The first FALSE means "this block's last key >= target" — our candidate.
        let idx = self
            .index
            .partition_point(|ie| ie.last_user_key.as_slice() < user_key);

        if idx < self.index.len() {
            Some(idx)
        } else {
            None // target is beyond all blocks
        }
    }
}

// ─── Checksum (shared with block.rs, duplicated for simplicity) ──

/// Simple 128-bit checksum for the trailer.
/// Same placeholder as block.rs — replace with XXH3-128 in production.
fn simple_checksum_128(data: &[u8]) -> [u8; 16] {
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

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{InternalEntry, ValueType};

    fn make_entry(key: &str, seqno: u64, value: &str) -> InternalEntry {
        InternalEntry::put(key.as_bytes().to_vec(), seqno, value.as_bytes().to_vec())
    }

    fn make_tombstone(key: &str, seqno: u64) -> InternalEntry {
        InternalEntry::delete(key.as_bytes().to_vec(), seqno)
    }

    /// Build a simple SSTable from a set of entries
    fn build_sst(entries: &[InternalEntry]) -> Vec<u8> {
        let mut writer = SstWriter::new(SstOptions::default());
        for e in entries {
            writer.add(e).unwrap();
        }
        writer.finish().unwrap()
    }

    /// Build an SSTable with small blocks to test multi-block behavior
    fn build_sst_small_blocks(entries: &[InternalEntry]) -> Vec<u8> {
        let opts = SstOptions {
            block_size: 100, // Very small — forces many blocks
            restart_interval: 2,
            bloom_bits_per_key: DEFAULT_BITS_PER_KEY,
        };
        let mut writer = SstWriter::new(opts);
        for e in entries {
            writer.add(e).unwrap();
        }
        writer.finish().unwrap()
    }

    // ── Basic roundtrip ──

    #[test]
    fn test_single_entry_roundtrip() {
        let entries = vec![make_entry("hello", 1, "world")];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        assert_eq!(reader.num_entries(), 1);
        assert_eq!(reader.num_data_blocks(), 1);

        let result = reader.get(b"hello", None).unwrap().unwrap();
        assert_eq!(result.value, b"world");
        assert_eq!(result.key.seqno, 1);
    }

    #[test]
    fn test_multiple_entries_single_block() {
        let entries = vec![
            make_entry("aaa", 3, "val_a"),
            make_entry("bbb", 2, "val_b"),
            make_entry("ccc", 1, "val_c"),
        ];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        assert_eq!(reader.num_entries(), 3);

        // Find each key
        for e in &entries {
            let result = reader.get(&e.key.user_key, None).unwrap().unwrap();
            assert_eq!(result.value, e.value);
        }

        // Miss
        assert!(reader.get(b"zzz", None).unwrap().is_none());
        assert!(reader.get(b"000", None).unwrap().is_none());
    }

    // ── Multi-block ──

    #[test]
    fn test_multi_block_sst() {
        // With block_size=100, each entry ~30-50 bytes, so we get multiple blocks
        let mut entries: Vec<InternalEntry> = Vec::new();
        for i in 0..50u32 {
            let key = format!("key_{:04}", i);
            let val = format!("value_{:04}", i);
            entries.push(make_entry(&key, i as u64 + 1, &val));
        }

        let sst = build_sst_small_blocks(&entries);
        let reader = SstReader::open(&sst).unwrap();

        assert_eq!(reader.num_entries(), 50);
        assert!(reader.num_data_blocks() > 1, "expected multiple blocks");

        // Verify all keys are findable
        for e in &entries {
            let result = reader.get(&e.key.user_key, None).unwrap();
            assert!(
                result.is_some(),
                "failed to find key: {:?}",
                core::str::from_utf8(&e.key.user_key)
            );
            assert_eq!(result.unwrap().value, e.value);
        }

        // Verify misses
        assert!(reader.get(b"key_9999", None).unwrap().is_none());
        assert!(reader.get(b"aaa", None).unwrap().is_none());
    }

    // ── MVCC / snapshot reads ──

    #[test]
    fn test_mvcc_versions() {
        // Same user key, multiple versions.
        // InternalKey ordering: (user_key ASC, seqno DESC)
        // So seqno=10 comes before seqno=5 comes before seqno=1.
        let entries = vec![
            make_entry("mykey", 10, "newest"),
            make_entry("mykey", 5, "middle"),
            make_entry("mykey", 1, "oldest"),
        ];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        // No limit → newest
        let result = reader.get(b"mykey", None).unwrap().unwrap();
        assert_eq!(result.value, b"newest");
        assert_eq!(result.key.seqno, 10);

        // Snapshot at seqno 7
        let result = reader.get(b"mykey", Some(7)).unwrap().unwrap();
        assert_eq!(result.value, b"middle");
        assert_eq!(result.key.seqno, 5);

        // Snapshot at seqno 1
        let result = reader.get(b"mykey", Some(1)).unwrap().unwrap();
        assert_eq!(result.value, b"oldest");
        assert_eq!(result.key.seqno, 1);

        // Snapshot at seqno 0 → not visible
        assert!(reader.get(b"mykey", Some(0)).unwrap().is_none());
    }

    // ── Tombstones ──

    #[test]
    fn test_tombstone_entry() {
        let entries = vec![make_entry("alive", 2, "data"), make_tombstone("dead", 3)];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        // Tombstone is found — caller decides what to do with it
        let result = reader.get(b"dead", None).unwrap().unwrap();
        assert_eq!(result.key.value_type, ValueType::Delete);
        assert!(result.value.is_empty());

        // Live key still works
        let result = reader.get(b"alive", None).unwrap().unwrap();
        assert_eq!(result.value, b"data");
    }

    // ── Bloom filter ──

    #[test]
    fn test_bloom_filter_skips_misses() {
        let mut entries = Vec::new();
        for i in 0..100u32 {
            let key = format!("key_{:04}", i);
            entries.push(make_entry(&key, i as u64 + 1, "v"));
        }
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        // Keys that definitely don't exist should be fast misses
        // (bloom filter says "definitely not here")
        assert!(reader.get(b"nonexistent_key_xyz", None).unwrap().is_none());
        assert!(reader.get(b"another_missing_key", None).unwrap().is_none());
    }

    #[test]
    fn test_no_bloom_filter() {
        let opts = SstOptions {
            bloom_bits_per_key: 0, // disabled
            ..Default::default()
        };
        let entries = vec![make_entry("aaa", 1, "val")];
        let mut writer = SstWriter::new(opts);
        writer.add(&entries[0]).unwrap();
        let sst = writer.finish().unwrap();

        let reader = SstReader::open(&sst).unwrap();
        let result = reader.get(b"aaa", None).unwrap().unwrap();
        assert_eq!(result.value, b"val");
    }

    // ── Metadata ──

    #[test]
    fn test_seqno_range() {
        let entries = vec![
            make_entry("a", 5, "v"),
            make_entry("b", 12, "v"),
            make_entry("c", 3, "v"),
        ];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        assert_eq!(reader.seqno_range(), (3, 12));
    }

    #[test]
    fn test_first_and_last_key() {
        let entries = vec![
            make_entry("alpha", 1, "v"),
            make_entry("beta", 2, "v"),
            make_entry("zeta", 3, "v"),
        ];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        assert_eq!(reader.first_user_key().unwrap().unwrap(), b"alpha");
        assert_eq!(reader.last_user_key().unwrap(), b"zeta");
    }

    // ── Iterator / full scan ──

    #[test]
    fn test_iter_all_entries() {
        let entries = vec![
            make_entry("aaa", 3, "val_a"),
            make_entry("bbb", 2, "val_b"),
            make_entry("ccc", 1, "val_c"),
        ];
        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        let all = reader.iter().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].key.user_key, b"aaa");
        assert_eq!(all[1].key.user_key, b"bbb");
        assert_eq!(all[2].key.user_key, b"ccc");
    }

    #[test]
    fn test_iter_multi_block() {
        let mut entries = Vec::new();
        for i in 0..30u32 {
            entries.push(make_entry(
                &format!("k{:03}", i),
                i as u64 + 1,
                &format!("v{:03}", i),
            ));
        }

        let sst = build_sst_small_blocks(&entries);
        let reader = SstReader::open(&sst).unwrap();
        assert!(reader.num_data_blocks() > 1);

        let all = reader.iter().unwrap();
        assert_eq!(all.len(), 30);

        // Verify order is preserved across blocks
        for i in 0..30 {
            let expected_key = format!("k{:03}", i);
            assert_eq!(all[i].key.user_key, expected_key.as_bytes());
        }
    }

    // ── Error cases ──

    #[test]
    fn test_empty_writer_errors() {
        let writer = SstWriter::new(SstOptions::default());
        assert_eq!(writer.finish(), Err(SstError::EmptyTable));
    }

    #[test]
    fn test_truncated_file() {
        assert_eq!(SstReader::open(&[0u8; 10]), Err(SstError::FileTooSmall));
    }

    #[test]
    fn test_corrupted_magic() {
        let entries = vec![make_entry("a", 1, "v")];
        let mut sst = build_sst(&entries);

        // Corrupt the magic number (4 bytes before the last 16-byte checksum)
        let magic_pos = sst.len() - 16 - 4;
        sst[magic_pos] ^= 0xFF;

        // Could be BadMagic or TrailerCorrupted depending on which check fires first
        let result = SstReader::open(&sst);
        assert!(result.is_err());
    }

    // ── Large scale ──

    #[test]
    fn test_large_sst() {
        let mut entries = Vec::new();
        for i in 0..1000u32 {
            let key = format!("large_key_{:06}", i);
            let val = format!("large_value_{:06}_padding_to_make_this_bigger", i);
            entries.push(make_entry(&key, i as u64 + 1, &val));
        }

        let sst = build_sst(&entries);
        let reader = SstReader::open(&sst).unwrap();

        assert_eq!(reader.num_entries(), 1000);
        assert!(
            reader.num_data_blocks() > 1,
            "expected multiple blocks for 1000 entries"
        );

        // Spot check
        let result = reader.get(b"large_key_000500", None).unwrap().unwrap();
        assert_eq!(result.key.seqno, 501);

        // First and last
        assert_eq!(
            reader.first_user_key().unwrap().unwrap(),
            b"large_key_000000"
        );
        assert_eq!(reader.last_user_key().unwrap(), b"large_key_000999");

        // Full iteration preserves order
        let all = reader.iter().unwrap();
        assert_eq!(all.len(), 1000);
        for i in 0..1000 {
            let expected = format!("large_key_{:06}", i);
            assert_eq!(all[i].key.user_key, expected.as_bytes());
        }
    }
}
