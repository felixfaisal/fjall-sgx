// fjall-sgx/src/db.rs
//
// DB: the top-level API for the fjall-sgx key-value store.
//
// This ties together all the pieces:
//
//   Write path:  put/delete → MemTable → (when full) → flush → SSTable at L0
//   Read path:   get → MemTable → frozen MemTables → L0 SSTables (newest first)
//
// The read path follows the freshness hierarchy:
//   1. Active memtable (newest writes)
//   2. Frozen memtable(s) (being flushed)
//   3. Level 0 SSTables (recently flushed, may overlap)
//   4. Level 1+ SSTables (compacted, non-overlapping per level) [future]
//
// For now (Phase 3), we have:
//   - Single active memtable
//   - Immediate flush (no background flushing yet)
//   - Flat list of L0 SSTables (no leveled compaction yet)

use fjall_sgx_storage::{StorageReader, StorageWriter};
use lsm_sgx::sstable::SstOptions;
use lsm_sgx::types::{InternalEntry, SeqNo, ValueType};
use std::vec::Vec;

use crate::compaction;
use crate::flush;
use crate::memtable::{MemTable, DEFAULT_MEMTABLE_SIZE};
use crate::sst_file::{self, SstFileError, SstFileMeta};

// ─── Configuration ──────────────────────────────────────────────

/// Configuration for the DB engine.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Maximum memtable size before flush (bytes)
    pub memtable_size_limit: usize,

    /// SSTable build options (block size, restart interval, bloom filter)
    pub sst_options: SstOptions,

    /// Number of L0 SSTables that triggers compaction.
    /// When l0_sstable_count() >= this threshold, L0 compaction runs.
    /// Default: 4 (matches RocksDB/Fjall defaults).
    pub l0_compaction_threshold: usize,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            memtable_size_limit: DEFAULT_MEMTABLE_SIZE,
            sst_options: SstOptions::default(),
            l0_compaction_threshold: 4,
        }
    }
}

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DbError {
    /// Error from SSTable file operations
    SstFile(SstFileError),
    /// Attempted operation on a closed DB
    Closed,
}

impl From<SstFileError> for DbError {
    fn from(e: SstFileError) -> Self {
        DbError::SstFile(e)
    }
}

// ─── Lookup Result ──────────────────────────────────────────────

/// Result of a point lookup.
///
/// Distinguished from Option<Vec<u8>> because we need to tell the
/// caller whether the key was found-but-deleted (tombstone) vs
/// genuinely not found. This matters when scanning across levels:
/// a tombstone at a higher level masks any value at lower levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// Key found with this value
    Found(Vec<u8>),
    /// Key has been explicitly deleted (tombstone found)
    Deleted,
    /// Key not found in any searched location
    NotFound,
}

// ─── DB ─────────────────────────────────────────────────────────

/// The core key-value store engine.
///
/// Generic over the storage backend so it works with MemoryStorage
/// (tests), StdStorage (disk), or SgxStorage (enclave) seamlessly.
pub struct Db<S: StorageReader + StorageWriter> {
    /// Configuration
    config: DbConfig,

    /// Storage backend
    storage: S,

    /// Active memtable (receives writes)
    active_memtable: MemTable,

    /// Frozen memtables waiting to be flushed.
    /// Ordered newest-first so reads check the most recent one first.
    frozen_memtables: Vec<MemTable>,

    /// Level 0 SSTables — recently flushed, may have overlapping key ranges.
    /// Ordered newest-first (most recently flushed first).
    l0_sstables: Vec<SstFileMeta>,

    /// Monotonically increasing sequence number counter.
    /// Each write gets the next seqno.
    next_seqno: SeqNo,
}

impl<S: StorageReader + StorageWriter> Db<S> {
    /// Open a new DB with the given storage backend and configuration.
    pub fn open(storage: S, config: DbConfig) -> Self {
        Self {
            config,
            storage,
            active_memtable: MemTable::new(),
            frozen_memtables: Vec::new(),
            l0_sstables: Vec::new(),
            next_seqno: 1,
        }
    }

    /// Open a DB with default configuration.
    pub fn open_default(storage: S) -> Self {
        Self::open(storage, DbConfig::default())
    }

    // ── Write Path ──────────────────────────────────────────────

    /// Insert a key-value pair.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        let seqno = self.next_seqno;
        self.next_seqno += 1;

        self.active_memtable.put(key, seqno, value);

        // Check if memtable needs flushing
        if self
            .active_memtable
            .should_flush(self.config.memtable_size_limit)
        {
            self.flush_active_memtable()?;
        }

        Ok(())
    }

    /// Delete a key (write a tombstone).
    pub fn delete(&mut self, key: &[u8]) -> Result<(), DbError> {
        let seqno = self.next_seqno;
        self.next_seqno += 1;

        self.active_memtable.delete(key, seqno);

        if self
            .active_memtable
            .should_flush(self.config.memtable_size_limit)
        {
            self.flush_active_memtable()?;
        }

        Ok(())
    }

    // ── Read Path ───────────────────────────────────────────────

    /// Look up a key, returning the latest value.
    ///
    /// Searches in order:
    ///   1. Active memtable
    ///   2. Frozen memtables (newest first)
    ///   3. L0 SSTables (newest first)
    ///
    /// Returns the value if found, None if not found or deleted.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        match self.get_internal(key, None)? {
            LookupResult::Found(value) => Ok(Some(value)),
            LookupResult::Deleted | LookupResult::NotFound => Ok(None),
        }
    }

    /// Look up a key with full result information (found/deleted/not found).
    pub fn get_detail(&self, key: &[u8]) -> Result<LookupResult, DbError> {
        self.get_internal(key, None)
    }

    /// Snapshot read: get the value as of a specific sequence number.
    pub fn get_at(&self, key: &[u8], seqno: SeqNo) -> Result<Option<Vec<u8>>, DbError> {
        match self.get_internal(key, Some(seqno))? {
            LookupResult::Found(value) => Ok(Some(value)),
            LookupResult::Deleted | LookupResult::NotFound => Ok(None),
        }
    }

    /// Internal get with optional seqno limit.
    fn get_internal(
        &self,
        key: &[u8],
        seqno_limit: Option<SeqNo>,
    ) -> Result<LookupResult, DbError> {
        // 1. Check active memtable
        if let Some(entry) = self.active_memtable.get(key, seqno_limit) {
            return Ok(entry_to_lookup_result(&entry));
        }

        // 2. Check frozen memtables (newest first)
        for mt in &self.frozen_memtables {
            if let Some(entry) = mt.get(key, seqno_limit) {
                return Ok(entry_to_lookup_result(&entry));
            }
        }

        // 3. Check L0 SSTables (newest first)
        for sst_meta in &self.l0_sstables {
            // Quick key range check — skip if key is outside this SSTable's range
            if key < sst_meta.first_key.as_slice() || key > sst_meta.last_key.as_slice() {
                continue;
            }

            // Quick seqno check — skip if this SSTable has no visible entries
            if let Some(limit) = seqno_limit {
                if sst_meta.min_seqno > limit {
                    continue;
                }
            }

            match sst_file::query_sstable(&self.storage, sst_meta.file_id, key, seqno_limit)? {
                Some(entry) => return Ok(entry_to_lookup_result(&entry)),
                None => continue,
            }
        }

        Ok(LookupResult::NotFound)
    }

    // ── Flush ───────────────────────────────────────────────────

    /// Freeze the active memtable and flush it to an L0 SSTable.
    ///
    /// In a production engine this would happen asynchronously on a
    /// background thread. For Phase 3, it's synchronous.
    fn flush_active_memtable(&mut self) -> Result<(), DbError> {
        if self.active_memtable.is_empty() {
            return Ok(());
        }

        // Swap in a fresh memtable
        let frozen = std::mem::replace(&mut self.active_memtable, MemTable::new());

        // Flush the frozen memtable to storage
        let meta =
            flush::flush_memtable(&frozen, &mut self.storage, self.config.sst_options.clone())?;

        // Register at the front of L0 (newest first)
        self.l0_sstables.insert(0, meta);

        // Check if L0 needs compaction
        self.maybe_compact_l0()?;

        // frozen memtable is dropped here — its data now lives on disk
        Ok(())
    }

    /// Force a flush of the active memtable, regardless of size.
    /// Useful for testing and for ensuring durability before shutdown.
    pub fn force_flush(&mut self) -> Result<(), DbError> {
        self.flush_active_memtable()
    }

    // ── Compaction ──────────────────────────────────────────────

    /// Run L0 compaction if the threshold is reached.
    fn maybe_compact_l0(&mut self) -> Result<(), DbError> {
        if self.l0_sstables.len() >= self.config.l0_compaction_threshold {
            self.run_l0_compaction()?;
        }
        Ok(())
    }

    /// Force an L0 compaction regardless of threshold.
    pub fn force_compact(&mut self) -> Result<(), DbError> {
        if self.l0_sstables.len() > 1 {
            self.run_l0_compaction()?;
        }
        Ok(())
    }

    /// Execute L0 compaction: merge all L0 SSTables into one.
    fn run_l0_compaction(&mut self) -> Result<(), DbError> {
        let result = compaction::compact_l0(
            &self.l0_sstables,
            &mut self.storage,
            self.config.sst_options.clone(),
            true, // drop tombstones — L0 is the only level for now
        )?;

        // Delete obsolete files
        for file_id in &result.obsolete_file_ids {
            // Best-effort delete — don't fail the compaction if cleanup fails
            let _ = self.storage.delete_file(*file_id);
        }

        // Replace L0 with compaction output
        self.l0_sstables = result.new_sstables;

        Ok(())
    }

    // ── Stats ───────────────────────────────────────────────────

    /// Current sequence number (next write gets this value).
    pub fn current_seqno(&self) -> SeqNo {
        self.next_seqno
    }

    /// Number of entries in the active memtable.
    pub fn memtable_entries(&self) -> usize {
        self.active_memtable.len()
    }

    /// Number of L0 SSTables.
    pub fn l0_sstable_count(&self) -> usize {
        self.l0_sstables.len()
    }

    /// Approximate memory used by the active memtable.
    pub fn memtable_size(&self) -> usize {
        self.active_memtable.approximate_size()
    }

    /// Metadata for all L0 SSTables.
    pub fn l0_sstables(&self) -> &[SstFileMeta] {
        &self.l0_sstables
    }
}

// ─── Helpers ────────────────────────────────────────────────────

fn entry_to_lookup_result(entry: &InternalEntry) -> LookupResult {
    match entry.key.value_type {
        ValueType::Put => LookupResult::Found(entry.value.clone()),
        ValueType::Delete => LookupResult::Deleted,
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fjall_sgx_storage::MemoryStorage;

    fn test_db() -> Db<MemoryStorage> {
        Db::open_default(MemoryStorage::new())
    }

    fn small_db() -> Db<MemoryStorage> {
        // Small memtable to trigger frequent flushes
        Db::open(
            MemoryStorage::new(),
            DbConfig {
                memtable_size_limit: 512, // Very small — flushes quickly
                sst_options: SstOptions {
                    block_size: 128,
                    ..SstOptions::default()
                },
                ..Default::default()
            },
        )
    }

    // ── Basic CRUD ──

    #[test]
    fn test_put_and_get() {
        let mut db = test_db();
        db.put(b"hello", b"world").unwrap();

        assert_eq!(db.get(b"hello").unwrap(), Some(b"world".to_vec()));
    }

    #[test]
    fn test_get_missing() {
        let db = test_db();
        assert_eq!(db.get(b"nope").unwrap(), None);
    }

    #[test]
    fn test_overwrite() {
        let mut db = test_db();
        db.put(b"key", b"v1").unwrap();
        db.put(b"key", b"v2").unwrap();

        assert_eq!(db.get(b"key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_delete() {
        let mut db = test_db();
        db.put(b"key", b"value").unwrap();
        db.delete(b"key").unwrap();

        assert_eq!(db.get(b"key").unwrap(), None);
        assert_eq!(db.get_detail(b"key").unwrap(), LookupResult::Deleted);
    }

    #[test]
    fn test_delete_then_put() {
        let mut db = test_db();
        db.put(b"key", b"v1").unwrap();
        db.delete(b"key").unwrap();
        db.put(b"key", b"v2").unwrap();

        assert_eq!(db.get(b"key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_delete_nonexistent() {
        let mut db = test_db();
        db.delete(b"ghost").unwrap();

        // Should be Deleted (tombstone exists), not NotFound
        assert_eq!(db.get_detail(b"ghost").unwrap(), LookupResult::Deleted);
    }

    // ── Multiple keys ──

    #[test]
    fn test_multiple_keys() {
        let mut db = test_db();
        db.put(b"aaa", b"1").unwrap();
        db.put(b"bbb", b"2").unwrap();
        db.put(b"ccc", b"3").unwrap();

        assert_eq!(db.get(b"aaa").unwrap(), Some(b"1".to_vec()));
        assert_eq!(db.get(b"bbb").unwrap(), Some(b"2".to_vec()));
        assert_eq!(db.get(b"ccc").unwrap(), Some(b"3".to_vec()));
    }

    // ── Flush + read across SSTable ──

    #[test]
    fn test_force_flush_and_read() {
        let mut db = test_db();
        db.put(b"key1", b"value1").unwrap();
        db.put(b"key2", b"value2").unwrap();

        // Force flush to SSTable
        db.force_flush().unwrap();
        assert_eq!(db.l0_sstable_count(), 1);
        assert_eq!(db.memtable_entries(), 0);

        // Should still find values (now reading from SSTable)
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_data_spans_memtable_and_sstable() {
        let mut db = test_db();

        // Write some data
        db.put(b"old_key", b"old_value").unwrap();

        // Flush to SSTable
        db.force_flush().unwrap();

        // Write more data (in new memtable)
        db.put(b"new_key", b"new_value").unwrap();

        // Both should be findable
        assert_eq!(db.get(b"old_key").unwrap(), Some(b"old_value".to_vec()));
        assert_eq!(db.get(b"new_key").unwrap(), Some(b"new_value".to_vec()));
    }

    #[test]
    fn test_newer_memtable_overrides_sstable() {
        let mut db = test_db();

        // Write v1 and flush
        db.put(b"key", b"v1").unwrap();
        db.force_flush().unwrap();

        // Write v2 (stays in memtable)
        db.put(b"key", b"v2").unwrap();

        // Should get v2 (memtable is checked first)
        assert_eq!(db.get(b"key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_delete_in_memtable_masks_sstable() {
        let mut db = test_db();

        // Write and flush
        db.put(b"key", b"value").unwrap();
        db.force_flush().unwrap();

        // Delete (tombstone in memtable)
        db.delete(b"key").unwrap();

        // Tombstone in memtable masks the SSTable value
        assert_eq!(db.get(b"key").unwrap(), None);
        assert_eq!(db.get_detail(b"key").unwrap(), LookupResult::Deleted);
    }

    // ── Auto-flush ──

    #[test]
    fn test_auto_flush_on_size_threshold() {
        let mut db = small_db();

        // Write enough data to trigger auto-flush
        for i in 0..50u32 {
            let key = format!("key_{:04}", i);
            let val = format!("val_{:04}", i);
            db.put(key.as_bytes(), val.as_bytes()).unwrap();
        }

        // Should have flushed at least once
        assert!(
            db.l0_sstable_count() > 0,
            "expected auto-flush, got {} L0 SSTables",
            db.l0_sstable_count()
        );

        // All data should still be readable
        for i in 0..50u32 {
            let key = format!("key_{:04}", i);
            let val = format!("val_{:04}", i);
            assert_eq!(
                db.get(key.as_bytes()).unwrap(),
                Some(val.into_bytes()),
                "failed to find key_{:04}",
                i
            );
        }
    }

    #[test]
    fn test_multiple_flushes() {
        let mut db = small_db();

        // Write in batches, flushing between each
        for batch in 0..5u32 {
            for i in 0..10u32 {
                let key = format!("b{}_k{:03}", batch, i);
                let val = format!("value_{}", batch * 10 + i);
                db.put(key.as_bytes(), val.as_bytes()).unwrap();
            }
            db.force_flush().unwrap();
        }

        assert_eq!(db.l0_sstable_count(), 5);

        // All data readable across all SSTables
        for batch in 0..5u32 {
            for i in 0..10u32 {
                let key = format!("b{}_k{:03}", batch, i);
                let result = db.get(key.as_bytes()).unwrap();
                assert!(result.is_some(), "missing key: {}", key);
            }
        }
    }

    // ── Snapshot reads ──

    #[test]
    fn test_snapshot_read() {
        let mut db = test_db();

        db.put(b"key", b"v1").unwrap();
        let snap1 = db.current_seqno() - 1; // seqno of the v1 write

        db.put(b"key", b"v2").unwrap();
        let snap2 = db.current_seqno() - 1;

        db.put(b"key", b"v3").unwrap();

        // Current: v3
        assert_eq!(db.get(b"key").unwrap(), Some(b"v3".to_vec()));

        // At snap2: v2
        assert_eq!(db.get_at(b"key", snap2).unwrap(), Some(b"v2".to_vec()));

        // At snap1: v1
        assert_eq!(db.get_at(b"key", snap1).unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn test_snapshot_read_across_flush() {
        let mut db = test_db();

        db.put(b"key", b"v1").unwrap();
        let snap1 = db.current_seqno() - 1;

        db.force_flush().unwrap();

        db.put(b"key", b"v2").unwrap();

        // Current: v2 (from memtable)
        assert_eq!(db.get(b"key").unwrap(), Some(b"v2".to_vec()));

        // Snapshot at snap1: v1 (from SSTable)
        assert_eq!(db.get_at(b"key", snap1).unwrap(), Some(b"v1".to_vec()));
    }

    // ── Stats ──

    #[test]
    fn test_stats() {
        let mut db = test_db();

        assert_eq!(db.current_seqno(), 1);
        assert_eq!(db.memtable_entries(), 0);
        assert_eq!(db.l0_sstable_count(), 0);

        db.put(b"k1", b"v1").unwrap();
        db.put(b"k2", b"v2").unwrap();
        assert_eq!(db.current_seqno(), 3);
        assert_eq!(db.memtable_entries(), 2);

        db.force_flush().unwrap();
        assert_eq!(db.memtable_entries(), 0);
        assert_eq!(db.l0_sstable_count(), 1);
    }

    // ── Edge cases ──

    #[test]
    fn test_empty_db() {
        let db = test_db();
        assert_eq!(db.get(b"anything").unwrap(), None);
        assert_eq!(db.get_detail(b"anything").unwrap(), LookupResult::NotFound);
    }

    #[test]
    fn test_flush_empty_memtable() {
        let mut db = test_db();
        // Flushing an empty memtable should be a no-op
        db.force_flush().unwrap();
        assert_eq!(db.l0_sstable_count(), 0);
    }

    #[test]
    fn test_large_values() {
        let mut db = test_db();
        let big_value = vec![0xABu8; 1024 * 100]; // 100 KB
        db.put(b"big", &big_value).unwrap();

        let result = db.get(b"big").unwrap().unwrap();
        assert_eq!(result.len(), 100 * 1024);
    }

    #[test]
    fn test_sequential_writes_and_reads() {
        let mut db = small_db();

        // Write 200 entries — will trigger multiple auto-flushes
        for i in 0..200u32 {
            let key = format!("{:08}", i);
            let val = format!("v{}", i);
            db.put(key.as_bytes(), val.as_bytes()).unwrap();
        }

        // Read all back
        for i in 0..200u32 {
            let key = format!("{:08}", i);
            let val = format!("v{}", i);
            let result = db.get(key.as_bytes()).unwrap();
            assert_eq!(result, Some(val.into_bytes()), "mismatch at key {}", i);
        }
    }

    // ── Compaction ──

    fn compacting_db() -> Db<MemoryStorage> {
        // Small memtable + low compaction threshold to test compaction
        Db::open(
            MemoryStorage::new(),
            DbConfig {
                memtable_size_limit: 256,
                l0_compaction_threshold: 3,
                sst_options: SstOptions {
                    block_size: 128,
                    ..SstOptions::default()
                },
            },
        )
    }

    #[test]
    fn test_force_compact() {
        let mut db = test_db();

        // Write 3 batches, flush each
        for batch in 0..3u32 {
            for i in 0..5u32 {
                let key = format!("key_{:03}", i);
                let val = format!("batch{}_{}", batch, i);
                db.put(key.as_bytes(), val.as_bytes()).unwrap();
            }
            db.force_flush().unwrap();
        }

        assert_eq!(db.l0_sstable_count(), 3);

        // Compact
        db.force_compact().unwrap();
        assert_eq!(db.l0_sstable_count(), 1);

        // All keys should return their newest value (batch 2)
        for i in 0..5u32 {
            let key = format!("key_{:03}", i);
            let val = format!("batch2_{}", i);
            assert_eq!(
                db.get(key.as_bytes()).unwrap(),
                Some(val.into_bytes()),
                "wrong value after compaction for key_{:03}",
                i
            );
        }
    }

    #[test]
    fn test_compact_deduplicates() {
        let mut db = test_db();

        // Write same key across multiple flushes
        db.put(b"key", b"v1").unwrap();
        db.force_flush().unwrap();

        db.put(b"key", b"v2").unwrap();
        db.force_flush().unwrap();

        db.put(b"key", b"v3").unwrap();
        db.force_flush().unwrap();

        assert_eq!(db.l0_sstable_count(), 3);

        db.force_compact().unwrap();
        assert_eq!(db.l0_sstable_count(), 1);

        // Should get newest
        assert_eq!(db.get(b"key").unwrap(), Some(b"v3".to_vec()));

        // Compacted SSTable should have fewer entries
        assert_eq!(db.l0_sstables()[0].num_entries, 1);
    }

    #[test]
    fn test_compact_drops_tombstones() {
        let mut db = test_db();

        db.put(b"key", b"value").unwrap();
        db.force_flush().unwrap();

        db.delete(b"key").unwrap();
        db.force_flush().unwrap();

        assert_eq!(db.l0_sstable_count(), 2);

        db.force_compact().unwrap();

        // Tombstone dropped — key is fully gone
        assert_eq!(db.get(b"key").unwrap(), None);
        assert_eq!(db.get_detail(b"key").unwrap(), LookupResult::NotFound);
    }

    #[test]
    fn test_auto_compaction() {
        let mut db = compacting_db();

        // Write enough to trigger multiple flushes + auto-compact
        for i in 0..100u32 {
            let key = format!("key_{:04}", i);
            let val = format!("val_{:04}", i);
            db.put(key.as_bytes(), val.as_bytes()).unwrap();
        }

        // Auto-compaction should have kept L0 count under control
        assert!(
            db.l0_sstable_count() < 10,
            "expected compaction to keep L0 small, got {} SSTables",
            db.l0_sstable_count()
        );

        // All data should be readable
        for i in 0..100u32 {
            let key = format!("key_{:04}", i);
            let val = format!("val_{:04}", i);
            assert_eq!(
                db.get(key.as_bytes()).unwrap(),
                Some(val.into_bytes()),
                "missing key_{:04} after auto-compaction",
                i
            );
        }
    }

    #[test]
    fn test_compact_with_overwrites_across_flushes() {
        let mut db = test_db();

        // Batch 1: write keys 0-9
        for i in 0..10u32 {
            let key = format!("k{:02}", i);
            db.put(key.as_bytes(), b"old").unwrap();
        }
        db.force_flush().unwrap();

        // Batch 2: overwrite even keys
        for i in (0..10u32).step_by(2) {
            let key = format!("k{:02}", i);
            db.put(key.as_bytes(), b"new").unwrap();
        }
        db.force_flush().unwrap();

        db.force_compact().unwrap();

        // Verify: even keys have "new", odd keys have "old"
        for i in 0..10u32 {
            let key = format!("k{:02}", i);
            let expected = if i % 2 == 0 {
                b"new".to_vec()
            } else {
                b"old".to_vec()
            };
            assert_eq!(
                db.get(key.as_bytes()).unwrap(),
                Some(expected),
                "wrong value for k{:02}",
                i
            );
        }
    }

    #[test]
    fn test_writes_after_compaction() {
        let mut db = test_db();

        // Flush + compact
        db.put(b"k1", b"v1").unwrap();
        db.force_flush().unwrap();
        db.put(b"k2", b"v2").unwrap();
        db.force_flush().unwrap();
        db.force_compact().unwrap();

        // Write more after compaction
        db.put(b"k3", b"v3").unwrap();
        db.put(b"k1", b"v1_updated").unwrap();

        assert_eq!(db.get(b"k1").unwrap(), Some(b"v1_updated".to_vec()));
        assert_eq!(db.get(b"k2").unwrap(), Some(b"v2".to_vec()));
        assert_eq!(db.get(b"k3").unwrap(), Some(b"v3".to_vec()));
    }

    #[test]
    fn test_stress_with_compaction() {
        let mut db = compacting_db();

        // Write 500 entries with overwrites — triggers many flushes + compactions
        for round in 0..5u32 {
            for i in 0..100u32 {
                let key = format!("stress_{:04}", i);
                let val = format!("r{}_{}", round, i);
                db.put(key.as_bytes(), val.as_bytes()).unwrap();
            }
        }

        // All keys should return round 4 values (newest)
        for i in 0..100u32 {
            let key = format!("stress_{:04}", i);
            let val = format!("r4_{}", i);
            assert_eq!(
                db.get(key.as_bytes()).unwrap(),
                Some(val.into_bytes()),
                "stress_{:04} wrong after stress test",
                i
            );
        }
    }
}
