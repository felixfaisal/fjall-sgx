// fjall-sgx/src/memtable.rs
//
// MemTable: the in-memory write buffer of the LSM-tree.
//
// All writes go here first. When the memtable grows past a size
// threshold, it's frozen (no more writes) and flushed to an SSTable
// on disk. While the frozen memtable is being flushed, a new active
// memtable accepts incoming writes so the write path is never blocked.
//
// Internally, a BTreeMap<InternalKey, UserValue> keeps entries sorted
// in the canonical LSM order: (user_key ASC, seqno DESC). This means:
// - Iteration yields entries in the exact order needed for SSTable flush
// - Point lookups find the newest version first
//
// The memtable does NOT assign sequence numbers itself — the caller
// (the DB layer) manages the global seqno counter. This keeps the
// memtable simple and testable.
//
// Memory tracking: we maintain an approximate byte count of all stored
// data (key + value + overhead). This is used to decide when to flush.

use std::collections::BTreeMap;
use std::vec::Vec;

use lsm_sgx::types::{InternalEntry, InternalKey, SeqNo, UserKey, UserValue, ValueType};

// ─── Constants ──────────────────────────────────────────────────

/// Default memtable size limit: 64 MB.
/// When approximate_size() exceeds this, the memtable should be flushed.
pub const DEFAULT_MEMTABLE_SIZE: usize = 64 * 1024 * 1024;

/// Approximate overhead per BTreeMap entry (pointers, alignment, node overhead).
/// BTreeMap uses B-tree nodes holding multiple entries; we estimate ~64 bytes
/// of overhead per entry as a reasonable approximation.
const BTREE_ENTRY_OVERHEAD: usize = 64;

// ─── MemTable ───────────────────────────────────────────────────

/// In-memory sorted write buffer.
///
/// Usage:
/// ```ignore
/// let mut mt = MemTable::new();
/// mt.put(b"key1", 1, b"value1");
/// mt.put(b"key1", 5, b"updated");
/// mt.delete(b"key2", 6);
///
/// // Point lookup (newest version)
/// let entry = mt.get(b"key1", None);
///
/// // Freeze and flush
/// let entries = mt.sorted_entries();
/// // → pass to write_sstable()
/// ```
pub struct MemTable {
    /// Sorted storage: InternalKey → value.
    ///
    /// Since InternalKey sorts by (user_key ASC, seqno DESC), the BTreeMap
    /// naturally maintains the MVCC ordering we need.
    entries: BTreeMap<InternalKey, UserValue>,

    /// Approximate total bytes stored (keys + values + overhead).
    /// Used to decide when to flush.
    approximate_bytes: usize,

    /// Number of entries
    num_entries: usize,
}

impl MemTable {
    /// Create a new empty memtable.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            approximate_bytes: 0,
            num_entries: 0,
        }
    }

    /// Insert a key-value pair.
    ///
    /// The caller must provide the sequence number (from a global counter).
    /// Multiple versions of the same user_key can coexist — MVCC ordering
    /// ensures the newest version (highest seqno) comes first.
    pub fn put(&mut self, user_key: &[u8], seqno: SeqNo, value: &[u8]) {
        let key = InternalKey::put(user_key.to_vec(), seqno);
        self.insert_entry(key, value.to_vec());
    }

    /// Insert a tombstone (deletion marker).
    ///
    /// The key isn't actually removed — a Delete marker is recorded.
    /// During compaction, the tombstone propagates downward and eventually
    /// gets cleaned up when it reaches the bottom level.
    pub fn delete(&mut self, user_key: &[u8], seqno: SeqNo) {
        let key = InternalKey::delete(user_key.to_vec(), seqno);
        self.insert_entry(key, Vec::new());
    }

    /// Core insertion logic.
    fn insert_entry(&mut self, key: InternalKey, value: UserValue) {
        let added_bytes = key.user_key.len() + 8 + 1 + value.len() + BTREE_ENTRY_OVERHEAD;
        self.entries.insert(key, value);
        self.approximate_bytes += added_bytes;
        self.num_entries += 1;
    }

    /// Look up the newest visible version of a user key.
    ///
    /// If `seqno_limit` is None, returns the newest version (highest seqno).
    /// If `seqno_limit` is Some(n), returns the newest version with seqno <= n
    /// (snapshot read).
    ///
    /// Returns the full InternalEntry (including value_type) so the caller
    /// can distinguish between Put and Delete results.
    pub fn get(&self, user_key: &[u8], seqno_limit: Option<SeqNo>) -> Option<InternalEntry> {
        // We want to find entries where the user_key matches.
        // BTreeMap range with InternalKey ordering:
        //   - Start: (user_key, seqno=MAX) — sorts BEFORE all versions of this key
        //   - End:   next key after user_key
        //
        // Because seqno is DESC in the ordering, the first match we encounter
        // will have the highest seqno (newest version).

        // Build a search key with seqno=MAX to position at the start of this user_key's range
        let search_start = InternalKey::new(user_key.to_vec(), u64::MAX, ValueType::Put);

        for (key, value) in self.entries.range(search_start..) {
            // Stop once we've passed our target user_key
            if key.user_key.as_slice() != user_key {
                break;
            }

            // Check seqno visibility
            match seqno_limit {
                None => {
                    // No limit — first match is newest
                    return Some(InternalEntry::new(key.clone(), value.clone()));
                }
                Some(limit) => {
                    if key.seqno <= limit {
                        return Some(InternalEntry::new(key.clone(), value.clone()));
                    }
                    // This version is too new, keep scanning for an older one
                }
            }
        }

        None
    }

    /// Return all entries in sorted order (for flushing to SSTable).
    ///
    /// The returned entries are in InternalKey order:
    /// (user_key ASC, seqno DESC) — exactly what SstWriter expects.
    pub fn sorted_entries(&self) -> Vec<InternalEntry> {
        self.entries
            .iter()
            .map(|(key, value)| InternalEntry::new(key.clone(), value.clone()))
            .collect()
    }

    /// Number of entries in the memtable.
    pub fn len(&self) -> usize {
        self.num_entries
    }

    /// Is the memtable empty?
    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }

    /// Approximate memory usage in bytes.
    ///
    /// This is a rough estimate used for flush-threshold decisions.
    /// It's not precise because BTreeMap's internal memory usage is
    /// complex, but it's good enough for deciding "is this memtable
    /// big enough to flush?"
    pub fn approximate_size(&self) -> usize {
        self.approximate_bytes
    }

    /// Check if the memtable has reached the flush threshold.
    pub fn should_flush(&self, max_size: usize) -> bool {
        self.approximate_bytes >= max_size
    }

    /// Get the sequence number range of entries in this memtable.
    /// Returns (min_seqno, max_seqno), or None if empty.
    pub fn seqno_range(&self) -> Option<(SeqNo, SeqNo)> {
        if self.entries.is_empty() {
            return None;
        }

        let mut min_seq = u64::MAX;
        let mut max_seq = 0;
        for key in self.entries.keys() {
            min_seq = min_seq.min(key.seqno);
            max_seq = max_seq.max(key.seqno);
        }
        Some((min_seq, max_seq))
    }
}

impl Default for MemTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic put/get ──

    #[test]
    fn test_put_and_get() {
        let mut mt = MemTable::new();
        mt.put(b"hello", 1, b"world");

        let result = mt.get(b"hello", None).unwrap();
        assert_eq!(result.key.user_key, b"hello");
        assert_eq!(result.value, b"world");
        assert_eq!(result.key.seqno, 1);
        assert_eq!(result.key.value_type, ValueType::Put);
    }

    #[test]
    fn test_get_missing_key() {
        let mut mt = MemTable::new();
        mt.put(b"exists", 1, b"val");

        assert!(mt.get(b"missing", None).is_none());
    }

    #[test]
    fn test_multiple_keys() {
        let mut mt = MemTable::new();
        mt.put(b"aaa", 1, b"val_a");
        mt.put(b"bbb", 2, b"val_b");
        mt.put(b"ccc", 3, b"val_c");

        assert_eq!(mt.get(b"aaa", None).unwrap().value, b"val_a");
        assert_eq!(mt.get(b"bbb", None).unwrap().value, b"val_b");
        assert_eq!(mt.get(b"ccc", None).unwrap().value, b"val_c");
        assert_eq!(mt.len(), 3);
    }

    // ── MVCC: multiple versions of same key ──

    #[test]
    fn test_mvcc_newest_version() {
        let mut mt = MemTable::new();
        mt.put(b"key1", 1, b"oldest");
        mt.put(b"key1", 5, b"middle");
        mt.put(b"key1", 10, b"newest");

        // No limit → newest version
        let result = mt.get(b"key1", None).unwrap();
        assert_eq!(result.value, b"newest");
        assert_eq!(result.key.seqno, 10);
    }

    #[test]
    fn test_mvcc_snapshot_read() {
        let mut mt = MemTable::new();
        mt.put(b"key1", 1, b"v1");
        mt.put(b"key1", 5, b"v5");
        mt.put(b"key1", 10, b"v10");

        // Snapshot at seqno 7 → should see v5
        let result = mt.get(b"key1", Some(7)).unwrap();
        assert_eq!(result.value, b"v5");
        assert_eq!(result.key.seqno, 5);

        // Snapshot at seqno 1 → should see v1
        let result = mt.get(b"key1", Some(1)).unwrap();
        assert_eq!(result.value, b"v1");

        // Snapshot at seqno 0 → nothing visible
        assert!(mt.get(b"key1", Some(0)).is_none());

        // Snapshot at seqno 10 → sees v10
        let result = mt.get(b"key1", Some(10)).unwrap();
        assert_eq!(result.value, b"v10");
    }

    #[test]
    fn test_mvcc_all_versions_stored() {
        let mut mt = MemTable::new();
        mt.put(b"key1", 1, b"v1");
        mt.put(b"key1", 5, b"v5");
        mt.put(b"key1", 10, b"v10");

        // All three versions should be stored (not overwritten)
        assert_eq!(mt.len(), 3);

        let entries = mt.sorted_entries();
        assert_eq!(entries.len(), 3);
        // InternalKey order: same user_key → seqno DESC
        assert_eq!(entries[0].key.seqno, 10);
        assert_eq!(entries[1].key.seqno, 5);
        assert_eq!(entries[2].key.seqno, 1);
    }

    // ── Tombstones ──

    #[test]
    fn test_delete_creates_tombstone() {
        let mut mt = MemTable::new();
        mt.put(b"key1", 1, b"alive");
        mt.delete(b"key1", 5);

        // get() returns the tombstone (newest version)
        let result = mt.get(b"key1", None).unwrap();
        assert_eq!(result.key.value_type, ValueType::Delete);
        assert_eq!(result.key.seqno, 5);
        assert!(result.value.is_empty());
    }

    #[test]
    fn test_put_after_delete() {
        let mut mt = MemTable::new();
        mt.put(b"key1", 1, b"original");
        mt.delete(b"key1", 5);
        mt.put(b"key1", 10, b"resurrected");

        // Newest is the put at seqno 10
        let result = mt.get(b"key1", None).unwrap();
        assert_eq!(result.value, b"resurrected");
        assert_eq!(result.key.value_type, ValueType::Put);

        // Snapshot at seqno 7 → sees the delete
        let result = mt.get(b"key1", Some(7)).unwrap();
        assert_eq!(result.key.value_type, ValueType::Delete);

        // Snapshot at seqno 3 → sees original put
        let result = mt.get(b"key1", Some(3)).unwrap();
        assert_eq!(result.value, b"original");
    }

    // ── Sorted iteration (for flush) ──

    #[test]
    fn test_sorted_entries_order() {
        let mut mt = MemTable::new();
        // Insert out of user_key order
        mt.put(b"charlie", 1, b"c");
        mt.put(b"alpha", 2, b"a");
        mt.put(b"bravo", 3, b"b");

        let entries = mt.sorted_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key.user_key, b"alpha");
        assert_eq!(entries[1].key.user_key, b"bravo");
        assert_eq!(entries[2].key.user_key, b"charlie");
    }

    #[test]
    fn test_sorted_entries_with_versions() {
        let mut mt = MemTable::new();
        mt.put(b"bbb", 1, b"b_old");
        mt.put(b"aaa", 5, b"a");
        mt.put(b"bbb", 10, b"b_new");

        let entries = mt.sorted_entries();
        assert_eq!(entries.len(), 3);

        // aaa (seqno 5)
        assert_eq!(entries[0].key.user_key, b"aaa");
        assert_eq!(entries[0].key.seqno, 5);

        // bbb (seqno 10) — newest first due to DESC seqno
        assert_eq!(entries[1].key.user_key, b"bbb");
        assert_eq!(entries[1].key.seqno, 10);

        // bbb (seqno 1)
        assert_eq!(entries[2].key.user_key, b"bbb");
        assert_eq!(entries[2].key.seqno, 1);
    }

    // ── Size tracking ──

    #[test]
    fn test_approximate_size() {
        let mut mt = MemTable::new();
        assert_eq!(mt.approximate_size(), 0);

        mt.put(b"key", 1, b"value");
        assert!(mt.approximate_size() > 0);

        let size_after_one = mt.approximate_size();
        mt.put(b"key2", 2, b"value2");
        assert!(mt.approximate_size() > size_after_one);
    }

    #[test]
    fn test_should_flush() {
        let mut mt = MemTable::new();
        assert!(!mt.should_flush(1024));

        // Add enough data to exceed threshold
        for i in 0..100u32 {
            let key = format!("key_{:06}", i);
            let val = format!("value_{:06}_with_some_extra_padding_to_increase_size", i);
            mt.put(key.as_bytes(), i as u64 + 1, val.as_bytes());
        }

        // With a small threshold, should flush
        assert!(mt.should_flush(1024));
        // With a huge threshold, should not
        assert!(!mt.should_flush(1024 * 1024 * 1024));
    }

    // ── Metadata ──

    #[test]
    fn test_seqno_range() {
        let mut mt = MemTable::new();
        assert!(mt.seqno_range().is_none());

        mt.put(b"a", 5, b"v");
        mt.put(b"b", 12, b"v");
        mt.put(b"c", 3, b"v");

        assert_eq!(mt.seqno_range(), Some((3, 12)));
    }

    #[test]
    fn test_empty() {
        let mt = MemTable::new();
        assert!(mt.is_empty());
        assert_eq!(mt.len(), 0);
        assert!(mt.sorted_entries().is_empty());
        assert!(mt.get(b"anything", None).is_none());
    }

    // ── Edge cases ──

    #[test]
    fn test_empty_key_and_value() {
        let mut mt = MemTable::new();
        mt.put(b"", 1, b"");

        let result = mt.get(b"", None).unwrap();
        assert!(result.key.user_key.is_empty());
        assert!(result.value.is_empty());
    }

    #[test]
    fn test_large_values() {
        let mut mt = MemTable::new();
        let big_value = vec![0xABu8; 1024 * 100]; // 100 KB
        mt.put(b"big", 1, &big_value);

        let result = mt.get(b"big", None).unwrap();
        assert_eq!(result.value.len(), 100 * 1024);
        assert_eq!(result.value[0], 0xAB);
    }

    #[test]
    fn test_many_entries() {
        let mut mt = MemTable::new();
        for i in 0..1000u32 {
            let key = format!("key_{:06}", i);
            mt.put(key.as_bytes(), i as u64 + 1, b"v");
        }

        assert_eq!(mt.len(), 1000);

        // Spot check
        let result = mt.get(b"key_000500", None).unwrap();
        assert_eq!(result.key.seqno, 501);

        // Verify sorted order
        let entries = mt.sorted_entries();
        for i in 1..entries.len() {
            assert!(entries[i - 1].key <= entries[i].key);
        }
    }
}
