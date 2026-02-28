// fjall-sgx/src/compaction.rs
//
// Compaction: merge multiple SSTables into fewer, larger ones.
//
// Without compaction, the LSM-tree accumulates L0 SSTables forever.
// Each flush adds one. Reads degrade because every L0 SSTable must be
// checked (they can have overlapping key ranges). Compaction fixes this
// by merging SSTables, deduplicating versions, and removing obsolete data.
//
// This module provides:
//
//   merge_entries()      — K-way merge of sorted entry streams
//   compact_l0()         — merge all L0 SSTables into one
//
// The merge follows these rules:
//   1. Entries are merged in InternalKey order (user_key ASC, seqno DESC)
//   2. For the same user_key, only the newest version is kept
//      (unless a seqno fence protects older versions — future snapshot support)
//   3. Tombstones (Delete markers) are kept if there might be older data
//      below that they need to mask. At L0 with no lower levels, tombstones
//      for which we've seen the key can be dropped.
//   4. The merged output is written as a new SSTable; old inputs are deleted.
//
// K-way merge strategy:
//   We use a simple approach: load all entries from all input SSTables into
//   a single Vec, sort, then deduplicate. This works well for L0 compaction
//   where the total data fits comfortably in memory (L0 is typically < 640 MB).
//
//   For larger compactions (L1+), a streaming merge with a min-heap would be
//   needed — that's a future optimization.

use fjall_sgx_storage::{FileId, StorageReader, StorageWriter};
use lsm_sgx::sstable::SstOptions;
use lsm_sgx::types::{InternalEntry, ValueType};
use std::vec::Vec;

use crate::sst_file::{self, SstFileError, SstFileMeta};

// ─── Merge Logic ────────────────────────────────────────────────

/// Merge multiple sorted entry streams into one, deduplicating versions.
///
/// Input: multiple Vec<InternalEntry>, each internally sorted by InternalKey.
/// (Typically each Vec comes from one SSTable via read_all_entries().)
///
/// Output: single sorted Vec<InternalEntry> with only the newest version
/// of each user_key retained.
///
/// If `drop_tombstones` is true, Delete markers are removed from the output.
/// This is safe when compacting the bottommost level (no older data below
/// that the tombstone needs to mask).
pub fn merge_entries(
    streams: Vec<Vec<InternalEntry>>,
    drop_tombstones: bool,
) -> Vec<InternalEntry> {
    // Phase 1: Collect all entries into one vec
    let total: usize = streams.iter().map(|s| s.len()).sum();
    let mut all = Vec::with_capacity(total);
    for stream in streams {
        all.extend(stream);
    }

    // Phase 2: Sort by InternalKey (user_key ASC, seqno DESC)
    all.sort_by(|a, b| a.key.cmp(&b.key));

    // Phase 3: Deduplicate — keep only the newest version per user_key
    let mut output = Vec::with_capacity(all.len());
    let mut last_user_key: Option<&[u8]> = None;

    for entry in &all {
        let dominated = match last_user_key {
            Some(prev) => prev == entry.key.user_key.as_slice(),
            None => false,
        };

        if dominated {
            // This is an older version of a key we've already emitted.
            // Skip it — the newer version (higher seqno) was already output.
            continue;
        }

        // This is the newest version of this user_key
        last_user_key = Some(&entry.key.user_key);

        // Optionally drop tombstones at the bottom level
        if drop_tombstones && entry.key.value_type == ValueType::Delete {
            continue;
        }

        output.push(entry.clone());
    }

    output
}

// ─── L0 Compaction ──────────────────────────────────────────────

/// Result of an L0 compaction.
#[derive(Debug)]
pub struct CompactionResult {
    /// The new SSTable(s) produced by compaction.
    /// For L0 compaction this is typically a single SSTable.
    pub new_sstables: Vec<SstFileMeta>,

    /// FileIds of the old SSTables that were compacted and can be deleted.
    pub obsolete_file_ids: Vec<FileId>,

    /// Number of input entries (before dedup)
    pub input_entries: u64,

    /// Number of output entries (after dedup)
    pub output_entries: u64,
}

/// Compact all L0 SSTables into a single new SSTable.
///
/// This is the simplest compaction strategy:
///   1. Read all entries from all L0 SSTables
///   2. Merge and deduplicate (keep newest version per user_key)
///   3. Write merged entries as a new SSTable
///   4. Return the new SSTable + list of old ones to delete
///
/// The caller (Db) is responsible for:
///   - Replacing l0_sstables with the compaction output
///   - Deleting the obsolete files via storage.delete_file()
///
/// `drop_tombstones`: if true, tombstones are removed since there are
/// no lower levels for them to mask. Set to true when L0 is the only level.
pub fn compact_l0(
    l0_sstables: &[SstFileMeta],
    storage: &mut (impl StorageReader + StorageWriter),
    sst_opts: SstOptions,
    drop_tombstones: bool,
) -> Result<CompactionResult, SstFileError> {
    if l0_sstables.len() <= 1 {
        // Nothing to compact — already a single SSTable (or empty)
        return Ok(CompactionResult {
            new_sstables: l0_sstables.to_vec(),
            obsolete_file_ids: Vec::new(),
            input_entries: l0_sstables.first().map_or(0, |s| s.num_entries),
            output_entries: l0_sstables.first().map_or(0, |s| s.num_entries),
        });
    }

    // Step 1: Read all entries from all input SSTables
    let mut streams = Vec::with_capacity(l0_sstables.len());
    let mut input_entries: u64 = 0;

    for sst_meta in l0_sstables {
        let entries = sst_file::read_all_entries(storage, sst_meta.file_id)?;
        input_entries += entries.len() as u64;
        streams.push(entries);
    }

    // Step 2: Merge and deduplicate
    let merged = merge_entries(streams, drop_tombstones);
    let output_entries = merged.len() as u64;

    // Step 3: Write new SSTable (if any entries remain after dedup)
    let obsolete_file_ids: Vec<FileId> = l0_sstables.iter().map(|s| s.file_id).collect();

    if merged.is_empty() {
        // All entries were tombstones that got dropped
        return Ok(CompactionResult {
            new_sstables: Vec::new(),
            obsolete_file_ids,
            input_entries,
            output_entries: 0,
        });
    }

    let new_meta = sst_file::write_sstable(storage, &merged, sst_opts)?;

    Ok(CompactionResult {
        new_sstables: vec![new_meta],
        obsolete_file_ids,
        input_entries,
        output_entries,
    })
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fjall_sgx_storage::MemoryStorage;
    use lsm_sgx::types::InternalEntry;

    fn make_entry(key: &str, seqno: u64, value: &str) -> InternalEntry {
        InternalEntry::put(key.as_bytes().to_vec(), seqno, value.as_bytes().to_vec())
    }

    fn make_tombstone(key: &str, seqno: u64) -> InternalEntry {
        InternalEntry::delete(key.as_bytes().to_vec(), seqno)
    }

    // ── merge_entries tests ──

    #[test]
    fn test_merge_single_stream() {
        let stream = vec![
            make_entry("aaa", 1, "a"),
            make_entry("bbb", 2, "b"),
            make_entry("ccc", 3, "c"),
        ];

        let result = merge_entries(vec![stream], false);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].key.user_key, b"aaa");
        assert_eq!(result[1].key.user_key, b"bbb");
        assert_eq!(result[2].key.user_key, b"ccc");
    }

    #[test]
    fn test_merge_two_streams_no_overlap() {
        let s1 = vec![make_entry("aaa", 1, "a"), make_entry("ccc", 2, "c")];
        let s2 = vec![make_entry("bbb", 3, "b"), make_entry("ddd", 4, "d")];

        let result = merge_entries(vec![s1, s2], false);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].key.user_key, b"aaa");
        assert_eq!(result[1].key.user_key, b"bbb");
        assert_eq!(result[2].key.user_key, b"ccc");
        assert_eq!(result[3].key.user_key, b"ddd");
    }

    #[test]
    fn test_merge_deduplicates_versions() {
        // Stream 1: older SSTable
        let s1 = vec![
            make_entry("key1", 1, "old_value"),
            make_entry("key2", 2, "only_version"),
        ];
        // Stream 2: newer SSTable
        let s2 = vec![
            make_entry("key1", 5, "new_value"),
            make_entry("key3", 6, "only_version"),
        ];

        let result = merge_entries(vec![s1, s2], false);
        assert_eq!(result.len(), 3);

        // key1: only newest (seqno 5)
        assert_eq!(result[0].key.user_key, b"key1");
        assert_eq!(result[0].key.seqno, 5);
        assert_eq!(result[0].value, b"new_value");

        // key2: only version
        assert_eq!(result[1].key.user_key, b"key2");

        // key3: only version
        assert_eq!(result[2].key.user_key, b"key3");
    }

    #[test]
    fn test_merge_three_versions_of_same_key() {
        let s1 = vec![make_entry("key", 1, "v1")];
        let s2 = vec![make_entry("key", 5, "v5")];
        let s3 = vec![make_entry("key", 10, "v10")];

        let result = merge_entries(vec![s1, s2, s3], false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key.seqno, 10);
        assert_eq!(result[0].value, b"v10");
    }

    #[test]
    fn test_merge_tombstone_wins_over_put() {
        // Older put, newer tombstone
        let s1 = vec![make_entry("key", 1, "value")];
        let s2 = vec![make_tombstone("key", 5)];

        let result = merge_entries(vec![s1, s2], false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key.value_type, ValueType::Delete);
        assert_eq!(result[0].key.seqno, 5);
    }

    #[test]
    fn test_merge_drop_tombstones() {
        let s1 = vec![
            make_entry("alive", 1, "data"),
            make_entry("dead", 2, "old_data"),
        ];
        let s2 = vec![make_tombstone("dead", 5)];

        // With drop_tombstones=true, the tombstone is removed
        let result = merge_entries(vec![s1, s2], true);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key.user_key, b"alive");
    }

    #[test]
    fn test_merge_keep_tombstones() {
        let s1 = vec![make_entry("key", 1, "old")];
        let s2 = vec![make_tombstone("key", 5)];

        // With drop_tombstones=false, tombstone is preserved
        let result = merge_entries(vec![s1, s2], false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key.value_type, ValueType::Delete);
    }

    #[test]
    fn test_merge_empty_streams() {
        let result = merge_entries(vec![], false);
        assert!(result.is_empty());

        let result = merge_entries(vec![vec![], vec![]], false);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_all_tombstones_dropped() {
        let s1 = vec![make_tombstone("a", 1)];
        let s2 = vec![make_tombstone("b", 2)];

        let result = merge_entries(vec![s1, s2], true);
        assert!(result.is_empty());
    }

    // ── compact_l0 tests ──

    fn write_test_sst(storage: &mut MemoryStorage, entries: &[InternalEntry]) -> SstFileMeta {
        sst_file::write_sstable(storage, entries, SstOptions::default()).unwrap()
    }

    #[test]
    fn test_compact_l0_single_sstable_noop() {
        let mut storage = MemoryStorage::new();
        let meta = write_test_sst(&mut storage, &[make_entry("a", 1, "v")]);

        let result =
            compact_l0(&[meta.clone()], &mut storage, SstOptions::default(), false).unwrap();

        assert!(result.obsolete_file_ids.is_empty());
        assert_eq!(result.new_sstables.len(), 1);
        assert_eq!(result.new_sstables[0].file_id, meta.file_id);
    }

    #[test]
    fn test_compact_l0_merges_two_sstables() {
        let mut storage = MemoryStorage::new();

        let meta1 = write_test_sst(
            &mut storage,
            &[make_entry("aaa", 1, "a_old"), make_entry("bbb", 2, "b")],
        );
        let meta2 = write_test_sst(
            &mut storage,
            &[make_entry("aaa", 5, "a_new"), make_entry("ccc", 6, "c")],
        );

        let result = compact_l0(
            &[meta2, meta1], // newest first (as Db stores them)
            &mut storage,
            SstOptions::default(),
            false,
        )
        .unwrap();

        assert_eq!(result.obsolete_file_ids.len(), 2);
        assert_eq!(result.new_sstables.len(), 1);
        assert_eq!(result.input_entries, 4);
        assert_eq!(result.output_entries, 3); // aaa deduped

        // Verify the new SSTable has correct content
        let new_id = result.new_sstables[0].file_id;
        let r = sst_file::query_sstable(&storage, new_id, b"aaa", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.value, b"a_new");
        assert_eq!(r.key.seqno, 5);

        let r = sst_file::query_sstable(&storage, new_id, b"bbb", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.value, b"b");

        let r = sst_file::query_sstable(&storage, new_id, b"ccc", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.value, b"c");
    }

    #[test]
    fn test_compact_l0_drops_tombstones() {
        let mut storage = MemoryStorage::new();

        let meta1 = write_test_sst(
            &mut storage,
            &[make_entry("alive", 1, "data"), make_entry("dead", 2, "old")],
        );
        let meta2 = write_test_sst(&mut storage, &[make_tombstone("dead", 5)]);

        let result = compact_l0(
            &[meta2, meta1],
            &mut storage,
            SstOptions::default(),
            true, // drop tombstones
        )
        .unwrap();

        assert_eq!(result.output_entries, 1);
        let new_id = result.new_sstables[0].file_id;

        // "alive" survives
        let r = sst_file::query_sstable(&storage, new_id, b"alive", None).unwrap();
        assert!(r.is_some());

        // "dead" is gone (tombstone dropped)
        let r = sst_file::query_sstable(&storage, new_id, b"dead", None).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn test_compact_l0_preserves_tombstones() {
        let mut storage = MemoryStorage::new();

        let meta1 = write_test_sst(&mut storage, &[make_entry("key", 1, "val")]);
        let meta2 = write_test_sst(&mut storage, &[make_tombstone("key", 5)]);

        let result = compact_l0(
            &[meta2, meta1],
            &mut storage,
            SstOptions::default(),
            false, // keep tombstones
        )
        .unwrap();

        assert_eq!(result.output_entries, 1);
        let new_id = result.new_sstables[0].file_id;
        let r = sst_file::query_sstable(&storage, new_id, b"key", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.key.value_type, ValueType::Delete);
    }

    #[test]
    fn test_compact_l0_many_overlapping_sstables() {
        let mut storage = MemoryStorage::new();

        // 5 SSTables, all writing to overlapping key space
        let mut metas = Vec::new();
        for batch in 0..5u32 {
            let entries: Vec<InternalEntry> = (0..20u32)
                .map(|i| {
                    let key = format!("key_{:04}", i);
                    let val = format!("batch{}_{}", batch, i);
                    let seqno = (batch * 20 + i + 1) as u64;
                    make_entry(&key, seqno, &val)
                })
                .collect();
            metas.push(write_test_sst(&mut storage, &entries));
        }

        // Reverse so newest is first (as Db stores them)
        metas.reverse();

        let result = compact_l0(&metas, &mut storage, SstOptions::default(), true).unwrap();

        assert_eq!(result.obsolete_file_ids.len(), 5);
        assert_eq!(result.input_entries, 100);
        assert_eq!(result.output_entries, 20); // 20 unique keys

        // Verify newest versions survive
        let new_id = result.new_sstables[0].file_id;
        for i in 0..20u32 {
            let key = format!("key_{:04}", i);
            let r = sst_file::query_sstable(&storage, new_id, key.as_bytes(), None)
                .unwrap()
                .unwrap();
            // Batch 4 (last written) should be the newest
            let expected_val = format!("batch4_{}", i);
            assert_eq!(
                r.value,
                expected_val.as_bytes(),
                "key {} has wrong value",
                key
            );
        }
    }

    #[test]
    fn test_compact_l0_empty() {
        let mut storage = MemoryStorage::new();
        let result = compact_l0(&[], &mut storage, SstOptions::default(), false).unwrap();
        assert!(result.new_sstables.is_empty());
        assert!(result.obsolete_file_ids.is_empty());
    }

    #[test]
    fn test_compact_l0_all_tombstones_produces_empty() {
        let mut storage = MemoryStorage::new();

        let meta1 = write_test_sst(
            &mut storage,
            &[make_tombstone("a", 1), make_tombstone("b", 2)],
        );
        let meta2 = write_test_sst(&mut storage, &[make_tombstone("c", 3)]);

        let result =
            compact_l0(&[meta2, meta1], &mut storage, SstOptions::default(), true).unwrap();

        assert_eq!(result.output_entries, 0);
        assert!(result.new_sstables.is_empty());
        assert_eq!(result.obsolete_file_ids.len(), 2);
    }
}
