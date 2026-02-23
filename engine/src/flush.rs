// fjall-sgx/src/flush.rs
//
// Flush: convert a frozen MemTable into a persisted SSTable.
//
// This is the bridge between the in-memory world and the on-disk world.
// When a memtable exceeds its size threshold:
//
//   1. The active memtable is frozen (becomes read-only)
//   2. A new empty memtable takes its place for incoming writes
//   3. The frozen memtable's entries are flushed to a new SSTable at Level 0
//   4. The frozen memtable can then be dropped
//
// The flush itself is straightforward:
//   - MemTable.sorted_entries() gives entries in InternalKey order
//   - write_sstable() builds and persists the SSTable
//
// The result is an SstFileMeta with the new SSTable's FileId and metadata.

use fjall_sgx_storage::StorageWriter;
use lsm_sgx::sstable::SstOptions;

use crate::memtable::MemTable;
use crate::sst_file::{self, SstFileError, SstFileMeta};

/// Flush a memtable to a new SSTable file.
///
/// Takes ownership of the entries (via sorted_entries()) and writes them
/// through the storage layer. Returns metadata about the new SSTable.
///
/// The caller is responsible for:
///   - Freezing the memtable before calling this
///   - Registering the returned SstFileMeta in the level manifest
///   - Dropping the old memtable after flush completes
pub fn flush_memtable(
    memtable: &MemTable,
    storage: &mut dyn StorageWriter,
    opts: SstOptions,
) -> Result<SstFileMeta, SstFileError> {
    let entries = memtable.sorted_entries();

    if entries.is_empty() {
        return Err(SstFileError::Sst(lsm_sgx::sstable::SstError::EmptyTable));
    }

    sst_file::write_sstable(storage, &entries, opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fjall_sgx_storage::{MemoryStorage, StorageReader};
    use lsm_sgx::types::ValueType;

    #[test]
    fn test_flush_basic() {
        let mut mt = MemTable::new();
        mt.put(b"apple", 1, b"red");
        mt.put(b"banana", 2, b"yellow");
        mt.put(b"cherry", 3, b"red");

        let mut storage = MemoryStorage::new();
        let meta = flush_memtable(&mt, &mut storage, SstOptions::default()).unwrap();

        assert_eq!(meta.num_entries, 3);
        assert_eq!(meta.first_key, b"apple");
        assert_eq!(meta.last_key, b"cherry");
        assert_eq!(meta.min_seqno, 1);
        assert_eq!(meta.max_seqno, 3);
        assert!(storage.exists(meta.file_id));
    }

    #[test]
    fn test_flush_preserves_versions() {
        let mut mt = MemTable::new();
        mt.put(b"key1", 1, b"v1");
        mt.put(b"key1", 5, b"v5");
        mt.put(b"key1", 10, b"v10");

        let mut storage = MemoryStorage::new();
        let meta = flush_memtable(&mt, &mut storage, SstOptions::default()).unwrap();

        // All three versions should be in the SSTable
        assert_eq!(meta.num_entries, 3);

        // Verify we can query with snapshot
        let result = sst_file::query_sstable(&storage, meta.file_id, b"key1", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.value, b"v10");

        let result = sst_file::query_sstable(&storage, meta.file_id, b"key1", Some(7))
            .unwrap()
            .unwrap();
        assert_eq!(result.value, b"v5");
    }

    #[test]
    fn test_flush_preserves_tombstones() {
        let mut mt = MemTable::new();
        mt.put(b"alive", 1, b"data");
        mt.delete(b"dead", 2);

        let mut storage = MemoryStorage::new();
        let meta = flush_memtable(&mt, &mut storage, SstOptions::default()).unwrap();

        let result = sst_file::query_sstable(&storage, meta.file_id, b"dead", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.key.value_type, ValueType::Delete);
    }

    #[test]
    fn test_flush_empty_memtable_errors() {
        let mt = MemTable::new();
        let mut storage = MemoryStorage::new();

        let result = flush_memtable(&mt, &mut storage, SstOptions::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_flush_large_memtable() {
        let mut mt = MemTable::new();
        for i in 0..500u32 {
            let key = format!("key_{:06}", i);
            let val = format!("value_{:06}", i);
            mt.put(key.as_bytes(), i as u64 + 1, val.as_bytes());
        }

        let mut storage = MemoryStorage::new();
        let meta = flush_memtable(
            &mt,
            &mut storage,
            SstOptions {
                block_size: 256,
                ..SstOptions::default()
            },
        )
        .unwrap();

        assert_eq!(meta.num_entries, 500);

        // Spot check through storage
        let result = sst_file::query_sstable(&storage, meta.file_id, b"key_000250", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.key.seqno, 251);
    }
}
