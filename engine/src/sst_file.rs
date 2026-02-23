// fjall-sgx/src/sst_file.rs
//
// SSTable file management — bridges lsm-sgx's pure SSTable logic
// with the storage abstraction layer.
//
// SstFile represents a persisted SSTable: it knows its FileId in
// the storage layer and can load/query the SSTable on demand.
//
// The write path:
//   1. Build SSTable bytes using lsm-sgx's SstWriter
//   2. Persist via SstFile::write() → storage.create_file() + storage.append()
//
// The read path:
//   1. Load bytes from storage via SstFile::load()
//   2. Parse and query using lsm-sgx's SstReader
//
// In the future, this is where block-level encryption/decryption
// would be injected (encrypt before write, decrypt after read).

use fjall_sgx_storage::{FileId, StorageError, StorageReader, StorageWriter};
use lsm_sgx::sstable::{SstError, SstOptions, SstReader, SstWriter};
use lsm_sgx::types::{InternalEntry, SeqNo, UserKey};

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SstFileError {
    Storage(StorageError),
    Sst(SstError),
}

impl From<StorageError> for SstFileError {
    fn from(e: StorageError) -> Self {
        SstFileError::Storage(e)
    }
}

impl From<SstError> for SstFileError {
    fn from(e: SstError) -> Self {
        SstFileError::Sst(e)
    }
}

// ─── SSTable File Metadata ──────────────────────────────────────

/// Metadata about a persisted SSTable.
///
/// Kept in memory so the engine can make decisions (e.g. "should I
/// check this SSTable?") without loading the full file.
#[derive(Debug, Clone)]
pub struct SstFileMeta {
    /// Storage layer file identifier
    pub file_id: FileId,

    /// Number of entries in the SSTable
    pub num_entries: u64,

    /// Sequence number range
    pub min_seqno: SeqNo,
    pub max_seqno: SeqNo,

    /// Key range (first and last user key)
    pub first_key: UserKey,
    pub last_key: UserKey,

    /// File size in bytes
    pub file_size: u64,
}

// ─── Write Path ─────────────────────────────────────────────────

/// Write sorted entries as a new SSTable file through the storage layer.
///
/// This is the flush path: when a memtable is full, its entries are
/// sorted and written here.
///
/// Returns metadata about the written SSTable.
pub fn write_sstable(
    storage: &mut dyn StorageWriter,
    entries: &[InternalEntry],
    opts: SstOptions,
) -> Result<SstFileMeta, SstFileError> {
    // Step 1: Build SSTable bytes in memory using lsm-sgx
    let mut writer = SstWriter::new(opts);
    for entry in entries {
        writer.add(entry)?;
    }
    let sst_bytes = writer.finish()?;

    // Step 2: Extract metadata from the in-memory bytes (before persisting)
    let sst_reader = SstReader::open(&sst_bytes)?;

    let first_key = sst_reader.first_user_key()?.unwrap_or_default();
    let last_key = sst_reader.last_user_key().cloned().unwrap_or_default();
    let (min_seqno, max_seqno) = sst_reader.seqno_range();
    let num_entries = sst_reader.num_entries();
    let file_size = sst_bytes.len() as u64;

    // Step 3: Persist through storage layer
    let file_id = storage.create_file()?;
    storage.append(file_id, &sst_bytes)?;
    storage.sync(file_id)?;
    storage.close_file(file_id)?;

    Ok(SstFileMeta {
        file_id,
        num_entries,
        min_seqno,
        max_seqno,
        first_key,
        last_key,
        file_size,
    })
}

// ─── Read Path ──────────────────────────────────────────────────

/// Load an SSTable from storage and query it for a key.
///
/// This loads the full SSTable into memory, parses it, and does a
/// point lookup. In the future, this could be optimized to load
/// only the index + bloom filter eagerly, and fetch data blocks
/// on demand.
pub fn query_sstable(
    storage: &dyn StorageReader,
    file_id: FileId,
    user_key: &[u8],
    seqno_limit: Option<SeqNo>,
) -> Result<Option<InternalEntry>, SstFileError> {
    let data = storage.read_all(file_id)?;
    let reader = SstReader::open(&data)?;
    Ok(reader.get(user_key, seqno_limit)?)
}

/// Load all entries from an SSTable (used in compaction).
pub fn read_all_entries(
    storage: &dyn StorageReader,
    file_id: FileId,
) -> Result<Vec<InternalEntry>, SstFileError> {
    let data = storage.read_all(file_id)?;
    let reader = SstReader::open(&data)?;
    Ok(reader.iter()?)
}

/// Load and return metadata for an existing SSTable file.
pub fn load_sstable_meta(
    storage: &dyn StorageReader,
    file_id: FileId,
) -> Result<SstFileMeta, SstFileError> {
    let data = storage.read_all(file_id)?;
    let reader = SstReader::open(&data)?;

    let first_key = reader.first_user_key()?.unwrap_or_default();
    let last_key = reader.last_user_key().cloned().unwrap_or_default();
    let (min_seqno, max_seqno) = reader.seqno_range();

    Ok(SstFileMeta {
        file_id,
        num_entries: reader.num_entries(),
        min_seqno,
        max_seqno,
        first_key,
        last_key,
        file_size: data.len() as u64,
    })
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fjall_sgx_storage::MemoryStorage;
    use lsm_sgx::sstable::SstOptions;
    use lsm_sgx::types::{InternalEntry, ValueType};

    fn make_entry(key: &str, seqno: u64, value: &str) -> InternalEntry {
        InternalEntry::put(key.as_bytes().to_vec(), seqno, value.as_bytes().to_vec())
    }

    fn make_tombstone(key: &str, seqno: u64) -> InternalEntry {
        InternalEntry::delete(key.as_bytes().to_vec(), seqno)
    }

    #[test]
    fn test_write_and_query_sstable() {
        let mut storage = MemoryStorage::new();

        // Sort entries in InternalKey order
        let entries = vec![
            make_entry("apple", 3, "red"),
            make_entry("banana", 2, "yellow"),
            make_entry("cherry", 1, "red"),
        ];

        let meta = write_sstable(&mut storage, &entries, SstOptions::default()).unwrap();

        assert_eq!(meta.num_entries, 3);
        assert_eq!(meta.first_key, b"apple");
        assert_eq!(meta.last_key, b"cherry");
        assert_eq!(meta.min_seqno, 1);
        assert_eq!(meta.max_seqno, 3);
        assert!(storage.exists(meta.file_id));

        // Query each key
        let result = query_sstable(&storage, meta.file_id, b"banana", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.value, b"yellow");

        let result = query_sstable(&storage, meta.file_id, b"apple", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.value, b"red");

        // Miss
        assert!(query_sstable(&storage, meta.file_id, b"date", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_write_and_read_all_entries() {
        let mut storage = MemoryStorage::new();

        let entries = vec![
            make_entry("aaa", 3, "val_a"),
            make_entry("bbb", 2, "val_b"),
            make_entry("ccc", 1, "val_c"),
        ];

        let meta = write_sstable(&mut storage, &entries, SstOptions::default()).unwrap();

        let all = read_all_entries(&storage, meta.file_id).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].key.user_key, b"aaa");
        assert_eq!(all[1].key.user_key, b"bbb");
        assert_eq!(all[2].key.user_key, b"ccc");
    }

    #[test]
    fn test_mvcc_through_storage() {
        let mut storage = MemoryStorage::new();

        // Same key, multiple versions (InternalKey sort: seqno DESC)
        let entries = vec![
            make_entry("key1", 10, "newest"),
            make_entry("key1", 5, "middle"),
            make_entry("key1", 1, "oldest"),
        ];

        let meta = write_sstable(&mut storage, &entries, SstOptions::default()).unwrap();

        // Latest version
        let result = query_sstable(&storage, meta.file_id, b"key1", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.value, b"newest");

        // Snapshot at seqno 7
        let result = query_sstable(&storage, meta.file_id, b"key1", Some(7))
            .unwrap()
            .unwrap();
        assert_eq!(result.value, b"middle");
    }

    #[test]
    fn test_tombstone_through_storage() {
        let mut storage = MemoryStorage::new();

        let entries = vec![make_entry("alive", 2, "data"), make_tombstone("dead", 3)];

        let meta = write_sstable(&mut storage, &entries, SstOptions::default()).unwrap();

        let result = query_sstable(&storage, meta.file_id, b"dead", None)
            .unwrap()
            .unwrap();
        assert_eq!(result.key.value_type, ValueType::Delete);
    }

    #[test]
    fn test_multiple_sstables() {
        let mut storage = MemoryStorage::new();

        // SSTable 1: keys a-c
        let entries1 = vec![
            make_entry("aaa", 1, "v1"),
            make_entry("bbb", 2, "v2"),
            make_entry("ccc", 3, "v3"),
        ];

        // SSTable 2: keys d-f
        let entries2 = vec![
            make_entry("ddd", 4, "v4"),
            make_entry("eee", 5, "v5"),
            make_entry("fff", 6, "v6"),
        ];

        let meta1 = write_sstable(&mut storage, &entries1, SstOptions::default()).unwrap();
        let meta2 = write_sstable(&mut storage, &entries2, SstOptions::default()).unwrap();

        assert_ne!(meta1.file_id, meta2.file_id);
        assert_eq!(storage.file_count(), 2);

        // Query across SSTables
        let r = query_sstable(&storage, meta1.file_id, b"bbb", None).unwrap();
        assert!(r.is_some());
        assert_eq!(r.unwrap().value, b"v2");

        let r = query_sstable(&storage, meta2.file_id, b"eee", None).unwrap();
        assert!(r.is_some());
        assert_eq!(r.unwrap().value, b"v5");

        // Key not in SSTable 1
        assert!(query_sstable(&storage, meta1.file_id, b"eee", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_load_meta() {
        let mut storage = MemoryStorage::new();

        let entries = vec![
            make_entry("first", 10, "v"),
            make_entry("middle", 20, "v"),
            make_entry("last", 30, "v"),
        ];

        let written_meta = write_sstable(&mut storage, &entries, SstOptions::default()).unwrap();

        // Reload metadata from storage
        let loaded_meta = load_sstable_meta(&storage, written_meta.file_id).unwrap();

        assert_eq!(loaded_meta.num_entries, written_meta.num_entries);
        assert_eq!(loaded_meta.first_key, written_meta.first_key);
        assert_eq!(loaded_meta.last_key, written_meta.last_key);
        assert_eq!(loaded_meta.min_seqno, written_meta.min_seqno);
        assert_eq!(loaded_meta.max_seqno, written_meta.max_seqno);
    }

    #[test]
    fn test_large_sstable_through_storage() {
        let mut storage = MemoryStorage::new();

        let mut entries = Vec::new();
        for i in 0..500u32 {
            let key = format!("key_{:06}", i);
            let val = format!("value_{:06}", i);
            entries.push(make_entry(&key, i as u64 + 1, &val));
        }

        let meta = write_sstable(
            &mut storage,
            &entries,
            SstOptions {
                block_size: 256,
                ..SstOptions::default()
            },
        )
        .unwrap();

        assert_eq!(meta.num_entries, 500);

        // Spot checks
        let r = query_sstable(&storage, meta.file_id, b"key_000250", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.key.seqno, 251);

        let r = query_sstable(&storage, meta.file_id, b"key_000000", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.key.seqno, 1);

        let r = query_sstable(&storage, meta.file_id, b"key_000499", None)
            .unwrap()
            .unwrap();
        assert_eq!(r.key.seqno, 500);

        // Full scan
        let all = read_all_entries(&storage, meta.file_id).unwrap();
        assert_eq!(all.len(), 500);
    }
}
