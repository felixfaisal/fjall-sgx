// fjall-sgx: Encrypted LSM-tree storage engine for Intel SGX enclaves
//
// This crate ties together the core LSM data structures (lsm-sgx) with
// the storage abstraction (fjall-sgx-storage) to form a working engine.
//
// Current status (Phase 2):
//   - sst_file: SSTable persistence through storage layer
//
// Future:
//   - memtable: In-memory sorted buffer (BTreeMap-based)
//   - flush: MemTable → SSTable conversion
//   - compaction: Merge SSTables across levels
//   - db: Public API (get/put/delete/scan)
//   - wal: Write-ahead log for crash recovery

pub mod sst_file;
