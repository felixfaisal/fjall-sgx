// fjall-sgx: Encrypted LSM-tree storage engine for Intel SGX enclaves
//
// This crate ties together the core LSM data structures (lsm-sgx) with
// the storage abstraction (fjall-sgx-storage) to form a working engine.
//
// Architecture:
//   Write:  Db::put/delete → MemTable → (size threshold) → flush → SSTable (L0)
//   Read:   Db::get → MemTable → Frozen MemTables → L0 SSTables
//
// Modules:
//   memtable    — In-memory sorted buffer (BTreeMap-based)
//   flush       — MemTable → SSTable conversion
//   sst_file    — SSTable persistence through storage layer
//   compaction  — L0 merge compaction
//   db          — Public API tying everything together

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(
    all(not(feature = "std"), target_vendor = "teaclave"),
    feature(rustc_private)
)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod compaction;
pub mod db;
pub mod flush;
pub mod memtable;
pub mod sst_file;
