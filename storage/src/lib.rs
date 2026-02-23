// fjall-sgx-storage: Storage abstraction layer for fjall-sgx
//
// Provides:
//   traits   — StorageReader, StorageWriter, FileId
//   memory   — In-memory backend (testing)
//   std_fs   — Filesystem backend (integration testing)
//
// Future:
//   sgx      — OCALL-backed backend with encryption (SGX production)

pub mod memory;
pub mod std_fs;
pub mod traits;

// Re-export the most commonly used items
pub use memory::MemoryStorage;
pub use std_fs::StdStorage;
pub use traits::{FileId, Storage, StorageError, StorageReader, StorageWriter};
