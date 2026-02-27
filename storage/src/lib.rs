// fjall-sgx-storage: Storage abstraction layer for fjall-sgx
//
// Provides:
//   traits      — StorageReader, StorageWriter, FileId
//   memory      — In-memory backend (testing)
//   std_fs      — Filesystem backend (integration testing)
//   crypto      — AES-256-GCM encryption/decryption + nonce derivation
//   encrypted   — Transparent encryption wrapper over any storage backend
//   ocall_bridge — OCALL-backed storage for SGX enclave I/O

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(
    all(not(feature = "std"), target_vendor = "teaclave"),
    feature(rustc_private)
)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate sgx_tstd as std;

// Traits and types are always available
pub mod traits;
pub use traits::{FileId, Storage, StorageError, StorageReader, StorageWriter};

// Concrete implementations only when feature is enabled
#[cfg(feature = "implementations")]
pub mod crypto;
#[cfg(feature = "implementations")]
pub mod encrypted;
#[cfg(feature = "implementations")]
pub mod memory;
#[cfg(feature = "implementations")]
pub mod std_fs;

#[cfg(feature = "implementations")]
pub use crypto::EncryptionKey;
#[cfg(feature = "implementations")]
pub use encrypted::EncryptedStorage;
#[cfg(feature = "implementations")]
pub use memory::MemoryStorage;
#[cfg(feature = "implementations")]
pub use std_fs::StdStorage;
