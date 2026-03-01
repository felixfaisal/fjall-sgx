// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![cfg_attr(not(target_vendor = "teaclave"), no_std)]
#![cfg_attr(target_vendor = "teaclave", feature(rustc_private))]

#[cfg(not(target_vendor = "teaclave"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_serialize;
extern crate sgx_trts;
extern crate sgx_tseal;
extern crate sgx_types;

use sgx_types::error::SgxStatus;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::slice;
use std::string::String;
use std::untrusted::fs;
use std::vec::Vec;

use fjall_sgx::db::{Db, DbConfig};
use fjall_sgx_storage::{FileId, StorageError, StorageReader, StorageWriter};

use sgx_serialize::opaque;
use sgx_tseal::seal::*;
use sgx_types::*;
use std::sync::Mutex;

// Global DB instance protected by a mutex
static DB_INSTANCE: Mutex<Option<Db<SgxOcallStorage>>> = Mutex::new(None);

// Looks like all ocalls must return sgx_status_t response
extern "C" {
    pub fn ocall_empty() -> SgxStatus;

    // Storage OCALLS for interacting with host
    pub fn ocall_create_file(file_id: *mut u64) -> SgxStatus;
    pub fn ocall_append(
        file_id: u64,
        data: *const u8,
        len: usize,
        bytes_written: *mut u64,
    ) -> SgxStatus;
    pub fn ocall_read_at(
        file_id: u64,
        offset: u64,
        buf: *mut u8,
        buf_len: usize,
        bytes_read: *mut usize,
    ) -> SgxStatus;
    pub fn ocall_file_size(file_id: u64, size: *mut u64) -> SgxStatus;
    pub fn ocall_sync(file_id: u64) -> SgxStatus;
    pub fn ocall_close_file(file_id: u64) -> SgxStatus;
    pub fn ocall_delete_file(file_id: u64) -> SgxStatus;
    pub fn ocall_file_exists(file_id: u64, exists: *mut u8) -> SgxStatus;

}

/// Storage implementation that uses SGX untrusted::fs for I/O.
///
/// Files are stored in ./data/ directory using untrusted filesystem access.
/// In SW mode, data is written as plaintext. In HW mode, data is sealed.
pub struct SgxOcallStorage {
    next_file_id: u64,
    data_dir: String,
}

impl SgxOcallStorage {
    pub fn new() -> Self {
        let data_dir = String::from("./data");

        // Create data directory if it doesn't exist
        let _ = fs::create_dir_all(&data_dir);

        Self {
            next_file_id: 1,
            data_dir,
        }
    }

    fn get_file_path(&self, file_id: FileId) -> String {
        format!("{}/file_{}.sealed", self.data_dir, file_id)
    }
}

impl StorageReader for SgxOcallStorage {
    fn read_at(&self, file_id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        // For read_at, we need to read the entire file, unseal it (if HW mode), then return the slice
        let full_data = self.read_all(file_id)?;

        let offset = offset as usize;
        if offset >= full_data.len() {
            return Ok(0);
        }

        let available = full_data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&full_data[offset..offset + to_read]);

        Ok(to_read)
    }

    fn file_size(&self, file_id: FileId) -> Result<u64, StorageError> {
        let path = self.get_file_path(file_id);

        match fs::metadata(&path) {
            Ok(metadata) => {
                let file_size = metadata.len();

                #[cfg(feature = "sw-mode")]
                {
                    // In SW mode, file size = plaintext size
                    Ok(file_size)
                }

                #[cfg(not(feature = "sw-mode"))]
                {
                    // In HW mode, need to unseal to get plaintext size
                    let plaintext = self.read_all(file_id)?;
                    Ok(plaintext.len() as u64)
                }
            }
            Err(_) => Ok(0), // File doesn't exist
        }
    }

    fn exists(&self, file_id: FileId) -> bool {
        let path = self.get_file_path(file_id);
        fs::metadata(&path).is_ok()
    }

    fn read_all(&self, file_id: FileId) -> Result<Vec<u8>, StorageError> {
        let path = self.get_file_path(file_id);

        // Read file using untrusted::fs
        let buffer =
            fs::read(&path).map_err(|e| StorageError::Io(format!("fs::read failed: {:?}", e)))?;

        if buffer.is_empty() {
            return Ok(Vec::new());
        }

        #[cfg(feature = "sw-mode")]
        {
            println!(
                "[Enclave] SW MODE: Read {} bytes (plaintext) from {}",
                buffer.len(),
                path
            );
            return Ok(buffer);
        }

        #[cfg(not(feature = "sw-mode"))]
        {
            println!(
                "[Enclave] HW MODE: Read {} sealed bytes from {}, unsealing...",
                buffer.len(),
                path
            );

            // Unseal to get plaintext
            let unsealed = UnsealedData::<[u8]>::unseal_from_bytes(buffer)
                .map_err(|e| StorageError::Io(format!("unseal failed: {:?}", e)))?;

            // Verify AAD matches (optional but recommended)
            let aad = unsealed.to_aad();
            if aad != b"fjall_sstable" {
                return Err(StorageError::Io(format!(
                    "AAD mismatch: expected 'fjall_sstable', got '{:?}'",
                    std::str::from_utf8(aad).unwrap_or("<invalid>")
                )));
            }

            // Extract plaintext
            let plaintext = unsealed.to_plaintext();
            println!(
                "[Enclave] Unsealed {} bytes → {} bytes",
                buffer.len(),
                plaintext.len()
            );

            Ok(plaintext.to_vec())
        }
    }
}

impl StorageWriter for SgxOcallStorage {
    fn create_file(&mut self) -> Result<FileId, StorageError> {
        let file_id = self.next_file_id;
        self.next_file_id += 1;

        println!("[Enclave] create_file() assigned file_id={}", file_id);
        Ok(file_id)
    }

    fn append(&mut self, file_id: FileId, data: &[u8]) -> Result<u64, StorageError> {
        let path = self.get_file_path(file_id);

        #[cfg(feature = "sw-mode")]
        {
            println!(
                "[Enclave] SW MODE: Writing {} bytes WITHOUT sealing to {}",
                data.len(),
                path
            );

            // In simulation mode: skip sealing, write plaintext directly
            fs::write(&path, data)
                .map_err(|e| StorageError::Io(format!("fs::write failed: {:?}", e)))?;

            println!("[Enclave] SW MODE: Wrote {} bytes (plaintext)", data.len());
            return Ok(data.len() as u64);
        }

        #[cfg(not(feature = "sw-mode"))]
        {
            println!(
                "[Enclave] HW MODE: Sealing {} bytes for file {}",
                data.len(),
                file_id
            );

            // In hardware mode: use real SGX sealing
            let sealed = match SealedData::<[u8]>::seal(
                data,
                Some(b"fjall_sstable"), // AAD for context
            ) {
                Ok(s) => {
                    println!("[Enclave] Seal successful");
                    s
                }
                Err(e) => {
                    println!("[Enclave] Seal FAILED: {:?}", e);
                    return Err(StorageError::Io(format!("seal failed: {:?}", e)));
                }
            };

            println!("[Enclave] Converting sealed data to bytes...");

            // Serialize sealed data to bytes
            let sealed_bytes = sealed.into_bytes().map_err(|e| {
                println!("[Enclave] into_bytes FAILED: {:?}", e);
                StorageError::Io(format!("seal into_bytes failed: {:?}", e))
            })?;

            println!(
                "[Enclave] Sealed {} bytes → {} bytes (overhead: {})",
                data.len(),
                sealed_bytes.len(),
                sealed_bytes.len() - data.len()
            );

            // Write sealed bytes to file
            fs::write(&path, &sealed_bytes)
                .map_err(|e| StorageError::Io(format!("fs::write failed: {:?}", e)))?;

            println!(
                "[Enclave] HW MODE: Wrote {} sealed bytes to {}",
                sealed_bytes.len(),
                path
            );
            Ok(sealed_bytes.len() as u64)
        }
    }

    fn sync(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // With untrusted::fs, sync is handled automatically
        // No explicit sync needed
        println!("[Enclave] sync() called for file {}", file_id);
        Ok(())
    }

    fn close_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // With untrusted::fs, files are automatically closed
        // No explicit close needed
        println!("[Enclave] close_file() called for file {}", file_id);
        Ok(())
    }

    fn delete_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        let path = self.get_file_path(file_id);

        fs::remove_file(&path)
            .map_err(|e| StorageError::Io(format!("fs::remove_file failed: {:?}", e)))?;

        println!("[Enclave] Deleted file {}", path);
        Ok(())
    }
}

// ─── Database API ───────────────────────────────────────────────────

/// Initialize the database
/// This should be called once before any put/get operations
#[no_mangle]
pub extern "C" fn db_init() -> SgxStatus {
    let ocall_storage = SgxOcallStorage::new();

    // Use very small memtable for testing (will flush to disk quickly)
    let config = DbConfig {
        memtable_size_limit: 200, // 200 bytes - triggers flush very quickly for testing
        ..DbConfig::default()
    };

    let db = Db::open(ocall_storage, config);

    let mut db_guard = match DB_INSTANCE.lock() {
        Ok(guard) => guard,
        Err(_) => return SgxStatus::Unexpected,
    };

    *db_guard = Some(db);
    println!("[Enclave] Database initialized with 512-byte memtable (testing mode)");

    SgxStatus::Success
}

/// Put a key-value pair into the database
#[no_mangle]
pub unsafe extern "C" fn db_put(
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> SgxStatus {
    // Convert raw pointers to slices
    let key_slice = slice::from_raw_parts(key, key_len);
    let value_slice = slice::from_raw_parts(value, value_len);

    // Get DB instance
    let mut db_guard = match DB_INSTANCE.lock() {
        Ok(guard) => guard,
        Err(_) => return SgxStatus::Unexpected,
    };

    let db = match db_guard.as_mut() {
        Some(db) => db,
        None => {
            println!("[Enclave] Error: DB not initialized. Call db_init() first.");
            return SgxStatus::InvalidParameter;
        }
    };

    // Perform the put operation
    match db.put(key_slice, value_slice) {
        Ok(_) => {
            println!(
                "[Enclave] Put success: key_len={}, value_len={}",
                key_len, value_len
            );
            SgxStatus::Success
        }
        Err(e) => {
            println!("[Enclave] Put failed: {:?}", e);
            SgxStatus::Unexpected
        }
    }
}

/// Get a value from the database by key
/// Returns the value length in out_len, or 0 if not found
#[no_mangle]
pub unsafe extern "C" fn db_get(
    key: *const u8,
    key_len: usize,
    value_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> SgxStatus {
    // Convert raw pointers to slices
    let key_slice = slice::from_raw_parts(key, key_len);

    // Get DB instance
    let db_guard = match DB_INSTANCE.lock() {
        Ok(guard) => guard,
        Err(_) => return SgxStatus::Unexpected,
    };

    let db = match db_guard.as_ref() {
        Some(db) => db,
        None => {
            println!("[Enclave] Error: DB not initialized. Call db_init() first.");
            return SgxStatus::InvalidParameter;
        }
    };

    // Perform the get operation
    match db.get(key_slice) {
        Ok(Some(value)) => {
            let copy_len = std::cmp::min(value.len(), buf_len);

            // Copy value to output buffer
            let out_slice = slice::from_raw_parts_mut(value_buf, copy_len);
            out_slice.copy_from_slice(&value[..copy_len]);

            *out_len = value.len();

            if value.len() > buf_len {
                println!(
                    "[Enclave] Get success but buffer too small: value_len={}, buf_len={}",
                    value.len(),
                    buf_len
                );
                return SgxStatus::InvalidParameter;
            }

            println!(
                "[Enclave] Get success: key_len={}, value_len={}",
                key_len,
                value.len()
            );
            SgxStatus::Success
        }
        Ok(None) => {
            println!("[Enclave] Get: key not found");
            *out_len = 0;
            SgxStatus::Success
        }
        Err(e) => {
            println!("[Enclave] Get failed: {:?}", e);
            SgxStatus::Unexpected
        }
    }
}
