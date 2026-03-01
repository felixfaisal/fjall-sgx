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
use std::io::{self, Write};
use std::slice;
use std::string::String;
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

/// Storage implementation that uses SGX OCALLs for I/O.
///
/// This bridges the extern "C" OCALL functions with the StorageWriter trait.
pub struct SgxOcallStorage;

impl SgxOcallStorage {
    pub fn new() -> Self {
        Self
    }
}

impl StorageReader for SgxOcallStorage {
    fn read_at(&self, file_id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        // For read_at, we need to read the entire sealed file, unseal it, then return the slice
        // This is because sealing is done at file-level, not block-level
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
        // Get sealed file size from host
        let mut sealed_size: u64 = 0;

        let status = unsafe { ocall_file_size(file_id, &mut sealed_size as *mut u64) };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL file_size failed: {:?}",
                status
            )));
        }

        // We need to unseal to get plaintext size
        // For now, read and unseal the file (could cache this)
        let plaintext = self.read_all(file_id)?;
        Ok(plaintext.len() as u64)
    }

    fn exists(&self, file_id: FileId) -> bool {
        let mut exists: u8 = 0;

        let status = unsafe { ocall_file_exists(file_id, &mut exists as *mut u8) };

        status == SgxStatus::Success && exists != 0
    }

    fn read_all(&self, file_id: FileId) -> Result<Vec<u8>, StorageError> {
        // First, get the sealed file size
        let mut sealed_size: u64 = 0;
        let status = unsafe { ocall_file_size(file_id, &mut sealed_size as *mut u64) };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL file_size failed: {:?}",
                status
            )));
        }

        if sealed_size == 0 {
            return Ok(Vec::new());
        }

        // Allocate buffer for sealed data
        let mut sealed_buffer = vec![0u8; sealed_size as usize];
        let mut bytes_read: usize = 0;

        // Read sealed bytes from host via OCALL
        let status = unsafe {
            ocall_read_at(
                file_id,
                0, // Read from beginning
                sealed_buffer.as_mut_ptr(),
                sealed_buffer.len(),
                &mut bytes_read as *mut usize,
            )
        };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL read_at failed: {:?}",
                status
            )));
        }

        sealed_buffer.truncate(bytes_read);

        println!("[Enclave] Read {} sealed bytes, unsealing...", bytes_read);

        // Unseal to get plaintext
        let unsealed = UnsealedData::<[u8]>::unseal_from_bytes(sealed_buffer)
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
            bytes_read,
            plaintext.len()
        );

        Ok(plaintext.to_vec())
    }
}

impl StorageWriter for SgxOcallStorage {
    fn create_file(&mut self) -> Result<FileId, StorageError> {
        let mut file_id: u64 = 0;

        let status = unsafe { ocall_create_file(&mut file_id as *mut u64) };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL create_file failed: {:?}",
                status
            )));
        }

        Ok(file_id)
    }

    fn append(&mut self, file_id: FileId, data: &[u8]) -> Result<u64, StorageError> {
        println!(
            "[Enclave] About to seal {} bytes for file {}",
            data.len(),
            file_id
        );

        // Seal plaintext data before sending to untrusted host
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

        // Send sealed bytes via OCALL
        let mut bytes_written: u64 = 0;
        let status = unsafe {
            ocall_append(
                file_id,
                sealed_bytes.as_ptr(),
                sealed_bytes.len(),
                &mut bytes_written as *mut u64,
            )
        };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL append failed: {:?}",
                status
            )));
        }

        Ok(bytes_written)
    }

    fn sync(&mut self, file_id: FileId) -> Result<(), StorageError> {
        let status = unsafe { ocall_sync(file_id) };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!("OCALL sync failed: {:?}", status)));
        }

        Ok(())
    }

    fn close_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        let status = unsafe { ocall_close_file(file_id) };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL close_file failed: {:?}",
                status
            )));
        }

        Ok(())
    }

    fn delete_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        let status = unsafe { ocall_delete_file(file_id) };

        if status != SgxStatus::Success {
            return Err(StorageError::Io(format!(
                "OCALL delete_file failed: {:?}",
                status
            )));
        }

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

/// Test SGX sealing in simulation mode
#[no_mangle]
pub extern "C" fn test_seal() -> SgxStatus {
    println!("[Enclave] Testing SGX seal/unseal...");

    // Simple test data
    let test_data: Vec<u8> = vec![1, 2, 3, 4, 5];
    println!("[Enclave] Original data: {:?}", test_data);

    // Step 1: Serialize using opaque encoding (required for SGX sealing)
    println!("[Enclave] Serializing with opaque::encode...");
    let encoded = match opaque::encode(&test_data) {
        Some(e) => {
            println!("[Enclave] ✓ Encoded to {} bytes", e.len());
            e
        }
        None => {
            println!("[Enclave] ✗ Encoding FAILED");
            return SgxStatus::Unexpected;
        }
    };

    // Step 2: Seal the encoded bytes
    println!("[Enclave] Attempting to seal...");
    let sealed = match SealedData::<[u8]>::seal(encoded.as_slice(), None::<&[u8]>) {
        Ok(s) => {
            println!("[Enclave] ✓ Seal successful!");
            s
        }
        Err(e) => {
            println!("[Enclave] ✗ Seal FAILED: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };

    // Convert to bytes
    println!("[Enclave] Converting to bytes...");
    let sealed_bytes = match sealed.into_bytes() {
        Ok(b) => {
            println!("[Enclave] ✓ Converted to {} bytes", b.len());
            b
        }
        Err(e) => {
            println!("[Enclave] ✗ into_bytes FAILED: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };

    // Try to unseal
    println!("[Enclave] Attempting to unseal...");
    let unsealed = match UnsealedData::<[u8]>::unseal_from_bytes(sealed_bytes) {
        Ok(u) => {
            println!("[Enclave] ✓ Unseal successful!");
            u
        }
        Err(e) => {
            println!("[Enclave] ✗ Unseal FAILED: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };

    // Step 4: Decode the unsealed bytes
    let plaintext = unsealed.to_plaintext();
    println!(
        "[Enclave] Decoding unsealed data ({} bytes)...",
        plaintext.len()
    );

    let decoded: Vec<u8> = match opaque::decode(plaintext) {
        Some(d) => {
            println!("[Enclave] ✓ Decoded successfully");
            d
        }
        None => {
            println!("[Enclave] ✗ Decoding FAILED");
            return SgxStatus::Unexpected;
        }
    };

    println!("[Enclave] Decoded data: {:?}", decoded);

    if decoded == test_data {
        println!("[Enclave] ✓✓✓ SUCCESS! Seal/unseal works in simulation mode!");
        SgxStatus::Success
    } else {
        println!(
            "[Enclave] ✗ Data mismatch! Expected {:?}, got {:?}",
            test_data, decoded
        );
        SgxStatus::Unexpected
    }
}
