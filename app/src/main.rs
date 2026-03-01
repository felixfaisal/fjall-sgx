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

extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::error::SgxStatus;
use sgx_types::types::*;
use sgx_urts::enclave::SgxEnclave;

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use log::{debug, error, info, trace, warn};

// Global file storage
// Maps file_id -> file path
lazy_static::lazy_static! {
    static ref FILE_STORAGE: Mutex<FileStore> = Mutex::new(FileStore::new());
}

struct FileStore {
    next_file_id: u64,
    files: HashMap<u64, PathBuf>,
    data_dir: PathBuf,
}

impl FileStore {
    fn new() -> Self {
        let data_dir = PathBuf::from("./data");
        fs::create_dir_all(&data_dir).expect("Failed to create data directory");

        Self {
            next_file_id: 1,
            files: HashMap::new(),
            data_dir,
        }
    }

    fn create_file(&mut self) -> u64 {
        let file_id = self.next_file_id;
        self.next_file_id += 1;

        let file_path = self.data_dir.join(format!("file_{}.sealed", file_id));
        self.files.insert(file_id, file_path);

        file_id
    }

    fn get_path(&self, file_id: u64) -> Option<PathBuf> {
        self.files.get(&file_id).cloned()
    }

    fn delete_file(&mut self, file_id: u64) -> bool {
        if let Some(path) = self.files.remove(&file_id) {
            let _ = fs::remove_file(path);
            true
        } else {
            false
        }
    }

    fn file_exists(&self, file_id: u64) -> bool {
        if let Some(path) = self.files.get(&file_id) {
            path.exists()
        } else {
            false
        }
    }
}

static ENCLAVE_FILE: &str = "enclave.signed.so";

extern "C" {
    fn say_something(
        eid: EnclaveId,
        retval: *mut SgxStatus,
        some_string: *const u8,
        len: usize,
    ) -> SgxStatus;

    fn db_init(eid: EnclaveId, retval: *mut SgxStatus) -> SgxStatus;

    fn db_put(
        eid: EnclaveId,
        retval: *mut SgxStatus,
        key: *const u8,
        key_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> SgxStatus;

    fn db_get(
        eid: EnclaveId,
        retval: *mut SgxStatus,
        key: *const u8,
        key_len: usize,
        value_buf: *mut u8,
        buf_len: usize,
        out_len: *mut usize,
    ) -> SgxStatus;
}

// ─── OCALL Implementations ──────────────────────────────────────────

/// Create a new file and return its file_id
#[no_mangle]
pub extern "C" fn ocall_create_file(file_id: *mut u64) -> SgxStatus {
    let mut store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    let new_file_id = store.create_file();
    unsafe {
        *file_id = new_file_id;
    }

    println!("[Host] Created file with ID: {}", new_file_id);
    SgxStatus::Success
}

/// Append data to a file
#[no_mangle]
pub extern "C" fn ocall_append(
    file_id: u64,
    data: *const u8,
    len: usize,
    bytes_written: *mut u64,
) -> SgxStatus {
    let store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    let path = match store.get_path(file_id) {
        Some(p) => p,
        None => {
            eprintln!("[Host] File ID {} not found", file_id);
            return SgxStatus::InvalidParameter;
        }
    };

    // Get sealed data from enclave
    let sealed_data = unsafe { std::slice::from_raw_parts(data, len) };

    // Append to file (host sees only opaque sealed bytes)
    match fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => match file.write_all(sealed_data) {
            Ok(_) => {
                unsafe {
                    *bytes_written = len as u64;
                }
                println!("[Host] Appended {} sealed bytes to file {}", len, file_id);
                SgxStatus::Success
            }
            Err(e) => {
                eprintln!("[Host] Failed to write to file: {}", e);
                SgxStatus::Unexpected
            }
        },
        Err(e) => {
            eprintln!("[Host] Failed to open file: {}", e);
            SgxStatus::Unexpected
        }
    }
}

/// Read data from a file at a specific offset
#[no_mangle]
pub extern "C" fn ocall_read_at(
    file_id: u64,
    offset: u64,
    buf: *mut u8,
    buf_len: usize,
    bytes_read: *mut usize,
) -> SgxStatus {
    let store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    let path = match store.get_path(file_id) {
        Some(p) => p,
        None => {
            eprintln!("[Host] File ID {} not found", file_id);
            return SgxStatus::InvalidParameter;
        }
    };

    match fs::File::open(&path) {
        Ok(mut file) => {
            // Seek to offset
            if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                eprintln!("[Host] Failed to seek: {}", e);
                return SgxStatus::Unexpected;
            }

            // Read sealed data
            let output_slice = unsafe { std::slice::from_raw_parts_mut(buf, buf_len) };
            match file.read(output_slice) {
                Ok(n) => {
                    unsafe {
                        *bytes_read = n;
                    }
                    println!(
                        "[Host] Read {} sealed bytes from file {} at offset {}",
                        n, file_id, offset
                    );
                    SgxStatus::Success
                }
                Err(e) => {
                    eprintln!("[Host] Failed to read from file: {}", e);
                    SgxStatus::Unexpected
                }
            }
        }
        Err(e) => {
            eprintln!("[Host] Failed to open file for reading: {}", e);
            SgxStatus::Unexpected
        }
    }
}

/// Get the size of a file
#[no_mangle]
pub extern "C" fn ocall_file_size(file_id: u64, size: *mut u64) -> SgxStatus {
    let store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    let path = match store.get_path(file_id) {
        Some(p) => p,
        None => {
            eprintln!("[Host] File ID {} not found", file_id);
            return SgxStatus::InvalidParameter;
        }
    };

    match fs::metadata(&path) {
        Ok(metadata) => {
            unsafe {
                *size = metadata.len();
            }
            SgxStatus::Success
        }
        Err(_) => {
            // File doesn't exist yet, return size 0
            unsafe {
                *size = 0;
            }
            SgxStatus::Success
        }
    }
}

/// Sync/flush a file to disk
#[no_mangle]
pub extern "C" fn ocall_sync(file_id: u64) -> SgxStatus {
    let store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    let path = match store.get_path(file_id) {
        Some(p) => p,
        None => {
            eprintln!("[Host] File ID {} not found", file_id);
            return SgxStatus::InvalidParameter;
        }
    };

    match fs::OpenOptions::new().write(true).open(&path) {
        Ok(file) => match file.sync_all() {
            Ok(_) => {
                println!("[Host] Synced file {}", file_id);
                SgxStatus::Success
            }
            Err(e) => {
                eprintln!("[Host] Failed to sync file: {}", e);
                SgxStatus::Unexpected
            }
        },
        Err(_) => {
            // File might not exist yet, that's ok
            SgxStatus::Success
        }
    }
}

/// Close a file
#[no_mangle]
pub extern "C" fn ocall_close_file(file_id: u64) -> SgxStatus {
    println!("[Host] Closed file {}", file_id);
    // In Rust, files are automatically closed when dropped
    // Nothing to do here explicitly
    SgxStatus::Success
}

/// Delete a file
#[no_mangle]
pub extern "C" fn ocall_delete_file(file_id: u64) -> SgxStatus {
    let mut store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    if store.delete_file(file_id) {
        println!("[Host] Deleted file {}", file_id);
        SgxStatus::Success
    } else {
        eprintln!("[Host] File ID {} not found for deletion", file_id);
        SgxStatus::InvalidParameter
    }
}

/// Check if a file exists
#[no_mangle]
pub extern "C" fn ocall_file_exists(file_id: u64, exists: *mut u8) -> SgxStatus {
    let store = match FILE_STORAGE.lock() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("[Host] Failed to lock file storage: {}", e);
            return SgxStatus::Unexpected;
        }
    };

    let file_exists = store.file_exists(file_id);
    unsafe {
        *exists = if file_exists { 1 } else { 0 };
    }

    SgxStatus::Success
}

fn main() {
    env_logger::init();
    let enclave = match SgxEnclave::create(ENCLAVE_FILE, true) {
        Ok(enclave) => {
            info!("[+] Init Enclave Successful {}!", enclave.eid());
            enclave
        }
        Err(err) => {
            error!("[-] Init Enclave Failed {}!", err.as_str());
            return;
        }
    };

    // Test database operations
    info!("\n=== Testing Database Operations ===");

    // 1. Initialize the database
    info!(target: "Host", "Step 1: Initializing database...");
    let mut retval = SgxStatus::Success;
    let result = unsafe { db_init(enclave.eid(), &mut retval) };

    match result {
        SgxStatus::Success => println!("[Host] ✓ Database initialized successfully"),
        _ => {
            println!(
                "[Host] ✗ Database initialization failed: {}",
                result.as_str()
            );
            return;
        }
    }

    // 2. Put some key-value pairs
    info!("\n[Host] Step 2: Putting key-value pairs...");

    let test_data = vec![
        ("hello", "world"),
        ("foo", "bar"),
        ("test_key", "test_value_123"),
        ("sgx", "secure enclave"),
    ];

    for (key, value) in &test_data {
        let mut retval = SgxStatus::Success;
        let result = unsafe {
            db_put(
                enclave.eid(),
                &mut retval,
                key.as_ptr(),
                key.len(),
                value.as_ptr(),
                value.len(),
            )
        };

        match result {
            SgxStatus::Success => {
                info!("[Host] ✓ Put success: '{}' => '{}'", key, value);
            }
            _ => {
                error!("[Host] ✗ Put failed for key '{}': {}", key, result.as_str());
            }
        }
    }

    // 3. Get the values back
    info!("\n[Host] Step 3: Getting values back...");

    for (key, expected_value) in &test_data {
        let mut retval = SgxStatus::Success;
        let mut value_buf = vec![0u8; 1024]; // Buffer for the value
        let mut out_len: usize = 0;

        let result = unsafe {
            db_get(
                enclave.eid(),
                &mut retval,
                key.as_ptr(),
                key.len(),
                value_buf.as_mut_ptr(),
                value_buf.len(),
                &mut out_len,
            )
        };

        match result {
            SgxStatus::Success => {
                if out_len == 0 {
                    warn!("[Host] ✗ Key '{}' not found!", key);
                } else {
                    let retrieved_value = String::from_utf8_lossy(&value_buf[..out_len]);
                    if retrieved_value == *expected_value {
                        info!(
                            "[Host] ✓ Get success: '{}' => '{}' (matches!)",
                            key, retrieved_value
                        );
                    } else {
                        error!(
                            "[Host] ✗ Get mismatch: '{}' => '{}' (expected '{}')",
                            key, retrieved_value, expected_value
                        );
                    }
                }
            }
            _ => {
                warn!("[Host] ✗ Get failed for key '{}': {}", key, result.as_str());
            }
        }
    }

    // 4. Test getting a non-existent key
    info!("\n[Host] Step 4: Testing non-existent key...");
    let nonexistent_key = "does_not_exist";
    let mut retval = SgxStatus::Success;
    let mut value_buf = vec![0u8; 1024];
    let mut out_len: usize = 0;

    let result = unsafe {
        db_get(
            enclave.eid(),
            &mut retval,
            nonexistent_key.as_ptr(),
            nonexistent_key.len(),
            value_buf.as_mut_ptr(),
            value_buf.len(),
            &mut out_len,
        )
    };

    match result {
        SgxStatus::Success => {
            if out_len == 0 {
                info!(
                    "[Host] ✓ Correctly returned not found for key '{}'",
                    nonexistent_key
                );
            } else {
                error!("[Host] ✗ Unexpectedly found value for non-existent key");
            }
        }
        _ => {
            error!("[Host] ✗ Get failed: {}", result.as_str());
        }
    }

    // 5. Test disk write (trigger flush) and read from disk
    info!("\n[Host] Step 5: Testing disk flush and read...");
    info!("[Host] Writing large values to trigger memtable flush (limit: 512 bytes)...");

    // Write enough data to exceed memtable limit (512 bytes)
    // Each entry has overhead, so a few large values will trigger flush
    let large_test_data = vec![
        ("disk_key_1", "x".repeat(100)), // 100 byte value
        ("disk_key_2", "y".repeat(100)), // 100 byte value
        ("disk_key_3", "z".repeat(100)), // 100 byte value
        ("disk_key_4", "a".repeat(100)), // 100 byte value
        ("disk_key_5", "b".repeat(100)), // 100 byte value
    ];

    info!(
        "[Host] Writing {} entries with 100-byte values...",
        large_test_data.len()
    );

    for (key, value) in &large_test_data {
        let mut retval = SgxStatus::Success;
        let result = unsafe {
            db_put(
                enclave.eid(),
                &mut retval,
                key.as_ptr(),
                key.len(),
                value.as_ptr(),
                value.len(),
            )
        };

        match result {
            SgxStatus::Success => {
                info!("[Host] ✓ Put success: '{}' => {}B", key, value.len());
            }
            _ => {
                error!("[Host] ✗ Put failed for key '{}': {}", key, result.as_str());
            }
        }
    }

    info!("\n[Host] MemTable should have flushed to disk. Now reading back from disk...");

    // Read back the data (should come from SSTable on disk)
    for (key, expected_value) in &large_test_data {
        let mut retval = SgxStatus::Success;
        let mut value_buf = vec![0u8; 1024];
        let mut out_len: usize = 0;

        let result = unsafe {
            db_get(
                enclave.eid(),
                &mut retval,
                key.as_ptr(),
                key.len(),
                value_buf.as_mut_ptr(),
                value_buf.len(),
                &mut out_len,
            )
        };

        match result {
            SgxStatus::Success => {
                if out_len == 0 {
                    error!("[Host] ✗ Key '{}' not found on disk!", key);
                } else {
                    let retrieved_value = String::from_utf8_lossy(&value_buf[..out_len]);
                    if retrieved_value == *expected_value {
                        info!(
                            "[Host] ✓ Disk read success: '{}' => {}B (matches!)",
                            key, out_len
                        );
                    } else {
                        error!(
                            "[Host] ✗ Disk read mismatch: '{}' (expected {}B, got {}B)",
                            key,
                            expected_value.len(),
                            out_len
                        );
                    }
                }
            }
            _ => {
                error!("[Host] ✗ Get failed for key '{}': {}", key, result.as_str());
            }
        }
    }

    info!("\n[Host] Checking if sealed files were created on disk...");
    let data_dir = std::path::Path::new("./data");
    if data_dir.exists() {
        match std::fs::read_dir(data_dir) {
            Ok(entries) => {
                let files: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                info!("[Host] ✓ Found {} sealed file(s) in ./data/", files.len());
                for entry in files {
                    let metadata = entry.metadata().ok();
                    let size = metadata.map(|m| m.len()).unwrap_or(0);
                    info!(
                        "[Host]   - {} ({} bytes)",
                        entry.file_name().to_string_lossy(),
                        size
                    );
                }
            }
            Err(e) => {
                error!("[Host] ✗ Failed to read data directory: {}", e);
            }
        }
    } else {
        error!("[Host] ✗ No ./data directory found");
    }

    info!("\n=== All tests completed ===");
}
