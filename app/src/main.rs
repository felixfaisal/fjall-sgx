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

// #[no_mangle]
// pub extern "C" fn ocall_say_something(some_string: *const u8, len: usize) {
//     let slice = unsafe { std::slice::from_raw_parts(some_string, len) };
//     let msg = std::str::from_utf8(slice).unwrap_or("<invalid utf8>");
//     println!("[Host] Enclave says: {}", msg);
// }

// ─── OCALL Implementations ──────────────────────────────────────────

/// Empty OCALL for testing
#[no_mangle]
pub extern "C" fn ocall_empty() {}

/// Create a new file and return its file_id
#[no_mangle]
pub extern "C" fn ocall_create_file(file_id: *mut u64) -> SgxStatus {
    // TODO: Implement file creation logic
    // For now, return a dummy file_id
    unsafe {
        *file_id = 0;
    }
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
    // TODO: Implement file append logic
    // let slice = unsafe { std::slice::from_raw_parts(data, len) };
    unsafe {
        *bytes_written = len as u64;
    }
    SgxStatus::Success
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
    // TODO: Implement file read logic
    unsafe {
        *bytes_read = 0;
    }
    SgxStatus::Success
}

/// Get the size of a file
#[no_mangle]
pub extern "C" fn ocall_file_size(file_id: u64, size: *mut u64) -> SgxStatus {
    // TODO: Implement file size query
    unsafe {
        *size = 0;
    }
    SgxStatus::Success
}

/// Sync/flush a file to disk
#[no_mangle]
pub extern "C" fn ocall_sync(file_id: u64) -> SgxStatus {
    // TODO: Implement file sync logic
    SgxStatus::Success
}

/// Close a file
#[no_mangle]
pub extern "C" fn ocall_close_file(file_id: u64) -> SgxStatus {
    // TODO: Implement file close logic
    SgxStatus::Success
}

/// Delete a file
#[no_mangle]
pub extern "C" fn ocall_delete_file(file_id: u64) -> SgxStatus {
    // TODO: Implement file deletion logic
    SgxStatus::Success
}

/// Check if a file exists
#[no_mangle]
pub extern "C" fn ocall_file_exists(file_id: u64, exists: *mut u8) -> SgxStatus {
    // TODO: Implement file existence check
    unsafe {
        *exists = 0; // 0 = does not exist, 1 = exists
    }
    SgxStatus::Success
}

fn main() {
    let enclave = match SgxEnclave::create(ENCLAVE_FILE, true) {
        Ok(enclave) => {
            println!("[+] Init Enclave Successful {}!", enclave.eid());
            enclave
        }
        Err(err) => {
            println!("[-] Init Enclave Failed {}!", err.as_str());
            return;
        }
    };

    // Test the original say_something function
    println!("\n=== Testing say_something ===");
    let input_string = String::from("This is a normal world string passed into Enclave!\n");
    let mut retval = SgxStatus::Success;

    let result = unsafe {
        say_something(
            enclave.eid(),
            &mut retval,
            input_string.as_ptr() as *const u8,
            input_string.len(),
        )
    };
    match result {
        SgxStatus::Success => println!("[+] say_something ECall Success"),
        _ => println!("[-] say_something ECall Failed: {}", result.as_str()),
    }

    // Test database operations
    println!("\n=== Testing Database Operations ===");

    // 1. Initialize the database
    println!("\n[Host] Step 1: Initializing database...");
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
    println!("\n[Host] Step 2: Putting key-value pairs...");

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
                println!("[Host] ✓ Put success: '{}' => '{}'", key, value);
            }
            _ => {
                println!("[Host] ✗ Put failed for key '{}': {}", key, result.as_str());
            }
        }
    }

    // 3. Get the values back
    println!("\n[Host] Step 3: Getting values back...");

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
                    println!("[Host] ✗ Key '{}' not found!", key);
                } else {
                    let retrieved_value = String::from_utf8_lossy(&value_buf[..out_len]);
                    if retrieved_value == *expected_value {
                        println!(
                            "[Host] ✓ Get success: '{}' => '{}' (matches!)",
                            key, retrieved_value
                        );
                    } else {
                        println!(
                            "[Host] ✗ Get mismatch: '{}' => '{}' (expected '{}')",
                            key, retrieved_value, expected_value
                        );
                    }
                }
            }
            _ => {
                println!("[Host] ✗ Get failed for key '{}': {}", key, result.as_str());
            }
        }
    }

    // 4. Test getting a non-existent key
    println!("\n[Host] Step 4: Testing non-existent key...");
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
                println!(
                    "[Host] ✓ Correctly returned not found for key '{}'",
                    nonexistent_key
                );
            } else {
                println!("[Host] ✗ Unexpectedly found value for non-existent key");
            }
        }
        _ => {
            println!("[Host] ✗ Get failed: {}", result.as_str());
        }
    }

    println!("\n=== All tests completed ===");
}
