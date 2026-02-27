// lsm-sgx: SGX-aware LSM-tree implementation inspired by Fjall
//
// This crate supports both standard Rust (std) and SGX environments (sgx_tstd).
// It contains only pure data structures and algorithms — no I/O,
// no filesystem access, no threads.
//
// This is the part that can live entirely inside an SGX enclave.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(
    all(not(feature = "std"), target_vendor = "teaclave"),
    feature(rustc_private)
)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod block;
pub mod bloom;
pub mod sstable;
pub mod types;
