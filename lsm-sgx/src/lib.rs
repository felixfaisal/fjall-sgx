// lsm-sgx: SGX-aware LSM-tree implementation inspired by Fjall
//
// This crate is designed to be no_std compatible (with alloc).
// It contains only pure data structures and algorithms — no I/O,
// no filesystem access, no threads.
//
// This is the part that can live entirely inside an SGX enclave.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod types;
pub mod block;
pub mod bloom;
