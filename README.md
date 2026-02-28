# fjall-sgx

Encrypted LSM-tree key-value store for Intel SGX enclaves, inspired by [Fjall](https://github.com/fjall-rs/fjall).

## Overview

fjall-sgx is a secure key-value database that runs inside Intel SGX enclaves. It implements an LSM-tree (Log-Structured Merge-tree) architecture with encryption, allowing data to be stored and queried while maintaining confidentiality and integrity guarantees provided by SGX.

## Quick Start

### Using Docker (Recommended)

Build and run the SGX simulation environment:

```bash
# Build the Docker image
docker build -t fjall-sgx .

# Run interactive shell in container
docker run -it -v $(pwd):/root/fjall-sgx fjall-sgx

# Inside the container
cd /root/fjall-sgx
source /opt/intel/sgxsdk/environment
make
cd bin
./app
```

### Local Build (Requires SGX SDK)

If you have Intel SGX SDK installed locally:

```bash
source /opt/intel/sgxsdk/environment
make
cd bin
./app
```

## Project Structure

```
fjall-sgx/
├── lsm-sgx/           # Core LSM data structures (blocks, bloom filters, SSTables)
│   └── src/           # Pure data structures, no I/O - runs inside enclave
├── storage/           # Storage abstraction layer
│   └── src/
│       ├── traits.rs      # StorageReader/StorageWriter traits
│       ├── memory.rs      # In-memory implementation (testing)
│       ├── std_fs.rs      # Filesystem implementation
│       ├── crypto.rs      # AES-256-GCM encryption
│       └── encrypted.rs   # Transparent encryption wrapper
├── engine/            # LSM engine tying everything together
│   └── src/
│       ├── db.rs          # Main DB API (put/get)
│       ├── memtable.rs    # In-memory write buffer (BTreeMap)
│       ├── flush.rs       # MemTable → SSTable conversion
│       ├── sst_file.rs    # SSTable persistence
│       └── compaction.rs  # L0 merge compaction
├── enclave/           # SGX enclave (trusted code)
│   ├── enclave.edl    # EDL interface definition (ECALLs/OCALLs)
│   └── src/lib.rs     # Database ECALLs and OCALL storage impl
├── app/               # Untrusted host application
│   └── src/main.rs    # OCALL implementations and test code
└── sgx_edl/           # SGX EDL files from Teaclave SDK
```

## Architecture

**Write Path:**
```
App → ECALL → Enclave DB → MemTable → (flush) → SSTable → OCALL → Host Disk
```

**Read Path:**
```
App → ECALL → Enclave DB → MemTable → Frozen MemTables → SSTables → OCALL → Host Disk
```

**Data Flow:**
1. **Trusted (Enclave)**: All data is plaintext, encryption keys are sealed
2. **Boundary (OCALLs)**: Data is encrypted before crossing enclave boundary
3. **Untrusted (Host)**: Only ciphertext is stored on disk

## Features

- **LSM-Tree Architecture**: In-memory MemTable with SSTable persistence
- **Encryption**: AES-256-GCM encryption for all data leaving the enclave
- **SGX Support**: Works in both simulation mode (dev) and hardware mode (prod)
- **Feature-based Compilation**: 
  - `std` (default): Standard Rust environment
  - `--no-default-features`: SGX enclave mode using `sgx_tstd`
- **Storage Abstraction**: Pluggable storage backends via traits

## API Example

The enclave exposes three main ECALLs:

```c
// Initialize the database
sgx_status_t db_init(void);

// Store a key-value pair
sgx_status_t db_put(const uint8_t* key, size_t key_len,
                    const uint8_t* value, size_t value_len);

// Retrieve a value by key
sgx_status_t db_get(const uint8_t* key, size_t key_len,
                    uint8_t* value_buf, size_t buf_len,
                    size_t* out_len);
```

## Development

### Building Individual Crates

```bash
# Build with std (default)
cargo build -p lsm-sgx
cargo build -p fjall-sgx-storage
cargo build -p fjall-sgx

# Build for SGX (no-std mode)
# Note: Requires SGX environment
cargo build -p lsm-sgx --no-default-features
```

### Running Tests

```bash
# Test storage implementations
cargo test -p fjall-sgx-storage

# Test LSM structures
cargo test -p lsm-sgx

# Test engine
cargo test -p fjall-sgx
```

## License

Apache-2.0

## References

- [Intel SGX SDK](https://github.com/intel/linux-sgx)
- [Teaclave SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk)
- [Fjall](https://github.com/fjall-rs/fjall) - Original inspiration
