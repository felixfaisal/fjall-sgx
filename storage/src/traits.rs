// fjall-sgx-storage/src/traits.rs
//
// Storage abstraction layer for fjall-sgx.
//
// The key insight: the enclave doesn't know about filesystems. It works
// with FileIds — opaque handles. The untrusted side maps FileIds to actual
// file paths. This is similar to how WASM uses handles for host resources.
//
// In SGX production:
//   Engine (enclave) → StorageWriter::append(file_id, encrypted_bytes)
//       → OCALL → untrusted host writes to disk
//   Engine (enclave) → StorageReader::read_at(file_id, offset, buf)
//       → OCALL → untrusted host reads from disk → enclave decrypts
//
// For testing:
//   StdStorage wraps std::fs behind the same trait
//   MemoryStorage keeps everything in-memory (fastest for unit tests)

use std::string::String;
use std::vec::Vec;

/// Opaque file identifier.
///
/// The engine works exclusively with FileIds. The mapping from FileId
/// to actual file path (or network location, or OCALL index) is the
/// storage implementation's responsibility.
pub type FileId = u64;

/// Storage operation errors.
#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    /// File not found (unknown FileId)
    NotFound,
    /// Read past end of file
    OutOfBounds,
    /// I/O error (wraps a description string)
    Io(String),
    /// File already exists or is already open
    AlreadyExists,
    /// Storage capacity exceeded
    Full,
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "file not found"),
            StorageError::OutOfBounds => write!(f, "read out of bounds"),
            StorageError::Io(msg) => write!(f, "I/O error: {}", msg),
            StorageError::AlreadyExists => write!(f, "file already exists"),
            StorageError::Full => write!(f, "storage full"),
        }
    }
}

/// Read-side storage operations.
///
/// All reads are positional (offset-based), enabling random access
/// into SSTable files without maintaining file cursors.
pub trait StorageReader {
    /// Read `buf.len()` bytes from `file_id` starting at `offset`.
    ///
    /// Returns the number of bytes actually read. May be less than
    /// `buf.len()` if near end of file.
    fn read_at(&self, file_id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError>;

    /// Get the size of a file in bytes.
    fn file_size(&self, file_id: FileId) -> Result<u64, StorageError>;

    /// Read an entire file into a Vec<u8>.
    ///
    /// Default implementation uses file_size + read_at.
    /// Implementations may override for efficiency.
    fn read_all(&self, file_id: FileId) -> Result<Vec<u8>, StorageError> {
        let size = self.file_size(file_id)? as usize;
        let mut buf = vec![0u8; size];
        let n = self.read_at(file_id, 0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Check whether a file exists.
    fn exists(&self, file_id: FileId) -> bool;
}

/// Write-side storage operations.
///
/// Files are append-only: once written, bytes are immutable.
/// This matches SSTable semantics perfectly — SSTables are written
/// once and never modified.
pub trait StorageWriter {
    /// Create a new file and return its FileId.
    ///
    /// The file is initially empty and open for appending.
    fn create_file(&mut self) -> Result<FileId, StorageError>;

    /// Append data to a file. Returns the byte offset where the data was written.
    ///
    /// The file must have been created via `create_file()`.
    fn append(&mut self, file_id: FileId, data: &[u8]) -> Result<u64, StorageError>;

    /// Ensure all previously written data is durable (flushed to disk).
    ///
    /// In SGX/OCALL mode this triggers a sync on the untrusted side.
    /// In memory mode this is a no-op.
    fn sync(&mut self, file_id: FileId) -> Result<(), StorageError>;

    /// Mark a file as complete. No more appends allowed after this.
    fn close_file(&mut self, file_id: FileId) -> Result<(), StorageError>;

    /// Delete a file. Used during compaction to remove obsolete SSTables.
    fn delete_file(&mut self, file_id: FileId) -> Result<(), StorageError>;
}

/// Combined read + write storage.
///
/// Most engine operations need both reading (for lookups and compaction
/// reads) and writing (for flushes and compaction output).
pub trait Storage: StorageReader + StorageWriter {}

/// Blanket implementation: anything that implements both traits
/// automatically implements the combined trait.
impl<T: StorageReader + StorageWriter> Storage for T {}
