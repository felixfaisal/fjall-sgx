// fjall-sgx-storage/src/std_fs.rs
//
// Filesystem-backed storage using std::fs.
//
// Maps FileIds to actual files on disk. Used for:
// - Integration testing outside SGX
// - Development / debugging
// - Potential use as the "untrusted side" of an SGX OCALL bridge
//
// File naming: each FileId N maps to "{base_dir}/{N:06}.sst"
// (e.g. FileId 1 → "000001.sst")

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::traits::{FileId, StorageError, StorageReader, StorageWriter};

/// Filesystem-backed storage.
///
/// All files live under a single base directory. FileIds are mapped
/// to filenames deterministically: `{id:06}.sst`.
pub struct StdStorage {
    base_dir: PathBuf,
    next_id: FileId,
    /// Track which files are open for writing
    open_writers: HashMap<FileId, File>,
}

impl StdStorage {
    /// Create a new filesystem storage rooted at `base_dir`.
    ///
    /// Creates the directory if it doesn't exist.
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)
            .map_err(|e| StorageError::Io(format!("create dir: {}", e)))?;

        // Scan existing files to determine next_id
        let mut max_id: FileId = 0;
        if let Ok(entries) = fs::read_dir(&base_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Some(stem) = name_str.strip_suffix(".sst") {
                    if let Ok(id) = stem.parse::<FileId>() {
                        max_id = max_id.max(id);
                    }
                }
            }
        }

        Ok(Self {
            base_dir,
            next_id: max_id + 1,
            open_writers: HashMap::new(),
        })
    }

    /// Get the filesystem path for a given FileId.
    fn file_path(&self, file_id: FileId) -> PathBuf {
        self.base_dir.join(format!("{:06}.sst", file_id))
    }
}

impl StorageReader for StdStorage {
    fn read_at(&self, file_id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        let path = self.file_path(file_id);
        let mut file = File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(format!("open {}: {}", path.display(), e))
            }
        })?;

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| StorageError::Io(format!("seek: {}", e)))?;

        let n = file
            .read(buf)
            .map_err(|e| StorageError::Io(format!("read: {}", e)))?;

        Ok(n)
    }

    fn file_size(&self, file_id: FileId) -> Result<u64, StorageError> {
        let path = self.file_path(file_id);
        let meta = fs::metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(format!("metadata: {}", e))
            }
        })?;
        Ok(meta.len())
    }

    fn exists(&self, file_id: FileId) -> bool {
        self.file_path(file_id).exists()
    }
}

impl StorageWriter for StdStorage {
    fn create_file(&mut self) -> Result<FileId, StorageError> {
        let id = self.next_id;
        self.next_id += 1;

        let path = self.file_path(id);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    StorageError::AlreadyExists
                } else {
                    StorageError::Io(format!("create {}: {}", path.display(), e))
                }
            })?;

        self.open_writers.insert(id, file);
        Ok(id)
    }

    fn append(&mut self, file_id: FileId, data: &[u8]) -> Result<u64, StorageError> {
        let file = self
            .open_writers
            .get_mut(&file_id)
            .ok_or_else(|| StorageError::Io("file not open for writing".into()))?;

        let offset = file
            .seek(SeekFrom::End(0))
            .map_err(|e| StorageError::Io(format!("seek: {}", e)))?;

        file.write_all(data)
            .map_err(|e| StorageError::Io(format!("write: {}", e)))?;

        Ok(offset)
    }

    fn sync(&mut self, file_id: FileId) -> Result<(), StorageError> {
        let file = self
            .open_writers
            .get(&file_id)
            .ok_or_else(|| StorageError::Io("file not open".into()))?;

        file.sync_all()
            .map_err(|e| StorageError::Io(format!("sync: {}", e)))?;

        Ok(())
    }

    fn close_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // Remove from writers — File is dropped, closing the handle.
        // We sync first for safety.
        if let Some(file) = self.open_writers.remove(&file_id) {
            file.sync_all()
                .map_err(|e| StorageError::Io(format!("sync on close: {}", e)))?;
        }
        Ok(())
    }

    fn delete_file(&mut self, file_id: FileId) -> Result<(), StorageError> {
        // Close writer if open
        self.open_writers.remove(&file_id);

        let path = self.file_path(file_id);
        fs::remove_file(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound
            } else {
                StorageError::Io(format!("delete: {}", e))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_dir() -> PathBuf {
        let dir = env::temp_dir().join(format!("fjall-sgx-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir); // Clean from previous runs
        dir
    }

    #[test]
    fn test_std_storage_basic_roundtrip() {
        let dir = temp_dir();
        let mut storage = StdStorage::new(&dir).unwrap();

        let id = storage.create_file().unwrap();
        storage.append(id, b"hello ").unwrap();
        storage.append(id, b"world").unwrap();
        storage.sync(id).unwrap();
        storage.close_file(id).unwrap();

        // Read back
        assert_eq!(storage.file_size(id).unwrap(), 11);

        let mut buf = [0u8; 5];
        let n = storage.read_at(id, 0, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        let n = storage.read_at(id, 6, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"world");

        let all = storage.read_all(id).unwrap();
        assert_eq!(all, b"hello world");

        // Cleanup
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_std_storage_file_naming() {
        let dir = temp_dir();
        let mut storage = StdStorage::new(&dir).unwrap();

        let id1 = storage.create_file().unwrap();
        let id2 = storage.create_file().unwrap();

        storage.append(id1, b"file1").unwrap();
        storage.append(id2, b"file2").unwrap();
        storage.close_file(id1).unwrap();
        storage.close_file(id2).unwrap();

        // Verify actual files exist on disk
        assert!(dir.join(format!("{:06}.sst", id1)).exists());
        assert!(dir.join(format!("{:06}.sst", id2)).exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_std_storage_delete() {
        let dir = temp_dir();
        let mut storage = StdStorage::new(&dir).unwrap();

        let id = storage.create_file().unwrap();
        storage.append(id, b"temp data").unwrap();
        storage.close_file(id).unwrap();

        assert!(storage.exists(id));
        storage.delete_file(id).unwrap();
        assert!(!storage.exists(id));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_std_storage_resume_ids() {
        let dir = temp_dir();

        // Create some files
        {
            let mut storage = StdStorage::new(&dir).unwrap();
            let id1 = storage.create_file().unwrap();
            let id2 = storage.create_file().unwrap();
            storage.append(id1, b"a").unwrap();
            storage.append(id2, b"b").unwrap();
            storage.close_file(id1).unwrap();
            storage.close_file(id2).unwrap();
            assert_eq!(id2, 2);
        }

        // Reopen — next_id should resume past existing files
        {
            let mut storage = StdStorage::new(&dir).unwrap();
            let id3 = storage.create_file().unwrap();
            assert!(id3 > 2, "new id {} should be > 2", id3);
            storage.close_file(id3).unwrap();
        }

        fs::remove_dir_all(&dir).unwrap();
    }
}
