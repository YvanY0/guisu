//! System abstraction for filesystem operations
//!
//! This module provides a trait-based abstraction over filesystem operations,
//! enabling testing and dry-run mode.

use guisu_core::path::AbsPath;
use guisu_core::{Error, Result};
use std::fs::{self, Metadata};
use std::path::Path;

/// Abstraction over filesystem operations
///
/// This trait allows us to implement different backends:
/// - `RealSystem`: Actual filesystem operations
/// - `DryRunSystem`: Records operations without executing them
/// - Mock implementations for testing
pub trait System {
    /// Read a file's contents
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read (e.g., not found, permission denied, I/O error)
    fn read_file(&self, path: &AbsPath) -> Result<Vec<u8>>;

    /// Write a file's contents with optional permissions
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written (e.g., permission denied, I/O error, parent directory doesn't exist)
    fn write_file(&self, path: &AbsPath, content: &[u8], mode: Option<u32>) -> Result<()>;

    /// Create a directory with optional permissions
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created (e.g., already exists, permission denied, I/O error)
    fn create_dir(&self, path: &AbsPath, mode: Option<u32>) -> Result<()>;

    /// Create all parent directories
    ///
    /// # Errors
    ///
    /// Returns an error if any directory in the path cannot be created (e.g., permission denied, I/O error)
    fn create_dir_all(&self, path: &AbsPath, mode: Option<u32>) -> Result<()>;

    /// Remove a file or directory
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be removed (e.g., not found, permission denied, directory not empty)
    fn remove(&self, path: &AbsPath) -> Result<()>;

    /// Remove a directory and all its contents
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or its contents cannot be removed (e.g., permission denied, I/O error)
    fn remove_all(&self, path: &AbsPath) -> Result<()>;

    /// Check if a path exists
    fn exists(&self, path: &AbsPath) -> bool;

    /// Get file metadata
    ///
    /// # Errors
    ///
    /// Returns an error if metadata cannot be read (e.g., file not found, permission denied)
    fn metadata(&self, path: &AbsPath) -> Result<Metadata>;

    /// Create a symbolic link
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink cannot be created (e.g., already exists, permission denied, platform not supported)
    fn symlink(&self, target: &Path, link: &AbsPath) -> Result<()>;

    /// Read a symbolic link
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink cannot be read (e.g., not a symlink, not found, permission denied)
    fn read_link(&self, path: &AbsPath) -> Result<std::path::PathBuf>;
}

/// Real filesystem implementation
///
/// This implementation performs actual filesystem operations.
pub struct RealSystem;

impl System for RealSystem {
    fn read_file(&self, path: &AbsPath) -> Result<Vec<u8>> {
        fs::read(path.as_path()).map_err(|e| Error::FileRead {
            path: path.as_path().to_path_buf(),
            source: e,
        })
    }

    fn write_file(&self, path: &AbsPath, content: &[u8], mode: Option<u32>) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            self.create_dir_all(&parent, None)?;
        }

        // Write the file
        fs::write(path.as_path(), content).map_err(|e| Error::FileWrite {
            path: path.as_path().to_path_buf(),
            source: e,
        })?;

        // Set permissions if specified
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(path.as_path(), permissions).map_err(|e| Error::FileWrite {
                path: path.as_path().to_path_buf(),
                source: e,
            })?;
        }

        Ok(())
    }

    fn create_dir(&self, path: &AbsPath, mode: Option<u32>) -> Result<()> {
        fs::create_dir(path.as_path()).map_err(|e| Error::DirectoryCreate {
            path: path.as_path().to_path_buf(),
            source: e,
        })?;

        // Set permissions if specified
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(path.as_path(), permissions).map_err(|e| {
                Error::DirectoryCreate {
                    path: path.as_path().to_path_buf(),
                    source: e,
                }
            })?;
        }

        Ok(())
    }

    fn create_dir_all(&self, path: &AbsPath, mode: Option<u32>) -> Result<()> {
        fs::create_dir_all(path.as_path()).map_err(|e| Error::DirectoryCreate {
            path: path.as_path().to_path_buf(),
            source: e,
        })?;

        // Set permissions if specified
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(mode);
            fs::set_permissions(path.as_path(), permissions).map_err(|e| {
                Error::DirectoryCreate {
                    path: path.as_path().to_path_buf(),
                    source: e,
                }
            })?;
        }

        Ok(())
    }

    fn remove(&self, path: &AbsPath) -> Result<()> {
        let metadata = self.metadata(path)?;
        if metadata.is_dir() {
            fs::remove_dir(path.as_path()).map_err(Error::Io)
        } else {
            fs::remove_file(path.as_path()).map_err(Error::Io)
        }
    }

    fn remove_all(&self, path: &AbsPath) -> Result<()> {
        fs::remove_dir_all(path.as_path()).map_err(Error::Io)
    }

    fn exists(&self, path: &AbsPath) -> bool {
        path.as_path().exists()
    }

    fn metadata(&self, path: &AbsPath) -> Result<Metadata> {
        fs::metadata(path.as_path()).map_err(|e| Error::Metadata {
            path: path.as_path().to_path_buf(),
            source: e,
        })
    }

    fn symlink(&self, target: &Path, link: &AbsPath) -> Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link.as_path()).map_err(Error::Io)
        }

        #[cfg(windows)]
        {
            // On Windows, we need to check if target is a dir or file
            if target.is_dir() {
                std::os::windows::fs::symlink_dir(target, link.as_path()).map_err(|e| Error::Io(e))
            } else {
                std::os::windows::fs::symlink_file(target, link.as_path()).map_err(|e| Error::Io(e))
            }
        }
    }

    fn read_link(&self, path: &AbsPath) -> Result<std::path::PathBuf> {
        fs::read_link(path.as_path()).map_err(Error::Io)
    }
}

/// Dry-run system that records operations without executing them
///
/// This is useful for showing what would be done without actually modifying the filesystem.
#[derive(Debug, Default)]
pub struct DryRunSystem {
    operations: std::cell::RefCell<Vec<Operation>>,
}

/// An operation that would be performed on the filesystem
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
    /// Read a file
    ReadFile {
        /// Path to the file to read
        path: AbsPath,
    },
    /// Write a file
    WriteFile {
        /// Path to the file to write
        path: AbsPath,
        /// Size of the file in bytes
        size: usize,
        /// File mode/permissions (Unix only)
        mode: Option<u32>,
    },
    /// Create a directory
    CreateDir {
        /// Path to the directory to create
        path: AbsPath,
        /// Directory mode/permissions (Unix only)
        mode: Option<u32>,
    },
    /// Remove a path
    Remove {
        /// Path to remove
        path: AbsPath,
    },
    /// Create a symlink
    Symlink {
        /// Path where the symlink will be created
        link: AbsPath,
        /// Target path that the symlink points to
        target: std::path::PathBuf,
    },
}

impl DryRunSystem {
    /// Create a new dry-run system
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the list of operations that would be performed
    pub fn operations(&self) -> Vec<Operation> {
        self.operations.borrow().clone()
    }

    /// Record an operation
    fn record(&self, op: Operation) {
        self.operations.borrow_mut().push(op);
    }
}

impl System for DryRunSystem {
    fn read_file(&self, path: &AbsPath) -> Result<Vec<u8>> {
        self.record(Operation::ReadFile { path: path.clone() });
        // In dry-run mode, we can't actually read files that don't exist yet
        // Return empty content
        Ok(Vec::new())
    }

    fn write_file(&self, path: &AbsPath, content: &[u8], mode: Option<u32>) -> Result<()> {
        self.record(Operation::WriteFile {
            path: path.clone(),
            size: content.len(),
            mode,
        });
        Ok(())
    }

    fn create_dir(&self, path: &AbsPath, mode: Option<u32>) -> Result<()> {
        self.record(Operation::CreateDir {
            path: path.clone(),
            mode,
        });
        Ok(())
    }

    fn create_dir_all(&self, path: &AbsPath, mode: Option<u32>) -> Result<()> {
        self.record(Operation::CreateDir {
            path: path.clone(),
            mode,
        });
        Ok(())
    }

    fn remove(&self, path: &AbsPath) -> Result<()> {
        self.record(Operation::Remove { path: path.clone() });
        Ok(())
    }

    fn remove_all(&self, path: &AbsPath) -> Result<()> {
        self.record(Operation::Remove { path: path.clone() });
        Ok(())
    }

    fn exists(&self, _path: &AbsPath) -> bool {
        // In dry-run mode, assume paths don't exist
        false
    }

    fn metadata(&self, path: &AbsPath) -> Result<Metadata> {
        // Can't get metadata in dry-run mode
        Err(Error::Metadata {
            path: path.as_path().to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "dry-run mode"),
        })
    }

    fn symlink(&self, target: &Path, link: &AbsPath) -> Result<()> {
        self.record(Operation::Symlink {
            link: link.clone(),
            target: target.to_path_buf(),
        });
        Ok(())
    }

    fn read_link(&self, _path: &AbsPath) -> Result<std::path::PathBuf> {
        // Can't read links in dry-run mode
        Ok(std::path::PathBuf::new())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn abs(s: &str) -> AbsPath {
        AbsPath::new(std::path::PathBuf::from(s)).unwrap()
    }

    #[test]
    fn dry_run_records_write_file() {
        let sys = DryRunSystem::new();
        let path = abs("/tmp/test.txt");
        let content = b"hello";

        sys.write_file(&path, content, Some(0o644)).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            Operation::WriteFile {
                path: path.clone(),
                size: 5,
                mode: Some(0o644),
            }
        );
    }

    #[test]
    fn dry_run_records_create_dir() {
        let sys = DryRunSystem::new();
        let path = abs("/tmp/mydir");

        sys.create_dir(&path, Some(0o755)).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            Operation::CreateDir {
                path: path.clone(),
                mode: Some(0o755),
            }
        );
    }

    #[test]
    fn dry_run_records_remove() {
        let sys = DryRunSystem::new();
        let path = abs("/tmp/old");

        sys.remove(&path).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], Operation::Remove { path: path.clone() });
    }

    #[test]
    fn dry_run_records_symlink() {
        let sys = DryRunSystem::new();
        let link = abs("/tmp/link");
        let target = std::path::Path::new("/actual/target");

        sys.symlink(target, &link).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            Operation::Symlink {
                link: link.clone(),
                target: std::path::PathBuf::from("/actual/target"),
            }
        );
    }

    #[test]
    fn dry_run_records_multiple_operations() {
        let sys = DryRunSystem::new();

        sys.write_file(&abs("/a"), b"x", None).unwrap();
        sys.create_dir(&abs("/b"), None).unwrap();
        sys.remove(&abs("/c")).unwrap();
        sys.symlink(std::path::Path::new("/t"), &abs("/d")).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 4);
        assert!(matches!(&ops[0], Operation::WriteFile { .. }));
        assert!(matches!(&ops[1], Operation::CreateDir { .. }));
        assert!(matches!(&ops[2], Operation::Remove { .. }));
        assert!(matches!(&ops[3], Operation::Symlink { .. }));
    }

    #[test]
    fn dry_run_exists_returns_false() {
        let sys = DryRunSystem::new();
        assert!(!sys.exists(&abs("/anything")));
    }

    #[test]
    fn dry_run_read_file_returns_empty() {
        let sys = DryRunSystem::new();
        let content = sys.read_file(&abs("/fake")).unwrap();
        assert!(content.is_empty());

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], Operation::ReadFile { .. }));
    }

    #[test]
    fn dry_run_create_dir_all_records_single_op() {
        let sys = DryRunSystem::new();
        sys.create_dir_all(&abs("/a/b/c"), None).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], Operation::CreateDir { .. }));
    }

    #[test]
    fn dry_run_remove_all_records_single_op() {
        let sys = DryRunSystem::new();
        sys.remove_all(&abs("/dir")).unwrap();

        let ops = sys.operations();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], Operation::Remove { .. }));
    }
}
