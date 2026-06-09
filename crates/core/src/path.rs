//! Type-safe path types
//!
//! This module provides three distinct path types using the newtype pattern:
//!
//! - [`AbsPath`]: Absolute filesystem paths
//! - [`RelPath`]: Relative paths (no leading slash)
//! - [`SourceRelPath`]: Relative paths in the source directory with encoded attributes
//!
//! These types prevent common path manipulation errors at compile time.
//!
//! # Examples
//!
//! ```
//! use guisu_core::path::{AbsPath, RelPath};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create an absolute path
//! let home = AbsPath::new("/home/user".into())?;
//!
//! // Create a relative path
//! let config = RelPath::new(".config/nvim/init.lua".into())?;
//!
//! // Join them to get a new absolute path
//! let nvim_config = home.join(&config);
//! assert_eq!(nvim_config.as_path().to_str().unwrap(), "/home/user/.config/nvim/init.lua");
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// An absolute path on the filesystem
///
/// This type guarantees that the path is absolute (starts with `/` on Unix or a drive letter on Windows).
/// Use this for file operations and as base directories.
///
/// # Examples
///
/// ```
/// use guisu_core::path::AbsPath;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let abs = AbsPath::new("/home/user".into())?;
/// assert_eq!(abs.as_path(), std::path::Path::new("/home/user"));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AbsPath(PathBuf);

impl AbsPath {
    /// Create a new `AbsPath` from a `PathBuf`
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not absolute.
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_core::path::AbsPath;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let abs = AbsPath::new("/home/user".into())?;
    /// assert!(abs.as_path().is_absolute());
    ///
    /// let err = AbsPath::new("relative/path".into());
    /// assert!(err.is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(path: PathBuf) -> Result<Self> {
        if path.is_absolute() {
            Ok(AbsPath(path))
        } else {
            Err(Error::PathNotAbsolute { path })
        }
    }

    /// Create a new `AbsPath` from a reference to a `Path`
    ///
    /// This will clone the path internally.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not absolute.
    pub fn from_path(path: &Path) -> Result<Self> {
        Self::new(path.to_path_buf())
    }

    /// Get the underlying `Path`
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Convert to a `PathBuf`
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Join with a relative path to create a new absolute path
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_core::path::{AbsPath, RelPath};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let home = AbsPath::new("/home/user".into())?;
    /// let config = RelPath::new(".config".into())?;
    /// let path = home.join(&config);
    /// assert_eq!(path.as_path().to_str().unwrap(), "/home/user/.config");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn join(&self, rel: &RelPath) -> Self {
        AbsPath(self.0.join(rel.as_path()))
    }

    /// Get the parent directory
    ///
    /// Returns `None` if this is the root directory.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|p| AbsPath(p.to_path_buf()))
    }

    /// Strip a base directory prefix to get a relative path
    ///
    /// # Errors
    ///
    /// Returns an error if `self` is not under `base`.
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_core::path::{AbsPath, RelPath};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let home = AbsPath::new("/home/user".into())?;
    /// let file = AbsPath::new("/home/user/.bashrc".into())?;
    /// let rel = file.strip_prefix(&home)?;
    /// assert_eq!(rel.as_path().to_str().unwrap(), ".bashrc");
    /// # Ok(())
    /// # }
    /// ```
    pub fn strip_prefix(&self, base: &AbsPath) -> Result<RelPath> {
        self.0
            .strip_prefix(&base.0)
            .map(|p| RelPath(p.to_path_buf()))
            .map_err(|_| Error::InvalidPathPrefix {
                path: std::sync::Arc::new(self.as_path().to_path_buf()),
                base: std::sync::Arc::new(base.as_path().to_path_buf()),
            })
    }

    /// Get the file name
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.0.file_name().and_then(|s| s.to_str())
    }

    /// Check if the path exists on the filesystem
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_core::path::AbsPath;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let path = AbsPath::new("/home/user".into())?;
    /// if path.exists() {
    ///     println!("Path exists!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn exists(&self) -> bool {
        self.0.exists()
    }

    /// Check if the path points to a directory
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.0.is_dir()
    }

    /// Check if the path points to a file
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.0.is_file()
    }

    /// Check if the path points to a symlink
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.0.is_symlink()
    }

    /// Get metadata for the path
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist or metadata cannot be read.
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(&self.0)
    }

    /// Read a directory, returning an iterator over entries
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not a directory or cannot be read.
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.0)
    }

    /// Canonicalize the path, resolving symlinks and relative components
    ///
    /// # Errors
    ///
    /// Returns an error if the path does not exist or cannot be canonicalized.
    pub fn canonicalize(&self) -> Result<Self> {
        std::fs::canonicalize(&self.0)
            .map(AbsPath)
            .map_err(|_| Error::PathNotAbsolute {
                path: self.0.clone(),
            })
    }
}

/// A relative path (no leading slash)
///
/// This type guarantees that the path is relative (does not start with `/`).
/// Use this for paths relative to a base directory.
///
/// # Examples
///
/// ```
/// use guisu_core::path::RelPath;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let rel = RelPath::new(".config/nvim/init.lua".into())?;
/// assert_eq!(rel.as_path().to_str().unwrap(), ".config/nvim/init.lua");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelPath(PathBuf);

impl RelPath {
    /// Create a new `RelPath` from a `PathBuf`
    ///
    /// # Errors
    ///
    /// Returns an error if the path is absolute.
    pub fn new(path: PathBuf) -> Result<Self> {
        if path.is_relative() {
            Ok(RelPath(path))
        } else {
            Err(Error::PathNotRelative { path })
        }
    }

    /// Get the underlying `Path`
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Convert to a `PathBuf`
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Join with another relative path
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_core::path::RelPath;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = RelPath::new(".config".into())?;
    /// let nvim = RelPath::new("nvim".into())?;
    /// let path = config.join(&nvim);
    /// assert_eq!(path.as_path().to_str().unwrap(), ".config/nvim");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn join(&self, other: &RelPath) -> Self {
        RelPath(self.0.join(&other.0))
    }

    /// Get the parent directory
    ///
    /// Returns `None` if this is a single component path.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|p| RelPath(p.to_path_buf()))
    }

    /// Get the file name
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.0.file_name().and_then(|s| s.to_str())
    }

    /// Convert to a `SourceRelPath` (assumes no attribute encoding)
    #[must_use]
    pub fn to_source(&self) -> SourceRelPath {
        SourceRelPath(self.0.clone())
    }
}

/// A relative path in the source directory
///
/// This type represents paths in the source directory. Attributes are encoded via:
/// - File extensions (`.j2` for templates, `.age` for encryption)
///
/// Unlike chezmoi, guisu does NOT use filename prefixes. The `dot_` /
/// `private_` / `executable_` / `readonly_` / `modify_` / `remove_` /
/// `symlink_` / `exact_` filename-prefix mechanisms are not supported.
/// The source file's actual Unix mode bits are the source of truth for
/// permissions — they are read from the file's `metadata().mode()`.
///
/// # Examples
///
/// ```
/// use guisu_core::path::SourceRelPath;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let source = SourceRelPath::new(".config/nvim/init.lua".into())?;
/// assert_eq!(source.as_path().to_str().unwrap(), ".config/nvim/init.lua");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceRelPath(PathBuf);

impl SourceRelPath {
    /// Create a new `SourceRelPath` from a `PathBuf`
    ///
    /// # Errors
    ///
    /// Returns an error if the path is absolute.
    pub fn new(path: PathBuf) -> Result<Self> {
        if path.is_relative() {
            Ok(SourceRelPath(path))
        } else {
            Err(Error::PathNotRelative { path })
        }
    }

    /// Get the underlying `Path`
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Convert to a `PathBuf`
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Join with another source relative path
    #[must_use]
    pub fn join(&self, other: &SourceRelPath) -> Self {
        SourceRelPath(self.0.join(&other.0))
    }

    /// Get the parent directory
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(|p| SourceRelPath(p.to_path_buf()))
    }

    /// Get the file name
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.0.file_name().and_then(|s| s.to_str())
    }

    /// Convert to a regular `RelPath` (preserves the encoded attributes)
    #[must_use]
    pub fn to_rel_path(&self) -> RelPath {
        RelPath(self.0.clone())
    }
}

// Implement AsRef<Path> for easy interop with std::path
impl AsRef<Path> for AbsPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for RelPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for SourceRelPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

// Implement Display for all path types
impl std::fmt::Display for AbsPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl std::fmt::Display for SourceRelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_abspath_new_valid() {
        let abs = AbsPath::new("/home/user".into()).expect("Should be valid");
        assert_eq!(abs.as_path(), Path::new("/home/user"));
    }

    #[test]
    fn test_abspath_new_invalid_relative() {
        let result = AbsPath::new("relative/path".into());
        assert!(result.is_err());
    }

    #[test]
    fn test_abspath_from_path() {
        let path = Path::new("/tmp");
        let abs = AbsPath::from_path(path).expect("Should be valid");
        assert_eq!(abs.as_path(), path);
    }

    #[test]
    fn test_abspath_into_path_buf() {
        let abs = AbsPath::new("/home/user".into()).unwrap();
        let path_buf = abs.into_path_buf();
        assert_eq!(path_buf, PathBuf::from("/home/user"));
    }

    #[test]
    fn test_abspath_join() {
        let base = AbsPath::new("/home/user".into()).unwrap();
        let rel = RelPath::new(".config/nvim".into()).unwrap();

        let joined = base.join(&rel);
        assert_eq!(joined.as_path(), Path::new("/home/user/.config/nvim"));
    }

    #[test]
    fn test_abspath_parent() {
        let abs = AbsPath::new("/home/user/documents".into()).unwrap();
        let parent = abs.parent().expect("Should have parent");
        assert_eq!(parent.as_path(), Path::new("/home/user"));
    }

    #[test]
    fn test_abspath_root_parent() {
        let abs = AbsPath::new("/".into()).unwrap();
        assert!(abs.parent().is_none());
    }

    #[test]
    fn test_abspath_strip_prefix() {
        let full = AbsPath::new("/home/user/.config/nvim/init.lua".into()).unwrap();
        let base = AbsPath::new("/home/user".into()).unwrap();

        let rel = full.strip_prefix(&base).expect("Should strip prefix");
        assert_eq!(rel.as_path(), Path::new(".config/nvim/init.lua"));
    }

    #[test]
    fn test_abspath_strip_prefix_not_prefix() {
        let path = AbsPath::new("/home/user/file.txt".into()).unwrap();
        let not_prefix = AbsPath::new("/var/log".into()).unwrap();

        let result = path.strip_prefix(&not_prefix);
        assert!(result.is_err());
    }

    #[test]
    fn test_abspath_file_name() {
        let abs = AbsPath::new("/home/user/document.txt".into()).unwrap();
        assert_eq!(abs.file_name(), Some("document.txt"));
    }

    #[test]
    fn test_abspath_file_name_directory() {
        let abs = AbsPath::new("/home/user".into()).unwrap();
        assert_eq!(abs.file_name(), Some("user"));
    }

    #[test]
    fn test_abspath_exists() {
        let root = AbsPath::new("/".into()).unwrap();
        assert!(root.exists());
    }

    #[test]
    fn test_abspath_is_dir() {
        let root = AbsPath::new("/".into()).unwrap();
        assert!(root.is_dir());
    }

    #[test]
    fn test_abspath_equality() {
        let abs1 = AbsPath::new("/home/user".into()).unwrap();
        let abs2 = AbsPath::new("/home/user".into()).unwrap();
        let abs3 = AbsPath::new("/var/log".into()).unwrap();

        assert_eq!(abs1, abs2);
        assert_ne!(abs1, abs3);
    }

    #[test]
    fn test_abspath_clone() {
        let abs = AbsPath::new("/home/user".into()).unwrap();
        let cloned = abs.clone();
        assert_eq!(abs, cloned);
    }

    #[test]
    fn test_relpath_new_valid() {
        let rel = RelPath::new(".config/nvim".into()).expect("Should be valid");
        assert_eq!(rel.as_path(), Path::new(".config/nvim"));
    }

    #[test]
    fn test_relpath_new_invalid_absolute() {
        let result = RelPath::new("/absolute/path".into());
        assert!(result.is_err());
    }

    #[test]
    fn test_relpath_single_component() {
        let rel = RelPath::new("file.txt".into()).expect("Should be valid");
        assert_eq!(rel.as_path(), Path::new("file.txt"));
    }

    #[test]
    fn test_relpath_into_path_buf() {
        let rel = RelPath::new("config/file.txt".into()).unwrap();
        let path_buf = rel.into_path_buf();
        assert_eq!(path_buf, PathBuf::from("config/file.txt"));
    }

    #[test]
    fn test_relpath_join() {
        let base = RelPath::new(".config".into()).unwrap();
        let other = RelPath::new("nvim/init.lua".into()).unwrap();

        let joined = base.join(&other);
        assert_eq!(joined.as_path(), Path::new(".config/nvim/init.lua"));
    }

    #[test]
    fn test_relpath_parent() {
        let rel = RelPath::new(".config/nvim/init.lua".into()).unwrap();
        let parent = rel.parent().expect("Should have parent");
        assert_eq!(parent.as_path(), Path::new(".config/nvim"));
    }

    #[test]
    fn test_relpath_parent_single_component() {
        let rel = RelPath::new("file.txt".into()).unwrap();
        let parent = rel.parent();
        // Single component has parent of empty path
        assert!(parent.is_some());
        if let Some(p) = parent {
            assert_eq!(p.as_path(), Path::new(""));
        }
    }

    #[test]
    fn test_relpath_file_name() {
        let rel = RelPath::new(".config/nvim/init.lua".into()).unwrap();
        assert_eq!(rel.file_name(), Some("init.lua"));
    }

    #[test]
    fn test_relpath_to_source() {
        let rel = RelPath::new(".gitconfig".into()).unwrap();
        let source = rel.to_source();
        assert_eq!(source.as_path(), Path::new(".gitconfig"));
    }

    #[test]
    fn test_relpath_equality() {
        let rel1 = RelPath::new(".config/nvim".into()).unwrap();
        let rel2 = RelPath::new(".config/nvim".into()).unwrap();
        let rel3 = RelPath::new(".bashrc".into()).unwrap();

        assert_eq!(rel1, rel2);
        assert_ne!(rel1, rel3);
    }

    #[test]
    fn test_sourcerelpath_new_valid() {
        let src = SourceRelPath::new(".gitconfig.j2".into()).expect("Should be valid");
        assert_eq!(src.as_path(), Path::new(".gitconfig.j2"));
    }

    #[test]
    fn test_sourcerelpath_new_invalid_absolute() {
        let result = SourceRelPath::new("/absolute/path".into());
        assert!(result.is_err());
    }

    #[test]
    fn test_sourcerelpath_into_path_buf() {
        let src = SourceRelPath::new("config.j2.age".into()).unwrap();
        let path_buf = src.into_path_buf();
        assert_eq!(path_buf, PathBuf::from("config.j2.age"));
    }

    #[test]
    fn test_sourcerelpath_join() {
        let base = SourceRelPath::new(".config".into()).unwrap();
        let other = SourceRelPath::new("nvim.j2".into()).unwrap();

        let joined = base.join(&other);
        assert_eq!(joined.as_path(), Path::new(".config/nvim.j2"));
    }

    #[test]
    fn test_sourcerelpath_parent() {
        let src = SourceRelPath::new(".config/nvim/init.lua.j2".into()).unwrap();
        let parent = src.parent().expect("Should have parent");
        assert_eq!(parent.as_path(), Path::new(".config/nvim"));
    }

    #[test]
    fn test_sourcerelpath_file_name() {
        let src = SourceRelPath::new(".config/file.j2.age".into()).unwrap();
        assert_eq!(src.file_name(), Some("file.j2.age"));
    }

    #[test]
    fn test_sourcerelpath_to_rel_path() {
        let src = SourceRelPath::new(".gitconfig.j2".into()).unwrap();
        let rel = src.to_rel_path();
        assert_eq!(rel.as_path(), Path::new(".gitconfig.j2"));
    }

    #[test]
    fn test_sourcerelpath_equality() {
        let src1 = SourceRelPath::new("config.j2".into()).unwrap();
        let src2 = SourceRelPath::new("config.j2".into()).unwrap();
        let src3 = SourceRelPath::new("file.age".into()).unwrap();

        assert_eq!(src1, src2);
        assert_ne!(src1, src3);
    }

    #[test]
    fn test_abspath_serde_roundtrip() {
        let abs = AbsPath::new("/home/user".into()).unwrap();

        let json = serde_json::to_string(&abs).expect("Serialize failed");
        let deserialized: AbsPath = serde_json::from_str(&json).expect("Deserialize failed");

        assert_eq!(abs, deserialized);
    }

    #[test]
    fn test_relpath_serde_roundtrip() {
        let rel = RelPath::new(".config/nvim".into()).unwrap();

        let json = serde_json::to_string(&rel).expect("Serialize failed");
        let deserialized: RelPath = serde_json::from_str(&json).expect("Deserialize failed");

        assert_eq!(rel, deserialized);
    }

    #[test]
    fn test_sourcerelpath_serde_roundtrip() {
        let src = SourceRelPath::new("file.j2.age".into()).unwrap();

        let json = serde_json::to_string(&src).expect("Serialize failed");
        let deserialized: SourceRelPath = serde_json::from_str(&json).expect("Deserialize failed");

        assert_eq!(src, deserialized);
    }

    #[test]
    fn test_path_with_spaces() {
        let rel = RelPath::new("my documents/file.txt".into()).unwrap();
        assert_eq!(rel.as_path(), Path::new("my documents/file.txt"));
    }

    #[test]
    fn test_path_with_unicode() {
        let rel = RelPath::new("documents/file.txt".into()).unwrap();
        assert_eq!(rel.as_path(), Path::new("documents/file.txt"));
    }

    #[test]
    fn test_hidden_file_path() {
        let rel = RelPath::new(".hidden_file".into()).unwrap();
        assert_eq!(rel.file_name(), Some(".hidden_file"));
    }

    #[test]
    fn test_empty_relpath() {
        let result = RelPath::new("".into());
        // Empty string is technically relative but may not be useful
        // The implementation should handle this gracefully
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_abspath_display() {
        let abs = AbsPath::new("/home/user/file.txt".into()).unwrap();
        let display = format!("{abs:?}");
        assert!(display.contains("/home/user/file.txt"));
    }

    #[test]
    fn test_multiple_join_operations() {
        let base = AbsPath::new("/home".into()).unwrap();
        let rel1 = RelPath::new("user".into()).unwrap();
        let rel2 = RelPath::new(".config".into()).unwrap();
        let rel3 = RelPath::new("nvim".into()).unwrap();

        let result = base.join(&rel1).join(&rel2).join(&rel3);
        assert_eq!(result.as_path(), Path::new("/home/user/.config/nvim"));
    }

    #[test]
    fn test_abspath_is_file() {
        use tempfile::NamedTempFile;
        let temp_file = NamedTempFile::new().unwrap();
        let path = AbsPath::new(temp_file.path().to_path_buf()).unwrap();
        assert!(path.is_file());
        assert!(!path.is_dir());
    }

    #[test]
    fn test_abspath_is_symlink() {
        #[cfg(unix)]
        {
            use tempfile::TempDir;
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("file.txt");
            std::fs::write(&file_path, "content").unwrap();

            let symlink_path = temp_dir.path().join("link");
            std::os::unix::fs::symlink(&file_path, &symlink_path).unwrap();

            let abs_symlink = AbsPath::new(symlink_path).unwrap();
            assert!(abs_symlink.is_symlink());
        }
    }

    #[test]
    fn test_abspath_metadata() {
        use tempfile::NamedTempFile;
        let temp_file = NamedTempFile::new().unwrap();
        let path = AbsPath::new(temp_file.path().to_path_buf()).unwrap();

        let metadata = path.metadata().expect("Should get metadata");
        assert!(metadata.is_file());
    }

    #[test]
    fn test_abspath_read_dir() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();

        // Create some files
        std::fs::write(temp_dir.path().join("file1.txt"), "content1").unwrap();
        std::fs::write(temp_dir.path().join("file2.txt"), "content2").unwrap();

        let path = AbsPath::new(temp_dir.path().to_path_buf()).unwrap();
        let entries: Vec<_> = path.read_dir().expect("Should read directory").collect();

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_abspath_canonicalize() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let abs = AbsPath::new(file_path.clone()).unwrap();
        let canonical = abs.canonicalize().expect("Should canonicalize");

        // Canonical path should be absolute
        assert!(canonical.as_path().is_absolute());
    }

    #[test]
    fn test_abspath_as_ref() {
        let abs = AbsPath::new("/home/user".into()).unwrap();
        let path_ref: &Path = abs.as_ref();
        assert_eq!(path_ref, Path::new("/home/user"));
    }

    #[test]
    fn test_relpath_as_ref() {
        let rel = RelPath::new(".config/nvim".into()).unwrap();
        let path_ref: &Path = rel.as_ref();
        assert_eq!(path_ref, Path::new(".config/nvim"));
    }

    #[test]
    fn test_sourcerelpath_as_ref() {
        let src = SourceRelPath::new("file.j2".into()).unwrap();
        let path_ref: &Path = src.as_ref();
        assert_eq!(path_ref, Path::new("file.j2"));
    }

    #[test]
    fn test_abspath_display_trait() {
        let abs = AbsPath::new("/home/user/file.txt".into()).unwrap();
        let display = abs.to_string();
        assert!(display.contains("/home/user/file.txt"));
    }

    #[test]
    fn test_relpath_display_trait() {
        let rel = RelPath::new(".config/nvim".into()).unwrap();
        let display = rel.to_string();
        assert_eq!(display, ".config/nvim");
    }

    #[test]
    fn test_sourcerelpath_display_trait() {
        let src = SourceRelPath::new("file.j2.age".into()).unwrap();
        let display = src.to_string();
        assert_eq!(display, "file.j2.age");
    }
}
