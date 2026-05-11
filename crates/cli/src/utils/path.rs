//! Path utility functions for consistent path resolution across commands
//!
//! This module provides extension traits for common path operations,
//! reducing code duplication and ensuring consistent path handling.

use std::path::{Path, PathBuf};

/// Extension trait for source directory path operations
///
/// Provides convenient methods for resolving guisu-specific paths
/// relative to the source directory.
pub trait SourceDirExt {
    /// Get the `.guisu` directory path
    ///
    /// # Returns
    /// Path to `.guisu/` directory inside the source directory
    fn guisu_dir(&self) -> PathBuf;

    /// Get the hooks directory path
    ///
    /// # Returns
    /// Path to `.guisu/hooks/` directory
    fn hooks_dir(&self) -> PathBuf;

    /// Get the templates directory path
    ///
    /// # Returns
    /// Path to `.guisu/templates/` directory
    fn templates_dir(&self) -> PathBuf;
}

impl SourceDirExt for Path {
    fn guisu_dir(&self) -> PathBuf {
        self.join(".guisu")
    }

    fn hooks_dir(&self) -> PathBuf {
        self.guisu_dir().join("hooks")
    }

    fn templates_dir(&self) -> PathBuf {
        self.guisu_dir().join("templates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_guisu_dir() {
        let source = Path::new("/home/user/dotfiles");
        assert_eq!(source.guisu_dir(), Path::new("/home/user/dotfiles/.guisu"));
    }

    #[test]
    fn test_hooks_dir() {
        let source = Path::new("/home/user/dotfiles");
        assert_eq!(
            source.hooks_dir(),
            Path::new("/home/user/dotfiles/.guisu/hooks")
        );
    }

    #[test]
    fn test_templates_dir() {
        let source = Path::new("/home/user/dotfiles");
        assert_eq!(
            source.templates_dir(),
            Path::new("/home/user/dotfiles/.guisu/templates")
        );
    }

    #[test]
    fn test_relative_path() {
        let source = Path::new("dotfiles");
        assert_eq!(source.guisu_dir(), Path::new("dotfiles/.guisu"));
        assert_eq!(source.hooks_dir(), Path::new("dotfiles/.guisu/hooks"));
    }
}
