//! Entry types for source, target, and destination states
//!
//! This module defines the different types of entries that can exist in each state:
//!
//! - [`SourceEntry`]: Entries in the source directory with encoded attributes
//! - [`TargetEntry`]: Computed entries after template rendering
//! - [`DestEntry`]: Entries in the destination (filesystem)

use crate::attr::FileAttributes;
use guisu_core::path::{RelPath, SourceRelPath};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A source entry in the source directory
///
/// Source entries have attributes encoded in their filenames and may need
/// processing (template rendering, encryption) before they can be applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SourceEntry {
    /// A regular file
    File {
        /// Path in the source directory (with encoded attributes)
        source_path: SourceRelPath,

        /// Path in the target/destination (without encoded attributes)
        target_path: RelPath,

        /// Parsed attributes from the filename
        attributes: FileAttributes,
    },

    /// A directory
    Directory {
        /// Path in the source directory (with encoded attributes)
        source_path: SourceRelPath,

        /// Path in the target/destination (without encoded attributes)
        target_path: RelPath,

        /// Parsed attributes from the directory name
        attributes: FileAttributes,
    },

    /// A symbolic link
    Symlink {
        /// Path in the source directory
        source_path: SourceRelPath,

        /// Path in the target/destination
        target_path: RelPath,

        /// Where the symlink points to
        link_target: PathBuf,
    },
}

impl SourceEntry {
    /// Get the source path for this entry
    #[must_use]
    pub fn source_path(&self) -> &SourceRelPath {
        match self {
            SourceEntry::File { source_path, .. }
            | SourceEntry::Directory { source_path, .. }
            | SourceEntry::Symlink { source_path, .. } => source_path,
        }
    }

    /// Get the target path for this entry
    #[must_use]
    pub fn target_path(&self) -> &RelPath {
        match self {
            SourceEntry::File { target_path, .. }
            | SourceEntry::Directory { target_path, .. }
            | SourceEntry::Symlink { target_path, .. } => target_path,
        }
    }

    /// Get the attributes for this entry (if applicable)
    #[must_use]
    pub fn attributes(&self) -> Option<&FileAttributes> {
        match self {
            SourceEntry::File { attributes, .. } | SourceEntry::Directory { attributes, .. } => {
                Some(attributes)
            }
            SourceEntry::Symlink { .. } => None,
        }
    }

    /// Check if this entry is a template
    pub fn is_template(&self) -> bool {
        self.attributes()
            .is_some_and(super::attr::FileAttributes::is_template)
    }

    /// Check if this entry is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.attributes()
            .is_some_and(super::attr::FileAttributes::is_encrypted)
    }
}

/// A target entry representing the desired state
///
/// Target entries are the result of processing source entries (rendering templates,
/// decrypting files, etc.) and represent what should exist in the destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TargetEntry {
    /// A regular file with its content and permissions
    File {
        /// Path in the destination
        path: RelPath,

        /// File content (after template rendering and decryption)
        content: Vec<u8>,

        /// Content hash (blake3) for fast drift detection
        content_hash: [u8; 32],

        /// Unix file permissions mode (optional)
        mode: Option<u32>,
    },

    /// A directory
    Directory {
        /// Path in the destination
        path: RelPath,

        /// Unix directory permissions mode (optional)
        mode: Option<u32>,
    },

    /// A symbolic link
    Symlink {
        /// Path in the destination
        path: RelPath,

        /// Where the symlink points to
        target: PathBuf,
    },

    /// A file or directory that should be removed
    Remove {
        /// Path to remove from the destination
        path: RelPath,
    },

    /// A script that modifies an existing file in-place
    Modify {
        /// Path to the file to modify
        path: RelPath,
        /// Script content (after template rendering and decryption)
        script: Vec<u8>,
        /// Content hash (blake3) for change detection
        content_hash: [u8; 32],
        /// Interpreter to use (e.g., "/bin/bash", "/usr/bin/env python3")
        interpreter: String,
    },
}

impl TargetEntry {
    /// Get the destination path for this entry
    #[inline]
    #[must_use]
    pub fn path(&self) -> &RelPath {
        match self {
            TargetEntry::File { path, .. }
            | TargetEntry::Directory { path, .. }
            | TargetEntry::Symlink { path, .. }
            | TargetEntry::Remove { path }
            | TargetEntry::Modify { path, .. } => path,
        }
    }

    /// Get the file mode if applicable
    #[inline]
    #[must_use]
    pub fn mode(&self) -> Option<u32> {
        match self {
            TargetEntry::File { mode, .. } | TargetEntry::Directory { mode, .. } => *mode,
            _ => None,
        }
    }

    /// Check if this is a removal entry
    #[inline]
    #[must_use]
    pub fn is_removal(&self) -> bool {
        matches!(self, TargetEntry::Remove { .. })
    }
}

/// A destination entry representing the current filesystem state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DestEntry {
    /// Path in the destination
    pub path: RelPath,

    /// Type of entry
    pub kind: EntryKind,

    /// File content (if it's a file)
    pub content: Option<Vec<u8>>,

    /// Unix permissions mode
    pub mode: Option<u32>,

    /// Symlink target (if it's a symlink)
    pub link_target: Option<PathBuf>,
}

/// The kind of entry in the destination
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Regular file
    File,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
    /// Entry does not exist
    Missing,
}

impl DestEntry {
    /// Create a new destination entry for a file
    #[must_use]
    pub fn file(path: RelPath, content: Vec<u8>, mode: Option<u32>) -> Self {
        Self {
            path,
            kind: EntryKind::File,
            content: Some(content),
            mode,
            link_target: None,
        }
    }

    /// Create a new destination entry for a directory
    #[must_use]
    pub fn directory(path: RelPath, mode: Option<u32>) -> Self {
        Self {
            path,
            kind: EntryKind::Directory,
            content: None,
            mode,
            link_target: None,
        }
    }

    /// Create a new destination entry for a symlink
    #[must_use]
    pub fn symlink(path: RelPath, target: PathBuf) -> Self {
        Self {
            path,
            kind: EntryKind::Symlink,
            content: None,
            mode: None,
            link_target: Some(target),
        }
    }

    /// Create a new destination entry for a missing file
    #[must_use]
    pub fn missing(path: RelPath) -> Self {
        Self {
            path,
            kind: EntryKind::Missing,
            content: None,
            mode: None,
            link_target: None,
        }
    }

    /// Check if this entry matches a target entry
    ///
    /// Returns `true` if the destination entry matches the target entry
    /// (same type, content, and permissions).
    #[must_use]
    pub fn matches(&self, target: &TargetEntry) -> bool {
        match (self.kind, target) {
            (EntryKind::File, TargetEntry::File { content, mode, .. }) => {
                self.content.as_ref() == Some(content) && self.mode == *mode
            }
            (EntryKind::Directory, TargetEntry::Directory { mode, .. }) => self.mode == *mode,
            (EntryKind::Symlink, TargetEntry::Symlink { target, .. }) => {
                self.link_target.as_ref() == Some(target)
            }
            (EntryKind::Missing, TargetEntry::Remove { .. }) => true,
            // Modify entries don't have a direct destination counterpart
            _ => false,
        }
    }
}
