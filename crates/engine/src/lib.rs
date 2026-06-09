//! # Guisu Core Engine
//!
//! Core library for the guisu dotfile manager.
//!
//! This crate provides the foundational types and functionality for managing dotfiles:
//!
//! - **Attributes**: Parsing and encoding file attributes in filenames
//! - **State Management**: Three-state architecture (source, target, destination)
//! - **Entry Types**: Representations of files, directories, and symlinks
//! - **Content Processing**: Trait-based processing with pluggable decryption and rendering
//! - **System Abstraction**: Filesystem operations abstracted for testing
//! - **Hooks**: Hook system for custom commands and scripts

pub mod adapters;
pub mod attr;
pub mod content;
pub(crate) mod database;
pub mod entry;
pub mod git;
pub(crate) mod hash;
pub mod hooks;
pub mod processor;
pub mod state;
pub(crate) mod system;
pub mod validator;

// Re-export path types from core
pub use guisu_core::path::{AbsPath, RelPath, SourceRelPath};

// Re-export error types from core
pub use guisu_core::{Error, Result};

// Re-export commonly used types
pub use attr::FileAttributes;
pub use entry::{SourceEntry, TargetEntry};

// Re-export database functions (module is pub(crate))
pub use database::{
    delete_config_metadata, get_config_metadata, get_db_path, get_entry_state,
    save_config_metadata, save_entry_state, save_entry_states_batch,
};

// Re-export hash functions (module is pub(crate))
pub use hash::{hash_content, hash_file};

// Re-export system types (module is pub(crate))
pub use system::{DryRunSystem, Operation, RealSystem, System};

// Re-export state types used by CLI
pub use state::{ConfigMetadata, RedbPersistentState};
