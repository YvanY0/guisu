//! Error types for CLI commands
//!
//! Re-exports `guisu_core::Error` for use throughout the CLI.

// Re-export guisu_core types for use in the CLI
pub use guisu_core::Error;

/// Result type alias for command operations
pub type Result<T> = guisu_core::Result<T>;
