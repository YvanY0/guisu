//! Error types for guisu
//!
//! This module provides unified error types for all guisu crates.
//! All crates (engine, config, crypto, template, etc.) use this single error type.

use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

/// Unified error type for all guisu operations
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    // ========== I/O Errors ==========
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Error reading a file
    #[error("Failed to read file {path}: {source}")]
    FileRead {
        /// Path to the file that failed to read
        path: PathBuf,
        /// Underlying IO error
        #[source]
        source: std::io::Error,
    },

    /// Error writing a file
    #[error("Failed to write file {path}: {source}")]
    FileWrite {
        /// Path to the file that failed to write
        path: PathBuf,
        /// Underlying IO error
        #[source]
        source: std::io::Error,
    },

    /// Error creating a directory
    #[error("Failed to create directory {path}: {source}")]
    DirectoryCreate {
        /// Path to the directory that failed to create
        path: PathBuf,
        /// Underlying IO error
        #[source]
        source: std::io::Error,
    },

    /// Error reading a directory
    #[error("Failed to read directory {path}: {source}")]
    DirectoryRead {
        /// Path to the directory that failed to read
        path: PathBuf,
        /// Underlying IO error
        #[source]
        source: std::io::Error,
    },

    /// Error with file metadata
    #[error("Failed to read metadata for {path}: {source}")]
    Metadata {
        /// Path to the file whose metadata failed to read
        path: PathBuf,
        /// Underlying IO error
        #[source]
        source: std::io::Error,
    },

    // ========== Path Errors ==========
    /// Path is not absolute
    #[error("Path must be absolute: {path}")]
    PathNotAbsolute {
        /// The path that is not absolute
        path: PathBuf,
    },

    /// Path is not relative
    #[error("Path must be relative: {path}")]
    PathNotRelative {
        /// The path that is not relative
        path: PathBuf,
    },

    /// Invalid path prefix
    #[error("Path {} is not under base directory {}", path.display(), base.display())]
    InvalidPathPrefix {
        /// The path that is invalid
        path: Arc<PathBuf>,
        /// The base directory
        base: Arc<PathBuf>,
    },

    /// Generic path error
    #[error("Path error: {0}")]
    Path(String),

    // ========== Attribute Parsing Errors ==========
    /// Invalid attributes in filename
    #[error("Invalid attributes in filename '{filename}': {reason}")]
    InvalidAttributes {
        /// The filename with invalid attributes
        filename: String,
        /// Reason for the error
        reason: String,
    },

    /// Duplicate attribute
    #[error("Duplicate attribute '{attribute}' in filename '{filename}'")]
    DuplicateAttribute {
        /// The filename with duplicate attributes
        filename: String,
        /// The duplicate attribute
        attribute: String,
    },

    /// Invalid attribute order
    #[error(
        "Invalid attribute order in '{filename}'.\n\
         Attributes must be in this order:\n\
         1. private_ or readonly_\n\
         2. executable_\n\
         3. dot_\n\
         \n\
         Got: {found}\n\
         Suggestion: {suggestion}"
    )]
    InvalidAttributeOrder {
        /// The filename with invalid attribute order
        filename: String,
        /// What was found
        found: String,
        /// Suggested correction
        suggestion: String,
    },

    // ========== Entry Errors ==========
    /// Source entry not found
    #[error("Source entry not found: {0}")]
    EntryNotFound(String),

    // ========== Configuration Errors ==========
    /// Invalid configuration
    #[error("Invalid configuration: {message}")]
    InvalidConfig {
        /// Error message
        message: String,
    },

    // ========== Template Errors ==========
    /// Template rendering error
    #[error("Template rendering failed for {path}: {source}")]
    TemplateRender {
        /// Path to the template file
        path: String,
        /// Underlying error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Template rendering error with location details
    #[error("Template error at {location}: {message}")]
    TemplateRenderDetailed {
        /// Location where the error occurred (file, line, column)
        location: String,
        /// Error message describing what went wrong
        message: String,
    },

    /// Template syntax error
    #[error("Template syntax error: {0}")]
    TemplateSyntax(String),

    /// Failed to convert template context
    #[error("Failed to convert template context: {0}")]
    TemplateContextConversion(String),

    // ========== Encryption/Decryption Errors ==========
    /// Age encryption/decryption error
    #[error("Age encryption error: {0}")]
    Age(String),

    /// No recipients provided for encryption
    #[error(
        "No recipients provided for encryption\n\
         \n\
         To fix this:\n\
         1. Add recipients to your .guisu.toml:\n\
         \n\
         [age]\n\
         recipient = \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\"\n\
         \n\
         2. Or generate a recipient from your identity:\n\
            guisu age generate --show-recipient"
    )]
    NoRecipients,

    /// Identity file not found
    #[error(
        "Identity file not found: {path}\n\
         \n\
         To fix this:\n\
         1. Generate a new identity:    guisu age generate\n\
         2. Or check the file path:     ls {path}\n\
         3. Or configure in .guisu.toml:\n\
         \n\
         [age]\n\
         identity = \"{path}\""
    )]
    IdentityNotFound {
        /// Path to the identity file that was not found
        path: String,
    },

    /// Identity file IO error (read/write failures)
    #[error(
        "Failed to {operation} identity file: {path}\n\
         Error: {source}\n\
         \n\
         To fix this:\n\
         1. Check file permissions:     ls -la {path}\n\
         2. Ensure directory exists:    mkdir -p $(dirname {path})\n\
         3. Check disk space:           df -h"
    )]
    IdentityFile {
        /// Operation that failed (read/write)
        operation: String,
        /// Path to the identity file
        path: String,
        /// Underlying IO error
        #[source]
        source: std::io::Error,
    },

    /// Invalid identity format or content
    #[error(
        "Invalid identity: {reason}\n\
         \n\
         Expected format:\n\
         - Age identity:  AGE-SECRET-KEY-1...\n\
         - SSH key:       -----BEGIN OPENSSH PRIVATE KEY-----\n\
         \n\
         To fix this:\n\
         1. Generate a new identity:    guisu age generate\n\
         2. Or use an SSH key:          ~/.ssh/id_ed25519\n\
         3. Check file contents:        cat {path}"
    )]
    InvalidIdentity {
        /// Reason for the invalid identity
        reason: String,
        /// Path to the identity file
        path: String,
    },

    /// Invalid recipient format
    #[error(
        "Invalid recipient: {recipient}\n\
         Reason: {reason}\n\
         \n\
         Expected format: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n\
         \n\
         To fix this:\n\
         1. Get recipient from identity:  guisu age generate --show-recipient\n\
         2. Or from public key file:      cat ~/.config/guisu/key.txt.pub\n\
         3. Check the recipient string carefully"
    )]
    InvalidRecipient {
        /// Invalid recipient string
        recipient: String,
        /// Reason for the invalid recipient
        reason: String,
    },

    /// Decryption failed due to wrong key
    #[error("Decryption failed - wrong key or corrupted data")]
    WrongKey,

    /// Decryption error (generic, with path)
    #[error("Decryption failed for {path}: {source}")]
    Decryption {
        /// Path to the encrypted file
        path: String,
        /// Underlying error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Decryption failed for other reasons
    #[error(
        "Decryption failed: {reason}\n\
         \n\
         To fix this:\n\
         1. Check the encrypted file:   cat <file>\n\
         2. Verify identity is loaded:  guisu doctor\n\
         3. Check file format is valid"
    )]
    DecryptionFailed {
        /// Reason for decryption failure
        reason: String,
    },

    /// No identity available for decryption
    #[error(
        "No identity available for decryption\n\
         \n\
         To fix this:\n\
         1. Generate a new identity:  guisu age generate\n\
         2. Or configure an existing identity in .guisu.toml:\n\
         \n\
         [age]\n\
         identity = \"~/.ssh/id_ed25519\"  # Use SSH key\n\
         # or\n\
         identity = \"~/.config/guisu/key.txt\"  # Use age key"
    )]
    NoIdentity,

    /// Attempted to encrypt empty value
    #[error(
        "Cannot encrypt empty value\n\
         \n\
         To fix this:\n\
         1. Provide non-empty content to encrypt\n\
         2. Or remove the encrypted file attribute if not needed"
    )]
    EmptyValue,

    /// Inline decryption error (for template content)
    #[error("Inline decryption failed: {message}")]
    InlineDecryption {
        /// Error message
        message: String,
    },

    /// Invalid UTF-8 encountered during processing
    #[error("Invalid UTF-8 in {path}: {source}")]
    InvalidUtf8 {
        /// Path to the file with invalid UTF-8
        path: String,
        /// UTF-8 conversion error
        #[source]
        source: std::string::FromUtf8Error,
    },

    // ========== Vault/Secret Manager Errors ==========
    /// Secret provider is not available or not installed
    #[error("Provider not available: {0}")]
    VaultProviderNotAvailable(String),

    /// Authentication is required to access the vault
    #[error("Authentication required: {0}")]
    VaultAuthenticationRequired(String),

    /// The requested secret was not found in the vault
    #[error("Secret not found: {0}")]
    VaultSecretNotFound(String),

    /// Invalid arguments provided to the provider
    #[error("Invalid vault arguments: {0}")]
    VaultInvalidArguments(String),

    /// Command execution failed
    #[error("Vault command execution failed: {0}")]
    VaultExecutionFailed(String),

    /// Failed to parse provider response
    #[error("Failed to parse vault response: {0}")]
    VaultParseError(String),

    /// User cancelled the operation
    #[error("User cancelled vault operation")]
    VaultCancelled,

    /// JSON parsing error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // ========== Hook Errors ==========
    /// Hook configuration error
    #[error("Hook configuration error: {0}")]
    HookConfig(String),

    /// Hook execution error
    #[error("Hook execution failed: {0}")]
    HookExecution(String),

    // ========== Variables Error ==========
    /// Variables loading error
    #[error("Variables error: {0}")]
    Variables(String),

    // ========== State Persistence Errors ==========
    /// State persistence error
    #[error("State error: {0}")]
    State(String),

    /// Database operation error
    #[error("Database error: {0}")]
    Database(String),

    // ========== CLI Command Errors ==========
    /// Path not under destination directory
    #[error("Path {} is not under destination directory {}", path.display(), dest_dir.display())]
    PathNotUnderDestination {
        /// The path that is not under the destination directory
        path: PathBuf,
        /// The destination directory path
        dest_dir: PathBuf,
    },

    /// Apply operation failed
    #[error("Apply failed: {failed} out of {total} entries")]
    ApplyFailed {
        /// Number of entries that failed
        failed: usize,
        /// Total number of entries
        total: usize,
    },

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    /// File already exists
    #[error("File already exists: {0}")]
    FileAlreadyExists(PathBuf),

    /// Git operation error
    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    // ========== Generic Errors ==========
    /// Generic error message
    #[error("{0}")]
    Message(String),

    /// Other error with context
    #[error("{context}: {source}")]
    Other {
        /// Contextual description of the error
        context: String,
        /// Underlying error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl Error {
    /// Create an error with additional context
    #[must_use]
    pub fn context(self, context: impl Into<String>) -> Self {
        Error::Other {
            context: context.into(),
            source: Box::new(self),
        }
    }
}

// Implement From<anyhow::Error> for CLI compatibility
#[cfg(feature = "anyhow")]
impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        // Convert anyhow::Error to a string message
        // We can't box it directly because anyhow::Error doesn't implement std::error::Error
        Error::Message(err.to_string())
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_error_context() {
        let base_error = Error::Message("base error".to_string());
        let error_with_context = base_error.context("additional context");

        let error_string = error_with_context.to_string();
        assert!(error_string.contains("additional context"));
        assert!(error_string.contains("base error"));
    }

    #[test]
    fn test_error_context_chain() {
        let base_error = Error::Message("original".to_string());
        let error = base_error.context("level 1").context("level 2");

        let error_string = error.to_string();
        assert!(error_string.contains("level 2"));
    }
}
