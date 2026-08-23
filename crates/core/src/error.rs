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

    /// SSH key type not supported as an age recipient
    #[error(
        "SSH {key_type} keys cannot be used as age recipients (age 0.11 protocol limitation).\n\
         \n\
         age encryption only supports ssh-rsa as an SSH-based recipient.\n\
         \n\
         Expected format:\n\
         - ssh-rsa  (begins with \"ssh-rsa \")\n\
         - age1...  (bech32 age x25519 public key)\n\
         \n\
         To generate a new age recipient:  guisu age generate --show-recipient"
    )]
    UnsupportedSshKey {
        /// The unsupported SSH key type (e.g. "ssh-ed25519")
        key_type: String,
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
    /// A typed operation against a state-persistence database table failed
    ///
    /// The `#[source]` field preserves the underlying `redb::Error` for
    /// `miette` rendering and `source()` chains.
    #[error("Database {operation} on bucket '{bucket}' failed: {source}")]
    BucketOperation {
        /// What we were trying to do (e.g. `get`, `set`, `begin_write_txn`)
        operation: &'static str,
        /// Which bucket/table was being touched (e.g. `ENTRY_STATE_BUCKET`).
        /// Owned `String` because `bucket` parameters arrive as `&str` from
        /// the public `PersistentState` API — making this `&'static` would
        /// force every caller to pass string literals.
        bucket: String,
        /// The underlying redb error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A typed operation against a state-persistence database transaction failed
    ///
    /// Variant of [`Error::BucketOperation`] for operations not tied to a
    /// specific bucket (begin/commit transactions, table open, etc.).
    #[error("Database {operation} failed: {source}")]
    DatabaseTransaction {
        /// What we were trying to do (e.g. `begin_write`, `commit`, `open_table`)
        operation: &'static str,
        /// The underlying redb error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to serialize a struct into the persistence format (bincode)
    #[error("Failed to serialize {type_name} for {operation}: {source}")]
    StateSerialization {
        /// The struct type being serialized (e.g. `EntryState`, `HookState`)
        type_name: &'static str,
        /// What we were trying to do (e.g. `save`, `build_entry`)
        operation: &'static str,
        /// The underlying bincode/serde error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to deserialize a struct from the persistence format (bincode)
    #[error("Failed to deserialize {type_name} from state: {source}")]
    StateDeserialize {
        /// The struct type being deserialized
        type_name: &'static str,
        /// The underlying bincode/serde error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Unknown bucket name passed to a state persistence operation
    ///
    /// Returned when `PersistentState::get/set/delete/...` is called with a bucket
    /// name that is not registered in the persistence layer. The valid bucket
    /// names are defined by each `PersistentState` implementation.
    #[error("Unknown bucket name: '{name}'. {context}")]
    InvalidBucket {
        /// The invalid bucket name
        name: String,
        /// Context explaining which buckets are valid
        context: String,
    },

    /// Failed to look up the state directory location (XDG / platform)
    #[error("Failed to locate state directory")]
    StateDirectory,

    // ========== Git Errors ==========
    /// A git operation failed
    ///
    /// Wraps a `git2::Error` with a label describing the operation we were
    /// attempting, replacing `Error::Message(format!("Git error: {e}"))`
    /// patterns that lost the operation context.
    #[error("Git {operation} failed: {source}")]
    GitOp {
        /// The git operation being attempted (e.g. "clone", "fetch", "merge")
        operation: &'static str,
        /// The underlying git2 error
        #[source]
        source: git2::Error,
    },

    // ========== Content Processing Errors ==========
    /// Content decryption failed inside the engine pipeline
    #[error("Decryption failed: {source}")]
    DecryptionPipeline {
        /// The underlying decryptor error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Content rendering failed inside the engine pipeline
    #[error("Rendering failed: {source}")]
    RenderingPipeline {
        /// The underlying renderer error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // ========== Vault Errors ==========
    /// Failed to deserialize a cached vault secret from JSON
    #[error("Failed to deserialize cached vault secret: {source}")]
    VaultCacheDeserialize {
        /// The underlying `serde_json` error
        #[source]
        source: serde_json::Error,
    },

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

// Newtype wrapper that adapts `anyhow::Error` to `std::error::Error`.
//
// `anyhow::Error` deliberately does not implement `std::error::Error` directly
// (dtolnay's design choice — preserves type erasure across the anyhow boundary).
// But it *does* provide:
//
//   impl From<Error> for Box<dyn StdError + Send + Sync + 'static>
//   impl AsRef<dyn StdError + Send + Sync> for Error
//   fn source(&self) -> Option<&(dyn StdError + 'static)>   (on ErrorImpl)
//
// So we can store an `anyhow::Error` and delegate both `Display` and
// `source()` to it — preserving the full cause chain (including any
// `.context(...)` segments the caller added in CLI code) when the typed
// `Error` is later displayed by miette.
#[cfg(feature = "anyhow")]
struct AnyhowErrorAdapter(anyhow::Error);

#[cfg(feature = "anyhow")]
impl std::fmt::Debug for AnyhowErrorAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

#[cfg(feature = "anyhow")]
impl std::fmt::Display for AnyhowErrorAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `anyhow::Error`'s own Display only shows the outermost context frame
        // (each `ErrorImpl` knows only its own message). Walk the full chain
        // with Debug formatting so callers see every context layer plus the
        // underlying cause — the same output `anyhow!` would produce via
        // `format!("{:?}", err)`.
        write!(f, "{:?}", self.0)
    }
}

#[cfg(feature = "anyhow")]
impl std::error::Error for AnyhowErrorAdapter {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // anyhow exposes its chain via AsRef<dyn StdError>. Walk through
        // it so callers iterating `std::error::Error::source()` see the
        // same frames they would have seen from the original anyhow error.
        Some(self.0.as_ref())
    }
}

// Implement From<anyhow::Error> for CLI compatibility
#[cfg(feature = "anyhow")]
impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        // Wrap in `Other` so the full anyhow cause chain is preserved through
        // the typed enum rather than flattened to a single string. `Display`
        // shows the anyhow-rendered chain (including `.context(...)` segments);
        // `source()` exposes the underlying concrete error when present.
        Error::Other {
            context: "converted from anyhow::Error".to_string(),
            source: Box::new(AnyhowErrorAdapter(err)),
        }
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

#[cfg(feature = "anyhow")]
mod anyhow_tests {
    #[test]
    fn conversion_preserves_context_chain() {
        // `anyhow::Error::context` is an inherent method (not a trait method),
        // so no `use anyhow::Context` is required.
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let anyhow_err: anyhow::Error = anyhow::Error::new(inner)
            .context("opening config")
            .context("loading guisu source");

        let typed: crate::Error = anyhow_err.into();

        // Display must surface both context layers and the underlying message.
        let rendered = typed.to_string();
        assert!(
            rendered.contains("loading guisu source"),
            "outer context missing from Display: {rendered}"
        );
        assert!(
            rendered.contains("opening config"),
            "inner context missing from Display: {rendered}"
        );
        assert!(
            rendered.contains("file missing"),
            "underlying io::Error message missing: {rendered}"
        );

        // source() chain must walk through to a std::error::Error so callers
        // iterating `std::error::Error::source()` see the underlying cause.
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(&typed);
        let mut depth = 0;
        while let Some(e) = current {
            depth += 1;
            assert!(depth < 16, "source chain looped or was absurdly deep");
            current = e.source();
        }
        assert!(depth >= 2, "expected at least 2 frames, got {depth}");
    }
}
