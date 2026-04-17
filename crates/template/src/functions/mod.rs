//! Template functions module
//!
//! This module provides custom functions and filters for use in templates.
//! Functions are organized into logical submodules:
//!
//! - `system`: System information (OS, arch, hostname, env vars, etc.)
//! - `strings`: String manipulation (trim, regex, split, join, quote)
//! - `data`: Data format conversion (JSON, TOML)
//! - `vault`: Password manager integration (Bitwarden)
//! - `crypto`: Cryptographic operations (encrypt, decrypt, hash)
//! - `files`: File operations (include, `include_template`)

// Submodules
pub mod crypto;
pub mod data;
pub mod files;
pub mod strings;
pub mod system;
pub mod vault;

// Re-export all public functions for backward compatibility

// System functions
pub use system::{arch, env, home_dir, hostname, join_path, look_path, os, username};

// String functions
pub use strings::{join, quote, regex_match, regex_replace_all, split, trim, trim_end, trim_start};

// Data format functions
pub use data::{from_json, from_toml, to_json, to_toml};

// Vault functions
pub use vault::{bitwarden, bitwarden_attachment, bitwarden_fields, bitwarden_secrets};

// Crypto functions
pub use crypto::{blake3sum, decrypt, encrypt};

// File functions
pub use files::{include, include_template};
