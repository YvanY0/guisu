//! Cryptographic functions
//!
//! Provides functions for encryption, decryption, and hashing.

use guisu_crypto::{Identity, decrypt_inline, encrypt_inline};
use std::sync::Arc;

/// Decrypt an inline encrypted value: `age:base64(...)`
///
/// This function decrypts values encrypted with the age encryption format.
/// The encrypted value must be in the inline format produced by the `encrypt` filter.
///
/// # Errors
///
/// Returns an error if:
/// - No identities are available for decryption
/// - Decryption fails (wrong key, corrupted data, etc.)
pub fn decrypt(value: &str, identities: &Arc<Vec<Identity>>) -> Result<String, minijinja::Error> {
    decrypt_inline(value, identities).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Decryption failed: {e}"),
        )
    })
}

/// Encrypt a plaintext value to inline encrypted format: `age:base64(...)`
///
/// This filter encrypts plaintext values using the age encryption format.
/// The result is a compact single-line format suitable for embedding in config files.
///
/// # Usage
///
/// ```jinja2
/// {# Encrypt a literal value #}
/// DATABASE_PASSWORD={{ "my-secret-password" | encrypt }}
///
/// {# Encrypt an environment variable #}
/// API_KEY={{ env("API_KEY") | encrypt }}
///
/// {# Encrypt a Bitwarden value #}
/// JWT_SECRET={{ bitwardenFields("item", "MyApp", "jwt_secret") | encrypt }}
///
/// {# Can be combined with other filters #}
/// TOKEN={{ env("TOKEN") | trim | encrypt }}
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - No identities are available for encryption
/// - Encryption fails
///
/// # Note
///
/// This filter requires that the `TemplateEngine` was created with `with_identities()`.
/// If no identities are available, encryption will fail.
///
/// The encrypted value will be different each time (due to encryption nonce),
/// even for the same plaintext.
pub fn encrypt(value: &str, identities: &Arc<Vec<Identity>>) -> Result<String, minijinja::Error> {
    if identities.is_empty() {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "No identity available for encryption.\n\
            \n\
            To fix this:\n\
            1. Generate a new identity:  guisu age generate\n\
            2. Or configure an existing identity in .guisu.toml:\n\
            \n\
            [age]\n\
            identity = \"~/.ssh/id_ed25519\"  # Use SSH key\n\
            # or\n\
            identity = \"~/.config/guisu/key.txt\"  # Use age key",
        ));
    }

    let recipient = identities[0].to_public();
    encrypt_inline(value, &[recipient]).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Encryption failed: {e}"),
        )
    })
}

/// Calculate blake3 hash of a string and return hex-encoded result
///
/// This filter hashes the input string using blake3 and returns the hex-encoded hash.
/// Blake3 is used throughout guisu for content hashing and change detection.
///
/// # Usage
///
/// ```jinja2
/// {# Hash a file's content to track changes #}
/// : << 'BREWFILE_HASH'
/// {{ include("darwin/Brewfile") | blake3sum }}
/// BREWFILE_HASH
///
/// {# Hash inline content #}
/// checksum = {{ "content to hash" | blake3sum }}
/// ```
///
/// # Returns
///
/// Hex-encoded blake3 hash (64 characters, 32 bytes)
///
/// # Examples
///
/// ```jinja2
/// # Track Brewfile changes by its hash
/// : << 'BREWFILE_HASH'
/// {{ include("darwin/Brewfile") | blake3sum }}
/// BREWFILE_HASH
/// ```
#[must_use]
pub fn blake3sum(value: &str) -> String {
    let hash_bytes = blake3::hash(value.as_bytes());
    hex::encode(hash_bytes.as_bytes())
}
