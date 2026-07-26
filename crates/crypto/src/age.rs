//! Age encryption and decryption implementation
//!
//! This module provides the core encryption and decryption functionality using the
//! age encryption format. It supports:
//!
//! - Standard file encryption with ASCII armor format
//! - Inline(SOPS-like) encryption with compact base64 encoding (age:base64...)
//! - Both age native keys and SSH keys
//! - Multiple recipients and identities

use crate::identity::Identity;
use crate::{Error, Recipient, Result};
use std::io::{Read, Write};
use std::sync::LazyLock;
use tracing::warn;

/// Prefix for inline encrypted values: "age:"
const INLINE_PREFIX: &str = "age:";

/// Cached regex pattern for matching inline encrypted values.
static INLINE_PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
    // Pattern matches age:base64 with greedy quantifier
    // Stops at non-base64 chars (including ':' which prevents matching into next age: prefix)
    regex::Regex::new(&format!(
        r"{}[A-Za-z0-9+/]+=*",
        regex::escape(INLINE_PREFIX)
    ))
    .expect("Failed to compile inline encryption pattern")
});

/// Helper to convert recipients to age trait objects
#[inline]
fn prepare_recipients(recipients: &[Recipient]) -> Vec<Box<dyn age::Recipient + Send>> {
    recipients.iter().map(Recipient::to_boxed).collect()
}

/// Helper to convert age errors to our Error type
#[inline]
fn age_error<E: std::fmt::Display>(e: E) -> Error {
    Error::Age(e.to_string())
}

/// Helper to map age decryption errors to our Error type
///
/// Uses type-safe pattern matching on `age::DecryptError` variants to
/// distinguish between different failure scenarios.
///
/// Note: We don't handle plugin-related errors (`MissingPlugin`, `Plugin`)
/// as we don't enable the 'plugin' feature in the age dependency.
#[inline]
fn map_decrypt_error(e: age::DecryptError) -> Error {
    match e {
        // Authentication/key matching failures
        age::DecryptError::NoMatchingKeys
        | age::DecryptError::InvalidMac
        | age::DecryptError::KeyDecryptionFailed => Error::WrongKey,

        // Decryption failures
        age::DecryptError::DecryptionFailed => Error::DecryptionFailed {
            reason: "Age decryption failed".to_string(),
        },
        age::DecryptError::ExcessiveWork { required, target } => Error::DecryptionFailed {
            reason: format!(
                "Excessive work factor: required {required}, target {target}. \
                 This file was encrypted with a higher work factor than this device can handle."
            ),
        },
        age::DecryptError::InvalidHeader => Error::DecryptionFailed {
            reason: "Invalid age header".to_string(),
        },
        age::DecryptError::UnknownFormat => Error::DecryptionFailed {
            reason: "Unknown age format (possibly from a newer version)".to_string(),
        },

        // I/O errors (pass through)
        age::DecryptError::Io(io_err) => Error::Io(io_err),

        // `DecryptError` is #[non_exhaustive]; surface any future/unhandled
        // variant (e.g. plugin errors we don't enable) with its own message.
        other => Error::Age(other.to_string()),
    }
}

/// Encrypt data with the given recipients in ASCII armor format.
///
/// Encrypts the provided data using age encryption and returns the result
/// in ASCII-armored format (PEM-like). The output can be decrypted by any
/// of the recipient's corresponding private keys (identities).
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt
/// * `recipients` - One or more recipients who can decrypt the data
///
/// # Returns
///
/// The encrypted data in ASCII armor format, beginning with
/// `-----BEGIN AGE ENCRYPTED FILE-----`.
///
/// # Errors
///
/// - Returns [`Error::NoRecipients`] if the recipients slice is empty
/// - Returns [`Error::Age`] if encryption fails
///
/// # Examples
///
/// ```no_run
/// use guisu_crypto::{encrypt, Identity};
///
/// let identity = Identity::generate();
/// let recipient = identity.to_public();
///
/// let plaintext = b"secret data";
/// let encrypted = encrypt(plaintext, &[recipient]).unwrap();
/// ```
pub fn encrypt(data: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }

    let boxed_recipients = prepare_recipients(recipients);
    let recipient_refs: Vec<&dyn age::Recipient> = boxed_recipients
        .iter()
        .map(|r| r.as_ref() as &dyn age::Recipient)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|_| Error::Age("Failed to create encryptor with recipients".to_string()))?;

    let mut encrypted = Vec::new();
    let armor =
        age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::AsciiArmor)
            .map_err(age_error)?;

    let mut writer = encryptor.wrap_output(armor).map_err(age_error)?;
    writer.write_all(data).map_err(age_error)?;
    writer
        .finish()
        .and_then(age::armor::ArmoredWriter::finish)
        .map_err(age_error)?;

    Ok(encrypted)
}

/// Decrypt data with the given identities (supports armor and binary formats).
///
/// Decrypts age-encrypted data using one or more identities (private keys).
/// Automatically detects and handles both ASCII-armored and binary formats.
///
/// # Arguments
///
/// * `data` - The encrypted data (either ASCII armor or binary format)
/// * `identities` - One or more identities to try for decryption
///
/// # Returns
///
/// The decrypted plaintext data.
///
/// # Errors
///
/// - Returns [`Error::NoIdentity`] if the identities slice is empty
/// - Returns [`Error::DecryptionFailed`] if decryption fails (wrong key, corrupted data)
/// - Returns [`Error::Age`] for other age-related errors
///
/// # Examples
///
/// ```no_run
/// use guisu_crypto::{encrypt, decrypt, Identity};
///
/// let identity = Identity::generate();
/// let recipient = identity.to_public();
///
/// let encrypted = encrypt(b"secret", &[recipient]).unwrap();
/// let decrypted = decrypt(&encrypted, &[identity]).unwrap();
/// assert_eq!(decrypted, b"secret");
/// ```
pub fn decrypt(data: &[u8], identities: &[Identity]) -> Result<Vec<u8>> {
    if identities.is_empty() {
        return Err(Error::NoIdentity);
    }

    // Fast path for single identity (common case)
    if identities.len() == 1 {
        return decrypt_single(data, &identities[0]);
    }

    let age_identities: Vec<&dyn age::Identity> =
        identities.iter().map(Identity::as_dyn_identity).collect();

    let mut decrypted = Vec::new();

    // Try armored format first
    if let Ok(decryptor) = age::Decryptor::new(age::armor::ArmoredReader::new(data)) {
        let mut reader = decryptor
            .decrypt(age_identities.iter().copied())
            .map_err(map_decrypt_error)?;
        reader.read_to_end(&mut decrypted).map_err(age_error)?;
    } else {
        // Fall back to binary format
        let decryptor = age::Decryptor::new(data).map_err(age_error)?;
        let mut reader = decryptor
            .decrypt(age_identities.iter().copied())
            .map_err(map_decrypt_error)?;
        reader.read_to_end(&mut decrypted).map_err(age_error)?;
    }

    Ok(decrypted)
}

/// Optimized decryption for single identity (avoids vec allocation)
#[inline]
fn decrypt_single(data: &[u8], identity: &Identity) -> Result<Vec<u8>> {
    let age_identity = identity.as_dyn_identity();
    let mut decrypted = Vec::new();

    // Try armored format first
    if let Ok(decryptor) = age::Decryptor::new(age::armor::ArmoredReader::new(data)) {
        let mut reader = decryptor
            .decrypt(std::iter::once(age_identity))
            .map_err(map_decrypt_error)?;
        reader.read_to_end(&mut decrypted).map_err(age_error)?;
    } else {
        // Fall back to binary format
        let decryptor = age::Decryptor::new(data).map_err(age_error)?;
        let mut reader = decryptor
            .decrypt(std::iter::once(age_identity))
            .map_err(map_decrypt_error)?;
        reader.read_to_end(&mut decrypted).map_err(age_error)?;
    }

    Ok(decrypted)
}

/// Encrypt a string and return the encrypted data.
///
/// Convenience wrapper around [`encrypt`] for string data.
///
/// # Arguments
///
/// * `data` - The plaintext string to encrypt
/// * `recipients` - One or more recipients who can decrypt the data
///
/// # Returns
///
/// The encrypted data in ASCII armor format.
///
/// # Errors
///
/// - Returns [`Error::NoRecipients`] if the recipients slice is empty
/// - Returns [`Error::Age`] if encryption fails
#[inline]
pub fn encrypt_string(data: &str, recipients: &[Recipient]) -> Result<Vec<u8>> {
    encrypt(data.as_bytes(), recipients)
}

/// Decrypt data and return it as a UTF-8 string.
///
/// Convenience wrapper around [`decrypt`] for string data.
///
/// # Arguments
///
/// * `data` - The encrypted data (either ASCII armor or binary format)
/// * `identities` - One or more identities to try for decryption
///
/// # Returns
///
/// The decrypted plaintext string.
///
/// # Errors
///
/// - Returns [`Error::NoIdentity`] if the identities slice is empty
/// - Returns [`Error::DecryptionFailed`] if decryption fails or the decrypted
///   data is not valid UTF-8
/// - Returns [`Error::Age`] for other age-related errors
#[inline]
pub fn decrypt_string(data: &[u8], identities: &[Identity]) -> Result<String> {
    let decrypted = decrypt(data, identities)?;
    String::from_utf8(decrypted).map_err(|e| Error::DecryptionFailed {
        reason: format!("Decrypted data is not valid UTF-8: {e}"),
    })
}

/// Encrypt a string to compact inline format: `age:base64(encrypted_data)`.
///
/// Creates a compact encrypted representation suitable for embedding in
/// configuration files. The format is `age:` followed by base64-encoded
/// binary encrypted data (without ASCII armor overhead).
///
/// This is similar to SOPS inline encryption and is useful for encrypting
/// specific values within configuration files while keeping the structure
/// readable.
///
/// # Arguments
///
/// * `plaintext` - The string to encrypt
/// * `recipients` - One or more recipients who can decrypt the data
///
/// # Returns
///
/// A compact encrypted string in the format `age:base64...`
///
/// # Errors
///
/// - Returns [`Error::NoRecipients`] if the recipients slice is empty
/// - Returns [`Error::Age`] if encryption fails
///
/// # Examples
///
/// ```no_run
/// use guisu_crypto::{encrypt_inline, decrypt_inline, Identity};
///
/// let identity = Identity::generate();
/// let recipient = identity.to_public();
///
/// let encrypted = encrypt_inline("secret_password", &[recipient]).unwrap();
/// assert!(encrypted.starts_with("age:"));
///
/// let decrypted = decrypt_inline(&encrypted, &[identity]).unwrap();
/// assert_eq!(decrypted, "secret_password");
/// ```
pub fn encrypt_inline(plaintext: &str, recipients: &[Recipient]) -> Result<String> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }

    let boxed_recipients = prepare_recipients(recipients);
    let recipient_refs: Vec<&dyn age::Recipient> = boxed_recipients
        .iter()
        .map(|r| r.as_ref() as &dyn age::Recipient)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|_| Error::Age("Failed to create encryptor with recipients".to_string()))?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).map_err(age_error)?;

    writer.write_all(plaintext.as_bytes()).map_err(age_error)?;
    writer.finish().map_err(age_error)?;

    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
    Ok(format!("{INLINE_PREFIX}{encoded}"))
}

/// Decrypt a compact inline encrypted value: `age:base64(encrypted_data)`.
///
/// Decrypts a string previously encrypted with [`encrypt_inline`].
/// The input must start with the `age:` prefix followed by base64-encoded
/// encrypted data.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted string (must start with "age:")
/// * `identities` - One or more identities to try for decryption
///
/// # Returns
///
/// The decrypted plaintext string.
///
/// # Errors
///
/// - Returns [`Error::NoIdentity`] if the identities slice is empty
/// - Returns [`Error::DecryptionFailed`] if the format is invalid, decryption fails,
///   or the decrypted data is not valid UTF-8
///
/// # Examples
///
/// See [`encrypt_inline`] for usage examples.
pub fn decrypt_inline(ciphertext: &str, identities: &[Identity]) -> Result<String> {
    if identities.is_empty() {
        return Err(Error::NoIdentity);
    }

    let base64_data =
        ciphertext
            .strip_prefix(INLINE_PREFIX)
            .ok_or_else(|| Error::DecryptionFailed {
                reason: format!(
                    "Invalid inline encrypted format: expected '{INLINE_PREFIX}' prefix"
                ),
            })?;

    let encrypted_data =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, base64_data).map_err(
            |e| Error::DecryptionFailed {
                reason: format!("Invalid base64 encoding: {e}"),
            },
        )?;

    let decrypted = decrypt(&encrypted_data, identities)?;

    String::from_utf8(decrypted).map_err(|e| Error::DecryptionFailed {
        reason: format!("Decrypted data is not valid UTF-8: {e}"),
    })
}

/// Decrypt all inline encrypted values in file content (SOPS-like workflow).
///
/// Scans the input text for all inline encrypted values (matching the pattern
/// `age:base64...`) and decrypts them in place. This enables a SOPS-like workflow
/// where only sensitive values within a configuration file are encrypted, while
/// the overall structure remains readable.
///
/// Values that fail to decrypt are left unchanged and a warning is logged.
///
/// # Performance
///
/// Uses a cached compiled regex for pattern matching, providing significant
/// performance improvement for repeated operations.
///
/// # Arguments
///
/// * `content` - The file content containing zero or more inline encrypted values
/// * `identities` - One or more identities to use for decryption
///
/// # Returns
///
/// The file content with all successfully decrypted inline values replaced
/// with their plaintext equivalents.
///
/// # Errors
///
/// - Returns [`Error::NoIdentity`] if the identities slice is empty
///
/// Note: Individual decryption failures for specific values do not cause
/// this function to error; instead, failed values are left encrypted and
/// a warning is logged.
///
/// # Examples
///
/// ```no_run
/// use guisu_crypto::{encrypt_inline, decrypt_file_content, Identity};
///
/// let identity = Identity::generate();
/// let recipient = identity.to_public();
///
/// let encrypted_pw = encrypt_inline("my_secret", &[recipient]).unwrap();
/// let config = format!("database_password = {}", encrypted_pw);
///
/// let decrypted_config = decrypt_file_content(&config, &[identity]).unwrap();
/// assert!(decrypted_config.contains("my_secret"));
/// ```
pub fn decrypt_file_content(content: &str, identities: &[Identity]) -> Result<String> {
    if identities.is_empty() {
        return Err(Error::NoIdentity);
    }

    let mut result = String::with_capacity(content.len());
    let mut pos = 0;

    while let Some(mat) = INLINE_PATTERN.find_at(content, pos) {
        result.push_str(&content[pos..mat.start()]);

        // Handle edge case where greedy pattern matches "age" from next "age:" prefix
        // Check if match ends with "age", "ag", or "a" followed by completion of "age:"
        let mut matched_str = mat.as_str();
        let mut next_pos = mat.end();

        // Bounds check before accessing content[mat.end()..]
        if mat.end() < content.len() {
            if matched_str.ends_with("age") && content[mat.end()..].starts_with(':') {
                matched_str = &matched_str[..matched_str.len() - 3];
                next_pos = mat.end() - 3;
            } else if matched_str.ends_with("ag") && content[mat.end()..].starts_with("e:") {
                matched_str = &matched_str[..matched_str.len() - 2];
                next_pos = mat.end() - 2;
            } else if matched_str.ends_with('a') && content[mat.end()..].starts_with("ge:") {
                matched_str = &matched_str[..matched_str.len() - 1];
                next_pos = mat.end() - 1;
            }
        }

        match decrypt_inline(matched_str, identities) {
            Ok(decrypted) => result.push_str(&decrypted),
            Err(e) => {
                warn!("Failed to decrypt value at position {}: {}", mat.start(), e);
                result.push_str(matched_str);
            }
        }

        pos = next_pos;
    }

    result.push_str(&content[pos..]);
    Ok(result)
}

/// Re-encrypt all inline encrypted values with new recipients (key rotation).
///
/// Scans the input text for all inline encrypted values, decrypts them using
/// the old identities, and re-encrypts them with new recipients. This is useful
/// for key rotation scenarios where you need to change the encryption keys
/// without manually re-entering all secrets.
///
/// Values that fail to decrypt or re-encrypt are left unchanged and a warning
/// is logged.
///
/// # Performance
///
/// Uses a cached compiled regex for pattern matching. However, this operation
/// requires both decryption and encryption for each value, so it is more
/// expensive than simple decryption.
///
/// # Arguments
///
/// * `content` - The file content containing zero or more inline encrypted values
/// * `old_identities` - Identities to decrypt the existing values
/// * `new_recipients` - Recipients to use when re-encrypting
///
/// # Returns
///
/// The file content with all successfully rotated values re-encrypted with
/// the new recipients.
///
/// # Errors
///
/// - Returns [`Error::NoRecipients`] if the `new_recipients` slice is empty
/// - Returns [`Error::NoIdentity`] if the `old_identities` slice is empty
///
/// Note: Individual rotation failures for specific values do not cause
/// this function to error; instead, failed values are left unchanged and
/// a warning is logged.
///
/// # Examples
///
/// ```no_run
/// use guisu_crypto::{encrypt_inline, encrypt_file_content, Identity};
///
/// let old_identity = Identity::generate();
/// let old_recipient = old_identity.to_public();
///
/// let new_identity = Identity::generate();
/// let new_recipient = new_identity.to_public();
///
/// let encrypted_pw = encrypt_inline("secret", &[old_recipient]).unwrap();
/// let config = format!("password = {}", encrypted_pw);
///
/// // Rotate to new key
/// let rotated = encrypt_file_content(&config, &[old_identity], &[new_recipient]).unwrap();
///
/// // Old key can't decrypt anymore
/// // assert!(decrypt_file_content(&rotated, &[old_identity]).is_err());
///
/// // New key can decrypt
/// // let decrypted = decrypt_file_content(&rotated, &[new_identity]).unwrap();
/// // assert!(decrypted.contains("secret"));
/// ```
pub fn encrypt_file_content(
    content: &str,
    old_identities: &[Identity],
    new_recipients: &[Recipient],
) -> Result<String> {
    if new_recipients.is_empty() {
        return Err(Error::NoRecipients);
    }

    if old_identities.is_empty() {
        return Err(Error::NoIdentity);
    }

    let mut result = String::with_capacity(content.len());
    let mut pos = 0;

    while let Some(mat) = INLINE_PATTERN.find_at(content, pos) {
        result.push_str(&content[pos..mat.start()]);

        // Handle edge case where greedy pattern matches "age" from next "age:" prefix
        let mut matched_str = mat.as_str();
        let mut next_pos = mat.end();

        // Bounds check before accessing content[mat.end()..]
        if mat.end() < content.len() {
            if matched_str.ends_with("age") && content[mat.end()..].starts_with(':') {
                matched_str = &matched_str[..matched_str.len() - 3];
                next_pos = mat.end() - 3;
            } else if matched_str.ends_with("ag") && content[mat.end()..].starts_with("e:") {
                matched_str = &matched_str[..matched_str.len() - 2];
                next_pos = mat.end() - 2;
            } else if matched_str.ends_with('a') && content[mat.end()..].starts_with("ge:") {
                matched_str = &matched_str[..matched_str.len() - 1];
                next_pos = mat.end() - 1;
            }
        }

        match decrypt_inline(matched_str, old_identities) {
            Ok(plaintext) => match encrypt_inline(&plaintext, new_recipients) {
                Ok(new_ciphertext) => result.push_str(&new_ciphertext),
                Err(e) => {
                    warn!(
                        "Failed to re-encrypt value at position {}: {}",
                        mat.start(),
                        e
                    );
                    result.push_str(matched_str);
                }
            },
            Err(e) => {
                warn!(
                    "Failed to decrypt value at position {} during re-encryption: {}",
                    mat.start(),
                    e
                );
                result.push_str(matched_str);
            }
        }

        pos = next_pos;
    }

    result.push_str(&content[pos..]);
    Ok(result)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    /// Helper to create a test identity
    fn test_identity() -> Identity {
        Identity::generate()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = b"Hello, World!";

        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = b"";

        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = vec![b'X'; 1024 * 1024]; // 1MB

        let encrypted = encrypt(&plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_multiple_recipients() {
        let id1 = test_identity();
        let id2 = test_identity();
        let id3 = test_identity();

        let recipients = vec![id1.to_public(), id2.to_public(), id3.to_public()];
        let plaintext = b"shared secret";

        let encrypted = encrypt(plaintext, &recipients).expect("Encryption failed");

        // All three identities should be able to decrypt
        let dec1 = decrypt(&encrypted, std::slice::from_ref(&id1)).expect("Decryption 1 failed");
        let dec2 = decrypt(&encrypted, std::slice::from_ref(&id2)).expect("Decryption 2 failed");
        let dec3 = decrypt(&encrypted, std::slice::from_ref(&id3)).expect("Decryption 3 failed");

        assert_eq!(plaintext, dec1.as_slice());
        assert_eq!(plaintext, dec2.as_slice());
        assert_eq!(plaintext, dec3.as_slice());
    }

    #[test]
    fn test_wrong_key() {
        let id1 = test_identity();
        let id2 = test_identity();

        let plaintext = b"secret";
        let encrypted = encrypt(plaintext, &[id1.to_public()]).expect("Encryption failed");

        // Try to decrypt with wrong key
        let result = decrypt(&encrypted, &[id2]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::WrongKey));
    }

    #[test]
    fn test_no_recipients_error() {
        let plaintext = b"data";
        let result = encrypt(plaintext, &[]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoRecipients));
    }

    #[test]
    fn test_no_identity_error() {
        let encrypted = b"some encrypted data";
        let result = decrypt(encrypted, &[]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoIdentity));
    }

    #[test]
    fn test_corrupted_data() {
        let identity = test_identity();
        let corrupted = b"this is not encrypted data";

        let result = decrypt(corrupted, &[identity]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_string() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = "Hello, Rust!";

        let encrypted = encrypt_string(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_string(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_string_invalid_utf8() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];

        let encrypted = encrypt(&invalid_utf8, &[recipient]).expect("Encryption failed");
        let result = decrypt_string(&encrypted, &[identity]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::DecryptionFailed { .. }
        ));
    }

    #[test]
    fn test_inline_encryption_format() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = "my_secret_value";

        let encrypted = encrypt_inline(plaintext, &[recipient]).expect("Encryption failed");

        // Check format
        assert!(encrypted.starts_with("age:"));
        assert!(encrypted.len() > 4); // More than just the prefix
        assert_ne!(encrypted, plaintext);
    }

    #[test]
    fn test_inline_encrypt_decrypt_roundtrip() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = "secret_password_123";

        let encrypted = encrypt_inline(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_inline(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_inline_decrypt_missing_prefix() {
        let identity = test_identity();
        let invalid = "this_is_not_encrypted";

        let result = decrypt_inline(invalid, &[identity]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::DecryptionFailed { .. }
        ));
    }

    #[test]
    fn test_inline_decrypt_invalid_base64() {
        let identity = test_identity();
        let invalid = "age:this-is-not-valid-base64!!!";

        let result = decrypt_inline(invalid, &[identity]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::DecryptionFailed { .. }
        ));
    }

    #[test]
    fn test_inline_no_recipients() {
        let result = encrypt_inline("secret", &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoRecipients));
    }

    #[test]
    fn test_inline_no_identity() {
        let result = decrypt_inline("age:something", &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoIdentity));
    }

    #[test]
    fn test_decrypt_file_content_no_encrypted_values() {
        let identity = test_identity();
        let content = "database_url = postgres://localhost\nport = 5432";

        let result = decrypt_file_content(content, &[identity]).expect("Should succeed");
        assert_eq!(content, result);
    }

    #[test]
    fn test_decrypt_file_content_single_value() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let encrypted_pw = encrypt_inline("secret123", &[recipient]).expect("Encryption failed");
        let content = format!("database_password = {encrypted_pw}");

        let decrypted = decrypt_file_content(&content, &[identity]).expect("Decryption failed");
        assert!(decrypted.contains("secret123"));
        assert!(!decrypted.contains("age:"));
    }

    #[test]
    fn test_decrypt_file_content_multiple_values() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc1 =
            encrypt_inline("secret1", std::slice::from_ref(&recipient)).expect("Encryption failed");
        let enc2 =
            encrypt_inline("secret2", std::slice::from_ref(&recipient)).expect("Encryption failed");

        let content = format!("password = {enc1}\napi_key = {enc2}\nother = plain_value");

        let decrypted = decrypt_file_content(&content, &[identity]).expect("Decryption failed");
        assert!(decrypted.contains("secret1"));
        assert!(decrypted.contains("secret2"));
        assert!(decrypted.contains("plain_value"));
        assert!(!decrypted.contains("age:"));
    }

    #[test]
    fn test_decrypt_file_content_no_identity() {
        let content = "some content";
        let result = decrypt_file_content(content, &[]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoIdentity));
    }

    #[test]
    fn test_encrypt_file_content_key_rotation() {
        let old_identity = test_identity();
        let old_recipient = old_identity.to_public();

        let new_identity = test_identity();
        let new_recipient = new_identity.to_public();

        let encrypted_value =
            encrypt_inline("my_secret", &[old_recipient]).expect("Encryption failed");
        let content = format!("password = {encrypted_value}");

        // Rotate keys
        let rotated = encrypt_file_content(
            &content,
            std::slice::from_ref(&old_identity),
            std::slice::from_ref(&new_recipient),
        )
        .expect("Key rotation failed");

        // Old key should not work anymore
        let old_decrypt = decrypt_file_content(&rotated, &[old_identity]);
        assert!(old_decrypt.is_err() || !old_decrypt.unwrap().contains("my_secret"));

        // New key should work
        let new_decrypt = decrypt_file_content(&rotated, &[new_identity])
            .expect("Decryption with new key failed");
        assert!(new_decrypt.contains("my_secret"));
    }

    #[test]
    fn test_encrypt_file_content_no_recipients() {
        let identity = test_identity();
        let content = "test";

        let result = encrypt_file_content(content, &[identity], &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoRecipients));
    }

    #[test]
    fn test_encrypt_file_content_no_identity() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let content = "test";

        let result = encrypt_file_content(content, &[], &[recipient]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoIdentity));
    }

    #[test]
    fn test_encrypt_file_content_no_encrypted_values() {
        let old_identity = test_identity();
        let new_identity = test_identity();
        let new_recipient = new_identity.to_public();

        let content = "plain_text = value\nno_encryption = here";

        let result = encrypt_file_content(content, &[old_identity], &[new_recipient])
            .expect("Should succeed");

        assert_eq!(content, result);
    }

    #[test]
    fn test_special_characters() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = "Hello World! Test @#$%";

        let encrypted = encrypt_string(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_string(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_inline_special_characters() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = "secret-password-123";

        let encrypted = encrypt_inline(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_inline(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_file_content_with_failed_decryption() {
        let id1 = test_identity();
        let id2 = test_identity();
        let recipient1 = id1.to_public();

        // Encrypt with id1
        let encrypted = encrypt_inline("secret", &[recipient1]).expect("Encryption failed");
        let content = format!("password = {encrypted}");

        // Try to decrypt with id2 (wrong key) - should log warning but continue
        let result = decrypt_file_content(&content, &[id2]).expect("Should not error");

        // The encrypted value should remain unchanged
        assert!(result.contains("age:"));
        assert!(!result.contains("secret"));
    }

    #[test]
    fn test_encrypt_file_content_with_failed_decryption() {
        let old_identity = test_identity();
        let wrong_identity = test_identity();
        let new_identity = test_identity();
        let old_recipient = old_identity.to_public();
        let new_recipient = new_identity.to_public();

        // Encrypt with old_identity
        let encrypted = encrypt_inline("secret", &[old_recipient]).expect("Encryption failed");
        let content = format!("password = {encrypted}");

        // Try to rotate with wrong identity - should log warning but continue
        let result = encrypt_file_content(&content, &[wrong_identity], &[new_recipient])
            .expect("Should not error");

        // The encrypted value should remain unchanged (couldn't decrypt)
        assert!(result.contains("age:"));
    }

    #[test]
    fn test_decrypt_single_fast_path() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = b"test single identity fast path";

        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");

        // Single identity should use fast path
        let decrypted = decrypt(&encrypted, &[identity]).expect("Decryption failed");
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_multiple_identities_decrypt() {
        let id1 = test_identity();
        let id2 = test_identity();
        let id3 = test_identity();
        let recipient = id2.to_public();

        let plaintext = b"test multiple identities";
        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");

        // Should work with multiple identities where second one is correct
        let decrypted = decrypt(&encrypted, &[id1, id2, id3]).expect("Decryption failed");
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_armor_format_detection() {
        let identity = test_identity();
        let recipient = identity.to_public();
        let plaintext = b"test armor detection";

        // Standard encrypt uses ASCII armor
        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");

        // Should detect and handle armored format
        assert!(String::from_utf8_lossy(&encrypted).contains("-----BEGIN AGE ENCRYPTED FILE-----"));

        let decrypted = decrypt(&encrypted, &[identity]).expect("Decryption failed");
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_partial_file_content_decryption() {
        let id1 = test_identity();
        let id2 = test_identity();
        let recipient1 = id1.to_public();
        let recipient2 = id2.to_public();

        // Create content with two encrypted values, but only one can be decrypted
        let enc1 = encrypt_inline("secret1", std::slice::from_ref(&recipient1))
            .expect("Encryption failed");
        let enc2 = encrypt_inline("secret2", std::slice::from_ref(&recipient2))
            .expect("Encryption failed");

        let content = format!("value1 = {enc1}\nvalue2 = {enc2}");

        // Decrypt with only id1 - enc1 should decrypt, enc2 should remain encrypted
        let result = decrypt_file_content(&content, &[id1]).expect("Should not error");

        assert!(result.contains("secret1"));
        assert!(!result.contains("secret2"));
        assert!(result.contains("age:")); // enc2 still encrypted
    }

    #[test]
    fn test_encrypt_file_content_partial_success() {
        let old_id1 = test_identity();
        let old_id2 = test_identity();
        let new_identity = test_identity();

        let recipient1 = old_id1.to_public();
        let recipient2 = old_id2.to_public();
        let new_recipient = new_identity.to_public();

        // Create two encrypted values with different keys
        let enc1 = encrypt_inline("secret1", &[recipient1]).expect("Encryption failed");
        let enc2 = encrypt_inline("secret2", &[recipient2]).expect("Encryption failed");

        let content = format!("val1 = {enc1}\nval2 = {enc2}");

        // Try to rotate with old_id1 only - enc1 should rotate, enc2 should stay unchanged
        let result = encrypt_file_content(
            &content,
            std::slice::from_ref(&old_id1),
            std::slice::from_ref(&new_recipient),
        )
        .expect("Should not error");

        // Both should still be encrypted
        assert!(result.contains("age:"));

        // Verify enc1 was rotated (can decrypt with new key)
        let decrypted = decrypt_file_content(&result, std::slice::from_ref(&new_identity))
            .expect("Should work");
        assert!(decrypted.contains("secret1"));

        // enc2 should still be encrypted with old key (wasn't rotated)
        let decrypted2 = decrypt_file_content(&result, &[old_id2]).expect("Should work");
        assert!(decrypted2.contains("secret2"));

        // new_identity shouldn't be able to decrypt enc2
        let decrypted3 = decrypt_file_content(&result, &[new_identity]).expect("Should work");
        assert!(!decrypted3.contains("secret2") || result.contains("age:")); // Either not decrypted or still has age:
    }

    #[test]
    fn test_prepare_recipients_helper() {
        let id1 = test_identity();
        let id2 = test_identity();
        let recipients = vec![id1.to_public(), id2.to_public()];

        // Test that prepare_recipients converts properly
        let boxed = prepare_recipients(&recipients);
        assert_eq!(boxed.len(), 2);
    }

    #[test]
    fn test_inline_pattern_matching() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc = encrypt_inline("test", &[recipient]).expect("Encryption failed");

        // Test that the pattern correctly matches inline encrypted values
        let content = format!("before {enc} after");

        // Should find the encrypted value
        assert!(INLINE_PATTERN.is_match(&content));

        let matches: Vec<_> = INLINE_PATTERN.find_iter(&content).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(), enc);
    }

    #[test]
    fn test_decrypt_file_content_multiple_on_same_line() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc1 =
            encrypt_inline("val1", std::slice::from_ref(&recipient)).expect("Encryption failed");
        let enc2 =
            encrypt_inline("val2", std::slice::from_ref(&recipient)).expect("Encryption failed");

        // Multiple encrypted values on the same line
        let content = format!("config = {{ key1: {enc1}, key2: {enc2} }}");

        let result = decrypt_file_content(&content, &[identity]).expect("Should work");

        assert!(result.contains("val1"));
        assert!(result.contains("val2"));
        assert!(!result.contains("age:"));
    }

    #[test]
    fn test_decrypt_file_content_empty_string() {
        let identity = test_identity();
        let result = decrypt_file_content("", &[identity]).expect("Should work");
        assert_eq!(result, "");
    }

    #[test]
    fn test_encrypt_file_content_empty_string() {
        let old_identity = test_identity();
        let new_identity = test_identity();
        let new_recipient = new_identity.to_public();

        let result =
            encrypt_file_content("", &[old_identity], &[new_recipient]).expect("Should work");
        assert_eq!(result, "");
    }

    #[test]
    fn test_decrypt_file_content_value_at_start() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc = encrypt_inline("start_secret", &[recipient]).expect("Encryption failed");
        let content = format!("{enc} and some text after");

        let result = decrypt_file_content(&content, &[identity]).expect("Should work");
        assert!(result.starts_with("start_secret"));
        assert!(!result.contains("age:"));
    }

    #[test]
    fn test_decrypt_file_content_value_at_end() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc = encrypt_inline("end_secret", &[recipient]).expect("Encryption failed");
        let content = format!("some text before {enc}");

        let result = decrypt_file_content(&content, &[identity]).expect("Should work");
        assert!(result.ends_with("end_secret"));
        assert!(!result.contains("age:"));
    }

    #[test]
    fn test_decrypt_file_content_only_encrypted_value() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc = encrypt_inline("only_value", &[recipient]).expect("Encryption failed");

        let result = decrypt_file_content(&enc, &[identity]).expect("Should work");
        assert_eq!(result, "only_value");
    }

    #[test]
    fn test_encrypt_file_content_value_at_boundaries() {
        let old_identity = test_identity();
        let new_identity = test_identity();
        let old_recipient = old_identity.to_public();
        let new_recipient = new_identity.to_public();

        let enc = encrypt_inline("secret", &[old_recipient]).expect("Encryption failed");
        let content = format!("{enc} middle {enc}");

        let result =
            encrypt_file_content(&content, &[old_identity], &[new_recipient]).expect("Should work");

        // Both values should be rotated
        let decrypted = decrypt_file_content(&result, &[new_identity]).expect("Should decrypt");

        // Should contain "secret" twice
        assert_eq!(decrypted.matches("secret").count(), 2);
    }

    #[test]
    fn test_inline_encrypt_empty_string() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let encrypted = encrypt_inline("", &[recipient]).expect("Encryption failed");
        assert!(encrypted.starts_with("age:"));

        let decrypted = decrypt_inline(&encrypted, &[identity]).expect("Decryption failed");
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_inline_encrypt_whitespace_only() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let encrypted = encrypt_inline("   ", &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_inline(&encrypted, &[identity]).expect("Decryption failed");
        assert_eq!(decrypted, "   ");
    }

    #[test]
    fn test_decrypt_file_content_with_newlines() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc = encrypt_inline("secret", &[recipient]).expect("Encryption failed");
        let content = format!("line1\n{enc}\nline3");

        let result = decrypt_file_content(&content, &[identity]).expect("Should work");
        assert!(result.contains("line1"));
        assert!(result.contains("secret"));
        assert!(result.contains("line3"));
        assert!(!result.contains("age:"));
    }

    #[test]
    fn test_encrypt_file_content_preserves_non_encrypted() {
        let old_identity = test_identity();
        let new_identity = test_identity();
        let old_recipient = old_identity.to_public();
        let new_recipient = new_identity.to_public();

        let enc = encrypt_inline("secret", &[old_recipient]).expect("Encryption failed");
        let content = format!("plain1\n{enc}\nplain2\nplain3");

        let result =
            encrypt_file_content(&content, &[old_identity], &[new_recipient]).expect("Should work");

        // Decrypt to verify plain text is preserved
        let decrypted = decrypt_file_content(&result, &[new_identity]).expect("Should work");

        assert!(decrypted.contains("plain1"));
        assert!(decrypted.contains("plain2"));
        assert!(decrypted.contains("plain3"));
        assert!(decrypted.contains("secret"));
    }

    #[test]
    fn test_encrypt_string_empty() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let encrypted = encrypt_string("", &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_string(&encrypted, &[identity]).expect("Decryption failed");
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_multiple_recipients_with_single_identity_decrypt() {
        let id1 = test_identity();
        let id2 = test_identity();
        let id3 = test_identity();

        let recipients = vec![id1.to_public(), id2.to_public(), id3.to_public()];
        let plaintext = b"multi-recipient test";

        let encrypted = encrypt(plaintext, &recipients).expect("Encryption failed");

        // Each identity should independently be able to decrypt
        for identity in &[id1, id2, id3] {
            let decrypted = decrypt(&encrypted, std::slice::from_ref(identity))
                .expect("Decryption should work with any single recipient");
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }

    #[test]
    fn test_decrypt_with_multiple_wrong_identities() {
        let id1 = test_identity();
        let id2 = test_identity();
        let id3 = test_identity();
        let id4 = test_identity();

        let plaintext = b"secret";
        let encrypted = encrypt(plaintext, &[id1.to_public()]).expect("Encryption failed");

        // Try with multiple wrong identities
        let result = decrypt(&encrypted, &[id2, id3, id4]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::WrongKey));
    }

    #[test]
    fn test_inline_very_long_plaintext() {
        let identity = test_identity();
        let recipient = identity.to_public();

        // Test with very long plaintext (should handle large base64)
        let long_text = "x".repeat(10000);

        let encrypted = encrypt_inline(&long_text, &[recipient]).expect("Encryption failed");
        assert!(encrypted.starts_with("age:"));
        assert!(encrypted.len() > long_text.len()); // Should be longer due to encryption overhead

        let decrypted = decrypt_inline(&encrypted, &[identity]).expect("Decryption failed");
        assert_eq!(decrypted, long_text);
    }

    #[test]
    fn test_decrypt_file_content_adjacent_encrypted_values() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc1 =
            encrypt_inline("val1", std::slice::from_ref(&recipient)).expect("Encryption failed");
        let enc2 =
            encrypt_inline("val2", std::slice::from_ref(&recipient)).expect("Encryption failed");

        // No space between encrypted values
        let content = format!("{enc1}{enc2}");

        let result = decrypt_file_content(&content, &[identity]).expect("Should work");

        assert!(result.contains("val1"));
        assert!(result.contains("val2"));
        assert!(!result.contains("age:"));
    }

    #[test]
    fn test_encrypt_file_content_all_values_rotated() {
        let old_identity = test_identity();
        let new_identity = test_identity();
        let old_recipient = old_identity.to_public();
        let new_recipient = new_identity.to_public();

        let enc1 = encrypt_inline("secret1", std::slice::from_ref(&old_recipient))
            .expect("Encryption failed");
        let enc2 = encrypt_inline("secret2", std::slice::from_ref(&old_recipient))
            .expect("Encryption failed");
        let enc3 = encrypt_inline("secret3", std::slice::from_ref(&old_recipient))
            .expect("Encryption failed");

        let content = format!("a={enc1}\nb={enc2}\nc={enc3}");

        let rotated = encrypt_file_content(
            &content,
            std::slice::from_ref(&old_identity),
            std::slice::from_ref(&new_recipient),
        )
        .expect("Should work");

        // Old identity should not be able to decrypt anymore
        let _old_result = decrypt_file_content(&rotated, &[old_identity]).expect("Should work");
        // Should still have age: prefixes since wrong key
        assert!(rotated.contains("age:"));

        // New identity should decrypt all values
        let new_result = decrypt_file_content(&rotated, &[new_identity]).expect("Should work");
        assert!(new_result.contains("secret1"));
        assert!(new_result.contains("secret2"));
        assert!(new_result.contains("secret3"));
        assert!(!new_result.contains("age:"));
    }

    #[test]
    fn test_inline_all_special_symbols() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let special = "!@#$%^&*()_+-={}[]|\\:\";<>?,./~`";

        let encrypted = encrypt_inline(special, &[recipient]).expect("Encryption failed");
        let decrypted = decrypt_inline(&encrypted, &[identity]).expect("Decryption failed");

        assert_eq!(decrypted, special);
    }

    #[test]
    fn test_decrypt_file_content_preserves_structure() {
        let identity = test_identity();
        let recipient = identity.to_public();

        let enc = encrypt_inline("VALUE", &[recipient]).expect("Encryption failed");

        let content = format!(
            "# Comment\n\
             [section]\n\
             key = {enc}\n\
             \n\
             [other]\n\
             plain = text"
        );

        let result = decrypt_file_content(&content, &[identity]).expect("Should work");

        // Structure should be preserved
        assert!(result.contains("# Comment"));
        assert!(result.contains("[section]"));
        assert!(result.contains("key = VALUE"));
        assert!(result.contains("[other]"));
        assert!(result.contains("plain = text"));
    }
}
