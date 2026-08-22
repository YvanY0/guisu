//! # Guisu Crypto
//!
//! Encryption and decryption support for guisu using age encryption.
//!
//! This crate provides functionality for encrypting and decrypting files
//! using the age encryption format with identity-based keys.

pub mod age;
pub mod identity;
pub mod recipient;

pub use age::{
    decrypt, decrypt_file_content, decrypt_inline, decrypt_string, encrypt, encrypt_file_content,
    encrypt_inline, encrypt_string,
};
pub use identity::{Identity, IdentityFile, load_identities};
pub use recipient::Recipient;

/// Convert a slice of identities to their corresponding recipients (public keys)
///
/// This is a convenience function that extracts the public key from each identity.
/// Useful when you need to encrypt data that can be decrypted by the same identities.
///
/// # Examples
///
/// ```
/// use guisu_crypto::{Identity, identities_to_recipients};
///
/// let identities = vec![Identity::generate(), Identity::generate()];
/// let recipients = identities_to_recipients(&identities);
///
/// // Now you can encrypt data for these recipients
/// guisu_crypto::encrypt(b"secret", &recipients).unwrap();
/// ```
#[must_use]
pub fn identities_to_recipients(identities: &[Identity]) -> Vec<Recipient> {
    identities.iter().map(Identity::to_public).collect()
}

// Re-export guisu_core types for use in this crate and by consumers
pub use guisu_core::Error;

/// Result type for crypto operations
pub type Result<T> = guisu_core::Result<T>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let recipients = vec![recipient.clone()];

        let original = b"test data for roundtrip";

        // Encrypt
        let encrypted = encrypt(original, &recipients).expect("Encryption should succeed");

        // Decrypt
        let identities = vec![identity];
        let decrypted = decrypt(&encrypted, &identities).expect("Decryption should succeed");

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_produces_different_output() {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let recipients = vec![recipient];

        let data = b"secret message";
        let encrypted = encrypt(data, &recipients).expect("Encryption should succeed");

        // Encrypted data should be different from original
        assert_ne!(encrypted, data);
        // Should be longer due to age envelope
        assert!(encrypted.len() > data.len());
    }

    #[test]
    fn test_encrypt_decrypt_with_recipients_and_identities_split() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Encrypt with recipient only
        let data = b"secret message";
        let encrypted = encrypt(data, &[recipient]).expect("Encryption should succeed");

        // Decrypt with identity only
        let decrypted = decrypt(&encrypted, &[identity]).expect("Decryption should succeed");

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_no_recipients_error() {
        let recipients: Vec<Recipient> = vec![];

        let data = b"cannot encrypt this";
        let result = encrypt(data, &recipients);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No recipients"));
    }

    #[test]
    fn test_decrypt_no_identities_error() {
        // Create some encrypted data first
        let identity = Identity::generate();
        let recipient = identity.to_public();
        let encrypted = encrypt(b"data", &[recipient]).expect("Encryption should succeed");

        // Try to decrypt with no identities
        let identities: Vec<Identity> = vec![];
        let result = decrypt(&encrypted, &identities);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No identity") || err.to_string().contains("decrypt"));
    }

    #[test]
    fn test_decrypt_wrong_identity_error() {
        // Encrypt with one identity's recipient
        let identity1 = Identity::generate();
        let recipient1 = identity1.to_public();
        let encrypted = encrypt(b"data", &[recipient1]).expect("Encryption should succeed");

        // Try to decrypt with a different identity
        let identity2 = Identity::generate();
        let result = decrypt(&encrypted, &[identity2]);

        assert!(result.is_err());
    }
}
