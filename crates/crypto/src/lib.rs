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

/// Age encryption provider that implements the `EncryptionProvider` trait
///
/// This struct wraps recipients and identities to provide encryption/decryption
/// functionality through a trait-based interface.
pub struct AgeEncryption {
    recipients: Vec<Recipient>,
    identities: Vec<Identity>,
}

impl AgeEncryption {
    /// Create a new `AgeEncryption` instance with the given recipients and identities
    #[must_use]
    pub fn new(recipients: Vec<Recipient>, identities: Vec<Identity>) -> Self {
        Self {
            recipients,
            identities,
        }
    }

    /// Create an instance with only recipients (encryption-only)
    #[must_use]
    pub fn with_recipients(recipients: Vec<Recipient>) -> Self {
        Self {
            recipients,
            identities: Vec::new(),
        }
    }

    /// Create an instance with only identities (decryption-only)
    #[must_use]
    pub fn with_identities(identities: Vec<Identity>) -> Self {
        Self {
            recipients: Vec::new(),
            identities,
        }
    }
}

// Implement EncryptionProvider trait for AgeEncryption
impl guisu_core::EncryptionProvider for AgeEncryption {
    fn encrypt(&self, data: &[u8]) -> guisu_core::Result<Vec<u8>> {
        encrypt(data, &self.recipients)
    }

    fn decrypt(&self, data: &[u8]) -> guisu_core::Result<Vec<u8>> {
        decrypt(data, &self.identities)
    }
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
    fn test_age_encryption_new() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let age_enc = AgeEncryption::new(vec![recipient.clone()], vec![identity.clone()]);

        assert_eq!(age_enc.recipients.len(), 1);
        assert_eq!(age_enc.identities.len(), 1);
    }

    #[test]
    fn test_age_encryption_with_recipients() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let age_enc = AgeEncryption::with_recipients(vec![recipient.clone()]);

        assert_eq!(age_enc.recipients.len(), 1);
        assert_eq!(age_enc.identities.len(), 0);
    }

    #[test]
    fn test_age_encryption_with_identities() {
        let identity = Identity::generate();

        let age_enc = AgeEncryption::with_identities(vec![identity.clone()]);

        assert_eq!(age_enc.recipients.len(), 0);
        assert_eq!(age_enc.identities.len(), 1);
    }

    #[test]
    fn test_encryption_provider_trait_encrypt() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let age_enc = AgeEncryption::with_recipients(vec![recipient]);

        let data = b"secret message";
        let encrypted = guisu_core::EncryptionProvider::encrypt(&age_enc, data)
            .expect("Encryption should succeed");

        // Encrypted data should be different from original
        assert_ne!(encrypted, data);
        // Should be longer due to age envelope
        assert!(encrypted.len() > data.len());
    }

    #[test]
    fn test_encryption_provider_trait_decrypt() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Encrypt with recipient
        let age_enc_encrypt = AgeEncryption::with_recipients(vec![recipient]);
        let data = b"secret message";
        let encrypted = guisu_core::EncryptionProvider::encrypt(&age_enc_encrypt, data)
            .expect("Encryption should succeed");

        // Decrypt with identity
        let age_enc_decrypt = AgeEncryption::with_identities(vec![identity]);
        let decrypted = guisu_core::EncryptionProvider::decrypt(&age_enc_decrypt, &encrypted)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_provider_trait_roundtrip() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let age_enc = AgeEncryption::new(vec![recipient], vec![identity]);

        let original = b"test data for roundtrip";

        // Encrypt
        let encrypted = guisu_core::EncryptionProvider::encrypt(&age_enc, original)
            .expect("Encryption should succeed");

        // Decrypt
        let decrypted = guisu_core::EncryptionProvider::decrypt(&age_enc, &encrypted)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encryption_provider_no_recipients_error() {
        let age_enc = AgeEncryption::with_recipients(vec![]);

        let data = b"cannot encrypt this";
        let result = guisu_core::EncryptionProvider::encrypt(&age_enc, data);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No recipients"));
    }

    #[test]
    fn test_encryption_provider_no_identities_error() {
        // Create some encrypted data first
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let age_enc_encrypt = AgeEncryption::with_recipients(vec![recipient]);
        let encrypted = guisu_core::EncryptionProvider::encrypt(&age_enc_encrypt, b"data")
            .expect("Encryption should succeed");

        // Try to decrypt with no identities
        let age_enc_decrypt = AgeEncryption::with_identities(vec![]);
        let result = guisu_core::EncryptionProvider::decrypt(&age_enc_decrypt, &encrypted);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No identity") || err.to_string().contains("decrypt"));
    }

    #[test]
    fn test_encryption_provider_wrong_identity() {
        // Encrypt with one identity's recipient
        let identity1 = Identity::generate();
        let recipient1 = identity1.to_public();

        let age_enc_encrypt = AgeEncryption::with_recipients(vec![recipient1]);
        let encrypted = guisu_core::EncryptionProvider::encrypt(&age_enc_encrypt, b"data")
            .expect("Encryption should succeed");

        // Try to decrypt with a different identity
        let identity2 = Identity::generate();
        let age_enc_decrypt = AgeEncryption::with_identities(vec![identity2]);
        let result = guisu_core::EncryptionProvider::decrypt(&age_enc_decrypt, &encrypted);

        assert!(result.is_err());
    }
}
