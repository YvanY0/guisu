//! Crypto adapter that implements the Decryptor trait from engine

use crate::content::Decryptor;
use guisu_core::{Error, Result};
use guisu_crypto::Identity;

/// Adapter that wraps crypto functions to implement `engine::content::Decryptor`
pub struct CryptoDecryptorAdapter {
    identity: Identity,
}

impl CryptoDecryptorAdapter {
    /// Create a new crypto adapter with the given identity
    #[must_use]
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }

    /// Get a reference to the identity
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

impl Decryptor for CryptoDecryptorAdapter {
    type Error = Error;

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        guisu_crypto::decrypt(encrypted, std::slice::from_ref(&self.identity))
    }

    fn decrypt_inline(&self, text: &str) -> Result<String> {
        guisu_crypto::decrypt_inline(text, std::slice::from_ref(&self.identity))
    }
}

impl Clone for CryptoDecryptorAdapter {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::content::Decryptor;
    use guisu_crypto::{encrypt, encrypt_inline};

    #[test]
    fn test_crypto_adapter_new() {
        let identity = Identity::generate();
        let adapter = CryptoDecryptorAdapter::new(identity.clone());

        // Verify identity is stored correctly
        assert_eq!(adapter.identity().to_string(), identity.to_string());
    }

    #[test]
    fn test_decrypt_success() {
        let identity = Identity::generate();
        let adapter = CryptoDecryptorAdapter::new(identity.clone());

        let plaintext = b"secret message";
        let recipient = identity.to_public();
        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");

        // Decrypt using adapter
        let decrypted = adapter.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let identity = Identity::generate();
        let adapter = CryptoDecryptorAdapter::new(identity);

        // Try to decrypt invalid data
        let invalid_data = b"not encrypted data";
        let result = adapter.decrypt(invalid_data);

        assert!(result.is_err(), "Should fail to decrypt invalid data");
    }

    #[test]
    fn test_decrypt_inline_success() {
        let identity = Identity::generate();
        let adapter = CryptoDecryptorAdapter::new(identity.clone());

        let plaintext = "secret password";
        let recipient = identity.to_public();
        let encrypted = encrypt_inline(plaintext, &[recipient]).expect("Encryption failed");

        // Verify encrypted format
        assert!(encrypted.starts_with("age:"));

        // Decrypt using adapter
        let decrypted = adapter
            .decrypt_inline(&encrypted)
            .expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_inline_plain_text() {
        let identity = Identity::generate();
        let adapter = CryptoDecryptorAdapter::new(identity);

        // Try to decrypt plain text (not encrypted)
        let plain_text = "not encrypted";
        let result = adapter.decrypt_inline(plain_text);

        assert!(result.is_err(), "Should fail to decrypt plain text");
    }

    #[test]
    fn test_clone() {
        let identity = Identity::generate();
        let adapter1 = CryptoDecryptorAdapter::new(identity.clone());
        let adapter2 = adapter1.clone();

        // Verify both adapters share the same identity Arc
        assert_eq!(
            adapter1.identity().to_string(),
            adapter2.identity().to_string()
        );

        // Test that both can decrypt
        let plaintext = b"test data";
        let recipient = identity.to_public();
        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");

        let decrypted1 = adapter1.decrypt(&encrypted).expect("Decryption 1 failed");
        let decrypted2 = adapter2.decrypt(&encrypted).expect("Decryption 2 failed");

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        // Create two different identities
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();

        // Encrypt with identity1
        let plaintext = b"secret";
        let recipient1 = identity1.to_public();
        let encrypted = encrypt(plaintext, &[recipient1]).expect("Encryption failed");

        // Try to decrypt with identity2
        let adapter = CryptoDecryptorAdapter::new(identity2);
        let result = adapter.decrypt(&encrypted);

        assert!(result.is_err(), "Should fail to decrypt with wrong key");
    }

    #[test]
    fn test_error_conversion() {
        let identity = Identity::generate();
        let adapter = CryptoDecryptorAdapter::new(identity);

        // Trigger an error and verify it converts correctly
        let result = adapter.decrypt(b"invalid");

        assert!(result.is_err(), "Expected decryption error");
    }
}
