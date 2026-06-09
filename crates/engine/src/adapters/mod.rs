//! Adapter implementations for engine traits
//!
//! This module provides concrete implementations of engine traits
//! using the crypto and template services.

pub mod crypto;
pub mod template;

pub use self::crypto::CryptoDecryptorAdapter;
pub use self::template::TemplateRendererAdapter;

use crate::processor::ContentProcessor;
use ::guisu_crypto::Identity;
use ::guisu_template::TemplateEngine;

/// Convenience function to create a fully configured `ContentProcessor`
///
/// # Arguments
///
/// * `identity` - Age identity for decryption
/// * `template_engine` - Template engine for rendering
///
/// # Returns
///
/// A `ContentProcessor` configured with `CryptoDecryptor` and `TemplateRenderer` adapters
pub fn create_processor(
    identity: Identity,
    template_engine: TemplateEngine,
) -> ContentProcessor<CryptoDecryptorAdapter, TemplateRendererAdapter> {
    let decryptor = CryptoDecryptorAdapter::new(identity);
    let renderer = TemplateRendererAdapter::new(template_engine);
    ContentProcessor::new(decryptor, renderer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::attr::FileAttributes;
    use guisu_crypto::encrypt;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_create_processor() {
        let identity = Identity::generate();
        let engine = TemplateEngine::new();

        let processor = create_processor(identity, engine);

        // Verify processor can be created successfully
        // The processor should be ready to use for processing files
        drop(processor);
    }

    #[test]
    fn test_processor_with_plain_content() {
        let identity = Identity::generate();
        let engine = TemplateEngine::new();
        let processor = create_processor(identity, engine);

        let content = b"plain text content";
        let attrs = FileAttributes::new(); // Plain file with no special attributes
        let template_context = json!({});

        let result = processor
            .process_content(content.to_vec(), &attrs, &template_context, "test")
            .expect("Processing failed");

        assert_eq!(result, content);
    }

    #[test]
    fn test_processor_with_template() {
        let identity = Identity::generate();
        let engine = TemplateEngine::new();
        let processor = create_processor(identity, engine);

        let content = b"Hello, {{ name }}!";
        let attrs = FileAttributes {
            is_template: true,
            ..FileAttributes::new()
        };
        let template_context = json!({
            "name": "World"
        });

        let result = processor
            .process_content(content.to_vec(), &attrs, &template_context, "test.j2")
            .expect("Processing failed");

        assert_eq!(result, b"Hello, World!");
    }

    #[test]
    fn test_processor_with_encrypted_content() {
        let identity = Identity::generate();
        let engine = TemplateEngine::new();
        let processor = create_processor(identity.clone(), engine);

        let plaintext = b"secret message";
        let recipient = identity.to_public();
        let encrypted = encrypt(plaintext, &[recipient]).expect("Encryption failed");

        let attrs = FileAttributes {
            is_encrypted: true,
            ..FileAttributes::new()
        };
        let template_context = json!({});

        let result = processor
            .process_content(encrypted, &attrs, &template_context, "test.age")
            .expect("Processing failed");

        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_processor_with_encrypted_template() {
        let identity = Identity::generate();
        let engine = TemplateEngine::new();
        let processor = create_processor(identity.clone(), engine);

        // Encrypt a template
        let template = "Hello, {{ name }}!";
        let recipient = identity.to_public();
        let encrypted = encrypt(template.as_bytes(), &[recipient]).expect("Encryption failed");

        let attrs = FileAttributes {
            is_template: true,
            is_encrypted: true,
            ..FileAttributes::new()
        };
        let template_context = json!({
            "name": "Alice"
        });

        let result = processor
            .process_content(encrypted, &attrs, &template_context, "test.j2.age")
            .expect("Processing failed");

        assert_eq!(result, b"Hello, Alice!");
    }

    #[test]
    fn test_processor_process_file() {
        let temp = TempDir::new().unwrap();
        let test_file = temp.path().join("test.txt");

        let content = b"file content";
        fs::write(&test_file, content).unwrap();

        let identity = Identity::generate();
        let engine = TemplateEngine::new();
        let processor = create_processor(identity, engine);

        let attrs = FileAttributes::new(); // Plain file
        let template_context = json!({});

        let abs_path = guisu_core::path::AbsPath::new(test_file).unwrap();
        let result = processor
            .process_file(&abs_path, &attrs, &template_context)
            .expect("Processing file failed");

        assert_eq!(result, content);
    }

    #[test]
    fn test_processor_with_multiple_flags() {
        let identity = Identity::generate();
        let engine = TemplateEngine::new();
        let processor = create_processor(identity.clone(), engine);

        // Create template content
        let template = "User: {{ user }}\nRole: {{ role }}";

        // PRIVATE flag was removed; private permissions are now tracked via
        // source file mode bits, not via a flag.
        let attrs = FileAttributes {
            is_template: true,
            mode: Some(0o600),
            ..FileAttributes::new()
        };
        let template_context = json!({
            "user": "alice",
            "role": "admin"
        });

        let result = processor
            .process_content(
                template.as_bytes().to_vec(),
                &attrs,
                &template_context,
                "test.j2",
            )
            .expect("Processing failed");

        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("User: alice"));
        assert!(result_str.contains("Role: admin"));
    }
}
