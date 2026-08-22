//! Content processing for template rendering and decryption
//!
//! This module handles the processing pipeline for source file contents:
//! 1. Read source file
//! 2. Decrypt if encrypted (.age extension)
//! 3. Render template if templated (.j2 extension)
//! 4. Return processed content
//!
//! The order is important: for `.j2.age` files, we decrypt first, then render.

use crate::attr::FileAttributes;
use crate::content::{Decryptor, TemplateRenderer};
use guisu_core::path::AbsPath;
use guisu_core::{Error, Result};
use std::fs;

/// Content processor with pluggable decryption and rendering
///
/// This struct manages the processing pipeline using trait objects,
/// allowing any implementation of Decryptor and `TemplateRenderer` to be used.
pub struct ContentProcessor<D, R>
where
    D: Decryptor,
    R: TemplateRenderer,
{
    /// Decryptor for handling encrypted files
    decryptor: D,

    /// Renderer for processing templates
    renderer: R,
}

impl<D, R> ContentProcessor<D, R>
where
    D: Decryptor,
    R: TemplateRenderer,
{
    /// Create a new content processor
    ///
    /// # Arguments
    ///
    /// * `decryptor` - Implementation of Decryptor trait
    /// * `renderer` - Implementation of `TemplateRenderer` trait
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_engine::content::{NoOpDecryptor, NoOpRenderer};
    /// use guisu_engine::processor::ContentProcessor;
    ///
    /// let processor = ContentProcessor::new(
    ///     NoOpDecryptor,
    ///     NoOpRenderer,
    /// );
    /// ```
    pub fn new(decryptor: D, renderer: R) -> Self {
        Self {
            decryptor,
            renderer,
        }
    }

    /// Process a file based on its attributes
    ///
    /// # Arguments
    ///
    /// * `source_path` - Path to the source file
    /// * `attrs` - File attributes (`is_encrypted`, `is_template`, etc.)
    /// * `context` - Context data for template rendering
    ///
    /// # Returns
    ///
    /// Processed file content
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be read
    /// - Decryption fails
    /// - Template rendering fails
    /// - Content is not valid UTF-8 (for templates)
    pub fn process_file(
        &self,
        source_path: &AbsPath,
        attrs: &FileAttributes,
        context: &serde_json::Value,
    ) -> Result<Vec<u8>> {
        let file_data = fs::read(source_path.as_path()).map_err(|e| Error::FileRead {
            path: source_path.as_path().to_path_buf(),
            source: e,
        })?;

        self.process_content(file_data, attrs, context, &source_path.to_string())
    }

    /// Process file content directly (without reading from disk)
    ///
    /// This is useful for testing or when content is already in memory.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails (e.g., decryption failure, invalid UTF-8, template rendering error)
    pub fn process_content(
        &self,
        mut data: Vec<u8>,
        attrs: &FileAttributes,
        context: &serde_json::Value,
        path_for_errors: &str,
    ) -> Result<Vec<u8>> {
        if attrs.is_encrypted {
            data = self
                .decryptor
                .decrypt(&data)
                .map_err(|e| Error::Decryption {
                    path: path_for_errors.to_string(),
                    source: Box::new(e),
                })?;
        }

        if attrs.is_template {
            let text = String::from_utf8(data).map_err(|e| Error::InvalidUtf8 {
                path: path_for_errors.to_string(),
                source: e,
            })?;

            let rendered =
                self.renderer
                    .render(&text, context)
                    .map_err(|e| Error::TemplateRender {
                        path: path_for_errors.to_string(),
                        source: Box::new(e),
                    })?;

            data = rendered.into_bytes();
        }

        Ok(data)
    }
}

// Type alias for no-op processor (useful for testing)
use crate::content::{NoOpDecryptor, NoOpRenderer};

/// No-op content processor (useful for testing)
pub type NoOpProcessor = ContentProcessor<NoOpDecryptor, NoOpRenderer>;

impl Default for NoOpProcessor {
    fn default() -> Self {
        Self::new(NoOpDecryptor, NoOpRenderer)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    // Mock decryptor that records decryption attempts
    struct MockDecryptor {
        decrypt_called: Arc<Mutex<bool>>,
        should_fail: bool,
        result_data: Vec<u8>,
    }

    impl MockDecryptor {
        fn success(data: Vec<u8>) -> Self {
            Self {
                decrypt_called: Arc::new(Mutex::new(false)),
                should_fail: false,
                result_data: data,
            }
        }

        fn failure() -> Self {
            Self {
                decrypt_called: Arc::new(Mutex::new(false)),
                should_fail: true,
                result_data: Vec::new(),
            }
        }

        fn was_called(&self) -> bool {
            *self.decrypt_called.lock().unwrap()
        }
    }

    impl Decryptor for MockDecryptor {
        type Error = Error;

        fn decrypt(&self, _content: &[u8]) -> std::result::Result<Vec<u8>, Self::Error> {
            *self.decrypt_called.lock().unwrap() = true;
            if self.should_fail {
                Err(Error::DecryptionPipeline {
                    source: Box::new(std::io::Error::other("mock decryption failure")),
                })
            } else {
                Ok(self.result_data.clone())
            }
        }

        fn decrypt_inline(&self, _text: &str) -> std::result::Result<String, Self::Error> {
            if self.should_fail {
                Err(Error::DecryptionPipeline {
                    source: Box::new(std::io::Error::other("mock inline decryption failure")),
                })
            } else {
                Ok(String::new())
            }
        }
    }

    // Mock renderer that records rendering attempts
    struct MockRenderer {
        render_called: Arc<Mutex<bool>>,
        should_fail: bool,
        result_data: String,
    }

    impl MockRenderer {
        fn success(data: String) -> Self {
            Self {
                render_called: Arc::new(Mutex::new(false)),
                should_fail: false,
                result_data: data,
            }
        }

        fn failure() -> Self {
            Self {
                render_called: Arc::new(Mutex::new(false)),
                should_fail: true,
                result_data: String::new(),
            }
        }

        fn was_called(&self) -> bool {
            *self.render_called.lock().unwrap()
        }
    }

    impl TemplateRenderer for MockRenderer {
        type Error = Error;

        fn render(
            &self,
            _template: &str,
            _context: &serde_json::Value,
        ) -> std::result::Result<String, Self::Error> {
            *self.render_called.lock().unwrap() = true;
            if self.should_fail {
                Err(Error::RenderingPipeline {
                    source: Box::new(std::io::Error::other("mock rendering failure")),
                })
            } else {
                Ok(self.result_data.clone())
            }
        }
    }

    #[test]
    fn test_noop_processor_default() {
        let processor = NoOpProcessor::default();
        let content = b"test content".to_vec();
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(content.clone(), &attrs, &template_context, "test.txt")
            .unwrap();

        assert_eq!(result, content);
    }

    #[test]
    fn test_process_plain_file() {
        let processor = NoOpProcessor::default();
        let content = b"plain content".to_vec();
        let attrs = FileAttributes::new(); // No special attributes
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(content.clone(), &attrs, &template_context, "test.txt")
            .unwrap();

        assert_eq!(result, content);
    }

    #[test]
    fn test_process_encrypted_file() {
        let decrypted = b"decrypted content".to_vec();
        let decryptor = MockDecryptor::success(decrypted.clone());
        let mock_renderer = NoOpRenderer;

        let processor = ContentProcessor::new(decryptor, mock_renderer);
        let attrs = FileAttributes {
            is_encrypted: true,
            ..FileAttributes::new()
        };
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(b"encrypted".to_vec(), &attrs, &template_context, "test.age")
            .unwrap();

        assert_eq!(result, decrypted);
    }

    #[test]
    fn test_process_template_file() {
        let rendered = "rendered content".to_string();
        let decryptor = NoOpDecryptor;
        let mock_renderer = MockRenderer::success(rendered.clone());

        let processor = ContentProcessor::new(decryptor, mock_renderer);
        let attrs = FileAttributes {
            is_template: true,
            ..FileAttributes::new()
        };
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(b"template".to_vec(), &attrs, &template_context, "test.j2")
            .unwrap();

        assert_eq!(result, rendered.into_bytes());
    }

    #[test]
    fn test_process_encrypted_template() {
        let decrypted = b"{{ variable }}".to_vec();
        let rendered = "rendered value".to_string();

        let decryptor = MockDecryptor::success(decrypted.clone());
        let mock_renderer = MockRenderer::success(rendered.clone());

        let processor = ContentProcessor::new(decryptor, mock_renderer);
        let attrs = FileAttributes {
            is_encrypted: true,
            is_template: true,
            ..FileAttributes::new()
        };
        let template_context = serde_json::json!({"variable": "value"});

        let result = processor
            .process_content(
                b"encrypted template".to_vec(),
                &attrs,
                &template_context,
                "test.j2.age",
            )
            .unwrap();

        assert_eq!(result, rendered.into_bytes());
    }

    #[test]
    fn test_decryption_called_only_when_encrypted() {
        let decryptor = MockDecryptor::success(b"decrypted".to_vec());
        let mock_renderer = NoOpRenderer;

        let processor = ContentProcessor::new(decryptor, mock_renderer);

        // Not encrypted
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});
        let _ =
            processor.process_content(b"content".to_vec(), &attrs, &template_context, "test.txt");

        assert!(!processor.decryptor.was_called());

        // Encrypted
        let attrs = FileAttributes {
            is_encrypted: true,
            ..FileAttributes::new()
        };
        let _ =
            processor.process_content(b"encrypted".to_vec(), &attrs, &template_context, "test.age");

        assert!(processor.decryptor.was_called());
    }

    #[test]
    fn test_rendering_called_only_when_template() {
        let decryptor = NoOpDecryptor;
        let mock_renderer = MockRenderer::success("rendered".to_string());

        let processor = ContentProcessor::new(decryptor, mock_renderer);

        // Not a template
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});
        let _ =
            processor.process_content(b"content".to_vec(), &attrs, &template_context, "test.txt");

        assert!(!processor.renderer.was_called());

        // Is a template
        let attrs = FileAttributes {
            is_template: true,
            ..FileAttributes::new()
        };
        let _ =
            processor.process_content(b"template".to_vec(), &attrs, &template_context, "test.j2");

        assert!(processor.renderer.was_called());
    }

    #[test]
    fn test_decryption_error() {
        let decryptor = MockDecryptor::failure();
        let mock_renderer = NoOpRenderer;

        let processor = ContentProcessor::new(decryptor, mock_renderer);
        let attrs = FileAttributes {
            is_encrypted: true,
            ..FileAttributes::new()
        };
        let template_context = serde_json::json!({});

        let result =
            processor.process_content(b"encrypted".to_vec(), &attrs, &template_context, "test.age");

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Decryption failed") || err_msg.contains("decryption"));
    }

    #[test]
    fn test_rendering_error() {
        let decryptor = NoOpDecryptor;
        let mock_renderer = MockRenderer::failure();

        let processor = ContentProcessor::new(decryptor, mock_renderer);
        let attrs = FileAttributes {
            is_template: true,
            ..FileAttributes::new()
        };
        let template_context = serde_json::json!({});

        let result =
            processor.process_content(b"template".to_vec(), &attrs, &template_context, "test.j2");

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Rendering failed") || err_msg.contains("render"));
    }

    #[test]
    fn test_invalid_utf8_in_template() {
        let decryptor = NoOpDecryptor;
        let mock_renderer = NoOpRenderer;

        let processor = ContentProcessor::new(decryptor, mock_renderer);
        let attrs = FileAttributes {
            is_template: true,
            ..FileAttributes::new()
        };
        let template_context = serde_json::json!({});

        // Invalid UTF-8 sequence
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let result = processor.process_content(invalid_utf8, &attrs, &template_context, "test.j2");

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("UTF-8") || err_msg.contains("utf8"));
    }

    #[test]
    fn test_process_file_reads_from_disk() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"file content";
        temp_file.write_all(content).unwrap();
        temp_file.flush().unwrap();

        let processor = NoOpProcessor::default();
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});

        let abs_path = AbsPath::new(temp_file.path().to_path_buf()).unwrap();
        let result = processor
            .process_file(&abs_path, &attrs, &template_context)
            .unwrap();

        assert_eq!(result, content);
    }

    #[test]
    fn test_process_file_nonexistent() {
        let processor = NoOpProcessor::default();
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});

        let abs_path = AbsPath::new("/nonexistent/file.txt".into()).unwrap();
        let result = processor.process_file(&abs_path, &attrs, &template_context);

        assert!(result.is_err());
    }

    #[test]
    fn test_process_empty_file() {
        let processor = NoOpProcessor::default();
        let content = b"".to_vec();
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(content.clone(), &attrs, &template_context, "empty.txt")
            .unwrap();

        assert_eq!(result, content);
    }

    #[test]
    fn test_process_binary_file() {
        let processor = NoOpProcessor::default();
        let content = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE];
        let attrs = FileAttributes::new(); // Not a template
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(content.clone(), &attrs, &template_context, "binary.bin")
            .unwrap();

        assert_eq!(result, content);
    }

    #[test]
    fn test_large_file_content() {
        let processor = NoOpProcessor::default();
        let large_content = vec![b'A'; 1_000_000]; // 1MB of 'A's
        let attrs = FileAttributes::new();
        let template_context = serde_json::json!({});

        let result = processor
            .process_content(
                large_content.clone(),
                &attrs,
                &template_context,
                "large.txt",
            )
            .unwrap();

        assert_eq!(result, large_content);
    }

    #[test]
    fn test_processor_new() {
        let decryptor = NoOpDecryptor;
        let mock_renderer = NoOpRenderer;
        let _processor = ContentProcessor::new(decryptor, mock_renderer);

        // Test that processor can be created
    }

    #[test]
    fn test_combined_attributes() {
        let decrypted = b"{{ name }}".to_vec();
        let rendered = "Alice".to_string();

        let decryptor = MockDecryptor::success(decrypted);
        let mock_renderer = MockRenderer::success(rendered.clone());

        let processor = ContentProcessor::new(decryptor, mock_renderer);

        let attrs = FileAttributes {
            is_encrypted: true,
            is_template: true,
            ..FileAttributes::new()
        };

        let template_context = serde_json::json!({"name": "Alice"});

        let result = processor
            .process_content(
                b"encrypted template".to_vec(),
                &attrs,
                &template_context,
                "test.j2.age",
            )
            .unwrap();

        assert_eq!(result, rendered.into_bytes());
    }
}
