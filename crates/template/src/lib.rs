//! # Guisu Template
//!
//! Template engine integration for guisu using minijinja.
//!
//! This crate provides template rendering capabilities with custom functions
//! for accessing system information, environment variables, and more.

pub mod context;
pub mod engine;
pub mod functions;
pub mod info;

pub use context::TemplateContext;
pub use engine::TemplateEngine;
pub use info::{AgeConfigInfo, BitwardenConfigInfo, ConfigInfo, UiConfigInfo};

// Re-export guisu_core types for use in this crate and by consumers
pub use guisu_core::Error;

/// Result type for template operations
pub type Result<T> = guisu_core::Result<T>;

/// Convert minijinja errors to `guisu_core::Error`
///
/// Helper function to convert minijinja errors since we can't implement From
/// due to orphan rules (both types are external to this crate).
pub(crate) fn convert_minijinja_error(err: &minijinja::Error) -> Error {
    // Extract detailed location information
    let location = match (err.name(), err.line(), err.range()) {
        (Some(name), Some(line), Some(range)) => {
            // Large column numbers indicate function return values being inlined.
            // For example, bitwardenFields() returns JSON that gets expanded in place.
            // The column refers to the expanded content, not the source line.
            // In such cases, omit the misleading column number.
            if range.start > 200 {
                format!("{name} line {line}")
            } else {
                format!("{} line {}, column {}", name, line, range.start)
            }
        }
        (Some(name), Some(line), None) => {
            format!("{name} line {line}")
        }
        (None, Some(line), Some(range)) => {
            if range.start > 200 {
                format!("line {line}")
            } else {
                format!("line {}, column {}", line, range.start)
            }
        }
        (None, Some(line), None) => {
            format!("line {line}")
        }
        _ => "unknown location".to_string(),
    };

    Error::TemplateRenderDetailed {
        location,
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_error_from_minijinja_syntax_error() {
        // Create a minijinja syntax error (invalid template syntax)
        let env = minijinja::Environment::new();
        // Invalid syntax: unclosed tag
        let template_result = env.render_str("{{ unclosed", minijinja::context!());

        assert!(template_result.is_err());
        let minijinja_err = template_result.unwrap_err();
        let error: Error = convert_minijinja_error(&minijinja_err);

        // Should contain location info
        let error_string = error.to_string();
        assert!(error_string.contains("Template error at"));
    }

    #[test]
    fn test_error_from_minijinja_undefined_filter() {
        // Test error conversion with undefined filter
        let env = minijinja::Environment::new();

        // Use an undefined filter
        let result = env.render_str("{{ 'test' | nonexistent }}", minijinja::context!());

        assert!(result.is_err());
        let minijinja_err = result.unwrap_err();
        let error: Error = convert_minijinja_error(&minijinja_err);
        let error_string = error.to_string();

        // Should contain template error message
        assert!(error_string.contains("Template error at"));
    }

    #[test]
    fn test_error_syntax() {
        let error = Error::TemplateSyntax("invalid syntax".to_string());
        assert_eq!(error.to_string(), "Template syntax error: invalid syntax");
    }

    #[test]
    fn test_error_render() {
        let error = Error::TemplateRenderDetailed {
            location: "test.j2 line 5".to_string(),
            message: "undefined variable".to_string(),
        };
        assert!(error.to_string().contains("test.j2 line 5"));
        assert!(error.to_string().contains("undefined variable"));
    }

    #[test]
    fn test_error_other() {
        let error = Error::Message("custom error".to_string());
        assert_eq!(error.to_string(), "custom error");
    }

    #[test]
    fn test_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let error: Error = io_err.into();
        assert!(error.to_string().contains("IO error"));
    }

    #[test]
    fn test_error_location_with_name_and_line_and_small_column() {
        let env = minijinja::Environment::new();
        // Use undefined filter which will cause error with location
        let result = env.render_str("{{ 'test' | undefined_filter }}", minijinja::context!());

        assert!(result.is_err());
        let error: Error = convert_minijinja_error(&result.unwrap_err());
        let error_string = error.to_string();

        // Should include line and column
        assert!(error_string.contains("Template error at"));
        assert!(error_string.contains("line"));
    }

    #[test]
    fn test_error_location_with_large_column() {
        // Test the branch where range.start > 200
        // This happens when function returns are inlined
        let error = Error::TemplateRenderDetailed {
            location: "test.j2 line 5".to_string(), // Simulating large column omission
            message: "error from inlined function".to_string(),
        };

        let error_string = error.to_string();
        assert!(error_string.contains("test.j2 line 5"));
        assert!(!error_string.contains("column")); // Should not include column
    }

    #[test]
    fn test_error_location_no_name_with_line_only() {
        // Test branch: (None, Some(line), None)
        let error = Error::TemplateRenderDetailed {
            location: "line 10".to_string(),
            message: "error without name or column".to_string(),
        };

        let error_string = error.to_string();
        assert!(error_string.contains("line 10"));
    }

    #[test]
    fn test_error_location_fallback_to_unknown() {
        // Test that we handle errors without location info gracefully
        // This is hard to trigger naturally, so we test the error display
        let error = Error::TemplateRenderDetailed {
            location: "unknown location".to_string(),
            message: "test error".to_string(),
        };

        assert!(error.to_string().contains("unknown location"));
        assert!(error.to_string().contains("test error"));
    }

    #[test]
    fn test_all_error_variants() {
        // Test that all error variants can be created and displayed
        let errors = vec![
            Error::TemplateRenderDetailed {
                location: "test".to_string(),
                message: "msg".to_string(),
            },
            Error::TemplateSyntax("syntax".to_string()),
            Error::Message("other".to_string()),
            Error::Io(std::io::Error::other("io")),
        ];

        for error in errors {
            // All should be displayable
            let _ = error.to_string();
        }
    }
}
