//! File operation functions
//!
//! Provides functions for including file contents and templates.

use std::fs;
use std::path::PathBuf;

fn validate_include_path(
    path: &str,
    source_dir: &std::path::Path,
) -> Result<std::path::PathBuf, minijinja::Error> {
    use std::path::Component;

    let requested_path = std::path::Path::new(path);

    // Reject absolute paths
    if requested_path.is_absolute() {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Absolute paths not allowed in include(): {path}"),
        ));
    }

    // Check for path traversal components
    for component in requested_path.components() {
        match component {
            Component::ParentDir => {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    format!("Path traversal (..) not allowed in include(): {path}"),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    format!("Invalid path component in include(): {path}"),
                ));
            }
            _ => {}
        }
    }

    let file_path = source_dir.join(path);

    // Final safety check: ensure resolved path is still within source_dir
    let canonical_file = fs::canonicalize(&file_path).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to resolve path '{path}': {e}"),
        )
    })?;

    let canonical_source = fs::canonicalize(source_dir).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to resolve source directory: {e}"),
        )
    })?;

    if !canonical_file.starts_with(&canonical_source) {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!(
                "Path '{}' escapes source directory. Canonical path: {}",
                path,
                canonical_file.display()
            ),
        ));
    }

    Ok(canonical_file)
}

/// Include the contents of a file
///
/// Reads and includes the raw contents of a file from the dotfiles directory (guisu.srcDir).
/// The file path is relative to the dotfiles directory.
///
/// Usage: `{{ include("dot_zshrc-common") }}`
///
/// # Arguments
///
/// - `path`: Relative path to the file from the dotfiles directory (guisu.srcDir)
///
/// # Examples
///
/// ```jinja2
/// # Include a common shell configuration from dotfiles
/// {{ include("dot_zshrc-common") }}
///
/// # Include platform-specific config
/// {{ include("dot_config/nvim/init.lua") }}
///
/// # Calculate hash of included file
/// {{ include("darwin/Brewfile") | blake3sum }}
/// ```
///
/// # Security
///
/// This function validates the path to prevent directory traversal attacks:
/// - Absolute paths are rejected
/// - Path traversal (..) is not allowed
/// - The final resolved path must be within the dotfiles directory
///
/// # Errors
///
/// Returns an error if:
/// - Dotfiles directory (guisu.srcDir) is not available in context
/// - Path contains invalid components (absolute, .., etc.)
/// - Path escapes the dotfiles directory
/// - File does not exist
/// - File cannot be read
pub fn include(state: &minijinja::State, path: &str) -> Result<String, minijinja::Error> {
    // Get guisu.srcDir from context
    let src_dir_str = state
        .lookup("guisu")
        .and_then(|guisu| guisu.get_attr("srcDir").ok())
        .and_then(|v| v.as_str().map(std::string::ToString::to_string))
        .ok_or_else(|| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "guisu.srcDir not found in template context for include() function",
            )
        })?;

    let source_dir = PathBuf::from(&src_dir_str);
    let canonical_file = validate_include_path(path, &source_dir)?;

    fs::read_to_string(&canonical_file).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to read file '{path}': {e}"),
        )
    })
}

/// Include a template file from .guisu/templates directory
///
/// Reads the raw contents of a template file from the .guisu/templates directory.
/// The file path is relative to guisu.workingTree/.guisu/templates.
///
/// This function reads the file content but does NOT render it - the content is
/// returned as-is and will be rendered in the parent template context.
///
/// For platform-specific templates, the loader searches in this order:
/// 1. .guisu/templates/{platform}/{name}.j2
/// 2. .guisu/templates/{platform}/{name}
/// 3. .guisu/templates/{name}.j2
/// 4. .guisu/templates/{name}
///
/// Usage: `{{ includeTemplate("darwin/Brewfile") }}`
///
/// # Arguments
///
/// - `path`: Relative path to the template file from .guisu/templates directory
///
/// # Examples
///
/// ```jinja2
/// # Include a template file (uses template loader search order)
/// {{ includeTemplate("darwin/Brewfile") }}
///
/// # Include and hash the content
/// {{ includeTemplate("darwin/Brewfile") | blake3sum }}
/// ```
///
/// # Note
///
/// This function is useful when you want to include template content without
/// creating a separate rendering context. For example, to hash the content of
/// a template file for change detection.
///
/// For full template rendering with a separate context, use minijinja's
/// built-in `{% include %}` statement instead:
/// ```jinja2
/// {% include "darwin/Brewfile" %}
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Templates directory (guisu.workingTree/.guisu/templates) is not available
/// - Path contains invalid components (absolute, .., etc.)
/// - File does not exist
/// - File cannot be read
pub fn include_template(state: &minijinja::State, path: &str) -> Result<String, minijinja::Error> {
    // Get guisu.workingTree from context
    let working_tree_str = state
        .lookup("guisu")
        .and_then(|guisu| guisu.get_attr("workingTree").ok())
        .and_then(|v| v.as_str().map(std::string::ToString::to_string))
        .ok_or_else(|| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "guisu.workingTree not found in template context for includeTemplate() function",
            )
        })?;

    let templates_dir = PathBuf::from(&working_tree_str)
        .join(".guisu")
        .join("templates");

    if !templates_dir.exists() {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!(
                "Templates directory does not exist: {}",
                templates_dir.display()
            ),
        ));
    }

    let canonical_file = validate_include_path(path, &templates_dir)?;

    fs::read_to_string(&canonical_file).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to read template file '{path}': {e}"),
        )
    })
}
