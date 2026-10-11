//! System information functions
//!
//! Read-only helpers that are not expressible as plain context fields:
//!
//! - `env("NAME")` — look up a single environment variable by name.
//! - `joinPath(...)` — join path components portably.
//! - `lookPath("cmd")` — resolve a binary on `$PATH` with input validation.
//!
//! Host information (OS, arch, hostname, username, home directory) lives on
//! the `system.*` fields of [`crate::TemplateContext`] — there is no separate
//! function form so there is exactly one source of truth per value.

use guisu_config::Env;
use minijinja::Value;
use std::path::PathBuf;

/// Get an environment variable
///
/// Usage: `{{ env("PATH") }}`
pub fn env(name: &str) -> std::borrow::Cow<'static, str> {
    Env::system()
        .get(name)
        .map_or(std::borrow::Cow::Borrowed(""), std::borrow::Cow::Owned)
}

/// Join path components
///
/// Usage: `{{ joinPath("/home", "user", ".config") }}`
#[must_use]
pub fn join_path(args: &[Value]) -> String {
    let mut path = PathBuf::new();
    for arg in args {
        if let Some(s) = arg.as_str() {
            path.push(s);
        }
    }
    path.to_string_lossy().into_owned()
}

/// Look up an executable in PATH
///
/// Usage: `{{ lookPath("git") }}`
///
/// # Security
///
/// Input is validated to prevent command injection:
/// - Only alphanumeric characters, dashes, and underscores are allowed
/// - Path traversal attempts (..) are rejected
/// - Absolute paths are rejected
///
/// # Errors
///
/// Returns error if executable is not found in PATH or input validation fails
pub fn look_path(name: &str) -> Result<String, minijinja::Error> {
    // Validate input: only alphanumeric, dash, underscore
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!(
                "Invalid executable name: '{name}'. Only alphanumeric characters, dashes, and underscores allowed"
            ),
        ));
    }

    // Path traversal prevention
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Path traversal detected in executable name",
        ));
    }

    which::which(name)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("Executable not found in PATH: {e}"),
            )
        })
}
