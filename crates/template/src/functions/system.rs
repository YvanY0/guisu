//! System information functions
//!
//! Provides functions for accessing system information like OS, architecture,
//! hostname, username, home directory, and PATH operations.

use minijinja::Value;
use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;

// Cached system information
static HOSTNAME_CACHE: OnceLock<String> = OnceLock::new();
static USERNAME_CACHE: OnceLock<String> = OnceLock::new();
static HOME_DIR_CACHE: OnceLock<String> = OnceLock::new();

/// Get an environment variable
///
/// Usage: `{{ env("PATH") }}`
pub fn env(name: &str) -> std::borrow::Cow<'static, str> {
    env::var(name)
        .map(std::borrow::Cow::Owned)
        .unwrap_or(std::borrow::Cow::Borrowed(""))
}

/// Get the operating system name
///
/// Usage: `{{ os() }}`
#[must_use]
pub fn os() -> &'static str {
    #[cfg(target_os = "linux")]
    return "linux";

    #[cfg(target_os = "macos")]
    return "macos";

    #[cfg(target_os = "windows")]
    return "windows";

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return env::consts::OS;
}

/// Get the system architecture
///
/// Usage: `{{ arch() }}`
#[must_use]
pub fn arch() -> &'static str {
    env::consts::ARCH
}

/// Get the system hostname
///
/// Usage: `{{ hostname() }}`
pub fn hostname() -> &'static str {
    HOSTNAME_CACHE.get_or_init(|| {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string())
    })
}

/// Get the current username
///
/// Usage: `{{ username() }}`
pub fn username() -> &'static str {
    USERNAME_CACHE.get_or_init(|| {
        env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

/// Get the home directory
///
/// Usage: `{{ home_dir() }}`
pub fn home_dir() -> &'static str {
    HOME_DIR_CACHE.get_or_init(|| {
        dirs::home_dir().map_or_else(
            || "/home/unknown".to_string(),
            |p| p.to_string_lossy().into_owned(),
        )
    })
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
