//! Type-safe wrappers for hook-related strings
//!
//! This module provides newtype wrappers around String to prevent mixing up
//! different kinds of string data (hook names, platform names, scripts, etc.).
//! This improves type safety and makes the API more self-documenting.

use guisu_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt;

/// A validated hook name
///
/// Hook names must be non-empty and are used for:
/// - Identification in logs and error messages
/// - Tracking execution in persistent state (for mode=once)
/// - Display in status output
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, bincode::Encode, bincode::Decode)]
#[serde(transparent)]
pub struct HookName(String);

impl<'de> Deserialize<'de> for HookName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom("Hook name cannot be empty"));
        }
        Ok(Self(s))
    }
}

impl HookName {
    /// Create a new hook name with validation
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(Error::HookConfig("Hook name cannot be empty".to_string()));
        }
        Ok(Self(name))
    }

    /// Get the hook name as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the inner String
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for HookName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for HookName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for HookName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// A validated platform name
///
/// Platform names must be one of the supported platforms: darwin, linux, windows.
/// This ensures compile-time prevention of typos in platform names.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
#[serde(rename_all = "lowercase")]
pub enum PlatformName {
    /// macOS platform
    Darwin,
    /// Linux platform
    Linux,
    /// Windows platform
    Windows,
}

impl PlatformName {
    /// All supported platform names
    pub const ALL: &'static [&'static str] = &["darwin", "linux", "windows"];

    /// Parse a platform name from a string
    ///
    /// # Errors
    ///
    /// Returns an error if the platform name is not recognized
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "darwin" => Ok(Self::Darwin),
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            _ => Err(Error::HookConfig(format!(
                "Invalid platform '{}'. Must be one of: {}",
                s,
                Self::ALL.join(", ")
            ))),
        }
    }

    /// Get the platform name as a string slice
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Darwin => "darwin",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }

    /// Check if this platform matches the given string
    #[must_use]
    pub fn matches(&self, s: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(s)
    }
}

impl fmt::Display for PlatformName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for PlatformName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Hook script content or path
///
/// Represents either:
/// - A direct command string (from `cmd` field)
/// - A script file path (from `script` field)
/// - Loaded script content (from reading the script file)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[serde(transparent)]
pub struct HookScript(String);

impl HookScript {
    /// Create a new hook script
    #[must_use]
    pub fn new(content: impl Into<String>) -> Self {
        Self(content.into())
    }

    /// Get the script content as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the inner String
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Check if the script is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the length of the script content in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for HookScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for HookScript {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for HookScript {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for HookScript {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_hook_name_validation() {
        // Valid names
        assert!(HookName::new("my-hook").is_ok());
        assert!(HookName::new("hook123").is_ok());

        // Invalid: empty name
        assert!(HookName::new("").is_err());
    }

    #[test]
    fn test_hook_name_display() {
        let name = HookName::new("test-hook").unwrap();
        assert_eq!(name.to_string(), "test-hook");
        assert_eq!(name.as_str(), "test-hook");
    }

    #[test]
    fn test_platform_name_parse() {
        // Valid platforms
        assert_eq!(PlatformName::parse("darwin").unwrap(), PlatformName::Darwin);
        assert_eq!(PlatformName::parse("Darwin").unwrap(), PlatformName::Darwin);
        assert_eq!(PlatformName::parse("DARWIN").unwrap(), PlatformName::Darwin);
        assert_eq!(PlatformName::parse("linux").unwrap(), PlatformName::Linux);
        assert_eq!(
            PlatformName::parse("windows").unwrap(),
            PlatformName::Windows
        );

        // Invalid platform
        assert!(PlatformName::parse("freebsd").is_err());
        assert!(PlatformName::parse("").is_err());
    }

    #[test]
    fn test_platform_name_matches() {
        let darwin = PlatformName::Darwin;
        assert!(darwin.matches("darwin"));
        assert!(darwin.matches("Darwin"));
        assert!(darwin.matches("DARWIN"));
        assert!(!darwin.matches("linux"));
    }

    #[test]
    fn test_platform_name_display() {
        assert_eq!(PlatformName::Darwin.to_string(), "darwin");
        assert_eq!(PlatformName::Linux.to_string(), "linux");
        assert_eq!(PlatformName::Windows.to_string(), "windows");
    }

    #[test]
    fn test_hook_script() {
        let script = HookScript::new("echo hello");
        assert_eq!(script.as_str(), "echo hello");
        assert!(!script.is_empty());
        assert_eq!(script.len(), 10);

        let empty = HookScript::new("");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_hook_script_from() {
        let script1: HookScript = "test".into();
        let script2: HookScript = String::from("test").into();
        assert_eq!(script1.as_str(), "test");
        assert_eq!(script2.as_str(), "test");
    }
}
