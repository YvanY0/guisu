//! Ignore patterns loading from .guisu/ignores.toml

use crate::Result;
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Configuration for ignore patterns loaded from .guisu/ignores.toml
///
/// Supports gitignore-style patterns with negation using ! prefix.
///
/// Example:
/// ```toml
/// global = [
///     ".DS_Store",
///     "*.log",
///     ".config/*",
///     "!.config/atuin/",
///     "!.config/bat/",
/// ]
///
/// darwin = [
///     ".Trash/",
/// ]
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct IgnoresConfig {
    /// Global ignore patterns for all platforms
    #[serde(default)]
    pub global: Vec<String>,
    /// macOS-specific ignore patterns
    #[serde(default)]
    pub darwin: Vec<String>,
    /// Linux-specific ignore patterns
    #[serde(default)]
    pub linux: Vec<String>,
    /// Windows-specific ignore patterns
    #[serde(default)]
    pub windows: Vec<String>,
}

impl IgnoresConfig {
    /// Load ignore configuration from .guisu/ignores.toml
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or TOML parsing fails
    pub fn load(source_dir: &Path) -> Result<Self> {
        let ignores_path = source_dir.join(".guisu").join("ignores.toml");

        if !ignores_path.exists() {
            return Ok(Self::default());
        }

        let content =
            fs::read_to_string(&ignores_path).map_err(|e| guisu_core::Error::FileRead {
                path: ignores_path.clone(),
                source: e,
            })?;

        let config: Self =
            toml::from_str(&content).map_err(|e| guisu_core::Error::InvalidConfig {
                message: format!("failed to parse {}: {e}", ignores_path.display()),
            })?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_ignores_config_default() {
        let config = IgnoresConfig::default();

        assert!(config.global.is_empty());
        assert!(config.darwin.is_empty());
        assert!(config.linux.is_empty());
        assert!(config.windows.is_empty());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let temp = TempDir::new().unwrap();

        // No .guisu directory exists
        let result = IgnoresConfig::load(temp.path()).unwrap();

        // Should return default config
        assert!(result.global.is_empty());
        assert!(result.darwin.is_empty());
        assert!(result.linux.is_empty());
        assert!(result.windows.is_empty());
    }

    #[test]
    fn test_load_valid_config() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();

        let config_content = r#"
global = [
    ".DS_Store",
    "*.log",
]

darwin = [
    ".Trash/",
]

linux = [
    "~/.cache/",
]
"#;

        fs::write(guisu_dir.join("ignores.toml"), config_content).unwrap();

        let config = IgnoresConfig::load(temp.path()).unwrap();

        assert_eq!(config.global, vec![".DS_Store", "*.log"]);
        assert_eq!(config.darwin, vec![".Trash/"]);
        assert_eq!(config.linux, vec!["~/.cache/"]);
        assert!(config.windows.is_empty()); // Not specified, should be default
    }

    #[test]
    fn test_load_with_negation_patterns() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();

        let config_content = r#"
global = [
    ".config/*",
    "!.config/atuin/",
    "!.config/bat/",
]
"#;

        fs::write(guisu_dir.join("ignores.toml"), config_content).unwrap();

        let config = IgnoresConfig::load(temp.path()).unwrap();

        assert_eq!(config.global.len(), 3);
        assert!(config.global.contains(&".config/*".to_string()));
        assert!(config.global.contains(&"!.config/atuin/".to_string()));
        assert!(config.global.contains(&"!.config/bat/".to_string()));
    }

    #[test]
    fn test_load_all_platforms() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();

        let config_content = r#"
global = ["*.tmp"]
darwin = [".DS_Store"]
linux = [".cache"]
windows = ["Thumbs.db"]
"#;

        fs::write(guisu_dir.join("ignores.toml"), config_content).unwrap();

        let config = IgnoresConfig::load(temp.path()).unwrap();

        assert_eq!(config.global, vec!["*.tmp"]);
        assert_eq!(config.darwin, vec![".DS_Store"]);
        assert_eq!(config.linux, vec![".cache"]);
        assert_eq!(config.windows, vec!["Thumbs.db"]);
    }

    #[test]
    fn test_load_empty_arrays() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();

        let config_content = r"
global = []
darwin = []
";

        fs::write(guisu_dir.join("ignores.toml"), config_content).unwrap();

        let config = IgnoresConfig::load(temp.path()).unwrap();

        assert!(config.global.is_empty());
        assert!(config.darwin.is_empty());
        assert!(config.linux.is_empty());
        assert!(config.windows.is_empty());
    }

    #[test]
    fn test_load_partial_config() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();

        // Only global specified
        let config_content = r#"
global = ["*.log"]
"#;

        fs::write(guisu_dir.join("ignores.toml"), config_content).unwrap();

        let config = IgnoresConfig::load(temp.path()).unwrap();

        assert_eq!(config.global, vec!["*.log"]);
        // Other platforms should default to empty
        assert!(config.darwin.is_empty());
        assert!(config.linux.is_empty());
        assert!(config.windows.is_empty());
    }

    #[test]
    fn test_load_invalid_toml() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();

        let invalid_content = "this is not valid toml [[[";
        fs::write(guisu_dir.join("ignores.toml"), invalid_content).unwrap();

        let result = IgnoresConfig::load(temp.path());
        assert!(result.is_err());

        let error = result.unwrap_err().to_string();
        assert!(error.contains("Failed to parse") || error.contains("parse"));
    }

    #[test]
    fn test_deserialize_from_toml_string() {
        let toml_str = r#"
global = ["*.tmp", "*.log"]
darwin = [".DS_Store"]
"#;

        let config: IgnoresConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.global, vec!["*.tmp", "*.log"]);
        assert_eq!(config.darwin, vec![".DS_Store"]);
        assert!(config.linux.is_empty());
        assert!(config.windows.is_empty());
    }

    #[test]
    fn test_deserialize_empty_toml() {
        let toml_str = "";

        let config: IgnoresConfig = toml::from_str(toml_str).unwrap();

        // Should deserialize to default
        assert!(config.global.is_empty());
        assert!(config.darwin.is_empty());
        assert!(config.linux.is_empty());
        assert!(config.windows.is_empty());
    }
}
