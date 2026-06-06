//! XDG directory utilities
//!
//! This module provides XDG-compliant directory paths for guisu.
//! It follows the XDG Base Directory specification using the `xdg` crate:
//! - `XDG_DATA_HOME` defaults to ~/.local/share
//! - `XDG_CONFIG_HOME` defaults to ~/.config
//! - `XDG_STATE_HOME` defaults to ~/.local/state

use std::path::PathBuf;

#[cfg(windows)]
use dirs as dirs_crate;
#[cfg(unix)]
use xdg::BaseDirectories;

/// Get the guisu data directory
///
/// Returns `$XDG_DATA_HOME/guisu` or `~/.local/share/guisu`
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        BaseDirectories::with_prefix("guisu").get_data_home()
    }
    #[cfg(windows)]
    {
        dirs_crate::data_dir().map(|p| p.join("guisu"))
    }
}

/// Get the guisu state directory
///
/// Returns `$XDG_STATE_HOME/guisu` or `~/.local/state/guisu`
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        BaseDirectories::with_prefix("guisu").get_state_home()
    }
    #[cfg(windows)]
    {
        dirs_crate::state_dir().map(|p| p.join("guisu"))
    }
}

/// Get the default source directory for dotfiles
///
/// Returns `$XDG_DATA_HOME/guisu` or `~/.local/share/guisu`
#[must_use]
pub fn default_source_dir() -> Option<PathBuf> {
    data_dir()
}

/// Get the default config file path
///
/// Returns `$XDG_DATA_HOME/guisu/config.toml` or `~/.local/share/guisu/config.toml`
#[must_use]
pub fn default_config_file() -> Option<PathBuf> {
    data_dir().map(|d| d.join("config.toml"))
}

/// Get the default age identity file path
///
/// Returns `$XDG_DATA_HOME/guisu/key.txt` or `~/.local/share/guisu/key.txt`
#[must_use]
pub fn default_age_identity() -> Option<PathBuf> {
    data_dir().map(|d| d.join("key.txt"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_data_dir_returns_some() {
        // Should return a path in normal environment
        let dir = data_dir();
        assert!(
            dir.is_some(),
            "data_dir should return Some in normal environment"
        );

        let path = dir.unwrap();
        assert!(
            path.to_string_lossy().contains("guisu"),
            "data_dir path should contain 'guisu': {path:?}"
        );
    }

    #[test]
    fn test_state_dir_returns_some() {
        // Should return a path in normal environment
        let dir = state_dir();
        assert!(
            dir.is_some(),
            "state_dir should return Some in normal environment"
        );

        let path = dir.unwrap();
        assert!(
            path.to_string_lossy().contains("guisu"),
            "state_dir path should contain 'guisu': {path:?}"
        );
    }

    #[test]
    fn test_default_source_dir_same_as_data_dir() {
        // default_source_dir should be identical to data_dir
        assert_eq!(
            default_source_dir(),
            data_dir(),
            "default_source_dir should be same as data_dir"
        );
    }

    #[test]
    fn test_default_config_file_ends_with_config_toml() {
        let config_file = default_config_file();
        assert!(
            config_file.is_some(),
            "default_config_file should return Some"
        );

        let path = config_file.unwrap();
        assert!(
            path.to_string_lossy().ends_with("config.toml"),
            "config file should end with 'config.toml': {path:?}"
        );
        assert!(
            path.to_string_lossy().contains("guisu"),
            "config file path should contain 'guisu': {path:?}"
        );
    }

    #[test]
    fn test_default_age_identity_ends_with_key_txt() {
        let key_file = default_age_identity();
        assert!(
            key_file.is_some(),
            "default_age_identity should return Some"
        );

        let path = key_file.unwrap();
        assert!(
            path.to_string_lossy().ends_with("key.txt"),
            "age identity should end with 'key.txt': {path:?}"
        );
        assert!(
            path.to_string_lossy().contains("guisu"),
            "age identity path should contain 'guisu': {path:?}"
        );
    }

    #[test]
    fn test_data_dir_is_absolute() {
        if let Some(path) = data_dir() {
            assert!(
                path.is_absolute(),
                "data_dir should return absolute path: {path:?}"
            );
        }
    }

    #[test]
    fn test_state_dir_is_absolute() {
        if let Some(path) = state_dir() {
            assert!(
                path.is_absolute(),
                "state_dir should return absolute path: {path:?}"
            );
        }
    }

    #[test]
    fn test_default_config_file_is_child_of_data_dir() {
        let data = data_dir();
        let config = default_config_file();

        if let (Some(data_path), Some(config_path)) = (data, config) {
            assert!(
                config_path.starts_with(&data_path),
                "config file should be inside data dir.\nData: {data_path:?}\nConfig: {config_path:?}"
            );
        }
    }

    #[test]
    fn test_default_age_identity_is_child_of_data_dir() {
        let data = data_dir();
        let key = default_age_identity();

        if let (Some(data_path), Some(key_path)) = (data, key) {
            assert!(
                key_path.starts_with(&data_path),
                "age identity should be inside data dir.\nData: {data_path:?}\nKey: {key_path:?}"
            );
        }
    }

    #[test]
    fn test_paths_are_consistent() {
        // All paths should be consistent with each other
        let data = data_dir();
        let state = state_dir();
        let source = default_source_dir();
        let config = default_config_file();
        let key = default_age_identity();

        // data_dir and default_source_dir should be identical
        assert_eq!(data, source);

        // If all return Some, they should all contain "guisu"
        if let Some(d) = &data {
            assert!(d.to_string_lossy().contains("guisu"));
        }
        if let Some(s) = &state {
            assert!(s.to_string_lossy().contains("guisu"));
        }
        if let Some(c) = &config {
            assert!(c.to_string_lossy().contains("guisu"));
        }
        if let Some(k) = &key {
            assert!(k.to_string_lossy().contains("guisu"));
        }
    }

    #[test]
    fn test_data_and_state_dirs_are_different() {
        let data = data_dir();
        let state = state_dir();

        // Both should return Some
        assert!(data.is_some());
        assert!(state.is_some());

        // They should be different paths
        if let (Some(d), Some(s)) = (data, state) {
            assert_ne!(d, s, "data_dir and state_dir should be different");
        }
    }

    #[test]
    fn test_config_and_key_have_different_names() {
        let config = default_config_file();
        let key = default_age_identity();

        if let (Some(c), Some(k)) = (config, key) {
            // Should have different filenames
            assert_ne!(c.file_name(), k.file_name());
            assert_eq!(c.file_name().and_then(|n| n.to_str()), Some("config.toml"));
            assert_eq!(k.file_name().and_then(|n| n.to_str()), Some("key.txt"));
        }
    }

    #[test]
    fn test_all_functions_called() {
        // Call all public functions to ensure they work
        let _ = data_dir();
        let _ = state_dir();
        let _ = default_source_dir();
        let _ = default_config_file();
        let _ = default_age_identity();
    }

    #[test]
    fn test_paths_use_correct_separators() {
        // Paths should use platform-appropriate separators
        if let Some(path) = data_dir() {
            let path_str = path.to_string_lossy();

            #[cfg(unix)]
            assert!(path_str.contains('/'), "Unix paths should use /");

            #[cfg(windows)]
            assert!(
                path_str.contains('\\') || path_str.contains('/'),
                "Windows paths should use \\ or /"
            );
        }
    }

    #[test]
    fn test_multiple_calls_return_same_value() {
        // Multiple calls should return consistent values
        let data1 = data_dir();
        let data2 = data_dir();
        assert_eq!(data1, data2);

        let state1 = state_dir();
        let state2 = state_dir();
        assert_eq!(state1, state2);

        let config1 = default_config_file();
        let config2 = default_config_file();
        assert_eq!(config1, config2);
    }
}
