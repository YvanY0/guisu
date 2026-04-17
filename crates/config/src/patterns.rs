//! Ignore pattern matcher with include/exclude support
//!
//! Uses the `ignore` crate (from ripgrep) for gitignore-style pattern matching.
//! Supports negation using ! prefix.
//!
//! Example:
//! ```toml
//! global = [
//!     ".config/*",        # Ignore all .config contents
//!     "!.config/atuin/",  # Re-include .config/atuin/
//!     "!.config/bat/",    # Re-include .config/bat/
//! ]
//! ```

use crate::{IgnoresConfig, Result};
use guisu_core::platform::CURRENT_PLATFORM;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

/// Ignore pattern matcher using ripgrep's gitignore implementation
///
/// This is a thin wrapper around `ignore::gitignore::Gitignore` that handles
/// loading patterns from `.guisu/ignores.toml` and platform-specific filtering.
pub struct IgnoreMatcher {
    /// The compiled gitignore matcher from the ignore crate
    gitignore: Gitignore,
}

impl IgnoreMatcher {
    /// Create from .guisu/ignores.toml file
    ///
    /// Loads patterns for the current platform (global + platform-specific).
    /// Patterns starting with ! are treated as exclude patterns (re-include).
    /// Uses ripgrep's gitignore implementation for accurate gitignore semantics.
    ///
    /// # Errors
    ///
    /// Returns error if ignores config cannot be loaded
    pub fn from_ignores_toml(source_dir: &Path) -> Result<Self> {
        let config = IgnoresConfig::load(source_dir)
            .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;
        let platform = CURRENT_PLATFORM.os;

        // Collect platform-specific patterns without cloning
        let platform_patterns: &[String] = match platform {
            "darwin" => &config.darwin,
            "linux" => &config.linux,
            "windows" => &config.windows,
            _ => &[],
        };

        // Build gitignore matcher using ignore crate
        let mut builder = GitignoreBuilder::new(source_dir);

        // Helper closure to add pattern and its directory content variant
        let mut add_pattern = |pattern: &str| -> Result<()> {
            // add_line returns error if pattern is invalid
            // We use None for the source path (means pattern is not from a file)
            builder
                .add_line(None, pattern)
                .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;

            // For patterns that might match directories, also add a pattern to match their contents
            // This is needed because ignore crate's directory patterns only match the directory itself,
            // not its contents. In a tree-walking scenario, you'd skip into ignored directories,
            // but guisu checks individual paths.
            //
            // Add /** suffix for:
            // 1. Patterns ending with / (explicit directory patterns)
            // 2. Patterns without / that could be directory names (like node_modules, .git)
            //
            // Don't add for patterns that already have glob wildcards in the last component
            // (like *.log, test-*.txt) as these are clearly file patterns.
            let needs_content_pattern = if pattern.ends_with('/') {
                !pattern.ends_with("**/")
            } else {
                // Check if the last path component contains wildcards
                let last_component = pattern.rsplit('/').next().unwrap_or(pattern);
                !last_component.contains('*') && !last_component.contains('?')
            };

            if needs_content_pattern {
                // Remove trailing / if present
                let base = pattern.strip_suffix('/').unwrap_or(pattern);

                // Add **/ prefix if pattern doesn't start with / (meaning it should match at any level)
                // Pre-allocate string with exact capacity to avoid reallocation
                let content_pattern = if base.starts_with('/') {
                    // Pattern starts with / - only matches at root
                    // Capacity: base.len() + 3 for "/**"
                    let mut s = String::with_capacity(base.len() + 3);
                    s.push_str(base);
                    s.push_str("/**");
                    s
                } else {
                    // Pattern doesn't start with / - should match at any level
                    // Capacity: base.len() + 7 for "**/" prefix and "/**" suffix
                    let mut s = String::with_capacity(base.len() + 7);
                    s.push_str("**/");
                    s.push_str(base);
                    s.push_str("/**");
                    s
                };

                builder
                    .add_line(None, &content_pattern)
                    .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;
            }

            Ok(())
        };

        // Process global patterns first
        for pattern in &config.global {
            add_pattern(pattern)?;
        }

        // Process platform-specific patterns
        for pattern in platform_patterns {
            add_pattern(pattern)?;
        }

        let gitignore = builder
            .build()
            .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?;

        Ok(Self { gitignore })
    }

    /// Check if path should be ignored
    ///
    /// Uses ripgrep's gitignore matching logic which correctly handles:
    /// - Glob patterns (*, ?, [])
    /// - Directory patterns (trailing /)
    /// - Negation patterns (! prefix)
    /// - Last match wins semantics
    ///
    /// The `is_dir` parameter indicates whether the path represents a directory.
    /// This is important for patterns ending with `/` which only match directories.
    /// Defaults to checking if the path exists and is a directory on the filesystem.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_config::IgnoreMatcher;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let matcher = IgnoreMatcher::from_ignores_toml(Path::new("."))?;
    ///
    /// // Check if a file path should be ignored (auto-detect is_dir)
    /// if matcher.is_ignored(Path::new(".config/nvim/init.lua"), None) {
    ///     println!("File is ignored");
    /// }
    ///
    /// // Or explicitly specify if it's a directory
    /// if matcher.is_ignored(Path::new(".config"), Some(true)) {
    ///     println!("Directory is ignored");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn is_ignored(&self, path: &Path, is_dir: Option<bool>) -> bool {
        // The gitignore matcher needs to know if the path is a directory
        // If not explicitly provided, try to check if it exists and is a dir
        let is_dir = is_dir.unwrap_or_else(|| path.is_dir());

        // matched() returns Match enum:
        // - Match::None: not matched
        // - Match::Ignore(_): matched an ignore pattern (should be ignored)
        // - Match::Whitelist(_): matched a negation pattern (should NOT be ignored)
        match self.gitignore.matched(path, is_dir) {
            ignore::Match::Ignore(_) => true, // Matched ignore pattern
            ignore::Match::None | ignore::Match::Whitelist(_) => false, // Not matched or whitelisted
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_ignores(temp: &TempDir, content: &str) -> std::path::PathBuf {
        let guisu_dir = temp.path().join(".guisu");
        fs::create_dir_all(&guisu_dir).unwrap();
        fs::write(guisu_dir.join("ignores.toml"), content).unwrap();
        temp.path().to_path_buf()
    }

    #[test]
    fn test_from_ignores_toml_basic() {
        let temp = TempDir::new().unwrap();
        let content = r#"
global = ["*.log", ".DS_Store"]
"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // Test that matcher was created successfully
        assert!(matcher.is_ignored(Path::new("test.log"), None));
        assert!(matcher.is_ignored(Path::new(".DS_Store"), None));
    }

    #[test]
    fn test_from_ignores_toml_with_negation() {
        let temp = TempDir::new().unwrap();
        let content = r#"
global = [".config/*", "!.config/atuin/"]
"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // .config/* should be ignored
        assert!(matcher.is_ignored(Path::new(".config/nvim"), Some(true)));

        // !.config/atuin/ should NOT be ignored
        assert!(!matcher.is_ignored(Path::new(".config/atuin/config.toml"), None));
    }

    #[test]
    fn test_is_ignored_exact_match() {
        let temp = TempDir::new().unwrap();
        let content = r#"global = ["file.txt"]"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        assert!(matcher.is_ignored(Path::new("file.txt"), None));
        assert!(!matcher.is_ignored(Path::new("other.txt"), None));
    }

    #[test]
    fn test_is_ignored_glob_pattern() {
        let temp = TempDir::new().unwrap();
        let content = r#"global = ["*.log"]"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        assert!(matcher.is_ignored(Path::new("test.log"), None));
        assert!(matcher.is_ignored(Path::new("error.log"), None));
        assert!(!matcher.is_ignored(Path::new("test.txt"), None));
    }

    #[test]
    fn test_is_ignored_directory_prefix() {
        let temp = TempDir::new().unwrap();
        // Use .config/** pattern to match everything under .config/
        let content = r#"global = [".config/**"]"#;
        let source_dir = create_test_ignores(&temp, content);

        // Create actual directories for testing (in temp directory)
        fs::create_dir_all(temp.path().join(".config/foo")).unwrap();
        fs::create_dir_all(temp.path().join(".config/foo/bar")).unwrap();
        fs::create_dir_all(temp.path().join(".confi")).unwrap();

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // Pattern .config/** matches everything under .config/
        assert!(matcher.is_ignored(Path::new(".config/foo"), Some(true)));
        assert!(matcher.is_ignored(Path::new(".config/foo/bar"), Some(true)));
        assert!(matcher.is_ignored(Path::new(".config/nvim/init.lua"), Some(false)));
        // .confi doesn't match the pattern
        assert!(!matcher.is_ignored(Path::new(".confi"), Some(true)));
    }

    #[test]
    fn test_is_ignored_directory_wildcard() {
        let temp = TempDir::new().unwrap();
        let content = r#"global = [".config/*"]"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // .config/* matches both files and directories under .config/
        assert!(matcher.is_ignored(Path::new(".config/foo"), Some(true)));
        assert!(matcher.is_ignored(Path::new(".config/bar"), Some(false)));
    }

    #[test]
    fn test_is_ignored_negation_pattern() {
        let temp = TempDir::new().unwrap();
        let content = r#"
global = [".config/*", "!.config/atuin/"]
"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // Matches .config/* -> ignored
        assert!(matcher.is_ignored(Path::new(".config/random"), None));

        // Matches !.config/atuin/ -> not ignored
        assert!(!matcher.is_ignored(Path::new(".config/atuin/config.toml"), None));
    }

    #[test]
    fn test_is_ignored_last_match_wins() {
        let temp = TempDir::new().unwrap();
        let content = r#"
global = [".config/*", "!.config/atuin/", ".config/atuin/secret"]
"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // Last pattern .config/atuin/secret wins
        assert!(matcher.is_ignored(Path::new(".config/atuin/secret"), None));

        // Negation pattern wins for other files
        assert!(!matcher.is_ignored(Path::new(".config/atuin/config.toml"), None));
    }

    #[test]
    fn test_is_ignored_directory_name_match() {
        let temp = TempDir::new().unwrap();
        // Use pattern to match directory and its contents
        let content = r#"global = ["**/DankMaterialShell/**", "**/DankMaterialShell"]"#;
        let source_dir = create_test_ignores(&temp, content);

        // Create actual directories and files for testing
        fs::create_dir_all(temp.path().join("DankMaterialShell")).unwrap();
        fs::create_dir_all(temp.path().join(".config/DankMaterialShell")).unwrap();
        fs::write(
            temp.path().join(".config/DankMaterialShell/file.txt"),
            "content",
        )
        .unwrap();

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // Pattern matches directory at any level and all its contents
        assert!(matcher.is_ignored(Path::new("DankMaterialShell"), Some(true)));
        assert!(matcher.is_ignored(Path::new(".config/DankMaterialShell"), Some(true)));
        assert!(matcher.is_ignored(Path::new(".config/DankMaterialShell/file.txt"), Some(false)));
        assert!(matcher.is_ignored(Path::new("DankMaterialShell/foo/bar.txt"), Some(false)));
    }

    #[test]
    fn test_is_ignored_default_not_ignored() {
        let temp = TempDir::new().unwrap();
        let content = r"global = []";
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // No patterns means nothing is ignored
        assert!(!matcher.is_ignored(Path::new("anything"), None));
    }

    #[test]
    fn test_debug_directory_pattern() {
        let temp = TempDir::new().unwrap();
        let content = r#"global = ["DankMaterialShell"]"#;
        let source_dir = create_test_ignores(&temp, content);

        let matcher = IgnoreMatcher::from_ignores_toml(&source_dir).unwrap();

        // Test how DankMaterialShell pattern behaves
        println!("\nTesting DankMaterialShell pattern (no trailing slash):");
        println!(
            "  DankMaterialShell:                       {:?}",
            matcher
                .gitignore
                .matched(Path::new("DankMaterialShell"), true)
        );
        println!(
            "  DankMaterialShell/config:                {:?}",
            matcher
                .gitignore
                .matched(Path::new("DankMaterialShell/config"), false)
        );
        println!(
            "  .config/DankMaterialShell:               {:?}",
            matcher
                .gitignore
                .matched(Path::new(".config/DankMaterialShell"), true)
        );
        println!(
            "  .config/DankMaterialShell/theme.json:    {:?}",
            matcher
                .gitignore
                .matched(Path::new(".config/DankMaterialShell/theme.json"), false)
        );

        // According to gitignore semantics, DankMaterialShell should match at any level
        assert!(matcher.is_ignored(Path::new("DankMaterialShell"), Some(true)));
        assert!(matcher.is_ignored(Path::new("DankMaterialShell/config"), Some(false)));
        assert!(matcher.is_ignored(Path::new(".config/DankMaterialShell"), Some(true)));
        assert!(matcher.is_ignored(
            Path::new(".config/DankMaterialShell/theme.json"),
            Some(false)
        ));
    }
}
