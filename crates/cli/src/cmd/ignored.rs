//! Ignored command operations
//!
//! This module provides commands for viewing ignored files and patterns:
//! - list: List files that are ignored on the current platform
//! - show: Show ignore rules for the current platform

use anyhow::{Context, Result};
use guisu_config::IgnoreMatcher;
use guisu_config::IgnoresConfig;
use guisu_core::platform::CURRENT_PLATFORM;
use guisu_engine::entry::SourceEntry;
use guisu_engine::state::SourceState;
use lscolors::{LsColors, Style};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::path::Path;

use guisu_config::Config;

/// Run ignored list command
///
/// Lists all files in the source directory that would be ignored on the current platform.
/// Shows the target file paths (after removing .j2, .age suffixes).
/// This includes entries ignored by:
/// - Global patterns from global section
/// - Platform-specific patterns from `<platform>` section
///
/// # Errors
///
/// Returns an error if:
/// - Resolving paths (source/destination directories) fails
/// - Loading ignore patterns from .guisu/ignores.toml fails
/// - Reading source state fails
pub fn run_list(source_dir: &Path, dest_dir: &Path, config: &Config) -> Result<()> {
    let platform = CURRENT_PLATFORM.os;

    // Detect if output is to a terminal for icon auto mode
    let is_tty = std::io::stdout().is_terminal();
    let show_icons = config.ui.icons.should_show_icons(is_tty);

    // Resolve dotfiles directory (handles root_entry and canonicalization)
    let paths = crate::common::ResolvedPaths::resolve(source_dir, dest_dir, config)?;
    let source_abs = &paths.dotfiles_dir;

    // Load ignore patterns from source_dir/.guisu/ignores.toml
    // Use dotfiles_dir as the match root so patterns match relative to the dotfiles directory
    let matcher = IgnoreMatcher::from_ignores_toml(source_dir)
        .context("Failed to load ignore patterns from .guisu/ignores.toml")?;

    // Read ALL source files (without filtering by ignore patterns)
    let source_state =
        SourceState::read(source_abs.to_owned()).context("Failed to read source state")?;

    // Collect all ignored files with their target paths
    let mut ignored_files = Vec::new();

    for entry in source_state.entries() {
        // Only process files
        if let SourceEntry::File { .. } = entry {
            // Get the target path (after processing .j2, .age, etc.)
            let target_path = entry.target_path();

            // Check if target path or any parent directory is ignored
            // Use relative path for matching (patterns are relative paths)
            let mut is_ignored = false;

            // Check the file itself (use relative path)
            if matcher.is_ignored(target_path.as_path(), None) {
                is_ignored = true;
            }

            // Check each parent directory (use relative paths)
            if !is_ignored {
                let mut current = target_path.as_path();
                while let Some(parent) = current.parent() {
                    // Stop at root (empty path)
                    if parent.as_os_str().is_empty() {
                        break;
                    }

                    if matcher.is_ignored(parent, None) {
                        is_ignored = true;
                        break;
                    }

                    current = parent;
                }
            }

            if is_ignored {
                ignored_files.push(target_path.to_string());
            }
        }
    }

    // Display results
    if ignored_files.is_empty() {
        println!("{}\n", format!("Ignored 0 files on {platform}").dimmed());
    } else {
        let count = ignored_files.len();

        println!(
            "{} {} {} {}\n",
            "Ignored".bright_white(),
            count.to_string().bright_cyan(),
            "files on".bright_white(),
            platform.bright_cyan()
        );

        // Sort for consistent output
        ignored_files.sort();

        // Initialize lscolors from environment for file coloring
        let lscolors = LsColors::from_env().unwrap_or_default();

        for file in &ignored_files {
            // Add ~/ prefix to path
            let display_path = format!("~/{file}");

            // Create FileIconInfo to get icon
            let icon_info = crate::ui::icons::FileIconInfo {
                path: display_path.as_str(),
                is_directory: false,
                is_symlink: false,
            };

            let icon = crate::ui::icons::icon_for_file(&icon_info, show_icons);

            // Get color style for file based on its extension/type
            let file_style = lscolors
                .style_for_path(&display_path)
                .map_or_default(Style::to_nu_ansi_term_style);

            // Apply style to both icon and path
            let styled_icon = file_style.paint(icon);
            let styled_path = file_style.paint(&display_path);

            println!("  {styled_icon} {styled_path}");
        }
    }

    Ok(())
}

/// Run ignored show command
///
/// Shows the ignore rules that apply to the current platform.
/// This reads from .guisu/ignores.toml in the source directory.
///
/// # Errors
///
/// Returns an error if loading .guisu/ignores.toml fails
pub fn run_show(source_dir: &Path, _config: &Config, show_all: bool) -> Result<()> {
    let platform = CURRENT_PLATFORM.os;

    // Load ignore config from source_dir/.guisu/ignores.toml
    // Note: ignores.toml is always in source_dir, not in dotfiles_dir
    // (dotfiles_dir might be source_dir/root_entry if root_entry is set)
    let ignores_config =
        IgnoresConfig::load(source_dir).context("Failed to load .guisu/ignores.toml")?;

    // Helper to display a section
    let display_section = |section_name: &str, patterns: &[String], is_current: bool| {
        if is_current {
            println!("{}:", format!("{section_name} (current)").bright_white());
        } else {
            println!("{}:", section_name.bright_white());
        }

        if patterns.is_empty() {
            println!("  {}", "(none)".dimmed());
        } else {
            for pattern in patterns {
                println!("  {pattern}");
            }
        }
    };

    if show_all {
        // Show all platforms
        println!(
            "{} {}\n",
            "Current platform:".bright_white(),
            platform.bright_cyan()
        );

        // Global patterns
        display_section("global", &ignores_config.global, false);
        println!();

        // All platform sections
        display_section("darwin", &ignores_config.darwin, platform == "darwin");
        println!();
        display_section("linux", &ignores_config.linux, platform == "linux");
        println!();
        display_section("windows", &ignores_config.windows, platform == "windows");
    } else {
        // Show only current platform
        println!(
            "{} {}\n",
            "Platform:".bright_white(),
            platform.bright_cyan()
        );

        // Show global patterns if any
        if !ignores_config.global.is_empty() {
            display_section("global", &ignores_config.global, false);
            println!();
        }

        // Show platform-specific patterns
        let empty_vec = Vec::new();
        let platform_patterns = match platform {
            "darwin" => &ignores_config.darwin,
            "linux" => &ignores_config.linux,
            "windows" => &ignores_config.windows,
            _ => &empty_vec,
        };

        display_section(platform, platform_patterns, true);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::utils::path::SourceDirExt;
    use std::fs;
    use tempfile::TempDir;

    /// Helper to create a test directory structure with config and source files
    fn setup_test_env() -> (TempDir, Config) {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // Create .guisu directory
        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        // Create ignores.toml
        fs::write(
            guisu_dir.join("ignores.toml"),
            r#"
global = [
    "*.log",
    "*.tmp",
    ".DS_Store"
]

darwin = [
    ".Trash/",
    "Library/Caches/"
]

linux = [
    "~/.cache/"
]

windows = [
    "Thumbs.db"
]
"#,
        )
        .unwrap();

        // Create dotfiles directory (default root_entry = "home")
        let dotfiles_dir = source_dir.join("home");
        fs::create_dir_all(&dotfiles_dir).unwrap();

        // Create some test files in dotfiles directory
        // Ignored files
        fs::write(dotfiles_dir.join("test.log"), "log content").unwrap();
        fs::write(dotfiles_dir.join("debug.tmp"), "tmp content").unwrap();
        fs::write(dotfiles_dir.join(".DS_Store"), "macos junk").unwrap();

        // Non-ignored files
        fs::write(dotfiles_dir.join("config.txt"), "config").unwrap();
        fs::write(dotfiles_dir.join("bashrc"), "bash config").unwrap();

        // Create subdirectory with mixed files
        let subdir = dotfiles_dir.join(".config");
        fs::create_dir_all(&subdir).unwrap();
        fs::write(subdir.join("app.log"), "app logs").unwrap(); // ignored
        fs::write(subdir.join("settings.toml"), "settings").unwrap(); // not ignored

        // Create default config
        let mut config = Config::default();
        config.general.root_entry = std::path::PathBuf::from("home");

        (temp, config)
    }

    #[test]
    fn test_run_list_basic() {
        let (temp, config) = setup_test_env();
        let source_dir = temp.path();

        // run_list should succeed without errors
        let result = run_list(source_dir, source_dir, &config);
        assert!(result.is_ok(), "run_list should succeed: {result:?}");
    }

    #[test]
    fn test_run_list_missing_ignores_toml() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // Create .guisu but NO ignores.toml (will use default empty config)
        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        let dotfiles_dir = source_dir.join("home");
        fs::create_dir_all(&dotfiles_dir).unwrap();
        fs::write(dotfiles_dir.join("test.txt"), "content").unwrap();

        let config = Config::default();

        // Should succeed with empty ignores (uses default)
        let result = run_list(source_dir, source_dir, &config);
        assert!(
            result.is_ok(),
            "Should succeed with default empty ignores: {result:?}"
        );
    }

    #[test]
    fn test_run_list_empty_directory() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // Create .guisu/ignores.toml
        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();
        fs::write(guisu_dir.join("ignores.toml"), "global = []").unwrap();

        // Create empty dotfiles directory
        let dotfiles_dir = source_dir.join("home");
        fs::create_dir_all(&dotfiles_dir).unwrap();

        let config = Config::default();

        // Should succeed with no ignored files
        let result = run_list(source_dir, source_dir, &config);
        assert!(result.is_ok(), "Should succeed with empty directory");
    }

    #[test]
    fn test_run_show_basic() {
        let (temp, config) = setup_test_env();
        let source_dir = temp.path();

        // Test show without --all flag
        let result = run_show(source_dir, &config, false);
        assert!(result.is_ok(), "run_show should succeed: {result:?}");
    }

    #[test]
    fn test_run_show_all_platforms() {
        let (temp, config) = setup_test_env();
        let source_dir = temp.path();

        // Test show with --all flag
        let result = run_show(source_dir, &config, true);
        assert!(result.is_ok(), "run_show --all should succeed: {result:?}");
    }

    #[test]
    fn test_run_show_missing_ignores_toml() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // No .guisu directory at all
        let config = Config::default();

        let result = run_show(source_dir, &config, false);
        // Should succeed with default (empty) config
        assert!(result.is_ok(), "Should succeed with missing ignores.toml");
    }

    #[test]
    fn test_run_show_empty_ignores() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        // Create empty ignores.toml
        fs::write(guisu_dir.join("ignores.toml"), "").unwrap();

        let config = Config::default();

        let result = run_show(source_dir, &config, false);
        assert!(result.is_ok(), "Should handle empty ignores.toml");

        let result_all = run_show(source_dir, &config, true);
        assert!(
            result_all.is_ok(),
            "Should handle empty ignores.toml with --all"
        );
    }

    #[test]
    fn test_run_show_invalid_toml() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        // Create invalid TOML
        fs::write(guisu_dir.join("ignores.toml"), "invalid toml {{{").unwrap();

        let config = Config::default();

        let result = run_show(source_dir, &config, false);
        assert!(result.is_err(), "Should fail with invalid TOML");

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to load") || error_msg.contains("parse"),
            "Error should mention parsing failure: {error_msg}"
        );
    }

    #[test]
    fn test_run_show_with_negation_patterns() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        fs::write(
            guisu_dir.join("ignores.toml"),
            r#"
global = [
    ".config/*",
    "!.config/nvim/",
    "!.config/bat/"
]
"#,
        )
        .unwrap();

        let config = Config::default();

        // Should display negation patterns correctly
        let result = run_show(source_dir, &config, false);
        assert!(result.is_ok(), "Should handle negation patterns");
    }

    #[test]
    fn test_run_list_with_subdirectories() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        fs::write(
            guisu_dir.join("ignores.toml"),
            r#"
global = [
    "*.log",
    "cache/"
]
"#,
        )
        .unwrap();

        let dotfiles_dir = source_dir.join("home");
        fs::create_dir_all(&dotfiles_dir).unwrap();

        // Create nested structure
        let cache_dir = dotfiles_dir.join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("data.txt"), "cached data").unwrap();

        let config_dir = dotfiles_dir.join(".config");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("app.log"), "logs").unwrap();
        fs::write(config_dir.join("settings.toml"), "settings").unwrap();

        let config = Config::default();

        let result = run_list(source_dir, source_dir, &config);
        assert!(result.is_ok(), "Should handle subdirectories: {result:?}");
    }

    #[test]
    fn test_run_list_with_templates_and_encrypted() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        fs::write(
            guisu_dir.join("ignores.toml"),
            r#"
global = [
    "*.log"
]
"#,
        )
        .unwrap();

        let dotfiles_dir = source_dir.join("home");
        fs::create_dir_all(&dotfiles_dir).unwrap();

        // Create files with .j2 and .age extensions
        fs::write(dotfiles_dir.join("config.txt.j2"), "template").unwrap();
        fs::write(dotfiles_dir.join("secret.txt.age"), "encrypted").unwrap();
        fs::write(dotfiles_dir.join("debug.log.j2"), "log template").unwrap(); // ignored

        let config = Config::default();

        let result = run_list(source_dir, source_dir, &config);
        assert!(
            result.is_ok(),
            "Should handle .j2 and .age files: {result:?}"
        );
    }

    #[test]
    fn test_run_show_only_global_patterns() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        fs::write(
            guisu_dir.join("ignores.toml"),
            r#"
global = [
    "*.tmp",
    "*.log"
]
"#,
        )
        .unwrap();

        let config = Config::default();

        // Should show only global patterns for current platform
        let result = run_show(source_dir, &config, false);
        assert!(result.is_ok(), "Should show only global patterns");
    }

    #[test]
    fn test_run_show_mixed_global_and_platform() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        fs::write(
            guisu_dir.join("ignores.toml"),
            r#"
global = ["*.tmp"]
darwin = [".DS_Store"]
linux = [".cache"]
windows = ["Thumbs.db"]
"#,
        )
        .unwrap();

        let config = Config::default();

        // Current platform view
        let result = run_show(source_dir, &config, false);
        assert!(result.is_ok(), "Should show global + platform patterns");

        // All platforms view
        let result_all = run_show(source_dir, &config, true);
        assert!(result_all.is_ok(), "Should show all platforms");
    }

    #[test]
    fn test_run_list_with_custom_root_entry() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let guisu_dir = source_dir.guisu_dir();
        fs::create_dir_all(&guisu_dir).unwrap();

        fs::write(guisu_dir.join("ignores.toml"), "global = []").unwrap();

        // Use custom root_entry instead of default "home"
        let dotfiles_dir = source_dir.join("dotfiles");
        fs::create_dir_all(&dotfiles_dir).unwrap();
        fs::write(dotfiles_dir.join("test.txt"), "content").unwrap();

        let mut config = Config::default();
        config.general.root_entry = std::path::PathBuf::from("dotfiles");

        let result = run_list(source_dir, source_dir, &config);
        assert!(
            result.is_ok(),
            "Should work with custom root_entry: {result:?}"
        );
    }
}
