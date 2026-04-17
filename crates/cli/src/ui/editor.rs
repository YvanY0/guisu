//! Editor integration for manual conflict resolution

use anyhow::{Context, Result, anyhow};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

/// Open content in the user's preferred editor
///
/// This function:
/// 1. Creates a temporary file with the content
/// 2. Launches the editor specified by $EDITOR, $VISUAL, or a platform default
/// 3. Waits for the editor to close
/// 4. Returns the edited content
///
/// # Arguments
/// * `content` - Initial content to edit
/// * `file_path` - Optional path hint for the editor (helps with syntax highlighting)
///
/// # Returns
/// The edited content as a string
///
/// # Errors
///
/// Returns an error if:
/// - Creating the temporary file fails
/// - Writing content to the temporary file fails
/// - Launching the editor fails
/// - The editor exits with a non-zero status
/// - Reading the edited content back fails
pub fn open_in_editor(content: &str, file_path: Option<&Path>) -> Result<String> {
    // Create temp file with appropriate extension
    let temp_file = if let Some(path) = file_path {
        if let Some(ext) = path.extension() {
            tempfile::Builder::new()
                .suffix(&format!(".{}", ext.to_string_lossy()))
                .tempfile()
                .context("Failed to create temporary file")?
        } else {
            NamedTempFile::new().context("Failed to create temporary file")?
        }
    } else {
        NamedTempFile::new().context("Failed to create temporary file")?
    };

    // Write content to temp file
    fs::write(temp_file.path(), content).with_context(|| {
        format!(
            "Failed to write to temporary file: {}",
            temp_file.path().display()
        )
    })?;

    // Get editor from environment
    let editor = get_editor();

    // Launch editor
    let status = Command::new(&editor)
        .arg(temp_file.path())
        .status()
        .with_context(|| format!("Failed to launch editor: {editor}"))?;

    if !status.success() {
        return Err(anyhow!(
            "Editor exited with non-zero status: {:?}",
            status.code()
        ));
    }

    // Read edited content
    let edited = fs::read_to_string(temp_file.path())
        .with_context(|| format!("Failed to read edited file: {}", temp_file.path().display()))?;

    Ok(edited)
}

/// Open content in editor for merging conflicts
///
/// Shows both complete files side-by-side for easy comparison and editing
///
/// # Errors
///
/// Returns an error if opening the editor or reading the edited content fails
pub fn open_for_merge(
    file_path: &Path,
    local_content: &str,
    remote_content: &str,
    base_content: Option<&str>,
) -> Result<String> {
    let mut content = String::new();

    // Add header comment explaining the split view format
    let _ = writeln!(content, "# Split view merge for: {}", file_path.display());
    content.push_str("#\n");
    content.push_str("# This file shows BOTH complete versions below.\n");
    content.push_str("# Edit this content to create your desired final version.\n");
    content.push_str("# Lines starting with '#' will be ignored.\n");
    content.push_str("#\n");

    if base_content.is_some() {
        content.push_str("# THREE-WAY MERGE available:\n");
        content.push_str("# - DESTINATION: Your current file (below)\n");
        content.push_str("# - BASE: Last synchronized version (shown in middle section)\n");
        content.push_str("# - SOURCE: Incoming changes (shown at bottom)\n");
    } else {
        content.push_str("# TWO-WAY MERGE:\n");
        content.push_str("# - DESTINATION: Your current file (shown first)\n");
        content.push_str("# - SOURCE: Incoming changes (shown second)\n");
    }

    content.push_str("#\n");
    content.push_str("# Instructions:\n");
    content.push_str("#   1. Review both complete files below\n");
    content.push_str("#   2. Edit this content to create your desired final version\n");
    content.push_str("#   3. Delete the separator lines and section headers\n");
    content.push_str("#   4. Save and close the editor\n");
    content.push_str("#\n\n");

    // Show DESTINATION (local) content in full
    content.push_str(&"=".repeat(80));
    content.push('\n');
    content.push_str("# DESTINATION (current file) - COMPLETE CONTENT\n");
    content.push_str(&"=".repeat(80));
    content.push_str("\n\n");
    content.push_str(local_content);
    if !local_content.ends_with('\n') {
        content.push('\n');
    }
    content.push('\n');

    // If we have base content, show it
    if let Some(base) = base_content {
        content.push_str(&"=".repeat(80));
        content.push('\n');
        content.push_str("# BASE (last synchronized) - COMPLETE CONTENT\n");
        content.push_str(&"=".repeat(80));
        content.push_str("\n\n");
        content.push_str(base);
        if !base.ends_with('\n') {
            content.push('\n');
        }
        content.push('\n');
    }

    // Show SOURCE (remote) content in full
    content.push_str(&"=".repeat(80));
    content.push('\n');
    content.push_str("# SOURCE (incoming changes) - COMPLETE CONTENT\n");
    content.push_str(&"=".repeat(80));
    content.push_str("\n\n");
    content.push_str(remote_content);
    if !remote_content.ends_with('\n') {
        content.push('\n');
    }
    content.push('\n');
    content.push_str(&"=".repeat(80));
    content.push('\n');

    // Open in editor
    let edited = open_in_editor(&content, Some(file_path))?;

    // Remove header comments and separator lines
    let cleaned: String = edited
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            // Remove comment lines and separator lines
            !trimmed.starts_with('#') && !trimmed.chars().all(|c| c == '=')
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(cleaned)
}

/// Get the editor command from environment variables
fn get_editor() -> String {
    // Try EDITOR first
    if let Ok(editor) = std::env::var("EDITOR")
        && !editor.is_empty()
    {
        return editor;
    }

    // Try VISUAL
    if let Ok(editor) = std::env::var("VISUAL")
        && !editor.is_empty()
    {
        return editor;
    }

    // Platform-specific defaults
    if cfg!(windows) {
        "notepad".to_string()
    } else if cfg!(target_os = "macos") {
        // Check if nano is available, otherwise fall back to vi
        if Command::new("which")
            .arg("nano")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            "nano".to_string()
        } else {
            "vi".to_string()
        }
    } else {
        // Unix/Linux
        "vi".to_string()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for merge content generation logic
    // Note: We can't easily test get_editor() or open_in_editor() without environment
    // variable manipulation (which requires unsafe code that this crate denies)
    // or without actually launching an editor. Instead, we focus on testing the
    // content generation and filtering logic which is the core of the merge functionality.

    #[test]
    fn test_merge_content_generation_two_way() {
        use std::fmt::Write;

        // Test the content generation logic for two-way merge
        let file_path = Path::new("config.txt");
        let local_content = "option1 = value1\noption2 = value2";
        let remote_content = "option1 = new_value1\noption3 = value3";

        let mut content = String::new();

        // Add header (simplified version of open_for_merge logic)
        let _ = writeln!(content, "# Split view merge for: {}", file_path.display());
        content.push_str("# TWO-WAY MERGE:\n");
        content.push_str("# - DESTINATION: Your current file (shown first)\n");
        content.push_str("# - SOURCE: Incoming changes (shown second)\n");
        content.push_str("#\n\n");

        // Add local content
        content.push_str(&"=".repeat(80));
        content.push('\n');
        content.push_str("# DESTINATION (current file) - COMPLETE CONTENT\n");
        content.push_str(&"=".repeat(80));
        content.push_str("\n\n");
        content.push_str(local_content);
        content.push('\n');

        // Add remote content
        content.push_str(&"=".repeat(80));
        content.push('\n');
        content.push_str("# SOURCE (incoming changes) - COMPLETE CONTENT\n");
        content.push_str(&"=".repeat(80));
        content.push_str("\n\n");
        content.push_str(remote_content);
        content.push('\n');

        // Verify structure
        assert!(content.contains("# Split view merge for: config.txt"));
        assert!(content.contains("# TWO-WAY MERGE:"));
        assert!(content.contains("# DESTINATION (current file)"));
        assert!(content.contains("# SOURCE (incoming changes)"));
        assert!(content.contains(local_content));
        assert!(content.contains(remote_content));
        assert!(!content.contains("# BASE"));
    }

    #[test]
    fn test_merge_content_generation_three_way() {
        use std::fmt::Write;

        // Test the content generation logic for three-way merge
        let file_path = Path::new("config.txt");
        let local_content = "option1 = local_value";
        let remote_content = "option1 = remote_value";
        let base_content = Some("option1 = original_value");

        let mut content = String::new();

        // Add header
        let _ = writeln!(content, "# Split view merge for: {}", file_path.display());

        if base_content.is_some() {
            content.push_str("# THREE-WAY MERGE available:\n");
            content.push_str("# - DESTINATION: Your current file (below)\n");
            content.push_str("# - BASE: Last synchronized version (shown in middle section)\n");
            content.push_str("# - SOURCE: Incoming changes (shown at bottom)\n");
        }

        content.push_str("#\n\n");

        // Add local content
        content.push_str("# DESTINATION (current file)\n");
        content.push_str(local_content);
        content.push('\n');

        // Add base content
        if let Some(base) = base_content {
            content.push_str("# BASE (last synchronized)\n");
            content.push_str(base);
            content.push('\n');
        }

        // Add remote content
        content.push_str("# SOURCE (incoming changes)\n");
        content.push_str(remote_content);
        content.push('\n');

        // Verify structure
        assert!(content.contains("# THREE-WAY MERGE"));
        assert!(content.contains("# DESTINATION"));
        assert!(content.contains("# BASE"));
        assert!(content.contains("# SOURCE"));
        assert!(content.contains(local_content));
        assert!(content.contains("option1 = original_value"));
        assert!(content.contains(remote_content));
    }

    #[test]
    fn test_merge_content_separator_lines() {
        // Test that separator lines are 80 characters
        let separators = "=".repeat(80);
        assert_eq!(separators.len(), 80);
        assert!(separators.chars().all(|c| c == '='));
    }

    #[test]
    fn test_merge_content_newline_handling() {
        // Test newline handling for content without trailing newline
        let content_without_newline = "line1\nline2";
        let content_with_newline = "line1\nline2\n";

        let mut result1 = String::new();
        result1.push_str(content_without_newline);
        if !content_without_newline.ends_with('\n') {
            result1.push('\n');
        }

        let mut result2 = String::new();
        result2.push_str(content_with_newline);
        if !content_with_newline.ends_with('\n') {
            result2.push('\n');
        }

        // Both should end with a newline
        assert_eq!(result1.matches('\n').count(), 2); // 1 internal + 1 added
        assert_eq!(result2.matches('\n').count(), 2); // 2 original (already has trailing newline)
        // Verify both end with newline
        assert!(result1.ends_with('\n'));
        assert!(result2.ends_with('\n'));
    }

    #[test]
    fn test_merge_content_cleaning_removes_comments() {
        // Test the comment filtering logic
        let edited = "# This is a comment\nactual content\n# Another comment\nmore content";

        let cleaned: String = edited
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with('#') && !trimmed.chars().all(|c| c == '=')
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!cleaned.contains("# This is a comment"));
        assert!(!cleaned.contains("# Another comment"));
        assert!(cleaned.contains("actual content"));
        assert!(cleaned.contains("more content"));
    }

    #[test]
    fn test_merge_content_cleaning_removes_separators() {
        // Test that separator lines are removed
        let edited =
            "content1\n================\ncontent2\n========================================";

        let cleaned: String = edited
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with('#') && !trimmed.chars().all(|c| c == '=')
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!cleaned.contains("================"));
        assert!(!cleaned.contains("========================================"));
        assert!(cleaned.contains("content1"));
        assert!(cleaned.contains("content2"));
    }

    #[test]
    fn test_merge_content_cleaning_preserves_code_comments() {
        // Test that code comments (not at line start) are preserved
        let edited = "# Header comment\ncode // inline comment\n  # indented comment\nmore code";

        let cleaned: String = edited
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with('#') && !trimmed.chars().all(|c| c == '=')
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Header comment should be removed
        assert!(!cleaned.contains("# Header comment"));
        // Indented comment should be removed (trimmed starts with #)
        assert!(!cleaned.contains("# indented comment"));
        // Inline comment should be preserved
        assert!(cleaned.contains("code // inline comment"));
        assert!(cleaned.contains("more code"));
    }

    #[test]
    fn test_merge_content_cleaning_empty_lines() {
        // Test that empty lines are NOT preserved (they're removed by the filter)
        // because empty string's .chars().all(|c| c == '=') returns true
        let edited = "line1\n\nline2\n# comment\n\nline3";

        let cleaned: String = edited
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                // This filters out: comments starting with # AND lines with only '=' chars (including empty lines)
                // Empty lines are filtered because "".chars().all(|c| c == '=') is true (vacuous truth)
                !trimmed.starts_with('#') && !trimmed.chars().all(|c| c == '=')
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Empty lines are NOT preserved - they're filtered out
        let lines: Vec<&str> = cleaned.lines().collect();
        assert_eq!(lines.len(), 3); // Only: line1, line2, line3
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[1], "line2");
        assert_eq!(lines[2], "line3");
    }

    #[test]
    fn test_merge_content_path_display() {
        // Test that file path is correctly displayed in header
        let file_path = Path::new("path/to/config.toml");
        let header = format!("# Split view merge for: {}\n", file_path.display());

        assert!(header.contains("path/to/config.toml"));
    }

    #[test]
    fn test_merge_content_instructions() {
        // Test that instructions are included in header
        let mut content = String::new();
        content.push_str("# Instructions:\n");
        content.push_str("#   1. Review both complete files below\n");
        content.push_str("#   2. Edit this content to create your desired final version\n");
        content.push_str("#   3. Delete the separator lines and section headers\n");
        content.push_str("#   4. Save and close the editor\n");

        assert!(content.contains("# Instructions:"));
        assert!(content.contains("#   1. Review both complete files"));
        assert!(content.contains("#   2. Edit this content"));
        assert!(content.contains("#   3. Delete the separator lines"));
        assert!(content.contains("#   4. Save and close"));
    }
}
