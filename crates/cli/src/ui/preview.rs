//! Change preview and summary utilities

use similar::{ChangeTag, TextDiff};

/// Summary of changes between two files
#[derive(Debug)]
pub struct ChangeSummary {
    /// Number of lines added
    pub lines_added: usize,
    /// Number of lines removed
    pub lines_removed: usize,
    /// Number of lines modified (paired additions and deletions)
    pub lines_modified: usize,
}

impl ChangeSummary {
    /// Calculate change summary from a text diff
    #[must_use]
    pub fn from_diff<'a>(diff: &TextDiff<'a, 'a, str>) -> Self {
        let mut lines_added = 0;
        let mut lines_removed = 0;

        for op in diff.ops() {
            for change in diff.iter_changes(op) {
                match change.tag() {
                    ChangeTag::Insert => lines_added += 1,
                    ChangeTag::Delete => lines_removed += 1,
                    ChangeTag::Equal => {}
                }
            }
        }

        // Calculate modified lines (pairs of adjacent delete/insert)
        // This is a simple heuristic
        let modifications = lines_added.min(lines_removed);
        let lines_modified = modifications;
        let lines_added = lines_added - modifications;
        let lines_removed = lines_removed - modifications;

        Self {
            lines_added,
            lines_removed,
            lines_modified,
        }
    }

    /// Create summary from two text contents
    #[must_use]
    pub fn from_texts(old: &str, new: &str) -> Self {
        let diff = TextDiff::from_lines(old, new);
        Self::from_diff(&diff)
    }
}

/// Preview of changes with limited lines
#[derive(Debug)]
pub struct ChangePreview {
    /// Lines in the preview
    pub lines: Vec<PreviewLine>,
    /// Whether the preview was truncated due to line limit
    pub truncated: bool,
}

/// A single line in a change preview
#[derive(Debug)]
pub struct PreviewLine {
    /// Type of change (add, remove, or context)
    pub tag: PreviewTag,
    /// Line content
    pub content: String,
}

/// Type of change for a preview line
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewTag {
    /// Line was added
    Add,
    /// Line was removed
    Remove,
    /// Line is unchanged context
    Context,
}

impl ChangePreview {
    /// Generate preview from text diff
    #[must_use]
    pub fn from_diff<'a>(diff: &TextDiff<'a, 'a, str>, max_lines: usize) -> Self {
        let mut lines = Vec::new();
        let mut total_lines = 0;

        for op in diff.ops() {
            if lines.len() >= max_lines {
                break;
            }

            for change in diff.iter_changes(op) {
                total_lines += 1;
                if lines.len() >= max_lines {
                    break;
                }

                let tag = match change.tag() {
                    ChangeTag::Insert => PreviewTag::Add,
                    ChangeTag::Delete => PreviewTag::Remove,
                    ChangeTag::Equal => PreviewTag::Context,
                };

                let content = change.value().trim_end_matches('\n').to_string();

                lines.push(PreviewLine { tag, content });
            }
        }

        let truncated = total_lines > max_lines;

        Self { lines, truncated }
    }

    /// Generate preview from two text contents
    #[must_use]
    pub fn from_texts(old: &str, new: &str, max_lines: usize) -> Self {
        let diff = TextDiff::from_lines(old, new);
        Self::from_diff(&diff, max_lines)
    }

    /// Get lines with change markers
    #[must_use]
    pub fn lines_with_markers(&self) -> Vec<String> {
        use crate::ui::icons::Icons;
        self.lines
            .iter()
            .map(|line| {
                let marker = match line.tag {
                    PreviewTag::Add => Icons::ACTION_ADD,
                    PreviewTag::Remove => Icons::ACTION_REMOVE,
                    PreviewTag::Context => " ",
                };
                format!("{} {}", marker, line.content)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for ChangeSummary

    #[test]
    fn test_change_summary_no_changes() {
        let old = "line1\nline2\nline3";
        let new = "line1\nline2\nline3";

        let summary = ChangeSummary::from_texts(old, new);

        assert_eq!(summary.lines_added, 0);
        assert_eq!(summary.lines_removed, 0);
        assert_eq!(summary.lines_modified, 0);
    }

    #[test]
    fn test_change_summary_only_additions() {
        // Use trailing newlines to avoid diff treating final line specially
        let old = "line1\nline2\n";
        let new = "line1\nline2\nline3\nline4\n";

        let summary = ChangeSummary::from_texts(old, new);

        assert_eq!(summary.lines_added, 2);
        assert_eq!(summary.lines_removed, 0);
        assert_eq!(summary.lines_modified, 0);
    }

    #[test]
    fn test_change_summary_only_deletions() {
        // Use trailing newlines to avoid diff treating final line specially
        let old = "line1\nline2\nline3\nline4\n";
        let new = "line1\nline2\n";

        let summary = ChangeSummary::from_texts(old, new);

        assert_eq!(summary.lines_added, 0);
        assert_eq!(summary.lines_removed, 2);
        assert_eq!(summary.lines_modified, 0);
    }

    #[test]
    fn test_change_summary_modifications() {
        // Equal number of additions and deletions are counted as modifications
        let old = "line1\nline2\nline3";
        let new = "line1\nchanged2\nchanged3";

        let summary = ChangeSummary::from_texts(old, new);

        // 2 deletions + 2 additions = 2 modifications
        assert_eq!(summary.lines_modified, 2);
        assert_eq!(summary.lines_added, 0);
        assert_eq!(summary.lines_removed, 0);
    }

    #[test]
    fn test_change_summary_mixed_changes() {
        // More additions than deletions
        let old = "line1\nline2\n";
        let new = "changed1\nline2\nline3\nline4\n";

        let summary = ChangeSummary::from_texts(old, new);

        // 1 deletion + 3 additions = 1 modification + 2 additions
        assert_eq!(summary.lines_modified, 1);
        assert_eq!(summary.lines_added, 2);
        assert_eq!(summary.lines_removed, 0);
    }

    #[test]
    fn test_change_summary_more_deletions_than_additions() {
        let old = "line1\nline2\nline3\nline4";
        let new = "changed1";

        let summary = ChangeSummary::from_texts(old, new);

        // 4 deletions + 1 addition = 1 modification + 3 deletions
        assert_eq!(summary.lines_modified, 1);
        assert_eq!(summary.lines_added, 0);
        assert_eq!(summary.lines_removed, 3);
    }

    #[test]
    fn test_change_summary_empty_to_content() {
        let old = "";
        let new = "line1\nline2\nline3";

        let summary = ChangeSummary::from_texts(old, new);

        assert_eq!(summary.lines_added, 3);
        assert_eq!(summary.lines_removed, 0);
        assert_eq!(summary.lines_modified, 0);
    }

    #[test]
    fn test_change_summary_content_to_empty() {
        let old = "line1\nline2\nline3";
        let new = "";

        let summary = ChangeSummary::from_texts(old, new);

        assert_eq!(summary.lines_added, 0);
        assert_eq!(summary.lines_removed, 3);
        assert_eq!(summary.lines_modified, 0);
    }

    // Tests for ChangePreview

    #[test]
    fn test_change_preview_no_truncation() {
        let old = "line1\nline2";
        let new = "line1\nchanged2";

        let preview = ChangePreview::from_texts(old, new, 10);

        assert!(!preview.truncated);
        assert_eq!(preview.lines.len(), 3); // 1 context + 1 delete + 1 add
    }

    #[test]
    fn test_change_preview_with_truncation() {
        let old = "line1\nline2\nline3\nline4\nline5";
        let new = "line1\nchanged2\nchanged3\nchanged4\nchanged5";

        let preview = ChangePreview::from_texts(old, new, 3);

        assert!(preview.truncated);
        assert_eq!(preview.lines.len(), 3); // Limited to max_lines
    }

    #[test]
    fn test_change_preview_empty_diff() {
        let old = "line1\nline2";
        let new = "line1\nline2";

        let preview = ChangePreview::from_texts(old, new, 10);

        assert!(!preview.truncated);
        assert_eq!(preview.lines.len(), 2); // All context lines
        assert!(preview.lines.iter().all(|l| l.tag == PreviewTag::Context));
    }

    #[test]
    fn test_change_preview_only_additions() {
        let old = "";
        let new = "line1\nline2";

        let preview = ChangePreview::from_texts(old, new, 10);

        assert!(!preview.truncated);
        assert_eq!(preview.lines.len(), 2);
        assert!(preview.lines.iter().all(|l| l.tag == PreviewTag::Add));
    }

    #[test]
    fn test_change_preview_only_deletions() {
        let old = "line1\nline2";
        let new = "";

        let preview = ChangePreview::from_texts(old, new, 10);

        assert!(!preview.truncated);
        assert_eq!(preview.lines.len(), 2);
        assert!(preview.lines.iter().all(|l| l.tag == PreviewTag::Remove));
    }

    #[test]
    fn test_change_preview_lines_with_markers() {
        let old = "line1\nline2\n";
        let new = "line1\nchanged2\n";

        let preview = ChangePreview::from_texts(old, new, 10);
        let lines = preview.lines_with_markers();

        assert_eq!(lines.len(), 3);
        // First line should be context (space marker)
        assert!(lines[0].starts_with(' '));
        assert!(lines[0].contains("line1"));
        // Second line should be removal (- marker)
        assert!(lines[1].starts_with('-'));
        assert!(lines[1].contains("line2"));
        // Third line should be addition (+ marker)
        assert!(lines[2].starts_with('+'));
        assert!(lines[2].contains("changed2"));
    }

    #[test]
    fn test_change_preview_content_trimming() {
        // Verify that newlines are trimmed from line content
        let old = "line1\n";
        let new = "line2\n";

        let preview = ChangePreview::from_texts(old, new, 10);

        // Check that content doesn't end with newline
        for line in &preview.lines {
            assert!(!line.content.ends_with('\n'));
        }
    }

    // Tests for PreviewTag

    #[test]
    fn test_preview_tag_equality() {
        assert_eq!(PreviewTag::Add, PreviewTag::Add);
        assert_eq!(PreviewTag::Remove, PreviewTag::Remove);
        assert_eq!(PreviewTag::Context, PreviewTag::Context);
        assert_ne!(PreviewTag::Add, PreviewTag::Remove);
        assert_ne!(PreviewTag::Add, PreviewTag::Context);
        assert_ne!(PreviewTag::Remove, PreviewTag::Context);
    }

    #[test]
    fn test_preview_tag_copy_clone() {
        let tag = PreviewTag::Add;
        let tag_copy = tag;
        let tag_clone = tag;

        assert_eq!(tag, tag_copy);
        assert_eq!(tag, tag_clone);
    }

    #[test]
    fn test_change_preview_max_lines_zero() {
        let old = "line1\nline2\nline3\n";
        let new = "changed1\nchanged2\nchanged3\n";

        let preview = ChangePreview::from_texts(old, new, 0);

        assert_eq!(preview.lines.len(), 0);
        // When max_lines is 0, no lines are collected and truncated stays false
        // because total_lines never gets incremented (loop breaks immediately)
        assert!(!preview.truncated);
    }

    #[test]
    fn test_change_preview_complex_diff() {
        let old = "line1\nline2\nline3\nline4\nline5";
        let new = "line1\nchanged2\nline3\nline5\nline6";

        let preview = ChangePreview::from_texts(old, new, 20);

        assert!(!preview.truncated);

        // Verify we have the expected mix of tags
        let has_add = preview.lines.iter().any(|l| l.tag == PreviewTag::Add);
        let has_remove = preview.lines.iter().any(|l| l.tag == PreviewTag::Remove);
        let has_context = preview.lines.iter().any(|l| l.tag == PreviewTag::Context);

        assert!(has_add);
        assert!(has_remove);
        assert!(has_context);
    }
}
