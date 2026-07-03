//! Path display formatting for CLI output.
//!
//! Different parts of the CLI surface target paths in different contexts:
//!
//! - **Relative paths** (status, diff headers) show the bare target path,
//!   e.g. `.config/foo`. This matches chezmoi's convention and avoids the
//!   shell-only `~/` glyph, which is meaningless in any non-shell context.
//! - **Absolute paths** (status, with the `--absolute-paths` flag) join the
//!   destination root onto the target path, e.g. `/home/user/.config/foo`.
//! - **Source-relative paths** (`<root_entry>/<rel>`) are used in error
//!   messages where the user's mental model is "the dotfiles repo".
//!
//! This module is the single place to encode those rules. Commands and
//! helpers should call [`PathFormatter::display`] instead of formatting paths
//! inline.

use guisu_core::path::{AbsPath, RelPath};
use std::path::Path;

/// Display style for a target path.
#[derive(Debug, Clone, Copy)]
pub enum PathDisplayStyle<'a> {
    /// The bare target path: `foo/bar`. This is the default for both
    /// `status` and `diff` output — chezmoi-style.
    Relative,
    /// `foo/bar` for unified diff headers. Currently identical to
    /// [`PathDisplayStyle::Relative`]; the variant exists so call sites
    /// read as real diff headers and so a future asymmetry (e.g. rename
    /// markers) has a natural extension point.
    #[allow(dead_code)] // `side` reserved for future asymmetry.
    DiffHeader { side: DiffSide },
    /// `<dest_root>/<rel>` — the full destination path. Used by `status`
    /// when the user passes `--absolute-paths`.
    Absolute,
    /// `<root_entry>/<rel>` for error messages that point back into the
    /// dotfiles source tree.
    SourceRelative { root_entry: &'a Path },
}

/// Which side of a unified diff header to format.
///
/// Both sides currently render the same relative path; the variant exists
/// so the call site reads as a real diff header (`--- old` / `+++ new`).
#[allow(dead_code)] // Reserved for a future asymmetry (e.g. rename markers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    /// The "old" file. Used in `--- {path}` headers.
    Old,
    /// The "new" file. Used in `+++ {path}` headers.
    New,
}

/// Constructs format strings used by diff output.
///
/// A `PathFormatter` carries the destination root; the relative / absolute
/// distinction is computed on demand.
#[derive(Debug, Clone)]
pub struct PathFormatter {
    dest_root: AbsPath,
}

impl PathFormatter {
    /// Create a new formatter rooted at `dest_root`.
    pub fn new(dest_root: &AbsPath) -> Self {
        Self {
            dest_root: dest_root.clone(),
        }
    }

    /// Format `target_path` according to `style`.
    pub fn display(&self, style: PathDisplayStyle<'_>, target_path: &RelPath) -> String {
        match style {
            PathDisplayStyle::Relative | PathDisplayStyle::DiffHeader { .. } => {
                target_path.as_path().display().to_string()
            }
            PathDisplayStyle::Absolute => {
                let full = self.dest_root.join(target_path);
                full.as_path().display().to_string()
            }
            PathDisplayStyle::SourceRelative { root_entry } => {
                format!(
                    "{}/{}",
                    root_entry.display(),
                    target_path.as_path().display()
                )
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn formatter_under_tmp() -> PathFormatter {
        let root = AbsPath::new(std::path::PathBuf::from("/tmp")).expect("/tmp is absolute");
        PathFormatter::new(&root)
    }

    #[test]
    fn relative_returns_bare_target_path() {
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo/bar/baz")).unwrap();
        let out = formatter.display(PathDisplayStyle::Relative, &rel);
        assert_eq!(out, "foo/bar/baz");
    }

    #[test]
    fn relative_does_not_consult_dest_root() {
        // Even when the dest_root is `/tmp`, Relative should still emit
        // just the target path. (This guards against a regression where
        // Relative accidentally joins dest_root.)
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo")).unwrap();
        let out = formatter.display(PathDisplayStyle::Relative, &rel);
        assert_eq!(out, "foo");
    }

    #[test]
    fn diff_header_old_uses_relative_path() {
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo/bar/baz")).unwrap();
        let out = formatter.display(
            PathDisplayStyle::DiffHeader {
                side: DiffSide::Old,
            },
            &rel,
        );
        assert_eq!(out, "foo/bar/baz");
    }

    #[test]
    fn diff_header_new_uses_relative_path() {
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo/bar/baz")).unwrap();
        let out = formatter.display(
            PathDisplayStyle::DiffHeader {
                side: DiffSide::New,
            },
            &rel,
        );
        assert_eq!(out, "foo/bar/baz");
    }

    #[test]
    fn absolute_joins_dest_root() {
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo/bar/baz")).unwrap();
        let out = formatter.display(PathDisplayStyle::Absolute, &rel);
        assert_eq!(out, "/tmp/foo/bar/baz");
    }

    #[test]
    fn source_relative_prefixes_root_entry() {
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo/bar/baz")).unwrap();
        let out = formatter.display(
            PathDisplayStyle::SourceRelative {
                root_entry: Path::new("qux"),
            },
            &rel,
        );
        assert_eq!(out, "qux/foo/bar/baz");
    }

    #[test]
    fn root_entry_is_compile_time_supplied_to_source_relative() {
        // Guard against a regression where SourceRelative might ignore its
        // `root_entry` argument and hard-code something like "root".
        let formatter = formatter_under_tmp();
        let rel = RelPath::new(std::path::PathBuf::from("foo")).unwrap();
        let out = formatter.display(
            PathDisplayStyle::SourceRelative {
                root_entry: Path::new("custom-label"),
            },
            &rel,
        );
        assert_eq!(out, "custom-label/foo");
    }
}
