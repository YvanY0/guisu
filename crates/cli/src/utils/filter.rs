//! Path-filter matching for command-line file arguments.
//!
//! When the user passes a directory like `~/.config/zsh` to a subcommand
//! (apply, diff, status), it should match every entry **under** that directory.
//! Exact matching would silently skip every nested file — see the bug where
//! `guisu diff ~/.config/zsh` reported no changes while `guisu apply` rewrote
//! the same files.

use guisu_core::path::RelPath;

/// Returns `true` if `target` is `filter` itself, or a descendant of it
/// (segment-boundary aware — `.config/zshrc` is **not** a descendant of
/// `.config/zsh`).
#[must_use]
pub fn path_matches_filter(target: &RelPath, filter: &RelPath) -> bool {
    if target == filter {
        return true;
    }

    let filter_str = filter.as_path().to_str().unwrap_or("");
    let target_str = target.as_path().to_str().unwrap_or("");

    target_str.starts_with(filter_str) && target_str.as_bytes().get(filter_str.len()) == Some(&b'/')
}

/// Returns `true` if `target` matches any entry in `filters`.
#[must_use]
pub fn path_matches_any_filter(target: &RelPath, filters: &[RelPath]) -> bool {
    filters.iter().any(|p| path_matches_filter(target, p))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn rel(s: &str) -> RelPath {
        RelPath::new(std::path::PathBuf::from(s)).unwrap()
    }

    #[test]
    fn exact_match() {
        assert!(path_matches_filter(
            &rel(".config/zsh"),
            &rel(".config/zsh")
        ));
    }

    #[test]
    fn descendant_directory() {
        assert!(path_matches_filter(
            &rel(".config/zsh/conf.d"),
            &rel(".config/zsh"),
        ));
    }

    #[test]
    fn descendant_file() {
        // The bug: previously diff skipped these because it did exact match.
        assert!(path_matches_filter(
            &rel(".config/zsh/conf.d/00_utils.zsh"),
            &rel(".config/zsh"),
        ));
    }

    #[test]
    fn prefix_without_separator_does_not_match() {
        // `.config/zshrc` is not under `.config/zsh` — segment boundary matters.
        assert!(!path_matches_filter(
            &rel(".config/zshrc"),
            &rel(".config/zsh"),
        ));
    }

    #[test]
    fn sibling_does_not_match() {
        assert!(!path_matches_filter(
            &rel(".config/zsh-other/file"),
            &rel(".config/zsh"),
        ));
    }

    #[test]
    fn filter_does_not_match_target() {
        assert!(!path_matches_filter(&rel(".config"), &rel(".config/zsh")));
    }

    #[test]
    fn any_filter_matches_first() {
        let filters = vec![rel(".config/zsh"), rel(".config/nvim")];
        assert!(path_matches_any_filter(
            &rel(".config/zsh/conf.d/00_utils.zsh"),
            &filters,
        ));
    }

    #[test]
    fn any_filter_matches_second() {
        let filters = vec![rel(".config/zsh"), rel(".config/nvim")];
        assert!(path_matches_any_filter(
            &rel(".config/nvim/init.lua"),
            &filters,
        ));
    }

    #[test]
    fn any_filter_no_match() {
        let filters = vec![rel(".config/zsh"), rel(".config/nvim")];
        assert!(!path_matches_any_filter(
            &rel(".config/git/config"),
            &filters
        ));
    }
}
