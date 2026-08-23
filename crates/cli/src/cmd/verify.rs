//! `guisu verify` — silent CI-friendly drift detector.
//!
//! Walks source → target state, then for each target entry asks
//! [`guisu_engine::verify::matches_dest`] whether the destination already
//! matches. Returns `Ok(false)` if any drift is found; the
//! [`Command::exit_code`](crate::command::Command::exit_code) override maps
//! that to process exit code 1.

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::AbsPath;
use guisu_engine::entry::TargetEntry;
use guisu_engine::state::{Metadata, TargetState};
use guisu_engine::verify::{MatchResult, matches_dest};
use guisu_template::TemplateContext;
use std::path::PathBuf;
use std::sync::Arc;

use crate::command::Command;
use crate::common::RuntimeContext;

/// Entry types accepted by '--include' / '--exclude'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lower")]
pub enum EntryTypeArg {
    /// Directory entries
    Dirs,
    /// Regular file entries
    Files,
    /// Symbolic link entries
    Symlinks,
    /// Dest paths declared in 'Metadata::remove'
    #[allow(clippy::doc_markdown)]
    Remove,
}

impl EntryTypeArg {
    /// Test whether this filter matches a target entry.
    ///
    /// `Remove` is handled separately by `check_remove_drift` (it iterates
    /// `Metadata::remove.paths` directly, since those paths never appear in
    /// `target_state.entries()`); here `Remove` returns `false` for every
    /// entry so it does not silently match unrelated entries.
    #[must_use]
    fn matches(self, entry: &TargetEntry) -> bool {
        match self {
            Self::Dirs => matches!(entry, TargetEntry::Directory { .. }),
            Self::Files => matches!(entry, TargetEntry::File { .. }),
            Self::Symlinks => matches!(entry, TargetEntry::Symlink { .. }),
            Self::Remove => false,
        }
    }
}

/// `guisu verify`
///
/// Compare the rendered source tree against the destination filesystem and
/// exit non-zero on drift. Silent on both success and failure — designed for
/// CI: `guisu verify && echo "no drift"`.
#[derive(Args)]
pub struct VerifyCommand {
    /// Optional paths to verify (default: all managed entries)
    pub paths: Vec<PathBuf>,

    /// Exclude entry types (comma-separated: dirs,files,symlinks,remove).
    /// Mutually exclusive with '--include'.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "TYPES",
        conflicts_with = "include"
    )]
    pub exclude: Vec<EntryTypeArg>,

    /// Include only these entry types. Mutually exclusive with '--exclude'.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "TYPES",
        default_value = "dirs,files,symlinks,remove"
    )]
    pub include: Vec<EntryTypeArg>,
}

impl Command for VerifyCommand {
    type Output = bool;

    fn execute(&self, context: &mut RuntimeContext) -> crate::error::Result<Self::Output> {
        let metadata =
            Metadata::load(context.source_dir()).context("Failed to load source metadata")?;

        let target_state = build_verify_target_state(context)?;

        let dest_root = context.dest_dir();
        let identities = context.load_identities()?;
        let fail_on_decrypt_error = context.config.age.fail_on_decrypt_error;

        // Resolve user-supplied positional paths (chezmoi convention:
        // `~/.bashrc` or `.bashrc`) to source-relative dotfiles paths once,
        // so they can be compared against each `entry.path()`.
        let wanted_paths = self.resolve_wanted_paths(context)?;

        let mut drifted = false;

        // Iteration 1: target state entries (files / dirs / symlinks).
        for entry in target_state.entries() {
            if !path_matches(&wanted_paths, entry, &context.config.general.root_entry) {
                continue;
            }
            if !filter_passes(&self.exclude, &self.include, entry) {
                continue;
            }

            let dest_path = dest_path_for_entry(dest_root, entry);
            let verdict = matches_dest(entry, &dest_path, &identities, fail_on_decrypt_error)?;

            if verdict != MatchResult::Match {
                drifted = true;
            }
        }

        // Iteration 2: `Metadata::remove` paths. These never appear in
        // `target_state.entries()` (they are dest-side directives, not
        // source files), so we check them separately. A path declared in
        // `Metadata::remove` that still exists on disk is drift.
        if filter_touches_remove(&self.exclude, &self.include) {
            for declared in metadata.remove.iter() {
                if !matches_wanted_remove_path(&wanted_paths, declared) {
                    continue;
                }
                if !remove_filter_passes(&self.exclude, &self.include) {
                    continue;
                }
                if remove_path_exists(dest_root, declared) {
                    drifted = true;
                }
            }
        }

        Ok(!drifted)
    }

    /// Drift detected → exit 1, all match → exit 0.
    ///
    /// Overrides the default `Command::exit_code` (which always returns 0)
    /// so that "found drift" becomes a non-zero exit code without abusing
    /// the `Result::Err` channel — which is reserved for actual engine
    /// failures.
    fn exit_code(&self, output: &Self::Output) -> i32 {
        i32::from(!*output)
    }
}

impl VerifyCommand {
    /// Resolve user-supplied positional paths to dest-relative paths via
    /// the chezmoi convention.
    ///
    /// Accepted forms:
    /// - `~/.bashrc` → expand `~` to home, strip `dest_root`
    /// - `.bashrc` / `foo/bar` → treat as dest-relative, used as-is
    ///
    /// Paths that escape `dest_root` after `~` expansion are rejected
    /// outright (they could be typos for unrelated absolute paths); we
    /// prefer a hard error over silently skipping them.
    fn resolve_wanted_paths(&self, context: &RuntimeContext) -> Result<Vec<std::path::PathBuf>> {
        use anyhow::Context;

        if self.paths.is_empty() {
            return Ok(Vec::new());
        }

        let dest_root = context.dest_dir();

        let mut resolved = Vec::with_capacity(self.paths.len());
        for raw in &self.paths {
            let expanded = crate::expand_tilde(raw.as_path());
            let rel = strip_dest_root(&expanded, dest_root)
                .with_context(|| format!("Invalid verify path: {}", raw.display()))?;
            resolved.push(rel);
        }
        Ok(resolved)
    }
}

/// Translate a target entry into its host-destination absolute path.
#[must_use]
fn dest_path_for_entry(dest_root: &AbsPath, entry: &TargetEntry) -> AbsPath {
    dest_root.join(entry.path())
}

/// True when `entry` is selected by `wanted_paths` (empty = all entries).
///
/// `entry.path()` is source-relative under the dotfiles root, so we add
/// `root_entry` before comparing against `wanted_paths` (which are
/// dest-relative).
#[must_use]
fn path_matches(
    wanted_paths: &[std::path::PathBuf],
    entry: &TargetEntry,
    root_entry: &std::path::Path,
) -> bool {
    if wanted_paths.is_empty() {
        return true;
    }
    let entry_dest_relative = root_entry.join(entry.path().as_path());
    wanted_paths
        .iter()
        .any(|p| p.as_path() == entry_dest_relative.as_path())
}

/// True when the entry passes the `--include` / `--exclude` filter.
///
/// `--exclude` wins when both are non-empty (clap normally prevents that
/// via `conflicts_with`, but the default `include` Vec is non-empty so we
/// can't rely on the absence of `exclude`).
#[must_use]
fn filter_passes(exclude: &[EntryTypeArg], include: &[EntryTypeArg], entry: &TargetEntry) -> bool {
    if exclude.is_empty() {
        include.iter().any(|t| t.matches(entry))
    } else {
        !exclude.iter().any(|t| t.matches(entry))
    }
}

/// True when either include or exclude mentions `Remove` — i.e. the user
/// asked us to check the `Metadata::remove` paths.
#[must_use]
fn filter_touches_remove(exclude: &[EntryTypeArg], include: &[EntryTypeArg]) -> bool {
    exclude.contains(&EntryTypeArg::Remove) || include.contains(&EntryTypeArg::Remove)
}

/// True when this declared remove path should be checked (given the user's
/// positional path filter). Declared paths live in dest-relative form
/// (e.g. `~/.cache/foo` or `.cache/foo`); `wanted_paths` are also
/// dest-relative (from `resolve_wanted_paths`).
#[must_use]
fn matches_wanted_remove_path(wanted_paths: &[std::path::PathBuf], declared: &str) -> bool {
    if wanted_paths.is_empty() {
        return true;
    }
    let normalized = declared.strip_prefix("~/").unwrap_or(declared);
    wanted_paths
        .iter()
        .any(|p| p.as_path() == std::path::Path::new(normalized))
}

/// True when the declared remove path passes the include/exclude filter.
/// For `Remove`, both `include=Remove` and `exclude=Remove` mean
/// "check the remove set"; the include/exclude distinction collapses
/// here because `Remove` only applies to one kind of artifact.
#[must_use]
fn remove_filter_passes(exclude: &[EntryTypeArg], include: &[EntryTypeArg]) -> bool {
    if exclude.is_empty() {
        include.contains(&EntryTypeArg::Remove)
    } else {
        exclude.contains(&EntryTypeArg::Remove)
    }
}

/// Does the dest path named by `declared` (e.g. `~/.cache/foo` or
/// `.cache/foo`) exist on disk?
#[must_use]
fn remove_path_exists(dest_root: &AbsPath, declared: &str) -> bool {
    let expanded = crate::expand_tilde(std::path::Path::new(declared));
    let dest_path = dest_root.as_path().join(&expanded);
    dest_path.exists()
}

/// Strip `dest_root` from an absolute path; pass relative paths through
/// unchanged. Returns an error if the absolute path is outside `dest_root`.
fn strip_dest_root(path: &std::path::Path, dest_root: &AbsPath) -> Result<std::path::PathBuf> {
    if !path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    path.strip_prefix(dest_root.as_path())
        .map(std::path::Path::to_path_buf)
        .map_err(|_| {
            anyhow::anyhow!(
                "path '{}' is outside the destination root '{}'",
                path.display(),
                dest_root.as_path().display()
            )
        })
}

/// Build the target state used by `verify`.
///
/// Mirrors `apply`'s state-build but is intentionally re-implemented here
/// (with helpers from `apply::pub(crate)`) to keep the verify command
/// independent of the apply module's many private helpers.
///
/// # Errors
///
/// Returns an error if:
/// - The source state cannot be read
/// - Template variables cannot be loaded
/// - The template context cannot be serialized
/// - Target state processing fails (e.g. decryption, template rendering)
fn build_verify_target_state(context: &RuntimeContext) -> Result<TargetState> {
    let config = &context.config;
    let source_dir = context.source_dir();
    let dest_dir = context.dest_dir();
    let identities_arc: Arc<Vec<guisu_crypto::Identity>> =
        Arc::new(context.load_identities()?.to_vec());

    let processor = crate::cmd::apply::setup_content_processor(source_dir, &identities_arc, config);

    let source_state =
        crate::cmd::apply::read_source_state(context.dotfiles_dir().to_owned(), source_dir, false)?;

    let all_variables = crate::cmd::apply::load_all_variables(source_dir, config)?;

    let working_tree = context.working_tree();
    let template_context = TemplateContext::with_guisu_context(
        context.dotfiles_dir().to_string(),
        working_tree.display().to_string(),
        dest_dir.to_string(),
        config.general.root_entry.display().to_string(),
        all_variables,
    );
    let template_context_value =
        serde_json::to_value(&template_context).context("Failed to serialize template context")?;

    TargetState::from_source(&source_state, &processor, &template_context_value)
        .map_err(|e| anyhow::Error::from(e).context("Failed to build verify target state"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Smoke test for `VerifyCommand::exit_code`: drift → exit 1,
    /// no drift → exit 0.
    #[test]
    fn exit_code_translates_drift() {
        let cmd = VerifyCommand {
            paths: vec![],
            exclude: vec![],
            include: vec![
                EntryTypeArg::Dirs,
                EntryTypeArg::Files,
                EntryTypeArg::Symlinks,
                EntryTypeArg::Remove,
            ],
        };
        assert_eq!(cmd.exit_code(&true), 0);
        assert_eq!(cmd.exit_code(&false), 1);
    }

    /// `EntryTypeArg::matches` correctly distinguishes the three
    /// `TargetEntry` variants and never matches `Remove` (which is
    /// handled by `check_remove_drift` instead of target iteration).
    #[test]
    fn entry_type_arg_matches_target_entry_variant() {
        let file = TargetEntry::File {
            path: guisu_core::path::RelPath::new("a".into()).expect("rel path"),
            content: b"x".to_vec(),
            content_hash: [0u8; 32],
            mode: None,
        };
        let dir = TargetEntry::Directory {
            path: guisu_core::path::RelPath::new("b".into()).expect("rel path"),
            mode: None,
        };
        let symlink = TargetEntry::Symlink {
            path: guisu_core::path::RelPath::new("c".into()).expect("rel path"),
            target: std::path::PathBuf::from("/d"),
        };

        assert!(EntryTypeArg::Files.matches(&file));
        assert!(!EntryTypeArg::Files.matches(&dir));
        assert!(!EntryTypeArg::Files.matches(&symlink));

        assert!(EntryTypeArg::Dirs.matches(&dir));
        assert!(!EntryTypeArg::Dirs.matches(&file));

        assert!(EntryTypeArg::Symlinks.matches(&symlink));
        assert!(!EntryTypeArg::Symlinks.matches(&dir));

        // Remove never matches a target entry — it has its own iteration.
        assert!(!EntryTypeArg::Remove.matches(&file));
        assert!(!EntryTypeArg::Remove.matches(&dir));
        assert!(!EntryTypeArg::Remove.matches(&symlink));
    }

    /// `strip_dest_root` peels off `dest_root` from absolute paths and
    /// passes relative paths through unchanged; rejects absolute paths
    /// that escape `dest_root`.
    #[test]
    fn strip_dest_root_strips_prefix() {
        let dest_root = AbsPath::new("/home/user".into()).expect("abs");

        // Relative path is returned as-is.
        let rel = strip_dest_root(Path::new(".bashrc"), &dest_root).expect("ok");
        assert_eq!(rel, PathBuf::from(".bashrc"));

        // Absolute path that is a strict descendant of dest_root.
        let abs = strip_dest_root(Path::new("/home/user/foo/bar"), &dest_root).expect("ok");
        assert_eq!(abs, PathBuf::from("foo/bar"));

        // Absolute path outside dest_root is rejected.
        let err = strip_dest_root(Path::new("/etc/passwd"), &dest_root).expect_err("must reject");
        assert!(err.to_string().contains("outside the destination root"));
    }

    /// `filter_passes` honours `--include` and `--exclude` semantics.
    #[test]
    fn filter_passes_include_and_exclude() {
        let file = TargetEntry::File {
            path: guisu_core::path::RelPath::new("a".into()).expect("rel path"),
            content: b"x".to_vec(),
            content_hash: [0u8; 32],
            mode: None,
        };
        let dir = TargetEntry::Directory {
            path: guisu_core::path::RelPath::new("b".into()).expect("rel path"),
            mode: None,
        };

        // include = files → files pass, directories don't.
        assert!(filter_passes(&[], &[EntryTypeArg::Files], &file));
        assert!(!filter_passes(&[], &[EntryTypeArg::Files], &dir));

        // exclude = files → files don't pass, directories do.
        assert!(!filter_passes(
            &[EntryTypeArg::Files],
            &[EntryTypeArg::Files],
            &file
        ));
        assert!(filter_passes(
            &[EntryTypeArg::Files],
            &[EntryTypeArg::Files],
            &dir
        ));
    }

    /// `filter_touches_remove` is true iff the user asked for the Remove
    /// iteration to run at all.
    #[test]
    fn filter_touches_remove_logic() {
        assert!(!filter_touches_remove(&[], &[EntryTypeArg::Files]));
        assert!(filter_touches_remove(&[], &[EntryTypeArg::Remove]));
        assert!(filter_touches_remove(
            &[EntryTypeArg::Remove],
            &[EntryTypeArg::Files]
        ));
    }

    /// `matches_wanted_remove_path` strips a leading `~/` so a user who
    /// asks for `~/.cache/foo` (resolved by `resolve_wanted_paths` to
    /// `.cache/foo`) matches the declared `~/.cache/foo`.
    #[test]
    fn matches_wanted_remove_path_strips_tilde() {
        let wanted = vec![PathBuf::from(".cache/foo")];
        assert!(matches_wanted_remove_path(&wanted, "~/.cache/foo"));

        // Bare (non-tilde) form also matches when identical.
        assert!(matches_wanted_remove_path(&wanted, ".cache/foo"));

        // Different paths don't match.
        let wanted = vec![PathBuf::from(".cache/foo")];
        assert!(!matches_wanted_remove_path(&wanted, ".cache/bar"));
    }
}
