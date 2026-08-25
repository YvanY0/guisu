//! Apply command implementation
//!
//! Apply the source state to the destination directory.

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::AbsPath;
use guisu_engine::entry::TargetEntry;
use guisu_engine::processor::ContentProcessor;
use guisu_engine::state::{SourceState, TargetState};
use guisu_engine::verify::{decrypt_inline_age_values, matches_dest};
use owo_colors::OwoColorize;
use rayon::prelude::*;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

use crate::command::Command;
use crate::common::RuntimeContext;
use crate::conflict::{ChangeType, ConflictHandler};
use crate::stats::ApplyStats;
use crate::ui::ConflictAction;
use crate::ui::progress;
use crate::utils::filter::path_matches_any_filter;
use crate::utils::path::SourceDirExt;

// File permission constants
const DEFAULT_SECURE_MODE: u32 = 0o600; // Default secure file mode (rw-------)

/// Type alias for batch entry state data (path, content, mode)
type BatchEntryData = (String, Vec<u8>, Option<u32>);

/// Apply the source state to the destination
#[derive(Debug, Clone, Args)]
pub struct ApplyCommand {
    /// Specific files to apply (all if not specified)
    #[arg(value_name = "FILES")]
    pub files: Vec<PathBuf>,

    /// Dry run - show what would be done
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Force overwrite of changed files
    #[arg(short, long)]
    pub force: bool,

    /// Interactive mode - prompt on conflicts
    #[arg(short, long)]
    pub interactive: bool,
}

/// Get the last written content hash for an entry from the database
///
/// Returns the content hash if the entry is a file and has state in the database.
/// Returns None for non-file entries or if no state exists.
fn get_last_written_hash(
    db: &guisu_engine::state::RedbPersistentState,
    entry: &TargetEntry,
) -> Option<[u8; 32]> {
    match entry {
        TargetEntry::File { .. } => {
            let path_str = entry.path().to_string();
            guisu_engine::get_entry_state(db, &path_str)
                .ok()
                .flatten()
                .map(|state| state.content_hash)
        }
        _ => None,
    }
}

/// Load and prepare all variables for template rendering
pub(crate) fn load_all_variables(
    source_dir: &std::path::Path,
    config: &guisu_config::Config,
) -> Result<indexmap::IndexMap<String, serde_json::Value>> {
    use guisu_config::variables;

    let guisu_dir = source_dir.guisu_dir();
    let platform_name = guisu_core::platform::CURRENT_PLATFORM.os;

    let guisu_variables = if guisu_dir.exists() {
        variables::load_variables(&guisu_dir, platform_name)
            .context("Failed to load variables from .guisu/variables/")?
    } else {
        indexmap::IndexMap::new()
    };

    // Merge variables: guisu variables + config variables (config overrides)
    let mut all_variables = guisu_variables;
    all_variables.extend(config.variables.clone());

    Ok(all_variables)
}

/// Apply the user-declared remove directives from `Metadata::remove`.
///
/// Each entry in `Metadata::remove.paths` is a dest-relative path (which may
/// start with `~` to mean the user's home). If the corresponding file or
/// directory exists in the destination, it is removed. Missing paths are
/// silently ignored — they are an idempotent directive, not an error.
///
/// Paths that escape the destination root (absolute paths, `..` segments
/// that resolve outside of it) are rejected. This guards against a
/// malicious or typo'd `state.toml` from deleting files outside the
/// dest tree.
fn apply_removed_paths(
    metadata: &guisu_engine::state::Metadata,
    dest_root: &AbsPath,
    system: &dyn guisu_engine::System,
    dry_run: bool,
    stats: &ApplyStats,
) -> Result<()> {
    for path_str in metadata.remove.iter() {
        let path = crate::expand_tilde(Path::new(path_str));

        // Reject absolute paths and reject empty paths (which would
        // resolve to the dest root itself and `rm -rf` it).
        if path.is_absolute() {
            anyhow::bail!(
                "remove path '{}' is absolute; must be dest-relative (or start with '~')",
                path.display()
            );
        }
        if path.as_os_str().is_empty() {
            anyhow::bail!("remove path is empty; refusing to remove the dest root");
        }

        let dest_path = dest_root.as_path().join(&path);

        // Canonicalize (if the path exists) and ensure the result is
        // still under `dest_root`. This catches `..` traversal that
        // `Path::join` doesn't strip.
        if let Ok(canonical) = dest_path.canonicalize()
            && !canonical.starts_with(dest_root.as_path())
        {
            anyhow::bail!(
                "remove path '{}' escapes the destination root",
                path.display()
            );
        }

        if !dest_path.exists() {
            debug!(path = %path.display(), "remove directive: path absent, skipping");
            continue;
        }

        // Use the System trait so DryRunSystem can record the operation
        // and the per-file policy (`is_dir` => `remove_dir`, else
        // `remove_file`) lives in one place.
        let abs_path = AbsPath::new(dest_path.clone())
            .with_context(|| format!("remove path is not absolute: {}", dest_path.display()))?;
        if dry_run {
            info!(
                "{} would remove: {}",
                "→".bright_cyan(),
                dest_path.display()
            );
            stats.inc_removed();
            continue;
        }

        system
            .remove(&abs_path)
            .with_context(|| format!("Failed to remove: {}", dest_path.display()))?;
        stats.inc_removed();
        info!("{} removed: {}", "✓".bright_green(), dest_path.display());
    }
    Ok(())
}

/// Setup content processor with decryptor and template renderer
pub(crate) fn setup_content_processor(
    source_dir: &std::path::Path,
    identities: &Arc<Vec<guisu_crypto::Identity>>,
    config: &guisu_config::Config,
) -> ContentProcessor<
    guisu_engine::adapters::crypto::CryptoDecryptorAdapter,
    guisu_engine::adapters::template::TemplateRendererAdapter,
> {
    use guisu_engine::adapters::crypto::CryptoDecryptorAdapter;
    use guisu_engine::adapters::template::TemplateRendererAdapter;

    let template_engine = crate::create_template_engine(source_dir, identities, config);

    let identity = identities
        .first()
        .map_or_else(guisu_crypto::Identity::generate, std::clone::Clone::clone);

    let decryptor = CryptoDecryptorAdapter::new(identity);
    let renderer = TemplateRendererAdapter::new(template_engine);
    ContentProcessor::new(decryptor, renderer)
}

/// Read source state with optional ignore filtering
pub(crate) fn read_source_state(
    source_abs: AbsPath,
    source_dir: &std::path::Path,
    has_named_target: bool,
) -> Result<SourceState> {
    let spinner = if has_named_target {
        None
    } else {
        Some(progress::create_spinner("Reading source state..."))
    };

    let matcher = guisu_config::IgnoreMatcher::from_ignores_toml(source_dir).ok();

    let source_state = if let Some(ref matcher) = matcher {
        SourceState::read_with_matcher(source_abs, Some(matcher))
            .context("Failed to read source state with ignore matcher")?
    } else {
        SourceState::read(source_abs).context("Failed to read source state")?
    };

    if let Some(spinner) = spinner {
        spinner.finish_and_clear();
    }

    Ok(source_state)
}

/// Build target state from source state (process templates, decrypt files)
#[allow(clippy::too_many_arguments)]
fn build_target_state(
    filtered_source_state: &SourceState,
    processor: &ContentProcessor<
        guisu_engine::adapters::crypto::CryptoDecryptorAdapter,
        guisu_engine::adapters::template::TemplateRendererAdapter,
    >,
    source_abs: &AbsPath,
    dest_abs: &AbsPath,
    working_tree: &Path,
    config: &guisu_config::Config,
    all_variables: indexmap::IndexMap<String, serde_json::Value>,
    has_named_target: bool,
) -> Result<TargetState> {
    let spinner = if has_named_target {
        None
    } else {
        Some(progress::create_spinner(
            "Processing templates and encrypted files...",
        ))
    };

    let template_context = guisu_template::TemplateContext::with_guisu_context(
        source_abs.to_string(),
        working_tree.display().to_string(),
        dest_abs.to_string(),
        config.general.root_entry.display().to_string(),
        all_variables,
    );

    let template_context_value =
        serde_json::to_value(&template_context).context("Failed to serialize template context")?;

    let target_state =
        TargetState::from_source(filtered_source_state, processor, &template_context_value)?;

    if let Some(spinner) = spinner {
        spinner.finish_and_clear();
    }

    Ok(target_state)
}

/// Filter entries to apply based on file paths, ignore patterns, and create-once status
fn filter_entries_to_apply<'a>(
    target_state: &'a TargetState,
    filter_paths: Option<&Vec<guisu_core::path::RelPath>>,
    ignore_matcher: &guisu_config::IgnoreMatcher,
    metadata: &guisu_engine::state::Metadata,
    dest_abs: &AbsPath,
) -> Vec<&'a TargetEntry> {
    let mut entries: Vec<&TargetEntry> = target_state
        .entries()
        .filter(|entry| {
            let target_path = entry.path();

            // Filter by files or directories
            if let Some(filter) = filter_paths
                && !path_matches_any_filter(target_path, filter)
            {
                return false;
            }

            if ignore_matcher.is_ignored(entry.path().as_path(), None) {
                debug!(path = %target_path, "Skipping ignored file");
                return false;
            }

            if let Some(path_str) = target_path.as_path().to_str()
                && metadata.is_create_once(path_str)
            {
                let dest_path = dest_abs.join(entry.path());
                if dest_path.as_path().exists() {
                    debug!(path = %target_path, "Skipping create-once file that already exists");
                    return false;
                }
            }

            true
        })
        .collect();

    entries.sort_by(|a, b| a.path().as_path().cmp(b.path().as_path()));
    entries
}
fn display_drift_warnings(drift_warnings: &[String]) {
    if !drift_warnings.is_empty() {
        println!("\n{}", "Configuration Drift Detected".yellow().bold());
        println!(
            "{}",
            "The following files have been modified both locally and in the source:".yellow()
        );
        for warning in drift_warnings {
            println!("  {} {}", "•".yellow(), warning.bright_white());
        }
        println!();
        println!(
            "{}",
            "These local changes will be overwritten during apply.".yellow()
        );
        println!(
            "{}",
            "Consider backing up modified files or using interactive mode (-i) for control."
                .dimmed()
        );
        println!();
    }
}

/// Handle dry run mode for a single entry
fn handle_dry_run_entry(
    entry: &TargetEntry,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    stats: &ApplyStats,
    show_icons: bool,
    fail_on_decrypt_error: bool,
) -> Result<bool> {
    let needs_update = entry_needs_update(entry, dest_path, identities, fail_on_decrypt_error)?;
    if !needs_update {
        debug!(path = %entry.path(), "File is already up to date, skipping");
        return Ok(false);
    }

    debug!(path = %entry.path(), "Would apply entry");
    print_dry_run_entry(entry, show_icons);
    stats.record_dry_run(entry);
    Ok(true)
}

/// Did the destination fall out of sync with the target entry?
///
/// Returns `true` if applying this entry would write to the destination.
/// `MatchResult` collapses into a single "needs write" predicate here:
/// both `Missing` and `Modified` (and any future "stale" variant) count
/// as drift. Adding a new `MatchResult` variant forces a decision in
/// the `match` below — the compiler won't let a new variant be silently
/// bucketed into the wrong category.
fn entry_needs_update(
    entry: &TargetEntry,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<bool> {
    use guisu_engine::verify::MatchResult;
    Ok(matches!(
        matches_dest(entry, dest_path, identities, fail_on_decrypt_error)?,
        MatchResult::Missing | MatchResult::Modified
    ))
}

/// Handle interactive conflict resolution
#[allow(clippy::too_many_arguments)]
fn handle_interactive_conflict(
    db: &guisu_engine::state::RedbPersistentState,
    entry: &TargetEntry,
    dest_abs: &AbsPath,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    handler: &mut ConflictHandler,
    fail_on_decrypt_error: bool,
    force: bool,
) -> Result<bool> {
    // Force mode: skip conflict detection and apply directly
    if force {
        return entry_needs_update(entry, dest_path, identities, fail_on_decrypt_error);
    }

    let last_written_hash = get_last_written_hash(db, entry);
    let change_type = ConflictHandler::detect_change_type(
        entry,
        dest_abs,
        last_written_hash.as_ref().map(|arr| &arr[..]),
        identities,
    )?;

    if let Some(change_type) = change_type {
        match handler.prompt_action(entry, dest_abs, None, change_type)? {
            ConflictAction::Override => Ok(true),
            ConflictAction::Skip => {
                debug!(path = %entry.path(), "Skipping due to user choice");
                println!("  {} {}", "⏭".yellow(), entry.path().bright_white());
                Ok(false)
            }
            ConflictAction::Quit => {
                info!("Apply operation cancelled by user");
                Ok(false)
            }
            _ => unreachable!("Unexpected action returned from prompt_action"),
        }
    } else {
        Ok(entry_needs_update(
            entry,
            dest_path,
            identities,
            fail_on_decrypt_error,
        )?)
    }
}

/// Handle non-interactive conflict resolution with user confirmation
fn handle_non_interactive_conflict(
    db: &guisu_engine::state::RedbPersistentState,
    entry: &TargetEntry,
    dest_abs: &AbsPath,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
    force: bool,
) -> Result<bool> {
    // Force mode: skip all conflict detection and apply directly
    if force {
        return entry_needs_update(entry, dest_path, identities, fail_on_decrypt_error);
    }

    if !entry_needs_update(entry, dest_path, identities, fail_on_decrypt_error)? {
        return Ok(false);
    }

    let last_written_hash = get_last_written_hash(db, entry);
    let change_type = ConflictHandler::detect_change_type(
        entry,
        dest_abs,
        last_written_hash.as_ref().map(|arr| &arr[..]),
        identities,
    )?;

    if let Some(change_type) = change_type {
        match change_type {
            ChangeType::LocalModification | ChangeType::TrueConflict => {
                use dialoguer::{Confirm, theme::ColorfulTheme};
                let change_label = match change_type {
                    ChangeType::LocalModification => "Local modification",
                    ChangeType::TrueConflict => "Conflict (both local and source modified)",
                    ChangeType::SourceUpdate => {
                        unreachable!("SourceUpdate filtered by outer match")
                    }
                };

                println!("\n{} {}", "⚠".yellow(), change_label.yellow().bold());
                println!("  File: {}", entry.path().bright_white());
                println!("  {}", "This file has been modified locally.".yellow());
                println!(
                    "  {}",
                    "Applying will overwrite your local changes.".yellow()
                );

                let theme = ColorfulTheme::default();
                Confirm::with_theme(&theme)
                    .with_prompt("Continue and overwrite local changes?")
                    .default(false)
                    .interact()
                    .context("Failed to read user input")
            }
            ChangeType::SourceUpdate => Ok(true),
        }
    } else {
        Ok(true)
    }
}

/// Apply entry and handle errors, returning entry data for batch save
///
/// Returns `Some((path, content, mode))` if the entry was successfully applied and needs state saved
fn apply_entry_with_error_handling(
    entry: &TargetEntry,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    stats: &ApplyStats,
    show_icons: bool,
    fail_on_decrypt_error: bool,
) -> Option<BatchEntryData> {
    match apply_target_entry(entry, dest_path, identities, fail_on_decrypt_error) {
        Ok(()) => {
            debug!(path = %entry.path(), "Applied entry successfully");
            print_success_entry(entry, show_icons);
            stats.record_success(entry);

            // Return entry data for batch save (files only — Modify entries
            // have been removed; removal is driven by Metadata).
            match entry {
                TargetEntry::File { content, mode, .. } => {
                    // Save decrypted content to match what was written to disk
                    let final_content = match decrypt_inline_age_values(
                        content,
                        identities,
                        fail_on_decrypt_error,
                    ) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            warn!(path = %entry.path(), error = %e, "Failed to decrypt inline age values for state saving");
                            // Fall back to original content to avoid data loss
                            content.clone()
                        }
                    };
                    Some((entry.path().to_string(), final_content, *mode))
                }
                _ => None,
            }
        }
        Err(e) => {
            warn!(path = %entry.path(), error = %e, "Failed to apply entry");
            print_error_entry(entry, &e, show_icons);
            stats.record_failure();
            None
        }
    }
}

/// Process entries sequentially (for interactive mode or dry run)
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn process_entries_sequential(
    db: &mut guisu_engine::state::RedbPersistentState,
    entries: Vec<&TargetEntry>,
    dest_abs: &AbsPath,
    identities: &[guisu_crypto::Identity],
    conflict_handler: &mut Option<ConflictHandler>,
    stats: &ApplyStats,
    show_icons: bool,
    dry_run: bool,
    fail_on_decrypt_error: bool,
    force: bool,
) -> Result<()> {
    // Pre-allocate capacity for worst case (all entries applied successfully)
    let mut batch_entries = Vec::with_capacity(entries.len());

    for entry in entries {
        let dest_path = dest_abs.join(entry.path());

        if dry_run {
            handle_dry_run_entry(
                entry,
                &dest_path,
                identities,
                stats,
                show_icons,
                fail_on_decrypt_error,
            )?;
        } else {
            let should_apply = if let Some(handler) = conflict_handler {
                handle_interactive_conflict(
                    db,
                    entry,
                    dest_abs,
                    &dest_path,
                    identities,
                    handler,
                    fail_on_decrypt_error,
                    force,
                )?
            } else {
                handle_non_interactive_conflict(
                    db,
                    entry,
                    dest_abs,
                    &dest_path,
                    identities,
                    fail_on_decrypt_error,
                    force,
                )?
            };

            if should_apply
                && let Some(state_data) = apply_entry_with_error_handling(
                    entry,
                    &dest_path,
                    identities,
                    stats,
                    show_icons,
                    fail_on_decrypt_error,
                )
            {
                batch_entries.push(state_data);
            }
        }
    }

    // Batch save all successful entries to database
    if !batch_entries.is_empty() {
        guisu_engine::save_entry_states_batch(db, &batch_entries).map_err(|e| {
            warn!(error = %e, "Failed to save batch state to database");
            e
        })?;
    }

    Ok(())
}

impl Command for ApplyCommand {
    type Output = ApplyStats;
    #[allow(clippy::too_many_lines)]
    fn execute(&self, context: &mut RuntimeContext) -> crate::error::Result<ApplyStats> {
        // Extract paths, config, and database from context.
        // `config` is read by reference; every `config` use below happens
        // before `context.database_mut()`, so the immutable borrow is
        // released by the time we need exclusive access to the database.
        // `database` is an `Arc<RedbPersistentState>` clone, kept under
        // that name because `detect_config_drift(&database, ...)` is a
        // gate pattern pinned by `test_named_target_gates_...`.
        let source_abs = context.dotfiles_dir();
        let dest_abs = context.dest_dir().clone();
        let source_dir = context.source_dir();
        let config = &context.config;
        let database = std::sync::Arc::clone(context.database());

        // Load age identities for decryption
        let spinner = progress::create_spinner("Loading identities...");
        let identities = Arc::new(config.age_identities().unwrap_or_default());
        spinner.finish_and_clear();

        // Detect if output is to a terminal for icon auto mode
        let is_tty = std::io::stdout().is_terminal();
        let show_icons = config.ui.icons.should_show_icons(is_tty);

        // Get decryption failure handling configuration
        let fail_on_decrypt_error = config.age.fail_on_decrypt_error;

        // Load variables and create processor
        let all_variables = load_all_variables(source_dir, config)?;
        let processor = setup_content_processor(source_dir, &identities, config);

        // Load metadata for create-once tracking
        let metadata =
            guisu_engine::state::Metadata::load(source_dir).context("Failed to load metadata")?;

        // Stats accumulator — declared early so `apply_removed_paths`
        // (which runs before source/target state is built) can record
        // any pending `Metadata::remove` directives into the same
        // counters that the post-apply summary reads.
        let stats = Arc::new(ApplyStats::new());

        // Apply remove directives from .guisu/state.toml.
        apply_removed_paths(
            &metadata,
            &dest_abs,
            &guisu_engine::RealSystem,
            self.dry_run,
            &stats,
        )?;

        // Create ignore matcher from .guisu/ignores.toml
        let ignore_matcher = guisu_config::IgnoreMatcher::from_ignores_toml(source_dir)
            .context("Failed to load ignore patterns from .guisu/ignores.toml")?;

        // `has_named_target` is true when the user passed exactly one positional
        // path. Drives verbose-mode gates: spinner + drift-detection are
        // skipped because a single named target doesn't benefit from
        // progress bars or per-file conflict hints. The two "No files"
        // messages below are intentionally UNCONDITIONAL — silently
        // succeeding on a typo'd path is worse than a noisy info line.
        let has_named_target = !self.files.is_empty() && self.files.len() == 1;

        // Build filter paths if specific paths requested
        let filter_paths = if self.files.is_empty() {
            None
        } else {
            Some(crate::build_filter_paths(&self.files, &dest_abs)?)
        };

        // Read source state
        let source_state = read_source_state(source_abs.to_owned(), source_dir, has_named_target)?;

        if source_state.is_empty() {
            info!("No files to apply");
            return Ok(ApplyStats::new());
        }

        // Build target state
        let working_tree = context.working_tree();
        let target_state = build_target_state(
            &source_state,
            &processor,
            source_abs,
            &dest_abs,
            &working_tree,
            config,
            all_variables,
            has_named_target,
        )?;

        // Filter entries to apply
        let entries_to_apply = filter_entries_to_apply(
            &target_state,
            filter_paths.as_ref(),
            &ignore_matcher,
            &metadata,
            &dest_abs,
        );

        if entries_to_apply.is_empty() {
            info!("No matching files to apply");
            return Ok(ApplyStats::new());
        }

        // Check for configuration drift (files modified by user AND source updated)
        if !self.dry_run && !has_named_target {
            let drift_warnings = detect_config_drift(&database, &entries_to_apply, &dest_abs);
            display_drift_warnings(&drift_warnings);
        }

        // Create conflict handler for interactive mode
        let mut conflict_handler = if self.interactive && !self.dry_run {
            Some(ConflictHandler::new(
                config.clone(),
                identities.clone(),
            ))
        } else {
            None
        };

        // Sequential processing. `filter_entries_to_apply` already sorts
        // `entries_to_apply` by path, so output order is deterministic across
        // runs. Parallel execution was removed because rayon `par_iter()`
        // produces non-deterministic print order — see "apply ordering" in
        // CHANGELOG if the regression needs revisiting.
        process_entries_sequential(
            context.database_mut(),
            entries_to_apply,
            &dest_abs,
            &identities,
            &mut conflict_handler,
            &stats,
            show_icons,
            self.dry_run,
            fail_on_decrypt_error,
            self.force,
        )?;

        // Return stats instead of printing here
        // The caller (lib.rs) will print the summary after hooks complete

        let failed_count = stats.failed();
        if failed_count > 0 {
            return Err(anyhow::anyhow!("Failed to apply {failed_count} entries").into());
        }

        Ok(stats.snapshot())
    }
}

/// Apply a single target entry to the destination
#[allow(clippy::too_many_lines)]
fn apply_target_entry(
    entry: &TargetEntry,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<()> {
    match entry {
        TargetEntry::File { content, mode, .. } => {
            // Ensure parent directory exists
            if let Some(parent) = dest_path.as_path().parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create parent directory: {}", parent.display())
                })?;
            }

            // Check if file exists and save its permissions
            #[cfg(unix)]
            let existing_mode = if dest_path.as_path().exists() {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(dest_path.as_path())
                    .ok()
                    .map(|m| m.permissions().mode())
            } else {
                None
            };

            // Decrypt inline age values before writing to destination
            // This allows source files to contain age:... encrypted values
            // but destination files get plaintext (for applications to use)
            let final_content =
                decrypt_inline_age_values(content, identities, fail_on_decrypt_error)?;

            // Write file with atomic permission setting to avoid TOCTOU race condition
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

                // Determine permissions to use
                // - If source has mode, use it (source is authoritative)
                // - Otherwise, preserve existing permissions if file existed
                // - Default to 0o600 (owner read/write only) for security
                let mode_to_use = mode.or(existing_mode).unwrap_or(DEFAULT_SECURE_MODE);

                // Create file with permissions atomically (no TOCTOU window)
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode_to_use)
                    .open(dest_path.as_path())
                    .with_context(|| format!("Failed to create file: {dest_path:?}"))?;

                file.write_all(&final_content)
                    .with_context(|| format!("Failed to write file content: {dest_path:?}"))?;

                // OpenOptions::mode() is only honored when the file is newly
                // created. For files that already existed (the common case
                // during `apply` after a small content edit), the kernel
                // preserves the previous mode. Chmod explicitly so source's
                // mode is always authoritative, as documented.
                let current_mode = file.metadata().ok().map(|m| m.permissions().mode());
                if current_mode != Some(mode_to_use) {
                    let permissions = std::fs::Permissions::from_mode(mode_to_use);
                    fs::set_permissions(dest_path.as_path(), permissions)
                        .with_context(|| format!("Failed to set permissions: {dest_path:?}"))?;
                }
            }

            #[cfg(not(unix))]
            {
                // On non-Unix systems, use standard write (no mode support)
                fs::write(dest_path.as_path(), &final_content)
                    .with_context(|| format!("Failed to write file: {:?}", dest_path))?;
            }

            Ok(())
        }

        TargetEntry::Directory { mode, .. } => {
            // Create directory
            fs::create_dir_all(dest_path.as_path())
                .with_context(|| format!("Failed to create directory: {dest_path:?}"))?;

            // Set permissions
            #[cfg(unix)]
            if let Some(mode) = mode {
                use std::os::unix::fs::PermissionsExt;
                let permissions = fs::Permissions::from_mode(*mode);
                fs::set_permissions(dest_path.as_path(), permissions)
                    .with_context(|| format!("Failed to set permissions: {dest_path:?}"))?;
            }

            Ok(())
        }

        TargetEntry::Symlink { target, .. } => {
            // Ensure parent directory exists
            if let Some(parent) = dest_path.as_path().parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create parent directory: {}", parent.display())
                })?;
            }

            // Remove existing symlink/file if it exists
            if dest_path.as_path().exists() || dest_path.as_path().is_symlink() {
                if dest_path.as_path().is_dir() && !dest_path.as_path().is_symlink() {
                    fs::remove_dir_all(dest_path.as_path()).with_context(|| {
                        format!("Failed to remove existing directory: {dest_path:?}")
                    })?;
                } else {
                    fs::remove_file(dest_path.as_path()).with_context(|| {
                        format!("Failed to remove existing file/symlink: {dest_path:?}")
                    })?;
                }
            }

            // Create symlink
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                symlink(target, dest_path.as_path())
                    .with_context(|| format!("Failed to create symlink: {dest_path:?}"))?;
            }

            #[cfg(windows)]
            {
                use std::os::windows::fs::symlink_file;
                symlink_file(target, dest_path.as_path())
                    .with_context(|| format!("Failed to create symlink: {:?}", dest_path))?;
            }

            Ok(())
        }
    }
}
impl ApplyStats {
    fn record_success(&self, entry: &TargetEntry) {
        match entry {
            TargetEntry::File { .. } => self.inc_files(),
            TargetEntry::Directory { .. } => self.inc_directories(),
            TargetEntry::Symlink { .. } => self.inc_symlinks(),
        }
    }

    fn record_failure(&self) {
        self.inc_failed();
    }

    fn record_dry_run(&self, entry: &TargetEntry) {
        // Same as success for counting purposes
        self.record_success(entry);
    }
}

/// Print a dry-run entry
fn print_dry_run_entry(entry: &TargetEntry, use_nerd_fonts: bool) {
    use lscolors::{LsColors, Style};
    use std::sync::atomic::{AtomicBool, Ordering};

    // Print blank line before first file to separate from INFO message
    static FIRST_PRINT: AtomicBool = AtomicBool::new(true);
    if FIRST_PRINT.swap(false, Ordering::Relaxed) {
        println!();
    }

    let lscolors = LsColors::from_env().unwrap_or_default();
    let path = entry.path();
    let display_path = format!("~/{path}");

    // Get file icon
    let (is_directory, is_symlink) = match entry {
        TargetEntry::File { .. } => (false, false),
        TargetEntry::Directory { .. } => (true, false),
        TargetEntry::Symlink { .. } => (false, true),
    };

    let icon_info = crate::ui::icons::FileIconInfo {
        path: display_path.as_str(),
        is_directory,
        is_symlink,
    };
    let icon = crate::ui::icons::icon_for_file(&icon_info, use_nerd_fonts);

    // Get color style
    let file_style = lscolors
        .style_for_path(&display_path)
        .map(Style::to_nu_ansi_term_style)
        .unwrap_or_default();

    let styled_icon = file_style.paint(icon);
    let styled_path = file_style.paint(&display_path);

    println!("  {styled_icon} {styled_path}");
}

/// Print a successful entry
fn print_success_entry(entry: &TargetEntry, use_nerd_fonts: bool) {
    use lscolors::{LsColors, Style};

    let lscolors = LsColors::from_env().unwrap_or_default();
    let path = entry.path();
    let display_path = format!("~/{path}");

    // Get file icon
    let (is_directory, is_symlink) = match entry {
        TargetEntry::File { .. } => (false, false),
        TargetEntry::Directory { .. } => (true, false),
        TargetEntry::Symlink { .. } => (false, true),
    };

    let icon_info = crate::ui::icons::FileIconInfo {
        path: display_path.as_str(),
        is_directory,
        is_symlink,
    };
    let icon = crate::ui::icons::icon_for_file(&icon_info, use_nerd_fonts);

    // Get color style
    let file_style = lscolors
        .style_for_path(&display_path)
        .map(Style::to_nu_ansi_term_style)
        .unwrap_or_default();

    let styled_icon = file_style.paint(icon);
    let styled_path = file_style.paint(&display_path);

    println!("  {} {} {}", "✓".bright_green(), styled_icon, styled_path);
}

/// Print an error entry
fn print_error_entry(entry: &TargetEntry, error: &anyhow::Error, use_nerd_fonts: bool) {
    use lscolors::{LsColors, Style};

    let lscolors = LsColors::from_env().unwrap_or_default();
    let path = entry.path();
    let display_path = format!("~/{path}");

    // Get file icon
    let (is_directory, is_symlink) = match entry {
        TargetEntry::File { .. } => (false, false),
        TargetEntry::Directory { .. } => (true, false),
        TargetEntry::Symlink { .. } => (false, true),
    };

    let icon_info = crate::ui::icons::FileIconInfo {
        path: display_path.as_str(),
        is_directory,
        is_symlink,
    };
    let icon = crate::ui::icons::icon_for_file(&icon_info, use_nerd_fonts);

    // Get color style
    let file_style = lscolors
        .style_for_path(&display_path)
        .map(Style::to_nu_ansi_term_style)
        .unwrap_or_default();

    let styled_icon = file_style.paint(icon);
    let styled_path = file_style.paint(&display_path);

    println!(
        "  {} {} {} - {}",
        "✗".bright_red(),
        styled_icon,
        styled_path,
        error.to_string().red()
    );
}

/// Detect configuration drift for files
///
/// Returns a list of file paths where:
/// 1. The user has modified the file locally (actual != `last_written`)
/// 2. The source has also been updated (target != `last_written`)
///
/// This indicates potential conflict where both local and source changes exist.
fn detect_config_drift(
    db: &guisu_engine::state::RedbPersistentState,
    entries: &[&TargetEntry],
    dest_abs: &AbsPath,
) -> Vec<String> {
    // Parallel processing of drift detection (3x blake3 hash per file = CPU-intensive)
    entries
        .par_iter()
        .filter_map(|entry| {
            // Only check files
            let TargetEntry::File {
                content: target_content,
                content_hash: target_hash,
                ..
            } = entry
            else {
                return None;
            };

            let dest_path = dest_abs.join(entry.path());

            // Skip if destination doesn't exist
            if !dest_path.as_path().exists() {
                return None;
            }

            let path_str = entry.path().as_path().to_str()?;
            let last_written_state = match guisu_engine::get_entry_state(db, path_str) {
                Ok(Some(state)) => state,
                Ok(None) => return None,
                Err(e) => {
                    warn!(path = %entry.path(), error = %e, "Failed to read entry state");
                    return None;
                }
            };

            let actual_content = match fs::read(dest_path.as_path()) {
                Ok(content) => content,
                Err(e) => {
                    warn!(path = %path_str, error = %e, "Failed to read destination file");
                    return None;
                }
            };

            let actual_hash = guisu_engine::hash_content(&actual_content);

            // Check for drift:
            // 1. actual != last_written (user modified)
            // 2. target != last_written (source updated)
            // 3. target != actual (they're different)
            //
            // Use constant-time comparison for hashes to prevent timing side-channel attacks
            let user_modified = !bool::from(actual_hash.ct_eq(&last_written_state.content_hash));
            let source_updated = !bool::from(target_hash.ct_eq(&last_written_state.content_hash));
            let contents_differ = target_content != &actual_content;

            if user_modified && source_updated && contents_differ {
                Some(path_str.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use guisu_core::path::AbsPath;
    use guisu_engine::entry::TargetEntry;
    use guisu_engine::hash_content;
    use tempfile::TempDir;

    // Tests for decrypt_inline_age_values

    #[test]
    fn test_decrypt_inline_age_values_no_age_prefix() {
        let content = b"password: my-secret";
        let identities = vec![];

        let result = decrypt_inline_age_values(content, &identities, true).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn test_decrypt_inline_age_values_empty_identities() {
        let content = b"password: age:encrypted-value";
        let identities = vec![];

        let result = decrypt_inline_age_values(content, &identities, true).unwrap();
        // Should return original content when no identities
        assert_eq!(result, content);
    }

    #[test]
    fn test_decrypt_inline_age_values_binary_content() {
        // Binary content (invalid UTF-8)
        let content = b"\xFF\xFE\xFD\xFC";
        let identities = vec![guisu_crypto::Identity::generate()];

        let result = decrypt_inline_age_values(content, &identities, true).unwrap();
        // Should return original binary content as-is
        assert_eq!(result, content);
    }

    #[test]
    fn test_decrypt_inline_age_values_empty_content() {
        let content = b"";
        let identities = vec![];

        let result = decrypt_inline_age_values(content, &identities, true).unwrap();
        assert_eq!(result, b"");
    }

    #[test]
    fn test_decrypt_inline_age_values_no_encrypted_values() {
        let content = b"username: john\npassword: plain-text";
        let identities = vec![guisu_crypto::Identity::generate()];

        let result = decrypt_inline_age_values(content, &identities, true).unwrap();
        // Should return original content when no age: prefix found
        assert_eq!(result, content);
    }

    // Tests for ApplyCommand structure

    #[test]
    fn test_apply_command_default_fields() {
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: false,
            force: false,
            interactive: false,
        };

        assert!(cmd.files.is_empty());
        assert!(!cmd.dry_run);
        assert!(!cmd.force);
        assert!(!cmd.interactive);
    }

    #[test]
    fn test_apply_command_with_files() {
        let cmd = ApplyCommand {
            files: vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")],
            dry_run: false,
            force: false,
            interactive: false,
        };

        assert_eq!(cmd.files.len(), 2);
        assert_eq!(cmd.files[0], PathBuf::from("file1.txt"));
    }

    #[test]
    fn test_apply_command_dry_run() {
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: true,
            force: false,
            interactive: false,
        };

        assert!(cmd.dry_run);
    }

    #[test]
    fn test_apply_command_force() {
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: false,
            force: true,
            interactive: false,
        };

        assert!(cmd.force);
    }

    #[test]
    fn test_apply_command_interactive() {
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: false,
            force: false,
            interactive: true,
        };

        assert!(cmd.interactive);
    }

    #[test]
    fn test_apply_command_clone() {
        let cmd = ApplyCommand {
            files: vec![PathBuf::from("test.txt")],
            dry_run: true,
            force: false,
            interactive: false,
        };

        let cloned = cmd.clone();
        assert_eq!(cloned.files, cmd.files);
        assert_eq!(cloned.dry_run, cmd.dry_run);
        assert_eq!(cloned.force, cmd.force);
        assert_eq!(cloned.interactive, cmd.interactive);
    }

    #[test]
    fn test_apply_target_entry_chmods_existing_dest_file() {
        // Regression test: when source has a different mode than the
        // existing destination file, `apply` must chmod the destination
        // to match. Previously, `OpenOptions::mode()` was a no-op for
        // already-existing files, so a `0o600` dest would silently stay
        // `0o600` even when source was `0o644`.
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon =
            std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp dir");
        let dest_dir = AbsPath::new(temp_canon).expect("Failed to create AbsPath");
        let rel = guisu_core::path::RelPath::new("perm.txt".into()).expect("Invalid rel path");
        let dest_path = dest_dir.join(&rel);

        // Pre-create dest file with 0o600.
        std::fs::write(dest_path.as_path(), b"old content").expect("Failed to write dest");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dest_path.as_path(), std::fs::Permissions::from_mode(0o600))
                .expect("Failed to chmod dest");
        }

        // Source entry declares 0o644.
        let content = b"new content".to_vec();
        let content_hash = hash_content(&content);
        let entry = TargetEntry::File {
            path: guisu_core::path::RelPath::new("perm.txt".into()).expect("Invalid rel path"),
            content,
            content_hash,
            mode: Some(0o644),
        };

        apply_target_entry(&entry, &dest_path, &[], false).expect("apply failed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let actual_mode = std::fs::metadata(dest_path.as_path())
                .expect("dest missing after apply")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                actual_mode, 0o644,
                "apply must chmod existing dest to source mode (was {actual_mode:o})"
            );
        }
    }

    #[test]
    fn test_apply_removed_paths_removes_dest_relative_path() {
        // Regression test: a dest-relative path declared in `Metadata::remove`
        // is removed from the destination on apply. Missing paths are an
        // idempotent no-op.
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon =
            std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp dir");
        let dest_dir = AbsPath::new(temp_canon).expect("Failed to create AbsPath");

        // Pre-create two files: one will be removed, one stays.
        let victim = dest_dir.as_path().join("victim.txt");
        let survivor = dest_dir.as_path().join("survivor.txt");
        std::fs::write(&victim, b"remove me").expect("Failed to write victim");
        std::fs::write(&survivor, b"keep me").expect("Failed to write survivor");

        let mut metadata = guisu_engine::state::Metadata::default();
        // Use dest-relative filenames, NOT the absolute paths — the
        // security guard rejects absolute paths.
        metadata.remove.add("victim.txt".to_string());
        metadata.remove.add("not-there.txt".to_string());

        apply_removed_paths(
            &metadata,
            &dest_dir,
            &guisu_engine::RealSystem,
            false,
            &ApplyStats::new(),
        )
        .expect("apply_removed_paths failed");

        assert!(!victim.exists(), "victim should have been removed");
        assert!(survivor.exists(), "survivor must not be touched");
    }

    #[test]
    fn test_apply_removed_paths_rejects_absolute_path() {
        // Security: an absolute path in Metadata::remove would otherwise let
        // a malicious state.toml delete files outside the destination root
        // (since `Path::join` ignores the base when given an absolute
        // argument). The function must bail.
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon =
            std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp dir");
        let dest_dir = AbsPath::new(temp_canon).expect("Failed to create AbsPath");

        // Pre-create a "victim" outside the dest tree.
        let outside = temp.path().join("outside.txt");
        std::fs::write(&outside, b"sensitive").expect("Failed to write outside victim");
        let absolute_outside = outside.to_string_lossy().into_owned();

        let mut metadata = guisu_engine::state::Metadata::default();
        metadata.remove.add(absolute_outside.clone());

        let result = apply_removed_paths(
            &metadata,
            &dest_dir,
            &guisu_engine::RealSystem,
            false,
            &ApplyStats::new(),
        );
        assert!(
            result.is_err(),
            "apply_removed_paths must reject absolute path escape"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("is absolute"),
            "error should mention absolute-path rejection, got: {err}"
        );
        assert!(
            outside.exists(),
            "victim outside dest must NOT be deleted by apply_removed_paths"
        );
    }

    #[test]
    fn test_apply_removed_paths_respects_dry_run() {
        // Regression: --dry-run must not actually delete the file. The
        // function emits a "would remove" line and returns Ok without
        // touching the filesystem.
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon =
            std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp dir");
        let dest_dir = AbsPath::new(temp_canon).expect("Failed to create AbsPath");

        let victim = dest_dir.as_path().join("victim.txt");
        std::fs::write(&victim, b"keep me in dry run").expect("Failed to write victim");

        let mut metadata = guisu_engine::state::Metadata::default();
        metadata.remove.add("victim.txt".to_string());

        apply_removed_paths(
            &metadata,
            &dest_dir,
            &guisu_engine::RealSystem,
            true,
            &ApplyStats::new(),
        )
        .expect("dry-run must not error");

        assert!(victim.exists(), "dry-run must not actually remove the file");
    }

    /// Regression test: `handle_dry_run_entry` must only emit output for
    /// entries that actually drifted against the destination. An entry
    /// whose target content already matches the dest is a no-op for
    /// `apply` and must be skipped (returning `false`, no `record_dry_run`,
    /// no `print_dry_run_entry`). An entry whose target content differs
    /// from the dest must be reported (returning `true`).
    ///
    /// This pins the polarity: the previous bug had the conditions
    /// inverted, so dry-run printed only up-to-date files and silently
    /// hid the drifted ones — the opposite of chezmoi's behaviour.
    #[test]
    fn dry_run_entry_skips_up_to_date_and_prints_drifted() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon =
            std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp dir");
        let dest_dir = AbsPath::new(temp_canon).expect("Failed to create AbsPath");

        // Entry 1: dest already matches target — should be skipped.
        let up_to_date_content = b"already in sync".to_vec();
        let up_to_date_path = dest_dir.as_path().join("up_to_date.txt");
        std::fs::write(&up_to_date_path, &up_to_date_content).expect("Failed to write dest");

        let up_to_date_entry = TargetEntry::File {
            path: guisu_core::path::RelPath::new("up_to_date.txt".into())
                .expect("Invalid rel path"),
            content: up_to_date_content.clone(),
            content_hash: hash_content(&up_to_date_content),
            mode: None,
        };
        let up_to_date_dest = dest_dir.join(up_to_date_entry.path());

        // Entry 2: dest missing — should be reported as would-apply.
        let drifted_content = b"new content not on dest yet".to_vec();
        let drifted_entry = TargetEntry::File {
            path: guisu_core::path::RelPath::new("drifted.txt".into()).expect("Invalid rel path"),
            content: drifted_content.clone(),
            content_hash: hash_content(&drifted_content),
            mode: None,
        };
        let drifted_dest = dest_dir.join(drifted_entry.path());

        let stats = ApplyStats::new();

        // Up-to-date entry: handle_dry_run_entry must return Ok(false) and
        // record nothing.
        let applied = handle_dry_run_entry(
            &up_to_date_entry,
            &up_to_date_dest,
            &[],
            &stats,
            false,
            false,
        )
        .expect("handle_dry_run_entry failed on up-to-date entry");
        assert!(
            !applied,
            "up-to-date entry must not be reported by dry-run, got applied=true"
        );
        assert_eq!(
            stats.files(),
            0,
            "up-to-date entry must not increment dry-run file count"
        );

        // Drifted entry must report and bump stats.files() to 1.
        let applied =
            handle_dry_run_entry(&drifted_entry, &drifted_dest, &[], &stats, false, false)
                .expect("handle_dry_run_entry failed on drifted entry");
        assert!(
            applied,
            "drifted entry must be reported by dry-run, got applied=false"
        );
        assert_eq!(
            stats.files(),
            1,
            "drifted entry must increment dry-run file count exactly once"
        );
    }

    /// Regression: dry-run `apply_removed_paths` must bump stats so the
    /// summary headline counts pending removes.
    #[test]
    fn test_apply_removed_paths_increments_stats_on_dry_run() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon =
            std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp dir");
        let dest_dir = AbsPath::new(temp_canon).expect("Failed to create AbsPath");

        let victim = dest_dir.as_path().join("victim.txt");
        std::fs::write(&victim, b"remove me").expect("Failed to write victim");

        let mut metadata = guisu_engine::state::Metadata::default();
        metadata.remove.add("victim.txt".to_string());

        let stats = ApplyStats::new();
        apply_removed_paths(
            &metadata,
            &dest_dir,
            &guisu_engine::RealSystem,
            true,
            &stats,
        )
        .expect("apply_removed_paths dry-run must not error");

        assert!(
            stats.total() >= 1,
            "dry-run must record at least one pending remove in stats, got total={}",
            stats.total()
        );
    }

    /// Both `info!("No files to apply")` and `info!("No matching files to apply")`
    /// must be UNCONDITIONAL. A user who explicitly named a single path
    /// (e.g. `guisu apply ~/.bashrc`) needs to see "nothing to apply"
    /// when their path is filtered out — silent failure is worse than
    /// a single info line. We assert via `include_str!` rather than
    /// capturing log output; `tracing-subscriber` for one test isn't
    /// worth the dep.
    #[test]
    fn test_no_matching_files_message_always_emitted() {
        let src = include_str!("apply.rs");
        let window_before = |needle: &str| -> &str {
            let idx = src
                .find(needle)
                .unwrap_or_else(|| panic!("`{needle}` must exist in apply.rs"));
            &src[idx.saturating_sub(160)..idx]
        };

        for needle in [
            "info!(\"No files to apply\")",
            "info!(\"No matching files to apply\")",
        ] {
            assert!(
                !window_before(needle).contains("!is_single_file"),
                "`{needle}` must NOT be gated on `!is_single_file` \
                 — single-path users need to see why nothing was applied"
            );
        }
    }

    /// The spinner and drift-detection gates must still suppress work
    /// for a single named path (they're per-entry noise gates — spinner
    /// is meaningless for one entry, drift detection is expensive and
    /// redundant when the user named exactly one file). Pin by name
    /// `has_named_target` so the predicate reflects "positional argument
    /// present" rather than the misleading "is single file" (which
    /// misreads `apply ~/.config/zsh` as single-file when it's a
    /// directory).
    #[test]
    fn test_named_target_gates_remain_on_spinner_and_drift() {
        let src = include_str!("apply.rs");

        let spinner_gate = src
            .find("create_spinner(\"Reading source state...\")")
            .expect("read-source spinner must exist");
        let drift_gate = src
            .find("detect_config_drift(&database, &entries_to_apply, &dest_abs)")
            .expect("drift detection call must exist");
        let target_state_spinner = src
            .find("create_spinner(\n            \"Processing templates and encrypted files...\",\n        )")
            .or_else(|| src.find("Processing templates and encrypted files..."))
            .expect("target-state spinner must exist");

        for (label, idx) in [
            ("read_source_state spinner", spinner_gate),
            ("build_target_state spinner", target_state_spinner),
            ("drift detection", drift_gate),
        ] {
            let window = &src[idx.saturating_sub(160)..idx];
            assert!(
                window.contains("has_named_target"),
                "{label} must be gated on `has_named_target` (single named path is the off-switch)"
            );
        }
    }

    /// `entry_needs_update` must use an exhaustive `match` on `MatchResult`
    /// rather than `!= MatchResult::Match`. The exhaustive form forces
    /// a decision on every future variant — `Missing` and `Modified`
    /// count as drift today, but if `MatchResult` gains e.g. `Stale`
    /// or `SymlinkTarget`, the compiler pins the call site until someone
    /// consciously decides where the new variant belongs.
    #[test]
    fn test_entry_needs_update_uses_exhaustive_match() {
        let src = include_str!("apply.rs");
        // Locate the function body — find the definition line and walk
        // forward to its closing `}`.
        let def_idx = src
            .find("fn entry_needs_update(")
            .expect("entry_needs_update must exist");
        let body_start = src[def_idx..]
            .find('{')
            .map(|o| def_idx + o + 1)
            .expect("function body must start with `{{`");
        let body_end = src[body_start..]
            .find("\n}\n")
            .map(|o| body_start + o)
            .expect("function body must end with `}}` at column 0");
        let body = &src[body_start..body_end];

        assert!(
            body.contains("matches!(") || body.contains("match "),
            "entry_needs_update must branch on MatchResult via match/matches! \
             rather than `!= MatchResult::Match`"
        );
        assert!(
            !body.contains("!= MatchResult::Match")
                && !body.contains("!= guisu_engine::verify::MatchResult::Match"),
            "entry_needs_update must not use the `!= Match` collapsing pattern \
             (forces new variants through exhaustive decision)"
        );
        // And pin the explicit variants we currently bucket as drift.
        assert!(
            body.contains("Missing"),
            "entry_needs_update body must enumerate `Missing`"
        );
        assert!(
            body.contains("Modified"),
            "entry_needs_update body must enumerate `Modified`"
        );
    }
}
