//! Apply command implementation
//!
//! Apply the source state to the destination directory.

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::AbsPath;
use guisu_engine::entry::TargetEntry;
use guisu_engine::processor::ContentProcessor;
use guisu_engine::state::{SourceState, TargetState};
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
use crate::utils::path::SourceDirExt;

// File permission constants
const PERM_MASK: u32 = 0o777; // Permission bits mask (rwxrwxrwx)
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

    /// Include only these entry types (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub include: Vec<String>,

    /// Exclude these entry types (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,
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
            guisu_engine::database::get_entry_state(db, &path_str)
                .ok()
                .flatten()
                .map(|state| state.content_hash)
        }
        _ => None,
    }
}

/// Get the last written script hash for a modify entry from the database
///
/// Returns the script hash if the modify entry has state in the database.
/// Returns None if no state exists.
fn get_last_script_hash(
    db: &guisu_engine::state::RedbPersistentState,
    entry: &TargetEntry,
) -> Option<[u8; 32]> {
    match entry {
        TargetEntry::Modify { .. } => {
            let path_str = format!("{}:modify", entry.path());
            guisu_engine::database::get_entry_state(db, &path_str)
                .ok()
                .flatten()
                .map(|state| state.content_hash)
        }
        _ => None,
    }
}

/// Load and prepare all variables for template rendering
fn load_all_variables(
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

/// Setup content processor with decryptor and template renderer
fn setup_content_processor(
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

    // Use Arc to share identity without cloning
    let identity_arc = identities.first().map_or_else(
        || Arc::new(guisu_crypto::Identity::generate()),
        |id| Arc::new(id.clone()),
    );

    let decryptor = CryptoDecryptorAdapter::from_arc(identity_arc);
    let renderer = TemplateRendererAdapter::new(template_engine);
    ContentProcessor::new(decryptor, renderer)
}

/// Read source state with optional ignore filtering
fn read_source_state(
    source_abs: AbsPath,
    source_dir: &std::path::Path,
    is_single_file: bool,
) -> Result<SourceState> {
    let spinner = if is_single_file {
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
    is_single_file: bool,
) -> Result<TargetState> {
    let spinner = if is_single_file {
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
            if let Some(filter) = filter_paths {
                let matches = filter.iter().any(|filter_path| {
                    // Exact match (file or directory itself)
                    if filter_path == target_path {
                        return true;
                    }

                    // Check if target is under the filter directory
                    // Ensure we don't match ".config/zsh-backup" when filter is ".config/zsh"
                    let filter_str = filter_path.as_path().to_str().unwrap_or("");
                    let target_str = target_path.as_path().to_str().unwrap_or("");

                    target_str.starts_with(filter_str)
                        && target_str.as_bytes().get(filter_str.len()) == Some(&b'/')
                });

                if !matches {
                    return false;
                }
            }

            // Skip if file is ignored
            if ignore_matcher.is_ignored(entry.path().as_path(), None) {
                debug!(
                    path = %target_path,
                    "Skipping ignored file"
                );
                return false;
            }

            if let Some(path_str) = target_path.as_path().to_str()
                && metadata.is_create_once(path_str)
            {
                let dest_path = dest_abs.join(entry.path());
                if dest_path.as_path().exists() {
                    debug!(
                        path = %target_path,
                        "Skipping create-once file that already exists"
                    );
                    return false;
                }
            }

            true
        })
        .collect();

    // Sort entries by path for consistent output
    entries.sort_by(|a, b| a.path().as_path().cmp(b.path().as_path()));
    entries
}

/// Display drift warnings for files modified both locally and in source
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
    if !needs_update(entry, dest_path, identities, fail_on_decrypt_error)? {
        debug!(path = %entry.path(), "File is already up to date, skipping");
        return Ok(false);
    }

    debug!(path = %entry.path(), "Would apply entry");
    print_dry_run_entry(entry, show_icons);
    stats.record_dry_run(entry);
    Ok(true)
}

/// Handle interactive conflict resolution
fn handle_interactive_conflict(
    db: &guisu_engine::state::RedbPersistentState,
    entry: &TargetEntry,
    dest_abs: &AbsPath,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    handler: &mut ConflictHandler,
    fail_on_decrypt_error: bool,
) -> Result<bool> {
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
        needs_update(entry, dest_path, identities, fail_on_decrypt_error)
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
) -> Result<bool> {
    if !needs_update(entry, dest_path, identities, fail_on_decrypt_error)? {
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
    db: &guisu_engine::state::RedbPersistentState,
) -> Option<BatchEntryData> {
    // Check if this is a modify script with unchanged content
    let should_execute = match entry {
        TargetEntry::Modify { content_hash, .. } => {
            let last_hash = get_last_script_hash(db, entry);
            match last_hash {
                Some(last) if last == *content_hash => {
                    debug!(path = %entry.path(), "Modify script unchanged, skipping execution");
                    false
                }
                _ => true,
            }
        }
        _ => true,
    };

    if should_execute {
        match apply_target_entry(entry, dest_path, identities, fail_on_decrypt_error) {
            Ok(()) => {
                debug!(path = %entry.path(), "Applied entry successfully");
                print_success_entry(entry, show_icons);
                stats.record_success(entry);

                // Return entry data for batch save (for files and modify scripts)
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
                    TargetEntry::Modify {
                        script,
                        content_hash: _content_hash,
                        ..
                    } => {
                        // Save script hash for change detection
                        let script_path = format!("{}:modify", entry.path());
                        Some((script_path, script.clone(), None))
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
    } else {
        // Script unchanged, but still return state data to ensure hash is saved
        match entry {
            TargetEntry::Modify {
                script,
                content_hash: _content_hash,
                ..
            } => {
                let script_path = format!("{}:modify", entry.path());
                Some((script_path, script.clone(), None))
            }
            _ => None,
        }
    }
}

/// Process entries sequentially (for interactive mode or dry run)
#[allow(clippy::too_many_arguments)]
fn process_entries_sequential(
    db: &guisu_engine::state::RedbPersistentState,
    entries: Vec<&TargetEntry>,
    dest_abs: &AbsPath,
    identities: &[guisu_crypto::Identity],
    conflict_handler: &mut Option<ConflictHandler>,
    stats: &ApplyStats,
    show_icons: bool,
    dry_run: bool,
    fail_on_decrypt_error: bool,
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
                )?
            } else {
                handle_non_interactive_conflict(
                    db,
                    entry,
                    dest_abs,
                    &dest_path,
                    identities,
                    fail_on_decrypt_error,
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
                    db,
                )
            {
                batch_entries.push(state_data);
            }
        }
    }

    // Batch save all successful entries to database
    if !batch_entries.is_empty() {
        guisu_engine::database::save_entry_states_batch(db, &batch_entries).map_err(|e| {
            warn!(error = %e, "Failed to save batch state to database");
            e
        })?;
    }

    Ok(())
}

/// Get user confirmations for entries with local modifications
fn get_user_confirmations(
    db: &guisu_engine::state::RedbPersistentState,
    entries: &[&TargetEntry],
    dest_abs: &AbsPath,
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<std::collections::HashSet<String>> {
    use dialoguer::{Confirm, theme::ColorfulTheme};
    use std::collections::HashSet;

    let mut confirmed_paths = HashSet::new();
    let mut has_warnings = false;

    for entry in entries {
        let dest_path = dest_abs.join(entry.path());
        if !needs_update(entry, &dest_path, identities, fail_on_decrypt_error)? {
            continue;
        }

        let last_written_hash = get_last_written_hash(db, entry);
        if let Ok(Some(change_type)) = ConflictHandler::detect_change_type(
            entry,
            dest_abs,
            last_written_hash.as_ref().map(|arr| &arr[..]),
            identities,
        ) {
            match change_type {
                ChangeType::LocalModification | ChangeType::TrueConflict => {
                    has_warnings = true;
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
                    let confirmed = Confirm::with_theme(&theme)
                        .with_prompt("Continue and overwrite local changes?")
                        .default(false)
                        .interact()
                        .context("Failed to read user input")?;

                    if confirmed {
                        confirmed_paths.insert(entry.path().to_string());
                    }
                }
                ChangeType::SourceUpdate => {
                    confirmed_paths.insert(entry.path().to_string());
                }
            }
        } else {
            confirmed_paths.insert(entry.path().to_string());
        }
    }

    if has_warnings {
        println!();
    }

    Ok(confirmed_paths)
}

/// Process a single entry and return batch data if successful
fn process_single_entry(
    entry: &TargetEntry,
    dest_abs: &AbsPath,
    identities: &[guisu_crypto::Identity],
    stats: &ApplyStats,
    show_icons: bool,
    fail_on_decrypt_error: bool,
) -> Result<Option<BatchEntryData>> {
    let dest_path = dest_abs.join(entry.path());

    if !needs_update(entry, &dest_path, identities, fail_on_decrypt_error)? {
        debug!(path = %entry.path(), "File is already up to date, skipping");
        return Ok(None);
    }

    apply_target_entry(entry, &dest_path, identities, fail_on_decrypt_error)?;
    debug!(path = %entry.path(), "Applied entry successfully");
    print_success_entry(entry, show_icons);
    stats.record_success(entry);

    // Prepare entry data for batch save (only for files)
    let state_data = if let TargetEntry::File { content, mode, .. } = entry {
        let final_content = decrypt_inline_age_values(content, identities, fail_on_decrypt_error)
            .unwrap_or_else(|e| {
                warn!(path = %entry.path(), error = %e, "Failed to decrypt inline age values for state saving");
                content.clone()
            });
        Some((entry.path().to_string(), final_content, *mode))
    } else {
        None
    };

    Ok(state_data)
}

/// Process entries in parallel (for non-interactive mode)
fn process_entries_parallel(
    db: &guisu_engine::state::RedbPersistentState,
    entries: &[&TargetEntry],
    dest_abs: &AbsPath,
    identities: &[guisu_crypto::Identity],
    stats: &ApplyStats,
    show_icons: bool,
    fail_on_decrypt_error: bool,
) -> Result<()> {
    // Get user confirmations for conflicting files
    let confirmed_paths =
        get_user_confirmations(db, entries, dest_abs, identities, fail_on_decrypt_error)?;

    // Process confirmed files in parallel
    let results: Vec<Result<Option<BatchEntryData>>> = entries
        .par_iter()
        .filter(|entry| confirmed_paths.contains(&entry.path().to_string()))
        .map(|entry| {
            process_single_entry(
                entry,
                dest_abs,
                identities,
                stats,
                show_icons,
                fail_on_decrypt_error,
            )
            .map_err(|e| {
                warn!(path = %entry.path(), error = %e, "Failed to apply entry");
                print_error_entry(entry, &e, show_icons);
                stats.record_failure();
                e
            })
        })
        .collect();

    // Collect successful entries and check for errors
    let mut batch_entries = Vec::with_capacity(results.len());
    for result in results {
        if let Some(data) = result? {
            batch_entries.push(data);
        }
    }

    // Batch save all successful entries to database
    if !batch_entries.is_empty() {
        guisu_engine::database::save_entry_states_batch(db, &batch_entries).map_err(|e| {
            warn!(error = %e, "Failed to save batch state to database");
            e
        })?;
    }

    Ok(())
}

impl Command for ApplyCommand {
    type Output = ApplyStats;
    #[allow(clippy::too_many_lines)]
    fn execute(&self, context: &RuntimeContext) -> crate::error::Result<ApplyStats> {
        // Parse entry type filters
        let include_types: Result<Vec<EntryType>> =
            self.include.iter().map(|s| s.parse()).collect();
        let _include_types = include_types?;

        let exclude_types: Result<Vec<EntryType>> =
            self.exclude.iter().map(|s| s.parse()).collect();
        let _exclude_types = exclude_types?;

        // Extract paths, config, and database from context
        let source_abs = context.dotfiles_dir();
        let dest_abs = context.dest_dir();
        let source_dir = context.source_dir();
        let config = &context.config;
        let database = context.database();

        if self.dry_run {
            info!("Dry run mode - no changes will be made");
        }

        // Load age identities for decryption
        let spinner = progress::create_spinner("Loading identities...");
        let identities = std::sync::Arc::new(config.age_identities().unwrap_or_default());
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

        // Create ignore matcher from .guisu/ignores.toml
        let ignore_matcher = guisu_config::IgnoreMatcher::from_ignores_toml(source_dir)
            .context("Failed to load ignore patterns from .guisu/ignores.toml")?;

        // Check if we're applying a single file (affects output verbosity)
        let is_single_file = !self.files.is_empty() && self.files.len() == 1;

        // Build filter paths if specific files requested
        let filter_paths = if self.files.is_empty() {
            None
        } else {
            Some(crate::build_filter_paths(&self.files, dest_abs)?)
        };

        // Read source state
        let source_state = read_source_state(source_abs.to_owned(), source_dir, is_single_file)?;

        if source_state.is_empty() {
            if !is_single_file {
                info!("No files to apply");
            }
            return Ok(ApplyStats::new());
        }

        // Build target state
        let working_tree = context.working_tree();
        let target_state = build_target_state(
            &source_state,
            &processor,
            source_abs,
            dest_abs,
            &working_tree,
            config,
            all_variables,
            is_single_file,
        )?;

        // Filter entries to apply
        let entries_to_apply = filter_entries_to_apply(
            &target_state,
            filter_paths.as_ref(),
            &ignore_matcher,
            &metadata,
            dest_abs,
        );

        if entries_to_apply.is_empty() {
            info!("No matching files to apply");
            return Ok(ApplyStats::new());
        }

        // Check for configuration drift (files modified by user AND source updated)
        if !self.dry_run && !is_single_file {
            let drift_warnings = detect_config_drift(database, &entries_to_apply, dest_abs);
            display_drift_warnings(&drift_warnings);
        }

        // Create conflict handler for interactive mode
        let mut conflict_handler = if self.interactive && !self.dry_run {
            Some(ConflictHandler::new(
                Arc::clone(config),
                Arc::clone(&identities),
            ))
        } else {
            None
        };

        // Apply entries
        let stats = Arc::new(ApplyStats::new());

        // Use parallel processing only when NOT in interactive mode
        if self.interactive || self.dry_run {
            process_entries_sequential(
                database,
                entries_to_apply,
                dest_abs,
                &identities,
                &mut conflict_handler,
                &stats,
                show_icons,
                self.dry_run,
                fail_on_decrypt_error,
            )?;
        } else {
            process_entries_parallel(
                database,
                &entries_to_apply,
                dest_abs,
                &identities,
                &stats,
                show_icons,
                fail_on_decrypt_error,
            )?;
        }

        // Return stats instead of printing here
        // The caller (lib.rs) will print the summary after hooks complete

        let failed_count = stats.failed();
        if failed_count > 0 {
            return Err(anyhow::anyhow!("Failed to apply {failed_count} entries").into());
        }

        Ok(stats.snapshot())
    }
}

/// Entry type filter for apply command
#[derive(Debug, Clone, Copy, PartialEq)]
enum EntryType {
    Files,
    Dirs,
    Symlinks,
    Templates,
    Encrypted,
}

impl std::str::FromStr for EntryType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "files" | "file" => Ok(EntryType::Files),
            "dirs" | "dir" | "directories" => Ok(EntryType::Dirs),
            "symlinks" | "symlink" => Ok(EntryType::Symlinks),
            "templates" | "template" => Ok(EntryType::Templates),
            "encrypted" | "encrypt" => Ok(EntryType::Encrypted),
            _ => anyhow::bail!(
                "Invalid entry type: {s}. Valid types: files, dirs, symlinks, templates, encrypted"
            ),
        }
    }
}
/// Check if a target entry needs to be updated at the destination
///
/// Returns true if:
/// - The destination file/directory doesn't exist
/// - The content differs from the target
/// - The permissions differ from the target
///
/// NOTE: This function should NOT be used alone to determine if a file needs updating.
/// Use `detect_change_type` instead for proper three-way comparison.
/// This function is only called after `detect_change_type` returns None.
fn needs_update(
    entry: &TargetEntry,
    dest_path: &AbsPath,
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<bool> {
    match entry {
        TargetEntry::File { content, mode, .. } => {
            // If file doesn't exist, it needs to be created
            if !dest_path.as_path().exists() {
                return Ok(true);
            }

            // Decrypt inline age values in target content before comparing
            // This matches the behavior in detect_change_type and apply_target_entry
            let target_content_decrypted =
                decrypt_inline_age_values(content, identities, fail_on_decrypt_error)?;

            // Check if content differs
            if let Ok(existing_content) = fs::read(dest_path.as_path()) {
                if existing_content != target_content_decrypted {
                    return Ok(true);
                }
            } else {
                // Can't read file, assume it needs update
                return Ok(true);
            }

            // Check if permissions differ (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(target_mode) = mode
                    && let Ok(metadata) = fs::metadata(dest_path.as_path())
                {
                    let current_mode = metadata.permissions().mode() & PERM_MASK;
                    if current_mode != *target_mode {
                        return Ok(true);
                    }
                }
            }

            // Content and permissions match, no update needed
            Ok(false)
        }
        TargetEntry::Directory { mode, .. } => {
            // If directory doesn't exist, it needs to be created
            if !dest_path.as_path().exists() {
                return Ok(true);
            }

            // Check if it's actually a directory
            if !dest_path.as_path().is_dir() {
                return Ok(true);
            }

            // Check if permissions differ (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(target_mode) = mode
                    && let Ok(metadata) = fs::metadata(dest_path.as_path())
                {
                    let current_mode = metadata.permissions().mode() & PERM_MASK;
                    if current_mode != *target_mode {
                        return Ok(true);
                    }
                }
            }

            // Directory exists with correct permissions
            Ok(false)
        }
        TargetEntry::Symlink { target, .. } => {
            // If symlink doesn't exist, it needs to be created
            if !dest_path.as_path().exists() {
                return Ok(true);
            }

            // Check if it's actually a symlink
            if !dest_path.as_path().is_symlink() {
                return Ok(true);
            }

            // Check if symlink target differs
            if let Ok(existing_target) = fs::read_link(dest_path.as_path()) {
                if existing_target != target.as_path() {
                    return Ok(true);
                }
            } else {
                // Can't read symlink, assume it needs update
                return Ok(true);
            }

            // Symlink exists with correct target
            Ok(false)
        }
        TargetEntry::Remove { .. } => {
            // Always needs update if file exists
            Ok(dest_path.as_path().exists())
        }
        TargetEntry::Modify { .. } => {
            // Modify scripts don't write to destination, they modify existing files
            // Execution is handled separately
            // Always execute modify scripts (they should be idempotent)
            Ok(true)
        }
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
                use std::os::unix::fs::OpenOptionsExt;

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

        TargetEntry::Remove { .. } => {
            // Handle removal entries (not used in apply, but included for completeness)
            if dest_path.as_path().exists() {
                if dest_path.as_path().is_dir() {
                    fs::remove_dir_all(dest_path.as_path())
                        .with_context(|| format!("Failed to remove directory: {dest_path:?}"))?;
                } else {
                    fs::remove_file(dest_path.as_path())
                        .with_context(|| format!("Failed to remove file: {dest_path:?}"))?;
                }
            }
            Ok(())
        }
        TargetEntry::Modify {
            script,
            interpreter,
            ..
        } => {
            // Execute modify script to modify target file in-place
            let executor = guisu_engine::modify::ModifyExecutor::new();
            executor.execute(script, interpreter, dest_path, &[])?;
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
            TargetEntry::Remove { .. } | TargetEntry::Modify { .. } => {}
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
        TargetEntry::File { .. } | TargetEntry::Remove { .. } | TargetEntry::Modify { .. } => {
            (false, false)
        }
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
        TargetEntry::File { .. } | TargetEntry::Remove { .. } | TargetEntry::Modify { .. } => {
            (false, false)
        }
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
        TargetEntry::File { .. } | TargetEntry::Remove { .. } | TargetEntry::Modify { .. } => {
            (false, false)
        }
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
            let last_written_state = match guisu_engine::database::get_entry_state(db, path_str) {
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

            let actual_hash = guisu_engine::hash::hash_content(&actual_content);

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

/// Decrypt inline age: encrypted values in file content
///
/// This function scans the content for age:base64(...) patterns and decrypts them,
/// allowing source files to store encrypted secrets while destination files get plaintext.
///
/// This enables the workflow:
/// - Source: password: age:YWdlLWVuY3J5cHRpb24...
/// - Destination: password: my-secret-password
///
/// # Behavior
///
/// - If `fail_on_decrypt_error` is true (default), decryption failures cause an error
/// - If `fail_on_decrypt_error` is false, decryption failures log a warning and return original content
/// - If no identities are available, returns the original content (not an error)
/// - If content is binary (non-UTF-8), returns the original content (not an error)
/// - If no age: patterns are found, returns the original content (not an error)
fn decrypt_inline_age_values(
    content: &[u8],
    identities: &[guisu_crypto::Identity],
    fail_on_decrypt_error: bool,
) -> Result<Vec<u8>> {
    // Convert to string (if not valid UTF-8, return original)
    let Ok(content_str) = String::from_utf8(content.to_vec()) else {
        return Ok(content.to_vec()); // Binary file, return as-is
    };

    // Check if content contains age: prefix (quick check before decrypting)
    if !content_str.contains("age:") {
        return Ok(content.to_vec()); // No encrypted values, return as-is
    }

    // If no identities available, return original content
    if identities.is_empty() {
        return Ok(content.to_vec());
    }

    // Decrypt all inline age values
    match guisu_crypto::decrypt_file_content(&content_str, identities) {
        Ok(decrypted) => Ok(decrypted.into_bytes()),
        Err(e) => {
            if fail_on_decrypt_error {
                // Fail loudly for security (matches chezmoi behavior)
                Err(anyhow::anyhow!(
                    "Failed to decrypt inline age values in file. \
                     This usually means the wrong identity was used or the encrypted value is corrupted. \
                     Error: {e}"
                ))
            } else {
                // Log the error with context
                warn!(
                    "Failed to decrypt inline age values in file. \
                     Content will be written with encrypted age: values intact. \
                     Applications may not be able to use these values. \
                     Error: {}",
                    e
                );

                // Return original content with encrypted values
                // This allows the file to be applied, but the application
                // will see "age:..." strings instead of plaintext
                Ok(content.to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for EntryType

    #[test]
    fn test_entry_type_from_str_files() {
        assert_eq!("files".parse::<EntryType>().unwrap(), EntryType::Files);
        assert_eq!("file".parse::<EntryType>().unwrap(), EntryType::Files);
        assert_eq!("FILES".parse::<EntryType>().unwrap(), EntryType::Files);
    }

    #[test]
    fn test_entry_type_from_str_dirs() {
        assert_eq!("dirs".parse::<EntryType>().unwrap(), EntryType::Dirs);
        assert_eq!("dir".parse::<EntryType>().unwrap(), EntryType::Dirs);
        assert_eq!("directories".parse::<EntryType>().unwrap(), EntryType::Dirs);
        assert_eq!("DIRS".parse::<EntryType>().unwrap(), EntryType::Dirs);
    }

    #[test]
    fn test_entry_type_from_str_symlinks() {
        assert_eq!(
            "symlinks".parse::<EntryType>().unwrap(),
            EntryType::Symlinks
        );
        assert_eq!("symlink".parse::<EntryType>().unwrap(), EntryType::Symlinks);
        assert_eq!(
            "SYMLINKS".parse::<EntryType>().unwrap(),
            EntryType::Symlinks
        );
    }

    #[test]
    fn test_entry_type_from_str_templates() {
        assert_eq!(
            "templates".parse::<EntryType>().unwrap(),
            EntryType::Templates
        );
        assert_eq!(
            "template".parse::<EntryType>().unwrap(),
            EntryType::Templates
        );
        assert_eq!(
            "TEMPLATES".parse::<EntryType>().unwrap(),
            EntryType::Templates
        );
    }

    #[test]
    fn test_entry_type_from_str_encrypted() {
        assert_eq!(
            "encrypted".parse::<EntryType>().unwrap(),
            EntryType::Encrypted
        );
        assert_eq!(
            "encrypt".parse::<EntryType>().unwrap(),
            EntryType::Encrypted
        );
        assert_eq!(
            "ENCRYPTED".parse::<EntryType>().unwrap(),
            EntryType::Encrypted
        );
    }

    #[test]
    fn test_entry_type_from_str_invalid() {
        let result = "invalid".parse::<EntryType>();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid entry type")
        );
    }

    #[test]
    fn test_entry_type_equality() {
        assert_eq!(EntryType::Files, EntryType::Files);
        assert_eq!(EntryType::Dirs, EntryType::Dirs);
        assert_ne!(EntryType::Files, EntryType::Dirs);
    }

    #[test]
    fn test_entry_type_clone() {
        let entry_type = EntryType::Files;
        let cloned = entry_type;
        assert_eq!(entry_type, cloned);
    }

    #[test]
    fn test_entry_type_copy() {
        let entry_type = EntryType::Templates;
        let copied = entry_type;
        // After copy, original should still be usable
        assert_eq!(entry_type, EntryType::Templates);
        assert_eq!(copied, EntryType::Templates);
    }

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
            include: vec![],
            exclude: vec![],
        };

        assert!(cmd.files.is_empty());
        assert!(!cmd.dry_run);
        assert!(!cmd.force);
        assert!(!cmd.interactive);
        assert!(cmd.include.is_empty());
        assert!(cmd.exclude.is_empty());
    }

    #[test]
    fn test_apply_command_with_files() {
        let cmd = ApplyCommand {
            files: vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")],
            dry_run: false,
            force: false,
            interactive: false,
            include: vec![],
            exclude: vec![],
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
            include: vec![],
            exclude: vec![],
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
            include: vec![],
            exclude: vec![],
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
            include: vec![],
            exclude: vec![],
        };

        assert!(cmd.interactive);
    }

    #[test]
    fn test_apply_command_with_filters() {
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: false,
            force: false,
            interactive: false,
            include: vec!["files".to_string(), "dirs".to_string()],
            exclude: vec!["encrypted".to_string()],
        };

        assert_eq!(cmd.include.len(), 2);
        assert_eq!(cmd.exclude.len(), 1);
        assert_eq!(cmd.include[0], "files");
        assert_eq!(cmd.exclude[0], "encrypted");
    }

    #[test]
    fn test_apply_command_clone() {
        let cmd = ApplyCommand {
            files: vec![PathBuf::from("test.txt")],
            dry_run: true,
            force: false,
            interactive: false,
            include: vec!["files".to_string()],
            exclude: vec![],
        };

        let cloned = cmd.clone();
        assert_eq!(cloned.files, cmd.files);
        assert_eq!(cloned.dry_run, cmd.dry_run);
        assert_eq!(cloned.force, cmd.force);
        assert_eq!(cloned.interactive, cmd.interactive);
        assert_eq!(cloned.include, cmd.include);
        assert_eq!(cloned.exclude, cmd.exclude);
    }
}
