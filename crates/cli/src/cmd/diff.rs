//! Diff command implementation
//!
//! Show differences between source and destination states.

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::AbsPath;
use guisu_engine::adapters::crypto::CryptoDecryptorAdapter;
use guisu_engine::adapters::template::TemplateRendererAdapter;
use guisu_engine::entry::{SourceEntry, TargetEntry};
use guisu_engine::hooks::display_script_name;
use guisu_engine::processor::ContentProcessor;
use guisu_engine::state::{PersistentState, SourceState, TargetState};
use owo_colors::OwoColorize;
use rayon::prelude::*;
use similar::{ChangeTag, TextDiff};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::command::Command;
use crate::common::RuntimeContext;
use crate::stats::DiffStats;
use crate::ui::{FileDiff, FileStatus, InteractiveDiffViewer};
use crate::utils::filter::path_matches_any_filter;
use crate::utils::path::SourceDirExt;
use crate::utils::path_display::{DiffSide, PathDisplayStyle, PathFormatter};
use guisu_config::{Config, Env};

// File permission constants
const PERM_MASK: u32 = 0o7777;
const S_IFREG: u32 = 0o100_000;
const DEFAULT_FILE_MODE: u32 = 0o100_644;
#[cfg(test)]
const DEFAULT_EXEC_MODE: u32 = 0o100_755;

// Binary detection constants
const BINARY_CHECK_BYTES: usize = 8000;

/// Diff command
#[derive(Args)]
pub struct DiffCommand {
    /// Specific files to diff (all if not specified)
    pub files: Vec<PathBuf>,

    /// Use pager for output
    #[arg(long)]
    pub pager: bool,

    /// Interactive diff viewer
    #[arg(short, long)]
    pub interactive: bool,
}

impl Command for DiffCommand {
    type Output = ();
    fn execute(&self, context: &mut RuntimeContext) -> anyhow::Result<()> {
        // Snapshot immutable pieces from `context` so we can take exclusive
        // `&mut` access to the database afterwards. `config` is cloned
        // (Arc refcount bump) so the immutable borrow on `context.config`
        // is released before `database_mut()` is called.
        let source_dir = context.source_dir().to_path_buf();
        let dest_dir = context.dest_dir().as_path().to_path_buf();
        let config = context.config.clone();
        let db = context.database_mut();
        run_impl(
            &source_dir,
            &dest_dir,
            &self.files,
            self.pager,
            self.interactive,
            &config,
            db,
        )
    }
}

/// Handle file processing errors, showing detailed messages for first error only
fn handle_file_processing_error<E: std::fmt::Display>(
    error: &E,
    target_path: &guisu_core::path::RelPath,
    identities: &[guisu_crypto::Identity],
    shown_decryption_error: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    config: &Config,
) {
    let error_msg = error.to_string();

    if error_msg.contains("Decryption failed") {
        if !shown_decryption_error.swap(true, std::sync::atomic::Ordering::Relaxed) {
            // First decryption error - check if it's a missing identity file
            if identities.is_empty() {
                if let Some(ref identity_path) = config.age.identity {
                    eprintln!(
                        "{} Decryption failed - {}: no such file or directory",
                        "Error:".red().bold(),
                        identity_path.display()
                    );
                } else if let Some(ref identities_paths) = config.age.identities {
                    if let Some(first_path) = identities_paths.first() {
                        eprintln!(
                            "{} Decryption failed - {}: no such file or directory",
                            "Error:".red().bold(),
                            first_path.display()
                        );
                    } else {
                        eprintln!("{} No age identity configured", "Error:".red().bold());
                    }
                } else {
                    eprintln!("{} No age identity configured", "Error:".red().bold());
                }
            } else {
                warn!(
                    "Decryption failed for {}: {}",
                    target_path.as_path().display(),
                    error
                );
            }
        }
    } else {
        // Non-decryption errors are still shown
        warn!(
            "Failed to process {}: {}",
            target_path.as_path().display(),
            error
        );
    }
}

/// Build target state by processing source entries
#[allow(clippy::too_many_arguments)]
fn build_diff_target_state(
    source_state: &SourceState,
    filter_paths: Option<&Vec<guisu_core::path::RelPath>>,
    ignore_matcher: &guisu_config::IgnoreMatcher,
    processor: &ContentProcessor<CryptoDecryptorAdapter, TemplateRendererAdapter>,
    template_ctx_value: &serde_json::Value,
    identities: &[guisu_crypto::Identity],
    shown_decryption_error: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    config: &Config,
) -> TargetState {
    let mut target_state = TargetState::new();

    for source_entry in source_state.entries() {
        let target_path = source_entry.target_path();

        // Skip if file is ignored
        if ignore_matcher.is_ignored(target_path.as_path(), None) {
            continue;
        }

        // If filtering, skip entries not in the filter
        if let Some(filter) = filter_paths
            && !path_matches_any_filter(target_path, filter)
        {
            continue;
        }

        // Process this entry manually to handle errors gracefully
        match source_entry {
            SourceEntry::File {
                source_path,
                target_path,
                attributes,
            } => {
                let abs_source_path = source_state.source_file_path(source_path);
                match processor.process_file(&abs_source_path, attributes, template_ctx_value) {
                    Ok(mut content) => {
                        // Decrypt inline age: values (sops-like behavior)
                        if !identities.is_empty()
                            && let Ok(content_str) = String::from_utf8(content.clone())
                            && content_str.contains("age:")
                            && let Ok(decrypted) =
                                guisu_crypto::decrypt_file_content(&content_str, identities)
                        {
                            content = decrypted.into_bytes();
                        }

                        let mode = attributes.mode();
                        let content_hash = guisu_engine::hash_content(&content);
                        target_state.add(TargetEntry::File {
                            path: target_path.clone(),
                            content,
                            content_hash,
                            mode,
                        });
                    }
                    Err(e) => {
                        handle_file_processing_error(
                            &e,
                            target_path,
                            identities,
                            shown_decryption_error,
                            config,
                        );
                    }
                }
            }
            SourceEntry::Directory {
                source_path: _,
                target_path,
                attributes,
            } => {
                let mode = attributes.mode();
                target_state.add(TargetEntry::Directory {
                    path: target_path.clone(),
                    mode,
                });
            }
            SourceEntry::Symlink {
                source_path: _,
                target_path,
                link_target,
            } => {
                target_state.add(TargetEntry::Symlink {
                    path: target_path.clone(),
                    target: link_target.clone(),
                });
            }
        }
    }

    target_state
}

/// Generate diff outputs in parallel
fn generate_diff_outputs(
    target_state: &TargetState,
    filter_paths: Option<&Vec<guisu_core::path::RelPath>>,
    metadata: &guisu_engine::state::Metadata,
    dest_abs: &AbsPath,
    stats: &DiffStats,
    config: &Config,
    formatter: &PathFormatter,
) -> Vec<String> {
    target_state
        .entries()
        .par_bridge()
        .filter_map(|entry| {
            // Skip directories, symlinks, and remove entries - only diff files
            if !matches!(entry, TargetEntry::File { .. }) {
                return None;
            }

            let target_path = entry.path();

            // Skip if filtering and this file is not in the filter
            if let Some(filter) = filter_paths
                && !path_matches_any_filter(target_path, filter)
            {
                return None;
            }
            let path_str = target_path.to_string();

            // Skip create-once files that already exist at destination (silently)
            if metadata.is_create_once(&path_str) {
                let dest_path = dest_abs.join(target_path);
                if dest_path.as_path().exists() {
                    debug!(
                        path = %path_str,
                        "Skipping create-once file that already exists in diff"
                    );
                    return None;
                }
            }

            match diff_target_entry(entry, dest_abs, stats, formatter) {
                Ok(entry_diff) => {
                    if entry_diff.is_empty() {
                        None
                    } else {
                        Some(entry_diff)
                    }
                }
                Err(e) => {
                    // Track error
                    stats.inc_errors();

                    // Debug log for verbose mode
                    debug!(path = %target_path, error = %e, "Failed to diff file");

                    // Show path through the formatter so users see `~/...`
                    // instead of bare relative paths in error messages.
                    let display_path = formatter.display(
                        PathDisplayStyle::SourceRelative {
                            root_entry: &config.general.root_entry,
                        },
                        target_path,
                    );
                    warn!("Error processing {}: {}", display_path, e);
                    None
                }
            }
        })
        .collect()
}

/// Build `FileDiff` structures for interactive mode
fn build_interactive_file_diffs(
    target_state: &TargetState,
    filter_paths: Option<&Vec<guisu_core::path::RelPath>>,
    metadata: &guisu_engine::state::Metadata,
    dest_abs: &AbsPath,
) -> Vec<crate::ui::FileDiff> {
    target_state
        .entries()
        .filter_map(|entry| {
            if !matches!(entry, TargetEntry::File { .. }) {
                return None;
            }

            let target_path = entry.path();
            let path_str = target_path.to_string();

            // Skip if filtering and this file is not in the filter
            if let Some(filter) = filter_paths
                && !path_matches_any_filter(target_path, filter)
            {
                return None;
            }

            // Skip create-once files that already exist at destination
            if metadata.is_create_once(&path_str) {
                let dest_path = dest_abs.join(target_path);
                if dest_path.as_path().exists() {
                    return None;
                }
            }

            if let TargetEntry::File {
                content: source_content,
                ..
            } = entry
            {
                let dest_path = dest_abs.join(target_path);

                // Determine file status and content
                let (file_status, old_content, new_content) = if !dest_path.as_path().exists() {
                    (
                        FileStatus::Added,
                        String::new(),
                        String::from_utf8_lossy(source_content).to_string(),
                    )
                } else if let Ok(dest_content) = fs::read(dest_path.as_path()) {
                    if is_binary(source_content) || is_binary(&dest_content) {
                        // Skip binary files in interactive mode
                        return None;
                    }
                    (
                        FileStatus::Modified,
                        String::from_utf8_lossy(&dest_content).to_string(),
                        String::from_utf8_lossy(source_content).to_string(),
                    )
                } else {
                    return None;
                };

                // Only include files that have actual changes
                if file_status == FileStatus::Modified && old_content == new_content {
                    return None;
                }

                Some(FileDiff::new(
                    path_str,
                    old_content,
                    new_content,
                    file_status,
                ))
            } else {
                None
            }
        })
        .collect()
}

/// Display diff output for non-interactive mode
fn display_diff_output(
    source_dir: &Path,
    diff_outputs: &[String],
    stats: &DiffStats,
    pager: bool,
    config: &Config,
    db: &mut dyn PersistentState,
) -> Result<()> {
    // Check and display hooks status first
    let hooks_displayed = print_hooks_status(source_dir, config, db);

    // Join all diff outputs
    let diff_output = diff_outputs.join("\n");

    // Print diff output (no message if no differences)
    // Output already contains ANSI color codes from generate_unified_diff
    if !diff_output.is_empty() {
        if pager {
            maybe_use_pager(&diff_output, config)?;
        } else {
            print!("{diff_output}");
        }
    }

    // Print statistics at the end (only add blank line if there was content above)
    let has_stats = stats.added() > 0 || stats.modified() > 0 || stats.errors() > 0;
    if has_stats && (hooks_displayed || !diff_output.is_empty()) {
        println!();
    }
    print_stats(stats);

    Ok(())
}

/// Run the diff command implementation
fn run_impl(
    source_dir: &Path,
    dest_dir: &Path,
    files: &[PathBuf],
    pager: bool,
    interactive: bool,
    config: &Config,
    db: &mut dyn PersistentState,
) -> Result<()> {
    // Resolve all paths (handles root_entry and canonicalization)
    let paths = crate::common::ResolvedPaths::resolve(source_dir, dest_dir, config)?;
    let source_abs = &paths.dotfiles_dir;
    let dest_abs = &paths.dest_dir;

    // Get .guisu directory and platform name for loading variables and ignore patterns
    let guisu_dir = source_dir.guisu_dir();
    let platform_name = guisu_core::platform::CURRENT_PLATFORM.os;

    // Load metadata for create-once tracking
    let metadata =
        guisu_engine::state::Metadata::load(source_dir).context("Failed to load metadata")?;

    // Create ignore matcher from .guisu/ignores.toml
    let ignore_matcher = guisu_config::IgnoreMatcher::from_ignores_toml(source_dir)
        .context("Failed to load ignore patterns from .guisu/ignores.toml")?;

    // Read source state
    let source_state =
        SourceState::read(source_abs.to_owned()).context("Failed to read source state")?;

    if source_state.is_empty() {
        // Hooks are compared against the state DB, not the source tree, so
        // they can still have changes to show even with no tracked files.
        let _hooks_displayed = print_hooks_status(source_dir, config, db);
        return Ok(());
    }

    // Load age identities for decryption
    let identities = Arc::new(config.age_identities().unwrap_or_default());

    // Track if we've already shown a decryption error message
    let shown_decryption_error = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Load variables from .guisu/variables/ directory
    let guisu_variables = if guisu_dir.exists() {
        guisu_config::variables::load_variables(&guisu_dir, platform_name)
            .context("Failed to load variables from .guisu/variables/")?
    } else {
        indexmap::IndexMap::new()
    };

    // Merge variables: guisu variables + config variables (config overrides)
    let mut all_variables = guisu_variables;
    all_variables.extend(config.variables.clone());

    // Create template engine with identities, template directory, and bitwarden provider
    let template_engine = crate::create_template_engine(source_dir, &identities, config);

    // Create content processor with real decryptor and renderer
    let identity = identities
        .first()
        .map_or_else(guisu_crypto::Identity::generate, std::clone::Clone::clone);
    let decryptor = CryptoDecryptorAdapter::new(identity);
    let renderer = TemplateRendererAdapter::new(template_engine);
    let processor = ContentProcessor::new(decryptor, renderer);

    // Build filter paths if specific files requested
    let filter_paths = if files.is_empty() {
        None
    } else {
        Some(crate::build_filter_paths(files, dest_abs)?)
    };

    // Build target state (processes templates and decrypts files)
    let working_tree = guisu_engine::git::find_working_tree(source_dir)
        .unwrap_or_else(|| source_dir.to_path_buf());
    let template_context = guisu_template::TemplateContext::with_guisu_context(
        source_abs.to_string(),
        working_tree.display().to_string(),
        dest_abs.to_string(),
        config.general.root_entry.display().to_string(),
        all_variables,
    );
    let template_ctx_value =
        serde_json::to_value(&template_context).context("Failed to serialize template context")?;

    let target_state = build_diff_target_state(
        &source_state,
        filter_paths.as_ref(),
        &ignore_matcher,
        &processor,
        &template_ctx_value,
        &identities,
        &shown_decryption_error,
        config,
    );

    // All path-formatting decisions flow through this one formatter.
    let formatter = PathFormatter::new(dest_abs);

    // Use thread-safe stats for parallel processing
    let stats = Arc::new(DiffStats::new());

    // If interactive mode is enabled, use the interactive diff viewer
    if interactive {
        let file_diffs =
            build_interactive_file_diffs(&target_state, filter_paths.as_ref(), &metadata, dest_abs);

        if !file_diffs.is_empty() {
            let mut viewer = InteractiveDiffViewer::new(file_diffs);
            viewer.run()?;
        }

        return Ok(());
    }

    // Generate diff outputs in parallel
    let diff_outputs = generate_diff_outputs(
        &target_state,
        filter_paths.as_ref(),
        &metadata,
        dest_abs,
        &stats,
        config,
        &formatter,
    );

    display_diff_output(source_dir, &diff_outputs, &stats, pager, config, db)
}

/// Diff a single target entry against destination
#[allow(clippy::too_many_lines)]
fn diff_target_entry(
    entry: &TargetEntry,
    dest_abs: &AbsPath,
    stats: &DiffStats,
    formatter: &PathFormatter,
) -> Result<String> {
    let target_path = entry.path();
    let dest_path = dest_abs.join(target_path);

    // Only process File entries
    let (source_content, source_mode) = match entry {
        TargetEntry::File { content, mode, .. } => (content.clone(), *mode),
        _ => return Ok(String::new()),
    };

    // Pre-compute the diff-header labels so every format branch agrees.
    let old_label = formatter.display(
        PathDisplayStyle::DiffHeader {
            side: DiffSide::Old,
        },
        target_path,
    );
    let new_label = formatter.display(
        PathDisplayStyle::DiffHeader {
            side: DiffSide::New,
        },
        target_path,
    );

    // Check if destination exists
    if !dest_path.as_path().exists() {
        stats.inc_added();
        // Check if content is binary before formatting
        if is_binary(&source_content) {
            let mut output = String::new();

            // File header with mode
            let effective_mode = source_mode.or(Some(DEFAULT_FILE_MODE));
            let new_mode_str = format_file_mode(effective_mode);

            let _ = writeln!(
                output,
                "{} {}",
                format!("+++ {new_label}").bold(),
                new_mode_str.dimmed()
            );

            // Binary file to be added message at the end
            let _ = writeln!(
                output,
                "{} {} {}",
                "Binary file".bold(),
                new_label.cyan(),
                "to be added".green()
            );
            return Ok(output);
        }
        return Ok(format_new_file(
            &old_label,
            &new_label,
            &source_content,
            source_mode,
        ));
    }

    // Get destination content and mode
    let dest_content = fs::read(dest_path.as_path())
        .with_context(|| format!("Failed to read destination file: {dest_path}"))?;

    #[cfg(unix)]
    let dest_mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(dest_path.as_path())
            .ok()
            .map(|m| m.permissions().mode())
    };
    #[cfg(not(unix))]
    let dest_mode: Option<u32> = None;

    // Check if mode differs (compare only permission bits, not file type)
    let mode_differs = if let Some(src_mode) = source_mode {
        if let Some(dst_mode) = dest_mode {
            // Mask to get only permission bits (lower 12 bits)
            (src_mode & PERM_MASK) != (dst_mode & PERM_MASK)
        } else {
            true // dest doesn't have mode
        }
    } else {
        false // source doesn't specify mode
    };

    // Check if binary
    if is_binary(&source_content) || is_binary(&dest_content) {
        if source_content != dest_content || mode_differs {
            stats.inc_modified();
            let mut output = String::new();

            // File headers with mode
            // If source doesn't specify mode, inherit from dest
            let effective_source_mode = source_mode.or(dest_mode);
            let old_mode_str = format_file_mode(dest_mode);
            let new_mode_str = format_file_mode(effective_source_mode);

            let _ = writeln!(
                output,
                "{} {}",
                format!("--- {old_label}").bold(),
                old_mode_str.dimmed()
            );
            let _ = writeln!(
                output,
                "{} {}",
                format!("+++ {new_label}").bold(),
                new_mode_str.dimmed()
            );

            // Binary files message at the end
            let _ = writeln!(
                output,
                "{} {} and {} differ",
                "Binary files".bold(),
                old_label.dimmed(),
                new_label.cyan()
            );
            return Ok(output);
        }
        stats.inc_unchanged();
        return Ok(String::new());
    }

    // Generate text diff
    let source_str = String::from_utf8_lossy(&source_content);
    let dest_str = String::from_utf8_lossy(&dest_content);
    let content_differs = source_str != dest_str;

    if !content_differs && !mode_differs {
        stats.inc_unchanged();
        return Ok(String::new());
    }

    stats.inc_modified();
    // If source doesn't specify mode, inherit from dest
    let effective_source_mode = source_mode.or(dest_mode);
    Ok(generate_unified_diff(
        &dest_str,
        &source_str,
        &old_label,
        &new_label,
        dest_mode,
        effective_source_mode,
    ))
}

/// Format file mode for display in file headers
fn format_file_mode(mode: Option<u32>) -> String {
    mode.map_or_else(String::new, |m| {
        // Ensure file type bits are included
        let mode_full = if m < 0o10000 { m | S_IFREG } else { m };
        format!("{mode_full:06o}")
    })
}

/// Check if content is binary
///
/// Uses a simple heuristic: checks for null bytes in the first 8KB of content.
/// This is a fast approximation that works well for most text vs binary detection.
fn is_binary(content: &[u8]) -> bool {
    content.iter().take(BINARY_CHECK_BYTES).any(|&b| b == 0)
}

/// Generate colored unified diff string using similar's native API
///
/// This function uses similar's `iter_all_changes()` to iterate through changes
/// and apply colors based on `ChangeTag` (Delete/Insert/Equal) instead of
/// parsing the diff string output. This avoids ambiguity when lines
/// naturally start with diff markers like "---".
fn generate_unified_diff(
    old: &str,
    new: &str,
    old_path: &str,
    new_path: &str,
    old_mode: Option<u32>,
    new_mode: Option<u32>,
) -> String {
    let mut output = String::new();

    let diff = TextDiff::from_lines(old, new);

    // Add file headers with mode
    let old_mode_str = format_file_mode(old_mode);
    let new_mode_str = format_file_mode(new_mode);

    let _ = writeln!(
        output,
        "{} {}",
        format!("--- {old_path}").bold(),
        old_mode_str.dimmed()
    );
    let _ = writeln!(
        output,
        "{} {}",
        format!("+++ {new_path}").bold(),
        new_mode_str.dimmed()
    );

    // Hunk body shared with the hook script renderer (`generate_text_diff`)
    // so file and hook diffs stay visually identical.
    output.push_str(&render_diff_hunks(&diff));

    output
}

/// Render a line diff as git-style hunks: up to 3 lines of context around
/// each change, `@@` hunk headers, and a blank line between hunks. Unchanged
/// regions far from any change are omitted, like `git diff`.
///
/// Shared by the file renderer (`generate_unified_diff`) and the hook script
/// renderer (`generate_text_diff`); line coloring matches `ChangeTag` instead
/// of parsing string output, which avoids ambiguity when lines naturally
/// start with diff markers like `---`.
fn render_diff_hunks(diff: &TextDiff<'_, '_, str>) -> String {
    let mut output = String::new();

    for (idx, group) in diff.grouped_ops(3).iter().enumerate() {
        if idx > 0 {
            output.push('\n'); // Add blank line between hunks
        }

        // Compute hunk header ranges from operations
        let first_op = &group[0];
        let last_op = &group[group.len() - 1];

        let old_start = first_op.old_range().start;
        let new_start = first_op.new_range().start;
        let old_end = last_op.old_range().end;
        let new_end = last_op.new_range().end;

        let _ = writeln!(
            output,
            "{}",
            format!(
                "@@ -{},{} +{},{} @@",
                old_start + 1,
                old_end - old_start,
                new_start + 1,
                new_end - new_start
            )
            .cyan()
        );

        // Add changes using iter_changes to get proper change tags
        for op in group {
            for change in diff.iter_changes(op) {
                let sign = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                let line = format!("{}{}", sign, change.value());
                let colored_line = match change.tag() {
                    ChangeTag::Delete => line.red().to_string(),
                    ChangeTag::Insert => line.green().to_string(),
                    ChangeTag::Equal => line,
                };
                let _ = write!(output, "{colored_line}");

                if !change.value().ends_with('\n') {
                    output.push('\n');
                }
            }
        }
    }

    output
}

/// Format a new file for diff output
fn format_new_file(new_label: &str, _old_label: &str, content: &[u8], mode: Option<u32>) -> String {
    let content_str = String::from_utf8_lossy(content);
    let mut output = String::new();

    // Add file header with mode
    let effective_mode = mode.or(Some(DEFAULT_FILE_MODE));
    let mode_str = format_file_mode(effective_mode);

    let _ = writeln!(
        output,
        "{} {}",
        format!("+++ {new_label}").bold(),
        mode_str.dimmed()
    );

    // Add hunk header
    let line_count = content_str.lines().count();
    let _ = writeln!(output, "{}", format!("@@ -0,0 +1,{line_count} @@").cyan());

    // Add content as additions
    for line in content_str.lines() {
        let _ = writeln!(output, "{}", format!("+{line}").green());
    }

    output
}

/// Use pager for output if available
fn maybe_use_pager(output: &str, _config: &Config) -> Result<()> {
    // Try to use pager from environment
    let pager = Env::system().get("PAGER").unwrap_or_else(|| {
        #[cfg(unix)]
        {
            "less -R".to_string()
        }
        #[cfg(windows)]
        {
            "more".to_string()
        }
    });

    let mut parts = pager.split_whitespace();
    let cmd = parts.next().unwrap_or("less");
    let args: Vec<_> = parts.collect();

    match ProcessCommand::new(cmd)
        .args(&args)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                // Output already contains ANSI color codes, write it directly
                let _ = stdin.write_all(output.as_bytes());
            }
            child.wait()?;
        }
        Err(_) => {
            // Fallback to direct print if pager fails
            print!("{output}");
        }
    }

    Ok(())
}

/// Print statistics summary
fn print_stats(stats: &DiffStats) {
    let added = stats.added();
    let modified = stats.modified();
    let unchanged = stats.unchanged();
    let errors = stats.errors();

    if added == 0 && modified == 0 && errors == 0 {
        return;
    }

    println!("{}", "Summary:".bold());
    if added > 0 {
        println!(
            "  {} {} to be added",
            added.to_string().green(),
            if added == 1 { "file" } else { "files" }
        );
    }
    if modified > 0 {
        println!(
            "  {} {} to be modified",
            modified.to_string().yellow(),
            if modified == 1 { "file" } else { "files" }
        );
    }
    if unchanged > 0 {
        println!(
            "  {} {} unchanged",
            unchanged.to_string().dimmed(),
            if unchanged == 1 { "file" } else { "files" }
        );
    }
    if errors > 0 {
        println!(
            "  {} {} with errors (check warnings above)",
            errors.to_string().red(),
            if errors == 1 { "file" } else { "files" }
        );

        // Show unified help message for decryption errors
        println!("\n{}", "Common fixes for decryption errors:".yellow());
        println!("  1. Ensure you're using the correct age identity");
        println!("  2. Check if files were encrypted with a different key");
        println!("  3. Re-encrypt if needed:  guisu edit <file>");
    }
}

/// Print cmd changes between hooks
fn print_cmd_changes(old_cmd: Option<&str>, new_cmd: Option<&str>) {
    if old_cmd == new_cmd {
        return;
    }

    match (old_cmd, new_cmd) {
        (Some(old), Some(new)) => {
            println!("    {} cmd changed:", "~".yellow().bold());
            let diff_output = generate_text_diff(old, new);
            for line in diff_output.lines() {
                println!("      {line}");
            }
        }
        (Some(old), None) => {
            println!("    {} cmd removed:", "-".red().bold());
            for line in old.lines() {
                println!("      - {}", line.red());
            }
        }
        (None, Some(new)) => {
            println!("    {} cmd added:", "+".green().bold());
            for line in new.lines() {
                println!("      + {}", line.green());
            }
        }
        (None, None) => {}
    }
}

/// Print script changes between hooks.
///
/// Script bodies are resolved once up front by `HookBodies` and carried on
/// the change — display code no longer re-renders per hook.
fn print_script_changes(
    prev: &guisu_engine::hooks::Hook,
    current: &guisu_engine::hooks::Hook,
    previous_body: Option<&str>,
    current_body: Option<&str>,
) {
    // For non-template scripts with the same path, we can do an early return if
    // content is identical. For template scripts, we need the rendered-content
    // compare since dependencies might have changed.
    let is_template = current
        .script
        .as_deref()
        .is_some_and(guisu_engine::hooks::is_template_script);

    if !is_template
        && current.script == prev.script
        && current.script_content == prev.script_content
    {
        return;
    }

    if current.script != prev.script {
        print_script_path_change(prev, current, previous_body, current_body);
    } else if let Some(script) = &current.script {
        // Same script path - compare rendered content to also catch changes
        // in template dependencies
        if let (Some(old), Some(new)) = (previous_body, current_body)
            && old != new
        {
            let display_script = display_script_name(script);
            println!(
                "    {} script content changed: {}",
                "~".yellow().bold(),
                display_script
            );

            let diff_output = generate_text_diff(old, new);
            for line in diff_output.lines() {
                println!("      {line}");
            }
        }
    }
}

/// Print the diff when the resolved script path changed.
fn print_script_path_change(
    prev: &guisu_engine::hooks::Hook,
    current: &guisu_engine::hooks::Hook,
    previous_body: Option<&str>,
    current_body: Option<&str>,
) {
    match (&prev.script, &current.script) {
        (Some(old_script), Some(new_script)) if old_script != new_script => {
            let display_old = display_script_name(old_script);
            let display_new = display_script_name(new_script);
            if display_old == display_new {
                // Only the .j2 suffix differs (e.g. the script became a
                // template) — the script itself did not move, so show a
                // content diff instead of a no-op rename.
                match (previous_body, current_body) {
                    (Some(old), Some(new)) if old != new => {
                        println!(
                            "    {} script content changed: {}",
                            "~".yellow().bold(),
                            display_new
                        );
                        let diff_output = generate_text_diff(old, new);
                        for line in diff_output.lines() {
                            println!("      {line}");
                        }
                    }
                    (Some(_), Some(_)) => {
                        // Cosmetic .j2 change only; nothing to show.
                    }
                    _ => {
                        // Old content unavailable; fall back to the arrow.
                        println!(
                            "    {} script: {} -> {}",
                            "~".yellow().bold(),
                            display_old.red(),
                            display_new.green()
                        );
                    }
                }
            } else {
                println!(
                    "    {} script: {} -> {}",
                    "~".yellow().bold(),
                    display_old.red(),
                    display_new.green()
                );
                if let (Some(old), Some(new)) = (previous_body, current_body) {
                    let diff_output = generate_text_diff(old, new);
                    for line in diff_output.lines() {
                        println!("      {line}");
                    }
                }
            }
        }
        (Some(old_script), None) => {
            let display_old = display_script_name(old_script);
            println!(
                "    {} script removed: {}",
                "-".red().bold(),
                display_old.red()
            );
            if let Some(old) = previous_body {
                for line in old.lines() {
                    println!("      - {}", line.red());
                }
            }
        }
        (None, Some(new_script)) => {
            let display_new = display_script_name(new_script);
            println!(
                "    {} script added: {}",
                "+".green().bold(),
                display_new.green()
            );
            if let Some(new) = current_body {
                for line in new.lines() {
                    println!("      + {}", line.green());
                }
            }
        }
        _ => {}
    }
}

/// Print other attribute changes (order, mode)
fn print_other_changes(prev: &guisu_engine::hooks::Hook, current: &guisu_engine::hooks::Hook) {
    if current.order != prev.order {
        println!(
            "    {} order: {} -> {}",
            "~".yellow(),
            prev.order.to_string().red(),
            current.order.to_string().green()
        );
    }
    if current.mode != prev.mode {
        println!(
            "    {} mode: {:?} -> {:?}",
            "~".yellow(),
            format!("{:?}", prev.mode).red(),
            format!("{:?}", current.mode).green()
        );
    }
}

/// Print one hook change detected by [`guisu_engine::hooks::diff_collections`].
fn print_hook_change(change: &guisu_engine::hooks::HookChange<'_>, stage: &str) {
    use guisu_engine::hooks::HookChange;

    match change {
        HookChange::Added {
            current,
            current_body,
        } => {
            println!();
            println!("  {} hook: {}", stage, current.name.green());
            if let Some(ref cmd) = current.cmd {
                println!("    {} cmd:", "+".bold());
                for line in cmd.lines() {
                    println!("      + {}", line.green());
                }
            } else if let Some(ref script) = current.script {
                println!("    {} script: {}", "+".bold(), display_script_name(script));
                if let Some(body) = current_body {
                    for line in body.lines() {
                        println!("      + {}", line.green());
                    }
                }
            }
        }
        HookChange::Removed {
            previous,
            previous_body,
        } => {
            println!();
            println!("  {} hook: {}", stage, previous.name.red());
            if let Some(ref cmd) = previous.cmd {
                println!("    {} cmd:", "-".red().bold());
                for line in cmd.lines() {
                    println!("      {} {}", "-".red(), line.red());
                }
            } else if let Some(ref script) = previous.script {
                println!(
                    "    {} script: {}",
                    "-".red().bold(),
                    display_script_name(script).red()
                );
                if let Some(body) = previous_body {
                    for line in body.lines() {
                        println!("      {} {}", "-".red(), line.red());
                    }
                }
            }
        }
        HookChange::Modified {
            previous,
            current,
            previous_body,
            current_body,
        } => {
            println!();
            println!("  {} hook: {}", stage, current.name.yellow());

            print_cmd_changes(previous.cmd.as_deref(), current.cmd.as_deref());
            print_script_changes(
                previous,
                current,
                previous_body.as_deref(),
                current_body.as_deref(),
            );
            print_other_changes(previous, current);
        }
    }
}

/// Generate unified diff for text content
fn generate_text_diff(old: &str, new: &str) -> String {
    let diff = TextDiff::from_lines(old, new);
    render_diff_hunks(&diff)
}

/// Check and print hooks status
/// Returns true if any hooks were displayed
fn print_hooks_status(source_dir: &Path, config: &Config, db: &mut dyn PersistentState) -> bool {
    use guisu_core::platform::CURRENT_PLATFORM;

    // Load hooks and state using the shared engine helper
    let Some((collections, state)) = guisu_engine::hooks::load_for_comparison(source_dir, db)
    else {
        return false;
    };

    // Only compare if we have last_collections to compare against.
    // This handles both file system changes and template rendering changes
    // (e.g., when Brewfile changes).
    let Some(last) = &state.last_collections else {
        return false;
    };

    let platform = CURRENT_PLATFORM.os;
    let bodies = crate::utils::hooks::HookBodies::with_fallback(source_dir, config);
    let mut any_hooks_printed = false;

    for (stage, current, previous) in [
        ("pre", &collections.pre, &last.pre),
        ("post", &collections.post, &last.post),
    ] {
        if current.is_empty() && previous.is_empty() {
            continue;
        }
        let changes = guisu_engine::hooks::diff_collections(
            current,
            previous,
            platform,
            &bodies.current_bodies(current.iter()),
            &bodies.previous_bodies(previous.iter(), &state.onchange_rendered),
        );
        for change in &changes {
            print_hook_change(change, stage);
            any_hooks_printed = true;
        }
    }

    // Add blank line after hooks only if we printed something
    if any_hooks_printed {
        println!();
    }

    // Note: We do NOT update database state here because `diff` is a read-only command.
    // State updates should only happen during `apply` or `hooks run` commands.
    // This prevents state pollution from read-only operations.

    any_hooks_printed
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for DiffCommand structure

    #[test]
    fn test_diff_command_default() {
        let cmd = DiffCommand {
            files: vec![],
            pager: false,
            interactive: false,
        };

        assert_eq!(cmd.files, [] as [std::path::PathBuf; 0]);
        assert!(!cmd.pager);
        assert!(!cmd.interactive);
    }

    #[test]
    fn test_diff_command_with_files() {
        let cmd = DiffCommand {
            files: vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")],
            pager: false,
            interactive: false,
        };

        assert_eq!(cmd.files.len(), 2);
        assert_eq!(cmd.files[0], PathBuf::from("file1.txt"));
        assert_eq!(cmd.files[1], PathBuf::from("file2.txt"));
    }

    #[test]
    fn test_diff_command_with_pager() {
        let cmd = DiffCommand {
            files: vec![],
            pager: true,
            interactive: false,
        };

        assert!(cmd.pager);
        assert!(!cmd.interactive);
    }

    #[test]
    fn test_diff_command_with_interactive() {
        let cmd = DiffCommand {
            files: vec![],
            pager: false,
            interactive: true,
        };

        assert!(!cmd.pager);
        assert!(cmd.interactive);
    }

    // Tests for is_binary

    #[test]
    fn test_is_binary_text_content() {
        let content = b"This is plain text content\nwith multiple lines\n";
        assert!(!is_binary(content));
    }

    #[test]
    fn test_is_binary_with_null_bytes() {
        let content = b"Some text\0with null bytes";
        assert!(is_binary(content));
    }

    #[test]
    fn test_is_binary_empty() {
        let content = b"";
        assert!(!is_binary(content));
    }

    #[test]
    fn test_is_binary_utf8() {
        let content = "Hello World".as_bytes();
        assert!(!is_binary(content));
    }

    #[test]
    fn test_is_binary_null_at_end() {
        let mut content = b"Normal text".to_vec();
        content.push(0);
        assert!(is_binary(&content));
    }

    #[test]
    fn test_is_binary_large_text() {
        // Create content larger than 8KB with no null bytes
        let content = "a".repeat(10000);
        assert!(!is_binary(content.as_bytes()));
    }

    #[test]
    fn test_is_binary_null_after_8kb() {
        // Null byte after 8KB threshold should not be detected
        let mut content = "a".repeat(9000);
        content.push('\0');
        // is_binary only checks first 8000 bytes
        assert!(!is_binary(content.as_bytes()));
    }

    // Tests for generate_unified_diff

    #[test]
    fn test_generate_unified_diff_no_changes() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nline2\nline3\n";

        let result = generate_unified_diff(old, new, "a/file", "b/file", None, None);

        // No hunks when files are identical, but headers are still present
        assert!(result.contains("--- a/file"));
        assert!(result.contains("+++ b/file"));
        assert!(!result.contains("@@")); // No hunk headers
    }

    #[test]
    fn test_generate_unified_diff_added_line() {
        let old = "line1\nline2\n";
        let new = "line1\nline2\nline3\n";

        let result = generate_unified_diff(old, new, "a/file", "b/file", None, None);

        // Check for headers and content (output contains ANSI color codes)
        assert!(result.contains("--- a/file"));
        assert!(result.contains("+++ b/file"));
        assert!(result.contains("line3")); // Content is there, regardless of color codes
    }

    #[test]
    fn test_generate_unified_diff_removed_line() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nline3\n";

        let result = generate_unified_diff(old, new, "a/file", "b/file", None, None);

        // Check for headers and content (output contains ANSI color codes)
        assert!(result.contains("--- a/file"));
        assert!(result.contains("+++ b/file"));
        assert!(result.contains("line2")); // Content is there, regardless of color codes
    }

    #[test]
    fn test_generate_unified_diff_modified_line() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nmodified\nline3\n";

        let result = generate_unified_diff(old, new, "a/file", "b/file", None, None);

        // Check for headers and content (output contains ANSI color codes)
        assert!(result.contains("--- a/file"));
        assert!(result.contains("+++ b/file"));
        assert!(result.contains("line2")); // Old content
        assert!(result.contains("modified")); // New content
    }

    #[test]
    fn test_generate_unified_diff_with_mode_change() {
        let old = "content\n";
        let new = "content\n";

        let result = generate_unified_diff(
            old,
            new,
            "a/file",
            "b/file",
            Some(DEFAULT_FILE_MODE),
            Some(DEFAULT_EXEC_MODE),
        );

        // Should include mode in file headers
        assert!(result.contains("--- a/file"));
        assert!(result.contains("100644"));
        assert!(result.contains("+++ b/file"));
        assert!(result.contains("100755"));
    }

    #[test]
    fn test_generate_unified_diff_mode_no_change() {
        let old = "content\n";
        let new = "content\n";

        let result = generate_unified_diff(old, new, "a/file", "b/file", Some(0o755), Some(0o755));

        // Should not include mode diff when same
        assert!(!result.contains("old mode"));
    }

    #[test]
    fn test_generate_unified_diff_empty_to_content() {
        let old = "";
        let new = "new content\n";

        let result = generate_unified_diff(old, new, "a/file", "b/file", None, None);

        // Check for headers and content (output contains ANSI color codes)
        assert!(result.contains("--- a/file"));
        assert!(result.contains("+++ b/file"));
        assert!(result.contains("new content")); // Content is there, regardless of color codes
    }

    #[test]
    fn test_generate_unified_diff_content_to_empty() {
        let old = "old content\n";
        let new = "";

        let result = generate_unified_diff(old, new, "a/file", "b/file", None, None);

        // Check for headers and content (output contains ANSI color codes)
        assert!(result.contains("--- a/file"));
        assert!(result.contains("+++ b/file"));
        assert!(result.contains("old content")); // Content is there, regardless of color codes
    }

    // Tests for format_new_file

    #[test]
    fn test_format_new_file_simple() {
        let content = b"line1\nline2\n";

        let result = format_new_file("b/test.txt", "a/test.txt", content, None);

        // Output contains ANSI color codes, check for plain content
        assert!(result.contains("+++ b/test.txt"));
        assert!(result.contains("line1")); // Content without sign
        assert!(result.contains("line2"));
    }

    #[test]
    fn test_format_new_file_with_mode() {
        let content = b"#!/bin/bash\necho hello\n";

        let result = format_new_file("b/script.sh", "a/script.sh", content, Some(0o755));

        // Output contains ANSI color codes, check for plain content
        assert!(result.contains("+++ b/script.sh"));
        assert!(result.contains("100755")); // Mode in header (0o755 becomes 0o100755 with S_IFREG)
        assert!(result.contains("#!/bin/bash")); // Content without sign
        assert!(result.contains("echo hello"));
    }

    #[test]
    fn test_format_new_file_empty() {
        let content = b"";

        let result = format_new_file("b/empty.txt", "a/empty.txt", content, None);

        assert!(result.contains("+++ b/empty.txt"));
        assert!(result.contains("@@ -0,0 +1,0 @@"));
    }

    #[test]
    fn test_format_new_file_single_line() {
        let content = b"single line";

        let result = format_new_file("b/single.txt", "a/single.txt", content, None);

        assert!(result.contains("+++ b/single.txt"));
        assert!(result.contains("@@ -0,0 +1,1 @@"));
        assert!(result.contains("+single line"));
    }

    #[test]
    fn test_format_new_file_line_count() {
        let content = b"line1\nline2\nline3\nline4\nline5\n";

        let result = format_new_file("b/multi.txt", "a/multi.txt", content, None);

        // Should show correct line count in hunk header
        assert!(result.contains("@@ -0,0 +1,5 @@"));
    }

    // Tests for generate_text_diff (git-style hunked output via
    // render_diff_hunks, shared with the file renderer)

    #[test]
    fn test_generate_text_diff_no_change() {
        let old = "line1\nline2\n";
        let new = "line1\nline2\n";

        let result = generate_text_diff(old, new);

        // Identical content produces no hunks
        assert_eq!(result, "");
    }

    #[test]
    fn test_generate_text_diff_addition() {
        let old = "line1\n";
        let new = "line1\nline2\n";

        let result = generate_text_diff(old, new);

        assert!(result.contains("@@"));
        assert!(result.contains(" line1\n")); // context
        assert!(result.contains("+line2\n"));
        assert!(!result.contains("-line1"));
    }

    #[test]
    fn test_generate_text_diff_deletion() {
        let old = "line1\nline2\n";
        let new = "line1\n";

        let result = generate_text_diff(old, new);

        assert!(result.contains(" line1\n")); // context
        assert!(result.contains("-line2\n"));
    }

    #[test]
    fn test_generate_text_diff_modification() {
        let old = "line1\nold line\nline3\n";
        let new = "line1\nnew line\nline3\n";

        let result = generate_text_diff(old, new);

        assert!(result.contains("-old line\n"));
        assert!(result.contains("+new line\n"));
        assert!(result.contains(" line1\n")); // context
        assert!(result.contains(" line3\n")); // context
    }

    #[test]
    fn test_generate_text_diff_empty_old() {
        let old = "";
        let new = "new content\n";

        let result = generate_text_diff(old, new);

        assert!(result.contains("+new content\n"));
    }

    #[test]
    fn test_generate_text_diff_empty_new() {
        let old = "old content\n";
        let new = "";

        let result = generate_text_diff(old, new);

        assert!(result.contains("-old content\n"));
    }

    #[test]
    fn test_generate_text_diff_multiple_changes() {
        let old = "keep1\nremove\nkeep2\nmodify_old\n";
        let new = "keep1\nkeep2\nmodify_new\nadd\n";

        let result = generate_text_diff(old, new);

        assert!(result.contains("-remove\n"));
        assert!(result.contains("+modify_new\n"));
        assert!(result.contains("+add\n"));
        assert!(result.contains(" keep2\n")); // shared context
    }

    #[test]
    fn test_generate_text_diff_omits_distant_context() {
        // Unchanged lines far from any change are not printed, like git diff
        let old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nold tail\n";
        let new = "a\nb\nc\nd\ne\nf\ng\nh\ni\nnew tail\n";

        let result = generate_text_diff(old, new);

        assert!(result.contains("-old tail\n"));
        assert!(result.contains("+new tail\n"));
        assert!(!result.contains(" a\n"));
        assert!(result.contains(" g\n")); // only nearby context survives
    }

    #[test]
    fn test_is_binary_png() {
        // Binary content with null bytes (PNG header)
        let content = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

        // Verify content is detected as binary
        assert!(is_binary(content));
    }
}
