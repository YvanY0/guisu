//! Status command implementation
//!
//! Show status of managed files with multiple output formats.

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::{AbsPath, RelPath};
use guisu_engine::adapters::crypto::CryptoDecryptorAdapter;
use guisu_engine::adapters::template::TemplateRendererAdapter;
use guisu_engine::entry::TargetEntry;
use guisu_engine::processor::ContentProcessor;
use guisu_engine::state::{DestinationState, RedbPersistentState, SourceState, TargetState};
use guisu_engine::system::RealSystem;
use owo_colors::OwoColorize;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

use crate::command::Command;
use crate::common::RuntimeContext;
use crate::conflict::{ThreeWayComparisonResult, compare_three_way};
use crate::ui::icons::{FileIconInfo, icon_for_file};
use crate::utils::path::SourceDirExt;
use guisu_config::Config;
use lscolors::{LsColors, Style};
use nu_ansi_term::Style as AnsiStyle;

/// Output format for status command
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    /// Simple list format
    Simple,
    /// Tree structure format
    Tree,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "simple" => Ok(OutputFormat::Simple),
            "tree" => Ok(OutputFormat::Tree),
            _ => anyhow::bail!("Invalid output format: {s}. Use 'simple' or 'tree'"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum FileStatus {
    /// File exists in source but not in dest (pending deployment)
    Latent,
    /// Destination is ahead of source (local modifications)
    Ahead,
    /// Source is ahead of destination (source updates)
    Behind,
    /// Both have changes (conflicting changes)
    Conflict,
    /// Files are in steady state (fully synced)
    Steady,
}

impl FileStatus {
    fn label(&self) -> &str {
        match self {
            FileStatus::Latent => "[L]",
            FileStatus::Ahead => "[A]",
            FileStatus::Behind => "[B]",
            FileStatus::Conflict => "[C]",
            FileStatus::Steady => "[S]",
        }
    }

    fn full_name(&self) -> &str {
        match self {
            FileStatus::Latent => "[L]atent",
            FileStatus::Ahead => "[A]head",
            FileStatus::Behind => "[B]ehind",
            FileStatus::Conflict => "[C]onflict",
            FileStatus::Steady => "[S]teady",
        }
    }

    fn color_str(self, text: &str) -> String {
        match self {
            FileStatus::Latent => text.bright_green().to_string(), // Green: pending deployment
            FileStatus::Behind => text.bright_yellow().to_string(), // Yellow: needs update
            FileStatus::Ahead => text.bright_cyan().to_string(),   // Cyan: local changes
            FileStatus::Conflict => text.bright_red().to_string(), // Red: conflict
            FileStatus::Steady => text.bright_blue().to_string(),  // Blue: steady
        }
    }
}

/// Complete file information for display
#[derive(Debug)]
struct FileInfo {
    path: String,
    status: FileStatus,
    file_type: char,
}

impl FileInfo {
    fn status_str(&self) -> String {
        let label = self.status.label();
        self.status.color_str(label)
    }
}

/// Status command
#[derive(Args)]
pub struct StatusCommand {
    /// Specific files to check (all if not specified)
    pub files: Vec<PathBuf>,

    /// Show all files including synced ones
    #[arg(short, long)]
    pub all: bool,

    /// Display output in tree format
    #[arg(long)]
    pub tree: bool,
}

impl Command for StatusCommand {
    type Output = ();
    fn execute(&self, context: &RuntimeContext) -> crate::error::Result<()> {
        let output_format = if self.tree {
            OutputFormat::Tree
        } else {
            OutputFormat::Simple
        };
        run_impl(
            context.database(),
            context.source_dir(),
            context.dest_dir().as_path(),
            &context.config,
            &self.files,
            self.all,
            output_format,
        )
        .map_err(Into::into)
    }
}

/// Build target state from source state for status command
fn build_status_target_state(
    source_state: &SourceState,
    processor: &ContentProcessor<CryptoDecryptorAdapter, TemplateRendererAdapter>,
    template_ctx_value: &serde_json::Value,
    filter_paths: Option<&Vec<RelPath>>,
    identities: &[guisu_crypto::Identity],
) -> TargetState {
    use guisu_engine::entry::SourceEntry;

    let mut target_state = TargetState::new();

    for source_entry in source_state.entries() {
        let target_path = source_entry.target_path();

        // If filtering, skip entries not in the filter
        if let Some(filter) = filter_paths
            && !filter.iter().any(|p| p == target_path)
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
                        let content_hash = guisu_engine::hash::hash_content(&content);
                        target_state.add(TargetEntry::File {
                            path: target_path.clone(),
                            content,
                            content_hash,
                            mode,
                        });
                    }
                    Err(e) => {
                        debug!(
                            "Warning: Failed to process {}: {}",
                            target_path.as_path().display(),
                            e
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

/// Run the status command implementation
fn run_impl(
    database: &std::sync::Arc<guisu_engine::state::RedbPersistentState>,
    source_dir: &Path,
    dest_dir: &Path,
    config: &Config,
    files: &[PathBuf],
    show_all: bool,
    output_format: OutputFormat,
) -> Result<()> {
    // Initialize lscolors from environment
    let lscolors = LsColors::from_env().unwrap_or_default();

    // Resolve all paths (handles root_entry and canonicalization)
    let paths = crate::common::ResolvedPaths::resolve(source_dir, dest_dir, config)?;
    let source_abs = &paths.dotfiles_dir;
    let dest_abs = &paths.dest_dir;

    // Load metadata for create-once tracking
    let metadata =
        guisu_engine::state::Metadata::load(source_dir).context("Failed to load metadata")?;

    // Create ignore matcher from .guisu/ignores.toml
    // Use dotfiles_dir as the match root so patterns match relative to the dotfiles directory
    let ignore_matcher = guisu_config::IgnoreMatcher::from_ignores_toml(source_dir)
        .context("Failed to load ignore patterns from .guisu/ignores.toml")?;

    // Read source state with ignore matcher from config
    let source_state =
        SourceState::read(source_abs.to_owned()).context("Failed to read source state")?;

    if source_state.is_empty() {
        return Ok(());
    }

    // Load age identities for decryption
    let identities = std::sync::Arc::new(config.age_identities().unwrap_or_default());

    // Load variables from .guisu/variables/ directory
    let guisu_dir = source_dir.guisu_dir();
    let platform_name = guisu_core::platform::CURRENT_PLATFORM.os;

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
    // Use Arc to share identity without unnecessary cloning
    let identity_arc = identities.first().map_or_else(
        || Arc::new(guisu_crypto::Identity::generate()),
        |id| Arc::new(id.clone()),
    );
    let decryptor = CryptoDecryptorAdapter::from_arc(identity_arc);
    let renderer = TemplateRendererAdapter::new(template_engine);
    let processor = ContentProcessor::new(decryptor, renderer);

    // Build filter paths if specific files were requested
    let filter_paths = if files.is_empty() {
        None
    } else {
        let paths = crate::build_filter_paths(files, dest_abs)?;
        // Check if any files match
        let has_matches = source_state
            .entries()
            .any(|entry| paths.iter().any(|p| p == entry.target_path()));

        if !has_matches {
            println!("No matching files found.");
            return Ok(());
        }
        Some(paths)
    };

    // Build target state (processes templates and decrypts files)
    // Process files one by one to handle errors gracefully
    // Create template context with system variables and guisu info
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

    let target_state = build_status_target_state(
        &source_state,
        &processor,
        &template_ctx_value,
        filter_paths.as_ref(),
        &identities,
    );

    // Read destination state
    let mut dest_state = DestinationState::new(dest_abs.to_owned());
    let system = RealSystem;

    // Collect file information
    let file_infos = collect_file_info(CollectParams {
        database,
        source_state: &source_state,
        target_state: &target_state,
        dest_state: &mut dest_state,
        system: &system,
        dest_root: dest_abs,
        metadata: &metadata,
        filter_paths: filter_paths.as_ref(),
        ignore_matcher: &ignore_matcher,
    });

    // Check if we're viewing a single file (don't show summary header)
    let is_single_file = !files.is_empty() && files.len() == 1;

    // Detect if output is to a terminal for icon auto mode
    let is_tty = std::io::stdout().is_terminal();
    let show_icons = config.ui.icons.should_show_icons(is_tty);

    // Render output based on format
    match output_format {
        OutputFormat::Simple => {
            render_simple(&file_infos, show_all, is_single_file, &lscolors, show_icons);
        }
        OutputFormat::Tree => {
            render_tree(&file_infos, show_all, is_single_file, &lscolors, show_icons);
        }
    }

    // Check and display hooks status
    print_hooks_status(source_dir, database, show_all, config);

    Ok(())
}

/// Parameters for collecting file information
struct CollectParams<'a> {
    database: &'a std::sync::Arc<guisu_engine::state::RedbPersistentState>,
    source_state: &'a SourceState,
    target_state: &'a TargetState,
    dest_state: &'a mut DestinationState,
    system: &'a RealSystem,
    dest_root: &'a AbsPath,
    metadata: &'a guisu_engine::state::Metadata,
    filter_paths: Option<&'a Vec<RelPath>>,
    ignore_matcher: &'a guisu_config::IgnoreMatcher,
}

/// Get file type character from source entry
fn get_entry_file_type(entry: &guisu_engine::entry::SourceEntry) -> char {
    use guisu_engine::entry::SourceEntry;
    match entry {
        SourceEntry::File { .. } => 'F',
        SourceEntry::Directory { .. } => 'D',
        SourceEntry::Symlink { .. } => 'L',
    }
}

/// Format path for display with ~/ prefix if under home directory
fn format_display_path(dest_root: &AbsPath, target_path: &RelPath) -> String {
    let full_dest_path = dest_root.join(target_path);
    if let Some(home_dir) = dirs::home_dir() {
        // If path is under home, show as ~/relative/path
        if let Ok(rel_path) = full_dest_path.as_path().strip_prefix(&home_dir) {
            format!("~/{}", rel_path.display())
        } else {
            full_dest_path.as_path().display().to_string()
        }
    } else {
        full_dest_path.as_path().display().to_string()
    }
}

/// Determine file status based on three-way comparison
fn determine_entry_status(
    database: &std::sync::Arc<guisu_engine::state::RedbPersistentState>,
    target_entry: &TargetEntry,
    dest_entry: &guisu_engine::entry::DestEntry,
    path_str: &str,
) -> FileStatus {
    use guisu_engine::entry::TargetEntry;

    // Get the base state from database (last applied state)
    let base_state = guisu_engine::database::get_entry_state(database, path_str)
        .ok()
        .flatten();

    match target_entry {
        TargetEntry::File { content, mode, .. } => {
            // Compute hashes for three-way comparison
            use guisu_engine::state::hash_data;
            let source_hash = hash_data(content);
            let dest_hash = dest_entry.content.as_ref().map(|c| hash_data(c));

            // Check mode matches
            let mode_matches = if let Some(expected_mode) = mode {
                dest_entry.mode == Some(*expected_mode)
            } else {
                true
            };

            // Use unified three-way comparison
            let dest_hash_vec = dest_hash.unwrap_or_default();
            let base_hash = base_state.as_ref().map(|s| s.content_hash.as_slice());

            let comparison_result = compare_three_way(&source_hash, &dest_hash_vec, base_hash);

            // Map comparison result to file status
            match comparison_result {
                ThreeWayComparisonResult::NoChange | ThreeWayComparisonResult::Converged => {
                    if mode_matches {
                        FileStatus::Steady
                    } else {
                        FileStatus::Behind // Mode changed
                    }
                }
                ThreeWayComparisonResult::SourceChanged => FileStatus::Behind,
                ThreeWayComparisonResult::DestinationChanged => FileStatus::Ahead,
                ThreeWayComparisonResult::BothChanged => FileStatus::Conflict,
            }
        }
        TargetEntry::Directory { mode, .. } => {
            if let Some(expected_mode) = mode {
                if dest_entry.mode == Some(*expected_mode) {
                    FileStatus::Steady
                } else {
                    FileStatus::Behind
                }
            } else {
                FileStatus::Steady
            }
        }
        TargetEntry::Symlink { target, .. } => {
            if dest_entry.link_target.as_ref() == Some(target) {
                FileStatus::Steady
            } else {
                FileStatus::Behind
            }
        }
        TargetEntry::Remove { .. } => {
            // Remove entries should not be in status
            FileStatus::Behind
        }
        TargetEntry::Modify { .. } => {
            // Modify scripts are not displayed in status for now
            FileStatus::Steady
        }
    }
}

/// Process a single entry for status display
#[allow(clippy::too_many_arguments)]
fn process_entry_for_status(
    database: &std::sync::Arc<guisu_engine::state::RedbPersistentState>,
    entry: &guisu_engine::entry::SourceEntry,
    dest_state_mutex: &std::sync::Mutex<&mut DestinationState>,
    target_state: &TargetState,
    system: &RealSystem,
    dest_root: &AbsPath,
    metadata: &guisu_engine::state::Metadata,
    filter_paths: Option<&Vec<RelPath>>,
    ignore_matcher: &guisu_config::IgnoreMatcher,
) -> Option<FileInfo> {
    use guisu_engine::entry::EntryKind;

    let target_path = entry.target_path();

    // Skip if filtering and this file is not in the filter
    if let Some(filter) = filter_paths
        && !filter.iter().any(|p| p == target_path)
    {
        return None;
    }

    // Skip if file is ignored
    if ignore_matcher.is_ignored(target_path.as_path(), None) {
        return None;
    }

    let path_str = target_path.to_string();

    // Read destination entry (thread-safe via mutex)
    let dest_entry = {
        let mut dest_state = dest_state_mutex
            .lock()
            .expect("Destination state mutex poisoned");
        match dest_state
            .read(target_path, system)
            .context("Failed to read destination state")
        {
            Ok(entry) => entry.clone(), // Clone to release the lock quickly
            Err(e) => {
                debug!(
                    "Failed to read destination state for {}: {}",
                    target_path.as_path().display(),
                    e
                );
                return None;
            }
        }
    };

    // Handle create-once files that already exist - show as Steady
    if metadata.is_create_once(&path_str) && dest_entry.kind != EntryKind::Missing {
        let file_type = get_entry_file_type(entry);
        let display_path = format_display_path(dest_root, target_path);

        return Some(FileInfo {
            path: display_path,
            status: FileStatus::Steady,
            file_type,
        });
    }

    // Determine file type
    let file_type = get_entry_file_type(entry);

    // Determine status based on three-way comparison (Base, Source, Destination)
    let status = if dest_entry.kind == EntryKind::Missing {
        // Destination doesn't exist → Latent
        FileStatus::Latent
    } else {
        // Destination exists, do three-way comparison
        // Use target_state which has processed content (decrypted + rendered)
        let Some(target_entry) = target_state.get(target_path) else {
            // Target entry not found (likely due to template processing error)
            // Skip this file
            debug!(
                "Skipping {}: target entry not found in target state",
                target_path.as_path().display()
            );
            return None;
        };

        determine_entry_status(database, target_entry, &dest_entry, &path_str)
    };

    // Format path for display
    let display_path = format_display_path(dest_root, target_path);

    Some(FileInfo {
        path: display_path,
        status,
        file_type,
    })
}

/// Collect file information from source and destination states
fn collect_file_info(params: CollectParams) -> Vec<FileInfo> {
    use std::sync::Mutex;

    // Destructure params to avoid partial move issues
    let CollectParams {
        database,
        source_state,
        target_state,
        dest_state,
        system,
        dest_root,
        metadata,
        filter_paths,
        ignore_matcher,
    } = params;

    // Wrap dest_state in a Mutex for thread-safe access during parallel processing
    // The cache mutations are serialized, but hash computation (CPU-intensive) is still parallel
    let dest_state_mutex = Mutex::new(dest_state);

    // Use parallel processing for file info collection
    let files: Vec<FileInfo> = source_state
        .entries()
        .par_bridge()
        .filter_map(|entry| {
            process_entry_for_status(
                database,
                entry,
                &dest_state_mutex,
                target_state,
                system,
                dest_root,
                metadata,
                filter_paths,
                ignore_matcher,
            )
        })
        .collect();

    // Sort files by path for consistent output
    // Note: Parallel collect doesn't preserve order, so we sort after
    let mut files = files;
    files.sort_by(|a, b| a.path.cmp(&b.path));

    files
}

/// Format status line with counts and labels
fn format_status_line(items: &[(usize, FileStatus)]) -> String {
    items
        .iter()
        .map(|(count, status)| {
            format!(
                "{} {}",
                status.color_str(&count.to_string()).bold(),
                status.color_str(status.full_name())
            )
        })
        .collect::<Vec<_>>()
        .join(&format!(" {} ", "|".dimmed()))
}

/// Filter and sort files by status (exclude directories)
fn filter_files_by_status(files: &[FileInfo], status: FileStatus) -> Vec<&FileInfo> {
    let mut filtered: Vec<_> = files
        .iter()
        .filter(|f| f.status == status && f.file_type != 'D')
        .collect();
    filtered.sort_by(|a, b| a.path.cmp(&b.path));
    filtered
}

/// Display a list of files with icons and colors
fn display_file_list(files: &[&FileInfo], lscolors: &LsColors, use_nerd_fonts: bool, dimmed: bool) {
    for file in files {
        let icon = get_file_icon_for_info(file, use_nerd_fonts);
        let mut file_style = get_file_style(file, lscolors);
        if dimmed {
            file_style = file_style.dimmed();
        }

        if dimmed {
            println!(
                "  {}  {} {}",
                file.status_str(),
                file_style.paint(icon),
                file_style.paint(&file.path),
            );
        } else {
            println!(
                "  {}  {} {}",
                file.status_str().bold(),
                file_style.paint(icon),
                file_style.paint(&file.path),
            );
        }
    }
}

/// Render simple format (default)
fn render_simple(
    files: &[FileInfo],
    show_all: bool,
    is_single_file: bool,
    lscolors: &LsColors,
    use_nerd_fonts: bool,
) {
    // Group files by status (exclude directories from display)
    let latent = filter_files_by_status(files, FileStatus::Latent);
    let behind = filter_files_by_status(files, FileStatus::Behind);
    let ahead = filter_files_by_status(files, FileStatus::Ahead);
    let conflict = filter_files_by_status(files, FileStatus::Conflict);
    let steady = filter_files_by_status(files, FileStatus::Steady);

    // Print header with status counts (inline abbreviations)
    // Skip header for single file view
    if !is_single_file {
        println!();
    }

    if !is_single_file && show_all {
        let status_items = vec![
            (latent.len(), FileStatus::Latent),
            (ahead.len(), FileStatus::Ahead),
            (behind.len(), FileStatus::Behind),
            (conflict.len(), FileStatus::Conflict),
            (steady.len(), FileStatus::Steady),
        ];
        println!("  {}", format_status_line(&status_items));
    } else if !is_single_file {
        let status_items = vec![
            (latent.len(), FileStatus::Latent),
            (ahead.len(), FileStatus::Ahead),
            (behind.len(), FileStatus::Behind),
            (conflict.len(), FileStatus::Conflict),
        ];
        println!("  {}", format_status_line(&status_items));
    }

    if !is_single_file {
        println!();
    }

    // Show latent files (to deploy)
    display_file_list(&latent, lscolors, use_nerd_fonts, false);

    // Show ahead files (local changes)
    display_file_list(&ahead, lscolors, use_nerd_fonts, false);

    // Show behind files (need update from source)
    display_file_list(&behind, lscolors, use_nerd_fonts, false);

    // Show conflict files
    display_file_list(&conflict, lscolors, use_nerd_fonts, false);

    // Show steady files (if --all is specified OR viewing a single file)
    if show_all || is_single_file {
        display_file_list(&steady, lscolors, use_nerd_fonts, true);
    }

    if !is_single_file
        && (!latent.is_empty()
            || !ahead.is_empty()
            || !behind.is_empty()
            || !conflict.is_empty()
            || show_all)
    {
        println!();
    }
}

/// Tree node for nested directory structure
#[derive(Debug)]
enum TreeNode<'a> {
    File(&'a FileInfo),
    Directory {
        children: BTreeMap<String, TreeNode<'a>>,
    },
}

/// Get icon for file using the new icon system
fn get_file_icon_for_info(file: &FileInfo, use_nerd_fonts: bool) -> &'static str {
    let info = FileIconInfo {
        path: &file.path,
        is_directory: file.file_type == 'D',
        is_symlink: file.file_type == 'L',
    };

    icon_for_file(&info, use_nerd_fonts)
}

/// Get ANSI style for file based on its type and attributes
fn get_file_style(file: &FileInfo, lscolors: &LsColors) -> AnsiStyle {
    // Get style from lscolors based on file path and extension
    let style = lscolors.style_for_path(&file.path);

    // Convert to nu_ansi_term::Style
    style.map(Style::to_nu_ansi_term_style).unwrap_or_default()
}

/// Build nested tree structure from file list
fn build_tree<'a>(files: &[&'a FileInfo]) -> BTreeMap<String, TreeNode<'a>> {
    let mut root: BTreeMap<String, TreeNode> = BTreeMap::new();

    for file in files {
        let path_parts: Vec<&str> = file.path.split('/').collect();

        let mut current = &mut root;

        // Navigate/create directories
        for (i, &part) in path_parts.iter().enumerate() {
            if i == path_parts.len() - 1 {
                // Last part - this is the file
                current.insert(part.to_string(), TreeNode::File(file));
            } else {
                // Directory part
                current =
                    match current
                        .entry(part.to_string())
                        .or_insert_with(|| TreeNode::Directory {
                            children: BTreeMap::new(),
                        }) {
                        TreeNode::Directory { children } => children,
                        TreeNode::File(_) => {
                            unreachable!("Cannot navigate into a file as if it were a directory")
                        }
                    };
            }
        }
    }

    root
}

/// Render tree node recursively
fn render_tree_node(
    node: &TreeNode,
    name: &str,
    prefix: &str,
    is_last: bool,
    lscolors: &LsColors,
    use_nerd_fonts: bool,
) {
    let connector = if is_last { "└─" } else { "├─" };
    let new_prefix = if is_last { "  " } else { "│ " };

    match node {
        TreeNode::File(file) => {
            let icon = get_file_icon_for_info(file, use_nerd_fonts);
            let file_style = get_file_style(file, lscolors);

            println!(
                "{}{} {}  {} {}",
                prefix.dimmed(),
                connector.dimmed(),
                file.status_str().bold(),
                file_style.paint(icon),
                file_style.paint(name),
            );
        }
        TreeNode::Directory { children } => {
            // Print directory
            println!(
                "{}{}  {}",
                prefix.dimmed(),
                connector.dimmed(),
                name.bright_cyan().bold()
            );

            // Print children
            let child_count = children.len();
            for (idx, (child_name, child_node)) in children.iter().enumerate() {
                let is_last_child = idx == child_count - 1;
                render_tree_node(
                    child_node,
                    child_name,
                    &format!("{prefix}{new_prefix}"),
                    is_last_child,
                    lscolors,
                    use_nerd_fonts,
                );
            }
        }
    }
}

/// Render tree format
fn render_tree(
    files: &[FileInfo],
    show_all: bool,
    is_single_file: bool,
    lscolors: &LsColors,
    use_nerd_fonts: bool,
) {
    let latent = files
        .iter()
        .filter(|f| f.status == FileStatus::Latent)
        .count();
    let ahead = files
        .iter()
        .filter(|f| f.status == FileStatus::Ahead)
        .count();
    let behind = files
        .iter()
        .filter(|f| f.status == FileStatus::Behind)
        .count();
    let conflict = files
        .iter()
        .filter(|f| f.status == FileStatus::Conflict)
        .count();
    let steady = files
        .iter()
        .filter(|f| f.status == FileStatus::Steady)
        .count();

    // Print header with status counts (inline abbreviations)
    // Skip header for single file view
    if !is_single_file {
        println!();
    }

    if !is_single_file && show_all {
        let status_items = vec![
            (latent, FileStatus::Latent),
            (ahead, FileStatus::Ahead),
            (behind, FileStatus::Behind),
            (conflict, FileStatus::Conflict),
            (steady, FileStatus::Steady),
        ];
        println!("  {}", format_status_line(&status_items));
    } else if !is_single_file {
        let status_items = vec![
            (latent, FileStatus::Latent),
            (ahead, FileStatus::Ahead),
            (behind, FileStatus::Behind),
            (conflict, FileStatus::Conflict),
        ];
        println!("  {}", format_status_line(&status_items));
    }

    if !is_single_file {
        println!();
    }

    // Filter files
    let filtered_files: Vec<&FileInfo> = files
        .iter()
        .filter(|f| {
            // Filter by show_all (but always show steady files in single file mode)
            if !show_all && !is_single_file && f.status == FileStatus::Steady {
                return false;
            }
            // Only show actual files, not directory entries
            f.file_type != 'D'
        })
        .collect();

    if filtered_files.is_empty() {
        if !is_single_file {
            println!("  {}", "No files to show".dimmed());
            println!();
        }
        return;
    }

    // Build and render tree
    let tree = build_tree(&filtered_files);

    if !is_single_file {
        println!("   {}", ".".bright_cyan().bold());
    }
    let node_count = tree.len();
    for (idx, (name, node)) in tree.iter().enumerate() {
        let is_last = idx == node_count - 1;
        render_tree_node(node, name, "  ", is_last, lscolors, use_nerd_fonts);
    }

    if !is_single_file {
        println!();
    }
}

/// Render hook template content
fn render_hook_template(source_dir: &Path, content: &str, config: &Config) -> Result<String> {
    use guisu_template::TemplateContext;
    use std::sync::Arc;

    // Load age identities for encryption support in templates
    let identities = Arc::new(config.age_identities().unwrap_or_else(|_| Vec::new()));

    // Create template engine with bitwarden provider support
    let engine = crate::create_template_engine(source_dir, &identities, config);

    // Get destination directory
    let dst_dir = config
        .general
        .dst_dir
        .clone()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("~"));

    // Create template context with guisu info and all variables
    let working_tree = guisu_engine::git::find_working_tree(source_dir)
        .unwrap_or_else(|| source_dir.to_path_buf());
    let dotfiles_dir = config.dotfiles_dir(source_dir);
    let template_ctx = TemplateContext::new()
        .with_guisu_info(
            crate::path_to_string(&dotfiles_dir),
            crate::path_to_string(&working_tree),
            crate::path_to_string(&dst_dir),
            crate::path_to_string(&config.general.root_entry),
        )
        .with_loaded_variables(source_dir, config)
        .map_err(|e| anyhow::anyhow!("Failed to load variables: {e}"))?;

    // Render template
    engine
        .render_str(content, &template_ctx)
        .map_err(|e| anyhow::anyhow!("Template rendering error: {e}"))
}

/// Render script content, handling templates if needed
fn render_script_content(
    source_dir: &Path,
    script: &str,
    content: &str,
    config: &Config,
) -> String {
    let is_template = Path::new(script)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("j2"));

    if is_template {
        render_hook_template(source_dir, content, config).unwrap_or_else(|e| {
            tracing::warn!("Failed to render hook template: {}", e);
            content.to_string()
        })
    } else {
        content.to_string()
    }
}

/// Check and print hooks status
fn print_hooks_status(
    source_dir: &Path,
    db: &RedbPersistentState,
    show_all: bool,
    config: &Config,
) {
    use guisu_engine::hooks::config::HookMode;

    // Load hooks and state using shared helper
    let Some((collections, state)) = crate::utils::hooks::load_hooks_and_state(source_dir, db)
    else {
        return;
    };

    let platform = guisu_core::platform::CURRENT_PLATFORM.os;

    // Check hook execution status and display
    let mut hooks_to_display = Vec::new();

    // Check if we have last_collections to compare against
    let has_previous_state = state.last_collections.is_some();

    for hook in collections.pre.iter().chain(collections.post.iter()) {
        // Skip hooks that don't run on this platform
        if !hook.should_run_on(platform) {
            continue;
        }

        // Determine hook status based on hook definition changes
        // This matches diff.rs logic
        let status = if has_previous_state {
            // Find the corresponding hook in last_collections
            let last_hook = state.last_collections.as_ref().and_then(|last| {
                last.pre
                    .iter()
                    .chain(last.post.iter())
                    .find(|h| h.name == hook.name)
            });

            if let Some(last_hook) = last_hook {
                // Check if hook definition changed (same logic as diff.rs)
                // Compare basic fields: order, mode, cmd, script, script_content
                let mut has_changes = hook.order != last_hook.order
                    || hook.mode != last_hook.mode
                    || hook.cmd != last_hook.cmd
                    || hook.script != last_hook.script
                    || hook.script_content != last_hook.script_content;

                // For mode=onchange hooks, also check if rendered content hash changed
                if !has_changes
                    && hook.mode == HookMode::OnChange
                    && let Some(content) = &hook.script_content
                {
                    // Render current content and compute hash
                    let rendered = render_script_content(
                        source_dir,
                        hook.script.as_ref().unwrap_or(&String::new()),
                        content,
                        config,
                    );
                    let current_hash = guisu_engine::hash::hash_content(rendered.as_bytes());

                    // Compare with saved hash
                    if let Some(saved_hash) = state.onchange_hashes.get(hook.name.as_str()) {
                        if &current_hash != saved_hash {
                            has_changes = true;
                        }
                    } else {
                        // No saved hash means first run
                        has_changes = true;
                    }
                }

                if has_changes {
                    FileStatus::Behind
                } else {
                    FileStatus::Steady
                }
            } else {
                // New hook
                FileStatus::Latent
            }
        } else {
            // No previous state, this is first run
            FileStatus::Latent
        };

        // Skip Steady hooks if not in --all mode
        if !show_all && status == FileStatus::Steady {
            continue;
        }

        hooks_to_display.push((hook.name.clone(), status));
    }

    // Display hooks that need execution
    if !hooks_to_display.is_empty() {
        println!();
        println!("{}:", "Hooks".bold());

        for (name, status) in hooks_to_display {
            let status_str = status.color_str(status.label());
            println!("  {}  {}", status_str.bold(), name);
        }
    }

    // Note: We do NOT update database state here because `status` is a read-only command.
    // State updates should only happen during `apply` or `hooks run` commands.
    // This prevents state pollution from read-only operations.
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for OutputFormat

    #[test]
    fn test_output_format_from_str_simple() {
        assert_eq!(
            "simple".parse::<OutputFormat>().unwrap(),
            OutputFormat::Simple
        );
        assert_eq!(
            "SIMPLE".parse::<OutputFormat>().unwrap(),
            OutputFormat::Simple
        );
    }

    #[test]
    fn test_output_format_from_str_tree() {
        assert_eq!("tree".parse::<OutputFormat>().unwrap(), OutputFormat::Tree);
        assert_eq!("TREE".parse::<OutputFormat>().unwrap(), OutputFormat::Tree);
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        let result = "invalid".parse::<OutputFormat>();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid output format")
        );
    }

    #[test]
    fn test_output_format_equality() {
        assert_eq!(OutputFormat::Simple, OutputFormat::Simple);
        assert_eq!(OutputFormat::Tree, OutputFormat::Tree);
        assert_ne!(OutputFormat::Simple, OutputFormat::Tree);
    }

    #[test]
    fn test_output_format_clone() {
        let format = OutputFormat::Simple;
        let cloned = format;
        assert_eq!(format, cloned);
    }

    #[test]
    fn test_output_format_copy() {
        let format = OutputFormat::Tree;
        let copied = format;
        assert_eq!(format, OutputFormat::Tree);
        assert_eq!(copied, OutputFormat::Tree);
    }

    // Tests for FileStatus

    #[test]
    fn test_file_status_label() {
        assert_eq!(FileStatus::Latent.label(), "[L]");
        assert_eq!(FileStatus::Ahead.label(), "[A]");
        assert_eq!(FileStatus::Behind.label(), "[B]");
        assert_eq!(FileStatus::Conflict.label(), "[C]");
        assert_eq!(FileStatus::Steady.label(), "[S]");
    }

    #[test]
    fn test_file_status_full_name() {
        assert_eq!(FileStatus::Latent.full_name(), "[L]atent");
        assert_eq!(FileStatus::Ahead.full_name(), "[A]head");
        assert_eq!(FileStatus::Behind.full_name(), "[B]ehind");
        assert_eq!(FileStatus::Conflict.full_name(), "[C]onflict");
        assert_eq!(FileStatus::Steady.full_name(), "[S]teady");
    }

    #[test]
    fn test_file_status_color_str() {
        // Test that color_str returns a string containing the input text
        // (actual ANSI codes are implementation details)
        assert!(FileStatus::Latent.color_str("test").contains("test"));
        assert!(FileStatus::Ahead.color_str("test").contains("test"));
        assert!(FileStatus::Behind.color_str("test").contains("test"));
        assert!(FileStatus::Conflict.color_str("test").contains("test"));
        assert!(FileStatus::Steady.color_str("test").contains("test"));
    }

    #[test]
    fn test_file_status_equality() {
        assert_eq!(FileStatus::Latent, FileStatus::Latent);
        assert_eq!(FileStatus::Ahead, FileStatus::Ahead);
        assert_eq!(FileStatus::Behind, FileStatus::Behind);
        assert_eq!(FileStatus::Conflict, FileStatus::Conflict);
        assert_eq!(FileStatus::Steady, FileStatus::Steady);
        assert_ne!(FileStatus::Latent, FileStatus::Ahead);
    }

    #[test]
    fn test_file_status_clone() {
        let status = FileStatus::Conflict;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_file_status_copy() {
        let status = FileStatus::Behind;
        let copied = status;
        assert_eq!(status, FileStatus::Behind);
        assert_eq!(copied, FileStatus::Behind);
    }

    // Tests for FileInfo

    #[test]
    fn test_file_info_status_str() {
        let file = FileInfo {
            path: "test.txt".to_string(),
            status: FileStatus::Latent,
            file_type: 'F',
        };

        let status_str = file.status_str();
        // Should contain the label
        assert!(status_str.contains("[L]"));
    }

    #[test]
    fn test_file_info_debug() {
        let file = FileInfo {
            path: "test.txt".to_string(),
            status: FileStatus::Ahead,
            file_type: 'F',
        };

        let debug_str = format!("{file:?}");
        assert!(debug_str.contains("FileInfo"));
        assert!(debug_str.contains("test.txt"));
    }

    // Tests for format_status_line

    #[test]
    fn test_format_status_line_empty() {
        let items: Vec<(usize, FileStatus)> = vec![];
        let result = format_status_line(&items);
        assert_eq!(result, "");
    }

    #[test]
    fn test_format_status_line_single() {
        let items = vec![(5, FileStatus::Latent)];
        let result = format_status_line(&items);

        // Should contain the count and status name
        assert!(result.contains('5'));
        assert!(result.contains("[L]atent"));
    }

    #[test]
    fn test_format_status_line_multiple() {
        let items = vec![
            (3, FileStatus::Latent),
            (2, FileStatus::Behind),
            (1, FileStatus::Conflict),
        ];
        let result = format_status_line(&items);

        // Should contain all counts and status names
        assert!(result.contains('3'));
        assert!(result.contains("[L]atent"));
        assert!(result.contains('2'));
        assert!(result.contains("[B]ehind"));
        assert!(result.contains('1'));
        assert!(result.contains("[C]onflict"));
        // Should have separator
        assert!(result.contains('|'));
    }

    #[test]
    fn test_format_status_line_all_statuses() {
        let items = vec![
            (1, FileStatus::Latent),
            (2, FileStatus::Ahead),
            (3, FileStatus::Behind),
            (4, FileStatus::Conflict),
            (5, FileStatus::Steady),
        ];
        let result = format_status_line(&items);

        assert!(result.contains('1'));
        assert!(result.contains('2'));
        assert!(result.contains('3'));
        assert!(result.contains('4'));
        assert!(result.contains('5'));
    }

    // Tests for build_tree

    #[test]
    fn test_build_tree_empty() {
        let files: Vec<&FileInfo> = vec![];
        let tree = build_tree(&files);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_build_tree_single_file() {
        let file = FileInfo {
            path: "test.txt".to_string(),
            status: FileStatus::Latent,
            file_type: 'F',
        };
        let file_list = vec![&file];

        let tree = build_tree(&file_list);
        assert_eq!(tree.len(), 1);
        assert!(tree.contains_key("test.txt"));

        match tree.get("test.txt") {
            Some(TreeNode::File(_)) => (),
            _ => panic!("Expected File node"),
        }
    }

    #[test]
    fn test_build_tree_nested_files() {
        let file1 = FileInfo {
            path: "dir1/file1.txt".to_string(),
            status: FileStatus::Latent,
            file_type: 'F',
        };
        let file2 = FileInfo {
            path: "dir1/file2.txt".to_string(),
            status: FileStatus::Behind,
            file_type: 'F',
        };
        let file_list = vec![&file1, &file2];

        let tree = build_tree(&file_list);
        assert_eq!(tree.len(), 1);
        assert!(tree.contains_key("dir1"));

        match tree.get("dir1") {
            Some(TreeNode::Directory { children }) => {
                assert_eq!(children.len(), 2);
                assert!(children.contains_key("file1.txt"));
                assert!(children.contains_key("file2.txt"));
            }
            _ => panic!("Expected Directory node"),
        }
    }

    #[test]
    fn test_build_tree_deep_nesting() {
        let file = FileInfo {
            path: "a/b/c/d/file.txt".to_string(),
            status: FileStatus::Conflict,
            file_type: 'F',
        };
        let file_list = vec![&file];

        let tree = build_tree(&file_list);
        assert_eq!(tree.len(), 1);
        assert!(tree.contains_key("a"));

        // Navigate down the tree
        let mut current = &tree;
        for dir in &["a", "b", "c", "d"] {
            match current.get(*dir) {
                Some(TreeNode::Directory { children }) => {
                    current = children;
                }
                _ => panic!("Expected Directory node at {dir}"),
            }
        }

        // Final level should have the file
        assert!(current.contains_key("file.txt"));
    }

    #[test]
    fn test_build_tree_multiple_roots() {
        let file1 = FileInfo {
            path: "dir1/file1.txt".to_string(),
            status: FileStatus::Latent,
            file_type: 'F',
        };
        let file2 = FileInfo {
            path: "dir2/file2.txt".to_string(),
            status: FileStatus::Behind,
            file_type: 'F',
        };
        let file3 = FileInfo {
            path: "file3.txt".to_string(),
            status: FileStatus::Ahead,
            file_type: 'F',
        };
        let file_list = vec![&file1, &file2, &file3];

        let tree = build_tree(&file_list);
        assert_eq!(tree.len(), 3);
        assert!(tree.contains_key("dir1"));
        assert!(tree.contains_key("dir2"));
        assert!(tree.contains_key("file3.txt"));
    }

    #[test]
    fn test_build_tree_mixed_depths() {
        let file1 = FileInfo {
            path: "a/b/deep.txt".to_string(),
            status: FileStatus::Latent,
            file_type: 'F',
        };
        let file2 = FileInfo {
            path: "a/shallow.txt".to_string(),
            status: FileStatus::Behind,
            file_type: 'F',
        };
        let file_list = vec![&file1, &file2];

        let tree = build_tree(&file_list);
        assert_eq!(tree.len(), 1);

        match tree.get("a") {
            Some(TreeNode::Directory { children }) => {
                assert_eq!(children.len(), 2);
                assert!(children.contains_key("b"));
                assert!(children.contains_key("shallow.txt"));
            }
            _ => panic!("Expected Directory node"),
        }
    }

    // Tests for StatusCommand

    #[test]
    fn test_status_command_default() {
        let cmd = StatusCommand {
            files: vec![],
            all: false,
            tree: false,
        };

        assert!(cmd.files.is_empty());
        assert!(!cmd.all);
        assert!(!cmd.tree);
    }

    #[test]
    fn test_status_command_with_files() {
        let cmd = StatusCommand {
            files: vec![PathBuf::from("file1.txt"), PathBuf::from("file2.txt")],
            all: false,
            tree: false,
        };

        assert_eq!(cmd.files.len(), 2);
        assert_eq!(cmd.files[0], PathBuf::from("file1.txt"));
        assert_eq!(cmd.files[1], PathBuf::from("file2.txt"));
    }

    #[test]
    fn test_status_command_with_all_flag() {
        let cmd = StatusCommand {
            files: vec![],
            all: true,
            tree: false,
        };

        assert!(cmd.all);
        assert!(!cmd.tree);
    }

    #[test]
    fn test_status_command_with_tree_flag() {
        let cmd = StatusCommand {
            files: vec![],
            all: false,
            tree: true,
        };

        assert!(!cmd.all);
        assert!(cmd.tree);
    }

    #[test]
    fn test_status_command_all_flags() {
        let cmd = StatusCommand {
            files: vec![PathBuf::from("test.txt")],
            all: true,
            tree: true,
        };

        assert_eq!(cmd.files.len(), 1);
        assert!(cmd.all);
        assert!(cmd.tree);
    }
}
