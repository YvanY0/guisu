//! Guisu CLI library
//!
//! This library contains all the CLI logic for guisu, making it reusable
//! for testing and integration with other tools.

pub mod cmd;
pub mod command;
pub mod common;
pub mod conflict;
pub mod error;
pub mod logging;
pub mod stats;
pub mod ui;
pub mod utils;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};

use command::Command;
use common::RuntimeContext;

/// Guisu - A dotfile manager inspired by chezmoi
#[derive(Parser)]
#[command(name = "guisu")]
#[command(about = "Manage your dotfiles with guisu (归宿)")]
#[command(version)]
#[command(long_about = "Manage your dotfiles with guisu (归宿)

A fast, secure dotfile manager written in Rust.
Inspired by chezmoi, designed for simplicity and security.

Features:
  • Template support with Jinja2-like syntax
  • Age encryption for sensitive files
  • Git integration for version control
  • Cross-platform (macOS, Linux, Windows)")]
pub struct Cli {
    /// Path to the source directory
    #[arg(long, env = "GUISU_SOURCE_DIR", value_name = "DIR")]
    pub source: Option<PathBuf>,

    /// Path to the destination directory (usually $HOME)
    #[arg(long, env = "GUISU_DEST_DIR", value_name = "DIR")]
    pub dest: Option<PathBuf>,

    /// Path to the config file
    #[arg(long, env = "GUISU_CONFIG", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable verbose output (shows DEBUG level logs)
    #[arg(short, long)]
    pub verbose: bool,

    /// Write logs to a file (useful for debugging)
    #[arg(long, env = "GUISU_LOG_FILE", value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands for guisu CLI
#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new source directory or clone from GitHub
    Init {
        /// Path to initialize, GitHub username, or GitHub repo (owner/repo).
        ///
        /// If not specified, defaults to ~/.local/share/guisu
        #[arg(
            value_name = "PATH_OR_REPO",
            long_help = "Path to initialize, GitHub username, or GitHub repo (owner/repo).

If not specified, defaults to ~/.local/share/guisu

Examples:
  • guisu init
      → Initialize at ~/.local/share/guisu (default)

  • guisu init .
      → Initialize at current directory

  • guisu init PaulYuuu
      → Clone github.com/PaulYuuu/dotfiles to ~/.local/share/guisu

  • guisu init owner/repo
      → Clone github.com/owner/repo to ~/.local/share/guisu

  • guisu --source /custom/path init username
      → Clone to custom path /custom/path"
        )]
        path_or_repo: Option<String>,

        /// Apply changes after initialization
        #[arg(short, long)]
        apply: bool,

        /// Create a shallow clone with the specified depth (commits)
        #[arg(short, long)]
        depth: Option<usize>,

        /// Specify the branch to clone (default: repository's default branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Use SSH instead of HTTPS when guessing repo URL
        #[arg(long)]
        ssh: bool,

        /// Checkout submodules recursively
        #[arg(long)]
        recurse_submodules: bool,
    },

    /// Add a file to the source directory
    Add(cmd::add::AddCommand),

    /// Apply the source state to the destination
    #[command(name = "apply")]
    Apply(cmd::apply::ApplyCommand),

    /// Show differences between source and destination
    Diff(cmd::diff::DiffCommand),

    /// Manage age encryption identities
    #[command(subcommand)]
    Age(AgeCommands),

    /// Show status of managed files
    Status(cmd::status::StatusCommand),

    /// Display file contents (decrypt and render templates)
    Cat(cmd::cat::CatCommand),

    /// Edit the source state of a target file
    Edit(cmd::edit::EditCommand),

    /// View ignored files and patterns
    #[command(subcommand)]
    Ignored(IgnoredCommands),

    /// Manage template files
    #[command(subcommand)]
    Templates(TemplatesCommands),

    /// Pull and apply changes from the source repository
    #[command(long_about = "Pull and apply changes from the source repository

Fetches the latest changes from the remote repository and applies them
to your destination directory.

Examples:
  • guisu update
      → Pull and apply changes

  • guisu update --rebase
      → Use rebase when branches diverge")]
    Update(cmd::update::UpdateCommand),

    /// Display guisu status information and validate configuration
    Info(cmd::info::InfoCommand),

    /// Display all template variables
    Variables(cmd::variables::VariablesCommand),

    /// Manage hooks (run, list, show)
    #[command(subcommand)]
    Hooks(HooksCommands),
}

/// Age encryption management commands
#[derive(Subcommand)]
pub enum AgeCommands {
    /// Generate a new age identity
    Generate {
        /// Output file (default: ~/.config/guisu/key.txt)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show the public key for the current identity
    Show,

    /// Encrypt a value using inline encryption format
    ///
    /// This encrypts a plaintext value and outputs it in the compact `age:base64...`
    /// format suitable for embedding in configuration files.
    Encrypt {
        /// Value to encrypt (if not provided, reads from stdin)
        value: Option<String>,

        /// Interactive mode - prompts for input
        #[arg(short, long)]
        interactive: bool,

        /// Recipients to encrypt for (age public keys or SSH public keys)
        ///
        /// If not specified, uses all identities from config.
        /// Can be specified multiple times to encrypt for multiple recipients.
        ///
        /// Examples:
        ///   --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
        ///   --recipient ssh-ed25519 `AAAAC3NzaC1lZDI1NTE5`...
        #[arg(short, long)]
        recipients: Vec<String>,
    },

    /// Decrypt an inline encrypted value
    ///
    /// This decrypts a value in the `age:base64...` format and outputs the plaintext.
    Decrypt {
        /// Encrypted value to decrypt
        #[arg(required = true)]
        value: String,
    },

    /// Migrate encrypted files from old keys to new keys
    ///
    /// This command re-encrypts all encrypted files and inline encrypted values
    /// in your source directory from old identities to new recipients.
    Migrate {
        /// Old identity files (private keys) to decrypt with
        #[arg(long = "from", required = true)]
        old_identities: Vec<PathBuf>,

        /// New identity files (private keys) to encrypt with
        /// Public keys will be automatically extracted from these identities
        #[arg(long = "to", required = true)]
        new_identities: Vec<PathBuf>,

        /// Dry run - show what would be migrated without making changes
        #[arg(short = 'n', long)]
        dry_run: bool,

        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

/// Commands for viewing ignored files and patterns
#[derive(Subcommand)]
pub enum IgnoredCommands {
    /// List files that are ignored on the current platform
    List,

    /// Show ignore rules for the current platform
    Rules {
        /// Show rules for all platforms
        #[arg(short, long)]
        all: bool,
    },
}

/// Commands for managing template files
#[derive(Subcommand)]
pub enum TemplatesCommands {
    /// List available template files for the current platform
    List,

    /// Show rendered content of a specific template
    Show {
        /// Template name to display
        #[arg(required = true)]
        name: String,
    },
}

/// Commands for managing and executing hooks
#[derive(Subcommand)]
pub enum HooksCommands {
    /// Run hooks from configuration
    Run {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,

        /// Run only the specified hook by name (optional)
        #[arg(long)]
        hook: Option<String>,
    },

    /// List configured hooks
    List {
        /// Output format (simple, json)
        #[arg(short, long, default_value = "simple")]
        format: String,
    },

    /// Show detailed information about a specific hook
    Show {
        /// Name of the hook to show
        name: String,
    },
}

/// Main entry point for the CLI logic
///
/// Load base config to determine source directory
fn load_base_config() -> guisu_config::Config {
    if let Some(source_dir) = guisu_config::default_source_dir()
        && source_dir.exists()
        && let Ok(config) = load_config_with_template_support(None, &source_dir, None)
    {
        config
    } else {
        guisu_config::Config::default()
    }
}

/// Determine source and destination directories from CLI and config
fn determine_directories(
    cli: &Cli,
    base_config: &guisu_config::Config,
) -> Result<(PathBuf, PathBuf)> {
    let source_dir = cli
        .source
        .clone()
        .or_else(|| base_config.source_dir().cloned())
        .or_else(guisu_config::dirs::default_source_dir)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not determine source directory. Please specify with --source or set in config file."
            )
        })?;

    let dest_dir = cli
        .dest
        .clone()
        .or_else(|| base_config.dest_dir().cloned())
        .or_else(::dirs::home_dir)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not determine destination directory (home directory not found). \
                 Please specify with --dest or set in config file."
            )
        })?;

    Ok((source_dir, dest_dir))
}

/// Handle init command separately (doesn't need config before directory creation)
#[allow(clippy::too_many_arguments)]
fn handle_init_command(
    path_or_repo: Option<&String>,
    custom_source: Option<&PathBuf>,
    depth: Option<usize>,
    branch: Option<&String>,
    ssh: bool,
    recurse_submodules: bool,
    apply: bool,
    dest_dir: &Path,
    config_path: Option<&Path>,
) -> Result<()> {
    let init_result = crate::cmd::init::run(
        path_or_repo.map(String::as_str),
        custom_source.map(std::path::PathBuf::as_path),
        depth,
        branch.map(String::as_str),
        ssh,
        recurse_submodules,
    )?;

    // Apply if requested
    if apply && let Some(source_path) = init_result {
        println!("\nApplying changes...");
        // Now load config after source directory is created (no caching needed for init)
        let config = load_config_with_template_support(config_path, &source_path, None)?;

        // Create ApplyCommand with default options (all files)
        let apply_cmd = cmd::apply::ApplyCommand {
            files: vec![],
            dry_run: false,
            force: false,
            interactive: false,
            include: vec![],
            exclude: vec![],
        };

        // Create RuntimeContext and execute
        let context = RuntimeContext::new(config, &source_path, dest_dir)?;
        apply_cmd.execute(&context)?;
    }
    Ok(())
}

/// Handle apply command with pre and post hooks
fn handle_apply_command(
    apply_cmd: &cmd::apply::ApplyCommand,
    context: &RuntimeContext,
) -> Result<()> {
    // Hooks should only run for global apply (no file arguments) and not in dry-run mode
    let should_run_hooks = !apply_cmd.dry_run && apply_cmd.files.is_empty();

    // Handle pre-apply hooks
    if should_run_hooks
        && let Err(e) =
            cmd::hooks::handle_hooks_pre(context.source_dir(), &context.config, &context.database)
    {
        tracing::warn!("Pre-apply hooks failed: {}", e);
        println!(
            "{}: Pre-apply hooks encountered issues: {}",
            "Warning".yellow(),
            e
        );
        println!("Continuing with file application...\n");
    }

    // Execute apply command and get stats
    let is_single_file = apply_cmd.files.len() == 1;
    let dry_run = apply_cmd.dry_run;
    let stats = apply_cmd.execute(context)?;

    // Database will be automatically closed when RuntimeContext is dropped

    // Handle post-apply hooks
    if should_run_hooks
        && let Err(e) =
            cmd::hooks::handle_hooks_post(context.source_dir(), &context.config, &context.database)
    {
        tracing::warn!("Post-apply hooks failed: {}", e);
        println!(
            "{}: Post-apply hooks encountered issues: {}",
            "Warning".yellow(),
            e
        );
    }

    // Print summary after hooks complete (skip for single file mode)
    if !is_single_file {
        println!();
        stats.print_summary(dry_run);
    }

    Ok(())
}

/// Execute the command based on the command type
#[allow(clippy::too_many_lines)]
fn execute_command(command: Commands, context: &RuntimeContext) -> Result<()> {
    match command {
        Commands::Init { .. } => {
            unreachable!("Init command already handled above")
        }
        Commands::Add(add_cmd) => {
            add_cmd.execute(context)?;
        }
        Commands::Apply(apply_cmd) => {
            handle_apply_command(&apply_cmd, context)?;
        }
        Commands::Diff(diff_cmd) => {
            diff_cmd.execute(context)?;
        }
        Commands::Age(age_cmd) => match age_cmd {
            AgeCommands::Generate { output } => {
                cmd::age::generate(output)?;
            }
            AgeCommands::Show => {
                cmd::age::show(&context.config)?;
            }
            AgeCommands::Encrypt {
                value,
                interactive,
                recipients,
            } => {
                cmd::age::encrypt(value, interactive, &recipients, &context.config)?;
            }
            AgeCommands::Decrypt { value } => {
                cmd::age::decrypt(&value, &context.config)?;
            }
            AgeCommands::Migrate {
                old_identities,
                new_identities,
                dry_run,
                yes,
            } => {
                cmd::age::migrate(
                    context.source_dir(),
                    &old_identities,
                    &new_identities,
                    dry_run,
                    yes,
                )?;
            }
        },
        Commands::Status(status_cmd) => {
            status_cmd.execute(context)?;
        }
        Commands::Cat(cat_cmd) => {
            cat_cmd.execute(context)?;
        }
        Commands::Edit(edit_cmd) => {
            edit_cmd.execute(context)?;
        }
        Commands::Ignored(ignored_cmd) => match ignored_cmd {
            IgnoredCommands::List => {
                cmd::ignored::run_list(context.source_dir(), &context.config)?;
            }
            IgnoredCommands::Rules { all } => {
                cmd::ignored::run_show(context.source_dir(), &context.config, all)?;
            }
        },
        Commands::Templates(templates_cmd) => match templates_cmd {
            TemplatesCommands::List => {
                cmd::templates::run_list(context.source_dir(), &context.config)?;
            }
            TemplatesCommands::Show { name } => {
                cmd::templates::run_show(
                    context.source_dir(),
                    context.dest_dir().as_path(),
                    &name,
                    &context.config,
                )?;
            }
        },
        Commands::Update(update_cmd) => {
            update_cmd.execute(context)?;
        }
        Commands::Info(info_cmd) => {
            info_cmd.execute(context)?;
        }
        Commands::Variables(vars_cmd) => {
            vars_cmd.execute(context)?;
        }
        Commands::Hooks(hooks_cmd) => match hooks_cmd {
            HooksCommands::Run { yes, hook } => {
                cmd::hooks::run_hooks(
                    context.source_dir(),
                    &context.config,
                    &context.database,
                    yes,
                    hook.as_deref(),
                )?;
            }
            HooksCommands::List { format } => {
                cmd::hooks::run_list(context.source_dir(), &context.config, &format)?;
            }
            HooksCommands::Show { name } => {
                cmd::hooks::run_show(context.source_dir(), &context.config, &name)?;
            }
        },
    }

    Ok(())
}

/// # Errors
///
/// Returns an error if:
/// - Logging initialization fails
/// - Configuration loading fails
/// - Source or destination directories cannot be determined
/// - Command execution fails
pub fn run(cli: Cli) -> Result<()> {
    // Initialize logging based on verbosity
    crate::logging::init(cli.verbose, cli.log_file.as_deref())?;

    // Save custom source for init command before it's consumed
    let custom_source = cli.source.clone();

    // Load base config and determine directories
    let base_config = load_base_config();
    let (source_dir, dest_dir) = determine_directories(&cli, &base_config)?;

    // Handle init command separately (doesn't need config before directory creation)
    if let Commands::Init {
        path_or_repo,
        apply,
        depth,
        branch,
        ssh,
        recurse_submodules,
    } = cli.command
    {
        return handle_init_command(
            path_or_repo.as_ref(),
            custom_source.as_ref(),
            depth,
            branch.as_ref(),
            ssh,
            recurse_submodules,
            apply,
            &dest_dir,
            cli.config.as_deref(),
        );
    }

    // For all other commands, create database first to enable config caching
    let db_path = guisu_engine::database::get_db_path().context("Failed to get database path")?;
    let database = std::sync::Arc::new(
        guisu_engine::state::RedbPersistentState::new(&db_path)
            .context("Failed to create database instance")?,
    );

    // Load config with database caching enabled
    let config =
        load_config_with_template_support(cli.config.as_deref(), &source_dir, Some(&database))?;

    // Create RuntimeContext for commands (reuses the database instance)
    let paths = crate::common::ResolvedPaths::resolve(&source_dir, &dest_dir, &config)?;
    let context = crate::common::RuntimeContext::from_parts_with_db(
        std::sync::Arc::new(config),
        paths,
        database,
    );

    // Execute the command
    execute_command(cli.command, &context)
}

// ============================================================================
// Common utility functions
// ============================================================================

/// Build filter paths from user-provided file arguments (crate-internal use only)
///
/// This function converts file paths (which may be relative, absolute, or use ~)
/// into `RelPath` entries that can be used to filter source/target states.
///
/// # Arguments
///
/// * `files` - List of file paths provided by the user
/// * `dest_abs` - Absolute path to the destination directory
///
/// # Returns
///
/// Returns a vector of `RelPath` entries representing the files relative to `dest_dir`.
///
/// # Errors
///
/// Returns an error if:
/// - A file path cannot be canonicalized
/// - A file path is not under the destination directory
pub(crate) fn build_filter_paths(
    files: &[std::path::PathBuf],
    dest_abs: &guisu_core::path::AbsPath,
) -> Result<Vec<guisu_core::path::RelPath>> {
    files
        .iter()
        .map(|file_path| {
            // Expand tilde and resolve to absolute path
            let expanded_path = expand_tilde(file_path);
            let file_abs = resolve_absolute_path(&expanded_path)?;

            // Convert to relative path under dest_dir
            file_abs.strip_prefix(dest_abs).map_err(|_| {
                anyhow::anyhow!(
                    "File {} is not under destination directory {}",
                    file_abs.as_path().display(),
                    dest_abs.as_path().display()
                )
            })
        })
        .collect()
}

/// Convert a Path to a String efficiently (crate-internal use only)
///
/// This avoids the common `.to_string_lossy().to_string()` double conversion pattern.
#[inline]
pub(crate) fn path_to_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Expand tilde (~) in a path to the home directory
fn expand_tilde(path: &std::path::Path) -> std::path::PathBuf {
    // Early return for common case (no tilde) - avoids string conversion
    if !path.as_os_str().as_encoded_bytes().starts_with(b"~") {
        return path.to_path_buf();
    }

    let Some(home) = dirs::home_dir() else {
        return path.to_path_buf();
    };

    // Only convert to string if starts with ~
    match path.to_str() {
        Some("~") => home,
        Some(s) if s.starts_with("~/") => home.join(&s[2..]),
        _ => path.to_path_buf(),
    }
}

/// Resolve a path to an absolute path
///
/// If the path exists, canonicalize it. Otherwise, construct an absolute path.
fn resolve_absolute_path(path: &std::path::Path) -> Result<guisu_core::path::AbsPath> {
    use anyhow::Context;

    if path.exists() {
        Ok(guisu_core::path::AbsPath::new(
            std::fs::canonicalize(path)
                .with_context(|| format!("Failed to resolve path: {}", path.display()))?,
        )?)
    } else if path.is_absolute() {
        Ok(guisu_core::path::AbsPath::new(path.to_path_buf())?)
    } else {
        let abs_path = std::env::current_dir()?.join(path);
        Ok(guisu_core::path::AbsPath::new(abs_path)?)
    }
}

/// Load configuration with template support and optional database caching
///
/// Handles both static `.guisu.toml` and templated `.guisu.toml.j2` configurations.
///
/// For `.guisu.toml.j2` templates:
/// - If database is provided, checks cache first using template hash
/// - Cache hit: Uses cached rendered config (avoids re-rendering)
/// - Cache miss: Renders template with minimal context and caches result
/// - Template rendering uses only system variables to avoid circular dependency
///
/// This database-backed caching solves the circular dependency problem:
/// - First load: Renders with minimal context, caches result
/// - Subsequent loads: Uses cached config (fast path)
/// - Cache invalidation: Automatic when template content changes (blake3 hash)
///
/// # Arguments
///
/// * `_config_path` - Optional path to config file (currently unused)
/// * `source_dir` - The source directory containing .guisu.toml or .guisu.toml.j2
/// * `database` - Optional database for caching rendered config
///
/// # Returns
///
/// A loaded and configured Config instance with all variables merged.
pub(crate) fn load_config_with_template_support(
    _config_path: Option<&std::path::Path>,
    source_dir: &std::path::Path,
    database: Option<&std::sync::Arc<guisu_engine::state::RedbPersistentState>>,
) -> Result<guisu_config::Config> {
    use std::fs;

    let toml_path = source_dir.join(".guisu.toml");
    let template_path = source_dir.join(".guisu.toml.j2");

    // If .guisu.toml exists, use the standard loader
    if toml_path.exists() {
        return guisu_config::Config::load_with_variables(None, source_dir)
            .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"));
    }

    // If .guisu.toml.j2 exists, render it (with optional database caching)
    if template_path.exists() {
        let template_content = fs::read_to_string(&template_path)?;

        // Try to use cached config if database is available
        let rendered_toml = if let Some(db) = database {
            match guisu_engine::database::get_config_metadata(db) {
                Ok(Some(metadata)) if metadata.template_matches(&template_content) => {
                    // Cache hit - use cached rendered config
                    metadata.rendered_config
                }
                _ => {
                    // Cache miss or invalid - render and cache
                    let rendered = render_config_template(source_dir, &template_content)?;
                    // Save to cache (ignore errors - caching is optional)
                    let _ = guisu_engine::database::save_config_metadata(
                        db,
                        &template_content,
                        rendered.clone(),
                    );
                    rendered
                }
            }
        } else {
            // No database - render without caching
            render_config_template(source_dir, &template_content)?
        };

        // Parse the rendered TOML
        let mut config = guisu_config::Config::from_toml_str(&rendered_toml, source_dir)
            .map_err(|e| anyhow::anyhow!("Failed to parse rendered config: {e}"))?;

        // Load and merge platform-specific variables and ignores (same as load_with_variables)
        let platform = guisu_core::platform::CURRENT_PLATFORM.os;
        let guisu_dir = source_dir.join(".guisu");
        if guisu_dir.exists() {
            // Load variables from .guisu/variables directory
            if let Ok(loaded_vars) = guisu_config::variables::load_variables(&guisu_dir, platform) {
                for (key, value) in loaded_vars {
                    config.variables.insert(key, value);
                }
            }

            // Load ignore patterns from .guisu/ignores.toml
            if let Ok(ignores_config) = guisu_config::IgnoresConfig::load(source_dir) {
                config.ignore.global.extend(ignores_config.global);
                config.ignore.darwin.extend(ignores_config.darwin);
                config.ignore.linux.extend(ignores_config.linux);
                config.ignore.windows.extend(ignores_config.windows);
            }
        }

        return Ok(config);
    }

    // Neither file exists, return error
    Err(anyhow::anyhow!(
        "Configuration file not found in source directory.\n\
         Expected: .guisu.toml or .guisu.toml.j2 in {}\n\
         \n\
         Create .guisu.toml with:\n\
         cat > .guisu.toml << 'EOF'\n\
         # Guisu configuration\n\
         \n\
         [age]\n\
         identity = \"~/.config/guisu/key.txt\"\n\
         EOF",
        source_dir.display()
    ))
}

/// Render config template with minimal context (system variables only)
///
/// Uses a minimal template engine to avoid circular dependency:
/// - No user variables (config not loaded yet)
/// - No password manager integration (requires identities from config)
/// - Only system info (OS, hostname, etc.)
///
/// # Arguments
///
/// * `source_dir` - The source directory
/// * `template_content` - The template file content to render
///
/// # Returns
///
/// Rendered TOML configuration string
fn render_config_template(source_dir: &std::path::Path, template_content: &str) -> Result<String> {
    // Create a minimal template engine for rendering config template
    // Use system variables only (no user variables since we haven't loaded config yet)
    let engine = guisu_template::TemplateEngine::new();

    // Create context with only system info
    let working_tree = guisu_engine::git::find_working_tree(source_dir)
        .unwrap_or_else(|| source_dir.to_path_buf());
    let context = guisu_template::TemplateContext::new().with_guisu_info(
        path_to_string(source_dir),
        path_to_string(&working_tree),
        path_to_string(&dirs::home_dir().unwrap_or_default()),
        "home".to_string(),
    );

    // Render the template
    engine
        .render_str(template_content, &context)
        .map_err(|e| anyhow::anyhow!("Failed to render .guisu.toml.j2 template: {e}"))
}

/// Create a template engine with common configuration (crate-internal use only)
///
/// This helper function centralizes the template engine initialization logic
/// used across multiple commands (apply, cat, diff, status, templates).
///
/// # Arguments
///
/// * `source_dir` - The source directory path
/// * `identities` - Arc-wrapped vector of age identities for decryption
/// * `config` - The configuration object
///
/// # Returns
///
/// A configured `TemplateEngine` instance with:
/// - Age identities for inline decryption
/// - Template directory (if .guisu/templates exists)
/// - Bitwarden provider configuration
pub(crate) fn create_template_engine(
    source_dir: &std::path::Path,
    identities: &std::sync::Arc<Vec<guisu_crypto::Identity>>,
    config: &guisu_config::Config,
) -> guisu_template::TemplateEngine {
    let templates_dir = source_dir.join(".guisu").join("templates");

    guisu_template::TemplateEngine::with_identities_arc_template_dir_and_bitwarden_provider(
        identities,
        if templates_dir.exists() {
            Some(templates_dir)
        } else {
            None
        },
        &config.bitwarden.provider,
    )
}

#[cfg(test)]
mod tests {
    use crate::cmd::apply::ApplyCommand;
    use std::path::PathBuf;

    #[test]
    fn test_should_run_hooks_logic() {
        // Test case 1: dry-run should not run hooks even with no files
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: true,
            force: false,
            interactive: false,
            include: vec![],
            exclude: vec![],
        };
        // should_run_hooks = !dry_run && files.is_empty()
        // !true && true = false
        assert!(cmd.dry_run || !cmd.files.is_empty());

        // Test case 2: not dry-run, no files -> should run hooks
        let cmd = ApplyCommand {
            files: vec![],
            dry_run: false,
            force: false,
            interactive: false,
            include: vec![],
            exclude: vec![],
        };
        assert!(!cmd.dry_run && cmd.files.is_empty());

        // Test case 3: not dry-run, with files -> should not run hooks
        let cmd = ApplyCommand {
            files: vec![PathBuf::from("somefile")],
            dry_run: false,
            force: false,
            interactive: false,
            include: vec![],
            exclude: vec![],
        };
        assert!(cmd.dry_run || !cmd.files.is_empty());

        // Test case 4: dry-run with files -> should not run hooks
        let cmd = ApplyCommand {
            files: vec![PathBuf::from("somefile")],
            dry_run: true,
            force: false,
            interactive: false,
            include: vec![],
            exclude: vec![],
        };
        assert!(cmd.dry_run || !cmd.files.is_empty());
    }
}
