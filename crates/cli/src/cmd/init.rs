//! Init command implementation
//!
//! Initialize a new guisu source directory or clone from GitHub.

use anyhow::{Context, Result, anyhow};
use git2::{FetchOptions, RemoteCallbacks, Repository, SubmoduleUpdateOptions};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Run the init command
///
/// Returns the path to the initialized source directory if successful
///
/// # Errors
///
/// Returns an error if:
/// - The target directory cannot be determined
/// - Git cloning fails
/// - Local directory initialization fails
pub fn run(
    path_or_repo: Option<&str>,
    custom_source: Option<&Path>,
    depth: Option<usize>,
    branch: Option<&str>,
    use_ssh: bool,
    recurse_submodules: bool,
) -> Result<Option<PathBuf>> {
    let (target_path, is_clone) = determine_init_target(path_or_repo, custom_source)?;
    debug!(path = %target_path.display(), is_clone, "Initializing guisu");

    if is_clone {
        // SAFETY: when `is_clone` is true, `path_or_repo` is `Some` per
        // `determine_init_target`. The `ok_or_else` makes that contract explicit
        // instead of relying on `.expect()` at runtime.
        let repo_url = path_or_repo
            .ok_or_else(|| anyhow!("internal: is_clone=true but path_or_repo is None"))?;
        clone_from_github(
            repo_url,
            &target_path,
            depth,
            branch,
            use_ssh,
            recurse_submodules,
        )?;
        return Ok(Some(target_path));
    }

    // Initialize local directory
    initialize_local_directory(&target_path)?;
    Ok(Some(target_path))
}

/// Determine the target path and whether we're cloning from GitHub
fn determine_init_target(
    path_or_repo: Option<&str>,
    custom_source: Option<&Path>,
) -> Result<(PathBuf, bool)> {
    match path_or_repo {
        None => {
            // Default: use custom source or XDG data directory
            let target = custom_source
                .map(std::path::Path::to_path_buf)
                .or_else(guisu_config::dirs::data_dir)
                .ok_or_else(|| anyhow!("Could not determine data directory"))?;
            Ok((target, false))
        }
        Some(input) => {
            // Check if it looks like a GitHub reference
            if is_github_reference(input) {
                // Use custom source or XDG data directory for cloned repos
                let target = custom_source
                    .map(std::path::Path::to_path_buf)
                    .or_else(guisu_config::dirs::data_dir)
                    .ok_or_else(|| anyhow!("Could not determine data directory"))?;
                Ok((target, true))
            } else {
                // Explicit local path (overrides custom_source)
                Ok((PathBuf::from(input), false))
            }
        }
    }
}

/// Check if the input looks like a GitHub reference (username or owner/repo)
fn is_github_reference(input: &str) -> bool {
    // Don't treat paths as GitHub references
    if input.starts_with('/') || input.starts_with('.') || input.contains('\\') {
        return false;
    }

    // Check if it looks like username or owner/repo
    // Simple heuristic: contains only alphanumeric, dash, underscore, and at most one slash
    let slash_count = input.matches('/').count();
    if slash_count > 1 {
        return false;
    }

    // Check if all characters are valid GitHub username/repo characters
    input
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/')
}

/// Clone a repository from GitHub
#[allow(clippy::too_many_lines)]
fn clone_from_github(
    repo_ref: &str,
    target_path: &Path,
    depth: Option<usize>,
    branch: Option<&str>,
    use_ssh: bool,
    recurse_submodules: bool,
) -> Result<()> {
    // Build the full repository URL
    let repo_url = if use_ssh {
        // Use SSH URL format
        if repo_ref.contains('/') {
            format!("git@github.com:{repo_ref}.git")
        } else {
            format!("git@github.com:{repo_ref}/dotfiles.git")
        }
    } else {
        // Use HTTPS URL format (default)
        if repo_ref.contains('/') {
            format!("https://github.com/{repo_ref}.git")
        } else {
            format!("https://github.com/{repo_ref}/dotfiles.git")
        }
    };

    // Check if directory is already a git repository
    if target_path.exists() {
        if let Ok(existing_repo) = Repository::open(target_path) {
            // Directory is already a git repository, skip cloning
            if let Ok(remote) = existing_repo.find_remote("origin")
                && let Ok(existing_url) = remote.url()
            {
                // Check if user is trying to init a different repository
                if existing_url != repo_url {
                    warn!(
                        "Source directory is using a different repository: {}",
                        existing_url
                    );
                    return Ok(());
                }
                info!("Source directory is already initialized");
                return Ok(());
            }

            info!("Source directory is already initialized");
            return Ok(());
        }

        // Not a git repository, check if empty
        if target_path.read_dir()?.next().is_some() {
            return Err(anyhow!(
                "Target directory is not empty and not a git repository: {}",
                target_path.display()
            ));
        }
    }

    info!("Cloning repository from {}", repo_url);

    let progress_bar = ProgressBar::new(100);
    let progress_style = ProgressStyle::default_bar()
        .template("  {spinner:.cyan} {bar:50.cyan/black} {pos:>3}% {msg:.white.dim}")
        .context("Failed to build progress bar template (this is a compile-time constant)")?
        .progress_chars("━━╸ ");
    progress_bar.set_style(progress_style);

    let mut callbacks = RemoteCallbacks::new();
    // Try the user's git config first; fall back to an in-memory empty config
    // so we don't panic on minimal environments (containers, fresh installs).
    let git_config = git2::Config::open_default()
        .unwrap_or_else(|_| git2::Config::new().expect("Failed to create in-memory git2::Config"));
    let mut credential_handler = git2_credentials::CredentialHandler::new(git_config);

    callbacks.transfer_progress(|stats| {
        let received = stats.received_objects();
        let total = stats.total_objects();

        if total > 0 {
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let percentage = (received as f64 / total as f64 * 100.0) as u64;
            progress_bar.set_position(percentage);

            if stats.received_bytes() > 0 {
                #[allow(clippy::cast_precision_loss)]
                let mb = stats.received_bytes() as f64 / 1_048_576.0;
                progress_bar.set_message(format!("{received}/{total} objects ({mb:.2} MiB)"));
            } else {
                progress_bar.set_message(format!("{received}/{total} objects"));
            }
        }

        true
    });

    callbacks.credentials(move |url, username_from_url, allowed_types| {
        credential_handler.try_next_credential(url, username_from_url, allowed_types)
    });

    let mut fetch_options = FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);

    if let Some(depth_value) = depth {
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        fetch_options.depth(depth_value as i32);
    }

    debug!(url = %repo_url, path = %target_path.display(), "Starting git clone");
    let mut builder = git2::build::RepoBuilder::new();
    builder.fetch_options(fetch_options);

    if let Some(branch_name) = branch {
        builder.branch(branch_name);
    }

    let repo = builder
        .clone(&repo_url, target_path)
        .with_context(|| {
            progress_bar.finish_and_clear();
            format!(
                "Failed to clone repository from {repo_url}. Make sure the repository exists and you have access."
            )
        })?;

    progress_bar.finish_and_clear();
    info!("Repository cloned successfully");

    if recurse_submodules {
        debug!("Initializing submodules recursively");
        init_submodules_recursive(&repo, target_path)?;
        info!("Submodules initialized successfully");
    }

    Ok(())
}

/// Initialize submodules recursively using git2
fn init_submodules_recursive(repo: &Repository, repo_path: &Path) -> Result<()> {
    let submodules = repo.submodules().context("Failed to get submodules")?;

    if submodules.is_empty() {
        debug!("No submodules found");
        return Ok(());
    }

    debug!(count = submodules.len(), "Found submodules");

    for mut submodule in submodules {
        let name = submodule.name().unwrap_or("<unnamed>").to_string();
        let path = submodule.path().to_path_buf();
        debug!(name = %name, path = %path.display(), "Initializing submodule");

        // Initialize the submodule
        submodule
            .init(false)
            .with_context(|| format!("Failed to initialize submodule '{name}'"))?;

        // Update the submodule (clone and checkout)
        let mut update_options = SubmoduleUpdateOptions::new();

        // Set up fetch options with credentials
        let mut fetch_options = FetchOptions::new();
        let mut callbacks = RemoteCallbacks::new();
        let git_config = git2::Config::open_default().unwrap_or_else(|_| {
            git2::Config::new().expect("Failed to create in-memory git2::Config")
        });
        let mut credential_handler = git2_credentials::CredentialHandler::new(git_config);

        callbacks.transfer_progress(|_| true);
        callbacks.credentials(move |url, username_from_url, allowed_types| {
            credential_handler.try_next_credential(url, username_from_url, allowed_types)
        });
        fetch_options.remote_callbacks(callbacks);

        update_options.fetch(fetch_options);

        submodule
            .update(true, Some(&mut update_options))
            .with_context(|| format!("Failed to update submodule '{name}'"))?;

        debug!(name = %name, "Submodule initialized");

        // Recursively initialize submodules of this submodule
        let submodule_path = repo_path.join(&path);
        if let Ok(sub_repo) = Repository::open(&submodule_path) {
            init_submodules_recursive(&sub_repo, &submodule_path)?;
        }
    }

    Ok(())
}

/// Initialize a local directory
fn initialize_local_directory(path: &Path) -> Result<()> {
    info!("Initializing source directory");

    if path.exists() {
        debug!(path = %path.display(), "Directory already exists");
    } else {
        fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        debug!(path = %path.display(), "Created directory");
    }

    // If the user initialised to a non-default source dir, point subsequent
    // `guisu apply` (no args) at it — `apply` falls back to `data_dir()`
    // otherwise. GUISU_SOURCE_DIR is the per-machine, repo-external override
    // (config stays repo-managed by design).
    if let Some(default_dir) = guisu_config::dirs::default_source_dir()
        && path != default_dir
    {
        println!();
        println!(
            "This is not the default source location ({}) on this machine.",
            default_dir.display()
        );
        println!("Subsequent `guisu apply` (no args) defaults there. To use this");
        println!("directory every time, export once in your shell profile:");
        println!();
        println!("    export GUISU_SOURCE_DIR=\"{}\"", path.display());
        println!();
        println!("Or pass --source on each invocation.");
    }
    info!("Source directory initialized successfully");

    Ok(())
}
