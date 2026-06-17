//! Update command implementation
//!
//! Pull the latest changes from the source repository and optionally apply them.

use anyhow::{Context, Result, anyhow};
use clap::Args;
use git2::{AnnotatedCommit, AutotagOption, FetchOptions, RemoteCallbacks, Repository};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use tracing::{debug, info, warn};

use crate::command::Command;
use crate::common::RuntimeContext;

/// Update command
#[derive(Args)]
pub struct UpdateCommand {
    /// Apply changes after pulling (default: true)
    #[arg(short, long, default_value_t = true)]
    pub apply: bool,

    /// Use rebase instead of merge when branches diverge
    #[arg(short, long)]
    pub rebase: bool,
}

impl Command for UpdateCommand {
    type Output = ();
    fn execute(&self, context: &RuntimeContext) -> crate::error::Result<()> {
        run_impl(context, self.apply, self.rebase).map_err(Into::into)
    }
}

/// Validate source directory and open repository
fn validate_and_open_repository(source_dir: &Path) -> Result<Repository> {
    if !source_dir.exists() {
        return Err(anyhow!(
            "Source directory does not exist: {}",
            source_dir.display()
        ));
    }

    Repository::open(source_dir).with_context(|| {
        format!(
            "Failed to open git repository at {}. Did you initialize with 'guisu init'?",
            source_dir.display()
        )
    })
}

/// Get the default remote for the repository
fn get_default_remote(repo: &Repository) -> Result<String> {
    if let Ok(head) = repo.head()
        && let Ok(branch_name) = head.shorthand()
        && let Ok(branch) = repo.find_branch(branch_name, git2::BranchType::Local)
        && let Ok(upstream) = branch.upstream()
        && let Some(upstream_name) = upstream.name()?
        && let Some(remote_name) = upstream_name.split('/').nth(2)
    {
        return Ok(remote_name.to_string());
    }

    let remotes = repo.remotes()?;
    if let Ok(Some(first_remote)) = remotes.get(0) {
        Ok(first_remote.to_string())
    } else {
        Err(anyhow!(
            "No remotes found. Make sure this repository has at least one remote."
        ))
    }
}

/// Get the upstream branch refspec for the current branch
fn get_upstream_refspec(repo: &Repository) -> Result<Option<String>> {
    if let Ok(head) = repo.head()
        && let Ok(branch_name) = head.shorthand()
        && let Ok(branch) = repo.find_branch(branch_name, git2::BranchType::Local)
        && let Ok(upstream) = branch.upstream()
        && let Some(upstream_name) = upstream.name()?
    {
        // Extract branch name from refs/remotes/<remote>/<branch>
        // e.g., "refs/remotes/origin/main" -> "main"
        if let Some(branch_part) = upstream_name.strip_prefix("refs/remotes/")
            && let Some((_remote, branch)) = branch_part.split_once('/')
        {
            return Ok(Some(branch.to_string()));
        }
    }
    Ok(None)
}

/// Setup and perform fetch with progress bar
fn setup_fetch_with_progress(repo: &Repository) -> Result<()> {
    let remote_name = get_default_remote(repo)?;
    let mut remote = repo.find_remote(&remote_name)?;

    let refspecs = if let Some(branch) = get_upstream_refspec(repo)? {
        vec![branch]
    } else {
        vec![]
    };

    let progress_bar = ProgressBar::new(100);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.cyan} {bar:50.cyan/black} {pos:>3}% {msg:.white.dim}")
            .expect("Invalid progress bar template")
            .progress_chars("━━╸ "),
    );

    let mut callbacks = RemoteCallbacks::new();
    let git_config = git2::Config::open_default()
        .unwrap_or_else(|_| git2::Config::new().expect("Failed to create git config"));
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
    fetch_options.download_tags(AutotagOption::Auto);

    debug!("Fetching from remote");
    progress_bar.set_message("Fetching updates...");

    remote
        .fetch(&refspecs, Some(&mut fetch_options), None)
        .with_context(|| "Failed to fetch from remote. Check your network connection.")?;

    progress_bar.finish_and_clear();

    Ok(())
}

/// Analyze fetch result and return merge analysis
fn analyze_fetch_result(repo: &Repository) -> Result<AnnotatedCommit<'_>> {
    let fetch_head = repo
        .find_reference("FETCH_HEAD")
        .context("Failed to find FETCH_HEAD after fetch")?;

    repo.reference_to_annotated_commit(&fetch_head)
        .context("Failed to get fetch commit")
}

/// Handle different merge scenarios
fn handle_merge_scenarios(
    repo: &Repository,
    fetch_commit: &AnnotatedCommit,
    source_dir: &Path,
    rebase: bool,
) -> Result<()> {
    let analysis = repo
        .merge_analysis(&[fetch_commit])
        .context("Failed to analyze merge")?;

    if analysis.0.is_up_to_date() {
        info!("Already up to date");
        return Ok(());
    }

    if analysis.0.is_fast_forward() {
        debug!("Performing fast-forward merge");
        perform_fast_forward(repo, fetch_commit).context("Failed to perform fast-forward merge")?;

        let commit_count = count_new_commits(repo, fetch_commit)?;
        info!(commits = commit_count, "Successfully updated");
        println!(
            "✓ Updated successfully ({} new commit{})",
            commit_count,
            if commit_count == 1 { "" } else { "s" }
        );
    } else if analysis.0.is_normal() {
        if rebase {
            debug!("Performing rebase");
            println!("Branches have diverged. Rebasing local changes...");

            perform_rebase(repo, fetch_commit).context("Failed to perform rebase")?;

            let commit_count = count_new_commits(repo, fetch_commit)?;
            info!(commits = commit_count, "Successfully rebased and updated");
            println!(
                "✓ Rebased successfully ({} new commit{})",
                commit_count,
                if commit_count == 1 { "" } else { "s" }
            );
        } else {
            warn!("Manual merge required");
            return Err(anyhow!(
                "Cannot fast-forward. Your local repository has diverged from the remote.\n\
                Please resolve this manually:\n\
                  cd {}\n\
                  git pull --rebase\n\
                \n\
                Or use: guisu update --rebase",
                source_dir.display()
            ));
        }
    } else {
        return Err(anyhow!(
            "Unknown merge state. Please update manually:\n\
              cd {}\n\
              git pull",
            source_dir.display()
        ));
    }

    Ok(())
}

/// Apply changes after update
fn apply_changes_after_update(context: &RuntimeContext) -> Result<()> {
    let apply_cmd = crate::cmd::apply::ApplyCommand {
        files: vec![],
        dry_run: false,
        force: false,
        interactive: false,
    };

    apply_cmd
        .execute(context)
        .context("Failed to apply changes")
        .map(|_| ())
}

/// Run the update command implementation
///
/// Pulls the latest changes from the remote repository and optionally applies them.
fn run_impl(context: &RuntimeContext, apply: bool, rebase: bool) -> Result<()> {
    let source_dir = context.source_dir();
    let repo = validate_and_open_repository(source_dir)?;

    let remote_name = get_default_remote(&repo)?;
    let remote_url = repo
        .find_remote(&remote_name)
        .ok()
        .and_then(|r| r.url().ok().map(str::to_string))
        .unwrap_or_else(|| source_dir.display().to_string());

    info!("Updating repository from {}", remote_url);

    setup_fetch_with_progress(&repo)?;

    let fetch_commit = analyze_fetch_result(&repo)?;

    handle_merge_scenarios(&repo, &fetch_commit, source_dir, rebase)?;

    if apply {
        apply_changes_after_update(context)?;
    }

    Ok(())
}

/// Perform a fast-forward merge
fn perform_fast_forward(repo: &Repository, fetch_commit: &AnnotatedCommit) -> Result<()> {
    let commit_id = fetch_commit.id();

    let main_ref_name = "refs/heads/main";
    let master_ref_name = "refs/heads/master";

    let reference = repo
        .find_reference("HEAD")
        .context("Failed to find HEAD reference")?;

    let reference = if reference.is_branch() {
        reference
    } else {
        repo.find_reference(main_ref_name)
            .or_else(|_| repo.find_reference(master_ref_name))
            .context("Failed to find main/master branch")?
    };

    let current_ref_name = reference
        .name()
        .map_err(|e| anyhow!("Invalid reference name: {e}"))?;

    repo.reference(
        current_ref_name,
        commit_id,
        true,
        &format!("guisu update: fast-forward to {commit_id}"),
    )
    .context("Failed to update reference")?;

    repo.checkout_head(Some(
        git2::build::CheckoutBuilder::new()
            .force()
            .remove_untracked(false),
    ))
    .context("Failed to checkout HEAD")?;

    debug!(commit = %commit_id, "Fast-forward complete");
    Ok(())
}

/// Perform a rebase operation
fn perform_rebase(repo: &Repository, fetch_commit: &AnnotatedCommit) -> Result<()> {
    use git2::RebaseOptions;

    let head = repo.head().context("Failed to get HEAD")?;
    let head_commit_obj = head.peel_to_commit().context("Failed to get HEAD commit")?;
    let head_commit = repo
        .find_annotated_commit(head_commit_obj.id())
        .context("Failed to convert HEAD commit to annotated commit")?;

    let branch_name = head
        .shorthand()
        .map_err(|e| anyhow!("Failed to get branch name: {e}"))?
        .to_string();

    debug!(branch = %branch_name, "Starting rebase");

    let mut rebase_options = RebaseOptions::new();
    let mut rebase = repo
        .rebase(
            Some(&head_commit),
            Some(fetch_commit),
            None,
            Some(&mut rebase_options),
        )
        .context("Failed to initialize rebase")?;

    while let Some(op) = rebase.next() {
        let operation = op.context("Failed to get rebase operation")?;
        let commit_id = operation.id();
        debug!(commit = %commit_id, "Rebasing commit");

        rebase
            .commit(None, &repo.signature()?, None)
            .with_context(|| format!("Failed to apply commit {commit_id} during rebase"))?;
    }

    rebase.finish(None).context("Failed to finish rebase")?;

    debug!("Rebase complete");
    Ok(())
}

/// Count how many new commits were pulled
fn count_new_commits(repo: &Repository, new_commit: &AnnotatedCommit) -> Result<usize> {
    let head = repo.head().context("Failed to get HEAD")?;
    let head_commit = head
        .peel_to_commit()
        .context("Failed to peel HEAD to commit")?;

    let new_commit_obj = repo
        .find_commit(new_commit.id())
        .context("Failed to find new commit")?;

    let mut revwalk = repo.revwalk().context("Failed to create revwalk")?;
    revwalk
        .push(new_commit_obj.id())
        .context("Failed to push new commit")?;
    revwalk
        .hide(head_commit.id())
        .context("Failed to hide old commit")?;

    let count = revwalk.count();
    Ok(count)
}
