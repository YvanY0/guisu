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
    fn execute(&self, context: &mut RuntimeContext) -> anyhow::Result<()> {
        run_impl(context, self.apply, self.rebase)
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
fn apply_changes_after_update(context: &mut RuntimeContext) -> Result<()> {
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
fn run_impl(context: &mut RuntimeContext, apply: bool, rebase: bool) -> Result<()> {
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

/// Fast-forward the current state to the fetched commit
///
/// The caller has already confirmed via merge analysis that the fetched
/// commit descends from HEAD, so a hard reset produces exactly the
/// fast-forward result (like `git reset --hard <fetched>` after `git fetch`):
/// on a branch it advances that branch, with a detached HEAD it moves HEAD.
fn perform_fast_forward(repo: &Repository, fetch_commit: &AnnotatedCommit) -> Result<()> {
    let commit_id = fetch_commit.id();

    let object = repo
        .find_object(commit_id, Some(git2::ObjectType::Commit))
        .context("Failed to find fetched commit")?;

    repo.reset(
        &object,
        git2::ResetType::Hard,
        Some(
            git2::build::CheckoutBuilder::new()
                .force()
                .remove_untracked(false),
        ),
    )
    .context("Failed to fast-forward to fetched commit")?;

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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use tempfile::TempDir;

    /// Create a repo with two commits on the given initial branch and return
    /// the ids of both commits (the second is the "fetched" commit).
    fn repo_with_two_commits(dir: &Path, initial_head: &str) -> (Repository, git2::Oid, git2::Oid) {
        let mut opts = git2::RepositoryInitOptions::new();
        opts.initial_head(initial_head);
        let repo = Repository::init_opts(dir, &opts).unwrap();

        // Fixed signature — repo.signature() would fall back to the global
        // git config (user.name/user.email), which CI environments lack.
        let sig = git2::Signature::now("guisu test", "test@guisu.local").unwrap();
        let (tree_id, tree_id2) = {
            let odb = repo.odb().unwrap();
            let blob_id = odb.write(git2::ObjectType::Blob, b"v1").unwrap();
            let tree_id = {
                let mut builder = repo.treebuilder(None).unwrap();
                builder
                    .insert("file.txt", blob_id, git2::FileMode::Blob.into())
                    .unwrap();
                builder.write().unwrap()
            };

            let blob_id2 = odb.write(git2::ObjectType::Blob, b"v2").unwrap();
            let tree_id2 = {
                let mut builder = repo.treebuilder(None).unwrap();
                builder
                    .insert("file.txt", blob_id2, git2::FileMode::Blob.into())
                    .unwrap();
                builder.write().unwrap()
            };
            (tree_id, tree_id2)
        };

        let first;
        let second;
        {
            let tree = repo.find_tree(tree_id).unwrap();
            let tree2 = repo.find_tree(tree_id2).unwrap();
            first = repo
                .commit(Some("HEAD"), &sig, &sig, "first", &tree, &[])
                .unwrap();
            let parent = repo.find_commit(first).unwrap();
            second = repo
                .commit(Some("HEAD"), &sig, &sig, "second", &tree2, &[&parent])
                .unwrap();
        }

        (repo, first, second)
    }

    #[test]
    fn test_fast_forward_detached_head() {
        let temp = TempDir::new().unwrap();
        let (repo, first_id, fetched_id) = repo_with_two_commits(temp.path(), "refs/heads/guisu");

        // Detach HEAD at the first commit
        repo.set_head_detached(first_id).unwrap();
        repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
            .unwrap();

        let fetch_commit = repo.find_annotated_commit(fetched_id).unwrap();
        perform_fast_forward(&repo, &fetch_commit).unwrap();

        let head = repo.head().unwrap();
        assert!(!head.is_branch());
        assert_eq!(head.peel_to_commit().unwrap().id(), fetched_id);
    }

    #[test]
    fn test_fast_forward_custom_branch_name() {
        let temp = TempDir::new().unwrap();
        let (repo, _, fetched_id) = repo_with_two_commits(temp.path(), "refs/heads/guisu");

        let fetch_commit = repo.find_annotated_commit(fetched_id).unwrap();
        perform_fast_forward(&repo, &fetch_commit).unwrap();

        let head = repo.head().unwrap();
        assert_eq!(head.shorthand().unwrap(), "guisu");
        assert_eq!(head.peel_to_commit().unwrap().id(), fetched_id);
    }

    #[test]
    fn test_fast_forward_main_branch() {
        let temp = TempDir::new().unwrap();
        let (repo, _, fetched_id) = repo_with_two_commits(temp.path(), "refs/heads/main");

        let fetch_commit = repo.find_annotated_commit(fetched_id).unwrap();
        perform_fast_forward(&repo, &fetch_commit).unwrap();

        let head = repo.head().unwrap();
        assert_eq!(head.shorthand().unwrap(), "main");
        assert_eq!(head.peel_to_commit().unwrap().id(), fetched_id);
    }
}
