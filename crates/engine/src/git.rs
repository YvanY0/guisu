//! Git operations abstraction layer
//!
//! This module provides a unified interface for Git operations, supporting both:
//! - Built-in git via git2 (libgit2) - default
//! - External git command - fallback or when explicitly configured
//!
//! The abstraction allows switching between implementations based on configuration
//! or availability, similar to chezmoi's approach.

use guisu_core::Result;
use std::path::Path;

/// Helper function to convert git2 errors to `guisu_core` errors
#[inline]
#[allow(clippy::needless_pass_by_value)]
fn git_err(e: git2::Error) -> guisu_core::Error {
    guisu_core::Error::Message(format!("Git error: {e}"))
}

/// Git provider trait defining all git operations needed by guisu
pub trait GitProvider {
    /// Clone a repository from URL to target path
    ///
    /// # Errors
    ///
    /// Returns an error if cloning fails (e.g., invalid URL, network error, authentication failure, target exists)
    fn clone(
        &self,
        url: &str,
        target: &Path,
        depth: Option<usize>,
        branch: Option<&str>,
        recurse_submodules: bool,
    ) -> Result<()>;

    /// Fetch updates from remote
    ///
    /// # Errors
    ///
    /// Returns an error if fetching fails (e.g., not a repository, remote not found, network error)
    fn fetch(&self, repo_path: &Path, remote: &str) -> Result<()>;

    /// Perform fast-forward merge
    ///
    /// # Errors
    ///
    /// Returns an error if fast-forward fails (e.g., conflicts, not a fast-forward, repository issues)
    fn fast_forward(&self, repo_path: &Path) -> Result<usize>;

    /// Perform rebase
    ///
    /// # Errors
    ///
    /// Returns an error if rebase fails (e.g., conflicts, repository issues, invalid state)
    fn rebase(&self, repo_path: &Path) -> Result<()>;

    /// Check if repository is up to date
    ///
    /// # Errors
    ///
    /// Returns an error if the check fails (e.g., not a repository, `FETCH_HEAD` not found)
    fn is_up_to_date(&self, repo_path: &Path) -> Result<bool>;

    /// Get repository status (has uncommitted changes, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if status cannot be determined (e.g., not a repository, I/O error)
    fn status(&self, repo_path: &Path) -> Result<GitStatus>;

    /// Get current branch name
    ///
    /// # Errors
    ///
    /// Returns an error if branch name cannot be determined (e.g., not a repository, detached HEAD)
    fn current_branch(&self, repo_path: &Path) -> Result<String>;
}

/// Git repository status
#[derive(Debug, Clone)]
pub struct GitStatus {
    /// Whether the repository has uncommitted changes
    pub has_uncommitted_changes: bool,
    /// Whether the repository has untracked files
    pub has_untracked_files: bool,
    /// Current branch name
    pub branch: String,
}

/// Type alias for progress callback function
/// Arguments: (current, total, percentage)
type ProgressCallback = Box<dyn Fn(usize, usize, f64) + Send + Sync>;

/// Git provider implementation using git2 (libgit2)
pub struct Git2Provider {
    progress_callback: Option<ProgressCallback>,
}

impl Git2Provider {
    /// Create a new Git2 provider
    #[must_use]
    pub fn new() -> Self {
        Self {
            progress_callback: None,
        }
    }

    /// Set progress callback for clone/fetch operations
    #[must_use]
    pub fn with_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize, usize, f64) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }
}

impl Default for Git2Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl GitProvider for Git2Provider {
    fn clone(
        &self,
        url: &str,
        target: &Path,
        depth: Option<usize>,
        branch: Option<&str>,
        recurse_submodules: bool,
    ) -> Result<()> {
        use git2::{FetchOptions, RemoteCallbacks, build::RepoBuilder};

        // Set up callbacks for progress reporting
        let mut callbacks = RemoteCallbacks::new();
        if let Some(progress_fn) = &self.progress_callback {
            callbacks.transfer_progress(move |stats| {
                let received = stats.received_objects();
                let total = stats.total_objects();
                #[allow(clippy::cast_precision_loss)]
                let bytes_mb = stats.received_bytes() as f64 / 1_048_576.0;
                progress_fn(received, total, bytes_mb);
                true
            });
        }

        // Configure fetch options
        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);

        if let Some(d) = depth {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            fetch_options.depth(d as i32);
        }

        // Build and execute clone
        let mut builder = RepoBuilder::new();
        builder.fetch_options(fetch_options);

        if let Some(b) = branch {
            builder.branch(b);
        }

        let repo = builder.clone(url, target)
            .map_err(|e| guisu_core::Error::Message(
                format!(
                    "Failed to clone repository from {url}. Check the URL and your network connection. Error: {e}"
                )
            ))?;

        // Initialize submodules if requested
        if recurse_submodules {
            init_submodules_recursive(&repo, target)?;
        }

        Ok(())
    }

    fn fetch(&self, repo_path: &Path, remote: &str) -> Result<()> {
        use git2::{AutotagOption, FetchOptions, RemoteCallbacks, Repository};

        let repo = Repository::open(repo_path).map_err(git_err)?;
        let mut remote = repo.find_remote(remote).map_err(git_err)?;

        let mut callbacks = RemoteCallbacks::new();
        if let Some(progress_fn) = &self.progress_callback {
            callbacks.transfer_progress(move |stats| {
                let received = stats.received_objects();
                let total = stats.total_objects();
                #[allow(clippy::cast_precision_loss)]
                let bytes_mb = stats.received_bytes() as f64 / 1_048_576.0;
                progress_fn(received, total, bytes_mb);
                true
            });
        }

        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);
        fetch_options.download_tags(AutotagOption::Auto);

        remote
            .fetch(&["HEAD"], Some(&mut fetch_options), None)
            .map_err(git_err)?;

        Ok(())
    }

    fn fast_forward(&self, repo_path: &Path) -> Result<usize> {
        use git2::Repository;

        let repo = Repository::open(repo_path).map_err(git_err)?;

        // Get FETCH_HEAD
        let fetch_head = repo.find_reference("FETCH_HEAD").map_err(git_err)?;
        let fetch_commit = repo
            .reference_to_annotated_commit(&fetch_head)
            .map_err(git_err)?;

        // Get the commit object
        let commit_id = fetch_commit.id();

        // Update HEAD reference
        let reference = repo.find_reference("HEAD").map_err(git_err)?;
        let ref_name = reference.name().map_err(git_err)?;

        repo.reference(
            ref_name,
            commit_id,
            true,
            &format!("guisu update: fast-forward to {commit_id}"),
        )
        .map_err(git_err)?;

        // Checkout updated HEAD
        repo.checkout_head(Some(
            git2::build::CheckoutBuilder::new()
                .force()
                .remove_untracked(false),
        ))
        .map_err(git_err)?;

        // Count new commits
        count_new_commits(&repo, &fetch_commit)
    }

    fn rebase(&self, repo_path: &Path) -> Result<()> {
        use git2::{RebaseOptions, Repository};

        let repo = Repository::open(repo_path).map_err(git_err)?;

        // Get FETCH_HEAD and HEAD
        let fetch_head = repo.find_reference("FETCH_HEAD").map_err(git_err)?;
        let fetch_commit = repo
            .reference_to_annotated_commit(&fetch_head)
            .map_err(git_err)?;

        let head = repo.head().map_err(git_err)?;
        let head_commit_obj = head.peel_to_commit().map_err(git_err)?;
        let head_commit = repo
            .find_annotated_commit(head_commit_obj.id())
            .map_err(git_err)?;

        // Initialize and perform rebase
        let mut rebase_options = RebaseOptions::new();
        let mut rebase = repo
            .rebase(
                Some(&head_commit),
                Some(&fetch_commit),
                None,
                Some(&mut rebase_options),
            )
            .map_err(git_err)?;

        while let Some(op) = rebase.next() {
            op.map_err(git_err)?;
            rebase
                .commit(None, &repo.signature().map_err(git_err)?, None)
                .map_err(git_err)?;
        }

        rebase.finish(None).map_err(git_err)?;
        Ok(())
    }

    fn is_up_to_date(&self, repo_path: &Path) -> Result<bool> {
        use git2::Repository;

        let repo = Repository::open(repo_path).map_err(git_err)?;
        let fetch_head = repo.find_reference("FETCH_HEAD").map_err(git_err)?;
        let fetch_commit = repo
            .reference_to_annotated_commit(&fetch_head)
            .map_err(git_err)?;

        let analysis = repo.merge_analysis(&[&fetch_commit]).map_err(git_err)?;
        Ok(analysis.0.is_up_to_date())
    }

    fn status(&self, repo_path: &Path) -> Result<GitStatus> {
        use git2::Repository;

        let repo = Repository::open(repo_path).map_err(git_err)?;
        let statuses = repo.statuses(None).map_err(git_err)?;

        let has_uncommitted_changes = statuses
            .iter()
            .any(|s| s.status().is_index_modified() || s.status().is_wt_modified());

        let has_untracked_files = statuses.iter().any(|s| s.status().is_wt_new());

        let head = repo.head().map_err(git_err)?;
        let branch = head.shorthand().map_err(git_err)?.to_string();

        Ok(GitStatus {
            has_uncommitted_changes,
            has_untracked_files,
            branch,
        })
    }

    fn current_branch(&self, repo_path: &Path) -> Result<String> {
        use git2::Repository;

        let repo = Repository::open(repo_path).map_err(git_err)?;
        let head = repo.head().map_err(git_err)?;
        let branch = head.shorthand().map_err(git_err)?.to_string();
        Ok(branch)
    }
}

/// Helper function to recursively initialize submodules
fn init_submodules_recursive(repo: &git2::Repository, repo_path: &Path) -> Result<()> {
    use git2::{FetchOptions, RemoteCallbacks, Repository, SubmoduleUpdateOptions};

    let submodules = repo.submodules().map_err(git_err)?;

    for mut submodule in submodules {
        let _name = submodule.name().unwrap_or("<unnamed>");
        let path = submodule.path().to_path_buf();

        // Initialize the submodule
        submodule.init(false).map_err(git_err)?;

        // Update the submodule
        let mut update_options = SubmoduleUpdateOptions::new();
        let mut fetch_options = FetchOptions::new();
        let mut callbacks = RemoteCallbacks::new();
        callbacks.transfer_progress(|_| true);
        fetch_options.remote_callbacks(callbacks);
        update_options.fetch(fetch_options);

        submodule
            .update(true, Some(&mut update_options))
            .map_err(git_err)?;

        // Recursively initialize nested submodules
        let submodule_path = repo_path.join(&path);
        if let Ok(sub_repo) = Repository::open(&submodule_path) {
            init_submodules_recursive(&sub_repo, &submodule_path)?;
        }
    }

    Ok(())
}

/// Helper function to count new commits
fn count_new_commits(repo: &git2::Repository, new_commit: &git2::AnnotatedCommit) -> Result<usize> {
    let head = repo.head().map_err(git_err)?;
    let head_commit = head.peel_to_commit().map_err(git_err)?;
    let new_commit_obj = repo.find_commit(new_commit.id()).map_err(git_err)?;

    let mut revwalk = repo.revwalk().map_err(git_err)?;
    revwalk.push(new_commit_obj.id()).map_err(git_err)?;
    revwalk.hide(head_commit.id()).map_err(git_err)?;

    Ok(revwalk.count())
}

/// Create git provider (uses git2)
#[must_use]
pub fn create_provider(_use_builtin: &guisu_config::config::AutoBool) -> Box<dyn GitProvider> {
    Box::new(Git2Provider::new())
}

/// Find git working tree root starting from the given path
///
/// Searches upward from the given path to find a .git directory or file.
/// Returns the working tree root path if found, None otherwise.
#[must_use]
pub fn find_working_tree(start_path: &Path) -> Option<std::path::PathBuf> {
    use git2::Repository;

    // Try to open repository from the given path
    if let Ok(repo) = Repository::discover(start_path) {
        // Get the working directory (not the .git directory)
        if let Some(workdir) = repo.workdir() {
            return Some(workdir.to_path_buf());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn find_working_tree_current_dir() {
        let cwd = std::env::current_dir().unwrap();
        let result = find_working_tree(&cwd);
        assert!(
            result.is_some(),
            "Should find a git repo from the working directory"
        );
        let workdir = result.unwrap();
        assert!(workdir.exists());
        assert!(workdir.join(".git").exists());
    }

    #[test]
    fn find_working_tree_nonexistent_path() {
        let result = find_working_tree(std::path::Path::new(
            "/nonexistent/path/that/does/not/exist",
        ));
        assert!(result.is_none());
    }

    #[test]
    fn git_err_contains_message() {
        let git2_err = git2::Error::from_str("test error message");
        let guisu_err = git_err(git2_err);

        let msg = format!("{guisu_err}");
        assert!(
            msg.contains("Git error") && msg.contains("test error message"),
            "Error should contain 'Git error' and original message, got: {msg}"
        );
    }
}
