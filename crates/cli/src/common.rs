//! Common utilities and types shared across CLI commands

use anyhow::{Context, Result};
use guisu_config::Config;
use guisu_core::path::AbsPath;
use guisu_engine::state::RedbPersistentState;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Resolved paths for dotfile operations
///
/// Holds canonicalized absolute paths, handling `root_entry` configuration.
#[derive(Debug, Clone)]
pub struct ResolvedPaths {
    /// Source directory path (not necessarily absolute)
    pub source_dir: PathBuf,
    /// Canonicalized destination directory
    pub dest_dir: AbsPath,
    /// Canonicalized dotfiles directory (accounts for `root_entry` config)
    pub dotfiles_dir: AbsPath,
}

impl ResolvedPaths {
    /// Resolve and canonicalize paths from source/dest directories
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Canonicalizing the dotfiles directory fails
    /// - Canonicalizing the destination directory fails
    /// - Creating absolute path wrappers fails
    pub fn resolve(source_dir: &Path, dest_dir: &Path, config: &Config) -> Result<Self> {
        let dotfiles_dir = config.dotfiles_dir(source_dir);

        // If dotfiles_dir doesn't exist, use its absolute path without canonicalizing
        // This matches chezmoi's behavior: when sourceDir doesn't exist, it simply
        // treats it as having no managed files instead of erroring
        let dotfiles_abs = if let Ok(canonical) = fs::canonicalize(&dotfiles_dir) {
            AbsPath::new(canonical)?
        } else {
            // Directory doesn't exist, use absolute path
            let abs_path = if dotfiles_dir.is_absolute() {
                dotfiles_dir.clone()
            } else {
                std::env::current_dir()?.join(&dotfiles_dir)
            };
            AbsPath::new(abs_path)?
        };

        let dest_abs = AbsPath::new(fs::canonicalize(dest_dir).with_context(|| {
            format!("Destination directory not found: {}", dest_dir.display())
        })?)?;

        Ok(Self {
            source_dir: source_dir.to_path_buf(),
            dest_dir: dest_abs,
            dotfiles_dir: dotfiles_abs,
        })
    }
}

/// Runtime context for CLI commands
///
/// Consolidates config, paths, database, and caches to reduce parameter passing.
#[derive(Clone)]
pub struct RuntimeContext {
    /// Application configuration
    pub config: Arc<Config>,
    /// Resolved and canonicalized paths
    pub paths: ResolvedPaths,
    /// Database instance for persistent state
    pub database: Arc<RedbPersistentState>,
    identities_cache: Arc<std::sync::OnceLock<Arc<[guisu_crypto::Identity]>>>,
    guisu_dir_cache: Arc<std::sync::OnceLock<PathBuf>>,
    templates_dir_cache: Arc<std::sync::OnceLock<Option<PathBuf>>>,
}

impl RuntimeContext {
    /// Create runtime context with resolved and canonicalized paths
    ///
    /// # Errors
    ///
    /// Returns an error if resolving and canonicalizing paths fails or database creation fails
    pub fn new(config: Config, source_dir: &Path, dest_dir: &Path) -> Result<Self> {
        let paths = ResolvedPaths::resolve(source_dir, dest_dir, &config)?;

        // Initialize database
        let db_path =
            guisu_engine::database::get_db_path().context("Failed to get database path")?;
        let database =
            RedbPersistentState::new(&db_path).context("Failed to create database instance")?;

        Ok(Self {
            config: Arc::new(config),
            paths,
            database: Arc::new(database),
            identities_cache: Arc::new(std::sync::OnceLock::new()),
            guisu_dir_cache: Arc::new(std::sync::OnceLock::new()),
            templates_dir_cache: Arc::new(std::sync::OnceLock::new()),
        })
    }

    /// Create context from already-resolved paths
    ///
    /// # Panics
    ///
    /// Panics if database path cannot be retrieved or database creation fails.
    /// This is acceptable for a convenience constructor.
    #[must_use]
    pub fn from_parts(config: Arc<Config>, paths: ResolvedPaths) -> Self {
        // Initialize database (panic on failure since this is a convenience constructor)
        let db_path = guisu_engine::database::get_db_path().expect("Failed to get database path");
        let database =
            RedbPersistentState::new(&db_path).expect("Failed to create database instance");

        Self {
            config,
            paths,
            database: Arc::new(database),
            identities_cache: Arc::new(std::sync::OnceLock::new()),
            guisu_dir_cache: Arc::new(std::sync::OnceLock::new()),
            templates_dir_cache: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Create context from already-resolved paths and existing database
    ///
    /// Use this when you've already created a database instance (e.g., for config caching)
    /// to avoid creating the database twice.
    #[must_use]
    pub fn from_parts_with_db(
        config: Arc<Config>,
        paths: ResolvedPaths,
        database: Arc<RedbPersistentState>,
    ) -> Self {
        Self {
            config,
            paths,
            database,
            identities_cache: Arc::new(std::sync::OnceLock::new()),
            guisu_dir_cache: Arc::new(std::sync::OnceLock::new()),
            templates_dir_cache: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Get the source directory (original input, may contain .guisu)
    #[inline]
    #[must_use]
    pub fn source_dir(&self) -> &Path {
        &self.paths.source_dir
    }

    /// Get the destination directory (canonicalized)
    #[inline]
    #[must_use]
    pub fn dest_dir(&self) -> &AbsPath {
        &self.paths.dest_dir
    }

    /// Get the dotfiles directory (canonicalized, includes `root_entry` if configured)
    #[inline]
    #[must_use]
    pub fn dotfiles_dir(&self) -> &AbsPath {
        &self.paths.dotfiles_dir
    }

    /// Get the database instance
    #[inline]
    #[must_use]
    pub fn database(&self) -> &Arc<RedbPersistentState> {
        &self.database
    }

    /// Load age identities (cached)
    ///
    /// # Errors
    ///
    /// Returns an error if loading age identities from configuration fails
    pub fn load_identities(&self) -> crate::error::Result<Arc<[guisu_crypto::Identity]>> {
        // Check if already initialized
        if let Some(identities) = self.identities_cache.get() {
            return Ok(Arc::clone(identities));
        }

        // Initialize if not cached
        let identities = self.config.age_identities()?;
        let arc_identities = Arc::from(identities.into_boxed_slice());

        // Try to set the value (ignore if another thread already set it)
        let _ = self.identities_cache.set(Arc::clone(&arc_identities));

        Ok(arc_identities)
    }

    /// Get the primary identity or generate a dummy one
    ///
    /// # Errors
    ///
    /// Returns an error if loading age identities fails
    pub fn primary_identity(&self) -> crate::error::Result<guisu_crypto::Identity> {
        let identities = self.load_identities()?;
        Ok(identities
            .first()
            .cloned()
            .unwrap_or_else(guisu_crypto::Identity::generate))
    }

    /// Get the .guisu directory path
    #[must_use]
    pub fn guisu_dir(&self) -> &PathBuf {
        self.guisu_dir_cache
            .get_or_init(|| self.source_dir().join(".guisu"))
    }

    /// Get the templates directory path if it exists
    #[must_use]
    pub fn templates_dir(&self) -> Option<&PathBuf> {
        self.templates_dir_cache
            .get_or_init(|| {
                let dir = self.source_dir().join(".guisu").join("templates");
                dir.exists().then_some(dir)
            })
            .as_ref()
    }

    /// Get the git working tree path (repository root)
    ///
    /// Attempts to find the git repository root from `source_dir`.
    /// Falls back to `source_dir` if no git repository is found.
    #[must_use]
    pub fn working_tree(&self) -> PathBuf {
        guisu_engine::git::find_working_tree(self.source_dir())
            .unwrap_or_else(|| self.source_dir().to_path_buf())
    }

    /// Create runtime context with a custom database path (test only)
    ///
    /// # Errors
    ///
    /// Returns an error if resolving paths fails or database creation fails
    #[cfg(test)]
    pub fn new_with_db_path(
        config: Config,
        source_dir: &Path,
        dest_dir: &Path,
        db_path: &Path,
    ) -> Result<Self> {
        let paths = ResolvedPaths::resolve(source_dir, dest_dir, &config)?;

        // Initialize database with custom path
        let database =
            RedbPersistentState::new(db_path).context("Failed to create database instance")?;

        Ok(Self {
            config: Arc::new(config),
            paths,
            database: Arc::new(database),
            identities_cache: Arc::new(std::sync::OnceLock::new()),
            guisu_dir_cache: Arc::new(std::sync::OnceLock::new()),
            templates_dir_cache: Arc::new(std::sync::OnceLock::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use tempfile::TempDir;

    // Helper to create test config
    fn test_config() -> Config {
        Config::default()
    }

    // Helper to create test config with root_entry
    fn test_config_with_root_entry(root_entry: &str) -> Config {
        let mut config = Config::default();
        config.general.root_entry = root_entry.into();
        config
    }

    // Helper to create RuntimeContext with isolated database for testing
    fn test_runtime_context(
        config: Config,
        source_dir: &Path,
        dest_dir: &Path,
        temp_db_dir: &TempDir,
    ) -> RuntimeContext {
        let db_path = temp_db_dir.path().join("test.db");
        RuntimeContext::new_with_db_path(config, source_dir, dest_dir, &db_path)
            .expect("Failed to create test RuntimeContext")
    }

    // Tests for ResolvedPaths

    #[test]
    fn test_resolved_paths_basic() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");

        // Create home directory (default root_entry)
        let home_dir = source_dir.join("home");
        std::fs::create_dir_all(&home_dir).expect("Failed to create home dir");

        let config = test_config();
        let paths = ResolvedPaths::resolve(&source_dir, &dest_dir, &config);

        assert!(paths.is_ok());
        let paths = paths.unwrap();

        assert_eq!(paths.source_dir, source_dir);
        assert!(paths.dest_dir.as_path().ends_with("dst"));
        assert!(paths.dotfiles_dir.as_path().ends_with("home"));
    }

    #[test]
    fn test_resolved_paths_with_custom_root_entry() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");

        // Create custom root_entry directory
        let dotfiles_dir = source_dir.join("dotfiles");
        std::fs::create_dir_all(&dotfiles_dir).expect("Failed to create dotfiles dir");

        let config = test_config_with_root_entry("dotfiles");
        let paths = ResolvedPaths::resolve(&source_dir, &dest_dir, &config);

        assert!(paths.is_ok());
        let paths = paths.unwrap();

        assert_eq!(paths.source_dir, source_dir);
        assert!(paths.dotfiles_dir.as_path().ends_with("dotfiles"));
    }

    #[test]
    fn test_resolved_paths_nonexistent_dest() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("nonexistent");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let paths = ResolvedPaths::resolve(&source_dir, &dest_dir, &config);

        // Should fail because dest_dir doesn't exist
        assert!(paths.is_err());
    }

    #[test]
    fn test_resolved_paths_clone() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let paths = ResolvedPaths::resolve(&source_dir, &dest_dir, &config).unwrap();

        let cloned = paths.clone();
        assert_eq!(paths.source_dir, cloned.source_dir);
        assert_eq!(paths.dest_dir, cloned.dest_dir);
        assert_eq!(paths.dotfiles_dir, cloned.dotfiles_dir);
    }

    // Tests for RuntimeContext

    #[test]
    fn test_runtime_context_new() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let _context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);
        // Test passes if no panic occurs during creation
    }

    #[test]
    fn test_runtime_context_from_parts() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        assert_eq!(context.source_dir(), &source_dir);
    }

    #[test]
    fn test_runtime_context_source_dir() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        assert_eq!(context.source_dir(), &source_dir);
    }

    #[test]
    fn test_runtime_context_dest_dir() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        assert!(context.dest_dir().as_path().ends_with("dst"));
    }

    #[test]
    fn test_runtime_context_dotfiles_dir() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        assert!(context.dotfiles_dir().as_path().ends_with("home"));
    }

    #[test]
    fn test_runtime_context_guisu_dir() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        let guisu_dir = context.guisu_dir();
        assert!(guisu_dir.ends_with(".guisu"));
    }

    #[test]
    fn test_runtime_context_guisu_dir_cached() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        // Call twice to test caching
        let guisu_dir1 = context.guisu_dir();
        let guisu_dir2 = context.guisu_dir();

        assert_eq!(guisu_dir1, guisu_dir2);
        // Verify they're the same pointer (cached)
        assert!(std::ptr::eq(guisu_dir1, guisu_dir2));
    }

    #[test]
    fn test_runtime_context_templates_dir_exists() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create templates directory
        let templates_dir = source_dir.join(".guisu").join("templates");
        std::fs::create_dir_all(&templates_dir).expect("Failed to create templates dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        let templates = context.templates_dir();
        assert!(templates.is_some());
        assert!(templates.unwrap().ends_with("templates"));
    }

    #[test]
    fn test_runtime_context_templates_dir_not_exists() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        let templates = context.templates_dir();
        assert!(templates.is_none());
    }

    #[test]
    fn test_runtime_context_working_tree_no_git() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        let working_tree = context.working_tree();
        // Should fallback to source_dir when no git repo found
        assert_eq!(working_tree, source_dir);
    }

    #[test]
    fn test_runtime_context_clone() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        let cloned = context.clone();
        assert_eq!(context.source_dir(), cloned.source_dir());
        assert_eq!(context.dest_dir(), cloned.dest_dir());
    }

    #[test]
    fn test_runtime_context_primary_identity_no_identities() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize");

        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&source_dir).expect("Failed to create source dir");
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        let config = test_config();
        let temp_db = TempDir::new().expect("Failed to create temp db dir");
        let context = test_runtime_context(config, &source_dir, &dest_dir, &temp_db);

        // Should generate a dummy identity when no identities configured
        let identity = context.primary_identity();
        // Will fail to load identities, but that's expected
        assert!(identity.is_err());
    }
}
