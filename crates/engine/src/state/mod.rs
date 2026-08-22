//! State management for dotfiles
//!
//! Provides state tracking for source, target, destination, and persistent states.
//!
//! The persistence layer (the [`PersistentState`] trait and the
//! [`RedbPersistentState`](persistence::RedbPersistentState) implementation)
//! lives in the [`persistence`] submodule.

mod persistence;

use crate::attr::FileAttributes;
use crate::entry::{DestEntry, SourceEntry, TargetEntry};
use crate::processor::ContentProcessor;
use crate::system::System;
use guisu_core::path::{AbsPath, RelPath, SourceRelPath};
use guisu_core::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use walkdir::WalkDir;

// Re-exports so callers can keep addressing the persistence API at
// `crate::state::*` without churning their imports.
pub use persistence::{
    CONFIG_METADATA_BUCKET, ENTRY_STATE_BUCKET, HOOK_STATE_BUCKET, PersistentState,
    RedbPersistentState, hash_data,
};

/// Custom serde module for `SystemTime` serialization
mod systemtime_serde {
    use super::{Deserialize, Deserializer, Duration, Serializer, SystemTime, UNIX_EPOCH};

    // This signature is required by serde's `#[serde(with)]` attribute
    #[allow(clippy::ref_option)]
    pub fn serialize<S>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match time {
            Some(t) => {
                let duration = t
                    .duration_since(UNIX_EPOCH)
                    .map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&duration.as_secs())
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<SystemTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs: Option<u64> = Option::deserialize(deserializer)?;
        Ok(secs.map(|s| UNIX_EPOCH + Duration::from_secs(s)))
    }
}

/// State tracking for hook execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookState {
    /// Last time hooks were executed
    #[serde(with = "systemtime_serde")]
    pub last_executed: Option<std::time::SystemTime>,
    /// blake3 hash of the hooks directory content (fixed 32-byte array)
    pub content_hash: Option<[u8; 32]>,
    /// Names of hooks that have been executed with mode=once
    /// These hooks will never be executed again unless state is reset
    #[serde(default)]
    pub once_executed: std::collections::HashSet<String>,
    /// Content hashes for hooks with mode=onchange
    /// Maps hook name to blake3 hash of its content (cmd or script, fixed 32-byte array)
    #[serde(default)]
    pub onchange_hashes: std::collections::HashMap<String, [u8; 32]>,
    /// Rendered content for hooks with mode=onchange (for diff display)
    /// Maps hook name to rendered script content
    #[serde(default)]
    pub onchange_rendered: std::collections::HashMap<String, String>,
    /// Snapshot of hooks from last execution (for diff display)
    #[serde(default)]
    pub last_collections: Option<crate::hooks::config::HookCollections>,
}

impl HookState {
    /// Create new hook state
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_executed: None,
            content_hash: None,
            once_executed: std::collections::HashSet::new(),
            onchange_hashes: std::collections::HashMap::new(),
            onchange_rendered: std::collections::HashMap::new(),
            last_collections: None,
        }
    }

    /// Check if a hook with mode=once has already been executed
    #[must_use]
    pub fn has_executed_once(&self, hook_name: &str) -> bool {
        self.once_executed.contains(hook_name)
    }

    /// Mark a hook with mode=once as executed
    pub fn mark_executed_once(&mut self, hook_name: String) {
        self.once_executed.insert(hook_name);
    }

    /// Check if a hook's content has changed (for mode=onchange)
    ///
    /// Returns true if:
    /// - No hash is stored (first run)
    /// - The stored hash differs from the provided hash
    #[must_use]
    pub fn hook_content_changed(&self, hook_name: &str, content_hash: &[u8]) -> bool {
        match self.onchange_hashes.get(hook_name) {
            None => true, // First run
            Some(stored_hash) => !bool::from(stored_hash.ct_eq(content_hash)),
        }
    }

    /// Update the content hash for a hook with mode=onchange
    pub fn update_onchange_hash(&mut self, hook_name: String, content_hash: [u8; 32]) {
        self.onchange_hashes.insert(hook_name, content_hash);
    }

    /// Update the rendered content for a hook with mode=onchange (for diff display)
    pub fn update_onchange_rendered(&mut self, hook_name: String, rendered_content: String) {
        self.onchange_rendered.insert(hook_name, rendered_content);
    }

    /// Update the state from a hooks directory
    ///
    /// This computes a hash of all files in the hooks directory and updates
    /// the `last_executed` timestamp.
    /// Optionally saves the current hook collections for diff display.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory hash cannot be computed (e.g., I/O error, permission denied)
    pub fn update(&mut self, hooks_dir: &Path) -> Result<()> {
        self.content_hash = Some(Self::compute_directory_hash(hooks_dir)?);
        self.last_executed = Some(std::time::SystemTime::now());
        Ok(())
    }

    /// Update state and save current hook collections
    ///
    /// # Errors
    ///
    /// Returns an error if the directory hash cannot be computed (e.g., I/O error, permission denied)
    pub fn update_with_collections(
        &mut self,
        hooks_dir: &Path,
        collections: crate::hooks::config::HookCollections,
    ) -> Result<()> {
        self.content_hash = Some(Self::compute_directory_hash(hooks_dir)?);
        self.last_executed = Some(std::time::SystemTime::now());
        self.last_collections = Some(collections);
        Ok(())
    }

    /// Check if hooks directory has changed
    ///
    /// Compares the current directory hash with the stored hash.
    /// Returns true if:
    /// - The directory doesn't exist
    /// - No hash is stored (first run)
    /// - The hash has changed
    ///
    /// # Errors
    ///
    /// Returns an error if the directory hash cannot be computed (e.g., I/O error, permission denied)
    pub fn has_changed(&self, hooks_dir: &Path) -> Result<bool> {
        // If directory doesn't exist, consider it unchanged
        if !hooks_dir.exists() {
            return Ok(false);
        }

        // If we have no stored hash, consider it changed (first run)
        let Some(stored_hash) = &self.content_hash else {
            return Ok(true);
        };

        // Compute current hash and compare using constant-time comparison
        // to prevent timing side-channel attacks
        let current_hash = Self::compute_directory_hash(hooks_dir)?;
        Ok(!bool::from(current_hash.ct_eq(stored_hash)))
    }

    /// Compute a hash of all files in a directory
    ///
    /// This creates a combined hash by:
    /// 1. Collecting all file paths (sequential - required by `WalkDir`)
    /// 2. Reading files and computing hashes in parallel
    /// 3. Sorting by path for deterministic ordering
    /// 4. Computing a final combined hash
    fn compute_directory_hash(dir: &Path) -> Result<[u8; 32]> {
        use rayon::prelude::*;

        // First pass: collect all file paths (must be sequential due to WalkDir)
        let file_paths: Vec<std::path::PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        // Second pass: parallel processing of files (read + hash)
        // This is where the performance benefit comes from for large hook directories
        let file_hashes: Result<Vec<(String, [u8; 32])>> = file_paths
            .par_iter()
            .map(|path| {
                // Get relative path
                let rel_path = path
                    .strip_prefix(dir)
                    .map_err(|_| Error::InvalidConfig {
                        message: format!("Invalid path in hooks directory: {}", path.display()),
                    })?
                    .to_string_lossy()
                    .to_string();

                // Read file content and compute hash
                let content = fs::read(path).map_err(|e| Error::InvalidConfig {
                    message: format!("Failed to read hook file {}: {}", path.display(), e),
                })?;

                let file_hash = hash_data(&content);
                Ok((rel_path, file_hash))
            })
            .collect();

        let mut file_hashes = file_hashes?;

        // Sort by path for deterministic hashing
        file_hashes.sort_by(|a, b| a.0.cmp(&b.0));

        // Combine all hashes into a single hash using blake3
        let mut hasher = blake3::Hasher::new();
        for (path, hash) in file_hashes {
            hasher.update(path.as_bytes());
            hasher.update(&hash);
        }

        Ok(*hasher.finalize().as_bytes())
    }

    /// Serialize to bytes for database storage
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (e.g., encoding error)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| Error::StateSerialization {
            type_name: "HookState",
            operation: "to_allocvec",
            source: Box::new(e),
        })
    }

    /// Deserialize from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

impl Default for HookState {
    fn default() -> Self {
        Self::new()
    }
}

/// Hook state persistence wrapper
pub struct HookStatePersistence<'a, T: PersistentState> {
    db: &'a mut T,
}

impl<'a, T: PersistentState> HookStatePersistence<'a, T> {
    /// Create new hook state persistence
    #[must_use]
    pub fn new(db: &'a mut T) -> Self {
        Self { db }
    }

    /// Load hook state from database
    ///
    /// Returns a new `HookState` if no state is stored or if deserialization fails
    /// (e.g., when schema has changed).
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be loaded from the database (e.g., database error)
    pub fn load(&mut self) -> Result<HookState> {
        const HOOK_STATE_KEY: &[u8] = b"hooks";

        match self.db.get(HOOK_STATE_BUCKET, HOOK_STATE_KEY)? {
            Some(bytes) => {
                // Try to deserialize, but if it fails (e.g., bincode→postcard migration), reset state
                Ok(HookState::from_bytes(&bytes).unwrap_or_else(|| {
                    tracing::warn!("Failed to deserialize hook state (possibly due to schema change), creating new state");
                    let _ = self.db.delete(HOOK_STATE_BUCKET, HOOK_STATE_KEY);
                    HookState::new()
                }))
            }
            None => Ok(HookState::new()),
        }
    }

    /// Save hook state to database
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be serialized or saved (e.g., serialization error, database error)
    pub fn save(&mut self, state: &HookState) -> Result<()> {
        const HOOK_STATE_KEY: &[u8] = b"hooks";

        let bytes = state.to_bytes()?;
        self.db.set(HOOK_STATE_BUCKET, HOOK_STATE_KEY, &bytes)?;
        Ok(())
    }
}

/// State of destination directory (actual files on disk)
#[derive(Debug)]
pub struct DestinationState {
    /// Root directory (typically home directory)
    root: AbsPath,

    /// Cached entries
    cache: HashMap<RelPath, DestEntry>,
}

impl DestinationState {
    /// Create a new destination state
    #[must_use]
    pub fn new(root: AbsPath) -> Self {
        Self {
            root,
            cache: HashMap::new(),
        }
    }

    /// Get the root directory
    #[must_use]
    pub fn root(&self) -> &AbsPath {
        &self.root
    }

    /// Read the current state of a file from the filesystem
    ///
    /// This reads the actual file and caches the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read from the filesystem (e.g., permission denied, I/O error)
    ///
    /// # Panics
    ///
    /// Panics if the cache entry cannot be retrieved after insertion (should never happen)
    pub fn read<S: System>(&mut self, path: &RelPath, system: &S) -> Result<&DestEntry> {
        if !self.cache.contains_key(path) {
            let abs_path = self.root.join(path);
            let entry = Self::read_entry(path, &abs_path, system)?;
            self.cache.insert(path.clone(), entry);
        }

        Ok(self
            .cache
            .get(path)
            .expect("entry was just inserted into cache"))
    }

    /// Extract file mode from metadata (Unix-specific)
    #[cfg(unix)]
    #[allow(clippy::unnecessary_wraps)]
    fn extract_mode(metadata: &std::fs::Metadata) -> Option<u32> {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode())
    }

    /// Extract file mode from metadata (non-Unix always returns None)
    #[cfg(not(unix))]
    fn extract_mode(_metadata: &std::fs::Metadata) -> Option<u32> {
        None
    }

    /// Read an entry from the filesystem
    fn read_entry<S: System>(
        rel_path: &RelPath,
        abs_path: &AbsPath,
        system: &S,
    ) -> Result<DestEntry> {
        if !system.exists(abs_path) {
            return Ok(DestEntry::missing(rel_path.clone()));
        }

        let metadata = system.metadata(abs_path)?;

        if metadata.is_dir() {
            let mode = Self::extract_mode(&metadata);
            Ok(DestEntry::directory(rel_path.clone(), mode))
        } else if metadata.is_symlink() {
            let target = system.read_link(abs_path)?;
            Ok(DestEntry::symlink(rel_path.clone(), target))
        } else {
            let content = system.read_file(abs_path)?;
            let mode = Self::extract_mode(&metadata);
            Ok(DestEntry::file(rel_path.clone(), content, mode))
        }
    }

    /// Get a cached entry
    #[must_use]
    pub fn get(&self, path: &RelPath) -> Option<&DestEntry> {
        self.cache.get(path)
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Metadata configuration from .guisu/metadata.toml
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Files that should only be created once and not tracked afterwards
    #[serde(default, rename = "create-once")]
    pub create_once: CreateOnceConfig,

    /// Dest paths to remove on apply. Each entry is a dest-relative path
    /// (e.g. `~/.cache/foo`) that `apply` will `rm` if it exists.
    #[serde(default, rename = "remove")]
    pub remove: RemoveConfig,
}

/// Configuration for create-once files
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOnceConfig {
    /// List of file paths (relative to destination) that should only be created once
    #[serde(default)]
    pub files: HashSet<String>,
}

/// Configuration for paths to remove on apply
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveConfig {
    /// Dest paths (relative to destination) that `apply` should remove
    #[serde(default)]
    pub paths: HashSet<String>,
}

impl RemoveConfig {
    /// Add a path to the remove set
    pub fn add(&mut self, path: String) {
        self.paths.insert(path);
    }

    /// Iterate over the configured paths
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.paths.iter().map(String::as_str)
    }

    /// Check whether the given dest path is scheduled for removal
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.paths.contains(path)
    }
}

impl Metadata {
    /// Load state from `.guisu/state.toml`
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be read or parsed (e.g., file not found, permission denied, invalid TOML syntax)
    pub fn load(source_dir: &Path) -> Result<Self> {
        let metadata_path = source_dir.join(".guisu/state.toml");

        if !metadata_path.exists() {
            return Ok(Self::default());
        }

        // Make path absolute for better error messages
        let abs_metadata_path =
            fs::canonicalize(&metadata_path).unwrap_or_else(|_| metadata_path.clone());

        let content = fs::read_to_string(&metadata_path).map_err(|e| {
            // Try to convert to AbsPath for error message, but fall back to PathBuf if it fails
            let path = guisu_core::path::AbsPath::new(abs_metadata_path.clone()).map_or_else(
                |_| abs_metadata_path.clone(),
                |abs| abs.as_path().to_path_buf(),
            );
            Error::FileRead { path, source: e }
        })?;

        toml::from_str(&content).map_err(|e| Error::InvalidConfig {
            message: format!("Failed to parse .guisu/state.toml: {e}"),
        })
    }

    /// Save state to `.guisu/state.toml`
    ///
    /// # Errors
    ///
    /// Returns an error if the state file cannot be written (e.g., permission denied, disk full, serialization error)
    pub fn save(&self, source_dir: &Path) -> Result<()> {
        let guisu_dir = source_dir.join(".guisu");

        // Make paths absolute for better error messages
        let abs_guisu_dir =
            fs::canonicalize(source_dir).map_or_else(|_| guisu_dir.clone(), |p| p.join(".guisu"));

        // Create .guisu directory if it doesn't exist
        if !guisu_dir.exists() {
            fs::create_dir_all(&guisu_dir).map_err(|e| {
                // Try to convert to AbsPath for error message, but fall back to PathBuf if it fails
                let path = guisu_core::path::AbsPath::new(abs_guisu_dir.clone())
                    .map_or_else(|_| abs_guisu_dir.clone(), |abs| abs.as_path().to_path_buf());
                Error::DirectoryCreate { path, source: e }
            })?;
        }

        let metadata_path = guisu_dir.join("state.toml");
        let abs_metadata_path = abs_guisu_dir.join("state.toml");

        let content = toml::to_string_pretty(self).map_err(|e| Error::InvalidConfig {
            message: format!("Failed to serialize metadata: {e}"),
        })?;

        fs::write(&metadata_path, content).map_err(|e| {
            // Try to convert to AbsPath for error message, but fall back to PathBuf if it fails
            let path = guisu_core::path::AbsPath::new(abs_metadata_path.clone()).map_or_else(
                |_| abs_metadata_path.clone(),
                |abs| abs.as_path().to_path_buf(),
            );
            Error::FileWrite { path, source: e }
        })?;

        Ok(())
    }

    /// Add a file to the create-once list
    pub fn add_create_once(&mut self, file_path: String) {
        self.create_once.files.insert(file_path);
    }

    /// Check if a file is in the create-once list
    #[must_use]
    pub fn is_create_once(&self, file_path: &str) -> bool {
        self.create_once.files.contains(file_path)
    }

    /// Remove a file from the create-once list
    pub fn remove_create_once(&mut self, file_path: &str) -> bool {
        self.create_once.files.remove(file_path)
    }
}

/// State of source directory (files in the guisu repository)
///
/// Tracks all files in the source directory with their attributes and target paths.
#[derive(Debug)]
pub struct SourceState {
    /// Root directory of the source files
    root: AbsPath,

    /// Map of target paths to source entries
    entries: HashMap<RelPath, SourceEntry>,
}

impl SourceState {
    /// Read the source state from a directory
    ///
    /// Preserves original filenames and uses file extensions and permissions.
    ///
    /// # Arguments
    ///
    /// * `root` - The root directory to read from
    /// * `matcher` - Optional ignore matcher to filter files
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read or files cannot be processed (e.g., permission denied, I/O error, invalid attributes)
    pub fn read(root: AbsPath) -> Result<Self> {
        Self::read_with_matcher(root, None)
    }

    /// Read the source state from a directory with ignore matcher
    ///
    /// This version allows filtering files using an `IgnoreMatcher`.
    ///
    /// # Arguments
    ///
    /// * `root` - The root directory to read from
    /// * `matcher` - Optional ignore matcher to filter files based on patterns
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read or files cannot be processed (e.g., permission denied, I/O error, invalid attributes, invalid path structure)
    pub fn read_with_matcher(
        root: AbsPath,
        matcher: Option<&guisu_config::IgnoreMatcher>,
    ) -> Result<Self> {
        use rayon::prelude::*;

        let root_path = root.as_path();

        // First, collect all file paths (WalkDir must be sequential)
        let file_paths: Vec<std::path::PathBuf> = WalkDir::new(root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.path();

                // Skip the root directory itself
                if path == root_path {
                    return None;
                }

                // Only process files, not directories
                // Note: With rootEntry enforced (defaults to "home"), all dotfiles are in a
                // subdirectory, so we don't need to skip .git, .guisu, etc.
                if !entry.file_type().is_file() {
                    return None;
                }

                // Apply ignore matcher if provided
                if let Some(matcher) = matcher
                    && let Ok(rel_path) = path.strip_prefix(root_path)
                    && matcher.is_ignored(rel_path, None)
                {
                    return None;
                }

                Some(path.to_path_buf())
            })
            .collect();

        // Now process all files in parallel (metadata reading + attribute parsing)
        // Pre-wrap root_path in Arc to avoid cloning in parallel error paths
        let root_path_arc = Arc::new(root_path.to_path_buf());

        let entries: Result<Vec<_>> = file_paths
            .par_iter()
            .map(|path| {
                // Get relative path from root
                let rel_path =
                    path.strip_prefix(root_path)
                        .map_err(|_| Error::InvalidPathPrefix {
                            path: Arc::new(path.clone()),
                            base: Arc::clone(&root_path_arc),
                        })?;

                let source_rel_path = SourceRelPath::new(rel_path.to_path_buf())?;

                // Parse attributes from filename
                let file_name = path
                    .file_name()
                    .ok_or_else(|| Error::InvalidConfig {
                        message: format!("Invalid path: {}", path.display()),
                    })?
                    .to_string_lossy();

                let metadata = std::fs::metadata(path).map_err(|e| Error::FileRead {
                    path: root
                        .join(&source_rel_path.to_rel_path())
                        .as_path()
                        .to_path_buf(),
                    source: e,
                })?;

                #[cfg(unix)]
                let permissions = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(metadata.permissions().mode())
                };

                #[cfg(not(unix))]
                let permissions = None;

                let (attrs, target_name) =
                    FileAttributes::parse_from_source(&file_name, permissions);

                // Calculate target path
                let target_rel = if let Some(parent) = rel_path.parent() {
                    parent.join(&target_name)
                } else {
                    std::path::PathBuf::from(&target_name)
                };

                let target_path = RelPath::new(target_rel)?;

                let source_entry = SourceEntry::File {
                    source_path: source_rel_path,
                    target_path: target_path.clone(),
                    attributes: attrs,
                };

                Ok((target_path, source_entry))
            })
            .collect();

        let mut entry_map = HashMap::new();
        for (target_path, source_entry) in entries? {
            entry_map.insert(target_path, source_entry);
        }

        Ok(Self {
            root,
            entries: entry_map,
        })
    }

    /// Get all source entries
    pub fn entries(&self) -> impl Iterator<Item = &SourceEntry> {
        self.entries.values()
    }

    /// Get a source entry by target path
    #[must_use]
    pub fn get(&self, target_path: &RelPath) -> Option<&SourceEntry> {
        self.entries.get(target_path)
    }

    /// Get the root directory
    #[must_use]
    pub fn root(&self) -> &AbsPath {
        &self.root
    }

    /// Get the number of entries
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if there are no entries
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the absolute path to a source file
    #[must_use]
    pub fn source_file_path(&self, source_path: &SourceRelPath) -> AbsPath {
        // Convert SourceRelPath to RelPath first, then join
        self.root.join(&source_path.to_rel_path())
    }
}

/// State of target files (after processing templates and encryption)
///
/// Represents the final state of files after applying all transformations
/// (template rendering, decryption) but before writing to destination.
#[derive(Debug)]
pub struct TargetState {
    /// Map of target paths to target entries
    entries: HashMap<RelPath, TargetEntry>,
}

impl TargetState {
    /// Create a new empty target state
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a target state from a source state
    ///
    /// This processes all source entries through the content processor,
    /// applying template rendering and decryption as needed.
    ///
    /// # Arguments
    ///
    /// * `source` - The source state to process
    /// * `processor` - The content processor to use for transformations
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use guisu_engine::state::{SourceState, TargetState};
    /// use guisu_engine::processor::ContentProcessor;
    /// use guisu_core::path::AbsPath;
    /// use serde_json::json;
    ///
    /// let source_dir = AbsPath::new("/home/user/.local/share/guisu".into())?;
    /// let source = SourceState::read(source_dir)?;
    ///
    /// // Create processor with decryptor and renderer
    /// let processor = ContentProcessor::new(my_decryptor, my_renderer);
    /// let context = json!({});
    /// let target = TargetState::from_source(&source, &processor, &context)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails (e.g., file read error, decryption failure, template rendering error, invalid UTF-8)
    pub fn from_source<D, R>(
        source: &SourceState,
        processor: &ContentProcessor<D, R>,
        context: &serde_json::Value,
    ) -> Result<Self>
    where
        D: crate::content::Decryptor + Sync,
        R: crate::content::TemplateRenderer + Sync,
    {
        use rayon::prelude::*;

        // Parallel processing of source entries (template rendering + decryption are CPU-intensive)
        let entries: Result<Vec<_>> = source
            .entries()
            .par_bridge()
            .map(|source_entry| Self::process_entry(source, source_entry, processor, context))
            .collect();

        let mut target_state = Self::new();
        for entry in entries? {
            target_state.add(entry);
        }

        Ok(target_state)
    }

    /// Process a single source entry into a target entry
    ///
    /// This applies the appropriate transformations based on the entry type:
    /// - Files: Read contents, decrypt if needed, render templates if needed
    /// - Directories: Create directory entry with permissions
    /// - Symlinks: Create symlink entry (no content processing)
    fn process_entry<D, R>(
        source: &SourceState,
        source_entry: &SourceEntry,
        processor: &ContentProcessor<D, R>,
        context: &serde_json::Value,
    ) -> Result<TargetEntry>
    where
        D: crate::content::Decryptor,
        R: crate::content::TemplateRenderer,
    {
        match source_entry {
            SourceEntry::File {
                source_path,
                target_path,
                attributes,
            } => {
                // Get the absolute path to the source file
                let abs_source_path = source.source_file_path(source_path);

                // Process the file contents through the decrypt→render pipeline
                // Note: process_file already provides detailed error context,
                // so we don't wrap it here to avoid redundant error messages
                let processed_content =
                    processor.process_file(&abs_source_path, attributes, context)?;

                let content_hash = crate::hash::hash_content(&processed_content);

                // Regular file. The source file's mode bits (if any) are
                // propagated to the destination by `apply` and compared
                // against the destination's mode by `diff`. Removal is no
                // longer expressed as an entry-type variant — see
                // `Metadata::remove` (`.guisu/state.toml`).
                let mode = attributes.mode();
                Ok(TargetEntry::File {
                    path: target_path.clone(),
                    content: processed_content,
                    content_hash,
                    mode,
                })
            }

            SourceEntry::Directory {
                target_path,
                attributes,
                ..
            } => {
                // Directories don't have content processing
                let mode = attributes.mode();

                Ok(TargetEntry::Directory {
                    path: target_path.clone(),
                    mode,
                })
            }

            SourceEntry::Symlink {
                target_path,
                link_target,
                ..
            } => {
                // Symlinks don't have content processing currently
                // NOTE: Future enhancement - support templating in symlink targets
                // Chezmoi supports this via .tmpl suffix on symlink files
                // See CLAUDE.md: "Symlink Target Templating"
                Ok(TargetEntry::Symlink {
                    path: target_path.clone(),
                    target: link_target.clone(),
                })
            }
        }
    }

    /// Add an entry to the target state
    pub fn add(&mut self, entry: TargetEntry) {
        let path = entry.path().clone();
        self.entries.insert(path, entry);
    }

    /// Get a target entry by path
    #[must_use]
    pub fn get(&self, path: &RelPath) -> Option<&TargetEntry> {
        self.entries.get(path)
    }

    /// Iterate over all entries
    pub fn entries(&self) -> impl Iterator<Item = &TargetEntry> {
        self.entries.values()
    }

    /// Get the number of entries
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the target state is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for TargetState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod metadata_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn metadata_remove_round_trip() {
        // A `.guisu/state.toml` like:
        //   [remove]
        //   paths = ["~/.cache/foo", "~/.config/dead"]
        // round-trips through Metadata::load and Metadata::save.
        let toml = r#"
[remove]
paths = ["~/.cache/foo", "~/.config/dead"]

[create-once]
files = ["~/.config/once.txt"]
"#;
        let parsed: Metadata = toml::from_str(toml).expect("parse toml");
        assert!(parsed.remove.contains("~/.cache/foo"));
        assert!(parsed.remove.contains("~/.config/dead"));
        assert!(!parsed.remove.contains("missing"));
        assert!(parsed.create_once.files.contains("~/.config/once.txt"));

        let rendered = toml::to_string(&parsed).expect("render toml");
        let reparsed: Metadata = toml::from_str(&rendered).expect("parse rendered");
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn metadata_remove_default_is_empty() {
        // A missing [remove] section should default to an empty path set,
        // not error.
        let parsed: Metadata = toml::from_str("").expect("parse empty toml");
        assert!(parsed.remove.paths.is_empty());
        assert!(parsed.remove.iter().next().is_none());
    }

    #[test]
    fn metadata_remove_add_and_iterate() {
        let mut m = Metadata::default();
        m.remove.add("~/.cache/foo".to_string());
        m.remove.add("~/.config/dead".to_string());

        let collected: Vec<&str> = m.remove.iter().collect();
        assert!(collected.contains(&"~/.cache/foo"));
        assert!(collected.contains(&"~/.config/dead"));
    }
}

// === Data types ===

/// Entry state - tracks file state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryState {
    /// blake3 hash of the file content (fixed 32-byte array)
    pub content_hash: [u8; 32],
    /// File mode/permissions (Unix only)
    pub mode: Option<u32>,
}

impl EntryState {
    /// Create a new entry state from content and mode
    #[must_use]
    pub fn new(content: &[u8], mode: Option<u32>) -> Self {
        Self {
            content_hash: hash_data(content),
            mode,
        }
    }

    /// Serialize to bytes
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (e.g., encoding error)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| Error::StateSerialization {
            type_name: "EntryState",
            operation: "to_allocvec",
            source: Box::new(e),
        })
    }

    /// Deserialize from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

/// Script state - tracks script execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptState {
    /// blake3 hash of the script content (fixed 32-byte array)
    pub content_hash: [u8; 32],
}

impl ScriptState {
    /// Create a new script state from content
    #[must_use]
    pub fn new(content: &[u8]) -> Self {
        Self {
            content_hash: hash_data(content),
        }
    }

    /// Serialize to bytes
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (e.g., encoding error)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| Error::StateSerialization {
            type_name: "ScriptState",
            operation: "to_allocvec",
            source: Box::new(e),
        })
    }

    /// Deserialize from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

/// Config metadata - tracks rendered configuration state
///
/// Stores the rendered configuration file content along with a hash of the template source.
/// This enables caching: if the template hasn't changed, we can use the cached rendered config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigMetadata {
    /// blake3 hash of the config template source file (fixed 32-byte array)
    /// Used to detect changes in .guisu.toml.j2
    pub template_hash: [u8; 32],
    /// Rendered TOML configuration string
    /// Result of processing the template with full context
    pub rendered_config: String,
}

impl ConfigMetadata {
    /// Create new config metadata from template source and rendered output
    #[must_use]
    pub fn new(template_source: &str, rendered_config: String) -> Self {
        Self {
            template_hash: hash_data(template_source.as_bytes()),
            rendered_config,
        }
    }

    /// Serialize to bytes
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (e.g., encoding error)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| Error::StateSerialization {
            type_name: "ConfigMetadata",
            operation: "to_allocvec",
            source: Box::new(e),
        })
    }

    /// Deserialize from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<ConfigMetadata> {
        postcard::from_bytes(bytes).ok()
    }

    /// Check if template source matches stored hash (for cache validation)
    #[must_use]
    pub fn template_matches(&self, template_source: &str) -> bool {
        let current_hash = hash_data(template_source.as_bytes());
        bool::from(self.template_hash.ct_eq(&current_hash))
    }
}
