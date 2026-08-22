//! Hook utility functions shared across commands
//!
//! This module provides helper functions for loading and managing hooks
//! that are used by multiple commands (diff, status, etc.).

use guisu_engine::hooks::{HookCollections, HookLoader};
use guisu_engine::state::{HookState, HookStatePersistence, RedbPersistentState};
use std::path::Path;

use super::path::SourceDirExt;

/// Load hooks collections and state from the source directory
///
/// This is a helper function that encapsulates the common logic of:
/// 1. Checking if hooks directory exists
/// 2. Loading hooks using `HookLoader`
/// 3. Loading hook state from database
///
/// Used by both `diff` and `status` commands to avoid code duplication.
///
/// # Returns
///
/// - `Some((collections, state))` if hooks directory exists, hooks load successfully,
///   and state can be loaded
/// - `None` if any of the above conditions fail
///
/// # Errors
///
/// This function does not return errors. Instead, it returns `None` on any failure,
/// allowing calling code to silently skip hook processing or return early.
#[must_use]
pub fn load_hooks_and_state(
    source_dir: &Path,
    db: &mut RedbPersistentState,
) -> Option<(HookCollections, HookState)> {
    let hooks_dir = source_dir.hooks_dir();

    // Check if hooks directory exists
    if !hooks_dir.exists() {
        return None;
    }

    // Load hooks
    let loader = HookLoader::new(source_dir);
    let collections = loader.load().ok()?;

    if collections.is_empty() {
        return None;
    }

    // Load state from database
    let mut persistence = HookStatePersistence::new(db);
    let state = persistence.load().ok()?;

    Some((collections, state))
}
