//! Hook configuration state tracking
//!
//! Tracks hook configuration file changes using blake3 hashing.
//! This is separate from the execution state tracking in engine/state.rs.

use crate::hash;
use guisu_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use subtle::ConstantTimeEq;

/// Hook configuration state
///
/// This tracks changes to hook configuration files, not execution state.
/// For execution state (mode=once, mode=onchange), see engine/state.rs `HookState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfigState {
    /// blake3 hash of the configuration file content (fixed 32-byte array)
    pub config_hash: [u8; 32],

    /// Last execution timestamp
    pub last_executed: SystemTime,
}

impl Default for HookConfigState {
    fn default() -> Self {
        Self {
            config_hash: [0; 32],
            last_executed: SystemTime::UNIX_EPOCH,
        }
    }
}

impl HookConfigState {
    /// Create a new state with config hash
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read or hashed (e.g., file not found, permission denied, I/O error)
    pub fn new(config_path: &Path) -> Result<Self> {
        let config_hash = Self::compute_config_hash(config_path)?;
        Ok(Self {
            config_hash,
            last_executed: SystemTime::now(),
        })
    }

    /// Compute blake3 hash of a configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read (e.g., file not found, permission denied, I/O error)
    pub fn compute_config_hash(config_path: &Path) -> Result<[u8; 32]> {
        let content = fs::read(config_path).map_err(|e| Error::FileRead {
            path: config_path.to_path_buf(),
            source: e,
        })?;

        Ok(hash::hash_content(&content))
    }

    /// Check if configuration has changed since last execution
    ///
    /// # Errors
    ///
    /// Returns an error if the current config file cannot be read or hashed (e.g., file not found, permission denied, I/O error)
    pub fn has_changed(&self, config_path: &Path) -> Result<bool> {
        let current_hash = Self::compute_config_hash(config_path)?;
        // Use constant-time comparison for hash to prevent timing side-channel attacks
        Ok(!bool::from(self.config_hash.ct_eq(&current_hash)))
    }

    /// Update state with new config hash
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read or hashed (e.g., file not found, permission denied, I/O error)
    pub fn update(&mut self, config_path: &Path) -> Result<()> {
        self.config_hash = Self::compute_config_hash(config_path)?;
        self.last_executed = SystemTime::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_default_state() {
        let state = HookConfigState::default();
        assert_eq!(state.config_hash, [0; 32]);
        assert_eq!(state.last_executed, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_new_state_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test config content").unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // Hash should not be empty
        assert!(!state.config_hash.is_empty());
        assert_eq!(state.config_hash.len(), 32); // blake3 is 32 bytes

        // Timestamp should be recent (not UNIX_EPOCH)
        assert_ne!(state.last_executed, SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_new_state_file_not_found() {
        let result = HookConfigState::new(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to read file") || err_msg.contains("FileRead"));
    }

    #[test]
    fn test_compute_config_hash() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"test config content";
        temp_file.write_all(content).unwrap();
        temp_file.flush().unwrap();

        let hash = HookConfigState::compute_config_hash(temp_file.path()).unwrap();

        // Verify hash properties
        assert_eq!(hash.len(), 32); // blake3 is 32 bytes

        // Computing hash again should give same result
        let hash2 = HookConfigState::compute_config_hash(temp_file.path()).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_hash_different_content() {
        let mut file1 = NamedTempFile::new().unwrap();
        file1.write_all(b"content 1").unwrap();
        file1.flush().unwrap();

        let mut file2 = NamedTempFile::new().unwrap();
        file2.write_all(b"content 2").unwrap();
        file2.flush().unwrap();

        let hash1 = HookConfigState::compute_config_hash(file1.path()).unwrap();
        let hash2 = HookConfigState::compute_config_hash(file2.path()).unwrap();

        // Different content should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_same_content() {
        let content = b"identical content";

        let mut file1 = NamedTempFile::new().unwrap();
        file1.write_all(content).unwrap();
        file1.flush().unwrap();

        let mut file2 = NamedTempFile::new().unwrap();
        file2.write_all(content).unwrap();
        file2.flush().unwrap();

        let hash1 = HookConfigState::compute_config_hash(file1.path()).unwrap();
        let hash2 = HookConfigState::compute_config_hash(file2.path()).unwrap();

        // Same content should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_file_not_found() {
        let result = HookConfigState::compute_config_hash(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_has_changed_when_unchanged() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"original content").unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // File hasn't changed yet
        let changed = state.has_changed(temp_file.path()).unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_has_changed_when_content_modified() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("config.txt");

        // Write initial content
        fs::write(&file_path, b"original content").unwrap();

        let state = HookConfigState::new(&file_path).unwrap();

        // Modify the file
        fs::write(&file_path, b"modified content").unwrap();

        // Should detect the change
        let changed = state.has_changed(&file_path).unwrap();
        assert!(changed);
    }

    #[test]
    fn test_has_changed_file_not_found() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"content").unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // Check against non-existent file
        let result = state.has_changed(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_update_state() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("config.txt");

        // Write initial content
        fs::write(&file_path, b"original content").unwrap();

        let mut state = HookConfigState::new(&file_path).unwrap();
        let original_hash = state.config_hash;
        let original_time = state.last_executed;

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Modify the file
        fs::write(&file_path, b"modified content").unwrap();

        // Update state
        state.update(&file_path).unwrap();

        // Hash should have changed
        assert_ne!(state.config_hash, original_hash);

        // Timestamp should be more recent
        assert!(state.last_executed > original_time);
    }

    #[test]
    fn test_update_state_file_not_found() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"content").unwrap();
        temp_file.flush().unwrap();

        let mut state = HookConfigState::new(temp_file.path()).unwrap();

        // Try to update from non-existent file
        let result = state.update(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Don't write anything - empty file
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // Should still compute a hash (hash of empty content)
        assert!(!state.config_hash.is_empty());
        assert_eq!(state.config_hash.len(), 32);
    }

    #[test]
    fn test_large_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write 1MB of data
        let large_content = vec![b'x'; 1_000_000];
        temp_file.write_all(&large_content).unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // Should handle large files correctly
        assert!(!state.config_hash.is_empty());
        assert_eq!(state.config_hash.len(), 32);
    }

    #[test]
    fn test_binary_content() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write binary content
        let binary_content = vec![0u8, 1u8, 255u8, 128u8, 0xFF, 0xFE, 0xFD];
        temp_file.write_all(&binary_content).unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // Should handle binary content correctly
        assert!(!state.config_hash.is_empty());
        assert_eq!(state.config_hash.len(), 32);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test content").unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&state).unwrap();

        // Deserialize back
        let deserialized: HookConfigState = serde_json::from_str(&json).unwrap();

        assert_eq!(state.config_hash, deserialized.config_hash);
        assert_eq!(state.last_executed, deserialized.last_executed);
    }

    #[test]
    fn test_clone() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test content").unwrap();
        temp_file.flush().unwrap();

        let state = HookConfigState::new(temp_file.path()).unwrap();
        let cloned = state.clone();

        assert_eq!(state.config_hash, cloned.config_hash);
        assert_eq!(state.last_executed, cloned.last_executed);
    }

    #[test]
    fn test_constant_time_comparison() {
        // This test verifies that has_changed uses constant-time comparison
        // While we can't directly test timing, we can verify it works correctly

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("config.txt");

        fs::write(&file_path, b"content").unwrap();
        let state = HookConfigState::new(&file_path).unwrap();

        // Should not have changed (same content)
        assert!(!state.has_changed(&file_path).unwrap());

        // Modify with different content
        fs::write(&file_path, b"different").unwrap();
        assert!(state.has_changed(&file_path).unwrap());
    }
}
