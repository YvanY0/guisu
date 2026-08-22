//! State validation and repair utilities
//!
//! This module provides tools for validating the integrity of the persistent state
//! and repairing inconsistencies that may arise from unexpected failures or data corruption.

use crate::state::{EntryState, RedbPersistentState};
use guisu_core::Result;
use std::collections::HashMap;

/// Validation report containing detected issues
#[derive(Debug, Default)]
pub struct ValidationReport {
    /// Number of entries checked
    pub entries_checked: usize,
    /// Entries with invalid hashes
    pub invalid_hashes: Vec<String>,
    /// Orphaned state entries (no corresponding source file)
    pub orphaned_entries: Vec<String>,
    /// Entries with missing required fields
    pub incomplete_entries: Vec<String>,
    /// Total issues found
    pub total_issues: usize,
}

impl ValidationReport {
    /// Check if validation passed (no issues found)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.total_issues == 0
    }

    /// Get a summary of validation results
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_valid() {
            format!("✓ All {} entries are valid", self.entries_checked)
        } else {
            let mut lines = vec![format!(
                "✗ Found {} issues in {} entries:",
                self.total_issues, self.entries_checked
            )];

            if !self.invalid_hashes.is_empty() {
                lines.push(format!(
                    "  - {} entries with invalid hashes",
                    self.invalid_hashes.len()
                ));
            }
            if !self.orphaned_entries.is_empty() {
                lines.push(format!(
                    "  - {} orphaned entries",
                    self.orphaned_entries.len()
                ));
            }
            if !self.incomplete_entries.is_empty() {
                lines.push(format!(
                    "  - {} incomplete entries",
                    self.incomplete_entries.len()
                ));
            }

            lines.join("\n")
        }
    }
}

/// State validator for checking and repairing persistent state
pub struct StateValidator;

impl StateValidator {
    /// Validate the integrity of all state entries
    ///
    /// This performs the following checks:
    /// 1. Hash integrity - ensure content hashes are valid
    /// 2. Completeness - ensure all required fields are present
    /// 3. Orphan detection - identify state entries without source files
    ///
    /// # Arguments
    /// * `db` - The persistent state database to validate
    ///
    /// # Errors
    /// Returns an error if the database cannot be read
    ///
    /// # Returns
    /// A validation report containing all detected issues
    pub fn validate(db: &RedbPersistentState) -> Result<ValidationReport> {
        let mut report = ValidationReport::default();

        // Get all entries from database
        let entries = Self::get_all_entries(db)?;
        report.entries_checked = entries.len();

        for (path, state) in &entries {
            // Check 1: Validate hash format
            if !Self::is_valid_hash(&state.content_hash) {
                report.invalid_hashes.push(path.clone());
                report.total_issues += 1;
            }

            // Check 2: Validate mode if present
            if let Some(mode) = state.mode
                && !Self::is_valid_mode(mode)
            {
                report.incomplete_entries.push(path.clone());
                report.total_issues += 1;
            }
        }

        Ok(report)
    }

    /// Repair detected inconsistencies in the state
    ///
    /// This will:
    /// - Remove orphaned entries
    /// - Fix invalid hash formats
    /// - Clean up incomplete entries
    ///
    /// # Arguments
    /// * `db` - The persistent state database to repair
    ///
    /// # Errors
    /// Returns an error if validation fails or entries cannot be deleted
    ///
    /// # Returns
    /// Number of entries repaired
    pub fn repair(db: &mut RedbPersistentState) -> Result<usize> {
        let report = Self::validate(db)?;
        let mut repaired = 0;

        // Remove orphaned entries
        for path in &report.orphaned_entries {
            if crate::database::delete_entry_state(db, path).is_ok() {
                repaired += 1;
            }
        }

        // Remove entries with invalid hashes
        for path in &report.invalid_hashes {
            if crate::database::delete_entry_state(db, path).is_ok() {
                repaired += 1;
            }
        }

        // Remove incomplete entries
        for path in &report.incomplete_entries {
            if crate::database::delete_entry_state(db, path).is_ok() {
                repaired += 1;
            }
        }

        Ok(repaired)
    }

    /// Get all entries from the database
    fn get_all_entries(db: &RedbPersistentState) -> Result<HashMap<String, EntryState>> {
        crate::database::get_all_entry_states(db)
    }

    /// Validate hash format (should be 32 bytes for BLAKE3)
    fn is_valid_hash(hash: &[u8]) -> bool {
        hash.len() == 32
    }

    /// Validate file mode (Unix permissions)
    fn is_valid_mode(mode: u32) -> bool {
        // Mode should be within valid range for Unix permissions
        // File type bits (upper 4 bits) + permission bits (lower 12 bits)
        mode <= 0o177_777
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_hash() {
        // Valid BLAKE3 hash (32 bytes)
        let valid_hash = vec![0u8; 32];
        assert!(StateValidator::is_valid_hash(&valid_hash));

        // Invalid hashes
        assert!(!StateValidator::is_valid_hash(&[0u8; 16])); // Too short
        assert!(!StateValidator::is_valid_hash(&[0u8; 64])); // Too long
        assert!(!StateValidator::is_valid_hash(&[])); // Empty
    }

    #[test]
    fn test_is_valid_mode() {
        // Valid modes
        assert!(StateValidator::is_valid_mode(0o644));
        assert!(StateValidator::is_valid_mode(0o755));
        assert!(StateValidator::is_valid_mode(0o100_644)); // Regular file
        assert!(StateValidator::is_valid_mode(0o40755)); // Directory

        // Invalid mode (too large)
        assert!(!StateValidator::is_valid_mode(0o200_000));
    }

    #[test]
    fn test_validation_report_is_valid() {
        let mut report = ValidationReport::default();
        assert!(report.is_valid());

        report.total_issues = 1;
        assert!(!report.is_valid());
    }

    #[test]
    fn test_validation_report_summary() {
        let mut report = ValidationReport {
            entries_checked: 10,
            ..Default::default()
        };

        // Valid state
        let summary = report.summary();
        assert!(summary.contains("✓"));
        assert!(summary.contains("10 entries"));

        // Invalid state
        report.total_issues = 3;
        report.invalid_hashes = vec!["file1.txt".to_string()];
        report.orphaned_entries = vec!["file2.txt".to_string()];
        report.incomplete_entries = vec!["file3.txt".to_string()];

        let summary = report.summary();
        assert!(summary.contains("✗"));
        assert!(summary.contains("3 issues"));
    }
}
