//! Thread-safe statistics tracking for parallel operations

use std::sync::atomic::{AtomicU32, Ordering};

/// Thread-safe statistics for apply operations
///
/// Uses `AtomicU32` instead of `AtomicUsize` to save memory (4 bytes vs 8 bytes on 64-bit systems).
/// File counts are unlikely to exceed `u32::MAX` (~4.3 billion).
#[derive(Debug, Default)]
pub struct ApplyStats {
    /// Number of files processed
    files: AtomicU32,
    /// Number of directories processed
    directories: AtomicU32,
    /// Number of symlinks processed
    symlinks: AtomicU32,
    /// Number of failed operations
    failed: AtomicU32,
}

impl ApplyStats {
    /// Create new statistics tracker
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment file count
    pub fn inc_files(&self) {
        self.files.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment directory count
    pub fn inc_directories(&self) {
        self.directories.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment symlink count
    pub fn inc_symlinks(&self) {
        self.symlinks.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed operation count
    pub fn inc_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current file count
    pub fn files(&self) -> usize {
        self.files.load(Ordering::Relaxed) as usize
    }

    /// Get current directory count
    pub fn directories(&self) -> usize {
        self.directories.load(Ordering::Relaxed) as usize
    }

    /// Get current symlink count
    pub fn symlinks(&self) -> usize {
        self.symlinks.load(Ordering::Relaxed) as usize
    }

    /// Get current failed operation count
    pub fn failed(&self) -> usize {
        self.failed.load(Ordering::Relaxed) as usize
    }

    /// Get total count (excludes failed)
    pub fn total(&self) -> usize {
        self.files() + self.directories() + self.symlinks()
    }

    /// Create a snapshot of current stats
    ///
    /// This is needed because `ApplyStats` uses atomics and cannot be cloned directly
    #[must_use]
    pub fn snapshot(&self) -> Self {
        Self {
            files: AtomicU32::new(self.files.load(Ordering::Relaxed)),
            directories: AtomicU32::new(self.directories.load(Ordering::Relaxed)),
            symlinks: AtomicU32::new(self.symlinks.load(Ordering::Relaxed)),
            failed: AtomicU32::new(self.failed.load(Ordering::Relaxed)),
        }
    }

    /// Print summary of apply statistics
    pub fn print_summary(&self, dry_run: bool) {
        use owo_colors::OwoColorize;

        let total = self.total();
        let failed = self.failed();
        let files = self.files();
        let directories = self.directories();
        let symlinks = self.symlinks();

        if dry_run {
            println!(
                "{} {} would be applied",
                "●".bright_green(),
                total.to_string().bright_white().bold()
            );
        } else if failed > 0 {
            println!(
                "{} {} | {} {}",
                "●".bright_green(),
                total.to_string().bright_green().bold(),
                "●".bright_red(),
                failed.to_string().bright_red().bold(),
            );
        } else {
            println!(
                "{} {} applied",
                "●".bright_green(),
                total.to_string().bright_green().bold()
            );
        }

        // Show breakdown if more than just files
        if directories > 0 || symlinks > 0 {
            let mut parts = Vec::new();
            if files > 0 {
                parts.push(format!("{files} files"));
            }
            if directories > 0 {
                parts.push(format!("{directories} directories"));
            }
            if symlinks > 0 {
                parts.push(format!("{symlinks} symlinks"));
            }
            println!("  {}", parts.join(", ").dimmed());
        }
    }
}

/// Thread-safe statistics for diff operations
///
/// Uses `AtomicU32` instead of `AtomicUsize` to save memory (4 bytes vs 8 bytes on 64-bit systems).
#[derive(Debug, Default)]
pub struct DiffStats {
    /// Number of added files
    added: AtomicU32,
    /// Number of modified files
    modified: AtomicU32,
    /// Number of unchanged files
    unchanged: AtomicU32,
    /// Number of errors encountered
    errors: AtomicU32,
}

impl DiffStats {
    /// Create new statistics tracker
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment added file count
    pub fn inc_added(&self) {
        self.added.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment modified file count
    pub fn inc_modified(&self) {
        self.modified.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment unchanged file count
    pub fn inc_unchanged(&self) {
        self.unchanged.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment error count
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current added file count
    pub fn added(&self) -> usize {
        self.added.load(Ordering::Relaxed) as usize
    }

    /// Get current modified file count
    pub fn modified(&self) -> usize {
        self.modified.load(Ordering::Relaxed) as usize
    }

    /// Get current unchanged file count
    pub fn unchanged(&self) -> usize {
        self.unchanged.load(Ordering::Relaxed) as usize
    }

    /// Get current error count
    pub fn errors(&self) -> usize {
        self.errors.load(Ordering::Relaxed) as usize
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for ApplyStats

    #[test]
    fn test_apply_stats_new() {
        let stats = ApplyStats::new();
        assert_eq!(stats.files(), 0);
        assert_eq!(stats.directories(), 0);
        assert_eq!(stats.symlinks(), 0);
        assert_eq!(stats.failed(), 0);
        assert_eq!(stats.total(), 0);
    }

    #[test]
    fn test_apply_stats_inc_files() {
        let stats = ApplyStats::new();
        stats.inc_files();
        assert_eq!(stats.files(), 1);
        stats.inc_files();
        stats.inc_files();
        assert_eq!(stats.files(), 3);
    }

    #[test]
    fn test_apply_stats_inc_directories() {
        let stats = ApplyStats::new();
        stats.inc_directories();
        stats.inc_directories();
        assert_eq!(stats.directories(), 2);
    }

    #[test]
    fn test_apply_stats_inc_symlinks() {
        let stats = ApplyStats::new();
        stats.inc_symlinks();
        assert_eq!(stats.symlinks(), 1);
    }

    #[test]
    fn test_apply_stats_inc_failed() {
        let stats = ApplyStats::new();
        stats.inc_failed();
        stats.inc_failed();
        stats.inc_failed();
        assert_eq!(stats.failed(), 3);
    }

    #[test]
    fn test_apply_stats_total() {
        let stats = ApplyStats::new();
        stats.inc_files();
        stats.inc_files();
        stats.inc_directories();
        stats.inc_symlinks();
        assert_eq!(stats.total(), 4); // 2 files + 1 directory + 1 symlink
    }

    #[test]
    fn test_apply_stats_total_excludes_failed() {
        let stats = ApplyStats::new();
        stats.inc_files();
        stats.inc_failed();
        stats.inc_failed();
        assert_eq!(stats.total(), 1); // Only counts successful items, not failures
        assert_eq!(stats.failed(), 2);
    }

    #[test]
    fn test_apply_stats_snapshot() {
        let stats = ApplyStats::new();
        stats.inc_files();
        stats.inc_directories();
        stats.inc_symlinks();
        stats.inc_failed();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.files(), 1);
        assert_eq!(snapshot.directories(), 1);
        assert_eq!(snapshot.symlinks(), 1);
        assert_eq!(snapshot.failed(), 1);

        // Modify original stats
        stats.inc_files();
        stats.inc_files();

        // Snapshot should remain unchanged
        assert_eq!(snapshot.files(), 1);
        assert_eq!(stats.files(), 3);
    }

    #[test]
    fn test_apply_stats_mixed_operations() {
        let stats = ApplyStats::new();
        stats.inc_files();
        stats.inc_files();
        stats.inc_directories();
        stats.inc_directories();
        stats.inc_directories();
        stats.inc_symlinks();
        stats.inc_failed();
        stats.inc_failed();

        assert_eq!(stats.files(), 2);
        assert_eq!(stats.directories(), 3);
        assert_eq!(stats.symlinks(), 1);
        assert_eq!(stats.failed(), 2);
        assert_eq!(stats.total(), 6); // 2 + 3 + 1
    }

    // Tests for DiffStats

    #[test]
    fn test_diff_stats_new() {
        let stats = DiffStats::new();
        assert_eq!(stats.added(), 0);
        assert_eq!(stats.modified(), 0);
        assert_eq!(stats.unchanged(), 0);
        assert_eq!(stats.errors(), 0);
    }

    #[test]
    fn test_diff_stats_inc_added() {
        let stats = DiffStats::new();
        stats.inc_added();
        stats.inc_added();
        assert_eq!(stats.added(), 2);
    }

    #[test]
    fn test_diff_stats_inc_modified() {
        let stats = DiffStats::new();
        stats.inc_modified();
        assert_eq!(stats.modified(), 1);
    }

    #[test]
    fn test_diff_stats_inc_unchanged() {
        let stats = DiffStats::new();
        stats.inc_unchanged();
        stats.inc_unchanged();
        stats.inc_unchanged();
        assert_eq!(stats.unchanged(), 3);
    }

    #[test]
    fn test_diff_stats_inc_errors() {
        let stats = DiffStats::new();
        stats.inc_errors();
        stats.inc_errors();
        assert_eq!(stats.errors(), 2);
    }

    #[test]
    fn test_diff_stats_mixed_operations() {
        let stats = DiffStats::new();
        stats.inc_added();
        stats.inc_added();
        stats.inc_modified();
        stats.inc_modified();
        stats.inc_modified();
        stats.inc_unchanged();
        stats.inc_errors();

        assert_eq!(stats.added(), 2);
        assert_eq!(stats.modified(), 3);
        assert_eq!(stats.unchanged(), 1);
        assert_eq!(stats.errors(), 1);
    }
}
