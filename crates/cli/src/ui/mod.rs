//! Terminal UI components for guisu
//!
//! This crate provides all terminal user interface components including:
//! - Conflict resolution prompts
//! - Diff viewers
//! - Text editors
//! - Progress indicators
//! - Icons and themes

/// Diff viewer implementations
pub mod diffviewer;
/// Text editor integration
pub mod editor;
/// Shared hook list formatting
pub(crate) mod hooks;
/// Icon definitions and file type detection
pub mod icons;
/// Merge conflict resolution
pub mod merge;
/// Change preview utilities
pub mod preview;
/// Progress indicators
pub mod progress;
/// Interactive user prompts
pub mod prompt;
/// UI theme configuration
pub mod theme;
/// Interactive file viewer
pub mod viewer;

pub use diffviewer::{DiffFormat, DiffViewer};
pub use editor::{open_for_merge, open_in_editor};
pub use icons::{FileIconInfo, Icons, StatusIcon};
pub use merge::MergeResult;
pub use preview::{ChangePreview, ChangeSummary};
pub use progress::{create_progress_bar, create_spinner};
pub use prompt::{ConflictAction, ConflictPrompt};
pub use theme::Theme;
pub use viewer::{FileDiff, FileStatus, InteractiveDiffViewer};
