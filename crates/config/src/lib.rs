//! Configuration management for guisu
//!
//! This crate handles:
//! - Configuration loading and validation
//! - XDG directory management
//! - Git integration
//! - Variable loading
//! - Hook configuration
//! - Database helpers

pub mod config;
pub mod dirs;
pub mod env;
pub mod ignores;
pub mod patterns;
pub mod variables;

// Re-export error types from core
pub use guisu_core::{Error, Result};

// Type aliases for common data structures
use indexmap::IndexMap;
use serde_json::Value as JsonValue;

/// Template variables map (used for configuration and template rendering)
pub type Variables = IndexMap<String, JsonValue>;

// Re-export main types
pub use config::{
    AgeConfig, BitwardenConfig, Config, GeneralConfig, IconMode, IgnoreConfig, UiConfig,
};
// NOTE: database module moved to guisu-engine
// CLI should import from engine::database directly
pub use dirs::{data_dir, default_source_dir, state_dir};
pub use env::Env;
pub use ignores::IgnoresConfig;
pub use patterns::IgnoreMatcher;
