//! Core types and utilities for guisu
//!
//! This is the foundation crate (Layer 0) that all other guisu crates depend on.
//! It provides:
//! - Path types (`AbsPath`, `RelPath`, `SourceRelPath`)
//! - Base error types
//! - Platform detection
//! - Core behavioral traits (e.g. `TemplateRenderer`)
//! - Common type definitions
//!
//! This crate has no dependencies on other guisu crates.

pub mod error;
pub mod path;
pub mod platform;
pub mod traits;

pub use error::{Error, Result};
pub use traits::TemplateRenderer;
