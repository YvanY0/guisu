//! Hook system for custom commands
//!
//! Provides a flexible hook system that can execute scripts or commands
//! at different stages (pre, post) with ordering and parallel execution support.
//!
//! ## Execution Model
//!
//! - Hooks are executed before and after applying dotfiles
//! - Different order values execute sequentially (order 10 before order 20)
//! - Hooks with the same order value execute **in parallel** for maximum performance
//! - Supports execution modes: Always, Once, `OnChange`
//!
//! ## Module Organization
//!
//! - `config`: Hook configuration structures (Hook, `HookCollections`, etc.)
//! - `loader`: Hook discovery and loading from filesystem
//! - `executor`: Hook execution engine with parallel support
//! - `state`: Hook configuration state tracking (separate from execution state)

pub mod config;
pub mod executor;
pub mod loader;
pub mod state;
pub mod types;

// Re-export main types for convenience
pub use config::{Hook, HookCollections, HookMode, HookStage};
pub use executor::{HookRunner, HookRunnerBuilder, NoOpRenderer, TemplateRenderer};
pub use loader::HookLoader;
pub use state::HookConfigState;
pub use types::{HookName, HookScript, PlatformName};
