//! Command trait for guisu CLI
//!
//! Uniform interface for command execution. All commands that need
//! configuration and resolved paths implement this trait.

use crate::common::RuntimeContext;
use anyhow::Result;

/// Trait for all guisu commands.
///
/// `execute` returns `anyhow::Result` (not the typed `guisu_core::Error`)
/// so the full error chain — every `.context(...)` layer a command adds —
/// survives the trip to `main`, where miette renders it with box-drawing.
pub trait Command {
    /// The type returned by this command
    type Output;

    /// Execute the command. `context` is `&mut` so commands can write
    /// to the persistent state database; do not hold the borrow across
    /// an `.await`.
    ///
    /// # Errors
    ///
    /// Returns an `anyhow::Error` describing what went wrong. Messages
    /// should be descriptive enough for the user to understand what
    /// failed and how to fix it.
    fn execute(&self, context: &mut RuntimeContext) -> Result<Self::Output>;

    /// Map the command's `Output` to a process exit code.
    ///
    /// Default `0`. Commands whose semantic outcome is "fail" rather
    /// than "error" (e.g. `guisu verify` finding drift) override this
    /// to translate their `Output` into a non-zero exit code.
    fn exit_code(&self, _output: &Self::Output) -> i32 {
        0
    }
}
