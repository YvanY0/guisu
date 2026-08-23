//! Command trait for guisu CLI
//!
//! This module defines the `Command` trait that all guisu commands implement.
//! It provides a uniform interface for command execution, making it easier to
//! test, extend, and maintain commands.

use crate::common::RuntimeContext;
use crate::error::Result;

/// Trait for all guisu commands
///
/// All commands that require configuration and resolved paths should implement
/// this trait. The `execute` method receives a `RuntimeContext` containing
/// shared state like configuration and resolved paths.
///
/// Commands can specify their return type via the `Output` associated type.
/// Most commands return `()`, but some may return values (e.g., init returns `Option<PathBuf>`).
///
/// # Example
///
/// ```rust,ignore
/// use crate::command::Command;
/// use crate::common::RuntimeContext;
/// use crate::error::Result;
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// pub struct MyCommand {
///     #[arg(short, long)]
///     pub some_flag: bool,
/// }
///
/// impl Command for MyCommand {
///     type Output = ();
///
///     fn execute(&self, context: &RuntimeContext) -> Result<()> {
///         // Access config: context.config
///         // Access paths: context.source_dir(), context.dest_dir(), context.dotfiles_dir()
///         Ok(())
///     }
/// }
/// ```
pub trait Command {
    /// The type returned by this command
    ///
    /// Most commands return `()`, but some may return values.
    type Output;

    /// Execute the command with the given runtime context
    ///
    /// The context is passed by `&mut` so commands can write to the
    /// persistent state database (see [`RuntimeContext::database_mut`]).
    /// Commands must not hold the database borrow across an `.await`
    /// point or yield it back to a caller that would then need it again.
    ///
    /// # Arguments
    ///
    /// * `context` - Runtime context containing configuration and resolved paths
    ///
    /// # Returns
    ///
    /// Returns `Ok(Output)` on success or a `CommandError` describing what went wrong.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if the command fails to execute. Error messages should
    /// be descriptive enough for the user to understand what went wrong.
    fn execute(&self, context: &mut RuntimeContext) -> Result<Self::Output>;

    /// Map the command's `Output` to a process exit code.
    ///
    /// Default is `0` (success). Commands whose semantic outcome is "fail"
    /// rather than "error" (e.g. `guisu verify` finding drift) override
    /// this to translate their `Output` into a non-zero exit code.
    fn exit_code(&self, _output: &Self::Output) -> i32 {
        0
    }
}
