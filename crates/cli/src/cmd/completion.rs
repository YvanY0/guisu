//! Shell completion script generation

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::Shell;

use crate::Cli;

/// Generate a shell completion script and print it to stdout
#[derive(Parser)]
pub struct CompletionCommand {
    /// Shell to generate completion for
    #[arg(value_enum)]
    pub shell: Shell,
}

impl CompletionCommand {
    /// Generate the completion script and write it to stdout.
    ///
    /// This intentionally does not implement the `Command` trait because
    /// completion generation does not need a `RuntimeContext` — it must
    /// work on a fresh machine with no `.guisu.toml` and no writable
    /// home directory. Bypassing the trait keeps `guisu completion` from
    /// touching the database, the source directory, or the config.
    ///
    /// # Errors
    ///
    /// Currently infallible in practice (`clap_complete::generate` writes
    /// to stdout and does not return a `Result`). The `Result` return
    /// type is kept for forward compatibility and to satisfy clippy's
    /// `missing_errors_doc` lint.
    pub fn run(&self) -> Result<()> {
        let mut cmd = Cli::command();
        let bin = cmd.get_name().to_string();
        clap_complete::generate(self.shell, &mut cmd, bin, &mut std::io::stdout());
        Ok(())
    }
}
