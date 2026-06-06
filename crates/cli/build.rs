//! Build script for guisu.
//!
//! Generates build-time metadata using vergen:
//! - Build information (timestamp, target, etc.)
//! - Rustc version information
//! - Git repository information (commit, branch, etc.)

use vergen_git2::{Emitter, Git2Builder};

fn main() -> anyhow::Result<()> {
    // Generate build and rustc info
    let build = vergen::BuildBuilder::all_build()?;
    let rustc = vergen::RustcBuilder::all_rustc()?;

    vergen::Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&rustc)?
        .emit()?;

    // Generate git info
    let git2 = Git2Builder::all_git()?;
    Emitter::default().add_instructions(&git2)?.emit()?;

    Ok(())
}
