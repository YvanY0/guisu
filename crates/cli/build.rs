//! Build script for guisu.
//!
//! Generates build-time metadata using vergen-git2:
//! - Build information (timestamp, target, etc.)
//! - Rustc version information
//! - Git repository information (commit, branch, etc.)

use vergen_git2::{Build, Emitter, Git2, Rustc};

fn main() -> anyhow::Result<()> {
    let build = Build::all_build();
    let rustc = Rustc::all_rustc();
    let git2 = Git2::all_git();

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&rustc)?
        .add_instructions(&git2)?
        .emit()?;

    Ok(())
}
