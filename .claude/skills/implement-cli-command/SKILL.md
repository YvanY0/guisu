---
name: implement-cli-command
description: Add a new CLI command to guisu. Use when adding user-facing subcommands; covers the Command trait, registration, argument parsing, and RuntimeContext integration.
---

# Implement a New CLI Command

## Steps

### 1. Create command file

`crates/cli/src/cmd/<name>.rs`:

```rust
use anyhow::Result;
use crate::command::Command;
use crate::common::RuntimeContext;

#[derive(clap::Args)]
pub struct <Name>Command {
    #[arg(short, long)]
    verbose: bool,
}

impl Command for <Name>Command {
    type Output = (); // or a stats struct

    fn execute(&self, ctx: &RuntimeContext) -> Result<Self::Output> {
        // ctx.config — Arc<Config>
        // ctx.paths — ResolvedPaths (source, dest)
        // ctx.db — Arc<RedbPersistentState>
        Ok(())
    }
}
```

### 2. Register in `lib.rs`

Add variant to `Commands` enum:
```rust
#[command(about = "Description of command")]
<Name>(cmd::<name>::<Name>Command),
```

Add match arm in `execute_command()`:
```rust
Commands::<Name>(cmd) => cmd.execute(&ctx)?,
```

### 3. Re-export in `cmd/mod.rs`

```rust
pub mod <name>;
```

### 4. Add tests in same file

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_<name>_command() {
        // Use RuntimeContext::from_parts() with TempDir and MockPersistentState
    }
}
```

## Key Patterns

- Accept `Vec<PathBuf>` for file arguments, resolve to `AbsPath` early
- Use `ctx.db` for persistent state, `ctx.config` for configuration
- For dry-run support: check `self.dry_run` and use `DryRunSystem`
- For progress/stats: return a struct implementing display
- For conflict handling: use `ConflictHandler` in `conflict.rs`

## Reference

- `crates/cli/src/command.rs` — `Command` trait
- `crates/cli/src/common.rs` — `RuntimeContext`
- `crates/cli/src/cmd/apply.rs` — most complete example
- `crates/cli/AGENTS.md` — CLI-specific rules
