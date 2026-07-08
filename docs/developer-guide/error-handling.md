# Error Handling

Guisu uses a two-tier error strategy, mirrored by [AGENTS.md](https://github.com/YvanY0/guisu/blob/main/AGENTS.md) "Rules":

1. **Libraries** (`guisu-core`, `guisu-crypto`, `guisu-engine`, …) — typed errors via `thiserror`. The error enum is `pub` and variants are matchable. Errors are converted to `anyhow::Error` at the boundary.
2. **CLI** (`guisu-cli`) — `anyhow::Result` at the boundary. Library errors are converted via `?` and `.context(...)` is added at the call site.

## Library error example

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to read source file {path}: {source}")]
    ReadSource {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("template error at {location}: {message}")]
    Render { location: String, message: String },

    #[error("decrypt failed for {path}: {source}")]
    Decrypt {
        path: String,
        #[source]
        source: guisu_crypto::Error,
    },
}
```

Key conventions:

- One error enum per crate, named simply `Error` and re-exported as `crate::Error`.
- `#[source]` chains the underlying cause so it shows up in the `Display` output and `std::error::Error::source()` chain.
- `#[from]` is used sparingly — most conversions go through explicit `map_err` calls so the user-visible error stays short.

## CLI usage

```rust
use anyhow::Context;

fn run() -> anyhow::Result<()> {
    let state = engine::read_source(&path)
        .context("failed to read source state")?;
    let target = engine::build_target(&state, &processor, &context)
        .context("failed to build target state")?;
    engine::apply(&target, &dest, &apply_opts)
        .context("apply failed")?;
    Ok(())
}
```

The `.context(...)` calls add a one-line breadcrumb that miette renders as part of the error chain. `crates/cli/src/main.rs` configures miette to print the full chain in a coloured, code-aware format.

## Logging

`tracing` is used for structured logging. Levels: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`. `RUST_LOG=info` is the default for the CLI; raise it with `RUST_LOG=guisu_engine=debug` for a single crate.

```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(content))]
fn process_file(path: &Path, content: &[u8]) -> Result<()> {
    debug!(path = %path.display(), size = content.len(), "processing file");
    // ...
    info!(path = %path.display(), "file processed successfully");
    Ok(())
}
```

## When to use `unwrap`

Almost never in library code. The two acceptable places are:

1. **In tests** (`#[cfg(test)] mod tests`) where a panic is a clear test failure.
2. **In `build.rs` or other build-time code** where a panic is acceptable because the build itself is the only thing that can fail.

Application code (`guisu-cli`) uses `anyhow::Context` and lets miette display the error. Library code uses `?` and typed errors.

## See also

- [Contributing](contributing.md) — the rules for adding new errors.
- [AGENTS.md](https://github.com/YvanY0/guisu/blob/main/AGENTS.md) — the project-level rule "No bare `unwrap()` — use `?` with anyhow".
