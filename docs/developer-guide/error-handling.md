# Error Handling

Guisu uses a two-tier error strategy, mirrored by [AGENTS.md](https://github.com/YvanY0/guisu/blob/main/AGENTS.md) "Rules":

1. **Libraries** (`guisu-core`, `guisu-crypto`, `guisu-engine`, `guisu-template`, `guisu-config`, `guisu-vault`) — a single, shared typed error enum in `guisu-core` (`crates/core/src/error.rs`), declared `#[non_exhaustive]` and re-exported as `guisu_core::Error` / `guisu_core::Result`. Every other library crate uses this same type — there is no per-crate `Error` enum. `guisu-vault` re-exports it directly (`pub use guisu_core::Error`). Variants are matchable and the type is `non_exhaustive` so new variants can land without a breaking change.
2. **CLI** (`guisu-cli`) — `anyhow::Result` at the boundary. Library errors are converted via `?` and `.context(...)` is added at the call site. Inside the CLI crate, a small internal `error::Error` (in `crates/cli/src/error.rs`) wraps `guisu_core::Error` to carry command-specific exit codes.

## Library error enum (excerpt)

The real enum has ~40 variants across I/O, paths, config, templates, encryption, vault, hooks, state, and git. A representative slice:

```rust
use thiserror::Error;

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to read file {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Template rendering failed for {path}: {source}")]
    TemplateRender {
        path: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Decryption failed for {path}: {source}")]
    Decryption {
        path: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // … InvalidConfig, IdentityNotFound, HookConfig, State, Git(#[from] git2::Error), …
}
```

Key conventions:

- One enum, in `guisu-core`, named `Error`. Other crates use `guisu_core::Error` / `guisu_core::Result<T>`.
- `#[source]` chains the underlying cause so it shows up in the `Display` output and `std::error::Error::source()` chain.
- `#[from]` is used for a few external types (e.g. `std::io::Error`, `serde_json::Error`, `git2::Error`); most conversions go through explicit `map_err` calls so the user-visible error stays short.
- `Error::context(self, ctx)` wraps an error in `Error::Other { context, source }` to add a breadcrumb without leaving the typed enum.

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

The `.context(...)` calls add a one-line breadcrumb that miette renders as part of the error chain. `crates/cli/src/main.rs` configures miette (coloured, code-aware rendering); `tracing` is initialised separately in `crates/cli/src/logging.rs::init(verbose, log_file)`.

## Logging

`tracing` is used for structured logging. Levels: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`. The default filter (when `RUST_LOG` is unset) is `guisu=<level>,engine=<level>,crypto=<level>,template=<level>`, where `<level>` is `info` normally and `debug` under `--verbose`. Set `RUST_LOG` to override the whole filter (e.g. `RUST_LOG=guisu_engine=debug`, or `RUST_LOG=trace` for everything).

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

Application code (`guisu-cli`) uses `anyhow::Context` and lets miette display the error. Library code uses `?` and the shared typed `guisu_core::Error`.

## See also

- [Contributing](contributing.md) — the rules for adding new errors.
- [AGENTS.md](https://github.com/YvanY0/guisu/blob/main/AGENTS.md) — the project-level rule "No bare `unwrap()` — use `?` with anyhow".
