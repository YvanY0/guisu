# Guisu

Rust dotfile manager. Three-state model: **Source → Target → Destination**
(see [three-state-model](docs/developer-guide/three-state-model.md)).

## Build & verify

```bash
cargo check --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt -- --check
```

`just` aliases: `just clippy`, `just test`, `just build`, `just fmt`.
Docs-only changes may skip the cargo checks.

## Where things live

- Architecture & data flow — [architecture](docs/developer-guide/architecture.md),
  [three-state-model](docs/developer-guide/three-state-model.md),
  [data-flow](docs/developer-guide/data-flow.md),
  [error-handling](docs/developer-guide/error-handling.md),
  [crates](docs/developer-guide/crates.md)
- Per-crate guidance — `crates/{core,crypto,vault,config,template,engine,cli}/AGENTS.md`
- Contributing, CI, docs tooling — [contributing](docs/developer-guide/contributing.md)

Read the per-crate `AGENTS.md` before editing that crate.

## Hard invariants

- No bare `unwrap()` — use `?` with anyhow.
- Newtype paths: `AbsPath`/`RelPath`, never raw `PathBuf`.
- Add context to errors with `anyhow::Context`.
- Look for existing utilities before adding new ones.

## Tests

Complex logic → write `#[test]` first. Bug fix → test first, then fix.
Simple change → tests not required.

## Scope — ask first

Deleting files, modifying CI/CD, changing settings, or force-pushing: confirm first.

**Never delete user state.** The state DB at
`${XDG_STATE_HOME:-~/.local/state}/guisu/state.db` (and `~/.guisu/state.toml`)
is durable user data — it records hook history, content hashes, and three-state
reconciliation. Deleting it silently loses history (e.g. `mode=once` hooks
re-run, drift detection forgets prior state). Reload from source to reset only
when the user explicitly asks.

## Committing

`git commit -s -S`. No fake `Signed-off-by:` trailers, no
`--no-gpg-sign`/`--no-verify`; if signing fails, stop and ask the user to commit
for you. Details: [contributing](docs/developer-guide/contributing.md).

## When done

Before claiming complete: `cargo fmt -- --check`,
`cargo clippy --workspace -- -D warnings`, `cargo test --workspace`
(skip for docs-only). Don't `#[ignore]` a test or `#[allow]` a lint to
make checks pass — fix the cause. User-facing changes also satisfy the
[contributing "Documentation" checklist](docs/developer-guide/contributing.md).
