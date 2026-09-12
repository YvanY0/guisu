# Guisu

Rust dotfile manager. Three-state model: **Source → Target → Destination**
(see [three-state-model](docs/developer-guide/three-state-model.md)).

## Build & verify

```bash
cargo check --workspace --all-targets --all-features --locked && cargo test --workspace --all-features --locked && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo fmt --all -- --check
```

`just` aliases: `just clippy`, `just test`, `just build`, `just fmt`,
`just docs-build`, `just docs-serve`. They mirror the CI commands above.
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

## Code Quality

- No bare `unwrap()` — use `?` with anyhow.
- Newtype paths: `AbsPath`/`RelPath`, never raw `PathBuf`.
- Add context to errors with `anyhow::Context`.
- Look for existing utilities before adding new ones.
- Environment variables: route through `guisu_config::Env`, not raw
  `std::env::var`. The `disallowed-methods` lint in `.clippy.toml`
  enforces this; the `Env` type itself is the one allowed caller.
- Prefer plain `if`/`else` over `.then()` / `.then_some()`; avoid clever
  combinators that hide the control flow.
- Avoid `panic!` / `unreachable!` / `.unwrap()` / `.expect()`; encode the
  constraint in the type system instead. A larger refactor is fine when
  it removes these calls.
- Prefer the smallest coherent change; reuse existing mechanisms instead
  of building wrappers or abstractions for speculative gains.
- When lint suppression is needed, prefer narrow
  `#[expect(reason = "...")]` over `#[allow(...)]` so a future fix
  becomes a compile error instead of silently re-enabling the lint.

## GitHub Interaction

Draft GitHub comments locally. Do not post comments, submit reviews,
resolve threads, or otherwise mutate GitHub state without explicit
authorization — that includes triggering workflows (e.g. `gh workflow run`),
opening issues, and pushing to remotes.

## Tests

Complex logic → write `#[test]` first. Bug fix → test first, then fix.
Simple change → tests not required.

For binary-output / structured-text assertions, prefer
`pretty_assertions::assert_eq` over the std macro — failure messages
include a coloured side-by-side diff that makes regressions obvious. New
integration tests go under `crates/*/tests/` (one file per surface).
Coverage is uploaded to Codecov from the main-branch CI run; the badge
is informational and never gates merges.

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

Before claiming complete: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
`cargo test --workspace --all-features --locked`
(skip for docs-only). Don't `#[ignore]` a test or `#[allow]` a lint to
make checks pass — fix the cause. User-facing changes also satisfy the
[contributing "Documentation" checklist](docs/developer-guide/contributing.md).
