# Guisu

Rust dotfile manager. Three-state model: Source → Target → Destination.

## Build & Verify

```bash
cargo check --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt -- --check
```

Also via `just`: `just clippy`, `just test`, `just build`, `just fmt`.

- Complex logic → write `#[test]` first
- Bug fix → write test first, then fix
- Simple change → tests not required

## Rules

- No bare `unwrap()` — use `?` with anyhow
- Use newtype paths: `AbsPath`/`RelPath`, never raw `PathBuf`
- Add context to errors with `anyhow::Context`
- Look for existing utilities first
- Don't narrate code — well-named identifiers self-document
- Three similar lines > premature abstraction

Subsystem rules: `crates/core/AGENTS.md` (foundation), `crates/crypto/AGENTS.md`, `crates/vault/AGENTS.md`, `crates/config/AGENTS.md`, `crates/template/AGENTS.md`, `crates/engine/AGENTS.md`, `crates/cli/AGENTS.md`.

## Scope

**Ask first**: delete files, modify CI/CD, change settings, force-push

**Never delete user state files**. The persistent state DB at `${XDG_STATE_HOME:-~/.local/state}/guisu/state.db` (and `~/.guisu/state.toml`) is durable user data — it records which hooks have run, content hashes, and three-state reconciliation history. Deleting it silently loses that history (e.g. `mode=once` hooks will re-run, source→dest drift detection forgets prior state). Do not `rm` these files even when debugging; reload from source to reset only when the user explicitly asks.

## Committing and signing

All commits must use `git commit -s -S` with `Signed-off-by:` matching your real `user.name`/`user.email`; if signing is unavailable, stop and ask the user to commit for you — never inject fake trailers or bypass with `--no-gpg-sign`/`--no-verify`.

## Loop completion

A code change is not done until all of these pass:

- `cargo fmt -- --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace` (skip for docs-only changes)

The three cargo checks are only required when the change can affect the build — any `.rs` file, `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, or similar. Pure docs/config/script edits (`.md`, `.sh`, non-Cargo `.toml`/`.yaml`/`.json`) can skip them.

User-facing changes also need `developer-guide/contributing.md` "Documentation" checklist satisfied.

Pick the right iteration pattern before editing — see `.claude/rules/loop-patterns.md` (auto-loaded on Rust paths).
