# Guisu

Rust dotfile manager. Three-state model: Source → Target → Destination.

## Build

```bash
cargo check --workspace                               # type check
cargo test --workspace                                # run all tests
cargo clippy --workspace --all-targets -- -D warnings # lint
cargo fmt -- --check                                  # format check
cargo test -p <crate>                                 # single crate
```

Also via `just`: `just clippy`, `just test`, `just build`, `just fmt`, `just bloat`, `just udeps`.

## Verify

Before reporting done: `cargo clippy --workspace -- -D warnings && cargo test --workspace`

- Complex logic → write `#[test]` first
- Bug fix → write a test that reproduces the bug before fixing
- Simple change (typo, doc, rename) → tests not required

## Architecture

```
crates/cli       → CLI entry point (clap, Command trait)
crates/config    → Configuration parsing
crates/core      → Core types (AbsPath, RelPath, Attributes, TargetEntry)
crates/crypto    → age encryption/decryption
crates/engine    → apply/diff/status pipeline, hooks, persistent state (redb)
crates/template  → minijinja template engine (Jinja2 syntax, .j2 files)
crates/vault     → Secret provider integrations (Bitwarden)
```

Dependency direction (CI enforces):

```
core ← crypto ← vault
  ↑       ↑
config ← template
  ↑       ↑
     engine
       ↑
      cli
```

Subsystem rules: `crates/engine/AGENTS.md`, `crates/cli/AGENTS.md`.
Skills: `.claude/skills/` — domain-knowledge, implement-cli-command, add-template-function, add-vault-provider, debug-state-issues.
Commands: `.agents/commands/review-branch`.

## Rules

Each rule exists because of a past failure.

- **No bare `unwrap()`.** Use `?` with anyhow, or `expect("reason")` for infallible cases.
- **Use newtype paths.** API boundaries use `AbsPath`/`RelPath`, never raw `PathBuf`.
- **Add context to errors.** All fallible I/O must use `anyhow::Context`.
- **Look for existing utilities first.** Check neighboring files before adding abstractions.
- **Follow existing code style.** `pedantic` + `correctness` clippy is denied workspace-wide.
- **Don't narrate code.** No comments unless the WHY is non-obvious.
- **Don't over-engineer.** Three similar lines > premature abstraction.

## Error Recovery

| Failure | Action |
|---------|--------|
| `cargo test` fails | Fix the root cause. Don't skip or suppress. |
| `cargo clippy` warns | Fix it. Don't add `#[allow(...)]` without documented reason. |
| Build fails after dep change | `cargo update` or check `Cargo.toml`. Don't revert blindly. |
| Agent is stuck / looping | Stop. Summarize what was tried. Ask the user. |

## Scope

**Out of scope by default** (ask first):
- Deleting files or directories
- Modifying CI/CD workflows (`.github/`)
- Changing `.claude/settings.json`
- Force-pushing or rewriting git history

## Orchestration

| Task | Agent | When |
|------|-------|------|
| Multi-file impl | `Plan` | Architecture decisions, cross-crate |
| Code review | `code-reviewer` | After completing a feature |
| Security | `security-auditor` | Crypto, vault, external input |
| Rust deep-dive | `rust-pro` | Complex lifetimes, async, traits |
| Search | `Explore` | Finding patterns (3+ queries) |

## Hooks

- **Formatting**: PostToolUse auto-runs `rustfmt` on `.rs` files
- **Destructive guard**: PreToolUse blocks `push --force`, `reset --hard`, `rm -rf /`
- **Pre-commit**: `prek` — `cargo fmt`, `cargo clippy`, `cargo test`, commitlint
- **CI**: GitHub Actions runs pre-commit on PR and push to main

## Commit

```
<type>: <description>
# type: feat | fix | refactor | chore | docs | test
```
