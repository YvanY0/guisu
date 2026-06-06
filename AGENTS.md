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

## Architecture

```
cli → engine → config/template/core
```

Subsystem rules: `crates/engine/AGENTS.md`, `crates/cli/AGENTS.md`.

## Rules

- No bare `unwrap()` — use `?` with anyhow
- Use newtype paths: `AbsPath`/`RelPath`, never raw `PathBuf`
- Add context to errors with `anyhow::Context`
- Look for existing utilities first
- Don't narrate code — well-named identifiers self-document
- Three similar lines > premature abstraction

## Commit rules

- `git commit` MUST include both `-s` (DCO `Signed-off-by:`) and `-S` (GPG or SSH signature). Do not commit without them.
- The repo's pre-commit framework (`.pre-commit-config.yaml`) runs lint hooks (taplo, gitleaks, typos, commitlint) on `git commit` from a terminal; if any fail, fix the underlying code rather than skipping hooks.
- Cargo tasks (`fmt`, `check`, `clippy`, `test`, `deny`, `outdated`) live in `.github/workflows/rust.yml` and run on every push to `main` and on PRs that touch `Cargo.toml`/`Cargo.lock`.
- Tip: in `~/.gitconfig`, set `[commit] gpgsign = true` and `signoff = true` to make git inject `-s` and `-S` automatically on every commit. This harness does not configure that for you; manage your global git config yourself.

## Error Recovery

| Failure | Action |
|---------|--------|
| `cargo test` fails | Fix the root cause |
| `cargo clippy` warns | Fix it |
| Agent stuck/looping | Stop. Summarize. Ask. |

## Scope

**Ask first**: delete files, modify CI/CD, change settings, force-push

## Claude Code Setup

Claude Code automations on this repo:

- **AGENTS.md / CLAUDE.md** — project rules, build commands, code style. Loaded every session.
- **Skills** — `.claude/skills/<name>/SKILL.md`. Domain knowledge (engine/template/vault) and reusable workflows (add-vault-provider, implement-cli-command, etc.). Claude auto-invokes by description match; you can also `/skill-name`.
- **Plugins** — installed via `/plugin`. `rust-analyzer-lsp` for live diagnostics and symbol navigation, `feature-dev` / `pr-review-toolkit` / `security-guidance` for subagent-based review, `commit-commands` for git workflows.
- **Subagents** — defined in plugins; not custom-defined in `.claude/agents/`. Use `Explore` for read-only codebase questions, `Plan` for design work, plugin-provided agents for review.
- **Hooks** — `.claude/settings.json` `hooks` block. PostToolUse runs `rustfmt` on `.rs` files. Stop hook runs `cargo fmt --check && cargo clippy --workspace -- -D warnings` and blocks completion on failure. Destructive Bash commands are not blocked; rely on the project's `AGENTS.md` "Ask first" rule below.
- **Pre-commit** — `pre-commit` framework via `.pre-commit-config.yaml` (independent of Claude Code). Runs lint hooks on `git commit` from a terminal.
- **Rust CI** — `.github/workflows/rust.yml`. Runs cargo fmt/check/clippy/test/deny/outdated in GitHub Actions. Auto-skipped on PRs that don't touch Rust files.

Memory (`.claude/memory/`) is **manually maintained**, not auto-synced. Edit it when you learn something the next session should know.
