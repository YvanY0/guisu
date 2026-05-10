# Guisu

Rust dotfile manager. Three-state model: Source → Target → Destination.

## Commands

```bash
cargo check --workspace                               # type check
cargo test --workspace                                # run all tests
cargo clippy --workspace --all-targets -- -D warnings # lint
cargo fmt -- --check                                  # format check
cargo check -p guisu-engine                           # single crate
```

Also available via `just`:

```bash
just clippy    # full clippy with all features
just test      # run all tests
just build     # release build + show binary size
just fmt       # format code
just bloat     # analyze binary size
just udeps     # find unused dependencies
```

## Architecture

```
crates/cli       → CLI entry point
crates/config    → Configuration parsing
crates/core      → Core types (AbsPath, RelPath, Attributes, TargetEntry)
crates/crypto    → age encryption/decryption
crates/engine    → apply/diff/status pipeline, hooks, persistent state (redb)
crates/template  → minijinja template engine
crates/vault     → Secret provider integrations
```

Dependency direction (enforced by linter):

```
core ← crypto ← vault
  ↑       ↑
config ← template
  ↑       ↑
     engine
       ↑
      cli
```

Only upward dependencies allowed. Violation = CI blocks merge (`.github/workflows/pre-commit.yml`).

## Development Guidelines

Each rule here exists because of a past agent failure.

- **Test your changes.** If you didn't run the tests, your code does not work. Run `cargo test -p <crate>` for targeted tests.
- **Look for existing utilities first.** Avoid writing significant new code. Check neighboring files for patterns before adding new abstractions.
- **Follow existing code style.** Check neighboring files for patterns. `pedantic` + `correctness` clippy is denied workspace-wide.
- **No bare `unwrap()`.** Use `?` with anyhow, or `expect("reason")` for truly infallible cases. `unsafe_code` is denied.
- **Use newtype paths.** API boundaries must use `AbsPath`/`RelPath`, never raw `PathBuf`.
- **Add context to errors.** All fallible I/O must use `anyhow::Context`.
- **Don't narrate code.** No comments unless the WHY is non-obvious (hidden constraint, subtle invariant, workaround).
- **Don't over-engineer.** Three similar lines is better than a premature abstraction. No half-finished implementations.
- **Run clippy and tests at the end of every task.** Before reporting done: `cargo clippy --workspace -- -D warnings && cargo test --workspace`.

## Error Recovery

When something fails, fix it — don't work around it.

| Failure | Action |
|---------|--------|
| `cargo test` fails | Read the error output, fix the root cause, re-run. Don't skip or suppress failing tests. |
| `cargo clippy` warns | Fix the warning. Don't add `#[allow(...)]` unless there's a documented reason. |
| Merge conflict | Resolve the conflict. Don't discard either side without understanding both. |
| Build fails after dependency change | Run `cargo update` or check `Cargo.toml`. Don't revert blindly — understand why it broke. |
| Agent is stuck / looping | Stop. Summarize what was tried. Re-approach from a different angle or ask the user. |

## Verification

- For complex logic (algorithms, state machines, edge cases): **write `#[test]`**.
- For simple changes (typo, doc, rename): tests not required.
- For bug fixes: **write a test that reproduces the bug before fixing it**.
- Test location: same crate, `tests` module or `tests/` directory.

## Scope

**In scope**: anything the user asks for — code, docs, config, tests.
**Out of scope by default** (ask first):
- Deleting files or directories
- Modifying CI/CD workflows (`.github/`)
- Changing `.claude/settings.json`
- Force-pushing or rewriting git history

## Agent Orchestration

### When to Use Subagents

| Task | Agent | Trigger |
|------|-------|---------|
| Multi-file implementation | `Plan` | Architecture decisions, cross-crate changes |
| Code review | `code-reviewer` | After completing a feature |
| Security check | `security-auditor` | Crypto, vault, external input handling |
| Rust deep-dive | `rust-pro` | Complex lifetimes, async, trait design |
| Codebase search | `Explore` | Finding files/patterns (3+ queries) |

### Parallel Patterns

```
Research:  Explore(code) + DeepWiki(chezmoi) → parallel
Review:    code-reviewer + security-auditor → parallel
```

### Hooks

- **Formatting**: `PostToolUse` hook auto-runs `rustfmt` on `.rs` files (`.claude/settings.json`)
- **Destructive ops guard**: `PreToolUse` hook blocks `push --force`, `reset --hard`, `rm -rf /`
- **Pre-commit**: `prek` manages git hooks — `cargo fmt`, `cargo clippy`, `cargo test`, commitlint (`.pre-commit-config.yaml`)
- **CI**: GitHub Actions runs pre-commit on PR and push to main

## Feature Status

### Implemented
- [x] Hooks system (pre/post, mode: once/onchange/always)
- [x] `modify_` file type — in-place modification via scripts
- [x] Bitwarden integration (bw CLI, rbw, Secrets Manager)
- [x] 29 template functions (system, files, vault, strings, data, crypto)
- [x] 14 CLI commands (init, add, apply, diff, status, cat, edit, update, info, variables, age, ignored, templates, hooks)
- [x] Git integration (clone, fetch, rebase via git2)
- [x] Persistent state (redb) with validation and repair
- [x] Three-way conflict detection and resolution

### Planned
- [ ] External resources — download and manage external files/archives (P0)
- [ ] `doctor` command — system diagnostics (P0)
- [ ] Template functions phase 2 — git, system info, advanced filters (~20 functions) (P1)
- [ ] Secret manager expansion — 1Password, Pass, Keychain, HashiCorp Vault (P1)
- [ ] `unmanaged` command — list unmanaged files (P1)
- [ ] `archive` command — export as tar/zip (P2)

### Notes
- `re-add` is covered by `add --force` — no separate command needed
- Template Phase 1 encryption: blake3sum implemented instead of SHA variants (better choice)

## Commit

```
<type>: <description>
# type: feat | fix | refactor | chore | docs | test
```
