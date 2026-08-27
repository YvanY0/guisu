# Contributing

Thanks for your interest in contributing. Guisu is pre-1.0; expect breaking API changes in the library crates.

## Documentation

> [!WARNING]
> **Update docs in the same PR**
> Every PR that adds or changes a user-facing command, flag, config key, file-attribute convention, template function, or hook mode must update the relevant page under `docs/{user-guide,reference}/` in the same PR. The PR template (below) has a matching checklist.



Checklist before opening a PR:

- [ ] If the PR adds a new subcommand, update [Reference — Commands](../reference/commands.md) and add a "Common usage" example to the relevant user-guide page.
- [ ] If the PR adds a template function or filter, update [Reference — Template Functions](../reference/template-functions.md) with the function's name, signature, and a one-line description. Mark the row as a function or filter explicitly.
- [ ] If the PR adds a config key, update [Reference — Configuration](../reference/configuration.md) with type, default, and notes.
- [ ] If the PR changes file-attribute behaviour, update [User Guide — File Attributes](../user-guide/file-attributes.md).
- [ ] If the PR changes hook semantics, update [User Guide — Hooks](../user-guide/hooks.md).
- [ ] If the PR changes the CLI global flags (`--source`, `--dest`, `--config`, `--log-file`, `--verbose`), update [Reference — Commands](../reference/commands.md).
- [ ] If the PR adds a new shell or installer integration (e.g. extending `guisu completion`), update [README — Shell completion](https://github.com/YvanY0/guisu/blob/main/README.md#shell-completion) with install instructions for the new shell.
- [ ] If the PR fixes a user-visible bug that previously diverged between commands (e.g. `diff` and `apply` reporting different file sets, or non-deterministic output order), document the corrected behaviour in the relevant getting-started / user-guide page so users can trust the docs again. Bug-fix PRs are not exempt from the "update docs in the same PR" rule above.

The site is English-only. A Chinese translation is not in scope; if one is added later, it is a separate effort and tracked elsewhere.

## Development setup

```bash
git clone https://github.com/YvanY0/guisu.git
cd guisu
cargo build
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt -- --check
```

Recommended tools:

- `mise` — Rust toolchain + project tasks (see `rust-toolchain.toml`).
- `pre-commit` — see `.pre-commit-config.yaml`. Install once with `pre-commit install`.
- `cargo-nextest` — faster test runner (`cargo nextest run`).

## CI & local hooks

- `.github/workflows/rust.yml` runs `cargo fmt`/`check`/`clippy`/`test`/`deny`/`outdated`. It auto-skips on PRs that don't touch Rust files.
- `.pre-commit-config.yaml` runs local lint hooks (taplo, gitleaks, typos, commitlint) on the `pre-commit` stage and cargo `fmt`/`clippy`/`check`/`test`/`deny` on the `pre-push` stage. Run from a terminal via `prek` or `pre-commit`.
- `.claude/settings.json` has a PostToolUse hook (on `Edit`/`Write` to `*.rs`) that runs `rustfmt` to auto-format saved files.

## Signing commits

`git commit` must include both `-s` (DCO `Signed-off-by:`) and `-S` (GPG or SSH signature). Don't commit without them; don't bypass with `--no-gpg-sign`/`--no-verify`. If signing fails, stop and ask the user to commit for you.

Tip: in `~/.gitconfig`, set `[commit] gpgsign = true` and `signoff = true` so git injects `-s` and `-S` automatically on every commit.

## Docs site tooling

**Zensical** (Python, Material-fork `material` theme variant). No version pin — both `.github/workflows/docs.yml` and the `docs-build`/`docs-serve` Justfile recipes invoke zensical via `uvx --from zensical`, so the docs always build against the latest upstream release. `--strict` surfaces upstream breakage at the next CI run.

## Pull request process

1. Branch from `main`. Use a short descriptive prefix: `feat/...`, `fix/...`, `docs/...`, `refactor/...`.
2. Commit with `-s` and `-S` (DCO + GPG/SSH signature). The repo enforces both — see [Signing commits](#signing-commits) above.
3. Run the build & verify commands above. They must all pass.
4. Open a PR with a clear title and a short description of the change. Reference any related issues.
5. Address review feedback. Squash-merge is preferred for a linear history.

## PR template

```markdown
## Description
Brief description of changes.

## Motivation
Why is this change needed?

## Changes
- List of changes
- Another change

## Documentation
- [ ] Updated the relevant docs page (which one: ...)
- [ ] No docs update needed (reason: ...)

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] `cargo fmt -- --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Commit signed (`-s -S`)
```

## Architecture guidelines

- Follow the existing layered architecture — see [Architecture](architecture.md). Lower layers never depend on higher layers.
- Use newtype paths (`AbsPath`, `RelPath`), not raw `PathBuf`.
- Use `?` with `.context(...)` in the CLI, not bare `unwrap()`. Library errors use `thiserror`; see [Error Handling](error-handling.md).
- For new template functions, follow the existing per-category layout in `crates/template/src/functions/`. One file per category; one function per `pub fn` with a doctest.
- For new vault providers, implement `SecretProvider` in `crates/vault/src/`. See [vault/AGENTS.md](https://github.com/YvanY0/guisu/blob/main/crates/vault/AGENTS.md) for the full checklist.

## Adding a new subcommand

1. Create `crates/cli/src/cmd/<name>.rs` with a `#[derive(Args)]` struct and a `Command` impl.
2. Add a variant to `Commands` in `crates/cli/src/lib.rs` with a docstring.
3. Add a row to [Reference — Commands](../reference/commands.md).
4. Add tests under `crates/cli/src/cmd/<name>_test.rs` (or inline with `#[cfg(test)]`).

## See also

- [Architecture](architecture.md)
- [Three-State Model](three-state-model.md)
- [Crates](crates.md)
- [Error Handling](error-handling.md)
- [AGENTS.md](https://github.com/YvanY0/guisu/blob/main/AGENTS.md) — the project rules every agent follows.
