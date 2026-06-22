---
paths:
  - ".github/workflows/**"
  - ".pre-commit-config.yaml"
---

# CI Workflows

- `.github/workflows/rust.yml` — runs cargo fmt/check/clippy/test/deny/outdated. Auto-skipped on PRs that don't touch Rust files.
- `.pre-commit-config.yaml` — local lint hooks (taplo, gitleaks, typos, commitlint) on `pre-commit` stage; cargo fmt/clippy/check/test/deny on `pre-push` stage. Runs from a terminal via `prek` / `pre-commit`.
- `.claude/settings.json` PostToolUse (Edit|Write on `*.rs`) — runs `rustfmt` to auto-format saved files.
