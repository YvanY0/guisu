---
paths:
  - ".github/workflows/**"
  - ".pre-commit-config.yaml"
---

# CI Workflows

- `.github/workflows/rust.yml` — runs cargo fmt/check/clippy/test/deny/outdated. Auto-skipped on PRs that don't touch Rust files.
- `.pre-commit-config.yaml` — local lint hooks (taplo, gitleaks, typos, commitlint). Independent of CI; runs on `git commit` from a terminal.
- `.claude/settings.json` Stop hook — runs `cargo fmt --check && cargo clippy --workspace -- -D warnings` and blocks completion on failure.
