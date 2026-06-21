---
paths:
  - ".github/workflows/**"
  - ".pre-commit-config.yaml"
---

# Commit rules

- `git commit` MUST include both `-s` (DCO `Signed-off-by:`) and `-S` (GPG or SSH signature). Do not commit without them.
- The repo's pre-commit framework (`.pre-commit-config.yaml`) runs lint hooks (taplo, gitleaks, typos, commitlint) on `git commit` from a terminal; if any fail, fix the underlying code rather than skipping hooks.
- Tip: in `~/.gitconfig`, set `[commit] gpgsign = true` and `signoff = true` to make git inject `-s` and `-S` automatically on every commit. This harness does not configure that for you; manage your global git config yourself.
