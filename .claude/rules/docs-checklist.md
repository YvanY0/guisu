---
paths:
  - "docs/**"
  - "README.md"
---

# Documentation Checklist

User-facing feature work must update `docs/developer-guide/contributing.md` "Documentation" checklist before merge — it already enumerates the pages to update (commands, template functions, config keys, file attributes, hooks, CLI flags, shell completion). PRs are not exempt.

Documentation site tooling: **Zensical 0.0.47** (Python, Material-fork "modern" theme variant). Configured via `zensical.toml` at repo root (nav block replaces the old `docs/src/SUMMARY.md`). Version pinned in `requirements.txt` at repo root. Local dev via `uvx` (no global install required) or `uv tool install -r requirements.txt` (one-time). Justfile recipes: `docs-install`, `docs-build`, `docs-serve`, `docs-check`.
