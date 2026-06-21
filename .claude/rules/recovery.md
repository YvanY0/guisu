---
paths:
  - "**/*.rs"
  - "**/Cargo.toml"
  - "**/Cargo.lock"
---

# Error Recovery

| Failure | Action |
|---------|--------|
| `cargo test` fails | Fix the root cause |
| `cargo clippy` warns | Fix it |
| Agent stuck/looping | Stop. Summarize. Ask. |
