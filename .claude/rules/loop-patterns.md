---
paths:
  - "**/*.rs"
  - "**/Cargo.toml"
---

# Loop Patterns

Pick the iteration pattern **before** editing. Most guisu tasks don't need a loop — explicit choice avoids spurious retries.

| Pattern | When to use | Stop signal |
|---------|-------------|-------------|
| Direct edit (no loop) | Single-line / typo / 1-line doc fix | File compiles, lint passes |
| TDD red-green | New function with non-trivial logic | Test passes after green |
| Subagent fan-out | Task decomposes into 3+ independent subtasks | All subtasks return, results merged |
| Plan-then-execute | Multi-file change requiring upfront design | Plan file exists, every plan item checked |
| Ralph-loop | Same prompt iterates to refine (test passes, format matches) | `--max-iterations` cap OR `completion-promise` string literal |

**Default for guisu: direct edit or TDD.** Reach for subagent fan-out only when subtasks are truly independent (no shared state, no shared files). Reserve Ralph for batch convergence ("make all tests pass", "fix all clippy warnings") — never as a default.

## Escape hatch

Same error repeating 3+ times → stop, summarize what was tried, ask the user. Don't keep retrying with minor variations.

For systematic debugging patterns, see the `systematic-debugging` skill.
