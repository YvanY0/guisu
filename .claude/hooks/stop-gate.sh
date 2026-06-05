#!/usr/bin/env bash
# Stop gate — runs on Claude Code's Stop event.
# Blocks the stop if cargo fmt or cargo clippy fail.
# Exits 2 with a JSON decision=block payload on stderr.
# Does NOT run cargo test; that gate is owned by the pre-commit
# framework at commit time.

set -e

cd "$CLAUDE_PROJECT_DIR"

echo "Running stop-gate checks..." >&2

if ! cargo fmt -- --check; then
  echo '{"decision":"block","reason":"cargo fmt found unformatted files. Run `cargo fmt` and re-verify."}' >&2
  exit 2
fi

if ! cargo clippy --workspace --all-targets -- -D warnings; then
  echo '{"decision":"block","reason":"cargo clippy produced warnings. Fix them and re-verify."}' >&2
  exit 2
fi

echo "Stop-gate passed." >&2
exit 0
