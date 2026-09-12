# Guisu (归宿)

> A Rust-based dotfile manager. Inspired by [chezmoi](https://www.chezmoi.io/),
> "归宿" means "home" or "destination" — Guisu is a safe harbor for managing
> your configuration files across all your machines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)](#)

**Early development**: Guisu is pre-1.0. APIs and features are subject to change;
production use is not recommended yet.

## Quick start

```bash
git clone https://github.com/YvanY0/guisu.git && cd guisu
cargo install --path crates/cli
# binary at ~/.cargo/bin/guisu — add to $PATH if needed
guisu info       # verify the binary resolves your source dir
```

Pre-built binaries are linked from the
[releases page](https://github.com/YvanY0/guisu/releases) once they ship.

## Documentation

- [Installation](https://yvany0.github.io/guisu/installation/)
- [User guide](https://yvany0.github.io/guisu/user-guide/file-attributes/)
- [Command reference](https://yvany0.github.io/guisu/reference/commands/)
- [Developer guide](https://yvany0.github.io/guisu/developer-guide/architecture/)
- [Contributing](https://yvany0.github.io/guisu/developer-guide/contributing/)
- [llms.txt (LLM-friendly)](https://yvany0.github.io/guisu/llms.txt) — for Claude/Cursor/Continue.dev context

## License

MIT — see [LICENSE](LICENSE).
