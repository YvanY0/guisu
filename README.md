# Guisu (归宿)

> A Rust-based dotfile manager. Inspired by [chezmoi](https://www.chezmoi.io/),
> "归宿" means "home" or "destination" — Guisu is a safe harbor for managing
> your configuration files across all your machines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)](#)

**Early development**: Guisu is pre-1.0. APIs and features are subject to change;
production use is not recommended yet.

The full pitch, feature list, install guide, command reference, architecture
deep-dive, and roadmap live in the
[**project documentation**](https://yvany0.github.io/guisu/).

## Quick install (from source)

```bash
git clone https://github.com/YvanY0/guisu.git
cd guisu
cargo install --path crates/cli
```

Pre-built binaries are linked from the
[releases page](https://github.com/YvanY0/guisu/releases) once they ship.

## Shell completion

```sh
eval "$(guisu completion zsh)"   # zsh / bash / fish
```

See [Shell completion](https://yvany0.github.io/guisu/installation.html#shell-completion)
in the docs for making it permanent.

## Documentation

<https://yvany0.github.io/guisu/> — [User Guide](https://yvany0.github.io/guisu/user-guide/file-attributes.html),
[Reference](https://yvany0.github.io/guisu/reference/commands.html),
[Developer Guide](https://yvany0.github.io/guisu/developer-guide/architecture.html).

## Contributing

See the [Contributing guide](https://yvany0.github.io/guisu/developer-guide/contributing.html).

## License

MIT — see [LICENSE](LICENSE).
