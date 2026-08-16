# Guisu (归宿)

> A Rust-based dotfile manager. Inspired by [chezmoi](https://www.chezmoi.io/),
> "归宿" means "home" or "destination" — Guisu is a safe harbor for managing
> your configuration files across all your machines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)](#project-status)

**Early Development Notice**: Guisu is currently in early development (pre-1.0).
APIs and features are subject to change. Production use is not recommended yet.

## What is Guisu?

A Rust-based dotfile manager. The full pitch, feature list, command reference,
architecture deep-dive, and migration guide live in the
[**project documentation**](https://yvany0.github.io/guisu/).

Quick comparison with chezmoi, install instructions, and a 30-second tour are
all in the docs. Reading order: [Introduction](https://yvany0.github.io/guisu/introduction.html)
→ [Installation](https://yvany0.github.io/guisu/installation.html)
→ [Getting Started](https://yvany0.github.io/guisu/getting-started/init.html).

## Quick Install (from source)

```bash
git clone https://github.com/YvanY0/guisu.git
cd guisu
cargo install --path crates/cli
```

Binary releases will be linked from the docs once they ship.

## Shell completion

Load the completion script into your current shell with `eval`:

```sh
eval "$(guisu completion zsh)"   # zsh
eval "$(guisu completion bash)"  # bash
eval "$(guisu completion fish)"  # fish
```

This works immediately but does not persist across shells. To make
the completion permanent, add the matching line to `~/.zshrc`,
`~/.bashrc`, or `~/.config/fish/config.fish` respectively.

The script is generated from the clap derive tree, so adding or
removing subcommands does not require any manual maintenance.

## Documentation

Full documentation is at <https://yvany0.github.io/guisu/> and lives in
`docs/` of this repository.

- [User Guide](https://yvany0.github.io/guisu/user-guide/file-attributes.html) —
  file attributes, templates, encryption, vault, hooks, config
- [Reference](https://yvany0.github.io/guisu/reference/commands.html) —
  every command, every template function, every config key
- [Developer Guide](https://yvany0.github.io/guisu/developer-guide/architecture.html) —
  crate layout, three-state model, data flow, contributing

## Project Status

Implemented: file/dir/symlink management, minijinja templates, age encryption,
git integration, interactive conflict resolution TUI, redb state tracking,
parallel processing, platform-specific config, Bitwarden integration, hooks
system, removal directives via `state.toml`.

Not yet: external resources, create-only files, password managers beyond
Bitwarden, full template function parity with chezmoi. See the
[Roadmap](https://yvany0.github.io/guisu/roadmap.html) for the milestone plan.

## Contributing

See [Contributing](https://yvany0.github.io/guisu/developer-guide/contributing.html).
Please note the [Documentation checklist](https://yvany0.github.io/guisu/developer-guide/contributing.html#documentation)
in that guide: every PR that adds or changes a user-facing command, flag,
config key, file-attribute convention, template function, or hook mode must
update the relevant docs page in the same PR.

## Inspiration

Guisu is heavily inspired by [chezmoi](https://www.chezmoi.io/), with the
goal of providing similar functionality in a Rust-native package.

## License

MIT — see [LICENSE](LICENSE).
