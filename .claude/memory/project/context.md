# Project Context

This file captures project-level information that persists across sessions.

## Project Overview

- **Name**: Guisu
- **Type**: Rust dotfile manager
- **Description**: Three-state model: Source → Target → Destination

## Architecture

```
crates/cli       → CLI entry point (clap, Command trait)
crates/config    → Configuration parsing
crates/core      → Core types (AbsPath, RelPath, Attributes, TargetEntry)
crates/crypto    → age encryption/decryption
crates/engine    → apply/diff/status pipeline, hooks, persistent state (redb)
crates/template  → minijinja template engine (Jinja2 syntax, .j2 files)
crates/vault      → Secret provider integrations (Bitwarden)
```

## Key Constraints

- No bare `unwrap()` - use `?` with anyhow
- Use newtype paths: `AbsPath`/`RelPath`, never raw `PathBuf`
- Add context to errors with `anyhow::Context`
- Follow existing code style - `pedantic` + `correctness` clippy denied workspace-wide

## Dependencies

Core ← Crypto ← Vault
  ↑       ↑
Config ← Template
  ↑       ↑
     Engine
       ↑
      CLI

## Last Updated

<!-- Manually maintained. Edit when project context changes. -->