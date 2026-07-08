# Guisu

A Rust-based dotfile manager. Keep your configuration files under version control and apply them across multiple machines, with templates, encryption, secret managers, hooks, and a three-way merge that detects when files have been edited locally.

!!! note "Early development"

    Guisu is pre-1.0. APIs and behaviour may change between minor versions. Pin to a specific version if you depend on it.

## Where to start

Pick the path that matches your situation:

- **New to Guisu:** start with [Installation](installation.md), then follow the [init](getting-started/init.md) walkthrough.
- **Migrating from chezmoi:** drop your existing `~/.local/share/chezmoi` into `~/.local/share/guisu` and read the [Configuration](user-guide/config.md) page — file-attribute conventions are compatible by design.
- **Looking for a specific flag or environment variable:** jump straight to the [Commands](reference/commands.md) or [Configuration Reference](reference/configuration.md).
- **Hitting an error or unexpected diff:** start with [Error Handling](developer-guide/error-handling.md), then [Hooks](user-guide/hooks.md) if it's about the apply phase.
- **Embedding Guisu as a library:** read [Architecture](developer-guide/architecture.md) and the [Three-State Model](developer-guide/three-state-model.md) first.

## The three-state model

Guisu manages every dotfile through three states:

```
Source state          Target state         Destination state
(repository)          (after processing)   (actual files)
     ↓                      ↓                     ↓
  .bashrc.j2     →     .bashrc (rendered)  →  ~/.bashrc
  key.txt.age    →     key.txt (decrypted) →  ~/key.txt
```

A persistent [redb](https://docs.rs/redb) database tracks the content hash of the **target** state that was last successfully applied. On the next run, Guisu compares the new target against the on-disk destination against the database and produces a status for each file: `Synced`, `Added`, `Modified`, `Removed`, or `Conflict`. The interactive `--interactive` mode lets you resolve conflicts in a TUI.

## How it compares

| Dimension | Guisu | Chezmoi |
| --- | --- | --- |
| Implementation | Rust, single static binary | Go, with cgo for some features |
| Encryption | Built-in (age crate) | External `age` binary, or built-in |
| Git | Built-in (git2 crate) | External `git` binary, or built-in |
| Database | redb (pure Rust) | BoltDB (cgo) |
| Template engine | minijinja (Jinja2-compatible) | Go `text/template` |
| Type safety | Compile-time path types (`AbsPath`, `RelPath`) | Runtime string checks |
| Typical binary size | 3-5 MB | ~20 MB |

The goal is **chezmoi parity with a smaller, faster, more self-contained binary** and a friendlier API for embedding Guisu as a library.

## Inspiration

Guisu is heavily inspired by [chezmoi](https://www.chezmoi.io/) and shares its directory layout, file-attribute conventions, and overall feel.
