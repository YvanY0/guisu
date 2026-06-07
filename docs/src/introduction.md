# Introduction

## What is Guisu?

Guisu is a Rust-based dotfile manager. It helps you keep your configuration files (dotfiles) under version control and apply them across multiple machines, with support for templates, encryption, secret managers, hooks, and a three-way merge that detects when files have been edited locally.

> [!NOTE]
> **Early development**
> Guisu is pre-1.0. APIs and behaviour may change between minor versions. Pin to a specific version if you depend on it.



## Why a new dotfile manager?

Guisu exists because the existing tools are good but each leaves room for improvement in one dimension:

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

## Inspiration

Guisu is heavily inspired by [chezmoi](https://www.chezmoi.io/) and shares its directory layout, file-attribute conventions, and overall feel.

## What to read next

- [Installation](installation.md) — get a working `guisu` binary.
- [Getting Started — init](getting-started/init.md) — `guisu init`.
- [User Guide — File Attributes](user-guide/file-attributes.md) — prefixes and suffixes.
- [Reference — Commands](reference/commands.md) — every subcommand.
- [Developer Guide — Architecture](developer-guide/architecture.md) — crates, state model, data flow, contributing.
