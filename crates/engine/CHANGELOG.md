# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **BREAKING**: Filename-prefix attribute mechanism is no longer supported. The
  `private_`, `readonly_`, `executable_`, `dot_`, `exact_` prefixes are no
  longer recognized. Permissions are now derived from the source file's
  actual Unix mode bits (`metadata().mode()`); the source file is the
  source of truth. To make a file `0o600`, `chmod 600` the source file.
- **BREAKING**: The `TargetEntry::Modify` variant and `ModifyExecutor`
  script-execution path have been removed. The `modify_*` filename
  prefix is no longer recognized. Modify scripts are no longer
  supported.
- **BREAKING**: The `TargetEntry::Remove` variant has been removed.
  The `remove_*` filename prefix is no longer recognized. To remove a
  destination path, list it under `[remove] paths` in
  `.guisu/state.toml` (see `Metadata::remove`).
- **BREAKING**: The `TargetEntry::Symlink` variant is no longer
  produced by `SourceState::read` from a `symlink_*` filename prefix.
  It is only produced when the source filesystem contains a real
  symlink (e.g. `~/.local/share/guisu/home/x -> /target`). The
  `symlink_*` filename prefix is no longer recognized.
- `FileAttributes` is no longer a `bitflags!` struct. It is now a plain
  struct with `is_template: bool`, `is_encrypted: bool`, and
  `mode: Option<u32>` fields.
- `Error::InvalidAttributes`, `Error::DuplicateAttribute`, and
  `Error::InvalidAttributeOrder` variants have been removed from
  `guisu_core::Error` (they were leftovers from the removed
  prefix-parser).

### Changed

- **`FileAttributes::parse_from_source` returns `(FileAttributes, String)`
  instead of `Result<(FileAttributes, String), _>`** — the parser
  cannot fail. Callers update from `?` to bare `let`.

## [0.2.2](https://github.com/YvanY0/guisu/releases/tag/guisu-engine-v0.2.2) - 2026-06-08

### Added

- implement modify file type support
- add state validator for database integrity checking
- *(config)* add database-backed configuration caching
- *(hooks)* simplify hooks command structure and add show command
- initial commit of Guisu dotfile manager

### Fixed

- address clippy warnings for modify implementation
- *(global)* apply hooks logic and resolve clippy warnings
- preserve explicitly set hook order values
- resolve critical code quality issues
- resolve clippy warnings and remove redundant tests
- *(engine)* eliminate memory leak in database bucket name handling

### Other

- upgrade workspace dependencies and fix breaking API changes
- update dependencies and add security checks
- use module re-exports and remove dead code
- extract hook env and script modules from executor
- consolidate workspace dependencies
- restructure AGENTS.md for agent harness compatibility
- remove unused sha2 dependency from cli and engine crates
- use struct for skip check results in hook executor
- migrate from bincode to postcard serialization
- simplify init output and clean up codebase
- cache content hash and optimize string allocations
- optimize hash functions to use stack-allocated arrays
- rename state_validator to validator
- extract constants and add type aliases
- optimize parallel processing and regex caching
- reduce code duplication and optimize allocations
- remove unused vault dependency from engine crate
- improve hooks system implementation
- migrate to ignore crate and improve infrastructure
- optimize hashing and database operations
- improve SourceRelPath documentation clarity
- replace once_cell with std::sync primitives
- *(engine)* [**breaking**] eliminate database singleton pattern
- *(cli)* improve error handling and remove incorrect config references
- *(engine)* enable parallel database tests with isolated instances
- *(engine)* optimize database with RwLock for concurrent reads
- comprehensive lint and type fixes
- *(engine)* improve error handling in serialization
- comprehensive optimization and code quality improvements
- *(error)* unify error handling in core module
- comprehensive optimization and code quality improvements
- *(engine)* optimize database bucket name allocations
- document TODO items as future features in CLAUDE.md
- *(hooks)* add parallel hook loading with rayon (Phase 3)
- *(engine)* [**breaking**] migrate git operations from config crate to engine
- *(engine)* [**breaking**] migrate hooks system from config crate to engine
