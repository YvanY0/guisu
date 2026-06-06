# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/YvanY0/guisu/releases/tag/v0.2.2) - 2026-06-06

### Added

- implement --force flag for apply command
- add config.edit.apply and smart apply for edit command
- improve update command with SSH auth and simplified UX
- improve info command and release v0.2.0
- add mode-aware hook change detection in status
- *(config)* add database-backed configuration caching
- *(cli)* add Command trait definition
- *(hooks)* simplify hooks command structure and add show command
- initial commit of Guisu dotfile manager

### Fixed

- address clippy warnings for modify implementation
- *(global)* apply hooks logic and resolve clippy warnings
- remove premature hook execution messages
- prevent read-only commands from modifying database state
- improve dry-run output formatting
- ensure hooks state persists even when no hooks execute
- resolve database lock errors by sharing database instance
- resolve critical code quality issues
- *(cli)* remove output and fix duplicate path in add command
- resolve clippy warnings and remove redundant tests

### Other

- rename guisu-cli crate to guisu, unify release tag
- *(dist)* point homebrew tap at YvanY0/homebrew-tap
- upgrade workspace dependencies and fix breaking API changes
- update dependencies and add security checks
- use module re-exports and remove dead code
- use specific error variants in config crate
- consolidate workspace dependencies
- restructure AGENTS.md for agent harness compatibility
- remove unused sha2 dependency from cli and engine crates
- remove unused --include/--exclude apply args
- prek autoupdate
- improve diff output formatting for mode and binary files
- simplify init output and clean up codebase
- cache content hash and optimize string allocations
- optimize hash functions to use stack-allocated arrays
- extract constants and add type aliases
- use named structs and helper extraction
- reduce code duplication and optimize allocations
- *(info)* optimize info command with zero-cost abstractions
- move all use statements to file tops
- reorganize utilities into utils module and reduce duplication
- unify path handling using SourceDirExt trait
- improve hooks show output formatting
- extract path utilities to reduce code duplication
- improve hooks system implementation
- migrate to ignore crate and improve infrastructure
- improve code quality in apply command
- replace once_cell with std::sync primitives
- *(engine)* [**breaking**] eliminate database singleton pattern
- *(cli)* improve error handling and remove incorrect config references
- comprehensive lint and type fixes
- comprehensive optimization and code quality improvements
- *(error)* unify error handling in core module
- comprehensive optimization and code quality improvements
- *(cli)* migrate all commands to Command trait pattern
- *(cli)* introduce RuntimeContext for shared state
- *(template)* optimize caching and string allocations
- *(modules)* rename modules for clarity
- document TODO items as future features in CLAUDE.md
- *(cli)* extract common path resolution helper (Phase 2)
- [**breaking**] optimize crate structure and dependencies (Phase 1)
- *(engine)* [**breaking**] migrate hooks system from config crate to engine
- *(hooks)* simplify Hook struct and execution logic
