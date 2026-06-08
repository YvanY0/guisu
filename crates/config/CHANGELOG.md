# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/YvanY0/guisu/releases/tag/guisu-config-v0.2.2) - 2026-06-08

### Added

- add config.edit.apply and smart apply for edit command
- *(hooks)* simplify hooks command structure and add show command
- initial commit of Guisu dotfile manager

### Fixed

- *(config)* use dirs crate on Windows to unblock MSVC build
- *(global)* apply hooks logic and resolve clippy warnings
- resolve critical code quality issues

### Other

- update dependencies and add security checks
- use specific error variants in config crate
- consolidate workspace dependencies
- extract constants and add type aliases
- use named structs and helper extraction
- migrate to ignore crate and improve infrastructure
- *(cli)* improve error handling and remove incorrect config references
- comprehensive lint and type fixes
- *(modules)* rename modules for clarity
- [**breaking**] optimize crate structure and dependencies (Phase 1)
- *(engine)* [**breaking**] migrate git operations from config crate to engine
- *(engine)* [**breaking**] migrate hooks system from config crate to engine
- *(hooks)* remove default and max timeout constraints
- *(hooks)* simplify Hook struct and execution logic
