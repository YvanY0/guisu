# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/YvanY0/guisu/releases/tag/guisu-crypto-v0.2.2) - 2026-06-08

### Added

- *(crypto)* map SSH ed25519 parse failure to typed error
- initial commit of Guisu dotfile manager

### Fixed

- *(global)* apply hooks logic and resolve clippy warnings
- *(crypto)* add bounds checking before string slicing
- resolve clippy warnings and remove redundant tests

### Other

- *(crypto)* replace ed25519 SSH fixtures with ssh-rsa, drop #[ignore]
- *(crypto)* add failing test for UnsupportedSshKey error
- update dependencies and add security checks
- simplify init output and clean up codebase
- use named structs and helper extraction
- replace once_cell with std::sync primitives
- *(cli)* improve error handling and remove incorrect config references
- comprehensive lint and type fixes
- comprehensive optimization and code quality improvements
