# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.6](https://github.com/YvanY0/guisu/compare/v0.2.5...v0.2.6) - 2026-07-13

### Fixed

- *(cli)* replace manual_assert_eq in test code

### Other

- *(cli)* centralize path display formatting via PathFormatter

## [0.2.5](https://github.com/YvanY0/guisu/compare/v0.2.4...v0.2.5) - 2026-07-02

### Added

- *(cli)* add guisu verify subcommand
- *(command)* add default exit_code method to Command trait
- *(engine)* promote per-entry comparison into verify module

### Fixed

- *(apply)* correct dry-run polarity, surface remove ops in summary, rename is_single_file

### Other

- *(apply)* exhaustive match on MatchResult in entry_needs_update
- *(apply)* use engine verify module for drift detection

## [0.2.4](https://github.com/YvanY0/guisu/compare/v0.2.3...v0.2.4) - 2026-06-22

### Added

- *(cli)* accept positional HOOK arg for `hooks run` and trim verbose output

### Fixed

- *(cli,engine)* persist full hook collection so status reflects last run
- *(cli)* align diff/apply filter logic and make apply output deterministic

### Other

- *(agents)* add .claude/rules/ and update contributing.md pointer

## [0.2.3](https://github.com/YvanY0/guisu/compare/v0.2.2...v0.2.3) - 2026-06-18

### Fixed

- *(deps)* upgrade git2 to 0.21 to address RUSTSEC-2026-0183/0184
- *(engine)* annotate unreachable and unignore runnable doctests

### Other

- update Cargo.toml dependencies
