# CLI Crate

Clap-based CLI with `Command` trait pattern.

## Rules

- **All commands implement `Command` trait** in `command.rs`.
- **Use `RuntimeContext`** for shared state (config, paths, database).
- **Conflict handling** — use `ConflictHandler` in `conflict.rs`, don't roll your own.
- **Progress output** — use `stats.rs` types (`ApplyStats`, etc.) for structured output.
- **File path arguments** — accept `Vec<PathBuf>`, resolve to `AbsPath` early.

## Adding a New Command

1. Create `cmd/<name>.rs` with struct implementing `Command` trait
2. Add variant to `Commands` enum in `lib.rs`
3. Add match arm in `execute_command()` in `lib.rs`
4. Re-export in `cmd/mod.rs`
5. Add tests in same file

## Module Visibility

Internal modules are `pub(crate)`: `conflict`, `error`, `logging`, `stats`, `utils`.
Engine modules accessed via top-level re-exports: `guisu_engine::get_entry_state`, `guisu_engine::hash_content`, etc.

## Key Files

| File | Purpose |
|------|---------|
| `lib.rs` | CLI entry, `Commands` enum, `execute_command()` dispatch |
| `command.rs` | `Command` trait definition |
| `common.rs` | `RuntimeContext`, `ResolvedPaths` |
| `conflict.rs` | Three-way conflict detection and resolution (pub(crate)) |
| `stats.rs` | Output statistics types (pub(crate)) |
| `cmd/apply.rs` | Apply command (largest, ~1500 lines) |
