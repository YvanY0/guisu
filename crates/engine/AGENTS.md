# Engine Crate

Core pipeline: state management, hooks, file processing, persistent state (redb).

## Rules

- **Use `System` trait** for all filesystem ops. Never call `std::fs` directly.
- **Use `PersistentState` trait** for database ops. Never use `RedbPersistentState` directly in tests.
- **Batch database writes** — `save_entry_states_batch()` not individual `save_entry_state()`.
- **Content processing order** — decrypt (`.age`) first, then render template (`.j2`). Reversed for `.j2.age`.
- **Hook execution** — hooks with same `order` run in parallel (rayon), different `order` runs sequentially.
- **Hash comparison** — use `subtle::ConstantTimeEq` for security-sensitive hash comparisons, not `==`.
- **Permissions** — the source file's `metadata().mode()` is the source of truth for permissions. `apply` propagates it to the destination. Do not encode permissions in the filename.

## Module Visibility

Internal modules are `pub(crate)` — use top-level re-exports from `lib.rs`:
- `guisu_engine::get_entry_state`, `save_entry_state`, `save_entry_states_batch`, `get_db_path`
- `guisu_engine::hash_content`, `hash_file`
- `guisu_engine::RealSystem`, `DryRunSystem`, `Operation`, `System`

## Key Files

| File | Purpose |
|------|---------|
| `state.rs` | Three-state model, `SourceState`/`TargetState`/`DestinationState`; `Metadata` for `state.toml` |
| `processor.rs` | Apply pipeline: compare target vs destination, write changes |
| `database.rs` | `RedbPersistentState` implementation, batch operations (pub(crate)) |
| `attr.rs` | `FileAttributes` plain struct (`is_template`, `is_encrypted`, `mode`) — extension-only parsing |
| `entry.rs` | `SourceEntry`, `TargetEntry` (`File` / `Directory` / `Symlink`), `DestEntry` types |
| `hooks/` | Hook system (6 files): config, loader, executor, state, types |
| `system.rs` | `System` trait, `RealSystem`, `DryRunSystem` (pub(crate)) |

## Removing a destination path

`TargetEntry::Remove` was removed; removals are now expressed via
`Metadata::remove.paths` in `.guisu/state.toml`. `apply` runs a
pre-pass that `rm`s each path (subject to dest-traversal safety
checks). To add new entry types:

1. Add a variant to `TargetEntry` in `entry.rs` (only `File`,
   `Directory`, and `Symlink` exist today).
2. If the variant is a source-side marker (e.g. `symlink_` was),
   define the marker convention in the user guide and route
   `SourceState::read` to produce the variant. The legacy
   filename-prefix attribute mechanism (`private_`, `modify_`, etc.)
   is no longer supported.
3. Handle the variant in `TargetState::from_source()` in `state.rs`.
4. Handle it in `apply_target_entry()` in `apply.rs` (CLI).
5. Add tests in the same file.

## Testing

Use the in-repo test doubles — never the real `RedbPersistentState` or `std::fs`:

| Tool | Location | Purpose |
|------|----------|---------|
| `MockPersistentState` | `engine/src/state.rs` | In-memory DB, no real redb |
| `TempDir` | `tempfile` crate | Auto-cleanup temp dirs |
| `NoOpDecryptor` | `engine/src/content.rs` | Skip encryption in tests |
| `NoOpRenderer` | `engine/src/content.rs` | Skip template rendering in tests |
| `NoOpProcessor` | `engine/src/content.rs` | Type alias for the above |

Pattern: build a `TempDir`, a `MockPersistentState`, and a `RealSystem` (or `DryRunSystem`), then drive the pipeline through the `System` + `PersistentState` traits.

## Debugging state

Read the three states with:

```bash
guisu status            # per-file state code
guisu diff              # content differences between states
guisu info --all        # config, identities, DB status
```

Common `status` codes and causes:

- **Behind** — destination changed outside guisu, or the state DB is stale. `guisu diff` shows what diverged; re-sync via `apply`, or re-add the source.
- **Conflict** — both source and destination changed since the last apply. Resolve, then re-add.

State lives in redb at `${XDG_STATE_HOME:-~/.local/state}/guisu/state.db`. **Never delete it to "reset"** — that silently loses hook history and drift detection (see AGENTS.md "Never delete user state"). Reload from source instead, and only when the user explicitly asks.
