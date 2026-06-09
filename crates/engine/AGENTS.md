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
