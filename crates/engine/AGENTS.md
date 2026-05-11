# Engine Crate

Core pipeline: state management, hooks, file processing, persistent state (redb).

## Rules

- **Use `System` trait** for all filesystem ops. Never call `std::fs` directly.
- **Use `PersistentState` trait** for database ops. Never use `RedbPersistentState` directly in tests.
- **Batch database writes** — `save_entry_states_batch()` not individual `save_entry_state()`.
- **Content processing order** — decrypt (`.age`) first, then render template (`.j2`). Reversed for `.j2.age`.
- **Hook execution** — hooks with same `order` run in parallel (rayon), different `order` runs sequentially.
- **Hash comparison** — use `subtle::ConstantTimeEq` for security-sensitive hash comparisons, not `==`.

## Module Visibility

Internal modules are `pub(crate)` — use top-level re-exports from `lib.rs`:
- `guisu_engine::get_entry_state`, `save_entry_state`, `save_entry_states_batch`, `get_db_path`
- `guisu_engine::hash_content`, `hash_file`
- `guisu_engine::RealSystem`, `DryRunSystem`, `Operation`, `System`
- `guisu_engine::ModifyExecutor`

## Key Files

| File | Purpose |
|------|---------|
| `state.rs` | Three-state model, `SourceState`/`TargetState`/`DestinationState` |
| `processor.rs` | Apply pipeline: compare target vs destination, write changes |
| `database.rs` | `RedbPersistentState` implementation, batch operations (pub(crate)) |
| `attr.rs` | Attribute prefix parsing (`dot_`, `private_`, `modify_`, etc.) |
| `entry.rs` | `SourceEntry`, `TargetEntry`, `DestEntry` types |
| `hooks/` | Hook system (6 files): config, loader, executor, state, types |
| `modify.rs` | `ModifyExecutor` for `modify_*` scripts (pub(crate)) |
| `system.rs` | `System` trait, `RealSystem`, `DryRunSystem` (pub(crate)) |

## Adding a New Entry Type

1. Add variant to `TargetEntry` enum in `entry.rs`
2. Add attribute flag in `attr.rs` if prefix-based
3. Handle in `TargetState::from_source()` in `state.rs`
4. Handle in `process_entry()` in `processor.rs`
5. Add tests in same file
