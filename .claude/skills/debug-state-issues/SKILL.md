---
name: debug-state-issues
description: Debug state management, drift detection, or persistent database issues in guisu. Use when chasing bugs in the redb state store or source/target/destination reconciliation.
---

# Debug State Issues

## Three-State Model

```
Source ──→ Target ──→ Destination
(repo)     (desired)   (filesystem)
```

State is tracked in redb at `~/.local/state/guisu/state.db`.

## Diagnostic Commands

```bash
guisu status                    # Show all file states (L/A/B/C/S)
guisu status --all              # Include synced files
guisu diff                      # Show content differences
guisu info --all                # Show config, identities, DB status
```

## Common Issues

### Files show as "Behind" [B] when they shouldn't

Cause: Destination was modified outside guisu, or state DB is stale.

Check:
```bash
guisu diff <file>               # See actual differences
```

Fix: `guisu apply --force <file>` to sync, or `guisu add --force <file>` to re-add source.

### Files show as "Conflict" [C]

Cause: Both source and destination changed since last apply.

Check:
```bash
guisu diff <file>               # See both changes
```

Fix: `guisu apply --interactive <file>` for guided resolution, or manually resolve and re-add.

### State DB corruption

Symptoms: Unexpected errors, missing entries, hash mismatches.

Check DB location:
```bash
ls -la ~/.local/state/guisu/state.db
```

Fix: Delete the DB to reset all state (next apply will rebuild):
```bash
rm ~/.local/state/guisu/state.db
guisu apply --dry-run           # Verify before applying
```

### Hook state issues

Hooks track execution state separately from file state.

Check hook status:
```bash
guisu hooks list
guisu hooks show <name>
```

Reset hook state: delete the `hookState` bucket in the DB, or delete the entire DB.

## State Architecture

Key types in `engine/src/state.rs`:

- `EntryState` — `content_hash` (blake3, 32 bytes) + `mode` (optional u32)
- `HookState` — `last_executed`, `once_executed` set, `onchange_hashes` map
- `ConfigMetadata` — template hash + rendered config cache
- `PersistentState` trait — `get`, `set`, `set_batch`, `delete`, `for_each`

Database buckets: `entryState`, `hookState`, `configMetadata`.

Hash comparison uses `subtle::ConstantTimeEq` for security.

## Debugging Tips

1. Use `guisu status --all` to see the full picture
2. Use `guisu diff` to see what actually changed
3. Use `guisu info --all` to check config and identities
4. Check `~/.local/state/guisu/state.db` existence and size
5. For hook issues: `guisu hooks list` and `guisu hooks show <name>`
6. For template issues: `guisu templates show <name>`
