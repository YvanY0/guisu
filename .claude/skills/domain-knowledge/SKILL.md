---
name: domain-knowledge
description: Load when implementing features, fixing bugs, or modifying engine/template/vault code. Covers the three-state model, attribute system, System trait, template engine, and testing patterns.
paths:
  - crates/engine/**/*.rs
  - crates/template/**/*.rs
  - crates/vault/**/*.rs
  - crates/crypto/**/*.rs
---

# Guisu Domain Knowledge

## Three-State Model

Guisu manages files through three states:

```
Source ──→ Target ──→ Destination
(user's     (desired     (actual
 repo)       state)       filesystem)
```

**Source → Target**: Decrypt (`.age`) then render template (`.j2`). Order matters for `.j2.age`.
**Target → Destination**: Write to disk via `System` trait.
**Destination ↔ Target**: Compare for drift detection (status/diff commands).

Key types in `engine/src/state.rs`:
- `SourceState` — reads source dir in parallel (rayon)
- `TargetState` — created via `from_source()`, processes entries through `ContentProcessor`
- `DestinationState` — reads current filesystem, uses `System` trait

## Attribute Prefix System

`engine/src/attr.rs` defines file attributes via prefixes parsed from filenames:

| Prefix | Flag | Effect |
|--------|------|--------|
| `dot_` | DOT | Hidden file (leading dot) |
| `private_` | PRIVATE | Permissions 0600/0700 |
| `readonly_` | READONLY | No write bits |
| `executable_` | EXECUTABLE | Owner execute bit |
| `exact_` | EXACT | Remove unmanaged files in dir |
| `symlink_` | SYMLINK | Create symlink, content = target path |
| `remove_` | REMOVE | Delete target file |
| `modify_` | MODIFY | In-place modification script |

Extensions: `.j2` (template), `.age` (encrypted), `.j2.age` (both, decrypt first).

Prefixes are stackable and case-insensitive: `private_dot_bashrc.j2.age`.

## System Trait Abstraction

`engine/src/system.rs` defines `System` trait for filesystem operations:

```rust
pub trait System {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>>;
    fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<()>;
    fn create_dir(&self, path: &Path) -> Result<()>;
    fn remove_file(&self, path: &Path) -> Result<()>;
    fn remove_dir(&self, path: &Path) -> Result<()>;
    fn symlink(&self, original: &Path, link: &Path) -> Result<()>;
    fn metadata(&self, path: &Path) -> Result<FileMetadata>;
}
```

- `RealSystem` — actual I/O
- `DryRunSystem` — records operations without executing

**Never call `std::fs` directly in engine code.** Always use `System` trait to preserve dry-run support.

## Template Engine

`crates/template/` uses **minijinja** (Jinja2 syntax). Files with `.j2` extension are templates.

Syntax:
- `{{ variable }}` — interpolation
- `{% if %}...{% endif %}` — control flow
- `{{ value | filterName }}` — filters (toJson, fromJson, trim, etc.)
- `{{ funcName(args) }}` — functions (env, hostname, include, bitwarden, etc.)

29 registered callables in `template/src/functions/`. See `template/src/engine.rs` lines 121-185 for registration.

## Testing Patterns

Use project-specific test infrastructure:

| Tool | Location | Purpose |
|------|----------|---------|
| `MockPersistentState` | `engine/src/state.rs` | In-memory DB, no real redb |
| `TempDir` | `tempfile` crate | Auto-cleanup temp dirs |
| `NoOpDecryptor` | `engine/src/content.rs` | Skip encryption in tests |
| `NoOpRenderer` | `engine/src/content.rs` | Skip template rendering in tests |
| `NoOpProcessor` | `engine/src/content.rs` | Type alias for testing |

Pattern:
```rust
#[test]
fn test_something() {
    let temp = TempDir::new().unwrap();
    let db = MockPersistentState::new();
    let system = RealSystem; // or DryRunSystem
    // ... test logic
}
```

## Database Batching

Prefer `save_entry_states_batch()` over individual `save_entry_state()` calls. Batch uses a single redb transaction vs N transactions.

`PersistentState` trait in `engine/src/state.rs` — use this, not `RedbPersistentState` directly.

## Hook System

`engine/src/hooks/` — 6 files, ~3000 lines. Fully implemented.

- Hooks live in `.guisu/hooks/{pre,post}/`
- TOML config or executable scripts
- Three modes: `Always`, `Once`, `OnChange`
- Parallel execution within same `order` group via rayon
- `HookRunner` in `executor.rs`, `Hook` config in `config.rs`
