# Template Crate

minijinja-based template rendering for dotfile processing. Depends on `guisu-core`, `guisu-config`, `guisu-crypto`, `guisu-vault`.

## What lives here

| File | Purpose |
|------|---------|
| `engine.rs` | `minijinja::Environment` setup, global registration, render entry point |
| `context.rs` | Build the template context (variables + functions) for a single file |
| `parser.rs` | Path / filename attribute parsing (`{{ var_name }}` detection, `.j2` suffix handling) |
| `info.rs` | File-info helpers exposed to templates (`file_mode`, `file_mtime`, …) |
| `functions/` | Built-in template functions, **one file per category** (see below) |

## `functions/` layout

Each category gets its own file with one or more `pub fn` definitions, **each with a doctest**:

| File | Category |
|------|----------|
| `strings.rs` | String manipulation (upper, lower, trim, replace, …) |
| `files.rs` | File-system queries (exists, is_file, is_dir, read_file, …) |
| `system.rs` | Host info (hostname, os, arch, env) |
| `data.rs` | Data structures (dict, list, json) |
| `vault.rs` | Vault lookups (`vault('github')`, `vault_field(...)`) — requires `guisu-vault` |
| `crypto.rs` | Encryption / decryption helpers — requires `guisu-crypto` |

## Rules

- **One file per category, one `pub fn` per function, doctest required.** The `add-template-function` skill enforces this; if you find yourself adding a second function to a file, split it.
- **Vault / crypto functions are feature-gated or guarded by provider availability** — never panic on missing backend. Return `Result` and let the caller decide.
- **`secrecy::Secret` values are exposed as opaque** to templates — `vault()` returns `String` after unwrapping, but raw key material must not leak into the template context.
- **Globals are registered in `engine.rs`**, not at call sites. Don't add a function by registering it lazily inside `context.rs`.
- **No `unwrap()`** in render paths — a single bad template shouldn't crash the whole `apply`.

## Adding a new function

1. Pick the category file (or create a new one if the function doesn't fit existing categories).
2. Add `pub fn your_name(...) -> ...` with a `///` doctest showing a worked example.
3. Register the function in `engine.rs` (and any necessary context fields in `context.rs`).
4. Add a row to `docs/src/reference/template-functions.md` — see contributing.md checklist.

Full checklist: `add-template-function` skill.
