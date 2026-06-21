# Config Crate

TOML configuration parsing. Depends on `guisu-core` and `guisu-crypto` (for encrypted config values).

## What lives here

| File | Purpose |
|------|---------|
| `config.rs` | Top-level config struct + deserialisation entry points |
| `dirs.rs` | XDG / platform-specific directory resolution |
| `ignores.rs` | `.guisuignore` parsing — file pattern matching against source paths |
| `patterns.rs` | Path-pattern matching primitives (used by `ignores` and template functions) |
| `variables.rs` | User-defined variable substitution (`[variables]` section) |

## Rules

- **Config schema is the public contract.** Changing a field name, type, or default is a breaking change — coordinate with `developer-guide/contributing.md` "Documentation" checklist.
- **TOML deserialisation is permissive** — unknown fields should warn (via `tracing`) rather than error, so users can keep older configs working. Use `serde`'s `default` attribute generously.
- **Encrypted values are `secrecy::Secret<String>`** — never `String` in the public API for sensitive fields. Decryption happens here, not in callers.
- **Pattern matching** uses the `ignore` crate's glob semantics, not custom regex. Don't roll a new pattern parser.
- Resolution order: CLI flags → env vars → config file → defaults. Implement at the top level (`config.rs`), not scattered across submodules.

## Module visibility

Internal helpers stay `pub(crate)`. Re-export `guisu_core::Error` / `Result`.
