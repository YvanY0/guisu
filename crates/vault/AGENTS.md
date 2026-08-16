# Vault Crate

Password-manager integrations. Depends on `guisu-core`. Each provider is a separate `pub mod` gated by a Cargo feature.

## What lives here

| File / Module | Feature | Purpose |
|------|---------|---------|
| `lib.rs` | — | `SecretProvider` trait + provider registry |
| `bw.rs` | `bw` | Bitwarden CLI (`bw`) — personal / team passwords |
| `bws.rs` | `bws` | Bitwarden Secrets Manager (`bws`) — organisation secrets |
| *(future)* `onepassword` | `onepassword` | Reserved (see commented stub in `lib.rs`) |

## Rules

- **Each provider implements `SecretProvider`** (defined in `lib.rs`). Don't add a new backend without going through that trait.
- **One feature flag per provider.** Default features include `bw` and `bws`. A provider module is `#[cfg(feature = "<name>")]`-gated; the feature must be declared in `Cargo.toml` even if empty (e.g. `bw = []`).
- **Provider CLI commands run via `std::process::Command`** — return parsed `serde_json::Value`, not raw stdout. Surface non-zero exit codes as `Error`.
- **Don't add async dependencies yet.** A comment in `Cargo.toml` marks `bw-sdk` as a future feature needing `tokio`; the current CLI-based providers stay sync.
- Adding a new provider is more than one file — see [Adding a new provider](#adding-a-new-provider) below.

## Module visibility

- All provider modules are `pub` (so consumers can construct them directly when the feature is enabled).
- Re-export `guisu_core::Error` / `Result` — don't define local error aliases.

## Adding a new provider

1. Implement the `SecretProvider` trait in a new `crates/vault/src/<provider>.rs` (model it on `bw.rs`).
2. Declare a feature in `crates/vault/Cargo.toml` (e.g. `<provider> = []`) and gate the module with `#[cfg(feature = "<provider>")]` in `lib.rs`.
3. Expose template functions in `crates/template/src/functions/vault.rs` behind the same feature, and register them in `crates/template/src/engine.rs`.
4. Add tests for CLI parsing, `is_available`, and non-zero exit handling.
