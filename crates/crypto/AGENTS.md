# Crypto Crate

age encryption support. Depends on `guisu-core`.

## What lives here

| File | Purpose |
|------|---------|
| `age.rs` | age encrypt / decrypt operations |
| `identity.rs` | age identity (private key) loading and parsing |
| `recipient.rs` | age recipient (public key) handling |

## Rules

- **Wrap `secrecy` types** when exposing key material — never return raw key bytes from the public API.
- Use `thiserror` for `Error` variants (re-exported through `guisu_core::Error`).
- Identity files are sensitive — never log them. Use `tracing` with explicit field redaction if you must log identity metadata.
- This crate is consumed by `guisu-config` and `guisu-template`. Don't reach back into those crates — dependency direction is one-way.
