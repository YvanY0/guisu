# Core Crate (Layer 0)

Foundation crate — every other guisu crate depends on this. Has no internal dependencies.

## What lives here

| File | Purpose |
|------|---------|
| `path.rs` | `AbsPath`, `RelPath`, `SourceRelPath` newtype wrappers |
| `error.rs` | `Error` / `Result` base types (`thiserror`; `anyhow` behind feature flag) |
| `platform.rs` | Platform detection helpers |
| `traits.rs` | `ConfigProvider`, `EncryptionProvider`, `TemplateRenderer`, `VaultProvider` — behavioural contracts |

## Rules

- **Do not add dependencies on other `guisu-*` crates** — this is the foundation layer. Anything you need here must be implementable in terms of external crates only.
- Use `thiserror` for `Error` variants. The `anyhow` feature flag exists for downstream CLI convenience — don't use `anyhow` types in this crate's public API.
- Path newtypes go here, not in higher crates. Don't re-wrap `PathBuf` downstream; add a variant to `path.rs` instead.
- Trait definitions belong in `traits.rs`. Keep them small and consumer-facing — implementation details go in the relevant crate.
