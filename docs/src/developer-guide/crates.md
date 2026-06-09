# Crates

Detailed per-crate reference. The seven crates form a strict DAG; see [Architecture](architecture.md) for the diagram. Module paths below are `crates/<name>/src/...`.

## `guisu-core`

Foundation types shared by every other crate. Zero non-`std` dependencies.

| Module | Types |
| --- | --- |
| `path.rs` | `AbsPath`, `RelPath` — newtype wrappers around `PathBuf` that cannot be mixed at compile time. |
| `platform.rs` | `Platform { os, arch }` and the `CURRENT_PLATFORM` constant. |
| `traits.rs` | Shared traits: `AsAbsPath`, `AsRelPath`. |
| `error.rs` | `Error` enum with the variants every crate needs. |

```rust
let p = AbsPath::new("/home/user/.config/guisu")?;
let r = p.join(RelPath::new("dotfiles")?);
```

## `guisu-crypto`

age encryption, file and inline. Built on the `age` crate.

| Module | Public API |
| --- | --- |
| `age.rs` | `decrypt_file_content`, `encrypt_file_content`, `decrypt_inline`, `encrypt_inline`. |
| `identity.rs` | `load_identities(path, is_ssh)` — read age or SSH identity files. |
| `recipient.rs` | `parse_recipient(string)` and `derive_recipients(identities)` — used during encryption. |

Encryption writes to all configured recipients; decryption tries each identity in order until one works.

## `guisu-vault`

Secret provider abstraction over password-manager CLIs.

```rust
pub trait SecretProvider: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn execute(&self, args: &[&str]) -> Result<serde_json::Value>;
    fn help(&self) -> &str;
}
```

| File | Provider |
| --- | --- |
| `bw.rs` | `BwCli` (Bitwarden CLI) and `RbwCli` (unofficial Rust Bitwarden CLI). |
| `bws.rs` | `BwsCli` (Bitwarden Secrets). |

The cache lives in `guisu-template` (per-`apply`), not here.

## `guisu-template`

minijinja environment with a curated function library.

| Module | What it contains |
| --- | --- |
| `engine.rs` | `TemplateEngine::new()` and the two `with_*` constructors. `add_function` / `add_filter` calls register every function. |
| `context.rs` | `TemplateContext` — the typed bag of variables injected into every render. |
| `functions/` | One file per category: `system.rs`, `vault.rs`, `strings.rs`, `data.rs`, `crypto.rs`, `files.rs`. |
| `info.rs` | Helper for `guisu info` to summarise the template engine state. |

```rust
let engine = TemplateEngine::with_identities_and_template_dir(
    identities,
    Some(template_dir),
);
let rendered = engine.render_str(template, &context)?;
```

## `guisu-config`

Loads and merges `.guisu.toml` plus platform-specific variable files.

| Module | What it contains |
| --- | --- |
| `config.rs` | The `Config` struct and sub-configs (`GeneralConfig`, `AgeConfig`, `BitwardenConfig`, `UiConfig`, `IgnoreConfig`, `EditConfig`). |
| `dirs.rs` | `resolve_dirs` — applies `[general] src_dir` / `dst_dir` to the runtime context. |
| `ignores.rs` | `IgnoresConfig` and the loader for per-platform ignore files. |
| `patterns.rs` | `IgnoreMatcher` — gitignore-style pattern compilation. |
| `variables.rs` | Per-platform variable loading (`.guisu/variables/{darwin,linux,windows}/*.toml`). |

```rust
let config = Config::load_from_source(source_dir)?;
let patterns = config.platform_ignore_patterns();
```

## `guisu-engine`

The three-state model and the apply loop. The largest crate by line count.

| Module | What it contains |
| --- | --- |
| `state.rs` | `SourceState`, `TargetState`, `DestinationState`, `PersistentState` trait + `RedbPersistentState`, `EntryState`, `HookState`. |
| `entry.rs` | `SourceEntry`, `TargetEntry`, `DestEntry`, `EntryKind`. |
| `attr.rs` | `FileAttributes` (plain struct: `is_template`, `is_encrypted`, `mode`). |
| `content.rs` | The raw byte pipeline. |
| `processor.rs` | `ContentProcessor<D, R>` — generic decrypt + render pipeline. |
| `database.rs` | redb table definitions. |
| `hash.rs` | BLAKE3 helpers. |
| `system.rs` | Platform-specific destination state reads. |
| `validator.rs` | Cross-state validation. |
| `git.rs` | In-process git operations (init, fetch, merge) using `git2`. |
| `hooks/` | Pre/post/once/onchange hook discovery and execution. |
| `adapters/` | Alternative implementations (e.g. for tests). |

## `guisu-cli`

Binary + library. The binary entry point is `src/main.rs`, which delegates to `guisu::run(cli)`.

| Module | What it contains |
| --- | --- |
| `lib.rs` | `Cli` (clap derive) and `Commands` enum. |
| `cmd/` | One file per subcommand: `add.rs`, `age.rs`, `apply.rs`, `cat.rs`, `diff.rs`, `edit.rs`, `hooks.rs`, `ignored.rs`, `info.rs`, `init.rs`, `status.rs`, `templates.rs`, `update.rs`, `variables.rs`. |
| `command.rs` | The `Command` trait implemented by every subcommand. |
| `common.rs` | `RuntimeContext` — shared state (config, paths, etc.) passed to every command. |
| `conflict.rs` | The interactive conflict TUI. |
| `ui/` | Reusable TUI widgets. |
| `stats.rs` | `ApplyStats` — counted output of an apply. |

```rust
impl Command for ApplyCommand {
    type Output = ApplyStats;
    fn execute(&self, ctx: &RuntimeContext) -> Result<ApplyStats> { ... }
}
```

## Public surface stability

The `guisu-cli` binary's command-line interface is stable. The library crates (`guisu-core`, `guisu-crypto`, `guisu-vault`, `guisu-template`, `guisu-config`, `guisu-engine`) are not yet API-stable; expect breaking changes before v1.0. See the [Roadmap](../roadmap.md) for the stabilisation timeline.

## See also

- [Architecture](architecture.md) — layer diagram.
- [Three-State Model](three-state-model.md) — the engine's core types.
