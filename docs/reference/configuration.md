# Configuration Reference

The full schema of `.guisu.toml`. Every key is optional; Guisu applies a default if a key is missing. The file is rendered as a Jinja template if its name is `.guisu.toml.j2`.

> [!NOTE]
> **Keys are camelCase**
> All config keys use camelCase (e.g. `srcDir`, `failOnDecryptError`). Snake_case keys are **not** accepted. This page is derived from `crates/config/src/config.rs` and `crates/config/src/ignores.rs` — the source is authoritative; if a key is added or removed, the source wins.



## `[general]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `srcDir` | path | `~/.local/share/guisu` | Source repository location. |
| `dstDir` | path | `~` | Destination root. |
| `rootEntry` | path | `home` | Every target path is relative to this subpath of the source dir. |
| `color` | bool | `true` | ANSI colour in output. |
| `progress` | bool | `true` | Progress bars. |
| `editor` | string | `$EDITOR` | Editor used by `guisu edit`. |
| `editorArgs` | list of string | `[]` | Extra args passed to the editor. |
| `useBuiltinAge` | enum | `auto` | `auto` / `true` / `false`. Use the in-process age implementation. |
| `useBuiltinGit` | enum | `auto` | `auto` / `true` / `false`. Use the in-process git implementation. |

## `[age]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `identity` | path | — | Single age or SSH identity file. |
| `identities` | list of path (nullable) | `null` | Multiple identity files; any one can decrypt. |
| `recipient` | string | — | Single age recipient. |
| `recipients` | list of string | `[]` | Multiple recipients; encryption writes to all. |
| `derive` | bool | `false` | Derive a recipient from the identity for encryption. Alias: `symmetric`. |
| `failOnDecryptError` | bool | `true` | Fail `apply` if a `.age` file cannot be decrypted. `false` logs a warning and continues with encrypted content. |

## `[bitwarden]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `provider` | string | `"bw"` | One of `bw`, `rbw`, `bws`. |

## `[ui]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `icons` | enum | `auto` | `auto` / `always` / `never`. How `status` and `diff` mark file types. |
| `diffFormat` | string | `"unified"` | One of `unified`, `split`, `inline`. Used by `diff` and the conflict TUI. |
| `contextLines` | integer | `3` | Lines of context around a change in diff output. |
| `previewLines` | integer | `10` | Lines of preview in the conflict TUI. |

## `[edit]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `apply` | bool | `false` | Whether `guisu edit` should apply after a successful save. Set `true` (or pass `--apply`) to auto-apply. |

## `[ignore]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `global` | list of string | `[]` | Always ignored, regardless of platform. |
| `darwin` | list of string | `[]` | macOS-only ignores. |
| `linux` | list of string | `[]` | Linux-only ignores. |
| `windows` | list of string | `[]` | Windows-only ignores. |

Patterns are gitignore-style: glob with `*`, `?`, `**`, negation with `!`, and trailing `/` for directory-only. Ignore patterns also live in `.guisu/ignores.toml` (same four arrays) and are merged with the `[ignore]` table.

## `[variables]`

Free-form key/value map. Every key is exposed as a top-level variable in the template context. See [User Guide — Templates](../user-guide/templates.md).

```toml
[variables]
email = "user@example.com"
editor = "nvim"
work = true
servers = ["srv1", "srv2", "srv3"]
```

## Resolving the effective config

Precedence, highest first:

1. Command-line flags (`--source`, `--dest`, `--config`, `--log-file`).
2. Environment variables (`GUISU_SOURCE_DIR`, `GUISU_DEST_DIR`, `GUISU_CONFIG`, `GUISU_LOG_FILE`).
3. `.guisu.toml` in the source directory (rendered as a template if `.guisu.toml.j2`).
4. Per-platform variables from `.guisu/variables/` and ignores from `.guisu/ignores.toml`.
5. Defaults (compiled in).

Run `guisu info --all` to see the merged result.

## See also

- [User Guide — Configuration](../user-guide/config.md) for a curated overview and a templated-config example.
