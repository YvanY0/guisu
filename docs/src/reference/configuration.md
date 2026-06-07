# Configuration Reference

The full schema of `.guisu.toml`. Every key is optional; Guisu applies a default if a key is missing. The file is rendered as a Jinja template if its name is `.guisu.toml.j2`.

> [!NOTE]
> **Derived from source**
> This page is derived from `crates/config/src/config.rs` and `crates/config/src/ignores.rs`. The authoritative list is the source — if a key is added or removed, the source wins.



## `[general]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `src_dir` | path | `~/.local/share/guisu` | Source repository location. |
| `dst_dir` | path | `~` | Destination root. |
| `root_entry` | path | (resolved at runtime) | Every target path is relative to this subpath. |
| `color` | bool | `true` | ANSI colour in output. |
| `progress` | bool | `true` | Progress bars. |
| `editor` | string | `$EDITOR` | Editor used by `guisu edit`. |
| `editor_args` | list of string | `[]` | Extra args passed to the editor. |
| `use_builtin_age` | enum | `auto` | `auto` / `true` / `false`. Use the in-process age implementation. |
| `use_builtin_git` | enum | `auto` | `auto` / `true` / `false`. Use the in-process git implementation. |

## `[age]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `identity` | path | — | Single age or SSH identity file. |
| `identities` | list of path | `[]` | Multiple identity files; any one can decrypt. |
| `recipient` | string | — | Single age recipient. |
| `recipients` | list of string | `[]` | Multiple recipients; encryption writes to all. |
| `derive` | bool | `false` | Derive a recipient from the SSH identity for encryption. |
| `fail_on_decrypt_error` | bool | `false` | Fail `apply` if a `.age` file cannot be decrypted. The default is to log a warning and skip. |

## `[bitwarden]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `provider` | string | `"rbw"` | One of `bw`, `rbw`, `bws`. |

## `[ui]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `icons` | enum | `auto` | `auto` / `text` / `symbols`. How `status` and `diff` mark file types. |
| `diff_format` | string | `"unified"` | One of `unified`, `side-by-side`. Used by the conflict TUI. |
| `context_lines` | integer | `3` | Lines of context around a change in `diff` output. |
| `preview_lines` | integer | `10` | Lines of preview in the conflict TUI. |

## `[edit]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `apply` | bool | `true` | Whether `guisu edit` should apply after a successful save. Set to `false` for read-only editing of templates. |

## `[ignore]`

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `global` | list of string | `[]` | Always ignored, regardless of platform. |
| `darwin` | list of string | `[]` | macOS-only ignores. |
| `linux` | list of string | `[]` | Linux-only ignores. |
| `windows` | list of string | `[]` | Windows-only ignores. |

Patterns are gitignore-style: glob with `*`, `?`, `**`, negation with `!`, and trailing `/` for directory-only.

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

1. Defaults (compiled in).
2. `.guisu.toml` in the source directory (rendered as template if `.guisu.toml.j2`).
3. Per-platform files in `.guisu/ignores/{darwin,linux,windows}.toml` (only for `[ignore]`).
4. Environment variables (`GUISU_SOURCE_DIR`, `GUISU_DEST_DIR`, `GUISU_CONFIG`, `GUISU_LOG_FILE`).
5. Command-line flags.

Run `guisu info --all` to see the merged result.

## See also

- [User Guide — Configuration](../user-guide/config.md) for a curated overview and a templated-config example.
