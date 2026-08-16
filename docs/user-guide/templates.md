# Templates

Guisu renders `.j2` files with [minijinja](https://docs.rs/minijinja), which implements the Jinja2 template language. Templates are evaluated **after** any `.age` decryption, so an encrypted template (`.j2.age`) is decrypted first and then rendered.

## Variables available in templates

The template context is composed from four sources:

| Source | Keys |
| --- | --- |
| **System** | `system.os`, `system.arch`, `system.hostname`, `system.username`, `system.homeDir`, … (the `os()` / `arch()` / `hostname()` / `username()` / `home_dir()` functions return the same values without the `system.` prefix) |
| **Environment** | (read with the `env` function: `env("HOME")`) |
| **Guisu** | `guisu.srcDir`, `guisu.workingTree`, `guisu.dstDir`, `guisu.rootEntry`, `guisu.config` |
| **User** | every key from `.guisu.toml` `[variables]` and from `.guisu/variables/*.toml` and platform-specific subdirectories |

## Example

```jinja
# ~/.bashrc — rendered on {{ os() }} ({{ arch() }})
{% if os() == "darwin" %}
export HOMEBREW_PREFIX="/opt/homebrew"
{% elif os() == "linux" %}
export HOMEBREW_PREFIX="/home/linuxbrew/.linuxbrew"
{% endif %}

export EDITOR="{{ editor }}"
export EMAIL="{{ email }}"
```

`os()` and `system.os` return the same value (`"darwin"` on macOS).

## Built-in template functions

The full list is in [Reference — Template Functions](../reference/template-functions.md). The most-used ones:

| Function | Purpose |
| --- | --- |
| `env("NAME")` | Read an environment variable (empty string if unset). |
| `os()`, `arch()`, `hostname()`, `username()`, `home_dir()` | System info. |
| `lookPath("cmd")` | Absolute path of `cmd` on `$PATH`, or empty. |
| `bitwarden("Item")` | Fetch a Bitwarden item as an object. |
| `bitwardenFields("Item", "Field")` | Fetch a specific field. |
| `include("name")` | Include the **raw** content of another template file. |
| `includeTemplate("name")` | Include and render a template file. |
| `regexMatch(string, pattern)` | Test whether a regex matches. |
| `split(string, sep)` / `join(list, sep)` | Split / join strings. |
| `decrypt(value)` *(filter)* | Decrypt an inline `age:base64,...` string. Used as `{{ 'value' | decrypt }}`. |
| `encrypt(value)` *(filter)* | Encrypt a value for the configured recipients. |
| `joinPath(parts...)` | Join path components portably. |

> [!TIP]
> **Cache expensive lookups**
> Vault calls (`bitwarden`, etc.) shell out to an external process. The vault layer caches the response for the lifetime of the process — since one `apply` is one process, repeated lookups in the same template are cheap and the cache is dropped when the run ends. Cross-`apply` caching is not implemented.



## Platform-specific variables

Variables can be split across multiple files under `.guisu/variables/`:

```text
.guisu/variables/
├── user.toml              # global
├── visual.toml            # global
├── darwin/
│   ├── git.toml
│   └── terminal.toml
└── linux/
    ├── git.toml
    └── terminal.toml
```

Loading order:

1. Global files (any `*.toml` directly in `.guisu/variables/`).
2. Platform-specific files from `<os>/`.

Each file is wrapped by its **stem**: `variables/git.toml` produces a `"git"`
key whose value is the whole file's contents, so a template reads
`{{ git.branch }}` for `[branch] name = ...`. A platform-specific
`variables/darwin/git.toml` is **deep-merged** into the same `"git"` key —
individual fields override, the rest of the object is preserved — so you can
override one key per platform without re-listing the others. Config `[variables]`
keys are flat (not wrapped) and override file variables of the same name.

## Templated configuration

A `.guisu.toml.j2` is itself rendered with the same context before being parsed. This lets you vary configuration per machine without committing a per-machine file. Note: the config crate does not depend on the template crate — the CLI layer renders `.guisu.toml.j2` and caches the result (keyed by template hash) in the state DB to avoid re-rendering on every run.

## See also

- [Reference — Template Functions](../reference/template-functions.md)
- [Configuration](config.md) for the full `.guisu.toml` schema.
- [Vault](vault.md) for password-manager integration.
