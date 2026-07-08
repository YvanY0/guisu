# Templates

Guisu renders `.j2` files with [minijinja](https://docs.rs/minijinja), which implements the Jinja2 template language. Templates are evaluated **after** any `.age` decryption, so an encrypted template (`.j2.age`) is decrypted first and then rendered.

## Variables available in templates

The template context is composed from four sources:

| Source | Keys |
| --- | --- |
| **System** | `os`, `arch`, `hostname`, `username`, `home_dir` |
| **Environment** | (read with the `env` function: `env("HOME")`) |
| **Guisu** | `source_dir`, `working_tree`, `dest_dir`, `config` |
| **User** | every key from `.guisu.toml` `[variables]` and from `.guisu/variables/*.toml` and platform-specific subdirectories |

## Example

```jinja
# ~/.bashrc — rendered on {{ os }} ({{ arch }})
{% if os == "darwin" %}
export HOMEBREW_PREFIX="/opt/homebrew"
{% elif os == "linux" %}
export HOMEBREW_PREFIX="/home/linuxbrew/.linuxbrew"
{% endif %}

export EDITOR="{{ editor }}"
export EMAIL="{{ email }}"
```

## Built-in template functions

The full list is in [Reference — Template Functions](../reference/template-functions.md). The most-used ones:

| Function | Purpose |
| --- | --- |
| `env("NAME")` | Read an environment variable (empty string if unset). |
| `lookPath("cmd")` | Absolute path of `cmd` on `$PATH`, or empty. |
| `bitwarden("Item")` | Fetch a Bitwarden item as an object. |
| `bitwardenFields("Item", "Field")` | Fetch a specific field. |
| `include("name")` | Include the **raw** content of another template file. |
| `includeTemplate("name")` | Include and render a template file. |
| `decrypt(value)` *(filter)* | Decrypt an inline `age:base64,...` string. Used as `{{ 'value' | decrypt }}`. |
| `encrypt(value)` *(filter)* | Encrypt a value for the configured recipients. |
| `joinPath(parts...)` | Join path components portably. |

> [!TIP]
> **Cache expensive lookups**
> Vault calls (`bitwarden`, `pass`, etc.) shell out to an external process. The vault layer caches the response for the duration of a single `apply` so repeated lookups in the same template are cheap. Cross-`apply` caching is not implemented — every `apply` re-fetches.



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

The merge is **per section**: a platform-specific `[git]` table is merged into the global `[git]` table, key by key, rather than overwriting the whole table. This means you can override one key in `darwin/git.toml` without re-listing the others.

## Templated configuration

A `.guisu.toml.j2` is itself rendered with the same context before being parsed. This lets you vary configuration per machine without committing a per-machine file.

## See also

- [Reference — Template Functions](../reference/template-functions.md)
- [Configuration](config.md) for the full `.guisu.toml` schema.
- [Vault](vault.md) for password-manager integration.
