# Configuration

Guisu reads `.guisu.toml` from the source directory. The file can itself be a template (`.guisu.toml.j2`), which lets you vary config per machine without committing per-machine files.

> [!NOTE]
> **Keys are camelCase**
> All config keys use camelCase (`srcDir`, `failOnDecryptError`, …). Snake_case keys are rejected. See [Reference — Configuration](../reference/configuration.md) for the full schema.

## Quick start

```toml
[general]
color = true
progress = true
editor = "nvim"

[age]
identity = "~/.local/share/guisu/key.txt"
derive = true

[bitwarden]
provider = "bw"

[variables]
email = "user@example.com"
editor = "nvim"

[ignore]
global = [".git", ".DS_Store"]
darwin = ["Thumbs.db"]
linux = ["*~"]
```

## Sections

| Section | Purpose |
| --- | --- |
| `[general]` | Top-level behaviour: paths, output, editor. |
| `[age]` | Encryption identity and recipients. |
| `[edit]` | `guisu edit` defaults (e.g. auto-apply). |
| `[bitwarden]` | Password-manager provider selection. |
| `[ui]` | Icons, diff format, context/preview line counts. |
| `[ignore]` | Files to skip, with per-platform variants. |
| `[variables]` | Free-form key/value map exposed as template variables. |

Hooks are **not** configured here — they live under `.guisu/hooks/` as scripts
and TOML hook files. See [Hooks](hooks.md).

The full schema with type, default, and notes per key is in [Reference — Configuration](../reference/configuration.md).

## Templated configuration

A `.guisu.toml.j2` is rendered with the same context as a regular template. Use this for per-machine values:

```jinja
[general]
editor = "{{ env("EDITOR") | default(value="nvim") }}"

[variables]
hostname = "{{ hostname }}"
```

The file is rendered before being parsed, so the resulting TOML is what the rest of the system sees. The config crate itself does not render templates — the CLI layer renders `.guisu.toml.j2` and caches the result (keyed by template hash) in the state DB.

> [!NOTE]
> **Config file is rendered with the same context as templates**
> `hostname`, `os()`, `arch()`, env vars, and user variables are all available in `.guisu.toml.j2`. This means a config file can be both a config and a small template at the same time.



## Validation

`guisu info` prints the resolved configuration. Use it to debug:

```bash
guisu info --all
```

`guisu info` prints the resolved configuration, the version, public keys, and a validation summary. Use `--json` for machine-readable output. There is no separate `guisu config get` / `guisu config set` subcommand — edit `.guisu.toml` directly.

## See also

- [Reference — Configuration](../reference/configuration.md) — every key with type and default.
- [Templates](templates.md) — variables and templated config.
- [Encryption](encryption.md) — the `[age]` section.
