# Hooks

Hooks are scripts that run before or after an `apply`. They live under `.guisu/hooks/` in the source repository, version-controlled alongside your dotfiles.

## Layout

Hooks are discovered in **flat** `pre/` and `post/` directories. Each entry is
either an executable script (run directly) or a `.toml` hook definition that
points at a `cmd` or `script`:

```text
.guisu/hooks/
├── pre/
│   ├── 01-setup.sh          # executable script
│   └── 02-install.toml      # hook definition (mode, platforms, script)
└── post/
    ├── 01-cleanup.sh
    └── 99-notify.toml
```

- `pre/` runs **before** the apply begins.
- `post/` runs **after** the apply completes successfully.
- Files are sorted by filename, so numeric prefixes (`01-`, `02-`, …) control
  order; ties break lexicographically. Each file's position also seeds its
  default `order` value (0, 10, 20, …).
- Hidden files (`.*`) and editor backups (`*~`, `*.swp`) are skipped.

There is **no** `always/` / `once/` / `onchange/` subdirectory tree, and **no**
platform subdirectories — both are TOML fields on a hook definition, see below.

## Script vs TOML hook

A hook is one of:

- An **executable script** placed directly in `pre/` or `post/` (filename becomes the hook name; mode defaults to `always`).
- A **TOML file** defining one or more hooks. A single hook:

  ```toml
  name = "install-packages"
  cmd = "brew bundle --file ~/.Brewfile"
  mode = "once"
  platforms = ["darwin"]
  ```

  Or an array of hooks (`[[pre]]` / `[[post]]` tables in one file). Use `cmd`
  for an inline command, or `script = "install.sh"` to run a script file
  (resolved relative to the hook file; a `script.sh.j2` next to it is
  auto-detected and rendered as a template).

A hook must have exactly one of `cmd` or `script`.

## Execution mode

`mode` controls when a hook re-runs:

| Mode | Behaviour |
| --- | --- |
| `always` | Run every time (default). |
| `once` | Run at most once ever, tracked by name in the persistent state DB. |
| `onchange` | Run when the rendered content's blake3 hash has changed since the last run. |

Mode is recorded in the state DB (`state.db`), not in `.guisu/state.toml`.

## Script interpreter

The script interpreter is auto-detected from the shebang line. `#!/bin/bash`, `#!/usr/bin/env python3`, `#!/usr/bin/env nix-shell`, etc. all work. A bare executable script with no shebang is executed as-is; a non-executable, non-`cmd` file is skipped with a warning.

## Template rendering

Hook scripts ending in `.j2` (and `cmd` strings are always rendered) are rendered as templates before execution. `{{ os() }}`, `{{ guisu.srcDir }}`, `{{ guisu.workingTree }}`, `{{ guisu.dstDir }}`, etc. are available. Branch on platform inside a single hook file:

```bash
#!/bin/bash
{% if os() == "darwin" %}
brew update
{% elif os() == "linux" %}
sudo apt-get update
{% endif %}
```

## Platform filtering

Scope a hook to platforms with the `platforms` TOML field (a list). Empty means
all platforms. Valid values: `darwin`, `linux`, `windows`.

```toml
name = "install-brew"
cmd = "brew bundle"
platforms = ["darwin"]
```

There are no platform subdirectories to create — the filter is the field.

## Other hook fields

| Field | Default | Notes |
| --- | --- | --- |
| `order` | derived from filename position | Lower runs first. Override explicitly in TOML. |
| `env` | `{}` | Environment variables set for the hook (table of `KEY = "value"`). |
| `failfast` | `true` | Stop the whole hook phase when this hook fails. |
| `timeout` | `0` | Seconds before the hook is killed. `0` = no timeout. |

## Environment variables

When a hook runs, the following are set in addition to its `[env]` table and the parent shell's environment:

| Variable | Value |
| --- | --- |
| `GUISU_SOURCE` | Absolute path to the source repo. |
| `HOME` | The current user's home directory. |

Phase (`pre`/`post`) and mode (`always`/`once`/`onchange`) are configuration,
not exposed to scripts as environment variables.

## See also

- [Reference — Commands](../reference/commands.md#guisu-hooks) for `guisu hooks run/list/show`.
- [Three-State Model](../developer-guide/three-state-model.md) for where hook state is recorded.
