# Hooks

Hooks are scripts that run before, after, or on change of an `apply`. They live under `.guisu/hooks/` in the source repository, and they are version-controlled alongside your dotfiles.

## Layout

```text
.guisu/hooks/
├── pre/
│   ├── always/
│   ├── once/
│   └── onchange/
└── post/
    ├── always/
    ├── once/
    └── onchange/
```

- `pre/` runs **before** the apply begins.
- `post/` runs **after** the apply completes successfully.
- `always/` runs every time.
- `once/` runs at most once per script (recorded in the persistent state).
- `onchange/` runs when the script's blake3 hash has changed since the last run.

## Filename ordering

`pre/always/10-install-packages.sh` runs before `pre/always/20-configure-shell.sh`. Number prefixes control order; ties break by filename (lexicographic).

## Script interpreter

The script interpreter is auto-detected from the shebang line. `#!/bin/bash`, `#!/usr/bin/env python3`, `#!/usr/bin/env nix-shell`, etc. all work. If there is no shebang and the file is not executable, the script fails.

## Template rendering

Hook commands are rendered as templates before execution. `{{ os }}`, `{{ guisu.source_dir }}`, `{{ guisu.working_tree }}`, etc. are available. This is how you can branch on platform inside a single hook file:

```bash
#!/bin/bash
{% if os == "darwin" %}
brew update
{% elif os == "linux" %}
sudo apt-get update
{% endif %}
```

## Platform filtering

You can place hooks under a platform subdirectory to scope them:

```text
.guisu/hooks/pre/always/darwin/10-install-brew.sh
.guisu/hooks/pre/always/linux/10-install-apt.sh
```

Only the directory matching the current platform is executed. The hook in the unfiltered `pre/always/` directory runs on every platform.

## Environment variables

When a hook is invoked, the following variables are set:

| Variable | Value |
| --- | --- |
| `GUISU_SOURCE` | Absolute path to the source repo |
| `HOME` | The current user's home directory |

Hook scripts also inherit the parent shell's environment. Hook phase (`pre`/`post`) and mode (`always`/`once`/`onchange`) are configuration, not exposed to scripts as environment variables.

## See also

- [Reference — Configuration](../reference/configuration.md) for the hooks section.
