# Getting Started — `init`

`guisu init` is the entry point: it obtains a source repository (by cloning from GitHub or by initialising one locally) and, by default, runs an apply to materialise your dotfiles.

## Clone an existing GitHub repository

```bash
guisu init username                       # shorthand for github.com/username/dotfiles
guisu init https://github.com/username/dotfiles.git
guisu init --ssh username                 # use SSH instead of HTTPS
guisu init --depth 1 username             # shallow clone (faster, no history)
guisu init --apply username              # clone and apply in one step
```

`guisu init` clones into the source directory (default `~/.local/share/guisu`). It does **not** apply automatically — pass `--apply` to materialise the files in the same step, or run `guisu apply` afterward. Use `guisu apply --interactive` to review each change before it lands in your home directory.

By default the source dir is resolved as `--source` → `GUISU_SOURCE_DIR` → `[general] srcDir` in `.guisu.toml` → `~/.local/share/guisu` (the XDG data dir). Choose your path before running `init`:

- **Use the default** (`~/.local/share/guisu`) — nothing to configure, `guisu init username` and later `guisu apply` "just work".
- **Use a custom path** (e.g. `~/dotfiles`) — see the next section.

## Initialise a brand-new local repository at a custom path

```bash
mkdir ~/dotfiles && cd ~/dotfiles
git init
cd ..
guisu init ~/dotfiles
```

`init` creates the directory if needed. When you pass an explicit path, `init` prints a hint pointing subsequent `guisu apply` (no args) at this location — since `apply` defaults to `~/.local/share/guisu`, you must either pass `--source` each time or set `GUISU_SOURCE_DIR` once in your shell profile:

```bash
echo 'export GUISU_SOURCE_DIR=~/dotfiles' >> ~/.zshrc
```

`guisu init` does not write a `.guisu.toml` for you — commit your files first, then `guisu add` to start tracking them.

> [!NOTE]
> **Where does the source go?**
> By default, Guisu uses `~/.local/share/guisu` as the source directory — the same convention as chezmoi. Override per-call with `--source`, per-session with `GUISU_SOURCE_DIR`, or persistently in the repo's `.guisu.toml` under `[general] srcDir`. Config stays repo-managed by design; the env var is the per-machine, repo-external override.



## Where things go

| Path | Default | Override |
| --- | --- | --- |
| Source directory | `~/.local/share/guisu` | `--source` / `[general] srcDir` |
| Destination directory | `$HOME` | `--dest` / `[general] dstDir` |
| Persistent state DB | `${XDG_STATE_HOME:-~/.local/state}/guisu/state.db` | (not configurable) |
| Editor (for `guisu edit`) | `$EDITOR` or `[general] editor` | env var or config |

## What `init` does not do

`init` does not commit any uncommitted changes. After cloning, the source repo is exactly as the remote left it; if you later `guisu add` a file, that change is staged in git but not committed.

## Next step

[Getting Started — add](add.md).
