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

## Initialise a brand-new local repository

```bash
mkdir ~/dotfiles && cd ~/dotfiles
git init
cd ..
guisu init
```

This creates a new directory, initialises git inside it, and writes a starter `.guisu.toml`. The next `guisu add` knows where to put files.

> [!NOTE]
> **Where does the source go?**
> By default, Guisu uses `~/.local/share/guisu` as the source directory — the same convention as chezmoi. Override per-call with `--source` or globally in `.guisu.toml` under `[general] srcDir`.



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
