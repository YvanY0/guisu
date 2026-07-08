# Getting Started — `add`

`guisu add` copies a file or directory from your destination into the source repository. It strips the `$HOME` prefix and preserves the rest of the path verbatim.

## Basic usage

```bash
guisu add ~/.bashrc                       # copy ~/.bashrc → source as .bashrc
guisu add ~/.config/nvim                 # copy a directory recursively
guisu add --encrypt ~/.ssh/id_rsa         # add as age-encrypted .age file
guisu add --template ~/.gitconfig         # add as a template (.j2)
guisu add ~/.config/nvim/init.vim         # add a single file inside a directory
guisu add --no-git ~/.zshrc                # add but do not run `git add`
```

`add` runs `git add` on the resulting source path by default. Pass `--no-git` to skip that step.

## Re-adding an existing source file

```bash
guisu add --force ~/.bashrc
```

`--force` overwrites the source file with the destination's current content. The `--encrypt` and `--template` flags compose with `--force` to re-add with the same attributes.

> [!WARNING]
> **--force overwrites silently**
> `--force` does not prompt. If you have local changes in the source repo (template edits, secret rotations), they are lost. Use `guisu diff` first to see what would change.



## Common flags

| Flag | Effect |
| --- | --- |
| `--encrypt` | Store the file as `<name>.age` in the source. |
| `--template` | Store the file as `<name>.j2` for Jinja rendering. |
| `--private` | Force mode `0600` on apply. |
| `--executable` | Force mode `0755` on apply. |
| `--exact` | Preserve the source filename as-is (no attribute inference). |
| `--force` | Overwrite the existing source entry. |
| `--no-git` | Skip the `git add` step. |

## Transformations you can expect

| Input | Source file | On apply |
| --- | --- | --- |
| `~/.bashrc` | `.bashrc` | `~/.bashrc` (verbatim) |
| `~/.ssh/config` | `.ssh/config` | `~/.ssh/config` (verbatim) |
| `~/.ssh/id_rsa` + `--encrypt` | `.ssh/id_rsa.age` | `~/.ssh/id_rsa` (decrypted, mode `0600`) |
| `~/.config/nvim/init.vim` + `--template` | `.config/nvim/init.vim.j2` | `~/.config/nvim/init.vim` (rendered) |

## Next step

[Getting Started — apply](apply.md).
