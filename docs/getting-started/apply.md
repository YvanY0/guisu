# Getting Started — `apply`

`guisu apply` materialises the source state into the destination directory, applying templates, decrypting, and respecting conflict rules. It is the command you will run most often — usually via `guisu update` which is `git pull` + `apply`.

## Basic usage

```bash
guisu apply                 # apply everything
guisu apply --dry-run       # show what would change, do not write
guisu apply --interactive   # prompt for conflicts in a TUI
guisu apply --force         # overwrite destination without asking
guisu apply path1 path2     # apply only specific paths
```

## How status is determined

For each file, Guisu compares three sources of truth:

1. **Target** — the rendered, decrypted content the source state wants.
2. **Destination** — the file currently on disk.
3. **Database** — the content hash stored the last time `apply` succeeded (in `${XDG_STATE_HOME:-~/.local/state}/guisu/state.db`).

The result is one of `Steady`, `Latent`, `Behind`, `Ahead`, or `Conflict`.

| Status | Meaning | Default action |
| --- | --- | --- |
| `Steady` | Target, destination, and last-applied hash all agree. | Skip. |
| `Latent` | Destination missing — pending deployment. | Create. |
| `Behind` | Source moved ahead of the last-applied state. | Apply. |
| `Ahead` | Destination moved ahead (local edits). | Overwrite (or prompt). |
| `Conflict` | Both source and destination moved since the last apply. | Prompt (`--interactive`) or overwrite. |

## Interactive mode

`--interactive` opens a TUI for every conflict, showing a side-by-side diff and four actions: **Overwrite**, **Skip**, **View Diff**, **Quit**.

```bash
guisu apply --interactive
```

> [!TIP]
> **Pipe-friendly output**
> `guisu apply --dry-run` prints a list of planned changes. Combine with `guisu info` for a complete preview before a real apply.

> [!NOTE]
> **Output order**
> Files are written sequentially in path-sorted order (e.g. `.zshrc` before `.config/zsh/conf.d/00_utils.zsh`). The order is deterministic across runs and matches what `guisu diff` shows. Earlier versions applied entries in parallel via rayon, which made the print order non-deterministic; sequential execution trades a small amount of throughput for predictable, log-friendly output. For very large repos the per-entry overhead is bounded — entries that already match the destination short-circuit on `needs_update` and cost only a `stat` + read.



## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All changes applied (or nothing to do). |
| `1` | An error occurred. |

For drift detection in CI, use `guisu verify` — it exits 1 on drift, 0 on a clean state.

## Hooks

`apply` runs pre- and post-hooks from `.guisu/hooks/pre/` and `.guisu/hooks/post/` around the apply. See [Hooks](../user-guide/hooks.md).

## Next step

Read the [User Guide](../user-guide/file-attributes.md) for the file-attribute conventions, or jump to [Templates](../user-guide/templates.md) if your dotfiles need environment-specific rendering.
