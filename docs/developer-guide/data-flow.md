# Data Flow

This page traces the major commands through the layers. Each flow is the same shape: parse args → load config → load identities → read source → build target → compare with destination and database → resolve conflicts → write → update database.

## `guisu apply`

The core command. Materialises source into destination. The flow is:

1. **Parse CLI args** — `--interactive`, `--dry-run`, `--force`, source/destination overrides.
2. **Load `.guisu.toml`** + any platform-specific variable files; merge them.
3. **Load age identities** from the configured identity files (age keys or SSH keys).
4. **Build the template engine** and a context populated with system info, guisu metadata, and user variables.
5. **Read `SourceState`** — walk the source directory in parallel via rayon; parse file attributes from each filename; build `SourceEntry` objects.
6. **Build `TargetState`** — for each source entry, decrypt `.age` files and render `.j2` templates, again in parallel.
7. **Open the redb database** at `<source>/.guisu-state.db`.
8. **For each entry in the target state** (sequential, so writes are deterministic):
    1. Read the corresponding `DestinationState` entry (the actual file on disk).
    2. Load the database entry (the last applied hash + mode).
    3. Three-way compare the three to compute a `FileStatus`.
    4. Resolve the status:
        - `Synced` — skip.
        - `Added` / `Modified` — write the target content with the target mode.
        - `Conflict` — if `--interactive`, open the TUI; otherwise overwrite.
        - User can also `Quit` from the TUI, which aborts the entire apply.
    5. Update the database with the new hash and mode.
9. **Show stats** — counts of added / modified / skipped / errored entries.

Steps 5 and 6 use rayon for parallel processing. Steps 8 and 9 are sequential so writes happen in a deterministic order and a mid-apply crash leaves the destination in a recoverable state.

## `guisu init`

1. Parse the target — a local path, a GitHub username, or `owner/repo`.
2. Determine the source directory (default `~/.local/share/guisu`).
3. If the source directory already exists, error out.
4. Clone the repository (in-process via the `git2` crate).
5. Run `guisu apply` in interactive mode so the user can review the changes before they land.

## `guisu add`

1. Resolve the path: expand `~`, make it absolute, verify it exists.
2. Compute the target path: strip the `$HOME` prefix.
3. If `--encrypt` was passed, encrypt the content and append `.age` as the suffix. `--template` instead appends `.j2`. Otherwise the file is used as-is.
4. Copy the (possibly transformed) file to the source directory, preserving metadata.
5. Run `git add` on the resulting source path.

## `guisu update`

1. Open the source repo via `git2`.
2. `git fetch origin`.
3. If `--rebase`, run `git rebase`; otherwise `git merge`.
4. If there are conflicts, error out (the user must resolve them manually).
5. Run `guisu apply`.

## `guisu edit`

1. Map the destination path back to the source path (look for `.j2` / `.age` suffixes).
2. If the source is an `.age` file, decrypt to a temp file (mode `0600`).
3. Open the source (or temp) file in `$EDITOR` and wait for it to exit.
4. If the content's hash changed, and the source is `.age`, re-encrypt and replace the source. Otherwise just replace the source.
5. Delete the temp file.

The temp file lives on the same filesystem as the source, with mode `0600`, and is `unlink()`-ed when the editor exits. Secure erasure (overwrite before unlink) is on the roadmap but not implemented.

## Parallel processing

The engine uses [rayon](https://docs.rs/rayon) for two passes:

| Pass | Operation | What parallelises |
| --- | --- | --- |
| Read source | `SourceState::read(root)` | One task per file system entry: read bytes, parse attributes, build `SourceEntry`. |
| Build target | `TargetState::from_source(source, processor, context)` | One task per source entry: decrypt (if `.age`), render template (if `.j2`), build `TargetEntry`. |

Sequential steps (`write`, `update db`, `compare`) stay single-threaded to keep the on-disk state coherent and the diff output stable.

## See also

- [Three-State Model](three-state-model.md) — the four stores the flows above touch.
- [Crates — guisu-engine](crates.md#guisu-engine) — the types in the flow.
