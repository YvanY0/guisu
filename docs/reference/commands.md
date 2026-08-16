# Commands

This page enumerates every guisu subcommand. Run `guisu <subcommand> --help` for the authoritative flag list; this page is the curated overview.

> [!NOTE]
> **How the page is organised**
> Top-level commands first, then sub-commands grouped under their parents (`age`, `ignored`, `templates`, `hooks`). Flags shown are the curated highlights; the full set comes from `--help`.



## Top-level commands

| Command | Purpose |
| --- | --- |
| `guisu init [PATH_OR_REPO]` | Clone a dotfiles repo or initialise a new one locally. |
| `guisu add PATH...` | Copy files from the destination into the source repo. |
| `guisu apply [FILES]...` | Render the source state and write to the destination. |
| `guisu diff [FILES]...` | Show the differences between target and destination. |
| `guisu status [FILES]...` | Per-file status (`Latent` / `Ahead` / `Behind` / `Conflict` / `Steady`). |
| `guisu cat PATHS...` | Print the rendered (target) content of one or more files. |
| `guisu edit PATH` | Open the source file in `$EDITOR` with transparent decrypt/encrypt. |
| `guisu update` | Fetch, merge (or rebase), and apply. |
| `guisu verify` | Verify destination matches source; exits non-zero on drift (CI-friendly). |
| `guisu info` | Print resolved source / destination / version / configuration. |
| `guisu variables` | Print all template variables available in the current context. |
| `guisu completion <SHELL>` | Generate a shell completion script (zsh, bash, fish). |
| `guisu age` | See age subcommand group. |
| `guisu ignored` | See ignored subcommand group. |
| `guisu templates` | See templates subcommand group. |
| `guisu hooks` | See hooks subcommand group. |

### `guisu init`

```bash
guisu init [PATH_OR_REPO] [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--apply`, `-a` | Apply changes after initialisation (off by default). |
| `--depth N` | Shallow clone with the given commit depth. |
| `--branch NAME` | Clone the specified branch. |
| `--ssh` | Use SSH instead of HTTPS when guessing the GitHub URL. |
| `--recurse-submodules` | Clone submodules recursively. |

`PATH_OR_REPO` accepts a local path, a GitHub username (shorthand for `github.com/username/dotfiles`), or a full URL. Defaults to `~/.local/share/guisu`.

### `guisu add`

```bash
guisu add PATH... [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--encrypt`, `-E` | Encrypt the file with age; store as `name.age`. |
| `--template`, `-t` | Store the file as `name.j2` for Jinja rendering. |
| `--autotemplate`, `-a` | Auto-detect template variables; store as `name.j2` (implies `--template`). |
| `--create`, `-c` | Create-once: only copy if the destination doesn't already exist. |
| `--force`, `-f` | Overwrite an existing source entry. |
| `--secrets {ignore\|warning\|error}` | How to handle files containing secrets (default `warning`). |

### `guisu apply`

```bash
guisu apply [FILES]... [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--dry-run`, `-n` | Show planned changes without writing. |
| `--force`, `-f` | Overwrite destination without prompting. |
| `--interactive`, `-i` | Open the TUI for every conflict. |

### `guisu diff`

```bash
guisu diff [FILES]... [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--interactive`, `-i` | Open the interactive diff viewer. |
| `--pager` | Pipe output through `$PAGER`. |

Shows a diff between target and destination. The format follows `[ui] diffFormat` (`unified` / `split` / `inline`). Honours the same source/destination overrides as `apply`.

### `guisu status`

```bash
guisu status [FILES]... [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--all` | Show synced (`Steady`) entries too (hidden by default). |
| `--tree` | Render output as a tree. |
| `--absolute` | Show full destination paths instead of chezmoi-style relative paths. |

Per-file status output, one line per entry. Statuses: `Latent` (to deploy), `Ahead` (local changes), `Behind` (source updated), `Conflict`, `Steady` (synced).

### `guisu cat`

```bash
guisu cat PATHS...
```

Print the rendered (decrypted + templated) target content to stdout. Useful for debugging templates without applying. Accepts multiple paths.

### `guisu edit`

```bash
guisu edit PATH [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--apply`, `-a` | Run `apply` after a successful save. Also enabled by `[edit] apply = true`. |

Decrypt (if `.age`), open in `$EDITOR`, re-encrypt on save. The temp file is `0600` and securely deleted on editor exit. Also handles files with inline `age:` values — all inline values are decrypted for editing and re-encrypted on save.

### `guisu update`

```bash
guisu update [FLAGS]
```

| Flag | Effect |
| --- | --- |
| `--rebase`, `-r` | Rebase (instead of erroring) when branches have diverged. |
| `--apply`, `-a` | Apply after pulling (default: on). |

Fetch from the source repo's remote, fast-forward or (with `--rebase`) rebase, then apply. When branches have diverged and `--rebase` is not set, `update` errors and tells you to resolve manually.

### `guisu info`

```bash
guisu info [FLAGS]
```

Print the resolved source directory, working tree, destination directory, and version. With `--all`, also print build info, public keys, and configuration. With `--json`, machine-readable.

> [!TIP]
> **Use info for first-time setup debugging**
> If `guisu apply` cannot find your source dir, run `guisu info --all` to see what Guisu resolved. Most "why is nothing happening?" questions answer themselves in this output.



### `guisu variables`

```bash
guisu variables [FLAGS]
```

Print every variable available in the current template context: system, guisu, user-defined, and platform-specific. `--builtin` shows only system + guisu; `--user` shows only user-defined; `--json` emits machine-readable.

### `guisu completion`

```bash
guisu completion <SHELL>
```

Print a shell completion script for `zsh`, `bash`, or `fish`. Load it with `eval "$(guisu completion zsh)"` (see [Installation](../installation.md#shell-completion)).

### `guisu verify`

```bash
guisu verify [PATHS]... [FLAGS]
```

Verify that the destination filesystem matches the source. Exits
non-zero when any drift is detected; silent on both success and
failure. Designed for CI: `guisu verify && echo "no drift"`.

Walks the source tree, renders the target state (template expansion,
age decryption), then compares each entry against the destination.
By default it checks files, directories, symlinks, and
`Metadata::remove` paths. Hooks and scripts are skipped in v1 — run
`guisu status` if you also need to check hook source drift. To see
*what* drifted, run `guisu diff`.

`guisu verify` recurses into all managed entries; it does not limit recursion depth. Use `--include`/`--exclude` to filter which entry types are checked.

`PATHS` accepts both chezmoi-style absolute paths (`~/.bashrc`) and
dest-relative paths (`.bashrc`, `foo/bar`); both are normalised
against the destination root and compared against the rendered
target state. Paths that escape the destination root are rejected
with an error.

| Flag | Effect |
| --- | --- |
| `--exclude TYPES` | Exclude entry types (comma-separated: `dirs,files,symlinks,remove`). |
| `--include TYPES` | Include only these entry types. Default: `dirs,files,symlinks,remove`. |

`--include` and `--exclude` are mutually exclusive; combining them
errors out.

**Exit codes**

| Code | Meaning |
| --- | --- |
| 0 | All selected entries match between source and destination. |
| 1 | At least one entry drifted. |
| 2 | Internal error (e.g. decrypt failure, I/O error). |

**Example**

```bash
$ guisu verify
$ echo $?
0
$ # ... user edits ~/.bashrc by hand ...
$ guisu verify
$ echo $?
1
$ guisu diff
... shows the drift ...
$ guisu apply
$ guisu verify
$ echo $?
0
```

**CI usage**

A typical GitHub Actions step:

```yaml
- name: Verify dotfiles match
  run: |
    cargo install --path crates/cli --root ./install
    ./install/bin/guisu verify
```

The step fails when the destination has drifted from the source,
catching manual edits, missed `guisu apply` runs, or
pull-then-forget workflows.

## Subcommand groups

### `guisu age`

| Subcommand | Purpose |
| --- | --- |
| `guisu age generate [-o FILE]` | Create a new age identity (default: `~/.local/share/guisu/key.txt`). |
| `guisu age show` | Print the public key for the current identity. |
| `guisu age encrypt [VALUE]` | Encrypt a value to the inline `age:base64,...` format. |
| `guisu age decrypt VALUE` | Decrypt an inline-encrypted value. |
| `guisu age migrate --from OLD --to NEW` | Re-encrypt all `.age` files and inline values from old identities to new. |

`guisu age encrypt` always outputs the compact inline format. With no
`VALUE`, or with `--interactive`/`-i`, it reads from stdin. `--recipient`/`-r`
(multi) overrides the recipients derived from configured identities.
`guisu age migrate` flags: `--from` and `--to` (both required, repeatable),
`--dry-run`/`-n`, `--yes`/`-y`.

### `guisu ignored`

| Subcommand | Purpose |
| --- | --- |
| `guisu ignored list` | List currently ignored files and the patterns that matched. |
| `guisu ignored rules [--all]` | Show ignore rules for the current platform (or all platforms with `--all`). |

### `guisu templates`

| Subcommand | Purpose |
| --- | --- |
| `guisu templates list` | List available template files for the current platform. |
| `guisu templates show NAME` | Print the rendered content of a specific template. |

### `guisu hooks`

| Subcommand | Purpose |
| --- | --- |
| `guisu hooks run [HOOK]` | Run hooks; with a `HOOK` name, only hooks matching it. |
| `guisu hooks list` | List all discovered hooks with their resolved mode. |
| `guisu hooks show NAME` | Show a hook's script path and the environment variables it would receive. |

`guisu hooks run` flags: `--yes`/`-y` (skip confirmation). With no `HOOK`, every
configured hook (pre + post) runs.

## Global flags

Most top-level commands accept:

| Flag | Effect |
| --- | --- |
| `--source DIR` | Override the source directory. Also reads `GUISU_SOURCE_DIR`. |
| `--dest DIR` | Override the destination directory. Also reads `GUISU_DEST_DIR`. |
| `--config FILE` | Override the config file path. Also reads `GUISU_CONFIG`. |
| `--log-file FILE` | Mirror logs to this file. Also reads `GUISU_LOG_FILE`. |
| `--verbose`, `-v` | Show debug-level logs. |
