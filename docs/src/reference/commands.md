# Commands

This page enumerates every guisu subcommand. Run guisu subcommand --help for the authoritative flag list; this page is the curated overview.

> [!NOTE]
> **How the page is organised**
> Top-level commands first, then sub-commands grouped under their parents (age, ignored, templates, hooks). Flags shown are the curated highlights; the full set comes from --help.



## Top-level commands

| Command | Purpose |
| --- | --- |
| guisu init [TARGET] | Clone a dotfiles repo or initialise a new one locally. |
| guisu add PATH... | Copy files from the destination into the source repo. |
| guisu apply [PATH]... | Render the source state and write to the destination. |
| guisu diff | Show the differences between target and destination. |
| guisu status | Per-file status (Synced / Added / Modified / Removed / Conflict). |
| guisu cat PATH | Print the rendered (target) content of a file. |
| guisu edit PATH | Open the source file in $EDITOR with transparent decrypt/encrypt. |
| guisu update | Fetch, merge, and apply. |
| guisu verify | Verify destination matches source; exits non-zero on drift (CI-friendly). |
| guisu info | Print resolved source / destination / version / configuration. |
| guisu variables | Print all template variables available in the current context. |
| guisu age | See age subcommand group. |
| guisu ignored | See ignored subcommand group. |
| guisu templates | See templates subcommand group. |
| guisu hooks | See hooks subcommand group. |

### guisu init

```bash
guisu init [PATH_OR_REPO] [FLAGS]
```

| Flag | Effect |
| --- | --- |
| --apply / -a | Apply changes after initialisation (default behaviour for cloned repos). |
| --depth N | Shallow clone with the given commit depth. |
| --branch NAME | Clone the specified branch. |
| --ssh | Use SSH instead of HTTPS when guessing the GitHub URL. |
| --recurse-submodules | Clone submodules recursively. |

PATH_OR_REPO accepts a local path, a GitHub username (shorthand for github.com/username/dotfiles), or a full URL. Defaults to ~/.local/share/guisu.

### guisu add

```bash
guisu add PATH... [FLAGS]
```

| Flag | Effect |
| --- | --- |
| --encrypt | Store the file as name.age in the source. |
| --template | Store the file as name.j2 for Jinja rendering. |
| --private | Force mode 0600 (or 0700 for directories). |
| --executable | Force mode 0755. |
| --exact | Preserve the source filename as-is; do not infer attributes. |
| --force | Overwrite an existing source entry. |
| --no-git | Skip the git add step. |

### guisu apply

```bash
guisu apply [PATH]... [FLAGS]
```

| Flag | Effect |
| --- | --- |
| --dry-run | Show planned changes without writing. |
| --force | Overwrite destination without prompting. |
| --interactive | Open the TUI for every conflict. |
| --include PATTERN | Only apply files matching the pattern. |
| --exclude PATTERN | Skip files matching the pattern. |
| --no-apply | (Used by init.) Skip the apply step. |

### guisu diff

```bash
guisu diff [PATH]... [FLAGS]
```

Shows a unified diff between target and destination. Honours --include / --exclude and the same source/destination overrides as apply.

### guisu status

```bash
guisu status [PATH]... [FLAGS]
```

Per-file status output, one line per entry. --json emits machine-readable output.

### guisu cat

```bash
guisu cat PATH
```

Print the rendered (decrypted + templated) target content to stdout. Useful for debugging templates without applying.

### guisu edit

```bash
guisu edit PATH
```

Decrypt (if .age), open in $EDITOR, re-encrypt on save. Temp file is 0600 and securely deleted on editor exit.

### guisu update

```bash
guisu update [FLAGS]
```

Fetch from the source repo's remote, merge (or rebase with --rebase), and run apply. --no-apply skips the apply step.

### guisu info

```bash
guisu info [FLAGS]
```

Print the resolved source directory, working tree, destination directory, and version. With --all, also print build info, public keys, and configuration. With --json, machine-readable.

> [!TIP]
> **Use info for first-time setup debugging**
> If guisu apply cannot find your source dir, run guisu info --all to see what Guisu resolved. Most "why is nothing happening?" questions answer themselves in this output.



### guisu variables

```bash
guisu variables [FLAGS]
```

Print every variable available in the current template context: system, guisu, user-defined, and platform-specific. --builtin shows only system + guisu; --user shows only user-defined; --json emits machine-readable.

### guisu verify

```bash
guisu verify [PATHS]... [FLAGS]
```

Verify that the destination filesystem matches the source. Exits
non-zero when any drift is detected; silent on both success and
failure. Designed for CI: guisu verify && echo "no drift".

Walks the source tree, renders the target state (template expansion,
age decryption), then compares each entry against the destination.
By default it checks files, directories, symlinks, and
Metadata::remove paths. Hooks and scripts are skipped in v1 — run
guisu status if you also need to check hook source drift. To see
*what* drifted, run guisu diff.

guisu verify always recurses into all managed entries; there is no
flag to limit recursion.

PATHS accepts both chezmoi-style absolute paths (~/.bashrc) and
dest-relative paths (.bashrc, foo/bar); both are normalised
against the destination root and compared against the rendered
target state. Paths that escape the destination root are rejected
with an error.

| Flag | Effect |
| --- | --- |
| -x, --exclude TYPES | Exclude entry types (comma-separated: dirs,files,symlinks,remove). |
| -i, --include TYPES | Include only these entry types. Default: dirs,files,symlinks,remove. |

--include and --exclude are mutually exclusive; combining them
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
catching manual edits, missed guisu apply runs, or
pull-then-forget workflows.

## Subcommand groups

### guisu age

| Subcommand | Purpose |
| --- | --- |
| guisu age generate -o FILE | Create a new age identity. |
| guisu age encrypt FILE | Encrypt a file with the configured recipients. |
| guisu age decrypt FILE | Decrypt a file with the configured identities. |
| guisu age encrypt --inline VALUE | Emit an inline-encrypted string for use in templates. |
| guisu age decrypt --inline VALUE | Decrypt an inline-encrypted string. |
| guisu age recipients | List the configured recipients. |

### guisu ignored

| Subcommand | Purpose |
| --- | --- |
| guisu ignored list | List currently ignored files and the patterns that matched. |
| guisu ignored add PATTERN | Add a pattern to .guisu.toml [ignore]. |
| guisu ignored remove PATTERN | Remove a pattern. |

### guisu templates

| Subcommand | Purpose |
| --- | --- |
| guisu templates execute PATH | Render a template with the current context (no apply). |

### guisu hooks

| Subcommand | Purpose |
| --- | --- |
| guisu hooks run PHASE | Manually execute pre or post hooks for the given phase. |
| guisu hooks list | List all discovered hooks with their resolved mode. |
| guisu hooks show HOOK | Show the script path and the environment variables it would receive. |

## Global flags

Most top-level commands accept:

| Flag | Effect |
| --- | --- |
| --source DIR | Override the source directory. Also reads GUISU_SOURCE_DIR. |
| --dest DIR | Override the destination directory. Also reads GUISU_DEST_DIR. |
| --config FILE | Override the config file path. Also reads GUISU_CONFIG. |
| --log-file FILE | Mirror logs to this file. Also reads GUISU_LOG_FILE. |
| --color WHEN | auto / always / never. |
| --progress WHEN | auto / always / never. |
