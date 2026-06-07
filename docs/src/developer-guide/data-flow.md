# Data Flow

This page traces the major commands through the layers. Each flow is the same shape: parse args → load config → load identities → read source → build target → compare with destination and database → resolve conflicts → write → update database.

## `guisu apply`

The core command. Materialises source into destination.

```mermaid
flowchart TD
    A["Parse CLI args<br/>(--interactive, --dry-run,<br/>--include, --exclude)"] --> B
    B["Load .guisu.toml +<br/>platform-specific variables"] --> C
    C["Load age identities<br/>(files or SSH keys)"] --> D
    D["Build template engine<br/>+ context (system, guisu,<br/>user variables)"] --> E
    E["Read SourceState<br/>(parallel via rayon)"] --> F
    F["Build TargetState<br/>(parallel: decrypt + render)"] --> G
    G["Open redb"] --> H
    H["For each entry"] --> I
    I["Read DestinationState<br/>(the actual file on disk)"] --> J
    J["Load DB state<br/>(last hash + mode)"] --> K
    K["Three-way compare"] --> L
    L{"Status?"}
    L -->|Synced| M["Skip"]
    L -->|Added / Modified| N["Write file"]
    L -->|Conflict| O{"--interactive?"}
    O -->|Yes| P["TUI prompt"]
    O -->|No| N
    P -->|User: Overwrite| N
    P -->|User: Skip| M
    P -->|User: Quit| R["Abort apply"]
    N --> Q["Update DB"]
    Q --> H
    M --> H
    R --> S
    H --> S["Show stats"]
```

Steps E and F use rayon for parallel processing (file I/O and template rendering are embarrassingly parallel). Steps H through Q are **sequential** so that writes happen in a deterministic order and a mid-apply crash leaves the destination in a recoverable state.

## `guisu init`

```mermaid
flowchart LR
    A["Parse target<br/>(path, username,<br/>or owner/repo)"] --> B
    B["Determine source dir<br/>(~/.local/share/guisu)"] --> C
    C{Already exists?}
    C -->|Yes| D["Error:<br/>source dir not empty"]
    C -->|No| E["git clone<br/>(in-process git2)"]
    E --> F["Apply (interactive)"]
    F --> G["Done"]
```

## `guisu add`

```mermaid
flowchart LR
    A["Resolve path<br/>(expand ~, make absolute)"] --> B
    B["Compute target path<br/>(strip $HOME)"] --> C
    C{"--encrypt?"}
    C -->|Yes| D["Encrypt content +<br/>append .age suffix"]
    C -->|No| E["Use as-is"]
    D --> F["Copy to source dir<br/>(preserve metadata)"]
    E --> F
    F --> G["git add"]
```

`--template` is handled the same way as `--encrypt` in this flow: the suffix becomes `.j2` instead of `.age`. `--private` and `--executable` do not change the file's location, only the attributes Guisa applies on the next apply.

## `guisu update`

```mermaid
flowchart LR
    A["Open repo<br/>(git2)"] --> B
    B["git fetch origin"] --> C
    C{"--rebase?"}
    C -->|Yes| D["git rebase"]
    C -->|No| E["git merge"]
    D --> F{Conflicts?}
    E --> F
    F -->|Yes| G["Error:<br/>resolve manually"]
    F -->|No| H["Run apply"]
    H --> I["Done"]
```

## `guisu edit`

```mermaid
flowchart LR
    A["Map dest path →<br/>source path"] --> B
    B{".age file?"}
    B -->|Yes| C["Decrypt to temp<br/>(mode 0600)"]
    B -->|No| D["Use source directly"]
    C --> E["Open $EDITOR"]
    D --> E
    E --> F{Hash changed?}
    F -->|No| G["Done"]
    F -->|Yes| H{".age file?"}
    H -->|Yes| I["Re-encrypt,<br/>replace source"]
    H -->|No| J["Replace source"]
    I --> K["Delete temp"]
    J --> K
```

The temp file is on the same filesystem as the source, mode `0600`, and is `unlink()`-ed when the editor exits. Secure erasure (overwrite before unlink) is on the roadmap but not implemented.

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
