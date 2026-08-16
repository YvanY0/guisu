# Three-State Model

The engine keeps three views of every file under management, plus a persistent record of what was last applied. Comparing the four is what makes conflict detection and safe interactive resolution possible.

## The four stores

The engine keeps four views of every file under management. The arrows below describe how data flows from one store to the next during an `apply`.

```
SOURCE                 TARGET                  DESTINATION            PERSISTENT
(filesystem)           (in memory)             (filesystem)           (redb)

.bashrc.j2     ───►    .bashrc (rendered) ──►  ~/.bashrc       ◄──►  blake3(.bashrc)
key.txt.age    ───►    key.txt (decrypted)──►  ~/key.txt      ◄──►  blake3(key.txt)
                     decrypt + render        write + chmod          record

Source     →  Target     : decrypt .age, then render .j2
Target     →  Destination: write to disk, apply mode
Target     ↔  Persistent : hash target, store in db
Target     ↔  Destination: three-way compare to detect Steady/Ahead/Behind/Conflict
```

The bold arrows show the **writes** the apply loop performs. The plain arrows are **reads** that drive the comparison.

| Store | Where it lives | Mutable? | Notes |
| --- | --- | --- | --- |
| **Source** | Files in the source repository (filesystem) | Read-only during apply | Filenames encode extensions (`.j2`, `.age`, `.j2.age`); file mode bits come from `metadata().mode()`. |
| **Target** | Rendered, decrypted content (in memory) | Recomputed on demand | Always the desired post-`apply` state for a given source. |
| **Destination** | The actual files on the user's machine (filesystem) | Read + Write | Where the user's dotfiles actually live. |
| **Persistent** | `redb` database at `${XDG_STATE_HOME:-~/.local/state}/guisu/state.db` | Written after a successful apply | Content hash + mode of the last applied target. |

## Status types

For each file under management, the engine computes a status by three-way-comparing target, destination, and the database hash. The status enum (`FileStatus`) is defined in the CLI crate (`crates/cli/src/cmd/status.rs`) and has five variants — there is no `Removed` variant; removals are expressed via `Metadata::remove` in `.guisu/state.toml` and processed in a pre-pass.

| Status | Label | Meaning | Default action |
| --- | --- | --- | --- |
| `Steady` | `[S]` | Target, destination, and last-applied hash all agree. | Skip. |
| `Latent` | `[L]` | Destination missing — file is pending deployment. | Create. |
| `Behind` | `[B]` | Source moved ahead of the last-applied state. | Apply. |
| `Ahead` | `[A]` | Destination moved ahead of the last-applied state (local edits). | Overwrite (or prompt). |
| `Conflict` | `[C]` | Both source and destination moved since the last apply. | Prompt (`--interactive`) or overwrite. |

The conceptual mapping to chezmoi-style names: `Steady`≈synced, `Latent`≈added, `Behind`≈modified-in-source, `Ahead`≈modified-by-you, `Conflict`≈conflict.

## Entry types

`crates/engine/src/entry.rs` defines three enums and a struct:

```rust
pub enum SourceEntry {
    File { source_path, target_path, attributes },
    Directory { source_path, target_path, attributes },
    Symlink { source_path, target_path, link_target },
}

pub enum TargetEntry {
    File { path, content: Vec<u8>, content_hash: [u8; 32], mode: Option<u32> },
    Directory { path, mode: Option<u32> },
    Symlink { path, target: PathBuf },
}

pub struct DestEntry {
    pub path: RelPath,
    pub kind: EntryKind,
    pub content: Option<Vec<u8>>,
    pub mode: Option<u32>,
    pub link_target: Option<PathBuf>,
}

pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Missing,
}
```

`SourceEntry` and `TargetEntry` differ slightly because the source carries parsed `attributes` while the target carries concrete content. `TargetEntry::File` stores a blake3 `content_hash` so drift detection can compare hashes without re-reading destination content.

> [!NOTE]
> **No `TargetEntry::Remove`**
> An earlier design had a `Remove` variant expressed via the `remove_` filename prefix. Both have been dropped. Removals are now declared via
> `Metadata::remove` in `.guisu/state.toml`; the apply step processes them in a separate pre-pass before applying targets. See
> [User Guide — File Attributes](../user-guide/file-attributes.md#removing-a-file-from-the-destination).

## File attributes

`FileAttributes` in `crates/engine/src/attr.rs` is a plain struct:

```rust
pub struct FileAttributes {
    pub is_template: bool,    // .j2 extension
    pub is_encrypted: bool,   // .age extension
    pub mode: Option<u32>,     // source file's metadata().mode()
}
```

`is_template` and `is_encrypted` are decoded from the filename
extension at read time. `mode` is read from the source file's
`metadata().mode()` and propagated to the destination by `apply`. The
permission-related bitflags (`private_` / `readonly_` / `executable_`
/ `dot_` / `exact_`) and the entry-type prefixes (`modify_` /
`remove_` / `symlink_`) are no longer recognized. See
[User Guide — File Attributes](../user-guide/file-attributes.md).

## See also

- [Data Flow](data-flow.md) — apply / init / add / update flows.
- [Crates — guisu-engine](crates.md#guisu-engine) — the public API for state types.
