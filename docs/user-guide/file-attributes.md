# File Attributes

Guisu derives per-file behaviour from three sources, in this order of
precedence:

1. The **source file's actual Unix mode bits** (read from disk via
   `metadata().mode()`). These are the source of truth for permissions
   and are propagated verbatim to the destination by `apply`.
2. The **file extension** on the source filename (`.j2`, `.age`,
   `.j2.age`). The extension is stripped from the target name.
3. The **`[remove] paths` array** in `.guisu/state.toml`, which
   declares dest paths to remove on `apply`.

## Extensions (transformation markers)

| Suffix | Meaning | Result on apply |
| --- | --- | --- |
| `.j2` | Jinja2 template | File is rendered with the template engine before write |
| `.age` | age-encrypted | File is decrypted before any other processing |
| `.j2.age` | Encrypted template | Decrypt first, then render |

Extensions stack in the order **`.j2.age`** (decrypt, then render). The
reverse order `.age.j2` is **not** valid — the renderer would run on
the encrypted bytes.

## File permissions

The destination file's mode is the source file's mode. If
`~/.local/share/guisu/home/.config/zsh/zshrc` is `0o644` on disk, the
rendered `~/.config/zsh/zshrc` will be `0o644` after `guisu apply`.
`guisu diff` reports any mismatch between source and dest mode bits.
`guisu apply` chmods the destination to match the source on every run.

This is a deliberate departure from chezmoi: guisu **does not** encode
permissions in the filename. There is no `private_` or `executable_`
prefix — if you want a private file, make the source file private
(`chmod 600 path/to/source`) and `apply` will propagate it. Keeping
the filename free of permission markers means a dotfiles repo can be
shared across machines with different UIDs without the filename lying
about the resulting mode.

## Removing a file from the destination

To remove a file or directory from the destination on `apply`, list
it under `[remove] paths` in `.guisu/state.toml`:

```toml
[remove]
paths = [
  "~/.cache/foo",
  "~/.config/old-app",
]
```

- Paths are **dest-relative** under the destination root. `~` is
  expanded to the user's home; absolute paths and `..` traversal are
  rejected as a safety check.
- Missing paths are silently ignored (idempotent directive).
- `--dry-run` reports the removal without touching the filesystem.

The legacy `remove_xxx` filename convention is **not** supported — the
only way to declare a removal is via `state.toml`. There is currently
no CLI command for editing the remove list; edit `state.toml` by
hand.

## Directories

The same rules apply. A directory's mode is read from the source and
propagated to the destination. A directory with no source counterpart
(an "extra" directory in the dest) is left alone unless it is listed
under `[remove]`.

## See also

- [Templates](templates.md) — how `.j2` files are rendered.
- [Encryption](encryption.md) — how `.age` files are decrypted.
- [Hooks](hooks.md) — pre/post scripts that run around `apply`.
- [Config](config.md) — how `.guisu/state.toml` is loaded.
