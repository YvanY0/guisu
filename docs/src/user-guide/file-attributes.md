# File Attributes

Guisu encodes per-file behaviour in the **source filename**. The destination filename is identical to the source, except for the special suffixes below. This is the same convention chezmoi uses.

## Suffixes (transformation markers)

| Suffix | Meaning | Result on apply |
| --- | --- | --- |
| `.j2` | Jinja2 template | File is rendered with the template engine before write |
| `.age` | age-encrypted | File is decrypted before any other processing |
| `.j2.age` | Encrypted template | Decrypt first, then render |
| `.remove` | Mark for removal | Removes the destination on apply |

Suffixes stack in the order **`.j2.age`** (decrypt, then render). The reverse order `.age.j2` is **not** valid — the renderer would run on the encrypted bytes.

## Prefixes (attribute and rename markers)

| Prefix | Meaning | Effect |
| --- | --- | --- |
| `dot_` | Hidden file | The leading `dot_` is replaced with `.` (`dot_bashrc` → `.bashrc`) |
| `private_` | Private mode | Mode `0600` (files) or `0700` (directories) |
| `readonly_` | Read-only mode | Mode `0444` (files) or `0555` (directories) |
| `executable_` | Executable mode | Mode `0755` |
| `modify_` | In-place modification | Source is a script; the script is invoked with the destination path in `$GUISU_TARGET` and is expected to modify it in place |
| `create_` | Create-only | Source is copied to the destination only if the destination does not exist |

## Combining attributes

Multiple prefixes stack. For example, `private_dot_config` is a hidden file with mode `0600`. Suffixes and prefixes combine: `private_config.j2.age` is an encrypted template, owned by the current user only.

## Directories

The same prefixes apply to directories. A directory named `private_dot_ssh` becomes `~/.ssh` with mode `0700`.

## Order of application

When applying a file, Guisu follows this order:

1. Strip prefixes to recover the destination filename.
2. Read the source file from disk.
3. If `.age`, decrypt.
4. If `.j2`, render the template with the current context.
5. Write to the destination with the mode from the prefix (if any).

The order is **fixed** so that encrypted templates (`.j2.age`) work: decrypt first, then render.

## See also

- [Templates](templates.md) — how `.j2` files are rendered.
- [Encryption](encryption.md) — how `.age` files are decrypted.
- [Hooks](hooks.md) — pre/post scripts that run around `apply`.
