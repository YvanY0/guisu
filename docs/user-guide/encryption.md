# Encryption

Guisu uses [age](https://age-encryption.org/) for symmetric and asymmetric encryption. Files marked with the `.age` suffix are decrypted on apply.

> [!WARNING]
> **Do not commit your age key**
> The age identity file is the only thing that can decrypt your secrets. Never commit it to the dotfiles repo; keep it in `~/.config/guisu/` (which is outside the source) or in a hardware token. If you lose the identity, the encrypted files are gone.



## Generate an identity

```bash
guisu age generate -o ~/.config/guisu/key.txt
```

This writes a native age key. To use an existing SSH key instead, point `.guisu.toml` at it:

```toml
[age]
identity = "~/.ssh/id_ed25519"
derive = true   # derive the recipient from the public key for encryption
```

When `derive = true`, Guisu uses the SSH public key as an age recipient. You can encrypt to the SSH public key, and the SSH private key acts as the age identity for decryption.

## Add an encrypted file

```bash
guisu add --encrypt ~/.ssh/id_rsa
```

The source file is `id_rsa.age` (ASCII-armored). On apply, it is decrypted to `~/.ssh/id_rsa`. The destination mode is the source file's own mode — `chmod 600` the `.age` file in the source repo and `apply` propagates `0600` to the destination (see [File Attributes](file-attributes.md#file-permissions)).

## Edit an encrypted file

```bash
guisu edit ~/.ssh/id_rsa
```

Guisu decrypts to a temp file (mode `0600`), opens your `$EDITOR`, then re-encrypts and replaces the source on save. The temp file is securely deleted when the editor exits.

> [!WARNING]
> **Editor backups and swap files**
> Your editor may leave backup files (`~/.ssh/id_rsa~`, `.swp`, etc.) on disk. Configure your editor to disable backups (`set nobackup nowritebackup noswapfile` in vim) or run `guisu edit` from a tmpfs-backed directory.



## Inline encryption in templates

For small secrets (API tokens, etc.) you can encrypt inline and embed in a template:

```jinja
export GITHUB_TOKEN="{{ 'age:base64,YWdl...' | decrypt }}"
```

Generate an inline value with:

```bash
guisu age encrypt --inline 'ghp_xxxxxxxxxxxx'
```

The output is safe to commit. Decryption happens at render time and the plaintext only ever exists in memory.

## Multiple recipients

```toml
[age]
recipients = [
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    "age1j0p6m6j3xcfua6jn8u6vnn7qk8h0qg5k7z2q3w..."
]
identity = "~/.config/guisu/key.txt"
```

Guisu encrypts to every recipient; any one identity can decrypt. Use this to give multiple machines access to the same secrets without sharing a private key.

## See also

- [Vault](vault.md) for fetching secrets from a password manager instead of committing them.
- [Reference — Configuration](../reference/configuration.md) for the `[age]` section.
