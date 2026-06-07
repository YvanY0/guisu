# Template Functions

The full list of functions and filters registered with the minijinja environment, grouped by category. Run `guisu variables` to inspect what is available in a given context.

> [!NOTE]
> **Functions vs filters**
> A function is called with parentheses: `fn(arg)`. A filter is applied with the pipe operator: `value | filter`. The same underlying operation may exist as both — see the encryption row below.



## System

| Function | Returns | Notes |
| --- | --- | --- |
| `os()` | string | `"darwin"`, `"linux"`, or `"windows"`. |
| `arch()` | string | `"x86_64"`, `"aarch64"`, `"arm"`. |
| `hostname()` | string | Machine hostname. |
| `username()` | string | Current OS user. |
| `home_dir()` | string | `$HOME`. |

## Environment

| Function | Returns | Notes |
| --- | --- | --- |
| `env("NAME")` | string | Empty string if unset. |
| `lookPath("cmd")` | string | Absolute path of `cmd` on `$PATH`, or empty if not found. |

## Paths

| Function | Returns | Notes |
| --- | --- | --- |
| `joinPath("a", "b", "c")` | string | Join path components portably. |

## Vault (Bitwarden)

All four functions are available when the `[bitwarden]` provider is configured. Caching is per-`apply`.

| Function | Returns | Notes |
| --- | --- | --- |
| `bitwarden("Item")` | object | The full Bitwarden item as a JSON object. |
| `bitwardenFields("Item", "Field")` | value | A specific custom field on the item. |
| `bitwardenAttachment("Item", "filename")` | string | An attachment's contents as a string. |
| `bitwardenSecrets("Item", "Field")` | string | A secret field (Bitwarden Secrets only). |

## Templates

| Function | Returns | Notes |
| --- | --- | --- |
| `include("name")` | string | The **raw** content of another template file. |
| `includeTemplate("name")` | string | Include and render a template file with the current context. |

## Encryption

These are **filters** (not functions) — they go on the right side of a `|`.

| Filter | Returns | Notes |
| --- | --- | --- |
| `value \| decrypt` | string | Decrypt an inline `age:base64,...` string. |
| `value \| encrypt` | string | Encrypt a string for the configured recipients. |

```jinja
export TOKEN="{{ 'age:base64,YWdl...' | decrypt }}"
```

## Strings

| Function | Returns | Notes |
| --- | --- | --- |
| `regexMatch(pattern, string)` | bool | True if the regex matches anywhere. |
| `regexReplaceAll(pattern, replacement, string)` | string | Replace all matches. |
| `split(separator, string)` | list | Split a string into a list. |
| `join(separator, list)` | string | Join a list into a string. |

## String filters

| Filter | Returns | Notes |
| --- | --- | --- |
| `s \| quote` | string | Surround with double quotes; escape inner quotes. |
| `s \| trim` | string | Strip leading and trailing whitespace. |
| `s \| trimStart` | string | Strip leading whitespace. |
| `s \| trimEnd` | string | Strip trailing whitespace. |
| `s \| custom` | string | Uppercase the string. (Built-in alias; useful for templates.) |

## Data formats

| Filter | Returns | Notes |
| --- | --- | --- |
| `value \| toJson` | string | Serialise to JSON. |
| `s \| fromJson` | value | Parse JSON. |
| `value \| toToml` | string | Serialise to TOML. |
| `s \| fromToml` | value | Parse TOML. |

## Hashing

| Filter | Returns | Notes |
| --- | --- | --- |
| `s \| blake3sum` | string | Hex-encoded BLAKE3-256 of the input. |

> [!TIP]
> **Generated inline values**
> Run `guisu age encrypt --inline "my secret"` to print an inline-encrypted value. The output can be committed safely and embedded in templates as `{{ 'value' | decrypt }}`.



## See also

- [User Guide — Templates](../user-guide/templates.md) for the broader template engine and platform-specific variables.
- [User Guide — Encryption](../user-guide/encryption.md) for the `.age` suffix and identity management.
- [User Guide — Vault](../user-guide/vault.md) for the Bitwarden integration.
