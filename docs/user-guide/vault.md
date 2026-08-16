# Vault (Secret Providers)

Guisu can pull secrets from a password manager CLI and expose them in templates. The built-in integrations are Bitwarden (`bw`), the unofficial Rust Bitwarden CLI (`rbw`), and Bitwarden Secrets (`bws`).

> [!WARNING]
> **Authentication is your responsibility**
> Guisu does not log you in to the password manager. You must run `bw login`, `rbw login`, or `bws login` (or set the appropriate env var) once per session before `guisu apply`. If the vault CLI is unauthenticated, the call will fail with a non-zero exit code.



## Configure a provider

```toml
[bitwarden]
provider = "bw"   # or "rbw", "bws"
```

The default provider is `"bw"`. The provider binary must be on `$PATH` and authenticated. All three providers compile into the default CLI build (`bw` and `bws` are default cargo features; `rbw` lives in the `bw` module). A non-default build that disables these features will not register the corresponding template functions.

## Use in a template

```jinja
export GITHUB_TOKEN="{{ bitwarden('GitHub').login.password }}"
export API_KEY="{{ bitwardenFields('GitHub', 'APIKey') }}"
```

The first call returns the full item as a structured object; the second returns a specific custom field. Both are JSON-typed — Jinja2's dot syntax and `[]` indexing both work.

## Caching

The vault layer caches responses for the lifetime of the process. If your template calls `bitwarden("GitHub")` three times, the underlying CLI is invoked once. Since each `guisu apply` is its own process, the cache is effectively per-`apply`. Cached secrets are stored zeroised (`secrecy::SecretString`).

> [!TIP]
> **Reference items by stable name**
> Password manager item names are user-defined and can change. If you rename an item in Bitwarden, the template will fail at the next `apply` because the lookup returns `null`. Treat item names as part of your template contract.



## Adding a new provider

New providers implement the `SecretProvider` trait in `guisu-vault` (see [crates/vault/AGENTS.md](https://github.com/YvanY0/guisu/blob/main/crates/vault/AGENTS.md) for the full checklist):

```rust
pub trait SecretProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn execute(&self, args: &[&str]) -> Result<serde_json::Value>;
    fn help(&self) -> &'static str;
}
```

`name()` and `help()` return `&'static str` — provider names are static strings. The CLI for the provider must return JSON; Guisu parses it as `serde_json::Value` and makes it available to the template.

## See also

- [Templates](templates.md) for the broader template engine.
- [Encryption](encryption.md) for committing encrypted secrets instead of fetching them.
