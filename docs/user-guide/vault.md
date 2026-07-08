# Vault (Secret Providers)

Guisu can pull secrets from a password manager CLI and expose them in templates. The built-in integrations are Bitwarden (`bw`), Roboform-bitwarden (`rbw`), and Bitwarden Secrets (`bws`).

> [!WARNING]
> **Authentication is your responsibility**
> Guisu does not log you in to the password manager. You must run `rbw login`, `bw login`, or `bws login` (or set the appropriate env var) once per session before `guisu apply`. If the vault CLI is unauthenticated, the call will fail with a non-zero exit code.



## Configure a provider

```toml
[bitwarden]
provider = "rbw"   # or "bw", "bws"
```

The provider binary must be on `$PATH` and authenticated. There is no per-provider feature flag — all three providers compile in by default.

## Use in a template

```jinja
export GITHUB_TOKEN="{{ bitwarden('GitHub').login.password }}"
export API_KEY="{{ bitwardenFields('GitHub', 'APIKey') }}"
```

The first call returns the full item as a structured object; the second returns a specific custom field. Both are JSON-typed — Jinja2's dot syntax and `[]` indexing both work.

## Caching

The vault layer caches the response for the duration of a single `apply`. If your template calls `bitwarden("GitHub")` three times, the underlying CLI is invoked once. The cache is per-`apply` and is dropped at the end of the run.

> [!TIP]
> **Reference items by stable name**
> Password manager item names are user-defined and can change. If you rename an item in Bitwarden, the template will fail at the next `apply` because the lookup returns `null`. Treat item names as part of your template contract.



## Adding a new provider

See the `add-vault-provider` skill in the repository. New providers implement the `SecretProvider` trait in `guisu-vault`:

```rust
pub trait SecretProvider: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn execute(&self, args: &[&str]) -> Result<serde_json::Value>;
    fn help(&self) -> &str;
}
```

The CLI for the provider must return JSON; Guisu parses it as `serde_json::Value` and makes it available to the template.

## See also

- [Templates](templates.md) for the broader template engine.
- [Encryption](encryption.md) for committing encrypted secrets instead of fetching them.
