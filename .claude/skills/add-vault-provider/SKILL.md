---
name: add-vault-provider
description: Add a new secret provider (1Password, Pass, Keychain, etc.) to guisu's vault system. Use when adding a new vault backend or integrating a new secrets manager.
---

# Add a Vault Provider

## Architecture

Vault providers live in `crates/vault/src/`. Each provider implements `SecretProvider` trait.

Current providers:
- `bw.rs` — Bitwarden CLI (`bw`) and rbw (`rbw`)
- `bws.rs` — Bitwarden Secrets Manager (`bws`)

## Steps

### 1. Implement SecretProvider trait

`crates/vault/src/lib.rs`:

```rust
pub trait SecretProvider: Send + Sync {
    /// Provider name for display
    fn name(&self) -> &str;

    /// Execute a query (e.g., get item by ID)
    fn execute(&self, args: &[&str]) -> Result<String>;

    /// Check if provider CLI is available
    fn is_available(&self) -> bool;

    /// Help text for the provider
    fn help(&self) -> &str;
}
```

### 2. Create provider file

`crates/vault/src/<provider>.rs`:

```rust
use anyhow::{Context, Result};
use std::process::Command;

pub struct <Provider>Cli;

impl SecretProvider for <Provider>Cli {
    fn name(&self) -> &str { "<provider>" }

    fn execute(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("<cli-binary>")
            .args(args)
            .output()
            .context("failed to execute <provider> CLI")?;

        if !output.status.success() {
            anyhow::bail!(
                "<provider> CLI failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(String::from_utf8(output.stdout)?)
    }

    fn is_available(&self) -> bool {
        Command::new("which")
            .arg("<cli-binary>")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn help(&self) -> &str {
        "Install <provider>: <install instructions>"
    }
}
```

### 3. Add feature flag

In `vault/Cargo.toml`:
```toml
[features]
default = ["bw"]
bw = []
bws = []
<provider> = []
```

Gate the module in `vault/src/lib.rs`:
```rust
#[cfg(feature = "<provider>")]
pub mod <provider>;
```

### 4. Register template functions

In `template/src/functions/vault.rs`, add template functions that use the new provider:

```rust
pub fn <provider>_read(args: &[Value]) -> Result<Value, Error> {
    // Use the provider to fetch secrets
}
```

Register in `template/src/engine.rs` behind feature flag.

### 5. Add tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_<provider>_available() {
        let cli = <Provider>Cli;
        // This test is provider-specific, may need mocking
    }
}
```

## Reference

- `vault/src/bw.rs` — Bitwarden implementation (most complete example)
- `vault/src/bws.rs` — Simpler Secrets Manager implementation
- `vault/src/lib.rs` — `SecretProvider` trait and `CachedSecretProvider`
- `domain-knowledge` skill — vault architecture overview
