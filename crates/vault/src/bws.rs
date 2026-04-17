//! Bitwarden Secrets Manager integration
//!
//! Provides access to Bitwarden Secrets Manager for organization secrets.
//! This is a separate product from Bitwarden Vault (personal/team passwords).
//!
//! Template function: `bitwardenSecrets()`

use crate::{Error, Result, SecretProvider};
use serde_json::Value as JsonValue;
use std::process::Command;

/// Bitwarden Secrets Manager CLI provider (`bws`)
pub struct BwsCli;

impl BwsCli {
    /// Create a new Bitwarden Secrets Manager CLI provider
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn check_access_token() -> Result<()> {
        if std::env::var("BWS_ACCESS_TOKEN").is_err() {
            return Err(Error::VaultAuthenticationRequired(
                "BWS_ACCESS_TOKEN environment variable not set.\n\
                 Get your access token from Bitwarden Secrets Manager:\n\
                 1. Go to your organization's Secrets Manager\n\
                 2. Create a Machine Account\n\
                 3. Generate an access token\n\
                 4. Set it: export BWS_ACCESS_TOKEN='your-token'"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for BwsCli {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for BwsCli {
    fn name(&self) -> &'static str {
        "bws"
    }

    fn execute(&self, args: &[&str]) -> Result<JsonValue> {
        if args.is_empty() {
            return Err(Error::VaultInvalidArguments(
                "At least one argument required".to_string(),
            ));
        }

        Self::check_access_token()?;

        // Build command with --output json flag
        let mut cmd_args: Vec<&str> = args.to_vec();
        cmd_args.push("--output");
        cmd_args.push("json");

        let output = Command::new("bws")
            .args(&cmd_args)
            .output()
            .map_err(Error::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::VaultExecutionFailed(stderr.trim().to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Err(Error::VaultParseError("Empty output".to_string()));
        }

        serde_json::from_str(&stdout).map_err(|e| Error::VaultParseError(e.to_string()))
    }

    fn is_available(&self) -> bool {
        Command::new("bws")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn help(&self) -> &'static str {
        "Bitwarden Secrets Manager CLI (bws)\n\
         \n\
         Requirements:\n\
         - Install: cargo install bws\n\
         - Set BWS_ACCESS_TOKEN environment variable\n\
         \n\
         Usage in templates:\n\
         {{ bitwardenSecrets(\"secret-uuid\") }}\n\
         {{ bitwardenSecrets(\"secret-uuid\").value }}"
    }
}
