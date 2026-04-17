//! Bitwarden Vault integration
//!
//! Provides access to Bitwarden personal/team password vaults.
//! Supports two CLI implementations:
//! - `BwCli`: Official Bitwarden CLI (`bw`)
//! - `RbwCli`: Unofficial Rust-based CLI (`rbw`)
//!
//! Both provide the same functionality but use different CLI tools.
//! Template functions `bitwarden()` and `bitwardenFields()` use whichever
//! implementation is configured.
//!
//! # Security Warning
//!
//! **Session Key Exposure Risk**: The Bitwarden CLI (`bw`) requires passing the
//! session key via the `BW_SESSION` environment variable. This means the session key
//! is visible to other users via `ps aux` or similar process inspection tools.
//!
//! **Mitigation**:
//! - Use `rbw` instead of `bw` where possible (rbw uses a daemon with better security)
//! - Ensure your system is single-user or trusted
//! - Session keys expire after a timeout (default 30 minutes)
//! - Consider using Bitwarden's PIN unlock feature to minimize unlock frequency
//!
//! This is a limitation of the official `bw` CLI tool and cannot be fully mitigated
//! at the application level without modifications to the `bw` tool itself.

use crate::{Error, Result, SecretProvider};
use serde_json::Value as JsonValue;
use std::env;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use tracing::info;

/// Official Bitwarden CLI provider (`bw`)
///
/// Uses the official Node.js-based `bw` CLI with session-based authentication.
pub struct BwCli {
    /// Cached session key (`BW_SESSION`)
    session_key: Mutex<Option<String>>,
}

impl BwCli {
    /// Create a new Bitwarden CLI provider
    #[must_use]
    pub fn new() -> Self {
        // Try to get session from environment variable
        let session_key = env::var("BW_SESSION").ok();

        Self {
            session_key: Mutex::new(session_key),
        }
    }

    /// Get the current session key (from cache or environment)
    fn get_session_key(&self) -> Option<String> {
        // Check cache first
        if let Ok(guard) = self.session_key.lock()
            && let Some(ref session) = *guard
        {
            return Some(session.clone());
        }

        // Check environment variable
        if let Ok(session) = env::var("BW_SESSION") {
            // Cache it
            if let Ok(mut guard) = self.session_key.lock() {
                *guard = Some(session.clone());
            }
            return Some(session);
        }

        None
    }

    /// Cache session key
    fn cache_session_key(&self, session: String) {
        if let Ok(mut guard) = self.session_key.lock() {
            *guard = Some(session);
        }
    }

    /// Check vault status using `bw status`
    fn check_vault_status() -> Result<bool> {
        let output = Command::new("bw")
            .arg("status")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(Error::Io)?;

        if !output.status.success() {
            return Ok(false); // Assume locked if status command fails
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON status response
        // {"serverUrl":"...","lastSync":"...","userEmail":"...","userId":"...","status":"locked"}
        // or {"status":"unlocked"}
        if let Ok(status) = serde_json::from_str::<JsonValue>(&stdout)
            && let Some(status_str) = status.get("status").and_then(|s| s.as_str())
        {
            return Ok(status_str == "unlocked");
        }

        // If we can't parse, assume locked for safety
        Ok(false)
    }

    /// Try to unlock the vault interactively
    fn try_unlock() -> Result<String> {
        info!("Bitwarden vault is locked. Unlocking...");

        let output = Command::new("bw")
            .arg("unlock")
            .arg("--raw")
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .map_err(Error::Io)?;

        if !output.status.success() {
            if let Some(code) = output.status.code()
                && code == 1
            {
                return Err(Error::VaultCancelled);
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.is_empty() {
                return Err(Error::VaultAuthenticationRequired(
                    "Failed to unlock. Wrong password?".to_string(),
                ));
            }
            return Err(Error::VaultAuthenticationRequired(
                stderr.trim().to_string(),
            ));
        }

        let session_key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if session_key.is_empty() {
            return Err(Error::VaultAuthenticationRequired(
                "Failed to get session key".to_string(),
            ));
        }

        info!("✓ Vault unlocked successfully");
        Ok(session_key)
    }

    /// Execute bw command with auto-unlock
    fn execute_with_unlock(&self, args: &[&str]) -> Result<JsonValue> {
        // Check vault status first using `bw status`
        let is_unlocked = Self::check_vault_status()?;

        // If vault is locked, unlock it first
        let session_key = if is_unlocked {
            // Use cached session key if available
            self.get_session_key()
        } else {
            let key = Self::try_unlock()?;
            self.cache_session_key(key.clone());
            Some(key)
        };

        // Execute the actual command with session key
        let mut cmd = Command::new("bw");
        cmd.args(args).env("NODE_OPTIONS", "--no-deprecation");

        if let Some(ref session) = session_key {
            // SECURITY NOTE: Passing session key via environment variable exposes it
            // to other users via process inspection (ps aux, /proc/<pid>/environ).
            // This is a limitation of the `bw` CLI design - consider using `rbw` instead.
            // See module documentation for details and mitigation strategies.
            cmd.env("BW_SESSION", session);
        }

        let output = cmd.output().map_err(Error::Io)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(Error::VaultExecutionFailed(format!(
                "Command failed: {}",
                if stderr.trim().is_empty() {
                    "Unknown error"
                } else {
                    stderr.trim()
                }
            )));
        }

        Self::parse_json(&stdout)
    }

    fn parse_json(stdout: &str) -> Result<JsonValue> {
        if stdout.trim().is_empty() {
            return Err(Error::VaultParseError("Empty output".to_string()));
        }

        serde_json::from_str(stdout).map_err(|e| Error::VaultParseError(e.to_string()))
    }
}

impl Default for BwCli {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for BwCli {
    fn name(&self) -> &'static str {
        "bw"
    }

    fn execute(&self, args: &[&str]) -> Result<JsonValue> {
        if args.is_empty() {
            return Err(Error::VaultInvalidArguments(
                "At least one argument required".to_string(),
            ));
        }

        self.execute_with_unlock(args)
    }

    fn is_available(&self) -> bool {
        Command::new("bw")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn help(&self) -> &'static str {
        "Official Bitwarden CLI (bw)\n\
         \n\
         Requirements:\n\
         - Install: npm install -g @bitwarden/cli\n\
         - Login: bw login\n\
         - The vault will be unlocked automatically when needed\n\
         \n\
         Usage in templates:\n\
         {{ bitwarden(\"GitHub\") }}\n\
         {{ bitwardenFields(\"GitHub\", \"username\") }}"
    }
}

/// Unofficial Rust-based Bitwarden CLI provider (`rbw`)
///
/// Uses the Rust-based `rbw` CLI with daemon-based authentication.
///
/// # Important differences from `BwCli`:
///
/// - Daemon-based: rbw uses a background daemon (`rbw-agent`) that handles vault state
/// - No session keys: The daemon manages authentication, no `BW_SESSION` env var needed
/// - Different JSON format: rbw outputs `data` field instead of `login`, requires mapping
/// - Unlock check: Use `rbw unlocked` to check vault status
pub struct RbwCli;

impl RbwCli {
    /// Create a new rbw provider instance
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Transform rbw JSON format to bw-compatible format
    ///
    /// rbw uses different field names and structures than bw CLI.
    /// This method transforms rbw output to match bw format internally.
    ///
    /// # Format Differences
    ///
    /// For login items (type 1):
    /// - rbw: `data.username`, `data.password`
    /// - bw: `login.username`, `login.password`
    ///
    /// For SSH keys (type 5):
    /// - rbw: `data.public_key`, `data.fingerprint` (`snake_case`)
    /// - bw: `sshKey.privateKey`, `sshKey.publicKey` (`camelCase`)
    ///
    /// # Known Limitations
    ///
    /// rbw does NOT provide `private_key` for SSH items - only `public_key`
    /// and `fingerprint`. If you need SSH private keys in templates, use
    /// the bw CLI instead.
    fn transform_to_bw_format(json: &mut JsonValue) {
        if let Some(obj) = json.as_object_mut()
            && let Some(data) = obj.get("data").cloned()
        {
            // Determine item type from data content (rbw doesn't include 'type' field)
            // Check if this is an SSH key by looking for SSH key fields in data
            let is_ssh_key = if let Some(data_obj) = data.as_object() {
                data_obj.contains_key("public_key")
                    || data_obj.contains_key("private_key")
                    || data_obj.contains_key("fingerprint")
            } else {
                false
            };

            if is_ssh_key {
                // SSH Key: map data.private_key/public_key to sshKey.privateKey/publicKey
                if let Some(data_obj) = data.as_object() {
                    let mut ssh_key = serde_json::Map::new();

                    // Map snake_case to camelCase
                    if let Some(private_key) = data_obj.get("private_key") {
                        ssh_key.insert("privateKey".to_string(), private_key.clone());
                    }

                    if let Some(public_key) = data_obj.get("public_key") {
                        ssh_key.insert("publicKey".to_string(), public_key.clone());
                    }

                    // Also add fingerprint if available (not in bw, but useful)
                    if let Some(fingerprint) = data_obj.get("fingerprint") {
                        ssh_key.insert("fingerprint".to_string(), fingerprint.clone());
                    }

                    obj.insert("sshKey".to_string(), JsonValue::Object(ssh_key));
                }
            } else {
                // Login and other types: copy data to login
                obj.insert("login".to_string(), data);
            }
        }
    }

    /// Execute rbw command and return parsed JSON in bw-compatible format
    ///
    /// This method executes the rbw command and transforms the output to match
    /// the bw CLI format, ensuring compatibility with templates that expect
    /// bw-style JSON structures.
    ///
    /// rbw handles all state management automatically:
    /// - Starts daemon if not running
    /// - Prompts for unlock if vault is locked
    ///
    /// # Arguments
    ///
    /// * `args` - Command arguments to pass to rbw
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Command execution fails
    /// - JSON parsing fails
    ///
    /// # Known Limitations
    ///
    /// - SSH private keys: rbw does not return `private_key` field for SSH items.
    ///   Only `public_key` and `fingerprint` are available. Use bw CLI if you need
    ///   to access SSH private keys in templates.
    fn execute_rbw(args: &[&str]) -> Result<JsonValue> {
        // Execute rbw - it handles daemon startup and unlocking automatically
        let output = Command::new("rbw")
            .args(args)
            .stdin(Stdio::inherit()) // Allow rbw to prompt for password if needed
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(Error::Io)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check for execution errors
        if !output.status.success() {
            // Check for common error cases
            if stderr.contains("not found") || stderr.contains("no entry") {
                return Err(Error::VaultSecretNotFound(format!(
                    "Entry not found: {}",
                    stderr.trim()
                )));
            }

            // Return rbw's original error message for all other cases
            return Err(Error::VaultExecutionFailed(format!(
                "rbw error: {}",
                stderr.trim()
            )));
        }

        // Parse and transform to bw-compatible format
        Self::parse_and_transform(&stdout)
    }

    /// Parse rbw JSON output and transform to bw-compatible format
    ///
    /// This method handles all format conversions internally, so external
    /// code can treat rbw output the same as bw output.
    fn parse_and_transform(stdout: &str) -> Result<JsonValue> {
        if stdout.trim().is_empty() {
            return Err(Error::VaultParseError("Empty output from rbw".to_string()));
        }

        let mut json: JsonValue = serde_json::from_str(stdout)
            .map_err(|e| Error::VaultParseError(format!("Failed to parse rbw JSON: {e}")))?;

        // Transform rbw format to bw-compatible format internally
        Self::transform_to_bw_format(&mut json);

        Ok(json)
    }
}

impl Default for RbwCli {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for RbwCli {
    fn name(&self) -> &'static str {
        "rbw"
    }

    fn execute(&self, args: &[&str]) -> Result<JsonValue> {
        if args.is_empty() {
            return Err(Error::VaultInvalidArguments(
                "At least one argument required".to_string(),
            ));
        }

        Self::execute_rbw(args)
    }

    fn is_available(&self) -> bool {
        // Check if rbw command exists
        Command::new("rbw")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn help(&self) -> &'static str {
        "Unofficial Rust Bitwarden CLI (rbw)\n\
         \n\
         Requirements:\n\
         - Install: cargo install rbw (or via package manager)\n\
         - Login: rbw login <email>\n\
         - Start daemon: rbwctl start\n\
         \n\
         Note: Unlike the official 'bw' CLI, rbw uses a background daemon\n\
         that manages vault state. If the vault is locked, rbw will automatically\n\
         prompt you to unlock it via pinentry.\n\
         \n\
         Usage in templates:\n\
         {{ bitwarden(\"GitHub\") }}\n\
         {{ bitwardenFields(\"GitHub\", \"username\") }}"
    }
}

// Implement VaultProvider trait for BwCli
impl guisu_core::VaultProvider for BwCli {
    fn name(&self) -> &'static str {
        "bitwarden (bw)"
    }

    fn is_available(&self) -> bool {
        SecretProvider::is_available(self)
    }

    fn requires_unlock(&self) -> bool {
        true // bw CLI requires session management
    }

    fn unlock(&mut self) -> guisu_core::Result<()> {
        if let Ok(true) = Self::check_vault_status() {
            Ok(()) // Already unlocked
        } else {
            let session =
                Self::try_unlock().map_err(|e| guisu_core::Error::Message(e.to_string()))?;
            self.cache_session_key(session);
            Ok(())
        }
    }

    fn get_secret(&self, key: &str) -> guisu_core::Result<String> {
        self.execute(&["get", "item", key])
            .and_then(|v| {
                v.as_str()
                    .map(std::string::ToString::to_string)
                    .ok_or(Error::VaultParseError("Expected string value".to_string()))
            })
            .map_err(|e| guisu_core::Error::Message(e.to_string()))
    }
}

// Implement VaultProvider trait for RbwCli
impl guisu_core::VaultProvider for RbwCli {
    fn name(&self) -> &'static str {
        "bitwarden (rbw)"
    }

    fn is_available(&self) -> bool {
        SecretProvider::is_available(self)
    }

    fn requires_unlock(&self) -> bool {
        false // rbw daemon handles unlocking automatically
    }

    fn unlock(&mut self) -> guisu_core::Result<()> {
        Ok(()) // rbw handles unlocking via daemon
    }

    fn get_secret(&self, key: &str) -> guisu_core::Result<String> {
        self.execute(&["get", key])
            .and_then(|v| {
                v.as_str()
                    .map(std::string::ToString::to_string)
                    .ok_or(Error::VaultParseError("Expected string value".to_string()))
            })
            .map_err(|e| guisu_core::Error::Message(e.to_string()))
    }
}
