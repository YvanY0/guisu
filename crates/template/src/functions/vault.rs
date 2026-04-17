//! Password manager (vault) integration functions
//!
//! Provides functions for accessing secrets from password managers like Bitwarden.

use guisu_vault::SecretProvider;
#[cfg(feature = "bws")]
use guisu_vault::{CachedSecretProvider, bws::BwsCli};
use indexmap::IndexMap;
use minijinja::Value;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

// Bitwarden cache structure with separated provider and cache
// Cache stores JSON as SecretString for automatic memory zeroization
struct BitwardenCache {
    provider: Box<dyn SecretProvider>,
    cache: Mutex<IndexMap<String, SecretString>>,
}

impl BitwardenCache {
    fn new(provider_name: &str) -> Result<Self, guisu_vault::Error> {
        let provider = Self::create_provider(provider_name)?;
        Ok(Self {
            provider,
            cache: Mutex::new(IndexMap::new()),
        })
    }

    /// Create Bitwarden provider based on configuration
    ///
    /// This is application-layer logic that chooses which provider implementation
    /// to use based on user configuration.
    fn create_provider(provider_name: &str) -> Result<Box<dyn SecretProvider>, guisu_vault::Error> {
        match provider_name {
            #[cfg(feature = "bw")]
            "bw" => Ok(Box::new(guisu_vault::bw::BwCli::new())),

            #[cfg(feature = "bw")]
            "rbw" => Ok(Box::new(guisu_vault::bw::RbwCli::new())),

            _ => {
                // Build list of available providers based on enabled features
                let providers = [
                    #[cfg(feature = "bw")]
                    "bw",
                    #[cfg(feature = "bw")]
                    "rbw",
                ];

                Err(guisu_vault::Error::VaultProviderNotAvailable(format!(
                    "Unknown Bitwarden Vault provider: '{}'. Valid options: {}",
                    provider_name,
                    providers.join(", ")
                )))
            }
        }
    }

    fn get_or_fetch(&self, cmd_args: &[&str]) -> Result<JsonValue, guisu_vault::Error> {
        let cache_key = cmd_args.join("|");

        // Quick read-only check - deserialize from Secret<String>
        if let Ok(cache) = self.cache.lock()
            && let Some(cached_secret) = cache.get(&cache_key)
        {
            // Deserialize from exposed secret
            let json_str = cached_secret.expose_secret();
            return serde_json::from_str(json_str).map_err(|e| {
                guisu_vault::Error::Message(format!("Failed to deserialize cached secret: {e}"))
            });
        }

        // Fetch from provider
        let result = self.provider.execute(cmd_args)?;

        // Serialize to string and wrap in SecretString for automatic zeroization
        if let Ok(mut cache) = self.cache.lock()
            && let Ok(json_str) = serde_json::to_string(&result)
        {
            cache.insert(cache_key, SecretString::new(json_str.into()));
        }

        Ok(result)
    }
}

// Bitwarden cache singleton
// Since provider is configured once in config, we only need one cache instance
// The cache is initialized on first use with the configured provider
static BITWARDEN_CACHE: OnceLock<Mutex<HashMap<String, Arc<BitwardenCache>>>> = OnceLock::new();

// Cache for Bitwarden Secrets Manager CLI calls
#[cfg(feature = "bws")]
static BWS_CACHE: Mutex<Option<CachedSecretProvider<BwsCli>>> = Mutex::new(None);

/// Convert vault error to minijinja error
fn convert_error(e: guisu_vault::Error) -> minijinja::Error {
    use guisu_vault::Error;
    match e {
        Error::VaultCancelled => minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Operation cancelled by user",
        ),
        Error::VaultAuthenticationRequired(msg) => minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Authentication required: {msg}"),
        ),
        Error::VaultProviderNotAvailable(msg) => minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Provider not available: {msg}"),
        ),
        _ => minijinja::Error::new(minijinja::ErrorKind::InvalidOperation, e.to_string()),
    }
}

/// Access Bitwarden Vault items
///
/// Retrieves a Bitwarden vault item (password, note, identity, etc.) by its name or UUID.
/// The item data is cached for the duration of the template rendering session.
///
/// # Usage
///
/// ```jinja2
/// {# Get a Bitwarden item #}
/// api_key = {{ bitwarden("Google").login.password }}
/// username = {{ bitwarden("Google").login.username }}
/// ```
///
/// # Arguments
///
/// - `item_id`: The name or UUID of the Bitwarden item
/// - `provider_name`: The Bitwarden provider to use ("bw" or "rbw")
///
/// # Returns
///
/// Returns the full Bitwarden item as a JSON object with all fields.
///
/// # Environment
///
/// Requires either `bw` or `rbw` CLI to be installed and authenticated.
///
/// # Errors
///
/// Returns error if Bitwarden provider is not available or item retrieval fails
pub fn bitwarden(args: &[Value], provider_name: &str) -> Result<Value, minijinja::Error> {
    if args.is_empty() {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "bitwarden requires at least 1 argument: item_id",
        ));
    }

    let item_id = args[0].as_str().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Item ID must be a string",
        )
    })?;

    // Return the raw item directly
    bitwarden_get_raw("item", item_id, provider_name)
}

/// Internal function to get raw Bitwarden item
#[cfg(any(feature = "bw", feature = "rbw"))]
fn bitwarden_get_raw(
    item_type: &str,
    item_id: &str,
    provider_name: &str,
) -> Result<Value, minijinja::Error> {
    // Build command arguments based on provider
    let cmd_args: Vec<&str> = if provider_name == "rbw" {
        // rbw uses: rbw get --raw <name>
        vec!["get", "--raw", item_id]
    } else {
        // bw uses: bw get <type> <name>
        vec!["get", item_type, item_id]
    };

    // Get or initialize cache for this provider
    let caches = BITWARDEN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut caches = caches.lock().unwrap_or_else(|poisoned| {
        // Recover from poisoned lock - cache may be incomplete but we can rebuild it
        poisoned.into_inner()
    });

    // Get or create cache for this provider
    if !caches.contains_key(provider_name) {
        let new_cache = BitwardenCache::new(provider_name).map_err(convert_error)?;
        caches.insert(provider_name.to_string(), Arc::new(new_cache));
    }

    let cache = Arc::clone(caches.get(provider_name).expect("Cache was just inserted"));
    drop(caches); // Release lock before executing command

    // Fetch from cache
    let result = cache.get_or_fetch(&cmd_args).map_err(convert_error)?;

    Ok(Value::from_serialize(&result))
}

/// Get an attachment from a Bitwarden item
///
/// Retrieves an attachment file from a Bitwarden item using the Bitwarden CLI.
///
/// # Usage
///
/// ```jinja2
/// {# Get an attachment by filename and item ID #}
/// {{ bitwardenAttachment("config.json", "item-uuid") }}
///
/// {# Common use case: SSH keys, certificates, config files #}
/// {{ bitwardenAttachment("id_rsa", "ssh-keys-item") }}
/// {{ bitwardenAttachment("server.crt", "certificates") }}
/// ```
///
/// # Arguments
///
/// - `filename`: The name of the attachment file
/// - `item_id`: The name or UUID of the item containing the attachment
/// - `provider_name`: The Bitwarden provider to use ("bw" or "rbw")
///
/// # Command executed
///
/// This function executes: `bw get attachment <filename> --itemid <itemid> --raw`
///
/// # Important
///
/// - Only works with `bw` CLI (Bitwarden official CLI)
/// - `rbw` does not support attachments, so this function will fail if rbw is configured
/// - The attachment content is returned as a string
/// - Binary attachments will be returned as-is (you may need to handle encoding)
///
/// # Environment
///
/// Requires `bw` CLI to be installed and authenticated. The vault must be unlocked.
///
/// # Panics
///
/// Should not panic under normal circumstances. Cache access is protected by mutex.
///
/// # Errors
///
/// Returns error if Bitwarden CLI is not available or attachment retrieval fails
#[cfg(feature = "bw")]
pub fn bitwarden_attachment(
    args: &[Value],
    provider_name: &str,
) -> Result<String, minijinja::Error> {
    if args.len() < 2 {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "bitwardenAttachment requires 2 arguments: filename, item_id",
        ));
    }

    let filename = args[0].as_str().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Filename must be a string",
        )
    })?;

    let item_id = args[1].as_str().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Item ID must be a string",
        )
    })?;

    // rbw doesn't support attachments
    if provider_name == "rbw" {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "bitwardenAttachment is not supported with rbw. Please use bw (Bitwarden CLI) instead.",
        ));
    }

    // Build command: bw get attachment <filename> --itemid <itemid> --raw
    let cmd_args = vec!["get", "attachment", filename, "--itemid", item_id, "--raw"];

    // Get or initialize cache for this provider
    let caches = BITWARDEN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut caches = caches.lock().unwrap_or_else(|poisoned| {
        // Recover from poisoned lock - cache may be incomplete but we can rebuild it
        poisoned.into_inner()
    });

    // Get or create cache for this provider
    if !caches.contains_key(provider_name) {
        let new_cache = BitwardenCache::new(provider_name).map_err(convert_error)?;
        caches.insert(provider_name.to_string(), Arc::new(new_cache));
    }

    let cache = Arc::clone(caches.get(provider_name).expect("Cache was just inserted"));
    drop(caches); // Release lock before executing command

    // Fetch from cache
    let result = cache.get_or_fetch(&cmd_args).map_err(convert_error)?;

    // Extract string content from result
    let content = if let Some(s) = result.as_str() {
        s.to_string()
    } else {
        result.to_string()
    };

    Ok(content)
}

/// Get a specific field from a Bitwarden item's fields array
///
/// Retrieves a value from the custom fields array in a Bitwarden item.
/// Also supports shorthand access to common fields like username, password, and notes.
///
/// # Usage
///
/// ```jinja2
/// {# Get custom fields from fields array #}
/// api_key = {{ bitwardenFields("Google", "APIKey") }}
/// project = {{ bitwardenFields("Google", "VertexProject") }}
///
/// {# Shorthand for common fields #}
/// username = {{ bitwardenFields("Google", "username") }}
/// password = {{ bitwardenFields("Google", "password") }}
/// notes = {{ bitwardenFields("Google", "notes") }}
/// ```
///
/// # Arguments
///
/// - `item_id`: The name or UUID of the item
/// - `field_name`: The name of the field to extract from the fields array
/// - `provider_name`: The Bitwarden provider to use ("bw" or "rbw")
///
/// # Note
///
/// For accessing top-level item properties (like sshKey), use `bitwarden()` instead:
/// `{{ bitwarden("YvanYo-ssh").sshKey.publicKey }}`
///
/// # Environment
///
/// Requires either `bw` or `rbw` CLI to be installed and authenticated.
///
/// # Errors
///
/// Returns error if Bitwarden provider is not available or field retrieval fails
pub fn bitwarden_fields(args: &[Value], provider_name: &str) -> Result<Value, minijinja::Error> {
    if args.len() < 2 {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "bitwardenFields requires 2 arguments: item_id, field_name",
        ));
    }

    let item_id = args[0].as_str().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Item ID must be a string",
        )
    })?;

    let field_name = args[1].as_str().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Field name must be a string",
        )
    })?;

    // Get the raw item
    let item = bitwarden_get_raw("item", item_id, provider_name)?;

    // Extract the specific field
    get_single_field(&item, field_name)
}

/// Get a single field from a Bitwarden item
fn get_single_field(item: &Value, field_name: &str) -> Result<Value, minijinja::Error> {
    // Try to get the field from common locations
    // First check custom fields
    if let Ok(fields) = item.get_attr("fields") {
        // Try to iterate if it's an array-like value
        if let Ok(iter) = fields.try_iter() {
            for field in iter {
                // Get name and value separately to avoid lifetime issues
                let name_result = field.get_attr("name");
                let value_result = field.get_attr("value");

                if let (Ok(name_val), Ok(value)) = (name_result, value_result)
                    && let Some(name) = name_val.as_str()
                    && name == field_name
                {
                    return Ok(value);
                }
            }
        }
    }

    // Check common shorthand fields
    match field_name {
        "username" => {
            if let Ok(login) = item.get_attr("login")
                && let Ok(username) = login.get_attr("username")
            {
                return Ok(username);
            }
        }
        "password" => {
            if let Ok(login) = item.get_attr("login")
                && let Ok(password) = login.get_attr("password")
            {
                return Ok(password);
            }
        }
        "notes" => {
            if let Ok(notes) = item.get_attr("notes") {
                return Ok(notes);
            }
        }
        _ => {}
    }

    Err(minijinja::Error::new(
        minijinja::ErrorKind::InvalidOperation,
        format!("Field '{field_name}' not found in Bitwarden item"),
    ))
}

/// Access Bitwarden Secrets Manager secrets
///
/// This function retrieves secrets from Bitwarden Secrets Manager (organization secrets).
/// This is separate from Bitwarden Vault (personal/team passwords).
///
/// # Usage
///
/// ```jinja2
/// {# Get a secret by ID #}
/// api_key = {{ bitwardenSecrets("secret-uuid") }}
///
/// {# Get secret value directly #}
/// api_key = {{ bitwardenSecrets("secret-uuid").value }}
/// ```
///
/// # Arguments
///
/// - `secret_id`: The secret ID/UUID
///
/// # Requirements
///
/// - Install: `cargo install bws`
/// - Set `BWS_ACCESS_TOKEN` environment variable with your machine account token
///
/// # Environment Variables
///
/// - `BWS_ACCESS_TOKEN`: Required - Your Bitwarden Secrets Manager access token
///
/// # Errors
///
/// Returns error if BWS CLI is not available, access token is missing, or secret retrieval fails
#[cfg(feature = "bws")]
pub fn bitwarden_secrets(args: &[Value]) -> Result<Value, minijinja::Error> {
    if args.is_empty() {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "bitwardenSecrets requires a secret ID",
        ));
    }

    let secret_id = args[0].as_str().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Secret ID must be a string",
        )
    })?;

    // Build command: bws get <secret-id>
    let cmd_args = vec!["get", secret_id];

    // Get or create the cached provider
    let mut cache = BWS_CACHE.lock().unwrap_or_else(|poisoned| {
        // Recover from poisoned lock - cache may be lost but we can recreate it
        poisoned.into_inner()
    });

    if cache.is_none() {
        *cache = Some(CachedSecretProvider::new(BwsCli::new()));
    }

    let provider = cache.as_mut().ok_or_else(|| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Failed to initialize BWS cache provider",
        )
    })?;

    let result = provider.execute_cached(&cmd_args).map_err(convert_error)?;

    Ok(Value::from_serialize(&result))
}
