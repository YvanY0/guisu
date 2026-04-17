//! Data format conversion functions
//!
//! Provides functions for converting between different data formats
//! including JSON and TOML.

use minijinja::Value;

/// Convert a value to JSON
///
/// Usage: `{{ some_data | toJson }}`
///
/// # Errors
///
/// Returns error if value cannot be converted to JSON
pub fn to_json(value: &Value) -> Result<String, minijinja::Error> {
    let json_value: serde_json::Value = serde_json::from_str(&value.to_string())
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));

    serde_json::to_string(&json_value)
        .map_err(|e| minijinja::Error::new(minijinja::ErrorKind::InvalidOperation, e.to_string()))
}

/// Parse a JSON string
///
/// Usage: `{{ json_string | fromJson }}`
///
/// # Errors
///
/// Returns error if value is not valid JSON
pub fn from_json(value: &str) -> Result<Value, minijinja::Error> {
    let json_value: serde_json::Value = serde_json::from_str(value).map_err(|e| {
        minijinja::Error::new(minijinja::ErrorKind::InvalidOperation, e.to_string())
    })?;

    Ok(Value::from_serialize(&json_value))
}

/// Convert a value to TOML format
///
/// # Usage
///
/// ```jinja2
/// {{ config | toToml }}
/// {{ {"name": "value"} | toToml }}
/// ```
///
/// # Errors
///
/// Returns error if value cannot be converted to TOML
pub fn to_toml(value: &Value) -> Result<String, minijinja::Error> {
    // Convert minijinja Value to serde_json::Value first
    let json_value: serde_json::Value = serde_json::from_str(&value.to_string())
        .or_else(|_| {
            // If direct parsing fails, try serializing the value
            serde_json::to_value(value).map_err(|e| e.to_string())
        })
        .map_err(|e| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("Failed to convert value: {e}"),
            )
        })?;

    // Convert to TOML
    toml::to_string(&json_value).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to serialize to TOML: {e}"),
        )
    })
}

/// Parse a TOML string
///
/// # Usage
///
/// ```jinja2
/// {{ toml_string | fromToml }}
/// {% set config = fromToml(file_content) %}
/// {{ config.database.host }}
/// ```
///
/// # Errors
///
/// Returns error if value is not valid TOML
pub fn from_toml(value: &str) -> Result<Value, minijinja::Error> {
    let toml_value: toml::Value = toml::from_str(value).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to parse TOML: {e}"),
        )
    })?;

    // Convert TOML value to JSON value for better compatibility
    let json_value: serde_json::Value = serde_json::to_value(&toml_value).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Failed to convert TOML to JSON: {e}"),
        )
    })?;

    Ok(Value::from_serialize(&json_value))
}
