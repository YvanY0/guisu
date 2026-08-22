//! Variables command implementation
//!
//! Display all template variables available to guisu templates.

use anyhow::{Context, Result};
use clap::Args;
use guisu_template::TemplateContext;
use owo_colors::OwoColorize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use guisu_config::Config;

use crate::command::Command;
use crate::common::RuntimeContext;
use crate::utils::path::SourceDirExt;

/// Variables command arguments
#[derive(Debug, Args)]
pub struct VariablesCommand {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Show only builtin (system) variables
    #[arg(long)]
    pub builtin: bool,

    /// Show only user-defined variables
    #[arg(long)]
    pub user: bool,
}

impl Command for VariablesCommand {
    type Output = ();
    fn execute(&mut self, context: &mut RuntimeContext) -> crate::error::Result<()> {
        // Determine filter based on flags
        let filter = match (self.builtin, self.user) {
            (true, false) => VariableFilter::BuiltinOnly,
            (false, true) => VariableFilter::UserOnly,
            _ => VariableFilter::All, // Both or neither = show all
        };

        run_impl(context.source_dir(), &context.config, self.json, filter).map_err(Into::into)
    }
}

/// Which variables to display
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VariableFilter {
    /// Show all variables (builtin and user)
    All,
    /// Show only builtin variables
    BuiltinOnly,
    /// Show only user-defined variables
    UserOnly,
}

/// Data structure for variable output
#[derive(Debug, Serialize)]
struct VariableData {
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<SystemVariables>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guisu: Option<GuisuVariables>,
    #[serde(flatten)]
    variables: BTreeMap<String, serde_json::Value>,
}

/// System variables extracted from `TemplateContext`
#[derive(Debug, Serialize)]
struct SystemVariables {
    os: String,
    #[serde(rename = "osFamily")]
    os_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    distro: String,
    #[serde(rename = "distroId", skip_serializing_if = "String::is_empty")]
    distro_id: String,
    #[serde(rename = "distroVersion", skip_serializing_if = "String::is_empty")]
    distro_version: String,
    arch: String,
    hostname: String,
    username: String,
    uid: String,
    gid: String,
    group: String,
    #[serde(rename = "homeDir")]
    home_dir: String,
}

/// Guisu runtime variables
#[derive(Debug, Serialize)]
struct GuisuVariables {
    #[serde(rename = "srcDir")]
    src_dir: String,
    #[serde(rename = "workingTree")]
    working_tree: String,
    #[serde(rename = "dstDir")]
    dst_dir: String,
    #[serde(rename = "rootEntry", skip_serializing_if = "Option::is_none")]
    root_entry: Option<String>,
}

/// Run the variables command (implementation)
fn run_impl(source_dir: &Path, config: &Config, json: bool, filter: VariableFilter) -> Result<()> {
    // Create template context to get system variables
    let context = TemplateContext::new();

    // Collect system variables (only if needed)
    let system_vars = if matches!(filter, VariableFilter::All | VariableFilter::BuiltinOnly) {
        Some(SystemVariables {
            os: context.system.os.clone(),
            os_family: context.system.os_family.clone(),
            distro: context.system.distro.clone(),
            distro_id: context.system.distro_id.clone(),
            distro_version: context.system.distro_version.clone(),
            arch: context.system.arch.clone(),
            hostname: context.system.hostname.clone(),
            username: context.system.username.clone(),
            uid: context.system.uid.clone(),
            gid: context.system.gid.clone(),
            group: context.system.group.clone(),
            home_dir: context.system.home_dir,
        })
    } else {
        None
    };

    // Collect guisu runtime variables (only if needed)
    let guisu_vars = if matches!(filter, VariableFilter::All | VariableFilter::BuiltinOnly) {
        let dest_dir = dirs::home_dir().map_or_else(
            || "/home/unknown".to_string(),
            |p| crate::path_to_string(&p),
        );

        // Get the full dotfiles directory (including rootEntry if configured)
        let dotfiles_dir = config.dotfiles_dir(source_dir);

        // Get git working tree
        let working_tree = guisu_engine::git::find_working_tree(source_dir)
            .unwrap_or_else(|| source_dir.to_path_buf());

        Some(GuisuVariables {
            src_dir: crate::path_to_string(&dotfiles_dir),
            working_tree: crate::path_to_string(&working_tree),
            dst_dir: dest_dir,
            root_entry: Some(crate::path_to_string(&config.general.root_entry)),
        })
    } else {
        None
    };

    // Get user-defined variables from both .guisu/variables/ and config (only if needed)
    let user_variables = if matches!(filter, VariableFilter::All | VariableFilter::UserOnly) {
        // Load variables from .guisu/variables/ directory
        let guisu_dir = source_dir.guisu_dir();
        let platform_name = guisu_core::platform::CURRENT_PLATFORM.os;

        let mut all_vars = if guisu_dir.exists() {
            guisu_config::variables::load_variables(&guisu_dir, platform_name)
                .context("Failed to load variables from .guisu/variables/")?
        } else {
            indexmap::IndexMap::new()
        };

        // Merge with config variables (config overrides)
        all_vars.extend(config.variables.iter().map(|(k, v)| (k.clone(), v.clone())));

        all_vars.into_iter().collect()
    } else {
        BTreeMap::new()
    };

    // Combine into output data structure
    let data = VariableData {
        system: system_vars,
        guisu: guisu_vars,
        variables: user_variables,
    };

    // Output based on flag
    if json {
        output_json(&data)?;
    } else {
        output_pretty(&data);
    }

    Ok(())
}

/// Collect system variables into key-value pairs
fn collect_system_variables(system: &SystemVariables) -> Vec<(String, serde_json::Value)> {
    let mut vars = vec![
        (
            "system.os".to_string(),
            serde_json::Value::String(system.os.clone()),
        ),
        (
            "system.osFamily".to_string(),
            serde_json::Value::String(system.os_family.clone()),
        ),
    ];

    if !system.distro.is_empty() {
        vars.push((
            "system.distro".to_string(),
            serde_json::Value::String(system.distro.clone()),
        ));
    }
    if !system.distro_id.is_empty() {
        vars.push((
            "system.distroId".to_string(),
            serde_json::Value::String(system.distro_id.clone()),
        ));
    }
    if !system.distro_version.is_empty() {
        vars.push((
            "system.distroVersion".to_string(),
            serde_json::Value::String(system.distro_version.clone()),
        ));
    }

    vars.extend_from_slice(&[
        (
            "system.arch".to_string(),
            serde_json::Value::String(system.arch.clone()),
        ),
        (
            "system.hostname".to_string(),
            serde_json::Value::String(system.hostname.clone()),
        ),
        (
            "system.username".to_string(),
            serde_json::Value::String(system.username.clone()),
        ),
        (
            "system.uid".to_string(),
            serde_json::Value::String(system.uid.clone()),
        ),
        (
            "system.gid".to_string(),
            serde_json::Value::String(system.gid.clone()),
        ),
        (
            "system.group".to_string(),
            serde_json::Value::String(system.group.clone()),
        ),
        (
            "system.homeDir".to_string(),
            serde_json::Value::String(system.home_dir.clone()),
        ),
    ]);

    vars
}

/// Collect guisu variables into key-value pairs
fn collect_guisu_variables(guisu: &GuisuVariables) -> Vec<(String, serde_json::Value)> {
    let mut vars = vec![
        (
            "guisu.srcDir".to_string(),
            serde_json::Value::String(guisu.src_dir.clone()),
        ),
        (
            "guisu.workingTree".to_string(),
            serde_json::Value::String(guisu.working_tree.clone()),
        ),
        (
            "guisu.dstDir".to_string(),
            serde_json::Value::String(guisu.dst_dir.clone()),
        ),
    ];

    if let Some(ref root_entry) = guisu.root_entry {
        vars.push((
            "guisu.rootEntry".to_string(),
            serde_json::Value::String(root_entry.clone()),
        ));
    }

    vars
}

/// Collect all variables from data
fn collect_all_variables(data: &VariableData) -> Vec<(String, serde_json::Value)> {
    let mut all_vars = Vec::new();

    if let Some(system) = &data.system {
        all_vars.extend(collect_system_variables(system));
    }

    if let Some(guisu) = &data.guisu {
        all_vars.extend(collect_guisu_variables(guisu));
    }

    // Collect user variables
    let flattened_user = flatten_json_map(&data.variables, "");
    all_vars.extend(flattened_user);

    all_vars
}

/// Display a section of variables
fn display_variable_section(title: &str, vars: &[(String, serde_json::Value)], max_key_len: usize) {
    if !vars.is_empty() {
        println!("\n{}", title.bright_cyan().bold());
        println!("{}", "─".repeat(60).dimmed());
        for (key, value) in vars {
            print_variable_aligned(key, value, max_key_len);
        }
    }
}

/// Output in pretty/table format
fn output_pretty(data: &VariableData) {
    let all_vars = collect_all_variables(data);

    // Calculate maximum key length
    let max_key_len = all_vars.iter().map(|(k, _)| k.len()).max().unwrap_or(20);

    // Group variables by prefix
    let system_vars: Vec<_> = all_vars
        .iter()
        .filter(|(k, _)| k.starts_with("system."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let guisu_vars: Vec<_> = all_vars
        .iter()
        .filter(|(k, _)| k.starts_with("guisu."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let user_vars: Vec<_> = all_vars
        .iter()
        .filter(|(k, _)| !k.starts_with("system.") && !k.starts_with("guisu."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    display_variable_section("System variables:", &system_vars, max_key_len);
    display_variable_section("Guisu variables:", &guisu_vars, max_key_len);
    display_variable_section("User variables:", &user_vars, max_key_len);

    println!();
}

/// Flatten nested JSON objects into dot-notation keys
fn flatten_json_map(
    map: &BTreeMap<String, serde_json::Value>,
    prefix: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut result = BTreeMap::new();

    for (key, value) in map {
        let full_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };

        match value {
            serde_json::Value::Object(obj) => {
                // Recursively flatten nested objects
                let nested_map: BTreeMap<String, serde_json::Value> =
                    obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                let flattened = flatten_json_map(&nested_map, &full_key);
                result.extend(flattened);
            }
            _ => {
                result.insert(full_key, value.clone());
            }
        }
    }

    result
}

/// Print a single variable in pretty format with dynamic alignment
fn print_variable_aligned(key: &str, value: &serde_json::Value, width: usize) {
    let formatted_value = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "...".to_string())
        }
    };

    println!(
        "  {:<width$} {}",
        key.bright_yellow(),
        formatted_value.bright_white(),
        width = width
    );
}

/// Output in JSON format
fn output_json(data: &VariableData) -> Result<()> {
    let json =
        serde_json::to_string_pretty(data).context("Failed to serialize variables to JSON")?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn test_flatten_json_map_empty() {
        let map = BTreeMap::new();
        let result = flatten_json_map(&map, "");
        assert!(result.is_empty());
    }

    #[test]
    fn test_flatten_json_map_simple() {
        let mut map = BTreeMap::new();
        map.insert("name".to_string(), json!("John"));
        map.insert("age".to_string(), json!(30));

        let result = flatten_json_map(&map, "");

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("name"), Some(&json!("John")));
        assert_eq!(result.get("age"), Some(&json!(30)));
    }

    #[test]
    fn test_flatten_json_map_nested() {
        let mut map = BTreeMap::new();
        map.insert(
            "user".to_string(),
            json!({
                "name": "Alice",
                "email": "alice@example.com"
            }),
        );

        let result = flatten_json_map(&map, "");

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("user.name"), Some(&json!("Alice")));
        assert_eq!(result.get("user.email"), Some(&json!("alice@example.com")));
    }

    #[test]
    fn test_flatten_json_map_deeply_nested() {
        let mut map = BTreeMap::new();
        map.insert(
            "config".to_string(),
            json!({
                "server": {
                    "host": "localhost",
                    "port": 8080
                },
                "database": {
                    "name": "mydb"
                }
            }),
        );

        let result = flatten_json_map(&map, "");

        assert_eq!(result.len(), 3);
        assert_eq!(result.get("config.server.host"), Some(&json!("localhost")));
        assert_eq!(result.get("config.server.port"), Some(&json!(8080)));
        assert_eq!(result.get("config.database.name"), Some(&json!("mydb")));
    }

    #[test]
    fn test_flatten_json_map_with_prefix() {
        let mut map = BTreeMap::new();
        map.insert("name".to_string(), json!("Bob"));
        map.insert("role".to_string(), json!("admin"));

        let result = flatten_json_map(&map, "user");

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("user.name"), Some(&json!("Bob")));
        assert_eq!(result.get("user.role"), Some(&json!("admin")));
    }

    #[test]
    fn test_flatten_json_map_mixed_types() {
        let mut map = BTreeMap::new();
        map.insert("string".to_string(), json!("text"));
        map.insert("number".to_string(), json!(42));
        map.insert("bool".to_string(), json!(true));
        map.insert("null".to_string(), json!(null));
        map.insert("array".to_string(), json!([1, 2, 3]));

        let result = flatten_json_map(&map, "");

        assert_eq!(result.len(), 5);
        assert_eq!(result.get("string"), Some(&json!("text")));
        assert_eq!(result.get("number"), Some(&json!(42)));
        assert_eq!(result.get("bool"), Some(&json!(true)));
        assert_eq!(result.get("null"), Some(&json!(null)));
        assert_eq!(result.get("array"), Some(&json!([1, 2, 3])));
    }

    #[test]
    fn test_flatten_json_map_preserves_order() {
        let mut map = BTreeMap::new();
        // BTreeMap maintains sorted order
        map.insert("zebra".to_string(), json!("last"));
        map.insert("apple".to_string(), json!("first"));
        map.insert("banana".to_string(), json!("second"));

        let result = flatten_json_map(&map, "");

        // BTreeMap should maintain alphabetical order
        let keys: Vec<_> = result.keys().collect();
        assert_eq!(keys, vec!["apple", "banana", "zebra"]);
    }

    #[test]
    fn test_flatten_json_map_empty_nested_object() {
        let mut map = BTreeMap::new();
        map.insert("empty".to_string(), json!({}));
        map.insert("value".to_string(), json!("test"));

        let result = flatten_json_map(&map, "");

        // Empty object produces no flattened keys
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("value"), Some(&json!("test")));
        assert!(!result.contains_key("empty"));
    }

    #[test]
    fn test_system_variables_serialization() {
        let sys_vars = SystemVariables {
            os: "darwin".to_string(),
            os_family: "unix".to_string(),
            distro: String::new(),
            distro_id: String::new(),
            distro_version: String::new(),
            arch: "aarch64".to_string(),
            hostname: "test-host".to_string(),
            username: "testuser".to_string(),
            uid: "1000".to_string(),
            gid: "1000".to_string(),
            group: "staff".to_string(),
            home_dir: "/home/testuser".to_string(),
        };

        let json = serde_json::to_value(&sys_vars).expect("Failed to serialize");

        assert_eq!(json["os"], "darwin");
        assert_eq!(json["arch"], "aarch64");
        // Empty strings should be skipped
        assert!(json.get("distro").is_none());
        assert!(json.get("distroId").is_none());
    }

    #[test]
    fn test_guisu_variables_serialization() {
        let guisu_vars = GuisuVariables {
            src_dir: "/path/to/src".to_string(),
            working_tree: "/path/to/repo".to_string(),
            dst_dir: "/home/user".to_string(),
            root_entry: Some("home".to_string()),
        };

        let json = serde_json::to_value(&guisu_vars).expect("Failed to serialize");

        assert_eq!(json["srcDir"], "/path/to/src");
        assert_eq!(json["workingTree"], "/path/to/repo");
        assert_eq!(json["dstDir"], "/home/user");
        assert_eq!(json["rootEntry"], "home");
    }

    #[test]
    fn test_guisu_variables_serialization_no_root_entry() {
        let guisu_vars = GuisuVariables {
            src_dir: "/path/to/src".to_string(),
            working_tree: "/path/to/repo".to_string(),
            dst_dir: "/home/user".to_string(),
            root_entry: None,
        };

        let json = serde_json::to_value(&guisu_vars).expect("Failed to serialize");

        // None root_entry should be skipped
        assert!(json.get("rootEntry").is_none());
    }

    #[test]
    fn test_variable_data_serialization_complete() {
        let mut vars = BTreeMap::new();
        vars.insert("email".to_string(), json!("user@example.com"));

        let data = VariableData {
            system: Some(SystemVariables {
                os: "linux".to_string(),
                os_family: "unix".to_string(),
                distro: "Ubuntu".to_string(),
                distro_id: "ubuntu".to_string(),
                distro_version: "22.04".to_string(),
                arch: "x86_64".to_string(),
                hostname: "myhost".to_string(),
                username: "myuser".to_string(),
                uid: "1000".to_string(),
                gid: "1000".to_string(),
                group: "myuser".to_string(),
                home_dir: "/home/myuser".to_string(),
            }),
            guisu: Some(GuisuVariables {
                src_dir: "/src".to_string(),
                working_tree: "/repo".to_string(),
                dst_dir: "/home".to_string(),
                root_entry: Some("home".to_string()),
            }),
            variables: vars,
        };

        let json = serde_json::to_value(&data).expect("Failed to serialize");

        assert!(json.get("system").is_some());
        assert!(json.get("guisu").is_some());
        assert_eq!(json["email"], "user@example.com");
    }

    #[test]
    fn test_variable_data_serialization_user_only() {
        let mut vars = BTreeMap::new();
        vars.insert("name".to_string(), json!("Test"));

        let data = VariableData {
            system: None,
            guisu: None,
            variables: vars,
        };

        let json = serde_json::to_value(&data).expect("Failed to serialize");

        // None values should be skipped
        assert!(json.get("system").is_none());
        assert!(json.get("guisu").is_none());
        assert_eq!(json["name"], "Test");
    }

    #[test]
    fn test_flatten_json_map_with_array_values() {
        let mut map = BTreeMap::new();
        map.insert(
            "config".to_string(),
            json!({
                "tags": ["dev", "prod"],
                "ports": [8080, 8443]
            }),
        );

        let result = flatten_json_map(&map, "");

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("config.tags"), Some(&json!(["dev", "prod"])));
        assert_eq!(result.get("config.ports"), Some(&json!([8080, 8443])));
    }

    #[test]
    fn test_flatten_json_map_complex_nested_structure() {
        let mut map = BTreeMap::new();
        map.insert(
            "app".to_string(),
            json!({
                "name": "myapp",
                "server": {
                    "host": "localhost",
                    "ports": {
                        "http": 8080,
                        "https": 8443
                    }
                },
                "enabled": true
            }),
        );

        let result = flatten_json_map(&map, "");

        assert_eq!(result.len(), 5);
        assert_eq!(result.get("app.name"), Some(&json!("myapp")));
        assert_eq!(result.get("app.server.host"), Some(&json!("localhost")));
        assert_eq!(result.get("app.server.ports.http"), Some(&json!(8080)));
        assert_eq!(result.get("app.server.ports.https"), Some(&json!(8443)));
        assert_eq!(result.get("app.enabled"), Some(&json!(true)));
    }
}
