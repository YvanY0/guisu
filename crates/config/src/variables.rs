//! Variable loading from .guisu/variables/ directory structure

use crate::Result;
use indexmap::IndexMap;
use serde_json::Value as JsonValue;
use std::fs;
use std::path::Path;

/// Load variables from .guisu/variables/ directory
///
/// Loading order:
/// 1. Load all *.toml from variables/ (all platforms)
/// 2. Load all *.toml from variables/{platform}/ (platform-specific, overwrites same keys)
///
/// # Errors
///
/// Returns error if TOML files cannot be read or parsed
pub fn load_variables(guisu_dir: &Path, platform: &str) -> Result<IndexMap<String, JsonValue>> {
    use rayon::prelude::*;

    let mut variables = IndexMap::new();

    let variables_dir = guisu_dir.join("variables");
    if !variables_dir.exists() {
        return Ok(variables);
    }

    // 1. Load platform-agnostic variables (parallel file reading + parsing)
    if let Ok(entries) = fs::read_dir(&variables_dir) {
        let paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();

        let loaded: Vec<_> = paths
            .par_iter()
            .filter_map(|path| load_variable_file(path).ok().flatten())
            .collect();

        for var_file in loaded {
            let wrapped = IndexMap::from([(
                var_file.stem,
                JsonValue::Object(var_file.variables.into_iter().collect()),
            )]);
            merge_variables(&mut variables, wrapped);
        }
    }

    // 2. Load platform-specific variables (parallel, overwrites)
    let platform_dir = variables_dir.join(platform);
    if platform_dir.exists()
        && let Ok(entries) = fs::read_dir(&platform_dir)
    {
        let paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();

        let loaded: Vec<_> = paths
            .par_iter()
            .filter_map(|path| load_variable_file(path).ok().flatten())
            .collect();

        for var_file in loaded {
            let wrapped = IndexMap::from([(
                var_file.stem,
                JsonValue::Object(var_file.variables.into_iter().collect()),
            )]);
            merge_variables(&mut variables, wrapped);
        }
    }

    Ok(variables)
}

/// Represents a loaded variable file with its name and contents
#[derive(Debug)]
struct VariableFile {
    /// File name without extension (e.g., "colors" from "colors.toml")
    stem: String,
    /// Variables loaded from the file
    variables: IndexMap<String, JsonValue>,
}

/// Load a single variable file (TOML only)
/// Returns the file stem (name without extension) and the loaded variables
fn load_variable_file(path: &Path) -> Result<Option<VariableFile>> {
    // Only process .toml files
    if path.extension().and_then(|s| s.to_str()) != Some("toml") {
        return Ok(None);
    }

    // Get the filename without extension
    let file_stem = match path.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => stem.to_string(),
        None => return Ok(None),
    };

    let content = fs::read_to_string(path).map_err(|e| guisu_core::Error::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let value: toml::Value =
        toml::from_str(&content).map_err(|e| guisu_core::Error::InvalidConfig {
            message: format!("failed to parse TOML from {}: {e}", path.display()),
        })?;

    let json_value = serde_json::to_value(value).map_err(|e| guisu_core::Error::InvalidConfig {
        message: format!("failed to convert TOML to JSON: {e}"),
    })?;

    if let JsonValue::Object(map) = json_value {
        Ok(Some(VariableFile {
            stem: file_stem,
            variables: map.into_iter().collect(),
        }))
    } else {
        Ok(None)
    }
}

/// Deep merge two variable maps (second overwrites first on conflicts)
fn merge_variables(base: &mut IndexMap<String, JsonValue>, overlay: IndexMap<String, JsonValue>) {
    for (key, value) in overlay {
        match (base.get_mut(&key), &value) {
            (Some(JsonValue::Object(base_obj)), JsonValue::Object(overlay_obj)) => {
                // Recursively merge objects
                let mut base_map: IndexMap<String, JsonValue> =
                    base_obj.clone().into_iter().collect();
                let overlay_map: IndexMap<String, JsonValue> =
                    overlay_obj.clone().into_iter().collect();
                merge_variables(&mut base_map, overlay_map);
                *base_obj = base_map.into_iter().collect();
            }
            _ => {
                // Overwrite with new value
                base.insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_load_variables_empty_directory() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();

        let result = load_variables(guisu_dir, "linux").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_variables_nonexistent_directory() {
        let temp = TempDir::new().unwrap();
        let nonexistent = temp.path().join("nonexistent");

        let result = load_variables(&nonexistent, "linux").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_variables_single_file() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();
        let vars_dir = guisu_dir.join("variables");
        fs::create_dir_all(&vars_dir).unwrap();

        // Create a simple TOML file
        fs::write(
            vars_dir.join("app.toml"),
            r#"
name = "test-app"
version = "1.0"
"#,
        )
        .unwrap();

        let result = load_variables(guisu_dir, "linux").unwrap();

        assert!(result.contains_key("app"));
        let app = &result["app"];
        assert_eq!(app["name"], json!("test-app"));
        assert_eq!(app["version"], json!("1.0"));
    }

    #[test]
    fn test_load_variables_multiple_files() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();
        let vars_dir = guisu_dir.join("variables");
        fs::create_dir_all(&vars_dir).unwrap();

        fs::write(vars_dir.join("app.toml"), "name = 'app1'").unwrap();
        fs::write(vars_dir.join("db.toml"), "host = 'localhost'").unwrap();
        fs::write(vars_dir.join("api.toml"), "port = 8080").unwrap();

        let result = load_variables(guisu_dir, "linux").unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.contains_key("app"));
        assert!(result.contains_key("db"));
        assert!(result.contains_key("api"));
    }

    #[test]
    fn test_load_variables_platform_specific() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();
        let vars_dir = guisu_dir.join("variables");
        fs::create_dir_all(&vars_dir).unwrap();

        // Common variable
        fs::write(
            vars_dir.join("app.toml"),
            r#"
name = "app"
env = "default"
"#,
        )
        .unwrap();

        // Platform-specific override
        let linux_dir = vars_dir.join("linux");
        fs::create_dir_all(&linux_dir).unwrap();
        fs::write(
            linux_dir.join("app.toml"),
            r#"
env = "linux"
platform_key = "linux-specific"
"#,
        )
        .unwrap();

        let result = load_variables(guisu_dir, "linux").unwrap();

        assert!(result.contains_key("app"));
        let app = &result["app"];
        assert_eq!(app["name"], json!("app"));
        assert_eq!(app["env"], json!("linux")); // Overridden
        assert_eq!(app["platform_key"], json!("linux-specific"));
    }

    #[test]
    fn test_load_variables_ignores_non_toml() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();
        let vars_dir = guisu_dir.join("variables");
        fs::create_dir_all(&vars_dir).unwrap();

        fs::write(vars_dir.join("app.toml"), "name = 'test'").unwrap();
        fs::write(vars_dir.join("README.md"), "# Variables").unwrap();
        fs::write(vars_dir.join("config.json"), "{}").unwrap();
        fs::write(vars_dir.join("data.txt"), "text").unwrap();

        let result = load_variables(guisu_dir, "linux").unwrap();

        // Only .toml file should be loaded
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("app"));
    }

    #[test]
    fn test_load_variable_file_valid() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.toml");

        fs::write(&file_path, "key = 'value'\nnumber = 42").unwrap();

        let result = load_variable_file(&file_path).unwrap();
        assert!(result.is_some());

        let var_file = result.unwrap();
        assert_eq!(var_file.stem, "test");
        assert_eq!(var_file.variables.get("key"), Some(&json!("value")));
        assert_eq!(var_file.variables.get("number"), Some(&json!(42)));
    }

    #[test]
    fn test_load_variable_file_non_toml() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        fs::write(&file_path, "text content").unwrap();

        let result = load_variable_file(&file_path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_variable_file_invalid_toml() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("invalid.toml");

        fs::write(&file_path, "invalid toml [[[").unwrap();

        let result = load_variable_file(&file_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parse") || err.contains("TOML"));
    }

    #[test]
    fn test_load_variable_file_nonexistent() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("nonexistent.toml");

        let result = load_variable_file(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_variables_simple_overwrite() {
        let mut base = IndexMap::new();
        base.insert("key1".to_string(), json!("value1"));
        base.insert("key2".to_string(), json!(42));

        let mut overlay = IndexMap::new();
        overlay.insert("key2".to_string(), json!(100)); // Overwrite
        overlay.insert("key3".to_string(), json!("new")); // Add new

        merge_variables(&mut base, overlay);

        assert_eq!(base.get("key1"), Some(&json!("value1"))); // Unchanged
        assert_eq!(base.get("key2"), Some(&json!(100))); // Overwritten
        assert_eq!(base.get("key3"), Some(&json!("new"))); // Added
    }

    #[test]
    fn test_merge_variables_deep_merge_objects() {
        let mut base = IndexMap::new();
        base.insert(
            "app".to_string(),
            json!({
                "name": "base-app",
                "settings": {
                    "debug": false,
                    "port": 8080
                }
            }),
        );

        let mut overlay = IndexMap::new();
        overlay.insert(
            "app".to_string(),
            json!({
                "settings": {
                    "debug": true,
                    "host": "localhost"
                }
            }),
        );

        merge_variables(&mut base, overlay);

        let app = &base["app"];
        assert_eq!(app["name"], json!("base-app")); // Preserved
        assert_eq!(app["settings"]["debug"], json!(true)); // Overwritten
        assert_eq!(app["settings"]["port"], json!(8080)); // Preserved
        assert_eq!(app["settings"]["host"], json!("localhost")); // Added
    }

    #[test]
    fn test_merge_variables_overwrite_with_different_type() {
        let mut base = IndexMap::new();
        base.insert("key".to_string(), json!({"nested": "object"}));

        let mut overlay = IndexMap::new();
        overlay.insert("key".to_string(), json!("simple string"));

        merge_variables(&mut base, overlay);

        // Object should be completely replaced with string
        assert_eq!(base.get("key"), Some(&json!("simple string")));
    }

    #[test]
    fn test_merge_variables_empty_overlay() {
        let mut base = IndexMap::new();
        base.insert("key".to_string(), json!("value"));

        let overlay = IndexMap::new();

        merge_variables(&mut base, overlay);

        // Base should remain unchanged
        assert_eq!(base.get("key"), Some(&json!("value")));
    }

    #[test]
    fn test_merge_variables_empty_base() {
        let mut base = IndexMap::new();

        let mut overlay = IndexMap::new();
        overlay.insert("key".to_string(), json!("value"));

        merge_variables(&mut base, overlay);

        // Overlay values should be added to empty base
        assert_eq!(base.get("key"), Some(&json!("value")));
    }

    #[test]
    fn test_load_variables_nested_structures() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();
        let vars_dir = guisu_dir.join("variables");
        fs::create_dir_all(&vars_dir).unwrap();

        fs::write(
            vars_dir.join("complex.toml"),
            r#"
[database]
host = "localhost"
port = 5432

[database.credentials]
user = "admin"
password = "secret"

[[servers]]
name = "web1"
ip = "192.168.1.1"

[[servers]]
name = "web2"
ip = "192.168.1.2"
"#,
        )
        .unwrap();

        let result = load_variables(guisu_dir, "linux").unwrap();

        assert!(result.contains_key("complex"));
        let complex = &result["complex"];
        assert_eq!(complex["database"]["host"], json!("localhost"));
        assert_eq!(complex["database"]["credentials"]["user"], json!("admin"));
        assert!(complex["servers"].is_array());
    }

    #[test]
    fn test_load_variables_parallel_loading() {
        let temp = TempDir::new().unwrap();
        let guisu_dir = temp.path();
        let vars_dir = guisu_dir.join("variables");
        fs::create_dir_all(&vars_dir).unwrap();

        // Create multiple files to test parallel loading
        for i in 0..10 {
            fs::write(
                vars_dir.join(format!("file{i}.toml")),
                format!("value = {i}"),
            )
            .unwrap();
        }

        let result = load_variables(guisu_dir, "linux").unwrap();

        assert_eq!(result.len(), 10);
        for i in 0..10 {
            let key = format!("file{i}");
            assert!(result.contains_key(&key));
        }
    }
}
