//! Template context management
//!
//! The context provides data that is available to templates during rendering.

use crate::info::ConfigInfo;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::env;

/// Context data available to templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateContext {
    /// System information
    pub system: SystemInfo,

    /// Guisu-specific information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guisu: Option<GuisuInfo>,

    /// Environment variables
    pub env: IndexMap<String, String>,

    /// Custom user-defined variables
    /// These are flattened so they can be accessed directly in templates
    /// e.g., {{ `my_var` }} instead of {{ `variables.my_var` }}
    #[serde(flatten)]
    pub variables: IndexMap<String, serde_json::Value>,
}

/// Guisu-specific runtime information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuisuInfo {
    /// Source directory path (includes `root_entry`)
    #[serde(rename = "srcDir")]
    pub src_dir: String,

    /// Git working tree directory (repository root)
    #[serde(rename = "workingTree")]
    pub working_tree: String,

    /// Destination directory path
    #[serde(rename = "dstDir")]
    pub dst_dir: String,

    /// Root entry (subdirectory within source, defaults to "home")
    #[serde(rename = "rootEntry")]
    pub root_entry: String,

    /// Configuration object (exposed to templates)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigInfo>,
}

/// System information available to templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system (`"darwin"`, `"linux"`, `"windows"`, or `"unknown"`)
    pub os: String,

    /// Operating system family (e.g., "unix", "windows")
    #[serde(rename = "osFamily")]
    pub os_family: String,

    /// Linux distribution (e.g., "ubuntu", "fedora", "arch", "debian")
    /// Empty string on non-Linux systems
    pub distro: String,

    /// Linux distribution ID (lowercase, no spaces)
    #[serde(rename = "distroId")]
    pub distro_id: String,

    /// Linux distribution version (e.g., "22.04", "38")
    #[serde(rename = "distroVersion")]
    pub distro_version: String,

    /// Architecture (e.g., "`x86_64`", "aarch64")
    pub arch: String,

    /// Hostname
    pub hostname: String,

    /// Username
    pub username: String,

    /// User ID
    pub uid: String,

    /// Primary group ID
    pub gid: String,

    /// Primary group name
    pub group: String,

    /// Home directory path
    #[serde(rename = "homeDir")]
    pub home_dir: String,
}

impl TemplateContext {
    /// Create a new template context with system information
    #[must_use]
    pub fn new() -> Self {
        Self {
            system: SystemInfo::detect(),
            guisu: None,
            env: Self::collect_env(),
            variables: IndexMap::new(),
        }
    }

    /// Create a context with custom variables (takes ownership)
    ///
    /// For cases where you already have an owned `IndexMap`, this moves it without cloning.
    /// If you need to borrow the variables, use `with_variables_ref` instead.
    #[must_use]
    pub fn with_variables(mut self, variables: IndexMap<String, serde_json::Value>) -> Self {
        self.variables = variables;
        self
    }

    /// Create a context with custom variables (borrows and clones)
    ///
    /// This is a convenience method that accepts a reference and clones it internally.
    /// Use this when you need to preserve the original `IndexMap`.
    #[must_use]
    pub fn with_variables_ref(mut self, variables: &IndexMap<String, serde_json::Value>) -> Self {
        Clone::clone_from(&mut self.variables, variables);
        self
    }

    /// Set guisu-specific information (source and destination directories, rootEntry)
    #[must_use]
    pub fn with_guisu_info(
        mut self,
        src_dir: String,
        working_tree: String,
        dst_dir: String,
        root_entry: String,
    ) -> Self {
        self.guisu = Some(GuisuInfo {
            src_dir,
            working_tree,
            dst_dir,
            root_entry,
            config: None,
        });
        self
    }

    /// Convenience method to create a context with both variables and guisu info
    ///
    /// This is a common pattern used across CLI commands to set up template rendering.
    ///
    /// # Arguments
    ///
    /// * `source_abs` - Absolute path to the source directory (dotfiles)
    /// * `working_tree` - Working tree path (git root or source dir)
    /// * `dest_abs` - Absolute path to the destination directory
    /// * `root_entry` - Root entry path from config
    /// * `variables` - User-defined and system variables
    #[must_use]
    pub fn with_guisu_context(
        src_dir: String,
        working_tree: String,
        dst_dir: String,
        root_entry: String,
        variables: IndexMap<String, serde_json::Value>,
    ) -> Self {
        Self::new().with_variables(variables).with_guisu_info(
            src_dir,
            working_tree,
            dst_dir,
            root_entry,
        )
    }

    /// Set guisu-specific information with config
    #[must_use]
    pub fn with_guisu_info_and_config(
        mut self,
        src_dir: String,
        working_tree: String,
        dst_dir: String,
        root_entry: String,
        config: ConfigInfo,
    ) -> Self {
        self.guisu = Some(GuisuInfo {
            src_dir,
            working_tree,
            dst_dir,
            root_entry,
            config: Some(config),
        });
        self
    }

    /// Add a custom variable
    pub fn add_variable(&mut self, key: String, value: serde_json::Value) {
        self.variables.insert(key, value);
    }

    /// Load variables from .guisu/variables/ directory and merge with config variables
    ///
    /// This method:
    /// 1. Loads platform-specific variables from .guisu/variables/{platform}/
    /// 2. Loads common variables from .guisu/variables/
    /// 3. Merges with config.variables (config overrides file-based variables)
    ///
    /// # Arguments
    ///
    /// * `source_dir` - Path to the source directory (containing .guisu/)
    /// * `config` - Configuration containing user-defined variables
    ///
    /// # Returns
    ///
    /// Self with all variables loaded and merged
    ///
    /// # Errors
    ///
    /// Returns error if variables cannot be loaded from the source directory
    pub fn with_loaded_variables(
        mut self,
        source_dir: &std::path::Path,
        config: &guisu_config::Config,
    ) -> Result<Self, guisu_config::Error> {
        let guisu_dir = source_dir.join(".guisu");
        let platform_name = guisu_core::platform::CURRENT_PLATFORM.os;

        // Load variables from .guisu/variables/ directory
        let guisu_variables = if guisu_dir.exists() {
            guisu_config::variables::load_variables(&guisu_dir, platform_name)?
        } else {
            IndexMap::new()
        };

        // Merge variables: .guisu/variables/ first, then config (config overrides)
        let mut all_variables = guisu_variables;
        all_variables.extend(config.variables.iter().map(|(k, v)| (k.clone(), v.clone())));

        self.variables = all_variables;
        Ok(self)
    }

    /// Get an environment variable
    #[must_use]
    pub fn get_env(&self, key: &str) -> Option<&String> {
        self.env.get(key)
    }

    /// Collect environment variables
    fn collect_env() -> IndexMap<String, String> {
        env::vars().collect()
    }
}

impl Default for TemplateContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemInfo {
    /// Detect system information
    #[must_use]
    pub fn detect() -> Self {
        let (distro, distro_id, distro_version) = Self::detect_distro();

        Self {
            os: Self::detect_os(),
            os_family: Self::detect_os_family(),
            distro,
            distro_id,
            distro_version,
            arch: Self::detect_arch(),
            hostname: Self::detect_hostname(),
            username: Self::detect_username(),
            uid: Self::detect_uid(),
            gid: Self::detect_gid(),
            group: Self::detect_group(),
            home_dir: Self::detect_home_dir(),
        }
    }

    fn detect_os() -> String {
        #[cfg(target_os = "linux")]
        return "linux".to_string();

        #[cfg(target_os = "macos")]
        return "darwin".to_string();

        #[cfg(target_os = "windows")]
        return "windows".to_string();

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        return env::consts::OS.to_string();
    }

    fn detect_os_family() -> String {
        #[cfg(unix)]
        return "unix".to_string();

        #[cfg(windows)]
        return "windows".to_string();

        #[cfg(not(any(unix, windows)))]
        return env::consts::FAMILY.to_string();
    }

    fn detect_arch() -> String {
        env::consts::ARCH.to_string()
    }

    fn detect_hostname() -> String {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn detect_username() -> String {
        env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn detect_uid() -> String {
        #[cfg(unix)]
        {
            // Safe: rustix provides a safe wrapper around getuid()
            rustix::process::getuid().as_raw().to_string()
        }

        #[cfg(not(unix))]
        {
            String::new()
        }
    }

    fn detect_gid() -> String {
        #[cfg(unix)]
        {
            // Safe: rustix provides a safe wrapper around getgid()
            rustix::process::getgid().as_raw().to_string()
        }

        #[cfg(not(unix))]
        {
            String::new()
        }
    }

    fn detect_group() -> String {
        #[cfg(unix)]
        {
            // Safe: uzers provides a safe API for querying group information
            let gid = rustix::process::getgid();
            if let Some(group) = uzers::get_group_by_gid(gid.as_raw()) {
                return group.name().to_string_lossy().to_string();
            }
            String::new()
        }

        #[cfg(not(unix))]
        {
            String::new()
        }
    }

    fn detect_home_dir() -> String {
        dirs::home_dir()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string))
            .unwrap_or_default()
    }

    /// Detect Linux distribution information
    ///
    /// Returns (`distro_name`, `distro_id`, `distro_version`)
    ///
    /// On Linux, reads /etc/os-release file to determine the distribution.
    /// On non-Linux systems, returns empty strings.
    fn detect_distro() -> (String, String, String) {
        #[cfg(target_os = "linux")]
        {
            use std::fs;

            // Try to read /etc/os-release (standard location)
            let os_release_content = fs::read_to_string("/etc/os-release")
                .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
                .unwrap_or_default();

            let mut name = String::new();
            let mut id = String::new();
            let mut version = String::new();

            for line in os_release_content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some(value) = line.strip_prefix("NAME=") {
                    name = Self::unquote(value);
                } else if let Some(value) = line.strip_prefix("ID=") {
                    id = Self::unquote(value);
                } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
                    version = Self::unquote(value);
                }
            }

            // If we couldn't detect from os-release, try some fallbacks
            if id.is_empty() {
                if fs::metadata("/etc/fedora-release").is_ok() {
                    id = "fedora".to_string();
                } else if fs::metadata("/etc/debian_version").is_ok() {
                    id = "debian".to_string();
                } else if fs::metadata("/etc/arch-release").is_ok() {
                    id = "arch".to_string();
                } else if fs::metadata("/etc/redhat-release").is_ok() {
                    id = "rhel".to_string();
                }
            }

            (name, id, version)
        }

        #[cfg(not(target_os = "linux"))]
        {
            (String::new(), String::new(), String::new())
        }
    }

    /// Remove quotes from a string value
    #[cfg(target_os = "linux")]
    fn unquote(s: &str) -> String {
        let s = s.trim();
        if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn test_template_context_new() {
        let ctx = TemplateContext::new();

        assert!(ctx.guisu.is_none());
        assert!(!ctx.env.is_empty()); // Should have some env vars
        assert!(ctx.variables.is_empty());
    }

    #[test]
    fn test_template_context_default() {
        let ctx = TemplateContext::default();

        assert!(ctx.guisu.is_none());
        assert!(ctx.variables.is_empty());
    }

    #[test]
    fn test_with_variables_owned() {
        let mut vars = IndexMap::new();
        vars.insert("key1".to_string(), json!("value1"));
        vars.insert("key2".to_string(), json!(42));

        let ctx = TemplateContext::new().with_variables(vars.clone());

        assert_eq!(ctx.variables.get("key1"), Some(&json!("value1")));
        assert_eq!(ctx.variables.get("key2"), Some(&json!(42)));
    }

    #[test]
    fn test_with_variables_ref() {
        let mut vars = IndexMap::new();
        vars.insert("test".to_string(), json!("data"));

        let ctx = TemplateContext::new().with_variables_ref(&vars);

        assert_eq!(ctx.variables.get("test"), Some(&json!("data")));
        // Original should still exist
        assert!(vars.contains_key("test"));
    }

    #[test]
    fn test_add_variable() {
        let mut ctx = TemplateContext::new();

        ctx.add_variable("name".to_string(), json!("Alice"));
        ctx.add_variable("age".to_string(), json!(30));

        assert_eq!(ctx.variables.get("name"), Some(&json!("Alice")));
        assert_eq!(ctx.variables.get("age"), Some(&json!(30)));
    }

    #[test]
    fn test_with_guisu_info() {
        let ctx = TemplateContext::new().with_guisu_info(
            "/source".to_string(),
            "/working".to_string(),
            "/dest".to_string(),
            "home".to_string(),
        );

        assert!(ctx.guisu.is_some());
        let guisu = ctx.guisu.unwrap();
        assert_eq!(guisu.src_dir, "/source");
        assert_eq!(guisu.working_tree, "/working");
        assert_eq!(guisu.dst_dir, "/dest");
        assert_eq!(guisu.root_entry, "home");
        assert!(guisu.config.is_none());
    }

    #[test]
    fn test_with_guisu_info_and_config() {
        let config_info = crate::info::ConfigInfo {
            age: crate::info::AgeConfigInfo { derive: true },
            bitwarden: crate::info::BitwardenConfigInfo {
                provider: "bw".to_string(),
            },
            ui: crate::info::UiConfigInfo {
                icons: "auto".to_string(),
                diff_format: "unified".to_string(),
                context_lines: 3,
                preview_lines: 20,
            },
        };

        let ctx = TemplateContext::new().with_guisu_info_and_config(
            "/src".to_string(),
            "/work".to_string(),
            "/dst".to_string(),
            "root".to_string(),
            config_info,
        );

        assert!(ctx.guisu.is_some());
        let guisu = ctx.guisu.unwrap();
        assert_eq!(guisu.src_dir, "/src");
        assert!(guisu.config.is_some());
        let config = guisu.config.unwrap();
        assert_eq!(config.bitwarden.provider, "bw");
    }

    #[test]
    fn test_get_env() {
        let ctx = TemplateContext::new();

        // PATH should exist on all systems
        if let Ok(path_val) = env::var("PATH") {
            assert_eq!(ctx.get_env("PATH"), Some(&path_val));
        }

        // Non-existent var
        assert_eq!(ctx.get_env("NONEXISTENT_VAR_12345"), None);
    }

    #[test]
    fn test_system_info_detect() {
        let sys = SystemInfo::detect();

        // Basic assertions that should work on all platforms
        assert!(!sys.os.is_empty());
        assert!(!sys.os_family.is_empty());
        assert!(!sys.arch.is_empty());
        assert!(!sys.hostname.is_empty());
        assert!(!sys.username.is_empty());
        assert!(!sys.home_dir.is_empty());

        // Platform-specific checks
        #[cfg(target_os = "linux")]
        assert_eq!(sys.os, "linux");

        #[cfg(target_os = "macos")]
        assert_eq!(sys.os, "darwin");

        #[cfg(target_os = "windows")]
        assert_eq!(sys.os, "windows");

        #[cfg(unix)]
        assert_eq!(sys.os_family, "unix");

        #[cfg(windows)]
        assert_eq!(sys.os_family, "windows");
    }

    #[test]
    fn test_system_info_os_detection() {
        let os = SystemInfo::detect_os();

        #[cfg(target_os = "linux")]
        assert_eq!(os, "linux");

        #[cfg(target_os = "macos")]
        assert_eq!(os, "darwin");

        #[cfg(target_os = "windows")]
        assert_eq!(os, "windows");
    }

    #[test]
    fn test_system_info_os_family() {
        let family = SystemInfo::detect_os_family();

        #[cfg(unix)]
        assert_eq!(family, "unix");

        #[cfg(windows)]
        assert_eq!(family, "windows");
    }

    #[test]
    fn test_system_info_arch() {
        let arch = SystemInfo::detect_arch();

        assert!(!arch.is_empty());
        assert!(["x86_64", "aarch64", "arm", "x86"].contains(&arch.as_str()));
    }

    #[test]
    fn test_system_info_hostname() {
        let hostname = SystemInfo::detect_hostname();

        assert!(!hostname.is_empty());
        assert_ne!(hostname, "unknown"); // Should detect actual hostname
    }

    #[test]
    fn test_system_info_username() {
        let username = SystemInfo::detect_username();

        assert!(!username.is_empty());
    }

    #[test]
    fn test_system_info_home_dir() {
        let home = SystemInfo::detect_home_dir();

        assert!(!home.is_empty());
        #[cfg(unix)]
        assert!(home.starts_with('/'));

        #[cfg(windows)]
        assert!(home.contains('\\') || home.contains(':'));
    }

    #[test]
    #[cfg(unix)]
    fn test_system_info_uid_gid() {
        let sys = SystemInfo::detect();

        // UID and GID should be non-empty on Unix
        assert!(!sys.uid.is_empty());
        assert!(!sys.gid.is_empty());

        // Should be parseable as numbers
        assert!(sys.uid.parse::<u32>().is_ok());
        assert!(sys.gid.parse::<u32>().is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_system_info_group() {
        let group = SystemInfo::detect_group();

        // Group name should be detected (though it might be empty in some edge cases)
        // Just verify it doesn't panic
        let _ = group;
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_unquote_double_quotes() {
        assert_eq!(SystemInfo::unquote("\"Ubuntu\""), "Ubuntu");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_unquote_single_quotes() {
        assert_eq!(SystemInfo::unquote("'Fedora'"), "Fedora");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_unquote_no_quotes() {
        assert_eq!(SystemInfo::unquote("Arch"), "Arch");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_unquote_with_spaces() {
        assert_eq!(SystemInfo::unquote("  \"Debian\"  "), "Debian");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_detect_distro() {
        let (name, id, _version) = SystemInfo::detect_distro();

        // On Linux, should detect some distribution info
        // At minimum, one of these should be non-empty
        assert!(
            !name.is_empty() || !id.is_empty(),
            "Should detect at least distro name or ID on Linux"
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_detect_distro_non_linux() {
        let (name, id, version) = SystemInfo::detect_distro();

        // On non-Linux, should all be empty
        assert_eq!(name, "");
        assert_eq!(id, "");
        assert_eq!(version, "");
    }

    #[test]
    fn test_context_serialization() {
        let ctx = TemplateContext::new()
            .with_variables({
                let mut vars = IndexMap::new();
                vars.insert("test".to_string(), json!("value"));
                vars
            })
            .with_guisu_info(
                "/src".to_string(),
                "/work".to_string(),
                "/dst".to_string(),
                "home".to_string(),
            );

        // Should be able to serialize
        let serialized = serde_json::to_string(&ctx).expect("Serialization failed");
        assert!(serialized.contains("test"));
        assert!(serialized.contains("value"));

        // Should be able to deserialize
        let deserialized: TemplateContext =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(deserialized.variables.get("test"), Some(&json!("value")));
        assert!(deserialized.guisu.is_some());
    }

    #[test]
    fn test_guisu_info_serialization() {
        let guisu = GuisuInfo {
            src_dir: "/source".to_string(),
            working_tree: "/work".to_string(),
            dst_dir: "/dest".to_string(),
            root_entry: "home".to_string(),
            config: None,
        };

        let serialized = serde_json::to_string(&guisu).expect("Serialization failed");

        // Check renamed fields
        assert!(serialized.contains("srcDir"));
        assert!(serialized.contains("workingTree"));
        assert!(serialized.contains("dstDir"));
        assert!(serialized.contains("rootEntry"));

        // Should not contain Rust field names
        assert!(!serialized.contains("src_dir"));
        assert!(!serialized.contains("dst_dir"));
    }

    #[test]
    fn test_system_info_serialization() {
        let sys = SystemInfo::detect();

        let serialized = serde_json::to_string(&sys).expect("Serialization failed");

        // Check renamed fields
        assert!(serialized.contains("osFamily"));
        assert!(serialized.contains("homeDir"));

        // Check regular fields
        assert!(serialized.contains("hostname"));
        assert!(serialized.contains("username"));
    }

    #[test]
    fn test_with_loaded_variables() {
        use std::fs;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();
        let guisu_dir = source_dir.join(".guisu");
        let variables_dir = guisu_dir.join("variables");

        // Create .guisu/variables directory structure
        fs::create_dir_all(&variables_dir).unwrap();

        // Create a common variable file
        let common_toml = r#"
common_var = "common_value"
shared = "from_file"
"#;
        fs::write(variables_dir.join("common.toml"), common_toml).unwrap();

        // Create platform-specific variable
        let platform_name = guisu_core::platform::CURRENT_PLATFORM.os;
        let platform_dir = variables_dir.join(platform_name);
        fs::create_dir_all(&platform_dir).unwrap();

        let platform_toml = r#"
platform_var = "platform_value"
"#;
        fs::write(platform_dir.join("platform.toml"), platform_toml).unwrap();

        // Create config with variables that should override
        let mut config = guisu_config::Config::default();
        config
            .variables
            .insert("shared".to_string(), json!("from_config"));
        config
            .variables
            .insert("config_only".to_string(), json!("config_value"));

        let ctx = TemplateContext::new()
            .with_loaded_variables(source_dir, &config)
            .expect("Failed to load variables");

        // Variables are wrapped by file stem
        // common.toml becomes {"common": {"common_var": "...", "shared": "..."}}
        assert!(ctx.variables.contains_key("common"));
        let common = &ctx.variables["common"];
        assert_eq!(common["common_var"], json!("common_value"));

        // Platform variables are also wrapped
        assert!(ctx.variables.contains_key("platform"));
        let platform = &ctx.variables["platform"];
        assert_eq!(platform["platform_var"], json!("platform_value"));

        // Config variables are flat (not wrapped)
        assert_eq!(ctx.variables.get("shared"), Some(&json!("from_config")));
        assert_eq!(
            ctx.variables.get("config_only"),
            Some(&json!("config_value"))
        );
    }

    #[test]
    fn test_with_loaded_variables_no_guisu_dir() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // No .guisu directory exists
        let config = guisu_config::Config::default();

        let ctx = TemplateContext::new()
            .with_loaded_variables(source_dir, &config)
            .expect("Should succeed even without .guisu dir");

        // Should have empty variables (only from config, which is also empty)
        assert!(ctx.variables.is_empty());
    }

    #[test]
    fn test_with_loaded_variables_empty_guisu_dir() {
        use std::fs;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();
        let guisu_dir = source_dir.join(".guisu");

        // Create empty .guisu directory (no variables/ subdirectory)
        fs::create_dir_all(&guisu_dir).unwrap();

        let config = guisu_config::Config::default();

        let ctx = TemplateContext::new()
            .with_loaded_variables(source_dir, &config)
            .expect("Should succeed with empty .guisu dir");

        assert!(ctx.variables.is_empty());
    }
}
