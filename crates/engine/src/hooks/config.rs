//! Hook configuration structures
//!
//! Defines the core types for hook configuration including Hook definitions,
//! collections, stages, and execution modes.

use guisu_core::{Error, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::types::HookName;

/// Type alias for hook environment variables
pub type HookEnvVars = IndexMap<String, String>;

/// Collections of hooks for different stages
#[derive(Debug, Clone, Default, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct HookCollections {
    /// Hooks to run before applying dotfiles
    #[serde(default)]
    pub pre: Vec<Hook>,

    /// Hooks to run after applying dotfiles
    #[serde(default)]
    pub post: Vec<Hook>,
}

impl HookCollections {
    /// Check if there are no hooks defined
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pre.is_empty() && self.post.is_empty()
    }

    /// Get total number of hooks
    #[must_use]
    pub fn total(&self) -> usize {
        self.pre.len() + self.post.len()
    }
}

/// A single hook definition
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Hook {
    /// Name of the hook (for logging and identification)
    pub name: HookName,

    /// Execution order (lower numbers run first)
    #[serde(default = "default_order")]
    pub order: i32,

    /// Platforms this hook should run on (empty = all platforms)
    #[serde(default)]
    pub platforms: Vec<String>,

    /// Direct command to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,

    /// Path to script file to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,

    /// Script file content (for diffing, not loaded from TOML)
    #[serde(skip)]
    pub script_content: Option<String>,

    /// Environment variables to set
    #[serde(default)]
    #[bincode(with_serde)]
    pub env: HookEnvVars,

    /// Fail fast on error (default: true)
    ///
    /// If true, stop execution when this hook fails.
    /// If false, continue executing remaining hooks even if this one fails.
    #[serde(default = "default_failfast")]
    pub failfast: bool,

    /// Execution mode (always, once, onchange)
    ///
    /// - `always`: Run every time (default)
    /// - `once`: Run only once, tracked by name
    /// - `onchange`: Run when hook content changes, tracked by content hash
    #[serde(default)]
    pub mode: HookMode,

    /// Timeout in seconds (default: 0 = no timeout)
    ///
    /// Set to 0 or omit for no timeout. Otherwise, the hook will be terminated
    /// if it runs longer than the specified number of seconds.
    #[serde(default)]
    pub timeout: u64,
}

impl Hook {
    /// Get the content of this hook for hashing (used in onchange mode)
    ///
    /// Returns the cmd or script content that should be hashed to detect changes
    #[must_use]
    pub fn get_content(&self) -> String {
        if let Some(cmd) = &self.cmd {
            cmd.clone()
        } else if let Some(content) = &self.script_content {
            // Use actual script content if available (for onchange detection)
            content.clone()
        } else if let Some(script) = &self.script {
            // Fallback to script path if content not loaded
            script.clone()
        } else {
            String::new()
        }
    }

    /// Validate hook configuration
    ///
    /// Checks for:
    /// - Either cmd or script (but not both)
    /// - Valid platform names
    /// - Valid environment variable names
    /// - Non-empty name
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails (e.g., empty name, both cmd and script specified, invalid platform, invalid environment variable name)
    pub fn validate(&self) -> Result<()> {
        // Supported platforms
        const VALID_PLATFORMS: &[&str] = &["darwin", "linux", "windows"];

        // Note: Hook name validation happens during deserialization via HookName::deserialize

        // Check cmd/script exclusivity
        match (&self.cmd, &self.script) {
            (None, None) => {
                return Err(Error::HookConfig(format!(
                    "Hook '{}' must have either 'cmd' or 'script'",
                    self.name
                )));
            }
            (Some(_), Some(_)) => {
                return Err(Error::HookConfig(format!(
                    "Hook '{}' cannot have both 'cmd' and 'script'",
                    self.name
                )));
            }
            _ => {}
        }

        // Validate platform names

        for platform in &self.platforms {
            if !VALID_PLATFORMS.contains(&platform.as_str()) {
                tracing::warn!(
                    hook_name = %self.name,
                    platform = %platform,
                    "Hook specifies unknown platform (typo?). Valid platforms: {}",
                    VALID_PLATFORMS.join(", ")
                );
            }
        }

        // Validate environment variable names (basic check: alphanumeric + underscore)
        for (key, _value) in &self.env {
            if key.is_empty() {
                return Err(Error::HookConfig(format!(
                    "Hook '{}' has empty environment variable name",
                    self.name
                )));
            }

            // Check if env var name is valid (starts with letter/underscore, contains alphanumeric/underscore)
            if !key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            {
                return Err(Error::HookConfig(format!(
                    "Hook '{}' has invalid environment variable name '{}': must start with letter or underscore",
                    self.name, key
                )));
            }

            if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(Error::HookConfig(format!(
                    "Hook '{}' has invalid environment variable name '{}': must contain only alphanumeric characters and underscores",
                    self.name, key
                )));
            }
        }

        // Validate cmd/script is not empty
        if let Some(cmd) = &self.cmd
            && cmd.trim().is_empty()
        {
            return Err(Error::HookConfig(format!(
                "Hook '{}' has empty 'cmd' field",
                self.name
            )));
        }

        if let Some(script) = &self.script
            && script.trim().is_empty()
        {
            return Err(Error::HookConfig(format!(
                "Hook '{}' has empty 'script' field",
                self.name
            )));
        }

        Ok(())
    }

    /// Check if this hook should run on the given platform
    #[must_use]
    pub fn should_run_on(&self, platform: &str) -> bool {
        self.platforms.is_empty() || self.platforms.iter().any(|p| p == platform)
    }
}

/// Hook execution stage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStage {
    /// Before applying dotfiles
    Pre,
    /// After applying dotfiles
    Post,
}

impl HookStage {
    /// Get the string name of this hook stage
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            HookStage::Pre => "pre",
            HookStage::Post => "post",
        }
    }
}

/// Hook execution mode
///
/// Controls when a hook should be executed based on its execution history
/// and content changes.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    bincode::Encode,
    bincode::Decode,
)]
#[serde(rename_all = "lowercase")]
pub enum HookMode {
    /// Always run the hook (default behavior)
    #[default]
    Always,

    /// Run the hook only once, ever
    ///
    /// After successful execution, the hook will never run again unless
    /// the state is manually reset. Tracked by hook name in persistent state.
    Once,

    /// Run the hook when its content changes
    ///
    /// The hook's content (script or command) is hashed and compared with
    /// the previous execution. Runs again when the hash differs.
    OnChange,
}

/// Default order value
pub(crate) fn default_order() -> i32 {
    100
}

/// Default failfast value (true = stop on error)
pub(crate) fn default_failfast() -> bool {
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_hook_collections_default() {
        let collections = HookCollections::default();
        assert!(collections.pre.is_empty());
        assert!(collections.post.is_empty());
        assert!(collections.is_empty());
        assert_eq!(collections.total(), 0);
    }

    #[test]
    fn test_hook_collections_is_empty() {
        let mut collections = HookCollections::default();
        assert!(collections.is_empty());

        collections.pre.push(Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        });

        assert!(!collections.is_empty());
    }

    #[test]
    fn test_hook_collections_total() {
        let mut collections = HookCollections::default();
        assert_eq!(collections.total(), 0);

        collections.pre.push(create_test_hook("hook1"));
        assert_eq!(collections.total(), 1);

        collections.pre.push(create_test_hook("hook2"));
        assert_eq!(collections.total(), 2);

        collections.post.push(create_test_hook("hook3"));
        assert_eq!(collections.total(), 3);
    }

    fn create_test_hook(name: &str) -> Hook {
        Hook {
            name: HookName::new(name).unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        }
    }

    #[test]
    fn test_hook_get_content_cmd() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo hello".to_string()),
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        assert_eq!(hook.get_content(), "echo hello");
    }

    #[test]
    fn test_hook_get_content_script() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: None,
            script: Some("script.sh".to_string()),
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        assert_eq!(hook.get_content(), "script.sh");
    }

    #[test]
    fn test_hook_get_content_empty() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: None,
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        assert_eq!(hook.get_content(), "");
    }

    #[test]
    fn test_hook_validate_empty_name() {
        // Empty names are now rejected during HookName construction
        let result = HookName::new("");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("name cannot be empty")
        );
    }

    #[test]
    fn test_hook_validate_no_cmd_or_script() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: None,
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must have either"));
    }

    #[test]
    fn test_hook_validate_both_cmd_and_script() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: Some("script.sh".to_string()),
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot have both"));
    }

    #[test]
    fn test_hook_validate_valid_cmd() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_validate_valid_script() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: None,
            script: Some("script.sh".to_string()),
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_validate_empty_cmd() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("   ".to_string()),
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("empty 'cmd' field")
        );
    }

    #[test]
    fn test_hook_validate_empty_script() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: None,
            script: Some("   ".to_string()),
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("empty 'script' field")
        );
    }

    #[test]
    fn test_hook_validate_empty_env_var_name() {
        let mut env = IndexMap::new();
        env.insert(String::new(), "value".to_string());

        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env,
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("empty environment variable name")
        );
    }

    #[test]
    fn test_hook_validate_invalid_env_var_name_start() {
        let mut env = IndexMap::new();
        env.insert("123VAR".to_string(), "value".to_string());

        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env,
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with letter or underscore")
        );
    }

    #[test]
    fn test_hook_validate_invalid_env_var_name_chars() {
        let mut env = IndexMap::new();
        env.insert("VAR-NAME".to_string(), "value".to_string());

        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env,
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        let result = hook.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must contain only alphanumeric characters and underscores")
        );
    }

    #[test]
    fn test_hook_validate_valid_env_var_names() {
        let mut env = IndexMap::new();
        env.insert("VAR".to_string(), "value".to_string());
        env.insert("VAR_NAME".to_string(), "value".to_string());
        env.insert("_VAR".to_string(), "value".to_string());
        env.insert("VAR123".to_string(), "value".to_string());

        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env,
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_should_run_on_empty_platforms() {
        let hook = create_test_hook("test");
        assert!(hook.should_run_on("darwin"));
        assert!(hook.should_run_on("linux"));
        assert!(hook.should_run_on("windows"));
        assert!(hook.should_run_on("unknown"));
    }

    #[test]
    fn test_hook_should_run_on_specific_platforms() {
        let mut hook = create_test_hook("test");
        hook.platforms = vec!["darwin".to_string(), "linux".to_string()];

        assert!(hook.should_run_on("darwin"));
        assert!(hook.should_run_on("linux"));
        assert!(!hook.should_run_on("windows"));
        assert!(!hook.should_run_on("unknown"));
    }

    #[test]
    fn test_hook_stage_name() {
        assert_eq!(HookStage::Pre.name(), "pre");
        assert_eq!(HookStage::Post.name(), "post");
    }

    #[test]
    fn test_hook_mode_default() {
        let mode = HookMode::default();
        assert_eq!(mode, HookMode::Always);
    }

    #[test]
    fn test_hook_mode_serialization() {
        assert_eq!(
            serde_json::to_value(HookMode::Always).unwrap(),
            serde_json::json!("always")
        );
        assert_eq!(
            serde_json::to_value(HookMode::Once).unwrap(),
            serde_json::json!("once")
        );
        assert_eq!(
            serde_json::to_value(HookMode::OnChange).unwrap(),
            serde_json::json!("onchange")
        );
    }

    #[test]
    fn test_hook_mode_deserialization() {
        assert_eq!(
            serde_json::from_value::<HookMode>(serde_json::json!("always")).unwrap(),
            HookMode::Always
        );
        assert_eq!(
            serde_json::from_value::<HookMode>(serde_json::json!("once")).unwrap(),
            HookMode::Once
        );
        assert_eq!(
            serde_json::from_value::<HookMode>(serde_json::json!("onchange")).unwrap(),
            HookMode::OnChange
        );
    }

    #[test]
    fn test_default_order() {
        assert_eq!(default_order(), 100);
    }

    #[test]
    fn test_default_failfast() {
        assert!(default_failfast());
    }

    #[test]
    fn test_hook_serialization_toml() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec!["darwin".to_string()],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env: {
                let mut env = IndexMap::new();
                env.insert("KEY".to_string(), "value".to_string());
                env
            },
            failfast: true,
            mode: HookMode::OnChange,
            timeout: 30,
        };

        let toml = toml::to_string(&hook).unwrap();
        assert!(toml.contains("name = \"test\""));
        assert!(toml.contains("order = 100"));
        assert!(toml.contains("cmd = \"echo test\""));
        assert!(toml.contains("mode = \"onchange\""));
        assert!(toml.contains("timeout = 30"));
    }

    #[test]
    fn test_hook_deserialization_toml() {
        let toml = r#"
name = "test"
cmd = "echo hello"
mode = "once"
"#;

        let hook: Hook = toml::from_str(toml).unwrap();
        assert_eq!(hook.name.as_str(), "test");
        assert_eq!(hook.cmd, Some("echo hello".to_string()));
        assert_eq!(hook.mode, HookMode::Once);
        assert_eq!(hook.order, 100); // default
        assert!(hook.failfast); // default
    }

    #[test]
    fn test_hook_collections_serialization() {
        let mut collections = HookCollections::default();
        collections.pre.push(create_test_hook("hook1"));
        collections.post.push(create_test_hook("hook2"));

        let toml = toml::to_string(&collections).unwrap();
        assert!(toml.contains("[[pre]]"));
        assert!(toml.contains("[[post]]"));
        assert!(toml.contains("name = \"hook1\""));
        assert!(toml.contains("name = \"hook2\""));
    }

    #[test]
    fn test_hook_collections_deserialization() {
        let toml = r#"
[[pre]]
name = "pre-hook"
cmd = "echo pre"

[[post]]
name = "post-hook"
cmd = "echo post"
"#;

        let collections: HookCollections = toml::from_str(toml).unwrap();
        assert_eq!(collections.pre.len(), 1);
        assert_eq!(collections.post.len(), 1);
        assert_eq!(collections.pre[0].name.as_str(), "pre-hook");
        assert_eq!(collections.post[0].name.as_str(), "post-hook");
    }

    #[test]
    fn test_hook_with_script_content() {
        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 100,
            platforms: vec![],
            cmd: None,
            script: Some("install.sh".to_string()),
            script_content: Some("#!/bin/bash\necho installing".to_string()),
            env: IndexMap::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        };

        // script_content should be skipped in serialization
        let toml = toml::to_string(&hook).unwrap();
        assert!(!toml.contains("script_content"));

        // But it should still exist in the struct
        assert_eq!(
            hook.script_content,
            Some("#!/bin/bash\necho installing".to_string())
        );
    }

    #[test]
    fn test_hook_complex_validation() {
        let mut env = IndexMap::new();
        env.insert("VALID_VAR".to_string(), "value".to_string());
        env.insert("_ANOTHER".to_string(), "value2".to_string());

        let hook = Hook {
            name: HookName::new("test").unwrap(),
            order: 50,
            platforms: vec!["darwin".to_string(), "linux".to_string()],
            cmd: Some("echo 'complex command'".to_string()),
            script: None,
            script_content: None,
            env,
            failfast: false,
            mode: HookMode::OnChange,
            timeout: 120,
        };

        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_stage_equality() {
        assert_eq!(HookStage::Pre, HookStage::Pre);
        assert_eq!(HookStage::Post, HookStage::Post);
        assert_ne!(HookStage::Pre, HookStage::Post);
    }

    #[test]
    fn test_hook_mode_equality() {
        assert_eq!(HookMode::Always, HookMode::Always);
        assert_eq!(HookMode::Once, HookMode::Once);
        assert_eq!(HookMode::OnChange, HookMode::OnChange);
        assert_ne!(HookMode::Always, HookMode::Once);
        assert_ne!(HookMode::Once, HookMode::OnChange);
    }

    #[test]
    fn test_hook_clone() {
        let original = create_test_hook("test");
        let cloned = original.clone();

        assert_eq!(original.name.as_str(), cloned.name.as_str());
        assert_eq!(original.order, cloned.order);
        assert_eq!(original.cmd, cloned.cmd);
        assert_eq!(original.mode, cloned.mode);
    }

    #[test]
    fn test_hook_collections_clone() {
        let mut original = HookCollections::default();
        original.pre.push(create_test_hook("hook1"));

        let cloned = original.clone();
        assert_eq!(original.pre.len(), cloned.pre.len());
        assert_eq!(original.pre[0].name.as_str(), cloned.pre[0].name.as_str());
    }
}
