//! Configuration information exposed to templates
//!
//! This module defines simplified configuration structures that are exposed
//! to the template engine. These are lighter-weight versions of the full
//! Config structs, containing only the information needed by templates.

use guisu_config::{Config, IconMode};
use serde::{Deserialize, Serialize};

/// Configuration information exposed to templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigInfo {
    /// Age encryption configuration
    pub age: AgeConfigInfo,

    /// Bitwarden configuration
    pub bitwarden: BitwardenConfigInfo,

    /// UI configuration
    pub ui: UiConfigInfo,
}

impl ConfigInfo {
    /// Create `ConfigInfo` from individual config components
    #[must_use]
    pub fn new(age: AgeConfigInfo, bitwarden: BitwardenConfigInfo, ui: UiConfigInfo) -> Self {
        Self { age, bitwarden, ui }
    }
}

/// Age configuration exposed to templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeConfigInfo {
    /// Whether to derive recipient from identity
    ///
    /// When enabled, the public key is automatically derived from the identity
    /// for encryption. The encryption still uses asymmetric age encryption.
    ///
    /// In templates, accessible as `{{ guisu.config.age.derive }}`.
    /// Legacy name `symmetric` is still supported for backward compatibility.
    #[serde(rename = "derive", alias = "symmetric")]
    pub derive: bool,
}

/// Bitwarden configuration exposed to templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfigInfo {
    /// Which Bitwarden CLI provider is used: "bw" or "bws"
    pub provider: String,
}

/// UI configuration exposed to templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfigInfo {
    /// Icon display mode: "auto", "always", or "never"
    pub icons: String,

    /// Diff format: "unified", "split", or "inline"
    #[serde(rename = "diffFormat")]
    pub diff_format: String,

    /// Number of context lines for diffs
    #[serde(rename = "contextLines")]
    pub context_lines: usize,

    /// Number of lines to show in preview
    #[serde(rename = "previewLines")]
    pub preview_lines: usize,
}

/// Convert from `guisu_config::Config` to `ConfigInfo`
///
/// This creates a simplified view of the configuration that is safe to expose
/// to templates. Sensitive information like identity file paths are not included.
impl From<&Config> for ConfigInfo {
    fn from(config: &Config) -> Self {
        ConfigInfo::new(
            AgeConfigInfo {
                derive: config.age.derive,
            },
            BitwardenConfigInfo {
                provider: config.bitwarden.provider.clone(),
            },
            UiConfigInfo {
                icons: match config.ui.icons {
                    IconMode::Auto => "auto".to_string(),
                    IconMode::Always => "always".to_string(),
                    IconMode::Never => "never".to_string(),
                },
                diff_format: config.ui.diff_format.clone(),
                context_lines: config.ui.context_lines,
                preview_lines: config.ui.preview_lines,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_config_info_new() {
        let age = AgeConfigInfo { derive: true };
        let bitwarden = BitwardenConfigInfo {
            provider: "bw".to_string(),
        };
        let ui = UiConfigInfo {
            icons: "auto".to_string(),
            diff_format: "unified".to_string(),
            context_lines: 3,
            preview_lines: 20,
        };

        let config = ConfigInfo::new(age.clone(), bitwarden.clone(), ui.clone());

        assert!(config.age.derive);
        assert_eq!(config.bitwarden.provider, "bw");
        assert_eq!(config.ui.icons, "auto");
        assert_eq!(config.ui.diff_format, "unified");
        assert_eq!(config.ui.context_lines, 3);
        assert_eq!(config.ui.preview_lines, 20);
    }

    #[test]
    fn test_age_config_info_serialization() {
        let age = AgeConfigInfo { derive: true };
        let serialized = serde_json::to_string(&age).unwrap();

        assert!(serialized.contains("\"derive\":true"));
        assert!(!serialized.contains("symmetric")); // Only in deserialization alias
    }

    #[test]
    fn test_age_config_info_deserialization() {
        // Test with "derive" field
        let json = r#"{"derive":true}"#;
        let age: AgeConfigInfo = serde_json::from_str(json).unwrap();
        assert!(age.derive);
    }

    #[test]
    fn test_age_config_info_deserialization_legacy_alias() {
        // Test backward compatibility with "symmetric" alias
        let json = r#"{"symmetric":false}"#;
        let age: AgeConfigInfo = serde_json::from_str(json).unwrap();
        assert!(!age.derive);
    }

    #[test]
    fn test_bitwarden_config_info_serialization() {
        let bw = BitwardenConfigInfo {
            provider: "bw".to_string(),
        };
        let serialized = serde_json::to_string(&bw).unwrap();

        assert!(serialized.contains("\"provider\":\"bw\""));
    }

    #[test]
    fn test_bitwarden_config_info_deserialization() {
        let json = r#"{"provider":"bw"}"#;
        let bw: BitwardenConfigInfo = serde_json::from_str(json).unwrap();
        assert_eq!(bw.provider, "bw");
    }

    #[test]
    fn test_ui_config_info_serialization() {
        let ui = UiConfigInfo {
            icons: "always".to_string(),
            diff_format: "split".to_string(),
            context_lines: 5,
            preview_lines: 30,
        };
        let serialized = serde_json::to_string(&ui).unwrap();

        // Check renamed fields
        assert!(serialized.contains("\"diffFormat\":\"split\""));
        assert!(serialized.contains("\"contextLines\":5"));
        assert!(serialized.contains("\"previewLines\":30"));

        // Should not contain Rust field names
        assert!(!serialized.contains("diff_format"));
        assert!(!serialized.contains("context_lines"));
        assert!(!serialized.contains("preview_lines"));
    }

    #[test]
    fn test_ui_config_info_deserialization() {
        let json = r#"{
            "icons": "never",
            "diffFormat": "inline",
            "contextLines": 7,
            "previewLines": 50
        }"#;
        let ui: UiConfigInfo = serde_json::from_str(json).unwrap();

        assert_eq!(ui.icons, "never");
        assert_eq!(ui.diff_format, "inline");
        assert_eq!(ui.context_lines, 7);
        assert_eq!(ui.preview_lines, 50);
    }

    #[test]
    fn test_config_info_serialization_roundtrip() {
        let original = ConfigInfo {
            age: AgeConfigInfo { derive: false },
            bitwarden: BitwardenConfigInfo {
                provider: "bw".to_string(),
            },
            ui: UiConfigInfo {
                icons: "auto".to_string(),
                diff_format: "unified".to_string(),
                context_lines: 3,
                preview_lines: 20,
            },
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: ConfigInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.age.derive, original.age.derive);
        assert_eq!(deserialized.bitwarden.provider, original.bitwarden.provider);
        assert_eq!(deserialized.ui.icons, original.ui.icons);
        assert_eq!(deserialized.ui.diff_format, original.ui.diff_format);
        assert_eq!(deserialized.ui.context_lines, original.ui.context_lines);
        assert_eq!(deserialized.ui.preview_lines, original.ui.preview_lines);
    }

    #[test]
    fn test_from_config_with_icon_mode_auto() {
        let mut config = Config::default();
        config.ui.icons = IconMode::Auto;

        let info = ConfigInfo::from(&config);
        assert_eq!(info.ui.icons, "auto");
    }

    #[test]
    fn test_from_config_with_icon_mode_always() {
        let mut config = Config::default();
        config.ui.icons = IconMode::Always;

        let info = ConfigInfo::from(&config);
        assert_eq!(info.ui.icons, "always");
    }

    #[test]
    fn test_from_config_with_icon_mode_never() {
        let mut config = Config::default();
        config.ui.icons = IconMode::Never;

        let info = ConfigInfo::from(&config);
        assert_eq!(info.ui.icons, "never");
    }

    #[test]
    fn test_from_config_preserves_all_fields() {
        let mut config = Config::default();
        config.age.derive = true;
        config.bitwarden.provider = "bw".to_string();
        config.ui.icons = IconMode::Always;
        config.ui.diff_format = "split".to_string();
        config.ui.context_lines = 10;
        config.ui.preview_lines = 100;

        let info = ConfigInfo::from(&config);

        assert!(info.age.derive);
        assert_eq!(info.bitwarden.provider, "bw");
        assert_eq!(info.ui.icons, "always");
        assert_eq!(info.ui.diff_format, "split");
        assert_eq!(info.ui.context_lines, 10);
        assert_eq!(info.ui.preview_lines, 100);
    }

    #[test]
    fn test_config_info_clone() {
        let original = ConfigInfo {
            age: AgeConfigInfo { derive: true },
            bitwarden: BitwardenConfigInfo {
                provider: "bw".to_string(),
            },
            ui: UiConfigInfo {
                icons: "auto".to_string(),
                diff_format: "unified".to_string(),
                context_lines: 3,
                preview_lines: 20,
            },
        };

        let cloned = original.clone();

        assert_eq!(cloned.age.derive, original.age.derive);
        assert_eq!(cloned.bitwarden.provider, original.bitwarden.provider);
        assert_eq!(cloned.ui.icons, original.ui.icons);
    }

    #[test]
    fn test_config_info_debug() {
        let config = ConfigInfo {
            age: AgeConfigInfo { derive: false },
            bitwarden: BitwardenConfigInfo {
                provider: "bw".to_string(),
            },
            ui: UiConfigInfo {
                icons: "never".to_string(),
                diff_format: "inline".to_string(),
                context_lines: 5,
                preview_lines: 30,
            },
        };

        let debug = format!("{config:?}");
        assert!(debug.contains("ConfigInfo"));
        assert!(debug.contains("derive"));
        assert!(debug.contains("provider"));
    }
}
