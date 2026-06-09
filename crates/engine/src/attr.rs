//! File attribute parsing and encoding
//!
//! This module handles parsing of source file attributes.
//!
//! # Attribute Encoding
//!
//! Attributes are encoded using file extensions and the source file's
//! actual Unix mode bits:
//!
//! - `.j2` - File is a Jinja2 template
//! - `.age` - File is encrypted with age
//! - `.j2.age` - Template that is encrypted (edit decrypts, render encrypts)
//!
//! Permission mode is the source file's real `metadata().mode()`. It is the
//! source of truth and is **not** derived from a filename prefix.
//!
//! The target filename strips recognized extensions (`.j2`, `.age`,
//! `.j2.age`); that's how guisu names the destination file when the source
//! uses these.
//!
//! # Examples
//!
//! ```
//! use guisu_engine::attr::FileAttributes;
//!
//! # fn main() {
//! // Template file: .j2 extension is stripped from the target name
//! let (attrs, name) = FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644));
//! assert!(attrs.is_template);
//! assert_eq!(name, ".gitconfig");
//! assert_eq!(attrs.mode(), Some(0o644));
//! # }
//! ```

use serde::{Deserialize, Serialize};

/// Attributes parsed from a source file's name and metadata.
///
/// `is_template` and `is_encrypted` are derived from file extensions. The
/// `mode` field is the source file's real Unix mode bits — it is the source
/// of truth for permissions and is **not** derived from a filename prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileAttributes {
    /// Whether the file is a Jinja2 template (`.j2` extension).
    pub is_template: bool,
    /// Whether the file is encrypted (`.age` extension).
    pub is_encrypted: bool,
    /// The source file's Unix mode bits, propagated to the destination by
    /// `apply` and compared against the destination's mode by `diff`.
    #[serde(default)]
    pub mode: Option<u32>,
}

impl FileAttributes {
    /// Create attributes with all flags set to false and no mode
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The source file's Unix mode bits (if known).
    ///
    /// `apply` propagates this to the destination, and `diff` reports any
    /// difference between this and the destination's mode. The value comes
    /// straight from the source file's metadata.
    #[must_use]
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }

    /// Parse attributes from a source filename
    ///
    /// The returned target name strips recognized extensions (`.j2`, `.age`,
    /// `.j2.age`) — that's how guisu names the destination file when the
    /// source uses these.
    ///
    /// The `mode` argument is the source file's real Unix mode bits and is
    /// exposed via [`FileAttributes::mode`].
    #[allow(clippy::must_use_candidate)] // returns (attrs, name) — both used at call sites
    pub fn parse_from_source(filename: &str, mode: Option<u32>) -> (Self, String) {
        let mut attrs = Self {
            is_template: false,
            is_encrypted: false,
            mode,
        };
        let mut target_name = filename.to_string();

        // Strip .age extension (must be stripped last so .j2.age works).
        if target_name.to_lowercase().ends_with(".age") {
            attrs.is_encrypted = true;
            target_name.truncate(target_name.len() - ".age".len());
        }

        // Strip .j2 extension (after .age so .j2.age order works).
        if target_name.to_lowercase().ends_with(".j2") {
            attrs.is_template = true;
            target_name.truncate(target_name.len() - ".j2".len());
        }

        (attrs, target_name)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_new_attributes() {
        let attrs = FileAttributes::new();
        assert!(!attrs.is_template);
        assert!(!attrs.is_encrypted);
        assert_eq!(attrs.mode(), None);
    }

    #[test]
    fn test_parse_template_strips_extension() {
        let (attrs, name) = FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644));
        assert!(attrs.is_template);
        assert!(!attrs.is_encrypted);
        assert_eq!(name, ".gitconfig");
        assert_eq!(attrs.mode(), Some(0o644));
    }

    #[test]
    fn test_parse_encrypted_strips_extension() {
        let (attrs, name) = FileAttributes::parse_from_source("secrets.age", Some(0o600));
        assert!(attrs.is_encrypted);
        assert!(!attrs.is_template);
        assert_eq!(name, "secrets");
        assert_eq!(attrs.mode(), Some(0o600));
    }

    #[test]
    fn test_parse_encrypted_template_strips_both_extensions() {
        let (attrs, name) = FileAttributes::parse_from_source("config.j2.age", Some(0o600));
        assert!(attrs.is_encrypted);
        assert!(attrs.is_template);
        assert_eq!(name, "config");
    }

    #[test]
    fn test_parse_plain_file_keeps_name() {
        let (attrs, name) = FileAttributes::parse_from_source("deploy.sh", Some(0o755));
        assert!(!attrs.is_template);
        assert!(!attrs.is_encrypted);
        assert_eq!(name, "deploy.sh");
        assert_eq!(attrs.mode(), Some(0o755));
    }

    #[test]
    fn test_no_mode_attribute_inference() {
        // 0o644 is "ordinary file" mode — it must NOT trigger any hidden
        // attribute flags, and mode() must return the real bits, not None.
        let (attrs, _) = FileAttributes::parse_from_source("foo", Some(0o644));
        assert!(!attrs.is_template);
        assert!(!attrs.is_encrypted);
        assert_eq!(attrs.mode(), Some(0o644));
    }

    #[test]
    fn test_parse_case_insensitive_extensions() {
        let (attrs, name) = FileAttributes::parse_from_source("Foo.J2", Some(0o644));
        assert!(attrs.is_template);
        assert_eq!(name, "Foo");
    }

    #[test]
    fn test_no_prefix_stripping() {
        // Filenames that used to be matched by `private_` / `executable_` /
        // `readonly_` / `dot_` / `modify_` / `remove_` / `symlink_` prefixes
        // are no longer rewritten. The target name is the source name
        // verbatim (modulo recognized extension stripping).
        for filename in [
            "private_xxx",
            "executable_yyy",
            "readonly_zzz",
            "dot_dotfiles",
            "modify_script",
            "remove_unused",
            "symlink_xdg",
        ] {
            let (attrs, name) = FileAttributes::parse_from_source(filename, Some(0o600));
            assert_eq!(name, filename, "{filename} target name");
            assert!(!attrs.is_template);
            assert!(!attrs.is_encrypted);
        }
    }

    #[test]
    fn test_serialize_round_trip() {
        let attrs = FileAttributes {
            is_template: true,
            is_encrypted: true,
            mode: Some(0o600),
        };

        let json = serde_json::to_string(&attrs).expect("serialize");
        let back: FileAttributes = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, attrs);
    }

    #[test]
    fn test_equality() {
        let mut a = FileAttributes::new();
        let mut b = FileAttributes::new();
        assert_eq!(a, b);

        a.is_template = true;
        assert_ne!(a, b);

        b.is_template = true;
        assert_eq!(a, b);

        a.mode = Some(0o644);
        b.mode = Some(0o644);
        assert_eq!(a, b);

        b.mode = Some(0o600);
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let attrs = FileAttributes {
            is_template: true,
            is_encrypted: true,
            mode: Some(0o600),
        };

        let cloned = attrs;
        assert_eq!(attrs, cloned);
    }
}
