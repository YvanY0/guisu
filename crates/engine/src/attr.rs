//! File attribute parsing and encoding
//!
//! This module handles parsing of source file attributes.
//!
//! # Attribute Encoding
//!
//! Attributes are encoded using file extensions and a small set of filename
//! prefixes. Permission-related attributes (private / executable / readonly
//! / dot / exact) are **not** encoded into filenames — the source file's
//! real Unix mode bits are the source of truth, exposed via
//! [`FileAttributes::mode`].
//!
//! File extensions:
//!
//! - `.j2` - File is a Jinja2 template
//! - `.age` - File is encrypted with age
//! - `.j2.age` - Template that is encrypted (edit decrypts, render encrypts)
//!
//! Filename prefixes (only the entry-type markers):
//!
//! - `modify_` - File is a modify script (target is `TargetEntry::Modify`)
//! - `remove_` - File is a remove directive (target is `TargetEntry::Remove`)
//! - `symlink_` - File declares a symlink target (the file content is the
//!   destination path the symlink should point at)
//!
//! The target filename is the source filename verbatim. The `apply` step
//! propagates the source file's mode bits to the destination; `diff` reports
//! any mismatch between source and destination mode bits.
//!
//! # Examples
//!
//! ```
//! use guisu_engine::attr::FileAttributes;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Template file: .j2 extension is stripped from the target name
//! let (attrs, name) = FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644))?;
//! assert!(attrs.is_template());
//! assert_eq!(name, ".gitconfig");
//! assert_eq!(attrs.mode(), Some(0o644));
//! # Ok(())
//! # }
//! ```

use guisu_core::Result;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const TEMPLATE_BIT: u16 = 1 << 0;
const ENCRYPTED_BIT: u16 = 1 << 1;
const MODIFY_BIT: u16 = 1 << 2;
const REMOVE_BIT: u16 = 1 << 3;
const SYMLINK_BIT: u16 = 1 << 4;

/// Attributes parsed from a source file's name and metadata.
///
/// The boolean flags here (`is_template` / `is_encrypted` / `is_modify` /
/// `is_remove` / `is_symlink`) are derived from file extensions and
/// entry-type filename prefixes. The `mode` field is the source file's
/// real Unix mode bits — it is the source of truth for permissions and is
/// **not** derived from a filename prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileAttributes {
    bits: u16,
    mode: Option<u32>,
}

impl FileAttributes {
    /// Create attributes with all flags set to false and no mode
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if file should be processed as a template
    #[inline]
    #[must_use]
    pub fn is_template(&self) -> bool {
        self.bits & TEMPLATE_BIT != 0
    }

    /// Check if file is encrypted
    #[inline]
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.bits & ENCRYPTED_BIT != 0
    }

    /// Check if file is a modify script
    #[inline]
    #[must_use]
    pub fn is_modify(&self) -> bool {
        self.bits & MODIFY_BIT != 0
    }

    /// Check if file should be removed
    #[inline]
    #[must_use]
    pub fn is_remove(&self) -> bool {
        self.bits & REMOVE_BIT != 0
    }

    /// Check if file is a symlink declaration
    #[inline]
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.bits & SYMLINK_BIT != 0
    }

    /// Set whether file should be processed as a template
    #[inline]
    pub fn set_template(&mut self, value: bool) {
        self.set_bit(TEMPLATE_BIT, value);
    }

    /// Set whether file is encrypted
    #[inline]
    pub fn set_encrypted(&mut self, value: bool) {
        self.set_bit(ENCRYPTED_BIT, value);
    }

    /// Set whether file is a modify script
    #[inline]
    pub fn set_modify(&mut self, value: bool) {
        self.set_bit(MODIFY_BIT, value);
    }

    /// Set whether file should be removed
    #[inline]
    pub fn set_remove(&mut self, value: bool) {
        self.set_bit(REMOVE_BIT, value);
    }

    /// Set whether file is a symlink declaration
    #[inline]
    pub fn set_symlink(&mut self, value: bool) {
        self.set_bit(SYMLINK_BIT, value);
    }

    #[inline]
    fn set_bit(&mut self, bit: u16, value: bool) {
        self.bits = if value {
            self.bits | bit
        } else {
            self.bits & !bit
        };
    }

    /// Parse attributes from a source filename
    ///
    /// The returned target name strips recognized extensions (`.j2`, `.age`,
    /// `.j2.age`) — that's how guisu names the destination file when the
    /// source uses these. The `modify_` / `remove_` / `symlink_` entry-type
    /// prefixes are **not** stripped and remain part of the destination path.
    ///
    /// The `mode` argument is the source file's real Unix mode bits and is
    /// exposed via [`FileAttributes::mode`].
    ///
    /// # Errors
    ///
    /// Returns an error if the filename cannot be parsed (e.g., invalid encoding)
    pub fn parse_from_source(filename: &str, mode: Option<u32>) -> Result<(Self, String)> {
        let mut attrs = Self { bits: 0, mode };
        let mut target_name = filename.to_string();

        // Detect entry-type prefixes (modify_ / remove_ / symlink_). These
        // do not rewrite the target name; the prefix stays on the file in
        // the source directory.
        let lower = target_name.to_lowercase();
        if lower.starts_with("modify_") {
            attrs.set_modify(true);
        } else if lower.starts_with("remove_") {
            attrs.set_remove(true);
        } else if lower.starts_with("symlink_") {
            attrs.set_symlink(true);
        }

        // Strip .age extension (must be stripped last so .j2.age works).
        if target_name.to_lowercase().ends_with(".age") {
            attrs.set_encrypted(true);
            target_name.truncate(target_name.len() - ".age".len());
        }

        // Strip .j2 extension (after .age so .j2.age order works).
        if target_name.to_lowercase().ends_with(".j2") {
            attrs.set_template(true);
            target_name.truncate(target_name.len() - ".j2".len());
        }

        Ok((attrs, target_name))
    }

    /// The source file's Unix mode bits (if known).
    ///
    /// `apply` propagates this to the destination, and `diff` reports any
    /// difference between this and the destination's mode. The value comes
    /// straight from the source file's metadata and is **not** inferred
    /// from the filename.
    #[must_use]
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }
}

// Custom Serialize to provide user-friendly JSON/TOML format.
// Expose the boolean flags plus the real mode bits.
impl Serialize for FileAttributes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileAttributes", 6)?;
        state.serialize_field("is_template", &self.is_template())?;
        state.serialize_field("is_encrypted", &self.is_encrypted())?;
        state.serialize_field("is_modify", &self.is_modify())?;
        state.serialize_field("is_remove", &self.is_remove())?;
        state.serialize_field("is_symlink", &self.is_symlink())?;
        state.serialize_field("mode", &self.mode())?;
        state.end()
    }
}

// Custom Deserialize to parse user-friendly JSON/TOML format.
impl<'de> Deserialize<'de> for FileAttributes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        #[allow(clippy::enum_variant_names)]
        enum Field {
            IsTemplate,
            IsEncrypted,
            IsModify,
            IsRemove,
            IsSymlink,
            Mode,
        }

        struct FileAttributesVisitor;

        impl<'de> Visitor<'de> for FileAttributesVisitor {
            type Value = FileAttributes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct FileAttributes")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<FileAttributes, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut attrs = FileAttributes::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::IsTemplate => {
                            let value: bool = map.next_value()?;
                            attrs.set_template(value);
                        }
                        Field::IsEncrypted => {
                            let value: bool = map.next_value()?;
                            attrs.set_encrypted(value);
                        }
                        Field::IsModify => {
                            let value: bool = map.next_value()?;
                            attrs.set_modify(value);
                        }
                        Field::IsRemove => {
                            let value: bool = map.next_value()?;
                            attrs.set_remove(value);
                        }
                        Field::IsSymlink => {
                            let value: bool = map.next_value()?;
                            attrs.set_symlink(value);
                        }
                        Field::Mode => {
                            let value: Option<u32> = map.next_value()?;
                            attrs.mode = value;
                        }
                    }
                }

                Ok(attrs)
            }
        }

        const FIELDS: &[&str] = &[
            "is_template",
            "is_encrypted",
            "is_modify",
            "is_remove",
            "is_symlink",
            "mode",
        ];
        deserializer.deserialize_struct("FileAttributes", FIELDS, FileAttributesVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_new_attributes() {
        let attrs = FileAttributes::new();
        assert!(!attrs.is_template());
        assert!(!attrs.is_encrypted());
        assert!(!attrs.is_modify());
        assert!(!attrs.is_remove());
        assert!(!attrs.is_symlink());
        assert_eq!(attrs.mode(), None);
    }

    #[test]
    fn test_set_and_check_flags() {
        let mut attrs = FileAttributes::new();

        attrs.set_template(true);
        assert!(attrs.is_template());

        attrs.set_encrypted(true);
        assert!(attrs.is_encrypted());

        attrs.set_modify(true);
        assert!(attrs.is_modify());

        attrs.set_remove(true);
        assert!(attrs.is_remove());

        attrs.set_symlink(true);
        assert!(attrs.is_symlink());
    }

    #[test]
    fn test_parse_template_strips_extension() {
        let (attrs, name) =
            FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644)).expect("parse failed");
        assert!(attrs.is_template());
        assert!(!attrs.is_encrypted());
        // Target name strips the .j2 extension
        assert_eq!(name, ".gitconfig");
        // Mode is the real source file mode
        assert_eq!(attrs.mode(), Some(0o644));
    }

    #[test]
    fn test_parse_encrypted_strips_extension() {
        let (attrs, name) =
            FileAttributes::parse_from_source("secrets.age", Some(0o600)).expect("parse failed");
        assert!(attrs.is_encrypted());
        assert!(!attrs.is_template());
        assert_eq!(name, "secrets");
        assert_eq!(attrs.mode(), Some(0o600));
    }

    #[test]
    fn test_parse_encrypted_template_strips_both_extensions() {
        let (attrs, name) =
            FileAttributes::parse_from_source("config.j2.age", Some(0o600)).expect("parse failed");
        assert!(attrs.is_encrypted());
        assert!(attrs.is_template());
        assert_eq!(name, "config");
    }

    #[test]
    fn test_parse_plain_file_keeps_name() {
        let (attrs, name) =
            FileAttributes::parse_from_source("deploy.sh", Some(0o755)).expect("parse failed");
        assert!(!attrs.is_template());
        assert!(!attrs.is_encrypted());
        assert_eq!(name, "deploy.sh");
        assert_eq!(attrs.mode(), Some(0o755));
    }

    #[test]
    fn test_parse_entry_type_prefix() {
        let (modify, _) =
            FileAttributes::parse_from_source("modify_script", Some(0o755)).expect("parse failed");
        assert!(modify.is_modify());

        let (remove, _) =
            FileAttributes::parse_from_source("remove_unused", Some(0o644)).expect("parse failed");
        assert!(remove.is_remove());

        let (symlink, _) =
            FileAttributes::parse_from_source("symlink_xdg", Some(0o644)).expect("parse failed");
        assert!(symlink.is_symlink());
    }

    #[test]
    fn test_no_mode_attribute_inference() {
        // 0o644 is "ordinary file" mode — it must NOT trigger any hidden
        // attribute flags, and mode() must return the real bits, not None.
        let (attrs, _) =
            FileAttributes::parse_from_source("foo", Some(0o644)).expect("parse failed");
        assert!(!attrs.is_template());
        assert!(!attrs.is_encrypted());
        assert!(!attrs.is_modify());
        assert!(!attrs.is_remove());
        assert!(!attrs.is_symlink());
        assert_eq!(attrs.mode(), Some(0o644));
    }

    #[test]
    fn test_parse_case_insensitive_extensions() {
        let (attrs, name) =
            FileAttributes::parse_from_source("Foo.J2", Some(0o644)).expect("parse failed");
        assert!(attrs.is_template());
        assert_eq!(name, "Foo");
    }

    #[test]
    fn test_serialize_round_trip() {
        let mut attrs = FileAttributes::new();
        attrs.set_template(true);
        attrs.set_encrypted(true);
        attrs.mode = Some(0o600);

        let json = serde_json::to_string(&attrs).expect("serialize");
        let back: FileAttributes = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, attrs);
    }

    #[test]
    fn test_equality() {
        let mut a = FileAttributes::new();
        let mut b = FileAttributes::new();
        assert_eq!(a, b);

        a.set_template(true);
        assert_ne!(a, b);

        b.set_template(true);
        assert_eq!(a, b);

        a.mode = Some(0o644);
        b.mode = Some(0o644);
        assert_eq!(a, b);

        b.mode = Some(0o600);
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let mut attrs = FileAttributes::new();
        attrs.set_template(true);
        attrs.set_encrypted(true);
        attrs.mode = Some(0o600);

        let cloned = attrs;
        assert_eq!(attrs, cloned);
    }
}
