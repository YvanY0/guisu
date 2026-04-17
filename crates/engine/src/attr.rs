//! File attribute parsing and encoding
//!
//! This module handles the parsing of attributes from source filenames and
//! encoding them back into filenames.
//!
//! # Attribute Encoding
//!
//! Attributes are encoded using file extensions and permissions:
//!
//! - `.j2` - File is a Jinja2 template
//! - `.age` - File is encrypted with age
//! - `.j2.age` - Template that is encrypted (edit decrypts, render encrypts)
//! - File permissions (Unix):
//!   - `0600` / `0700` - Private files/directories
//!   - `0755` - Executable files
//!
//! Target filename is source filename with extensions removed:
//! - `.gitconfig.j2` → `~/.gitconfig`
//! - `secrets.age` → `~/secrets`
//! - `config.j2.age` → `~/config`
//!
//! # Examples
//!
//! ```
//! use guisu_engine::attr::FileAttributes;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse from source file (extensions + permissions)
//! let (attrs, target_name) = FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644))?;
//! assert!(attrs.is_template());
//! assert_eq!(target_name, ".gitconfig");
//!
//! // Encrypted file with private permissions
//! let (attrs, target_name) = FileAttributes::parse_from_source("secrets.age", Some(0o600))?;
//! assert!(attrs.is_encrypted());
//! assert!(attrs.is_private());
//! assert_eq!(target_name, "secrets");
//! # Ok(())
//! # }
//! ```

use guisu_core::Result;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Unix permission constants
const PERMISSION_MASK: u32 = 0o777;
const PRIVATE_FILE: u32 = 0o600;
const PRIVATE_DIR: u32 = 0o700;
const OWNER_EXECUTE: u32 = 0o100;
const ALL_WRITE: u32 = 0o222;
const READONLY: u32 = 0o444;
const READONLY_EXEC: u32 = 0o555;
const STANDARD_EXEC: u32 = 0o755;

bitflags::bitflags! {
    /// Attributes that can be encoded in a filename
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileAttributes: u16 {
        /// Should this file be hidden (start with a dot)?
        const DOT = 1 << 0;
        /// Should this file have restrictive permissions (private)?
        const PRIVATE = 1 << 1;
        /// Should this file be read-only?
        const READONLY = 1 << 2;
        /// Should this file be executable?
        const EXECUTABLE = 1 << 3;
        /// Should this file be processed as a template?
        const TEMPLATE = 1 << 4;
        /// Is this file encrypted?
        const ENCRYPTED = 1 << 5;
        /// Is this a modify script?
        const MODIFY = 1 << 6;
        /// Should this file be removed?
        const REMOVE = 1 << 7;
        /// Is this a symlink?
        const SYMLINK = 1 << 8;
        /// Should exact mode be used (remove unmanaged files)?
        const EXACT = 1 << 9;
    }
}

impl FileAttributes {
    /// Create attributes with all flags set to false
    #[must_use]
    pub fn new() -> Self {
        Self::empty()
    }

    /// Check if file should be hidden (start with a dot)
    #[inline]
    #[must_use]
    pub fn is_dot(&self) -> bool {
        self.contains(Self::DOT)
    }

    /// Check if file should have restrictive permissions (private)
    #[inline]
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.contains(Self::PRIVATE)
    }

    /// Check if file should be read-only
    #[inline]
    #[must_use]
    pub fn is_readonly(&self) -> bool {
        self.contains(Self::READONLY)
    }

    /// Check if file should be executable
    #[inline]
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.contains(Self::EXECUTABLE)
    }

    /// Check if file should be processed as a template
    #[inline]
    #[must_use]
    pub fn is_template(&self) -> bool {
        self.contains(Self::TEMPLATE)
    }

    /// Check if file is encrypted
    #[inline]
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.contains(Self::ENCRYPTED)
    }

    /// Check if file is a modify script
    #[inline]
    #[must_use]
    pub fn is_modify(&self) -> bool {
        self.contains(Self::MODIFY)
    }

    /// Check if file should be removed
    #[inline]
    #[must_use]
    pub fn is_remove(&self) -> bool {
        self.contains(Self::REMOVE)
    }

    /// Check if file is a symlink
    #[inline]
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.contains(Self::SYMLINK)
    }

    /// Check if exact mode should be used (remove unmanaged files)
    #[inline]
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.contains(Self::EXACT)
    }

    /// Set whether file should be hidden (start with a dot)
    #[inline]
    pub fn set_dot(&mut self, value: bool) {
        self.set(Self::DOT, value);
    }

    /// Set whether file should have restrictive permissions (private)
    #[inline]
    pub fn set_private(&mut self, value: bool) {
        self.set(Self::PRIVATE, value);
    }

    /// Set whether file should be read-only
    #[inline]
    pub fn set_readonly(&mut self, value: bool) {
        self.set(Self::READONLY, value);
    }

    /// Set whether file should be executable
    #[inline]
    pub fn set_executable(&mut self, value: bool) {
        self.set(Self::EXECUTABLE, value);
    }

    /// Set whether file should be processed as a template
    #[inline]
    pub fn set_template(&mut self, value: bool) {
        self.set(Self::TEMPLATE, value);
    }

    /// Set whether file is encrypted
    #[inline]
    pub fn set_encrypted(&mut self, value: bool) {
        self.set(Self::ENCRYPTED, value);
    }

    /// Set whether file is a modify script
    #[inline]
    pub fn set_modify(&mut self, value: bool) {
        self.set(Self::MODIFY, value);
    }

    /// Set whether file should be removed
    #[inline]
    pub fn set_remove(&mut self, value: bool) {
        self.set(Self::REMOVE, value);
    }

    /// Set whether file is a symlink
    #[inline]
    pub fn set_symlink(&mut self, value: bool) {
        self.set(Self::SYMLINK, value);
    }

    /// Set whether exact mode should be used (remove unmanaged files)
    #[inline]
    pub fn set_exact(&mut self, value: bool) {
        self.set(Self::EXACT, value);
    }

    /// Parse attributes from a source file
    ///
    /// Returns the parsed attributes and the target filename (with extensions stripped).
    ///
    /// # Arguments
    ///
    /// * `filename` - The source filename (e.g., `.gitconfig.j2`, `secrets.age`)
    /// * `mode` - Optional Unix file mode for permission detection
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_engine::attr::FileAttributes;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Template file
    /// let (attrs, name) = FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644))?;
    /// assert!(attrs.is_template());
    /// assert_eq!(name, ".gitconfig");
    ///
    /// // Encrypted file with private permissions
    /// let (attrs, name) = FileAttributes::parse_from_source("secrets.age", Some(0o600))?;
    /// assert!(attrs.is_encrypted());
    /// assert!(attrs.is_private());
    /// assert_eq!(name, "secrets");
    ///
    /// // Executable script
    /// let (attrs, name) = FileAttributes::parse_from_source("deploy.sh", Some(0o755))?;
    /// assert!(attrs.is_executable());
    /// assert_eq!(name, "deploy.sh");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the filename cannot be parsed (e.g., invalid encoding)
    pub fn parse_from_source(filename: &str, mode: Option<u32>) -> Result<(Self, String)> {
        let mut attrs = Self::new();
        let mut target_name = filename.to_string();

        // Strip prefixes (e.g., private_, exact_, symlink_, remove_, modify_, dot_, executable_, readonly_)
        // Prefixes can be stacked and are stripped in order they appear
        loop {
            let lower = target_name.to_lowercase();
            if lower.starts_with("private_") {
                attrs.set_private(true);
                target_name = target_name["private_".len()..].to_string();
            } else if lower.starts_with("exact_") {
                attrs.set_exact(true);
                target_name = target_name["exact_".len()..].to_string();
            } else if lower.starts_with("symlink_") {
                attrs.set_symlink(true);
                target_name = target_name["symlink_".len()..].to_string();
            } else if lower.starts_with("remove_") {
                attrs.set_remove(true);
                target_name = target_name["remove_".len()..].to_string();
            } else if lower.starts_with("modify_") {
                attrs.set_modify(true);
                target_name = target_name["modify_".len()..].to_string();
            } else if lower.starts_with("dot_") {
                attrs.set_dot(true);
                target_name = target_name["dot_".len()..].to_string();
            } else if lower.starts_with("executable_") {
                attrs.set_executable(true);
                target_name = target_name["executable_".len()..].to_string();
            } else if lower.starts_with("readonly_") {
                attrs.set_readonly(true);
                target_name = target_name["readonly_".len()..].to_string();
            } else {
                break;
            }
        }

        // Check for .age extension (must be last) - case insensitive
        if target_name.to_lowercase().ends_with(".age") {
            attrs.set_encrypted(true);
            // Strip the extension preserving the original case
            let ext_len = ".age".len();
            target_name.truncate(target_name.len() - ext_len);
        }

        // Check for .j2 extension (before .age) - case insensitive
        if target_name.to_lowercase().ends_with(".j2") {
            attrs.set_template(true);
            // Strip the extension preserving the original case
            let ext_len = ".j2".len();
            target_name.truncate(target_name.len() - ext_len);
        }

        // If dot flag is set, prepend a dot to the target name
        if attrs.is_dot() && !target_name.starts_with('.') {
            target_name.insert(0, '.');
        }

        // Parse permissions from Unix mode
        if let Some(mode) = mode {
            attrs.parse_permissions(mode);
        }

        Ok((attrs, target_name))
    }

    /// Parse Unix permissions to set attributes
    ///
    /// Detects private, executable, and readonly attributes from file mode.
    fn parse_permissions(&mut self, mode: u32) {
        // Extract permission bits (last 9 bits)
        let perms = mode & PERMISSION_MASK;

        // Check for private files (0600 for files, 0700 for directories)
        // Private means owner-only read/write, no group or other permissions
        if perms == PRIVATE_FILE || perms == PRIVATE_DIR {
            self.set_private(true);
        }

        // Check for executable (owner execute bit set)
        if (perms & OWNER_EXECUTE) != 0 {
            self.set_executable(true);
        }

        // Check for readonly (no write bits set)
        if (perms & ALL_WRITE) == 0 {
            self.set_readonly(true);
        }
    }

    /// Get the Unix file permission mode for these attributes
    ///
    /// Returns `None` if no specific permissions are required (use defaults).
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_engine::attr::FileAttributes;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Private directory (0700)
    /// let (attrs, _) = FileAttributes::parse_from_source(".ssh", Some(0o700))?;
    /// assert_eq!(attrs.mode(), Some(0o700));
    ///
    /// // Executable script (0755)
    /// let (attrs, _) = FileAttributes::parse_from_source("script.sh", Some(0o755))?;
    /// assert_eq!(attrs.mode(), Some(0o755));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn mode(&self) -> Option<u32> {
        match (self.is_private(), self.is_readonly(), self.is_executable()) {
            (true, false, true) => Some(PRIVATE_DIR), // private + executable
            (true, false, false) => Some(PRIVATE_FILE), // private only
            (false, true, true) => Some(READONLY_EXEC), // readonly + executable
            (false, true, false) => Some(READONLY),   // readonly only
            (false, false, true) => Some(STANDARD_EXEC), // executable only
            _ => None,                                // use defaults or invalid combination
        }
    }
}

// Custom Serialize to provide user-friendly JSON/TOML format
// Instead of serializing as a bitflags integer, we expose individual boolean fields
impl Serialize for FileAttributes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileAttributes", 10)?;
        state.serialize_field("is_dot", &self.is_dot())?;
        state.serialize_field("is_private", &self.is_private())?;
        state.serialize_field("is_readonly", &self.is_readonly())?;
        state.serialize_field("is_executable", &self.is_executable())?;
        state.serialize_field("is_template", &self.is_template())?;
        state.serialize_field("is_encrypted", &self.is_encrypted())?;
        state.serialize_field("is_modify", &self.is_modify())?;
        state.serialize_field("is_remove", &self.is_remove())?;
        state.serialize_field("is_symlink", &self.is_symlink())?;
        state.serialize_field("is_exact", &self.is_exact())?;
        state.end()
    }
}

// Custom Deserialize to parse user-friendly JSON/TOML format
// Reads individual boolean fields and converts them to bitflags representation
impl<'de> Deserialize<'de> for FileAttributes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        // Allow `Is` prefix for boolean attribute fields - it improves clarity
        // by explicitly indicating these are boolean flags (isDot, isPrivate, etc.)
        #[allow(clippy::enum_variant_names)]
        enum Field {
            IsDot,
            IsPrivate,
            IsReadonly,
            IsExecutable,
            IsTemplate,
            IsEncrypted,
            IsModify,
            IsRemove,
            IsSymlink,
            IsExact,
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
                let mut attrs = FileAttributes::empty();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::IsDot => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::DOT, value);
                        }
                        Field::IsPrivate => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::PRIVATE, value);
                        }
                        Field::IsReadonly => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::READONLY, value);
                        }
                        Field::IsExecutable => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::EXECUTABLE, value);
                        }
                        Field::IsTemplate => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::TEMPLATE, value);
                        }
                        Field::IsEncrypted => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::ENCRYPTED, value);
                        }
                        Field::IsModify => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::MODIFY, value);
                        }
                        Field::IsRemove => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::REMOVE, value);
                        }
                        Field::IsSymlink => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::SYMLINK, value);
                        }
                        Field::IsExact => {
                            let value: bool = map.next_value()?;
                            attrs.set(FileAttributes::EXACT, value);
                        }
                    }
                }

                Ok(attrs)
            }
        }

        const FIELDS: &[&str] = &[
            "is_dot",
            "is_private",
            "is_readonly",
            "is_executable",
            "is_template",
            "is_encrypted",
            "is_modify",
            "is_remove",
            "is_symlink",
            "is_exact",
        ];
        deserializer.deserialize_struct("FileAttributes", FIELDS, FileAttributesVisitor)
    }
}

impl Default for FileAttributes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_new_attributes() {
        let attrs = FileAttributes::new();
        assert!(!attrs.is_dot());
        assert!(!attrs.is_private());
        assert!(!attrs.is_readonly());
        assert!(!attrs.is_executable());
        assert!(!attrs.is_template());
        assert!(!attrs.is_encrypted());
    }

    #[test]
    fn test_set_and_check_flags() {
        let mut attrs = FileAttributes::new();

        // Test each flag
        attrs.set_dot(true);
        assert!(attrs.is_dot());

        attrs.set_private(true);
        assert!(attrs.is_private());

        attrs.set_readonly(true);
        assert!(attrs.is_readonly());

        attrs.set_executable(true);
        assert!(attrs.is_executable());

        attrs.set_template(true);
        assert!(attrs.is_template());

        attrs.set_encrypted(true);
        assert!(attrs.is_encrypted());

        // Test unsetting
        attrs.set_dot(false);
        assert!(!attrs.is_dot());
    }

    #[test]
    fn test_parse_template_extension() {
        let (attrs, target) =
            FileAttributes::parse_from_source(".gitconfig.j2", Some(0o644)).expect("parse failed");

        assert!(attrs.is_template());
        assert!(!attrs.is_encrypted());
        assert_eq!(target, ".gitconfig");
    }

    #[test]
    fn test_parse_encrypted_extension() {
        let (attrs, target) =
            FileAttributes::parse_from_source("secrets.age", Some(0o600)).expect("parse failed");

        assert!(!attrs.is_template());
        assert!(attrs.is_encrypted());
        assert!(attrs.is_private());
        assert_eq!(target, "secrets");
    }

    #[test]
    fn test_parse_encrypted_template() {
        let (attrs, target) =
            FileAttributes::parse_from_source("config.j2.age", Some(0o600)).expect("parse failed");

        assert!(attrs.is_template());
        assert!(attrs.is_encrypted());
        assert!(attrs.is_private());
        assert_eq!(target, "config");
    }

    #[test]
    fn test_parse_executable_file() {
        let (attrs, target) =
            FileAttributes::parse_from_source("deploy.sh", Some(0o755)).expect("parse failed");

        assert!(attrs.is_executable());
        assert!(!attrs.is_private());
        assert!(!attrs.is_readonly());
        assert_eq!(target, "deploy.sh");
    }

    #[test]
    fn test_parse_private_file_permissions() {
        let (attrs, _) =
            FileAttributes::parse_from_source("test", Some(0o600)).expect("parse failed");
        assert!(attrs.is_private());
        assert!(!attrs.is_readonly());
    }

    #[test]
    fn test_parse_private_directory_permissions() {
        let (attrs, _) =
            FileAttributes::parse_from_source(".ssh", Some(0o700)).expect("parse failed");
        assert!(attrs.is_private());
        assert!(attrs.is_executable());
    }

    #[test]
    fn test_parse_readonly_permissions() {
        let (attrs, _) =
            FileAttributes::parse_from_source("readonly.txt", Some(0o444)).expect("parse failed");
        assert!(attrs.is_readonly());
        assert!(!attrs.is_executable());
        assert!(!attrs.is_private());
    }

    #[test]
    fn test_parse_readonly_executable() {
        let (attrs, _) =
            FileAttributes::parse_from_source("readonly-exec", Some(0o555)).expect("parse failed");
        assert!(attrs.is_readonly());
        assert!(attrs.is_executable());
    }

    #[test]
    fn test_parse_standard_executable() {
        let (attrs, _) =
            FileAttributes::parse_from_source("script", Some(0o755)).expect("parse failed");
        assert!(attrs.is_executable());
        assert!(!attrs.is_private());
        assert!(!attrs.is_readonly());
    }

    #[test]
    fn test_parse_no_permissions() {
        let (attrs, target) =
            FileAttributes::parse_from_source("file.txt", None).expect("parse failed");

        assert!(!attrs.is_private());
        assert!(!attrs.is_executable());
        assert!(!attrs.is_readonly());
        assert_eq!(target, "file.txt");
    }

    #[test]
    fn test_parse_multiple_dots() {
        let (attrs, target) = FileAttributes::parse_from_source(".my.config.file.j2", Some(0o644))
            .expect("parse failed");

        assert!(attrs.is_template());
        assert_eq!(target, ".my.config.file");
    }

    #[test]
    fn test_mode_private_file() {
        let mut attrs = FileAttributes::new();
        attrs.set_private(true);
        assert_eq!(attrs.mode(), Some(0o600));
    }

    #[test]
    fn test_mode_private_directory() {
        let mut attrs = FileAttributes::new();
        attrs.set_private(true);
        attrs.set_executable(true);
        assert_eq!(attrs.mode(), Some(0o700));
    }

    #[test]
    fn test_mode_readonly() {
        let mut attrs = FileAttributes::new();
        attrs.set_readonly(true);
        assert_eq!(attrs.mode(), Some(0o444));
    }

    #[test]
    fn test_mode_readonly_executable() {
        let mut attrs = FileAttributes::new();
        attrs.set_readonly(true);
        attrs.set_executable(true);
        assert_eq!(attrs.mode(), Some(0o555));
    }

    #[test]
    fn test_mode_standard_executable() {
        let mut attrs = FileAttributes::new();
        attrs.set_executable(true);
        assert_eq!(attrs.mode(), Some(0o755));
    }

    #[test]
    fn test_mode_default() {
        let attrs = FileAttributes::new();
        assert_eq!(attrs.mode(), None);
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut attrs = FileAttributes::new();
        attrs.set_template(true);
        attrs.set_encrypted(true);
        attrs.set_private(true);

        // Serialize to JSON
        let json = serde_json::to_string(&attrs).expect("serialize failed");

        // Deserialize back
        let deserialized: FileAttributes = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(attrs, deserialized);
        assert!(deserialized.is_template());
        assert!(deserialized.is_encrypted());
        assert!(deserialized.is_private());
    }

    #[test]
    fn test_serialize_format() {
        let mut attrs = FileAttributes::new();
        attrs.set_template(true);
        attrs.set_executable(true);

        let json = serde_json::to_value(attrs).expect("serialize failed");

        assert_eq!(json["is_template"], true);
        assert_eq!(json["is_executable"], true);
        assert_eq!(json["is_encrypted"], false);
        assert_eq!(json["is_private"], false);
    }

    #[test]
    fn test_deserialize_all_flags() {
        let json = r#"{
            "is_dot": true,
            "is_private": true,
            "is_readonly": false,
            "is_executable": true,
            "is_template": true,
            "is_encrypted": true
        }"#;

        let attrs: FileAttributes = serde_json::from_str(json).expect("deserialize failed");

        assert!(attrs.is_dot());
        assert!(attrs.is_private());
        assert!(!attrs.is_readonly());
        assert!(attrs.is_executable());
        assert!(attrs.is_template());
        assert!(attrs.is_encrypted());
    }

    #[test]
    fn test_roundtrip_parse_and_mode() {
        // Test that parsing permissions and then getting mode returns the same value
        let test_cases = vec![
            (0o600, 0o600), // private file
            (0o700, 0o700), // private dir
            (0o755, 0o755), // executable
            (0o444, 0o444), // readonly
            (0o555, 0o555), // readonly executable
        ];

        for (input_mode, expected_mode) in test_cases {
            let (attrs, _) =
                FileAttributes::parse_from_source("test", Some(input_mode)).expect("parse failed");
            assert_eq!(attrs.mode(), Some(expected_mode));
        }
    }

    #[test]
    fn test_bitflags_combinations() {
        // Test that we can combine multiple flags
        let mut attrs = FileAttributes::new();
        attrs.set_template(true);
        attrs.set_encrypted(true);
        attrs.set_private(true);
        attrs.set_executable(true);

        assert!(attrs.is_template());
        assert!(attrs.is_encrypted());
        assert!(attrs.is_private());
        assert!(attrs.is_executable());
    }

    #[test]
    fn test_empty_filename() {
        let (attrs, target) = FileAttributes::parse_from_source("", None).expect("parse failed");

        assert_eq!(target, "");
        assert!(!attrs.is_template());
        assert!(!attrs.is_encrypted());
    }

    #[test]
    fn test_only_extensions() {
        let (attrs, target) =
            FileAttributes::parse_from_source(".j2.age", Some(0o644)).expect("parse failed");

        assert!(attrs.is_template());
        assert!(attrs.is_encrypted());
        assert_eq!(target, "");
    }

    #[test]
    fn test_hidden_file_starting_with_dot() {
        // Files starting with . should keep the dot in target name
        let (attrs, target) =
            FileAttributes::parse_from_source(".bashrc", Some(0o644)).expect("parse failed");

        assert_eq!(target, ".bashrc");
        assert!(!attrs.is_template());
    }

    #[test]
    fn test_hidden_template_file() {
        let (attrs, target) =
            FileAttributes::parse_from_source(".config.j2", Some(0o644)).expect("parse failed");

        assert!(attrs.is_template());
        assert_eq!(target, ".config");
    }

    #[test]
    fn test_parse_permissions_with_extra_bits() {
        // Test that we correctly mask out non-permission bits
        let (attrs, _) =
            FileAttributes::parse_from_source("test", Some(0o100_755)).expect("parse failed");

        assert!(attrs.is_executable());
        assert!(!attrs.is_private());
    }

    #[test]
    fn test_equality() {
        let mut attrs1 = FileAttributes::new();
        let mut attrs2 = FileAttributes::new();

        assert_eq!(attrs1, attrs2);

        attrs1.set_template(true);
        assert_ne!(attrs1, attrs2);

        attrs2.set_template(true);
        assert_eq!(attrs1, attrs2);
    }

    #[test]
    fn test_clone() {
        let mut attrs = FileAttributes::new();
        attrs.set_template(true);
        attrs.set_encrypted(true);

        let cloned = attrs;
        assert_eq!(attrs, cloned);
    }
}
