//! Identity management for age encryption
//!
//! This module handles loading and managing age identities (private keys).

use crate::{Error, Recipient, Result};
use age::secrecy::ExposeSecret;
use age::x25519;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use tracing::warn;

/// An age identity (private key) for decryption
#[derive(Clone)]
pub enum Identity {
    /// Native age x25519 identity
    Age(x25519::Identity),
    /// SSH private key with its corresponding public key recipient
    /// Note: recipient is boxed to reduce enum size (`ssh::Recipient` is large)
    Ssh {
        /// SSH private key identity
        identity: age::ssh::Identity,
        /// SSH public key recipient (boxed to reduce size)
        recipient: Box<age::ssh::Recipient>,
    },
}

impl Identity {
    /// Generate a new random age identity
    #[must_use]
    pub fn generate() -> Self {
        let identity = x25519::Identity::generate();
        Self::Age(identity)
    }

    /// Create from SSH identity and recipient
    #[must_use]
    pub fn from_ssh(identity: age::ssh::Identity, recipient: age::ssh::Recipient) -> Self {
        Self::Ssh {
            identity,
            recipient: Box::new(recipient),
        }
    }

    /// Get the public key (recipient) for this identity
    #[must_use]
    pub fn to_public(&self) -> Recipient {
        match self {
            Self::Age(identity) => Recipient::from_age(identity.to_public()),
            Self::Ssh { recipient, .. } => Recipient::from_ssh((**recipient).clone()),
        }
    }

    /// Get a reference to the inner identity as a trait object
    pub(crate) fn as_dyn_identity(&self) -> &dyn age::Identity {
        match self {
            Self::Age(identity) => identity,
            Self::Ssh { identity, .. } => identity,
        }
    }
}

impl FromStr for Identity {
    type Err = Error;

    /// Parse an age identity from a string
    fn from_str(s: &str) -> Result<Self> {
        let identity = s
            .parse::<x25519::Identity>()
            .map_err(|e| Error::InvalidIdentity {
                reason: e.to_string(),
                path: "<string>".to_string(),
            })?;
        Ok(Self::Age(identity))
    }
}

impl fmt::Display for Identity {
    /// Get the identity as a string (private key)
    /// Only supported for age identities - SSH identities return a placeholder
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Age(identity) => write!(f, "{}", identity.to_string().expose_secret()),
            Self::Ssh { .. } => write!(f, "[SSH identity]"),
        }
    }
}

/// An identity file containing one or more age identities
pub struct IdentityFile {
    /// Path to the identity file
    path: String,

    /// Loaded identities
    identities: Vec<Identity>,
}

impl IdentityFile {
    /// Load identities from a file
    ///
    /// The file should contain one identity per line in the age format.
    ///
    /// # Errors
    ///
    /// Returns error if file not found, cannot be read, or contains invalid identity data
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_string_lossy().to_string();

        let file = fs::File::open(path_ref).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::IdentityNotFound {
                    path: path_str.clone(),
                }
            } else {
                Error::IdentityFile {
                    operation: "read".to_string(),
                    path: path_str.clone(),
                    source: e,
                }
            }
        })?;

        let reader = BufReader::new(file);
        let mut identities = Vec::new();
        let mut line_num = 0;

        for line in reader.lines() {
            line_num += 1;

            let line = line.map_err(|e| Error::IdentityFile {
                operation: "read".to_string(),
                path: path_str.clone(),
                source: e,
            })?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Try to parse as an identity
            match Identity::from_str(line) {
                Ok(identity) => identities.push(identity),
                Err(e) => {
                    // Warn about invalid lines - could indicate configuration errors
                    warn!(
                        "Skipping invalid identity on line {} in {}: {}",
                        line_num, path_str, e
                    );
                }
            }
        }

        if identities.is_empty() {
            return Err(Error::InvalidIdentity {
                reason: "No valid identities found in file".to_string(),
                path: path_str,
            });
        }

        Ok(Self {
            path: path_str,
            identities,
        })
    }

    /// Save identities to a file
    ///
    /// This will overwrite the file if it exists.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be created or written to
    pub fn save<P: AsRef<Path>>(path: P, identities: &[Identity]) -> Result<()> {
        use chrono::Utc;
        use std::fmt::Write as _;

        let path_ref = path.as_ref();
        let path_str = path_ref.to_string_lossy().to_string();

        let mut content = String::new();

        // Add creation timestamp in RFC3339 format (UTC for consistency across machines)
        let now = Utc::now();
        writeln!(content, "# created: {}", now.to_rfc3339())
            .expect("writing to String cannot fail");

        // Add public key(s) and secret key(s)
        for identity in identities {
            let public_key = identity.to_public();
            writeln!(content, "# public key: {public_key}").expect("writing to String cannot fail");
            content.push_str(&identity.to_string());
            content.push('\n');
        }

        // On Unix, create file with restricted permissions atomically to avoid race condition
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path_ref)
                .map_err(|e| Error::IdentityFile {
                    operation: "write".to_string(),
                    path: path_str.clone(),
                    source: e,
                })?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .and_then(|()| file.set_len(0))
                .map_err(|e| Error::IdentityFile {
                    operation: "write".to_string(),
                    path: path_str.clone(),
                    source: e,
                })?;

            file.write_all(content.as_bytes())
                .map_err(|e| Error::IdentityFile {
                    operation: "write".to_string(),
                    path: path_str,
                    source: e,
                })?;
        }

        // On non-Unix platforms, use regular write (no permission restrictions)
        #[cfg(not(unix))]
        {
            fs::write(path_ref, content).map_err(|e| Error::IdentityFile {
                operation: "write".to_string(),
                path: path_str,
                source: e,
            })?;
        }

        Ok(())
    }

    /// Get the path to the identity file
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the identities
    #[must_use]
    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }

    /// Convert all identities to their public recipients
    ///
    /// This is useful when you want to encrypt data to all identities in the file,
    /// or when exporting public keys for team members.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_crypto::IdentityFile;
    ///
    /// let identity_file = IdentityFile::load("~/.config/guisu/key.txt").unwrap();
    /// let recipients = identity_file.to_recipients();
    ///
    /// // Use all recipients for encryption
    /// guisu_crypto::encrypt(b"secret", &recipients).unwrap();
    /// ```
    #[must_use]
    pub fn to_recipients(&self) -> Vec<Recipient> {
        crate::identities_to_recipients(&self.identities)
    }

    /// Write recipients (public keys) to a file or writer
    ///
    /// This is useful for sharing public keys with team members who need to
    /// encrypt files that you can decrypt. The output contains only public keys,
    /// never private keys, so it's safe to share.
    ///
    /// # Arguments
    ///
    /// * `output` - Where to write the recipients (file, stdout, etc.)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_crypto::IdentityFile;
    /// use std::fs::File;
    ///
    /// let identity_file = IdentityFile::load("~/.config/guisu/key.txt").unwrap();
    ///
    /// // Write to file
    /// let output = File::create("recipients.txt").unwrap();
    /// identity_file.write_recipients_file(output).unwrap();
    ///
    /// // Or write to stdout
    /// identity_file.write_recipients_file(std::io::stdout()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if writing to output fails
    pub fn write_recipients_file<W: Write>(&self, mut output: W) -> Result<()> {
        for recipient in self.to_recipients() {
            writeln!(output, "{recipient}")?;
        }

        Ok(())
    }
}

/// Load identities from a file (supports both age and SSH keys)
///
/// # Arguments
///
/// * `path` - Path to the identity file
/// * `is_ssh` - If true, treat as SSH private key; otherwise as age identity file
///
/// # Errors
///
/// Returns error if file cannot be read or contains invalid identity data
///
/// # Examples
///
/// ```no_run
/// use guisu_crypto::load_identities;
/// use std::path::Path;
///
/// // Load age identity
/// let identities = load_identities(Path::new("~/.config/guisu/key.txt"), false).unwrap();
///
/// // Load SSH key
/// let identities = load_identities(Path::new("~/.ssh/id_ed25519"), true).unwrap();
/// ```
pub fn load_identities<P: AsRef<Path>>(path: P, is_ssh: bool) -> Result<Vec<Identity>> {
    use std::str::FromStr;

    let path_ref = path.as_ref();
    let path_str = path_ref.to_string_lossy().to_string();

    if is_ssh {
        // Load SSH private key
        let file = fs::File::open(path_ref).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::IdentityNotFound {
                    path: path_str.clone(),
                }
            } else {
                Error::IdentityFile {
                    operation: "read".to_string(),
                    path: path_str.clone(),
                    source: e,
                }
            }
        })?;

        let reader = BufReader::new(file);

        // Parse as SSH identity using age's SSH support
        // Note: from_buffer returns a single Identity enum, not a Vec
        let _ssh_identity_check =
            age::ssh::Identity::from_buffer(reader, None).map_err(|e| Error::InvalidIdentity {
                reason: format!("Failed to parse SSH key: {e}"),
                path: path_str.clone(),
            })?;

        // Load the corresponding public key file
        // Try appending .pub to the path
        let pub_key_path = path_ref.to_string_lossy().to_string() + ".pub";
        let pub_key_content = fs::read_to_string(&pub_key_path).map_err(|_| Error::InvalidIdentity {
            reason: format!(
                "SSH public key file not found: {pub_key_path}\n\
                 For SSH key encryption, the public key file (.pub) must exist alongside the private key."
            ),
            path: path_str.clone(),
        })?;

        // Parse SSH public key - need to use str::parse with FromStr trait
        let ssh_recipient = age::ssh::Recipient::from_str(&pub_key_content).map_err(|e| {
            Error::InvalidIdentity {
                reason: format!("Failed to parse SSH public key: {e:?}"),
                path: pub_key_path.clone(),
            }
        })?;

        // For SSH, we can only create one Identity per file
        // Parse the SSH key as bytes to get the concrete type
        let content = fs::read(path_ref).map_err(|e| Error::IdentityFile {
            operation: "read".to_string(),
            path: path_str.clone(),
            source: e,
        })?;

        let ssh_identity = age::ssh::Identity::from_buffer(&content[..], None).map_err(|e| {
            Error::InvalidIdentity {
                reason: format!("Failed to parse SSH key: {e}"),
                path: path_str.clone(),
            }
        })?;

        // Create our Identity wrapper with the SSH identity and recipient
        // Note: from_buffer returns a single identity for SSH keys
        let identity = Identity::from_ssh(ssh_identity, ssh_recipient);

        Ok(vec![identity])
    } else {
        // Load age identity file
        let identity_file = IdentityFile::load(path_ref)?;
        Ok(identity_file.identities().to_vec())
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_identity_generate() {
        let identity = Identity::generate();

        // Should be able to get public key
        let recipient = identity.to_public();
        assert_ne!(recipient.to_string(), "");
    }

    #[test]
    fn test_identity_to_public() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let pub1 = id1.to_public();
        let pub2 = id2.to_public();

        // Different identities should have different public keys
        assert_ne!(pub1.to_string(), pub2.to_string());
    }

    #[test]
    fn test_identity_from_str() {
        let identity = Identity::generate();
        let identity_str = identity.to_string();

        // Should be able to parse back
        let parsed = Identity::from_str(&identity_str).expect("Failed to parse identity");

        // Public keys should match
        assert_eq!(
            identity.to_public().to_string(),
            parsed.to_public().to_string()
        );
    }

    #[test]
    fn test_identity_from_str_invalid() {
        let result = Identity::from_str("not a valid identity");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_identity_display() {
        let identity = Identity::generate();
        let displayed = identity.to_string();

        // Should start with "AGE-SECRET-KEY-"
        assert!(displayed.starts_with("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_identity_file_save_and_load() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        // Generate test identities
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let identities = vec![id1.clone(), id2.clone()];

        // Save
        IdentityFile::save(path, &identities).expect("Failed to save identities");

        // Load
        let loaded = IdentityFile::load(path).expect("Failed to load identities");

        assert_eq!(loaded.identities().len(), 2);
        assert_eq!(path.to_string_lossy(), loaded.path());

        // Public keys should match
        assert_eq!(
            id1.to_public().to_string(),
            loaded.identities()[0].to_public().to_string()
        );
        assert_eq!(
            id2.to_public().to_string(),
            loaded.identities()[1].to_public().to_string()
        );
    }

    #[test]
    fn test_identity_file_load_nonexistent() {
        let result = IdentityFile::load("/nonexistent/path/to/identity.txt");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::IdentityNotFound { .. }));
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_identity_file_save_restricts_existing_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        fs::set_permissions(temp_file.path(), fs::Permissions::from_mode(0o644))
            .expect("Failed to set permissive mode");
        let identities = vec![Identity::generate()];

        IdentityFile::save(temp_file.path(), &identities).expect("Failed to save identity file");

        let mode = fs::metadata(temp_file.path())
            .expect("Failed to read identity metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_identity_file_empty() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        // Write empty file
        fs::write(path, "").expect("Failed to write empty file");

        let result = IdentityFile::load(path);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_identity_file_with_comments() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        let content = format!(
            "# This is a comment\n# created: 2024-01-01T00:00:00Z\n# public key: {}\n{}\n# Another comment\n",
            identity.to_public(),
            identity
        );

        fs::write(path, content).expect("Failed to write file");

        let loaded = IdentityFile::load(path).expect("Failed to load");
        assert_eq!(loaded.identities().len(), 1);
    }

    #[test]
    fn test_identity_file_with_blank_lines() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        let content = format!("\n\n{identity}\n\n\n");

        fs::write(path, content).expect("Failed to write file");

        let loaded = IdentityFile::load(path).expect("Failed to load");
        assert_eq!(loaded.identities().len(), 1);
    }

    #[test]
    fn test_identity_file_to_recipients() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let identities = vec![id1.clone(), id2.clone()];

        IdentityFile::save(path, &identities).expect("Failed to save");
        let loaded = IdentityFile::load(path).expect("Failed to load");

        let recipients = loaded.to_recipients();
        assert_eq!(recipients.len(), 2);
        assert_eq!(recipients[0].to_string(), id1.to_public().to_string());
        assert_eq!(recipients[1].to_string(), id2.to_public().to_string());
    }

    #[test]
    fn test_identity_file_write_recipients_file() {
        let identity_file = NamedTempFile::new().expect("Failed to create temp file");
        let recipients_file = NamedTempFile::new().expect("Failed to create temp file");

        let identities = vec![Identity::generate(), Identity::generate()];
        IdentityFile::save(identity_file.path(), &identities).expect("Failed to save");

        let loaded = IdentityFile::load(identity_file.path()).expect("Failed to load");

        // Write recipients to file
        let mut output = fs::File::create(recipients_file.path()).expect("Failed to create file");
        loaded
            .write_recipients_file(&mut output)
            .expect("Failed to write recipients");

        // Read back and verify
        let content = fs::read_to_string(recipients_file.path()).expect("Failed to read");
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("age1"));
        assert!(lines[1].starts_with("age1"));
    }

    #[test]
    fn test_load_identities_age() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, std::slice::from_ref(&identity)).expect("Failed to save");

        let loaded = load_identities(path, false).expect("Failed to load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].to_public().to_string(),
            identity.to_public().to_string()
        );
    }

    #[test]
    fn test_load_identities_nonexistent() {
        let result = load_identities("/nonexistent/file.txt", false);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::IdentityNotFound { .. }));
        }
    }

    #[test]
    fn test_identity_file_path_method() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, &[identity]).expect("Failed to save");

        let loaded = IdentityFile::load(path).expect("Failed to load");
        assert_eq!(loaded.path(), path.to_string_lossy());
    }

    #[test]
    fn test_identity_file_identities_method() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let id1 = Identity::generate();
        let id2 = Identity::generate();
        IdentityFile::save(path, &[id1.clone(), id2.clone()]).expect("Failed to save");

        let loaded = IdentityFile::load(path).expect("Failed to load");
        let ids = loaded.identities();

        assert_eq!(ids.len(), 2);
    }

    #[test]
    #[cfg(unix)]
    fn test_identity_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, &[identity]).expect("Failed to save");

        // Check permissions are 0600 (owner read/write only)
        let metadata = fs::metadata(path).expect("Failed to get metadata");
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_identity_roundtrip_through_string() {
        let identity = Identity::generate();
        let public_before = identity.to_public().to_string();

        // Convert to string and back
        let identity_str = identity.to_string();
        let restored = Identity::from_str(&identity_str).expect("Failed to parse");
        let public_after = restored.to_public().to_string();

        assert_eq!(public_before, public_after);
    }

    #[test]
    fn test_multiple_identities_in_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identities: Vec<Identity> = (0..5).map(|_| Identity::generate()).collect();
        IdentityFile::save(path, &identities).expect("Failed to save");

        let loaded = IdentityFile::load(path).expect("Failed to load");
        assert_eq!(loaded.identities().len(), 5);

        // Verify all public keys match
        for (i, loaded_id) in loaded.identities().iter().enumerate() {
            assert_eq!(
                loaded_id.to_public().to_string(),
                identities[i].to_public().to_string()
            );
        }
    }

    #[test]
    fn test_identity_file_with_invalid_lines() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let valid_identity = Identity::generate();
        let content = format!(
            "# Valid identity below\n{valid_identity}\n# Invalid line below\ninvalid_identity_string\n# Another valid one\n{valid_identity}\n"
        );

        fs::write(path, content).expect("Failed to write file");

        // Should load successfully, skipping invalid lines
        let loaded = IdentityFile::load(path).expect("Should load despite invalid lines");

        // Should have loaded 2 valid identities (same identity written twice)
        assert_eq!(loaded.identities().len(), 2);
    }

    #[test]
    fn test_identity_file_all_invalid_lines() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let content = "# All invalid\ninvalid1\ninvalid2\n# More invalid\ninvalid3\n";
        fs::write(path, content).expect("Failed to write file");

        // Should fail because no valid identities found
        let result = IdentityFile::load(path);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
            assert!(e.to_string().contains("No valid identities"));
        }
    }

    #[test]
    fn test_ssh_identity_display() {
        // Create a mock SSH identity for testing display
        // We can't easily create a real SSH identity without SSH keys,
        // but we can test that the Display implementation works by
        // checking that Age identities don't return "[SSH identity]"
        let age_identity = Identity::generate();
        let display = age_identity.to_string();

        // Age identity should NOT display as "[SSH identity]"
        assert_ne!(display, "[SSH identity]");
        assert!(display.starts_with("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_identity_file_save_creates_formatted_output() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, std::slice::from_ref(&identity)).expect("Failed to save");

        let content = fs::read_to_string(path).expect("Failed to read file");

        // Check that file contains expected format
        assert!(content.contains("# created:"));
        assert!(content.contains("# public key:"));
        assert!(content.contains("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_identity_file_save_multiple_with_comments() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let id1 = Identity::generate();
        let id2 = Identity::generate();

        IdentityFile::save(path, &[id1.clone(), id2.clone()]).expect("Failed to save");

        let content = fs::read_to_string(path).expect("Failed to read file");

        // Should have one creation timestamp
        assert_eq!(content.matches("# created:").count(), 1);

        // Should have two public key comments
        assert_eq!(content.matches("# public key:").count(), 2);

        // Should have two secret keys
        assert_eq!(content.matches("AGE-SECRET-KEY-").count(), 2);
    }

    #[test]
    fn test_load_identities_ssh_without_pub_file() {
        // Test that SSH loading fails gracefully when .pub file doesn't exist
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        // Write some content (not a valid SSH key, but we're testing .pub file logic)
        fs::write(path, "not-a-real-ssh-key").expect("Failed to write");

        // Try to load as SSH - should fail because .pub file doesn't exist
        let result = load_identities(path, true);

        // Should fail before even trying to parse the key
        // (because age's SSH parser would fail first on invalid content)
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_file_write_recipients_to_vec() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identities = vec![Identity::generate(), Identity::generate()];
        IdentityFile::save(path, &identities).expect("Failed to save");

        let loaded = IdentityFile::load(path).expect("Failed to load");

        // Write recipients to a Vec<u8>
        let mut output = Vec::new();
        loaded
            .write_recipients_file(&mut output)
            .expect("Failed to write");

        let content = String::from_utf8(output).expect("Invalid UTF-8");
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("age1"));
        assert!(lines[1].starts_with("age1"));
    }

    #[test]
    fn test_identity_clone() {
        let identity = Identity::generate();
        let cloned = identity.clone();

        // Public keys should match
        assert_eq!(
            identity.to_public().to_string(),
            cloned.to_public().to_string()
        );
    }

    #[test]
    fn test_load_identities_ssh_nonexistent() {
        let result = load_identities("/nonexistent/ssh/key", true);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::IdentityNotFound { .. }));
        }
    }

    #[test]
    fn test_identity_file_save_empty_identities() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        // Save empty identities list
        IdentityFile::save(path, &[]).expect("Failed to save empty identities");

        // Should create a file with just header
        let content = fs::read_to_string(path).expect("Failed to read file");
        assert!(content.contains("# created:"));
        // No identities, so no public key or secret key lines
        assert!(!content.contains("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_identity_file_save_single_identity() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, std::slice::from_ref(&identity)).expect("Failed to save");

        let content = fs::read_to_string(path).expect("Failed to read file");

        // Should have exactly one public key comment
        assert_eq!(content.matches("# public key:").count(), 1);

        // Should have exactly one secret key
        assert_eq!(content.matches("AGE-SECRET-KEY-").count(), 1);
    }

    #[test]
    fn test_identity_file_save_preserves_identity_order() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let id3 = Identity::generate();

        let pub1 = id1.to_public().to_string();
        let pub2 = id2.to_public().to_string();
        let pub3 = id3.to_public().to_string();

        IdentityFile::save(path, &[id1, id2, id3]).expect("Failed to save");

        let content = fs::read_to_string(path).expect("Failed to read file");

        // Find positions of public keys in file
        let pos1 = content.find(&pub1).expect("pub1 not found");
        let pos2 = content.find(&pub2).expect("pub2 not found");
        let pos3 = content.find(&pub3).expect("pub3 not found");

        // Order should be preserved
        assert!(pos1 < pos2);
        assert!(pos2 < pos3);
    }

    #[test]
    fn test_identity_file_path_is_absolute() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, &[identity]).expect("Failed to save");

        let loaded = IdentityFile::load(path).expect("Failed to load");

        // Path should be stored as provided (absolute in this case)
        assert!(
            loaded
                .path()
                .contains(temp_file.path().file_name().unwrap().to_str().unwrap())
        );
    }

    #[test]
    fn test_to_recipients_empty() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        // Create file with just header (no identities)
        IdentityFile::save(path, &[]).expect("Failed to save");

        // Can't load empty file (should fail)
        let result = IdentityFile::load(path);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_write_recipients_file_empty_output() {
        let identity_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = identity_file.path();

        let identity = Identity::generate();
        IdentityFile::save(path, &[identity]).expect("Failed to save");

        let loaded = IdentityFile::load(path).expect("Failed to load");

        // Write to empty Vec
        let mut output = Vec::new();
        loaded
            .write_recipients_file(&mut output)
            .expect("Failed to write");

        // Should have written one recipient line with newline
        let content = String::from_utf8(output).expect("Invalid UTF-8");
        assert_eq!(content.lines().count(), 1);
        assert!(content.starts_with("age1"));
    }

    #[test]
    fn test_identity_from_str_empty_string() {
        let result = "".parse::<Identity>();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_identity_from_str_whitespace() {
        let result = "   ".parse::<Identity>();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_identity_from_str_partial_key() {
        let result = "AGE-SECRET-KEY-".parse::<Identity>();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_identity_from_str_wrong_prefix() {
        let result = "WRONG-SECRET-KEY-1234567890".parse::<Identity>();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
        }
    }

    #[test]
    fn test_identity_file_load_with_only_comments() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let content = "# Comment 1\n# Comment 2\n# Comment 3\n";
        fs::write(path, content).expect("Failed to write file");

        let result = IdentityFile::load(path);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidIdentity { .. }));
            assert!(e.to_string().contains("No valid identities"));
        }
    }

    #[test]
    fn test_identity_file_load_mixed_valid_invalid() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let valid1 = Identity::generate();
        let valid2 = Identity::generate();

        let content =
            format!("# Header\n{valid1}\ninvalid line 1\n{valid2}\ninvalid line 2\n# End\n");
        fs::write(path, content).expect("Failed to write file");

        let loaded = IdentityFile::load(path).expect("Failed to load");

        // Should have loaded both valid identities, skipping invalid ones
        assert_eq!(loaded.identities().len(), 2);
    }

    #[test]
    fn test_load_identities_age_with_multiple() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let id3 = Identity::generate();

        IdentityFile::save(path, &[id1.clone(), id2.clone(), id3.clone()]).expect("Failed to save");

        let loaded = load_identities(path, false).expect("Failed to load");

        assert_eq!(loaded.len(), 3);

        // Public keys should match
        assert_eq!(
            loaded[0].to_public().to_string(),
            id1.to_public().to_string()
        );
        assert_eq!(
            loaded[1].to_public().to_string(),
            id2.to_public().to_string()
        );
        assert_eq!(
            loaded[2].to_public().to_string(),
            id3.to_public().to_string()
        );
    }

    #[test]
    fn test_to_recipients_single_identity() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let identity = Identity::generate();
        let expected_recipient = identity.to_public().to_string();

        IdentityFile::save(path, &[identity]).expect("Failed to save");
        let loaded = IdentityFile::load(path).expect("Failed to load");

        let recipients = loaded.to_recipients();
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].to_string(), expected_recipient);
    }

    #[test]
    fn test_to_recipients_multiple_identities() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let pub1 = id1.to_public().to_string();
        let pub2 = id2.to_public().to_string();

        IdentityFile::save(path, &[id1, id2]).expect("Failed to save");
        let loaded = IdentityFile::load(path).expect("Failed to load");

        let recipients = loaded.to_recipients();
        assert_eq!(recipients.len(), 2);
        assert_eq!(recipients[0].to_string(), pub1);
        assert_eq!(recipients[1].to_string(), pub2);
    }

    #[test]
    fn test_identity_display_format_consistency() {
        let identity = Identity::generate();

        let display1 = identity.to_string();
        let display2 = format!("{identity}");
        let display3 = identity.to_string();

        // All should produce same output
        assert_eq!(display1, display2);
        assert_eq!(display1, display3);

        // Should start with correct prefix
        assert!(display1.starts_with("AGE-SECRET-KEY-"));
    }
}
