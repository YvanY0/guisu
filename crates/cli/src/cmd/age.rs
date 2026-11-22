//! Age encryption identity management
//!
//! Commands for generating and showing age identities.

use anyhow::{Context, Result};
use guisu_crypto::{
    Identity, IdentityFile, Recipient, decrypt_inline, encrypt_file_content, encrypt_inline,
    load_identities,
};
use owo_colors::OwoColorize;
use std::io::{self, Write};
use std::path::PathBuf;
use walkdir::WalkDir;

use guisu_config::Config;

/// Generate a new age identity
///
/// Without an explicit output path, the identity configured in `.guisu.toml`
/// is used; only if none is configured does it fall back to the default
/// location. An existing key is never overwritten.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration directory cannot be determined (when no output path specified)
/// - The target path holds an existing key
/// - The configured identity points at an SSH key
/// - Parent directory creation fails
/// - Identity file cannot be saved
pub fn generate(output: Option<PathBuf>, config: &Config) -> Result<()> {
    let (output_path, from_config) = if let Some(path) = output {
        (path, false)
    } else {
        let configured = configured_identity_path(config);
        let from_config = configured.is_some();
        let path = configured
            .or_else(guisu_config::dirs::default_age_identity)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not determine config directory. Please specify output path with --output."
                )
            })?;
        (path, from_config)
    };

    let identity = Identity::generate();
    let public_key = identity.to_public();

    if from_config && Config::is_ssh_identity(&output_path) {
        return Err(anyhow::anyhow!(
            "Configured identity is an SSH key: {}\n\
             Refusing to write an age identity there. Use --output <path> to choose another location.",
            output_path.display()
        ));
    }

    // Overwriting the key in use would lock out every encrypted file.
    if let Ok(metadata) = std::fs::metadata(&output_path)
        && metadata.is_file()
        && metadata.len() > 0
    {
        return Err(anyhow::anyhow!(
            "Identity file already exists: {}\n\
             Refusing to overwrite an existing key. Remove it first, or pass --output <path>.",
            output_path.display()
        ));
    }

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Save the identity
    IdentityFile::save(&output_path, &[identity]).context("Failed to save identity file")?;

    println!("Generated new age identity");
    println!("Private key saved to: {}", output_path.display());
    println!("\nPublic key: {public_key}");
    println!("\nKeep your private key secure!");
    println!("Share your public key with others to allow them to encrypt files for you.");

    Ok(())
}

/// The identity path configured in `.guisu.toml`, if any.
fn configured_identity_path(config: &Config) -> Option<PathBuf> {
    if let Some(identity) = &config.age.identity {
        return Some(identity.clone());
    }

    config
        .age
        .identities
        .as_ref()
        .and_then(|identities| identities.first())
        .cloned()
}

/// Show the public key for the current identity
///
/// # Errors
///
/// Returns an error if loading configured identities fails
pub fn show(config: &Config) -> Result<()> {
    let identities = config.age_identities()?;

    println!("{}", "Age Identities".bright_white().bold());
    println!();

    if identities.is_empty() {
        println!(
            "  {} {:14} {}",
            "✗".bright_red(),
            "Status",
            "No identities configured".dimmed()
        );
        return Ok(());
    }

    // Display identity files
    if let Some(ref identity_path) = config.age.identity {
        print_item("Identity", &identity_path.display().to_string(), true);
    }
    if let Some(ref identity_paths) = config.age.identities {
        for (i, path) in identity_paths.iter().enumerate() {
            let label = if i == 0 && config.age.identity.is_none() {
                "Identity"
            } else {
                ""
            };
            print_item(label, &path.display().to_string(), true);
        }
    }

    println!();
    println!("{}", "Public Keys".bright_white().bold());
    println!();

    // Display public keys
    for (i, identity) in identities.iter().enumerate() {
        let label = if i == 0 {
            if identities.len() == 1 {
                "Public key"
            } else {
                "Public keys"
            }
        } else {
            ""
        };
        print_item(label, &identity.to_public().to_string(), true);
    }

    Ok(())
}

/// Print a formatted item with status indicator
fn print_item(label: &str, value: &str, ok: bool) {
    let symbol = if ok {
        "✓".bright_green().to_string()
    } else {
        "✗".bright_red().to_string()
    };

    let formatted_value = if ok {
        value.bright_white().to_string()
    } else {
        value.dimmed().to_string()
    };

    println!("  {symbol} {label:14} {formatted_value}");
}

/// Encrypt a value using inline encryption format
///
/// This encrypts a plaintext value and outputs it in the compact `age:base64...` format
/// suitable for embedding in configuration files.
///
/// # Errors
///
/// Returns an error if:
/// - Recipients cannot be parsed from the provided strings
/// - Loading configured identities fails (when no recipients specified)
/// - Reading from stdin fails (in interactive mode)
/// - No value is provided to encrypt
/// - Encryption fails
pub fn encrypt(
    value: Option<String>,
    interactive: bool,
    recipient_strs: &[String],
    config: &Config,
) -> Result<()> {
    // Determine recipients
    let recipients = if recipient_strs.is_empty() {
        // No recipients specified, derive from all configured identities
        let identities = config.age_identities()?;

        // Convert all identities to recipients
        identities
            .iter()
            .map(guisu_crypto::Identity::to_public)
            .collect()
    } else {
        // Use explicitly specified recipients
        recipient_strs
            .iter()
            .map(|s| s.parse::<Recipient>())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse recipient")?
    };

    // Get the value to encrypt
    let plaintext = match value {
        Some(v) if !interactive => v,
        _ => {
            // Interactive mode or no value provided: read from stdin
            if interactive {
                print!("Enter value to encrypt: ");
                io::stdout().flush()?;
            }

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    if plaintext.is_empty() {
        anyhow::bail!("No value provided to encrypt");
    }

    // Encrypt the value with all recipients
    let encrypted = encrypt_inline(&plaintext, &recipients).context("Failed to encrypt value")?;

    // Output the encrypted value
    println!("{encrypted}");

    if interactive {
        println!();
        println!("Copy the above encrypted value into your configuration file.");
        println!("Use {{ encrypted_value | decrypt }} in templates to decrypt it.");
    }

    Ok(())
}

/// Decrypt an inline encrypted value
///
/// This decrypts a value in the `age:base64...` format and outputs the plaintext.
///
/// # Errors
///
/// Returns an error if:
/// - Loading configured identities fails
/// - Decryption fails (invalid format or wrong identity)
pub fn decrypt(value: &str, config: &Config) -> Result<()> {
    // Load all configured identities
    let identities = config.age_identities()?;

    // Decrypt the value
    let plaintext = decrypt_inline(value, &identities).context("Failed to decrypt value")?;

    // Output the plaintext
    println!("{plaintext}");

    Ok(())
}

/// Load old and new identities for migration
fn load_migration_identities(
    old_identity_paths: &[PathBuf],
    new_identity_paths: &[PathBuf],
) -> Result<(Vec<guisu_crypto::Identity>, Vec<guisu_crypto::Recipient>)> {
    // Load old identities
    println!("{}", "Loading old identities...".dimmed());
    let mut old_identities = Vec::new();
    for path in old_identity_paths {
        let is_ssh = guisu_config::Config::is_ssh_identity(path);
        let ids = load_identities(path, is_ssh)
            .with_context(|| format!("Failed to load old identity: {}", path.display()))?;
        println!("  ✓ {}", path.display());
        old_identities.extend(ids);
    }
    println!();

    // Load new identities and extract recipients
    println!("{}", "Loading new identities...".dimmed());
    let mut new_recipients = Vec::new();
    for path in new_identity_paths {
        let is_ssh = guisu_config::Config::is_ssh_identity(path);
        let ids = load_identities(path, is_ssh)
            .with_context(|| format!("Failed to load new identity: {}", path.display()))?;
        println!("  ✓ {}", path.display());
        for identity in &ids {
            new_recipients.push(identity.to_public());
        }
    }
    println!();

    Ok((old_identities, new_recipients))
}

/// Scan source directory for encrypted files
fn scan_encrypted_files(source_dir: &std::path::Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    println!("{}", "Scanning for encrypted files...".dimmed());

    let mut encrypted_files = Vec::new(); // .age files
    let mut inline_files = Vec::new(); // Files with inline age: encryption

    // Compile regex once outside the loop
    let inline_pattern = regex::Regex::new(r"age:[A-Za-z0-9+/]+=*")
        .expect("hardcoded regex pattern should be valid");

    for entry in WalkDir::new(source_dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        // Check for .age files
        if path.extension().and_then(|s| s.to_str()) == Some("age") {
            encrypted_files.push(path.to_path_buf());
            continue;
        }

        // Check for inline encrypted content
        if let Ok(content) = std::fs::read_to_string(path)
            && content.contains("age:")
            && inline_pattern.is_match(&content)
        {
            inline_files.push(path.to_path_buf());
        }
    }

    (encrypted_files, inline_files)
}

/// Display list of files to be migrated
fn display_migration_file_list(
    encrypted_files: &[PathBuf],
    inline_files: &[PathBuf],
    source_dir: &std::path::Path,
) {
    println!("{}", "Files to be migrated:".bold());

    if !encrypted_files.is_empty() {
        println!("\n{}", "Encrypted files (.age):".cyan());
        for file in encrypted_files {
            let relative = file.strip_prefix(source_dir).unwrap_or(file);
            println!("  • {}", relative.display());
        }
    }

    if !inline_files.is_empty() {
        println!("\n{}", "Files with inline encryption:".cyan());
        for file in inline_files {
            let relative = file.strip_prefix(source_dir).unwrap_or(file);
            println!("  • {}", relative.display());
        }
    }
    println!();
}

/// Perform the actual migration of files
fn perform_file_migrations(
    encrypted_files: &[PathBuf],
    inline_files: &[PathBuf],
    source_dir: &std::path::Path,
    old_identities: &[guisu_crypto::Identity],
    new_recipients: &[guisu_crypto::Recipient],
) -> Result<(usize, usize)> {
    println!("{}", "Migrating files...".bold().cyan());

    let mut migrated_count = 0;
    let mut error_count = 0;

    // Migrate .age files
    for file in encrypted_files {
        let relative = file.strip_prefix(source_dir).unwrap_or(file);
        print!("  Migrating {} ... ", relative.display());
        io::stdout().flush()?;

        match migrate_encrypted_file(file, old_identities, new_recipients) {
            Ok(()) => {
                println!("{}", "✓".green());
                migrated_count += 1;
            }
            Err(e) => {
                println!("{}", "✗".red());
                eprintln!("    Error: {e}");
                error_count += 1;
            }
        }
    }

    // Migrate files with inline encryption
    for file in inline_files {
        let relative = file.strip_prefix(source_dir).unwrap_or(file);
        print!("  Migrating {} ... ", relative.display());
        io::stdout().flush()?;

        match migrate_inline_file(file, old_identities, new_recipients) {
            Ok(()) => {
                println!("{}", "✓".green());
                migrated_count += 1;
            }
            Err(e) => {
                println!("{}", "✗".red());
                eprintln!("    Error: {e}");
                error_count += 1;
            }
        }
    }

    Ok((migrated_count, error_count))
}

/// Migrate encrypted files from old keys to new keys
///
/// Re-encrypts all encrypted files (.age) and inline encrypted values in the source directory
///
/// # Errors
///
/// Returns an error if:
/// - Loading old or new identities fails
/// - Reading from stdin fails (for user confirmation)
/// - Migrating individual encrypted files fails
/// - File I/O operations fail
///
/// # Panics
///
/// Panics if the hardcoded regex pattern for detecting inline encryption is invalid.
/// This should never happen as the pattern is validated at compile time.
pub fn migrate(
    source_dir: &std::path::Path,
    old_identity_paths: &[PathBuf],
    new_identity_paths: &[PathBuf],
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    println!("{}", "Age Key Migration".bold().cyan());
    println!();

    // Load identities
    let (old_identities, new_recipients) =
        load_migration_identities(old_identity_paths, new_identity_paths)?;

    // Scan for encrypted files
    let (encrypted_files, inline_files) = scan_encrypted_files(source_dir);

    let total_files = encrypted_files.len() + inline_files.len();

    if total_files == 0 {
        println!(
            "{}",
            "No encrypted files found in source directory.".yellow()
        );
        return Ok(());
    }

    // Display summary
    println!();
    println!("{}", "Migration Summary:".bold());
    println!("  Encrypted files (.age):  {}", encrypted_files.len());
    println!("  Files with inline encryption: {}", inline_files.len());
    println!("  Total files to migrate:  {total_files}");
    println!();

    // Show files if dry-run or not auto-confirmed
    if dry_run || !yes {
        display_migration_file_list(&encrypted_files, &inline_files, source_dir);
    }

    if dry_run {
        println!("{}", "Dry run - no files were modified.".yellow().bold());
        return Ok(());
    }

    // Confirmation prompt
    if !yes {
        print!(
            "{} {}",
            "Proceed with migration?".yellow().bold(),
            "(yes/no):".dimmed()
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();

        if answer != "yes" && answer != "y" {
            println!("{}", "Migration cancelled.".yellow());
            return Ok(());
        }
        println!();
    }

    // Perform migration
    let (migrated_count, error_count) = perform_file_migrations(
        &encrypted_files,
        &inline_files,
        source_dir,
        &old_identities,
        &new_recipients,
    )?;

    // Summary
    println!();
    if error_count == 0 {
        println!(
            "{} Successfully migrated {} files.",
            "✓".green().bold(),
            migrated_count
        );
    } else {
        println!(
            "{} Migrated {} files with {} errors.",
            "!".yellow().bold(),
            migrated_count,
            error_count
        );
    }

    Ok(())
}

/// Migrate a single .age encrypted file
fn migrate_encrypted_file(
    file_path: &std::path::Path,
    old_identities: &[guisu_crypto::Identity],
    new_recipients: &[guisu_crypto::Recipient],
) -> Result<()> {
    // Read and decrypt with old key
    let encrypted_content = std::fs::read(file_path)?;
    let decrypted = guisu_crypto::decrypt(&encrypted_content, old_identities)
        .context("Failed to decrypt with old identities")?;

    // Re-encrypt with new key
    let re_encrypted = guisu_crypto::encrypt(&decrypted, new_recipients)
        .context("Failed to encrypt with new recipients")?;

    // Write back
    std::fs::write(file_path, re_encrypted)
        .with_context(|| format!("Failed to write file: {}", file_path.display()))?;

    Ok(())
}

/// Migrate a file with inline encrypted values
fn migrate_inline_file(
    file_path: &std::path::Path,
    old_identities: &[guisu_crypto::Identity],
    new_recipients: &[guisu_crypto::Recipient],
) -> Result<()> {
    // Read file content
    let content = std::fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

    // Re-encrypt inline values
    let re_encrypted = encrypt_file_content(&content, old_identities, new_recipients)
        .context("Failed to re-encrypt inline values")?;

    // Write back
    std::fs::write(file_path, re_encrypted)
        .with_context(|| format!("Failed to write file: {}", file_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use guisu_crypto::{Identity, encrypt_inline};
    use tempfile::TempDir;

    #[test]
    fn test_print_item_ok() {
        // Just verify it doesn't panic
        print_item("Label", "value", true);
    }

    #[test]
    fn test_print_item_not_ok() {
        // Just verify it doesn't panic
        print_item("Label", "value", false);
    }

    #[test]
    fn test_print_item_empty_label() {
        print_item("", "value", true);
    }

    #[test]
    fn test_print_item_empty_value() {
        print_item("Label", "", true);
    }

    #[test]
    fn test_generate_with_specific_path() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let output_path = temp.path().join("test-identity.txt");

        let result = generate(Some(output_path.clone()), &Config::default());
        assert!(result.is_ok());

        // Verify file was created
        assert!(output_path.exists());

        // Verify file contains identity data
        let content = std::fs::read_to_string(&output_path).expect("Failed to read identity file");
        assert!(content.contains("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_generate_creates_parent_directory() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let output_path = temp.path().join("subdir").join("identity.txt");

        let result = generate(Some(output_path.clone()), &Config::default());
        assert!(result.is_ok());

        // Verify parent directory was created
        assert!(output_path.parent().unwrap().exists());
        assert!(output_path.exists());
    }

    #[test]
    fn test_generate_uses_configured_identity_path() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_path = temp.path().join("configured-key.txt");

        let mut config = Config::default();
        config.age.identity = Some(identity_path.clone());

        let result = generate(None, &config);
        assert!(result.is_ok());
        assert!(identity_path.exists());
    }

    #[test]
    fn test_generate_refuses_to_overwrite_existing_identity() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_path = temp.path().join("existing-key.txt");
        std::fs::write(&identity_path, "AGE-SECRET-KEY-1EXISTING").expect("Failed to write key");

        let mut config = Config::default();
        config.age.identity = Some(identity_path.clone());

        let result = generate(None, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Refusing to overwrite")
        );

        let content =
            std::fs::read_to_string(&identity_path).expect("Failed to read identity file");
        assert!(content.contains("AGE-SECRET-KEY-1EXISTING"));
    }

    #[test]
    fn test_generate_refuses_ssh_identity_path() {
        let mut config = Config::default();
        config.age.identity = Some(PathBuf::from("/home/user/.ssh/id_ed25519"));

        let result = generate(None, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SSH key"));
    }

    #[test]
    fn test_migrate_encrypted_file_roundtrip() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        // Create old and new identities
        let old_identity = Identity::generate();
        let old_recipient = old_identity.to_public();

        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();

        // Create and encrypt a test file with old key
        let test_file = temp.path().join("test.txt.age");
        let original_content = b"secret data";

        let encrypted =
            guisu_crypto::encrypt(original_content, &[old_recipient]).expect("Encryption failed");
        std::fs::write(&test_file, encrypted).expect("Failed to write file");

        // Migrate the file
        let result = migrate_encrypted_file(&test_file, &[old_identity], &[new_recipient]);
        assert!(result.is_ok());

        // Verify the file can be decrypted with new identity
        let migrated_content = std::fs::read(&test_file).expect("Failed to read migrated file");
        let decrypted =
            guisu_crypto::decrypt(&migrated_content, &[new_identity]).expect("Decryption failed");

        assert_eq!(decrypted, original_content);
    }

    #[test]
    fn test_migrate_encrypted_file_wrong_old_key() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        // Create identities
        let identity1 = Identity::generate();
        let recipient1 = identity1.to_public();

        let identity2 = Identity::generate();
        let identity3 = Identity::generate();
        let recipient3 = identity3.to_public();

        // Create and encrypt a test file with identity1
        let test_file = temp.path().join("test.txt.age");
        let original_content = b"secret data";

        let encrypted =
            guisu_crypto::encrypt(original_content, &[recipient1]).expect("Encryption failed");
        std::fs::write(&test_file, encrypted).expect("Failed to write file");

        // Try to migrate with wrong old identity (identity2)
        let result = migrate_encrypted_file(&test_file, &[identity2], &[recipient3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_migrate_inline_file_roundtrip() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        // Create old and new identities
        let old_identity = Identity::generate();
        let old_recipient = old_identity.to_public();

        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();

        // Create a test file with inline encrypted content
        let test_file = temp.path().join("config.txt");
        let encrypted_value =
            encrypt_inline("my_secret", &[old_recipient]).expect("Encryption failed");
        let file_content = format!("password = {encrypted_value}\nother = plain");

        std::fs::write(&test_file, &file_content).expect("Failed to write file");

        // Migrate the file
        let result = migrate_inline_file(&test_file, &[old_identity], &[new_recipient]);
        assert!(result.is_ok());

        // Verify the file still contains inline encryption
        let migrated_content =
            std::fs::read_to_string(&test_file).expect("Failed to read migrated file");
        assert!(migrated_content.contains("age:"));
        assert!(migrated_content.contains("other = plain"));

        // Verify the inline encrypted value can be decrypted with new identity
        let decrypted = guisu_crypto::decrypt_file_content(&migrated_content, &[new_identity])
            .expect("Decryption failed");
        assert!(decrypted.contains("my_secret"));
        assert!(decrypted.contains("other = plain"));
    }

    #[test]
    fn test_migrate_inline_file_multiple_values() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        // Create old and new identities
        let old_identity = Identity::generate();
        let old_recipient = old_identity.to_public();

        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();

        // Create a test file with multiple inline encrypted values
        let test_file = temp.path().join("config.txt");
        let enc1 = encrypt_inline("secret1", std::slice::from_ref(&old_recipient))
            .expect("Encryption failed");
        let enc2 = encrypt_inline("secret2", std::slice::from_ref(&old_recipient))
            .expect("Encryption failed");
        let file_content = format!("password = {enc1}\napi_key = {enc2}");

        std::fs::write(&test_file, &file_content).expect("Failed to write file");

        // Migrate the file
        let result = migrate_inline_file(&test_file, &[old_identity], &[new_recipient]);
        assert!(result.is_ok());

        // Verify both values can be decrypted with new identity
        let migrated_content =
            std::fs::read_to_string(&test_file).expect("Failed to read migrated file");
        let decrypted = guisu_crypto::decrypt_file_content(&migrated_content, &[new_identity])
            .expect("Decryption failed");

        assert!(decrypted.contains("secret1"));
        assert!(decrypted.contains("secret2"));
    }

    #[test]
    fn test_migrate_inline_file_preserves_non_encrypted() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        // Create old and new identities
        let old_identity = Identity::generate();
        let old_recipient = old_identity.to_public();

        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();

        // Create a test file with mixed content
        let test_file = temp.path().join("config.txt");
        let encrypted_value =
            encrypt_inline("secret", &[old_recipient]).expect("Encryption failed");
        let file_content =
            format!("# Comment\nplain_text = hello\npassword = {encrypted_value}\nother = world");

        std::fs::write(&test_file, &file_content).expect("Failed to write file");

        // Migrate the file
        let result = migrate_inline_file(&test_file, &[old_identity], &[new_recipient]);
        assert!(result.is_ok());

        // Verify plain text is preserved
        let migrated_content =
            std::fs::read_to_string(&test_file).expect("Failed to read migrated file");
        let decrypted = guisu_crypto::decrypt_file_content(&migrated_content, &[new_identity])
            .expect("Decryption failed");

        assert!(decrypted.contains("# Comment"));
        assert!(decrypted.contains("plain_text = hello"));
        assert!(decrypted.contains("other = world"));
        assert!(decrypted.contains("secret"));
    }

    #[test]
    fn test_encrypt_with_specific_recipients() {
        let identity1 = Identity::generate();
        let recipient1 = identity1.to_public();

        let identity2 = Identity::generate();
        let recipient2 = identity2.to_public();

        // Verify recipient parsing works
        let recipient_strs = [recipient1.to_string(), recipient2.to_string()];

        let parse_result: Result<Vec<_>, _> = recipient_strs
            .iter()
            .map(|s| s.parse::<guisu_crypto::Recipient>())
            .collect();

        assert!(parse_result.is_ok());
        let parsed_recipients = parse_result.unwrap();
        assert_eq!(parsed_recipients.len(), 2);
    }

    #[test]
    fn test_decrypt_with_valid_value() {
        let identity = Identity::generate();
        let recipient = identity.to_public();

        // Create a valid encrypted value
        let encrypted = encrypt_inline("test_secret", &[recipient]).expect("Encryption failed");

        // Create config with this identity
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_file = temp.path().join("identity.txt");
        guisu_crypto::IdentityFile::save(&identity_file, std::slice::from_ref(&identity))
            .expect("Failed to save identity");

        let mut config = Config::default();
        config.age.identity = Some(identity_file);

        // Decrypt should work
        let result = decrypt(&encrypted, &config);
        // Note: decrypt prints to stdout, so we can't easily capture the result
        // Just verify it doesn't panic
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_with_no_identities() {
        let config = Config::default();
        let result = show(&config);
        // Should return error when no identities configured
        assert!(result.is_err());
    }

    #[test]
    fn test_show_with_single_identity() {
        let identity = Identity::generate();

        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_file = temp.path().join("identity.txt");
        guisu_crypto::IdentityFile::save(&identity_file, &[identity])
            .expect("Failed to save identity");

        let mut config = Config::default();
        config.age.identity = Some(identity_file);

        let result = show(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_with_multiple_identities() {
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();

        let temp = TempDir::new().expect("Failed to create temp dir");
        let file1 = temp.path().join("identity1.txt");
        let file2 = temp.path().join("identity2.txt");

        guisu_crypto::IdentityFile::save(&file1, &[identity1]).expect("Failed to save identity1");
        guisu_crypto::IdentityFile::save(&file2, &[identity2]).expect("Failed to save identity2");

        let mut config = Config::default();
        config.age.identities = Some(vec![file1, file2]);

        let result = show(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_identity_is_valid() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let output_path = temp.path().join("identity.txt");

        // Generate identity
        generate(Some(output_path.clone()), &Config::default()).expect("Generate failed");

        // Load the generated identity
        let identities =
            guisu_crypto::load_identities(&output_path, false).expect("Failed to load identity");

        assert_eq!(identities.len(), 1);

        // Verify we can encrypt and decrypt with it
        let recipient = identities
            .first()
            .expect("identity vec should have one element")
            .to_public();
        let plaintext = b"test message";

        let encrypted = guisu_crypto::encrypt(plaintext, &[recipient]).expect("Encryption failed");
        let decrypted = guisu_crypto::decrypt(&encrypted, &identities).expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_migrate_encrypted_file_preserves_permissions() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let temp = TempDir::new().expect("Failed to create temp dir");

            // Create identities
            let old_identity = Identity::generate();
            let old_recipient = old_identity.to_public();
            let new_identity = Identity::generate();
            let new_recipient = new_identity.to_public();

            // Create encrypted file with specific permissions
            let test_file = temp.path().join("secret.age");
            let encrypted =
                guisu_crypto::encrypt(b"data", &[old_recipient]).expect("Encryption failed");
            std::fs::write(&test_file, encrypted).expect("Failed to write file");

            // Set specific permissions (e.g., 0600)
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&test_file, perms).expect("Failed to set permissions");

            // Migrate
            migrate_encrypted_file(&test_file, &[old_identity], &[new_recipient])
                .expect("Migration failed");

            // Verify permissions are preserved
            let metadata = std::fs::metadata(&test_file).expect("Failed to get metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_migrate_inline_file_empty_file() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        let old_identity = Identity::generate();
        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();

        // Create empty file
        let test_file = temp.path().join("empty.txt");
        std::fs::write(&test_file, "").expect("Failed to write file");

        // Migration should succeed (no encrypted values to migrate)
        let result = migrate_inline_file(&test_file, &[old_identity], &[new_recipient]);
        assert!(result.is_ok());

        // File should still be empty
        let content = std::fs::read_to_string(&test_file).expect("Failed to read file");
        assert_eq!(content, "");
    }

    #[test]
    fn test_migrate_inline_file_no_encrypted_values() {
        let temp = TempDir::new().expect("Failed to create temp dir");

        let old_identity = Identity::generate();
        let new_identity = Identity::generate();
        let new_recipient = new_identity.to_public();

        // Create file with no encrypted values
        let test_file = temp.path().join("plain.txt");
        let content = "This is plain text\nNo encryption here";
        std::fs::write(&test_file, content).expect("Failed to write file");

        // Migration should succeed
        let result = migrate_inline_file(&test_file, &[old_identity], &[new_recipient]);
        assert!(result.is_ok());

        // Content should be unchanged
        let migrated = std::fs::read_to_string(&test_file).expect("Failed to read file");
        assert_eq!(migrated, content);
    }
}
