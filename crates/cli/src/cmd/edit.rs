//! Edit command implementation
//!
//! Edit files in the source directory with transparent decryption for encrypted files.

use anyhow::{Context, Result};
use clap::Args;
use guisu_crypto::{decrypt, decrypt_file_content, encrypt, encrypt_inline};
use owo_colors::OwoColorize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use tempfile::TempDir;

use crate::command::Command;
use crate::common::RuntimeContext;
use guisu_config::Config;

/// Cached regex for matching inline age encrypted values
static AGE_VALUE_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"age:[A-Za-z0-9+/]+=*")
        .expect("AGE_VALUE_REGEX compilation should never fail")
});

/// Edit command
#[derive(Args)]
pub struct EditCommand {
    /// Target file to edit (e.g., ~/.bashrc)
    #[arg(required = true)]
    pub target: PathBuf,

    /// Apply changes after editing
    #[arg(short, long)]
    pub apply: bool,
}

impl Command for EditCommand {
    type Output = ();
    fn execute(&self, context: &RuntimeContext) -> crate::error::Result<()> {
        // Determine whether to apply: command line flag takes precedence over config
        // If --apply is passed on command line, use it
        // Otherwise, use config.edit.apply as default
        let should_apply = self.apply || context.config.edit.apply;

        // Edit the file and check if it was modified
        let modified = edit_file(
            context.source_dir(),
            context.dest_dir().as_path(),
            &self.target,
            &context.config,
        )?;

        // Apply only if requested AND file was modified
        if should_apply && modified {
            // Create ApplyCommand with target file
            let apply_cmd = crate::cmd::apply::ApplyCommand {
                files: vec![self.target.clone()],
                dry_run: false,
                force: false,
                interactive: false,
                include: vec![],
                exclude: vec![],
            };

            // Execute apply with the existing context (no database lock issue)
            apply_cmd.execute(context)?;
        }

        Ok(())
    }
}

/// Edit a file in the source directory
/// Returns true if the file was modified
fn edit_file(source_dir: &Path, dest_dir: &Path, target: &Path, config: &Config) -> Result<bool> {
    let source_file = find_source_file(source_dir, dest_dir, target, config)?;

    // Read original content
    let before = fs::read(&source_file)?;

    // Edit the file
    let is_encrypted = source_file
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e == "age");

    if is_encrypted {
        edit_encrypted_file(&source_file, config)?;
    } else {
        edit_regular_file(&source_file, config)?;
    }

    // Check if modified
    let after = fs::read(&source_file)?;
    Ok(before != after)
}

/// Find the source file corresponding to a target file
fn find_source_file(
    source_dir: &Path,
    dest_dir: &Path,
    target: &Path,
    config: &Config,
) -> Result<PathBuf> {
    // Convert target to absolute path
    let target_abs = fs::canonicalize(target)
        .with_context(|| format!("Target file not found: {}", target.display()))?;

    // Get relative path from destination
    let rel_path = target_abs.strip_prefix(dest_dir).with_context(|| {
        format!(
            "Target {} is not under destination directory {}",
            target_abs.display(),
            dest_dir.display()
        )
    })?;

    // Build base path with root_entry
    let base_path = source_dir.join(&config.general.root_entry).join(rel_path);

    // Try possible file name combinations
    let candidates = vec![
        base_path.clone(),
        // Try adding .age extension
        {
            let mut path = base_path.clone();
            if let Some(file_name) = base_path.file_name() {
                path.set_file_name(format!("{}.age", file_name.to_string_lossy()));
            }
            path
        },
        // Try adding .j2 extension
        {
            let mut path = base_path.clone();
            if let Some(file_name) = base_path.file_name() {
                path.set_file_name(format!("{}.j2", file_name.to_string_lossy()));
            }
            path
        },
        // Handle .j2.age case
        {
            let mut path = base_path.clone();
            if let Some(file_name) = base_path.file_name() {
                path.set_file_name(format!("{}.j2.age", file_name.to_string_lossy()));
            }
            path
        },
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    anyhow::bail!("File not managed by guisu: {}", target.display())
}

/// Get the editor command to use
fn get_editor(config: &Config) -> (String, Vec<String>) {
    // 4. System default editor constants
    #[cfg(unix)]
    const DEFAULT_EDITOR: &str = "vi";
    #[cfg(windows)]
    const DEFAULT_EDITOR: &str = "notepad.exe";

    // 1. Use configured editor if available
    if let Some(editor_cmd) = config.editor_command()
        && let Some((cmd, args)) = editor_cmd.split_first()
    {
        return (cmd.clone(), args.to_vec());
    }

    // 2. Try $VISUAL environment variable
    if let Ok(visual) = env::var("VISUAL") {
        return (visual, vec![]);
    }

    // 3. Try $EDITOR environment variable
    if let Ok(editor) = env::var("EDITOR") {
        return (editor, vec![]);
    }

    (DEFAULT_EDITOR.to_string(), vec![])
}

/// Run the editor with the given file
fn run_editor(editor: &str, args: &[String], file: &Path) -> Result<()> {
    let status = ProcessCommand::new(editor)
        .args(args)
        .arg(file)
        .status()
        .with_context(|| format!("Failed to run editor: {editor}"))?;

    if !status.success() {
        anyhow::bail!("Editor exited with error: {status}");
    }

    Ok(())
}

/// Edit a regular (non-encrypted) file
/// This also handles files with inline age: encrypted values (sops-like behavior)
fn edit_regular_file(source_file: &Path, config: &Config) -> Result<()> {
    // Try to load all configured identities for inline decryption
    let identities = config.age_identities().ok();

    // If we have identities, check if the file contains inline encrypted values
    if let Some(ref ids) = identities
        && let Ok(content) = fs::read_to_string(source_file)
    {
        // Check if content contains age: prefix
        if content.contains("age:") {
            // Edit with inline decryption/encryption
            return edit_file_with_inline_encryption(source_file, config, ids);
        }
    }

    // No inline encryption or no identities - edit normally
    let (editor, args) = get_editor(config);
    run_editor(&editor, &args, source_file)
}

/// Edit a file that contains inline age: encrypted values
/// Decrypts them before editing and re-encrypts after
fn edit_file_with_inline_encryption(
    source_file: &Path,
    config: &Config,
    identities: &[guisu_crypto::Identity],
) -> Result<()> {
    // Read the original file content
    let original_content = fs::read_to_string(source_file)
        .with_context(|| format!("Failed to read file: {}", source_file.display()))?;

    // Track all encrypted values for re-encryption using cached regex
    let encrypted_positions: Vec<_> = AGE_VALUE_REGEX
        .find_iter(&original_content)
        .map(|m| (m.start(), m.end(), m.as_str().to_string()))
        .collect();

    // Decrypt all inline values for editing
    let decrypted_content = decrypt_file_content(&original_content, identities)
        .context("Failed to decrypt inline age values")?;

    // Create temporary file
    let temp_dir = tempfile::TempDir::new().context("Failed to create temporary directory")?;
    let temp_file = temp_dir
        .path()
        .join(source_file.file_name().context("Invalid file name")?);

    // Write decrypted content to temp file
    fs::write(&temp_file, &decrypted_content)
        .context("Failed to write decrypted content to temporary file")?;

    // Open editor
    let (editor, args) = get_editor(config);
    run_editor(&editor, &args, &temp_file)?;

    // Read edited content
    let edited_content = fs::read_to_string(&temp_file).context("Failed to read edited content")?;

    // Check if content changed
    if edited_content == decrypted_content {
        println!("  {} No changes made", "ℹ".bright_blue());
        return Ok(());
    }

    // Re-encrypt the edited plaintext values
    let mut final_content = edited_content;

    // Convert all identities to recipients for re-encryption
    let recipients = guisu_crypto::identities_to_recipients(identities);

    for (_, _, encrypted_value) in encrypted_positions {
        if let Ok(decrypted_value) = guisu_crypto::decrypt_inline(&encrypted_value, identities)
            && final_content.contains(&decrypted_value)
        {
            let new_encrypted = encrypt_inline(&decrypted_value, &recipients)
                .context("Failed to re-encrypt value")?;
            final_content = final_content.replacen(&decrypted_value, &new_encrypted, 1);
        }
    }

    // Write the final content back to source file
    fs::write(source_file, &final_content)
        .with_context(|| format!("Failed to write file: {}", source_file.display()))?;

    println!(
        "  {} File updated with re-encrypted values",
        "✓".bright_green()
    );

    Ok(())
}

/// Edit an encrypted file with transparent decryption/encryption
fn edit_encrypted_file(source_file: &Path, config: &Config) -> Result<()> {
    // Load all configured identities
    let identities = config
        .age_identities()
        .context("Age identity not configured. Cannot edit encrypted files.")?;

    // Read and decrypt the file
    let encrypted_content = fs::read(source_file)
        .with_context(|| format!("Failed to read encrypted file: {}", source_file.display()))?;

    let decrypted_content =
        decrypt(&encrypted_content, &identities).context("Failed to decrypt file")?;

    // Create temporary directory and file
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;

    // Build temporary file name (remove .age extension)
    let temp_file_name = source_file
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid file name")?;

    let temp_file = temp_dir.path().join(temp_file_name);

    // Write decrypted content to temporary file
    fs::write(&temp_file, &decrypted_content)
        .context("Failed to write decrypted content to temporary file")?;

    // Get editor and run it
    let (editor, args) = get_editor(config);
    run_editor(&editor, &args, &temp_file)?;

    // Read the edited content
    let edited_content =
        fs::read(&temp_file).context("Failed to read edited content from temporary file")?;

    // Check if content changed
    if edited_content == decrypted_content {
        return Ok(());
    }

    // Re-encrypt the content with all recipients
    let recipients = guisu_crypto::identities_to_recipients(&identities);
    let reencrypted_content =
        encrypt(&edited_content, &recipients).context("Failed to re-encrypt file")?;

    // Write back to source file
    fs::write(source_file, &reencrypted_content)
        .with_context(|| format!("Failed to write encrypted file: {}", source_file.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    use tempfile::TempDir;

    // Helper to create test config
    fn test_config() -> Config {
        Config::default()
    }
    #[test]
    fn test_age_value_regex_matches_simple() {
        let content = "password = age:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOQ==";
        assert!(AGE_VALUE_REGEX.is_match(content));
    }

    #[test]
    fn test_age_value_regex_matches_multiple() {
        let content = "pass1 = age:ABC123+/= and pass2 = age:XYZ789+/=";
        let matches: Vec<_> = AGE_VALUE_REGEX.find_iter(content).collect();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_age_value_regex_no_match() {
        let content = "This is plain text without encryption";
        assert!(!AGE_VALUE_REGEX.is_match(content));
    }

    #[test]
    fn test_find_source_file_plain() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        // Canonicalize temp path to resolve symlinks (like /var -> /private/var on macOS)
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        // Create directories
        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create a plain file in source
        let source_file = source_dir.join("home").join("test.txt");
        std::fs::write(&source_file, "content").expect("Failed to write source file");

        // Create corresponding target file in destination
        let target_file = dest_dir.join("test.txt");
        std::fs::write(&target_file, "content").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), source_file);
    }

    #[test]
    fn test_find_source_file_encrypted() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create encrypted file in source (with .age extension)
        let source_file = source_dir.join("home").join("test.txt.age");
        std::fs::write(&source_file, "encrypted").expect("Failed to write source file");

        // Create corresponding target file in destination
        let target_file = dest_dir.join("test.txt");
        std::fs::write(&target_file, "plain").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), source_file);
    }

    #[test]
    fn test_find_source_file_template() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create template file in source (with .j2 extension)
        let source_file = source_dir.join("home").join("test.txt.j2");
        std::fs::write(&source_file, "template").expect("Failed to write source file");

        // Create corresponding target file in destination
        let target_file = dest_dir.join("test.txt");
        std::fs::write(&target_file, "rendered").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), source_file);
    }

    #[test]
    fn test_find_source_file_encrypted_template() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create encrypted template file in source (with .j2.age extension)
        let source_file = source_dir.join("home").join("test.txt.j2.age");
        std::fs::write(&source_file, "encrypted template").expect("Failed to write source file");

        // Create corresponding target file in destination
        let target_file = dest_dir.join("test.txt");
        std::fs::write(&target_file, "rendered").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), source_file);
    }

    #[test]
    fn test_find_source_file_not_found() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create target file in destination but no corresponding source file
        let target_file = dest_dir.join("test.txt");
        std::fs::write(&target_file, "content").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not managed"));
    }

    #[test]
    fn test_find_source_file_not_under_dest() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");

        // Create target file outside destination directory
        let target_file = temp_canon.join("outside.txt");
        std::fs::write(&target_file, "content").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not under destination")
        );
    }

    #[test]
    fn test_get_editor_from_config() {
        let mut config = Config::default();
        config.general.editor = Some("vim".to_string());
        config.general.editor_args = vec!["-n".to_string()];

        let (editor, args) = get_editor(&config);
        assert_eq!(editor, "vim");
        assert_eq!(args, vec!["-n".to_string()]);
    }

    #[test]
    fn test_get_editor_from_config_without_args() {
        let mut config = Config::default();
        config.general.editor = Some("emacs".to_string());

        let (editor, args) = get_editor(&config);
        assert_eq!(editor, "emacs");
        assert!(args.is_empty());
    }

    #[test]
    fn test_age_value_regex_with_padding() {
        // Test with various base64 padding scenarios
        let test_cases = vec![
            "age:ABC123",   // No padding
            "age:ABC123=",  // Single padding
            "age:ABC123==", // Double padding
            "age:A+B/C=",   // With + and /
        ];

        for case in test_cases {
            assert!(AGE_VALUE_REGEX.is_match(case), "Failed to match: {case}");
        }
    }

    #[test]
    fn test_find_source_file_prefers_plain() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let temp_canon = std::fs::canonicalize(temp.path()).expect("Failed to canonicalize temp");
        let source_dir = temp_canon.join("src");
        let dest_dir = temp_canon.join("dst");

        std::fs::create_dir_all(&dest_dir).expect("Failed to create dest dir");
        std::fs::create_dir_all(source_dir.join("home")).expect("Failed to create home dir");

        // Create both plain and .age versions
        let plain_file = source_dir.join("home").join("test.txt");
        let age_file = source_dir.join("home").join("test.txt.age");

        std::fs::write(&plain_file, "plain").expect("Failed to write plain file");
        std::fs::write(&age_file, "encrypted").expect("Failed to write age file");

        // Create target
        let target_file = dest_dir.join("test.txt");
        std::fs::write(&target_file, "content").expect("Failed to write target file");

        let config = test_config();

        let result = find_source_file(&source_dir, &dest_dir, &target_file, &config);
        assert!(result.is_ok());
        // Should prefer plain file (checked first in candidates list)
        assert_eq!(result.unwrap(), plain_file);
    }
}
