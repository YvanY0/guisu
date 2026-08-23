//! Cat command implementation
//!
//! Display the processed content of managed files (decrypt + render templates).

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::AbsPath;
use guisu_engine::state::SourceState;
use guisu_template::TemplateContext;
use std::fs;
use std::path::{Path, PathBuf};

use crate::command::Command;
use crate::common::RuntimeContext;
use guisu_config::Config;

/// Cat command
#[derive(Args)]
pub struct CatCommand {
    /// Files to display
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
}

impl Command for CatCommand {
    type Output = ();
    fn execute(&self, context: &mut RuntimeContext) -> crate::error::Result<()> {
        run_impl(
            context.source_dir(),
            context.dest_dir().as_path(),
            &self.files,
            &context.config,
        )
        .map_err(Into::into)
    }
}

/// Run the cat command implementation
fn run_impl(source_dir: &Path, dest_dir: &Path, files: &[PathBuf], config: &Config) -> Result<()> {
    if files.is_empty() {
        anyhow::bail!("No files specified. Usage: guisu cat <file>");
    }

    // Resolve all paths (handles root_entry and canonicalization)
    let paths = crate::common::ResolvedPaths::resolve(source_dir, dest_dir, config)?;
    let source_abs = &paths.dotfiles_dir;
    let dest_abs = &paths.dest_dir;

    // Create ignore matcher from .guisu/ignores.toml
    // Use dotfiles_dir as the match root so patterns match relative to the dotfiles directory
    let _ignore_matcher = guisu_config::IgnoreMatcher::from_ignores_toml(source_dir)
        .context("Failed to load ignore patterns from .guisu/ignores.toml")?;

    // Read source state
    let source_state =
        SourceState::read(source_abs.to_owned()).context("Failed to read source state")?;

    if source_state.is_empty() {
        anyhow::bail!("No files managed. Add files with: guisu add <file>");
    }

    // Process each file
    for file_path in files {
        cat_file(
            &source_state,
            dest_abs,
            file_path,
            config,
            source_dir,
            dest_dir,
        )?;
    }

    Ok(())
}

/// Resolve file path by expanding tilde and converting to absolute path
fn resolve_file_path(file_path: &Path, dest_abs: &AbsPath) -> Result<guisu_core::path::RelPath> {
    // Expand tilde in path
    let expanded_path = if file_path.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            let path_str = file_path.to_string_lossy();
            let without_tilde = path_str
                .strip_prefix("~/")
                .or(path_str.strip_prefix("~"))
                .unwrap_or(&path_str);
            home.join(without_tilde)
        } else {
            file_path.to_path_buf()
        }
    } else {
        file_path.to_path_buf()
    };

    // Try to get absolute path, but if file doesn't exist, construct it manually
    let file_abs = if expanded_path.exists() {
        AbsPath::new(
            fs::canonicalize(&expanded_path)
                .with_context(|| format!("Failed to resolve path: {}", expanded_path.display()))?,
        )?
    } else {
        // File doesn't exist yet, construct absolute path manually
        let abs_path = if expanded_path.is_absolute() {
            expanded_path
        } else {
            std::env::current_dir()?.join(&expanded_path)
        };
        AbsPath::new(abs_path)?
    };

    // Get relative path from destination
    file_abs.strip_prefix(dest_abs).with_context(|| {
        format!(
            "File {} is not under destination directory {}",
            file_abs.as_path().display(),
            dest_abs.as_path().display()
        )
    })
}

/// Get source entry info and validate it's a file (not directory or symlink)
fn get_source_entry_info<'a>(
    source_state: &'a SourceState,
    rel_path: &guisu_core::path::RelPath,
    file_path: &Path,
) -> Result<(&'a guisu_core::path::SourceRelPath, bool, bool)> {
    // Find the entry in source state
    let entry = source_state
        .get(rel_path)
        .with_context(|| format!("File not managed by guisu: {}", file_path.display()))?;

    // Get source file path and attributes
    match entry {
        guisu_engine::entry::SourceEntry::File {
            source_path,
            attributes,
            ..
        } => Ok((source_path, attributes.is_template, attributes.is_encrypted)),
        guisu_engine::entry::SourceEntry::Directory { .. } => {
            anyhow::bail!("{} is a directory", file_path.display());
        }
        guisu_engine::entry::SourceEntry::Symlink { .. } => {
            anyhow::bail!("{} is a symlink", file_path.display());
        }
    }
}

/// Render template content with context
fn render_template_content(
    content_str: &str,
    source_path: &guisu_core::path::SourceRelPath,
    source_dir: &Path,
    dest_dir: &Path,
    config: &Config,
) -> Result<Vec<u8>> {
    // Load identities for encryption/decryption filters
    let identities = load_identities_for_template(config)?;
    let identities_arc = std::sync::Arc::new(identities);

    // Create template engine with template directory support and bitwarden provider
    let engine = crate::create_template_engine(source_dir, &identities_arc, config);

    let dotfiles_dir_str = crate::path_to_string(&config.dotfiles_dir(source_dir));
    let root_entry_str = crate::path_to_string(&config.general.root_entry);
    let working_tree = guisu_engine::git::find_working_tree(source_dir)
        .unwrap_or_else(|| source_dir.to_path_buf());
    let mut template_ctx = TemplateContext::new().with_guisu_info(
        dotfiles_dir_str,
        crate::path_to_string(&working_tree),
        crate::path_to_string(dest_dir),
        root_entry_str.clone(),
    );

    // Add user variables from config
    template_ctx = template_ctx.with_variables_ref(&config.variables);

    // Build template name with root_entry prefix
    let template_name = format!("{}/{}", root_entry_str, source_path.as_path().display());

    let rendered = engine
        .render_named_str(&template_name, content_str, &template_ctx)
        .map_err(|e| {
            // Enhance error message with source line content
            let error_msg = e.to_string();
            let enhanced_msg = enhance_template_error(&error_msg, content_str);
            anyhow::anyhow!("{enhanced_msg}")
        })?;

    Ok(rendered.into_bytes())
}

/// Decrypt inline age values in content (sops-like behavior)
fn decrypt_inline_values(content: Vec<u8>, config: &Config) -> Result<Vec<u8>> {
    let content_str = String::from_utf8(content).context("File content is not valid UTF-8")?;
    let identities = load_identities_for_template(config)?;

    if identities.is_empty() {
        Ok(content_str.into_bytes())
    } else {
        // Only try to decrypt if we have identities available
        let decrypted_content =
            guisu_crypto::decrypt_file_content(&content_str, &identities).unwrap_or(content_str);
        Ok(decrypted_content.into_bytes())
    }
}

/// Output content to stdout with POSIX-compliant newline
fn output_content_with_newline(content: &[u8]) -> Result<()> {
    std::io::Write::write_all(&mut std::io::stdout(), content)?;

    // Ensure output ends with newline (POSIX standard for text files)
    // This prevents the shell '%' symbol from appearing
    if !content.is_empty() && !content.ends_with(b"\n") {
        println!();
    }

    Ok(())
}

fn cat_file(
    source_state: &SourceState,
    dest_abs: &AbsPath,
    file_path: &Path,
    config: &Config,
    source_dir: &Path,
    dest_dir: &Path,
) -> Result<()> {
    // Resolve file path and get relative path
    let rel_path = resolve_file_path(file_path, dest_abs)?;

    // Get source entry info and validate it's a file
    let (source_path, is_template, is_encrypted) =
        get_source_entry_info(source_state, &rel_path, file_path)?;

    let source_file_path = source_state.source_file_path(source_path);

    // Read the file content
    let mut content = fs::read(source_file_path.as_path())
        .with_context(|| format!("Failed to read source file: {source_file_path:?}"))?;

    // Decrypt if encrypted
    if is_encrypted {
        content = decrypt_content(&content, config)?;
    }

    // Render template if needed
    if is_template {
        let content_str = String::from_utf8(content).context("File content is not valid UTF-8")?;
        content = render_template_content(&content_str, source_path, source_dir, dest_dir, config)?;
    }

    // Decrypt inline age values (sops-like behavior)
    content = decrypt_inline_values(content, config)?;

    // Output the content
    output_content_with_newline(&content)?;

    Ok(())
}

/// Decrypt content using age
fn decrypt_content(encrypted: &[u8], config: &Config) -> Result<Vec<u8>> {
    // Load all configured identities
    let identities = config.age_identities()?;

    guisu_crypto::decrypt(encrypted, &identities).context("Failed to decrypt content")
}

/// Load age identities for template rendering (encrypt/decrypt filters)
fn load_identities_for_template(config: &Config) -> Result<Vec<guisu_crypto::Identity>> {
    // Try to load all configured identities
    // If no identities configured or files don't exist, return empty vec
    // Templates with encrypt/decrypt filters will fail with helpful error
    config.age_identities().or_else(|_| Ok(Vec::new()))
}

/// Enhance template error messages with source line content
///
/// Extracts the line number from the error message, removes redundant path info,
/// and includes the actual source line content to help users identify issues.
fn enhance_template_error(error_msg: &str, template_source: &str) -> String {
    // Clean up the error message - remove redundant " (in filename:line)" suffix
    let cleaned_msg = if let Some(pos) = error_msg.find(" (in ") {
        error_msg[..pos].to_string()
    } else {
        error_msg.to_string()
    };

    // Try to extract line number from error message
    // Format: "... line 25 ..." or "... line 25, column 10 ..."
    let line_num = if let Some(pos) = cleaned_msg.find(" line ") {
        let after_line = &cleaned_msg[pos + 6..];
        // Extract digits until non-digit
        let num_str: String = after_line
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        num_str.parse::<usize>().ok()
    } else {
        None
    };

    // If we found a line number, try to include the full source line
    if let Some(line_no) = line_num {
        let lines: Vec<&str> = template_source.lines().collect();
        if line_no > 0 && line_no <= lines.len() {
            let source_line = lines[line_no - 1]; // lines are 1-indexed
            // Show the full line content (no truncation)
            return format!("{cleaned_msg}\nSource line {line_no}:\n  {source_line}");
        }
    }

    // If we couldn't enhance the message, return the cleaned version
    cleaned_msg
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use guisu_crypto::{Identity, IdentityFile, encrypt};
    use tempfile::TempDir;

    // Helper to create test config
    fn test_config() -> Config {
        Config::default()
    }

    // Helper to create test config with age identity
    fn test_config_with_identity(identity_path: &Path) -> Config {
        let mut config = Config::default();
        config.age.identity = Some(identity_path.to_path_buf());
        config
    }

    #[test]
    fn test_enhance_template_error_with_line_number() {
        let error_msg = "undefined variable 'missing' at line 5";
        let template_source = "line 1\nline 2\nline 3\nline 4\nthis is {{ missing }}\nline 6";

        let enhanced = enhance_template_error(error_msg, template_source);

        assert!(enhanced.contains("line 5"));
        assert!(enhanced.contains("this is {{ missing }}"));
    }

    #[test]
    fn test_enhance_template_error_with_path_suffix() {
        let error_msg = "undefined variable 'foo' at line 3 (in template.j2:3)";
        let template_source = "line 1\nline 2\n{{ foo }}\nline 4";

        let enhanced = enhance_template_error(error_msg, template_source);

        // Should remove the " (in template.j2:3)" suffix
        assert!(!enhanced.contains("(in template.j2:3)"));
        assert!(enhanced.contains("{{ foo }}"));
    }

    #[test]
    fn test_enhance_template_error_no_line_number() {
        let error_msg = "template error: syntax error";
        let template_source = "some template content";

        let enhanced = enhance_template_error(error_msg, template_source);

        // Should return cleaned message without source line
        assert_eq!(enhanced, "template error: syntax error");
    }

    #[test]
    fn test_enhance_template_error_line_out_of_bounds() {
        let error_msg = "error at line 100";
        let template_source = "line 1\nline 2\nline 3";

        let enhanced = enhance_template_error(error_msg, template_source);

        // Should return cleaned message when line number is out of bounds
        assert_eq!(enhanced, "error at line 100");
    }

    #[test]
    fn test_enhance_template_error_with_column() {
        let error_msg = "syntax error at line 2, column 5";
        let template_source = "line 1\n{{ bad syntax }}\nline 3";

        let enhanced = enhance_template_error(error_msg, template_source);

        assert!(enhanced.contains("line 2"));
        assert!(enhanced.contains("{{ bad syntax }}"));
    }

    #[test]
    fn test_decrypt_content_success() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_file = temp.path().join("identity.txt");

        // Generate identity and save
        let identity = Identity::generate();
        IdentityFile::save(&identity_file, std::slice::from_ref(&identity))
            .expect("Failed to save identity");

        // Create config with identity
        let config = test_config_with_identity(&identity_file);

        // Encrypt some content
        let plaintext = b"secret content";
        let encrypted = encrypt(plaintext, &[identity.to_public()]).expect("Encryption failed");

        // Decrypt using our function
        let decrypted = decrypt_content(&encrypted, &config).expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_content_no_identity() {
        let config = test_config();

        // Create some fake encrypted content
        let encrypted = b"age-encryption-data";

        // Should fail when no identity configured
        let result = decrypt_content(encrypted, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_identities_for_template_success() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_file = temp.path().join("identity.txt");

        // Generate identity and save
        let identity = Identity::generate();
        IdentityFile::save(&identity_file, &[identity]).expect("Failed to save identity");

        // Create config with identity
        let config = test_config_with_identity(&identity_file);

        // Load identities
        let identities = load_identities_for_template(&config).expect("Failed to load identities");

        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn test_load_identities_for_template_no_identity() {
        let config = test_config();

        // Should return empty vec when no identities configured
        let identities = load_identities_for_template(&config).expect("Failed to load identities");

        assert_eq!(identities.len(), 0);
    }

    #[test]
    fn test_load_identities_for_template_missing_file() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_file = temp.path().join("nonexistent.txt");

        // Create config with non-existent identity file
        let config = test_config_with_identity(&identity_file);

        // Should return empty vec when identity file doesn't exist
        let identities = load_identities_for_template(&config).expect("Failed to load identities");

        assert_eq!(identities.len(), 0);
    }

    #[test]
    fn test_enhance_template_error_empty_template() {
        let error_msg = "error at line 1";
        let template_source = "";

        let enhanced = enhance_template_error(error_msg, template_source);

        // Should handle empty template gracefully
        assert_eq!(enhanced, "error at line 1");
    }

    #[test]
    fn test_enhance_template_error_multiline_source() {
        let error_msg = "undefined variable at line 3";
        let template_source = "# Header\n\nConfig: {{ undefined }}\n\n# Footer";

        let enhanced = enhance_template_error(error_msg, template_source);

        assert!(enhanced.contains("Config: {{ undefined }}"));
    }

    #[test]
    fn test_enhance_template_error_line_zero() {
        let error_msg = "error at line 0";
        let template_source = "line 1\nline 2";

        let enhanced = enhance_template_error(error_msg, template_source);

        // Line 0 is invalid (out of bounds for 1-indexed lines)
        assert_eq!(enhanced, "error at line 0");
    }

    #[test]
    fn test_run_impl_no_files() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = temp.path();
        let dest_dir = temp.path();
        let config = test_config();

        let result = run_impl(source_dir, dest_dir, &[], &config);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No files specified")
        );
    }

    #[test]
    fn test_decrypt_content_wrong_identity() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let identity_file = temp.path().join("identity.txt");

        // Generate two different identities
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();

        // Save identity2 to file
        IdentityFile::save(&identity_file, &[identity2]).expect("Failed to save identity");

        // Create config with identity2
        let config = test_config_with_identity(&identity_file);

        // Encrypt with identity1
        let plaintext = b"secret content";
        let encrypted = encrypt(plaintext, &[identity1.to_public()]).expect("Encryption failed");

        // Try to decrypt with identity2 (should fail)
        let result = decrypt_content(&encrypted, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_enhance_template_error_preserves_original_message() {
        let error_msg = "complex error with multiple parts at line 5 and more info";
        let template_source = "1\n2\n3\n4\n5\n6";

        let enhanced = enhance_template_error(error_msg, template_source);

        // Should preserve the original error message
        assert!(enhanced.starts_with("complex error with multiple parts at line 5"));
    }

    #[test]
    fn test_enhance_template_error_with_special_characters_in_line() {
        let error_msg = "error at line 2";
        let template_source = "normal line\n{{ special_chars: \"@#$%^&*()\" }}\nnormal line";

        let enhanced = enhance_template_error(error_msg, template_source);

        assert!(enhanced.contains("{{ special_chars: \"@#$%^&*()\" }}"));
    }
}
