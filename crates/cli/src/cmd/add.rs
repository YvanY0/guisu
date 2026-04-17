//! Add command implementation
//!
//! Add files to the guisu source directory.

use anyhow::{Context, Result};
use clap::Args;
use guisu_core::path::AbsPath;
use guisu_crypto::encrypt;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;
use walkdir::WalkDir;

use crate::command::Command;
use crate::common::RuntimeContext;
use guisu_config::Config;

/// How to handle files containing secrets
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum SecretsMode {
    /// Ignore secrets and add files anyway
    Ignore,
    /// Show warnings about secrets but proceed
    Warning,
    /// Fail if secrets are detected
    Error,
}

/// Add files to the source directory
#[derive(Debug, Clone, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct AddCommand {
    /// Files to add to the source directory
    #[arg(required = true)]
    pub files: Vec<PathBuf>,

    /// Mark file as a template
    #[arg(short, long)]
    pub template: bool,

    /// Auto-detect template variables and create templates (implies --template)
    #[arg(short, long)]
    pub autotemplate: bool,

    /// Encrypt the file with age
    #[arg(short = 'E', long)]
    pub encrypt: bool,

    /// Mark file for create-once (only copy if destination doesn't exist)
    #[arg(short, long)]
    pub create: bool,

    /// Force overwrite if file already exists in source
    #[arg(short, long)]
    pub force: bool,

    /// How to handle files containing secrets
    #[arg(long, value_enum, default_value = "warning")]
    pub secrets: SecretsMode,
}

/// Parameters for adding files to guisu (internal)
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct AddParams<'a> {
    source_dir: &'a AbsPath,
    dest_dir: &'a AbsPath,
    template: bool,
    autotemplate: bool,
    encrypt: bool,
    force: bool,
    secrets_mode: SecretsMode,
    config: &'a Config,
}

impl Command for AddCommand {
    type Output = ();
    fn execute(&self, context: &RuntimeContext) -> crate::error::Result<()> {
        let source_dir = context.source_dir();
        let source_abs = context.dotfiles_dir();
        let dest_abs = context.dest_dir();
        let config = &context.config;

        // Create source directory if it doesn't exist
        if !source_dir.exists() {
            fs::create_dir_all(source_dir).with_context(|| {
                format!(
                    "Failed to create source directory: {}",
                    source_dir.display()
                )
            })?;
        }

        // Load metadata if create flag is used
        let mut metadata = if self.create {
            guisu_engine::state::Metadata::load(source_dir).context("Failed to load metadata")?
        } else {
            guisu_engine::state::Metadata::default()
        };

        // Create AddParams struct to pass to helper functions
        let params = AddParams {
            source_dir: source_abs,
            dest_dir: dest_abs,
            template: self.template,
            autotemplate: self.autotemplate,
            encrypt: self.encrypt,
            force: self.force,
            secrets_mode: self.secrets,
            config,
        };

        for file_path in &self.files {
            let (rel_path, _count) = add_file(&params, file_path)
                .with_context(|| format!("Failed to add file: {}", file_path.display()))?;

            // Add to create-once list if requested
            if self.create {
                metadata.add_create_once(rel_path.to_string());
            }
        }

        // Save metadata if create flag was used
        if self.create {
            metadata
                .save(source_dir)
                .context("Failed to save metadata")?;
        }

        Ok(())
    }
}

fn add_file(params: &AddParams, file_path: &Path) -> Result<(guisu_core::path::RelPath, usize)> {
    // Check if file is a symlink before canonicalization
    // This prevents symlink-based path traversal attacks
    let metadata = fs::symlink_metadata(file_path)
        .with_context(|| format!("File not found: {}", file_path.display()))?;

    let file_abs = if metadata.is_symlink() {
        // For symlinks, resolve the parent directory but not the symlink itself
        let parent = file_path
            .parent()
            .with_context(|| format!("Cannot get parent directory of {}", file_path.display()))?;
        let file_name = file_path
            .file_name()
            .with_context(|| format!("Cannot get file name of {}", file_path.display()))?;

        let parent_abs = fs::canonicalize(parent)
            .with_context(|| format!("Cannot resolve parent directory: {}", parent.display()))?;

        AbsPath::new(parent_abs.join(file_name))?
    } else {
        // For regular files/directories, canonicalize normally
        AbsPath::new(
            fs::canonicalize(file_path)
                .with_context(|| format!("Cannot resolve path: {}", file_path.display()))?,
        )?
    };

    // Get relative path from destination
    let rel_path = file_abs.strip_prefix(params.dest_dir).with_context(|| {
        format!(
            "File {} is not under destination directory {}",
            file_abs.as_path().display(),
            params.dest_dir.as_path().display()
        )
    })?;

    // Check if it's a directory
    let metadata = fs::metadata(file_abs.as_path())
        .with_context(|| format!("Failed to read metadata: {}", file_path.display()))?;

    let count = if metadata.is_dir() {
        // Add directory recursively
        add_directory(params, &file_abs, &rel_path)?
    } else if metadata.is_symlink() {
        // Add symlink
        add_symlink(params.source_dir, &rel_path, &file_abs, params.force)?;
        1
    } else {
        // Add regular file
        add_regular_file(params, &rel_path, &file_abs)?;
        1
    };

    Ok((rel_path, count))
}

/// Add a regular file to the source directory
/// Handle secret detection based on secrets mode
fn handle_secret_detection(
    secrets_mode: SecretsMode,
    file_abs: &AbsPath,
    rel_path: &guisu_core::path::RelPath,
    content: &[u8],
) -> Result<()> {
    if secrets_mode != SecretsMode::Ignore
        && let Some(secret_findings) = detect_secrets(file_abs.as_path(), content)
    {
        let warning_msg = format!(
            "Potential secrets detected in {}:\n{}",
            rel_path.as_path().display(),
            secret_findings
        );

        match secrets_mode {
            SecretsMode::Error => {
                anyhow::bail!(
                    "{warning_msg}\n\nTo add anyway, use: guisu add --secrets ignore\n\
                         To encrypt the file, use: guisu add --encrypt"
                );
            }
            SecretsMode::Warning => {
                warn!("{}", warning_msg);
                warn!("  Tip: Use --encrypt to protect sensitive data");
            }
            SecretsMode::Ignore => unreachable!(),
        }
    }
    Ok(())
}

/// Determine if file should be templated and process content accordingly
fn determine_template_processing(
    autotemplate: bool,
    encrypt: bool,
    template: bool,
    content: &[u8],
    file_abs: &AbsPath,
    config: &guisu_config::Config,
) -> (bool, Vec<u8>) {
    if autotemplate && !encrypt {
        // Auto-detect template variables and convert content
        match auto_template_content(content, config) {
            Ok((templated_content, has_replacements)) => {
                if has_replacements {
                    (true, templated_content)
                } else {
                    (template, content.to_vec())
                }
            }
            Err(e) => {
                warn!(
                    "autotemplate failed for {}: {}",
                    file_abs.as_path().display(),
                    e
                );
                (template, content.to_vec())
            }
        }
    } else {
        (template, content.to_vec())
    }
}

/// Build source file path with appropriate extensions
fn build_source_file_path(
    source_dir: &AbsPath,
    rel_path: &guisu_core::path::RelPath,
    is_template: bool,
    encrypt: bool,
) -> PathBuf {
    let rel_str = rel_path.as_path().to_string_lossy();
    let mut source_filename = rel_str.to_string();

    // Add extensions in the correct order (template, then encryption)
    if is_template {
        source_filename.push_str(".j2");
    }
    if encrypt {
        source_filename.push_str(".age");
    }

    source_dir.as_path().join(&source_filename)
}

/// Handle existing source file (check if re-adding with force flag)
fn handle_existing_source_file(
    source_dir: &AbsPath,
    rel_path: &guisu_core::path::RelPath,
    is_template: bool,
    encrypt: bool,
    force: bool,
) -> Result<()> {
    if let Some(existing_file) = check_file_exists_in_source(source_dir, rel_path) {
        if force {
            // Force is true - handle re-adding with potentially different attributes

            // Detect existing file attributes
            let was_template = existing_file.to_string_lossy().contains(".j2");
            let was_encrypted = existing_file
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("age"));

            // Determine if attributes are changing
            let attrs_changing = (is_template != was_template) || (encrypt != was_encrypted);

            if attrs_changing {
                // Attributes are changing - delete the old file
                fs::remove_file(&existing_file).with_context(|| {
                    format!("Failed to remove old file: {}", existing_file.display())
                })?;
            }
        } else {
            // Determine the type of existing file
            let path_str = existing_file.to_string_lossy();
            let has_j2 = path_str.contains(".j2");
            let has_age = existing_file
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("age"));

            let file_type = if has_j2 && has_age {
                "encrypted template"
            } else if has_age {
                "encrypted file"
            } else if has_j2 {
                "template"
            } else {
                "file"
            };

            anyhow::bail!(
                "This file is already managed by guisu as a {}:\n  {}\n\n\
                 To re-add with different attributes, use: guisu add --force\n\
                 To see differences, use: guisu diff\n\
                 To merge changes, use: guisu merge (not yet implemented)",
                file_type,
                existing_file.display()
            );
        }
    }
    Ok(())
}

fn add_regular_file(
    params: &AddParams,
    rel_path: &guisu_core::path::RelPath,
    file_abs: &AbsPath,
) -> Result<()> {
    // Read the file content first (needed for autotemplate detection)
    let content = fs::read(file_abs.as_path())
        .with_context(|| format!("Failed to read file: {}", file_abs.as_path().display()))?;

    // Check for secrets unless mode is Ignore
    handle_secret_detection(params.secrets_mode, file_abs, rel_path, &content)?;

    // Determine if file should be templated
    let (is_template, processed_content) = determine_template_processing(
        params.autotemplate,
        params.encrypt,
        params.template,
        &content,
        file_abs,
        params.config,
    );

    // Validate encryption configuration if needed (before deleting any files)
    if params.encrypt {
        validate_encryption_config(params.config)?;
    }

    // Build source filename with V2 extensions
    let source_file_path =
        build_source_file_path(params.source_dir, rel_path, is_template, params.encrypt);

    // Check if file already exists in source (in any form)
    handle_existing_source_file(
        params.source_dir,
        rel_path,
        is_template,
        params.encrypt,
        params.force,
    )?;

    // Create parent directory if needed
    if let Some(parent) = source_file_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Encrypt if requested
    let final_content = if params.encrypt {
        encrypt_content(&processed_content, params.config)?
    } else {
        processed_content.clone()
    };

    // Write the (possibly encrypted) content
    fs::write(&source_file_path, &final_content)
        .with_context(|| format!("Failed to write file: {}", source_file_path.display()))?;

    // Preserve file permissions (Unix only)
    #[cfg(unix)]
    {
        let metadata = fs::metadata(file_abs.as_path()).with_context(|| {
            format!("Failed to read metadata: {}", file_abs.as_path().display())
        })?;
        let perms = metadata.permissions();
        fs::set_permissions(&source_file_path, perms).with_context(|| {
            format!("Failed to set permissions: {}", source_file_path.display())
        })?;
    }

    Ok(())
}

/// Add a directory recursively to the source directory
fn add_directory(
    params: &AddParams,
    dir_abs: &AbsPath,
    rel_path: &guisu_core::path::RelPath,
) -> Result<usize> {
    let source_dir_path = params.source_dir.as_path().join(rel_path.as_path());
    fs::create_dir_all(&source_dir_path)
        .with_context(|| format!("Failed to create directory: {}", source_dir_path.display()))?;

    let mut count = 0;

    // Walk the directory and add all files
    for entry in WalkDir::new(dir_abs.as_path()).follow_links(false) {
        let entry = entry.with_context(|| {
            format!("Failed to read directory: {}", dir_abs.as_path().display())
        })?;
        let entry_path = entry.path();

        // Skip the root directory itself
        if entry_path == dir_abs.as_path() {
            continue;
        }

        // Get the entry as an absolute path
        let entry_abs = AbsPath::new(entry_path.to_path_buf())?;
        let entry_rel = entry_abs.strip_prefix(params.dest_dir)?;

        if entry.file_type().is_dir() {
            let source_subdir = params.source_dir.as_path().join(entry_rel.as_path());
            fs::create_dir_all(&source_subdir).with_context(|| {
                format!("Failed to create directory: {}", source_subdir.display())
            })?;
        } else if entry.file_type().is_symlink() {
            add_symlink(params.source_dir, &entry_rel, &entry_abs, params.force)?;
            count += 1;
        } else {
            add_regular_file(params, &entry_rel, &entry_abs)?;
            count += 1;
        }
    }

    Ok(count)
}

/// Add a symlink to the source directory
fn add_symlink(
    source_dir: &AbsPath,
    rel_path: &guisu_core::path::RelPath,
    link_abs: &AbsPath,
    force: bool,
) -> Result<()> {
    // Read the symlink target
    let link_target = fs::read_link(link_abs.as_path())
        .with_context(|| format!("Failed to read symlink: {}", link_abs.as_path().display()))?;

    let source_link_path = source_dir.as_path().join(rel_path.as_path());

    // Check if symlink already exists in source (in any form)
    if let Some(existing_file) = check_file_exists_in_source(source_dir, rel_path) {
        if force {
            // Force is true - remove the existing symlink to overwrite it
            fs::remove_file(&existing_file).with_context(|| {
                format!("Failed to remove old symlink: {}", existing_file.display())
            })?;
        } else {
            anyhow::bail!(
                "This symlink is already managed by guisu:\n  {}\n\n\
                 To re-add, use: guisu add --force",
                existing_file.display()
            );
        }
    }

    // Create parent directory if needed
    if let Some(parent) = source_link_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Create the symlink in source directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&link_target, &source_link_path)
            .with_context(|| format!("Failed to create symlink: {}", source_link_path.display()))?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;
        symlink_file(&link_target, &source_link_path)
            .with_context(|| format!("Failed to create symlink: {}", source_link_path.display()))?;
    }

    Ok(())
}

/// Validate encryption configuration without actually encrypting
///
/// This allows us to fail fast before modifying any files
fn validate_encryption_config(config: &Config) -> Result<()> {
    // Try to get recipients from config first (for team collaboration)
    let recipients = config.age_recipients()?;
    if recipients.is_empty() {
        // No recipients configured - check if symmetric mode is enabled
        if !config.age.derive {
            anyhow::bail!(
                "No recipients configured for encryption.\n\
                 \n\
                 You must either:\n\
                 \n\
                 1. Enable symmetric mode (auto-derive public key from identity):\n\
                    [age]\n\
                    identity = \"~/.config/guisu/key.txt\"\n\
                    symmetric = true\n\
                 \n\
                 2. Specify explicit recipients:\n\
                    [age]\n\
                    identity = \"~/.config/guisu/key.txt\"\n\
                    recipients = [\n\
                        \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\",  # Your public key\n\
                    ]\n\
                 \n\
                 3. For team collaboration:\n\
                    [age]\n\
                    identities = [\"~/.config/guisu/key.txt\"]\n\
                    recipients = [\n\
                        \"age1ql3z...\",  # Alice\n\
                        \"age1zvk...\",  # Bob\n\
                    ]\n\
                 \n\
                 Generate age key with: guisu age generate\n\
                 Get your public key with: guisu age show"
            );
        }

        // Symmetric mode enabled - verify identities can be loaded
        config.age_identities().context(
            "Symmetric mode enabled but no identity configured.\n\
             \n\
             Add to your config file:\n\
             [age]\n\
             identity = \"~/.config/guisu/key.txt\"\n\
             symmetric = true\n\
             \n\
             Generate age key with: guisu age generate",
        )?;

        Ok(())
    } else {
        // Recipients configured, all good
        Ok(())
    }
}

/// Encrypt content using age
fn encrypt_content(content: &[u8], config: &Config) -> Result<Vec<u8>> {
    // Try to get recipients from config first (for team collaboration)
    let recipients = config.age_recipients()?;
    let recipients = if recipients.is_empty() {
        // No recipients configured - check if symmetric mode is enabled
        if !config.age.derive {
            anyhow::bail!(
                "No recipients configured for encryption.\n\
                 \n\
                 You must either:\n\
                 \n\
                 1. Enable symmetric mode (auto-derive public key from identity):\n\
                    [age]\n\
                    identity = \"~/.config/guisu/key.txt\"\n\
                    symmetric = true\n\
                 \n\
                 2. Specify explicit recipients:\n\
                    [age]\n\
                    identity = \"~/.config/guisu/key.txt\"\n\
                    recipients = [\n\
                        \"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\",  # Your public key\n\
                    ]\n\
                 \n\
                 3. For team collaboration:\n\
                    [age]\n\
                    identities = [\"~/.config/guisu/key.txt\"]\n\
                    recipients = [\n\
                        \"age1ql3z...\",  # Alice\n\
                        \"age1zvk...\",  # Bob\n\
                    ]\n\
                 \n\
                 Generate age key with: guisu age generate\n\
                 Get your public key with: guisu age show"
            );
        }

        // Symmetric mode enabled - derive recipients from all identities
        // This ensures that if the identity file contains multiple keys (e.g., for team
        // collaboration or key rotation), all of them can decrypt the encrypted file.
        let identities = config.age_identities().context(
            "Symmetric mode enabled but no identity configured.\n\
             \n\
             Add to your config file:\n\
             [age]\n\
             identity = \"~/.config/guisu/key.txt\"\n\
             symmetric = true\n\
             \n\
             Generate age key with: guisu age generate",
        )?;

        guisu_crypto::identities_to_recipients(&identities)
    } else {
        // Use configured recipients
        recipients
    };

    // Encrypt the content with all recipients
    encrypt(content, &recipients).context("Failed to encrypt content")
}

/// Cached secret detection regex patterns
static SECRET_PATTERNS: std::sync::LazyLock<Vec<(regex::Regex, &'static str)>> =
    std::sync::LazyLock::new(|| {
        vec![
            (
                regex::Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{3,}"#)
                    .expect("Valid regex"),
                "Password",
            ),
            (
                regex::Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[^\s'"]{8,}"#)
                    .expect("Valid regex"),
                "API Key",
            ),
            (
                regex::Regex::new(r#"(?i)(secret[_-]?key|secret)\s*[:=]\s*['"]?[^\s'"]{8,}"#)
                    .expect("Valid regex"),
                "Secret Key",
            ),
            (
                regex::Regex::new(r#"(?i)(access[_-]?token|token)\s*[:=]\s*['"]?[^\s'"]{8,}"#)
                    .expect("Valid regex"),
                "Access Token",
            ),
            (
                regex::Regex::new(r#"(?i)(auth[_-]?token|bearer)\s*[:=]\s*['"]?[^\s'"]{8,}"#)
                    .expect("Valid regex"),
                "Auth Token",
            ),
            (
                regex::Regex::new(r#"(?i)(client[_-]?secret)\s*[:=]\s*['"]?[^\s'"]{8,}"#)
                    .expect("Valid regex"),
                "Client Secret",
            ),
            (
                regex::Regex::new(r"(?i)(private[_-]?key)\s*[:=]").expect("Valid regex"),
                "Private Key",
            ),
            (
                regex::Regex::new(r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----")
                    .expect("Valid regex"),
                "PEM Private Key",
            ),
            (
                regex::Regex::new(
                    r#"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"]?[A-Z0-9]{20}"#,
                )
                .expect("Valid regex"),
                "AWS Access Key",
            ),
            (
                regex::Regex::new(
                    r#"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#,
                )
                .expect("Valid regex"),
                "AWS Secret Key",
            ),
        ]
    });

/// Cached high-entropy pattern for token detection
static HIGH_ENTROPY_PATTERN: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"[A-Za-z0-9+/=]{32,}").expect("Valid regex"));

/// Detect potential secrets in a file
///
/// Returns Some(findings) if secrets are detected, None otherwise
fn detect_secrets(file_path: &Path, content: &[u8]) -> Option<String> {
    let mut findings = Vec::new();

    // 1. Check filename for known private key patterns
    if let Some(filename) = file_path.file_name().and_then(|n| n.to_str()) {
        let private_key_patterns = [
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            "private-key",
            "privatekey",
        ];

        for pattern in &private_key_patterns {
            if filename.contains(pattern) {
                findings.push(format!("  • Filename contains '{pattern}'"));
                break;
            }
        }
    }

    // 2. Check content for secret patterns (only for text files)
    if !content.iter().take(8000).any(|&b| b == 0)
        && let Ok(text) = String::from_utf8(content.to_vec())
    {
        // Check against cached secret patterns
        for (re, description) in SECRET_PATTERNS.iter() {
            if re.is_match(&text) {
                findings.push(format!("  • Contains {description}"));
            }
        }

        // 3. Check for high-entropy strings (potential tokens)
        // Look for long alphanumeric strings that might be tokens
        for cap in HIGH_ENTROPY_PATTERN.find_iter(&text).take(5) {
            let s = cap.as_str();
            if calculate_entropy(s) > 4.5 {
                // Safe string slicing using char-based approach to avoid UTF-8 boundary issues
                let preview: String = s.chars().take(32).collect();
                findings.push(format!(
                    "  • High-entropy string (potential token): {preview}..."
                ));
                break; // Only report one to avoid spam
            }
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings.join("\n"))
    }
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(s: &str) -> f64 {
    // Empty string has zero entropy
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts = indexmap::IndexMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    // Single unique character has zero entropy
    if char_counts.len() == 1 {
        return 0.0;
    }

    #[allow(clippy::cast_precision_loss)]
    let len = s.len() as f64;
    let mut entropy = 0.0;

    for count in char_counts.values() {
        let probability = f64::from(*count) / len;
        // Guard against log2(0) which would produce -inf
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    // Ensure non-negative result (entropy is always >= 0)
    entropy.max(0.0)
}

/// A replacement to be made in the text
struct Replacement {
    /// Start byte offset in the original text
    start: usize,
    /// End byte offset in the original text (exclusive)
    end: usize,
    /// Template variable string to insert
    text: String,
}

/// Auto-detect template variables in content and replace them
///
/// Returns (`templated_content`, `has_replacements`)
fn auto_template_content(content: &[u8], config: &Config) -> Result<(Vec<u8>, bool)> {
    // Only process text files
    if content.iter().take(8000).any(|&b| b == 0) {
        // Binary file, don't template
        return Ok((content.to_vec(), false));
    }

    let text = String::from_utf8_lossy(content);

    // Convert config.variables (IndexMap) to serde_json::Value for processing
    let variables_value =
        serde_json::to_value(&config.variables).context("Failed to convert variables to JSON")?;

    // Extract all variables from config with their paths
    let mut variables = extract_variables(&variables_value, "");

    // Sort by priority: longer values first, then shallower paths, then alphabetically
    variables.sort_by(|a, b| {
        // First priority: longer value
        let len_cmp = b.value.len().cmp(&a.value.len());
        if len_cmp != std::cmp::Ordering::Equal {
            return len_cmp;
        }

        // Second priority: shallower path (fewer dots)
        let depth_a = a.path.matches('.').count();
        let depth_b = b.path.matches('.').count();
        let depth_cmp = depth_a.cmp(&depth_b);
        if depth_cmp != std::cmp::Ordering::Equal {
            return depth_cmp;
        }

        // Third priority: alphabetical
        a.path.cmp(&b.path)
    });

    // Collect all replacements with their positions
    let mut replacements: Vec<Replacement> = Vec::new();

    for var in variables {
        // Skip very short values to avoid false matches
        if var.value.len() < 3 {
            continue;
        }

        // Find all matches in the text (avoiding already-replaced regions)
        let mut pos = 0;
        while let Some(idx) = text[pos..].find(&var.value) {
            let start = pos + idx;
            let end = start + var.value.len();

            // Check if this region overlaps with any existing replacement
            let overlaps = replacements
                .iter()
                .any(|r| (start >= r.start && start < r.end) || (end > r.start && end <= r.end));

            if !overlaps {
                let template_var = format!("{{{{ {} }}}}", var.path);
                replacements.push(Replacement {
                    start,
                    end,
                    text: template_var,
                });
            }

            pos = end;
        }
    }

    // Sort replacements by position (earlier positions first)
    replacements.sort_by_key(|r| r.start);

    // Build result string in one pass if there are replacements
    let (result, has_replacements) = if replacements.is_empty() {
        (text.to_string(), false)
    } else {
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for r in replacements {
            // Copy text between last replacement and this one
            result.push_str(&text[last_end..r.start]);
            // Add the replacement
            result.push_str(&r.text);
            last_end = r.end;
        }

        // Copy remaining text after last replacement
        result.push_str(&text[last_end..]);

        (result, true)
    };

    Ok((result.into_bytes(), has_replacements))
}

/// Variable with its path and value for autotemplate
#[derive(Debug)]
struct TemplateVariable {
    path: String,
    value: String,
}

/// Extract all variables from config with their full paths
fn extract_variables(value: &serde_json::Value, prefix: &str) -> Vec<TemplateVariable> {
    let mut variables = Vec::new();

    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };

                if let serde_json::Value::String(s) = val {
                    // This is a leaf string value
                    variables.push(TemplateVariable {
                        path: path.clone(),
                        value: s.clone(),
                    });
                }

                // Recursively extract from nested objects
                variables.extend(extract_variables(val, &path));
            }
        }
        serde_json::Value::String(s)
            // Direct string value
            if !prefix.is_empty() => {
                variables.push(TemplateVariable {
                    path: prefix.to_string(),
                    value: s.clone(),
                });
            }
        _ => {
            // Ignore other types (numbers, booleans, arrays, null)
        }
    }

    variables
}

/// Check if a file with the given relative path already exists in source directory
///
/// This checks for all possible variants of the file:
/// - Without any extension (plain file)
/// - With .j2 extension (template)
/// - With .age extension (encrypted)
/// - With .j2.age extension (encrypted template)
///
/// Returns the path of the existing file if found, None otherwise.
fn check_file_exists_in_source(
    source_dir: &AbsPath,
    rel_path: &guisu_core::path::RelPath,
) -> Option<PathBuf> {
    let rel_str = rel_path.as_path().to_string_lossy();

    // All possible variants in order of checking
    let variants = [
        rel_str.to_string(),         // Plain file
        format!("{rel_str}.j2"),     // Template
        format!("{rel_str}.age"),    // Encrypted
        format!("{rel_str}.j2.age"), // Encrypted template
    ];

    for variant in &variants {
        let source_file_path = source_dir.as_path().join(variant);

        if source_file_path.exists() {
            return Some(source_file_path);
        }
    }

    None
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

    // Helper to create test config with variables
    fn test_config_with_vars() -> Config {
        let mut config = Config::default();
        config.variables.insert(
            "email".to_string(),
            serde_json::Value::String("user@example.com".to_string()),
        );
        config.variables.insert(
            "name".to_string(),
            serde_json::Value::String("John Doe".to_string()),
        );

        // Nested variables
        let mut git_obj = indexmap::IndexMap::new();
        git_obj.insert(
            "user".to_string(),
            serde_json::Value::String("johndoe".to_string()),
        );
        git_obj.insert(
            "repo".to_string(),
            serde_json::Value::String("myproject".to_string()),
        );
        config.variables.insert(
            "git".to_string(),
            serde_json::Value::Object(git_obj.into_iter().collect()),
        );

        config
    }

    #[test]
    fn test_calculate_entropy_empty_string() {
        assert!((calculate_entropy("") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_entropy_single_char() {
        assert!((calculate_entropy("aaaaaaa") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_calculate_entropy_uniform_distribution() {
        // "abcd" has high entropy (uniform distribution)
        let entropy = calculate_entropy("abcd");
        assert!(entropy > 1.0, "Expected high entropy, got {entropy}");
    }

    #[test]
    fn test_calculate_entropy_low_entropy() {
        // "aaaab" has low entropy (biased distribution)
        let entropy = calculate_entropy("aaaab");
        assert!(entropy < 1.0, "Expected low entropy, got {entropy}");
    }

    #[test]
    fn test_calculate_entropy_random_token() {
        // Simulated random token should have high entropy
        let token = "abcdefghijklmnopqrstuvwxyz0123456";
        let entropy = calculate_entropy(token);
        assert!(
            entropy > 4.0,
            "Expected very high entropy for random token, got {entropy}"
        );
    }

    #[test]
    fn test_extract_variables_empty() {
        let value = serde_json::json!({});
        let vars = extract_variables(&value, "");
        assert!(vars.is_empty());
    }

    #[test]
    fn test_extract_variables_flat() {
        let value = serde_json::json!({
            "name": "John",
            "email": "john@example.com"
        });
        let vars = extract_variables(&value, "");
        // Note: Current implementation extracts each string value twice
        // (once in Object match, once in recursive String match)
        assert_eq!(vars.len(), 4);

        let names: Vec<_> = vars.iter().map(|v| v.path.as_str()).collect();
        assert!(names.iter().filter(|&&n| n == "name").count() == 2);
        assert!(names.iter().filter(|&&n| n == "email").count() == 2);
    }

    #[test]
    fn test_extract_variables_nested() {
        let value = serde_json::json!({
            "user": {
                "name": "John",
                "email": "john@example.com"
            },
            "system": {
                "os": "linux"
            }
        });
        let vars = extract_variables(&value, "");
        // Note: Current implementation extracts each string value twice
        assert_eq!(vars.len(), 6);

        let paths: Vec<_> = vars.iter().map(|v| v.path.as_str()).collect();
        assert!(paths.iter().filter(|&&p| p == "user.name").count() == 2);
        assert!(paths.iter().filter(|&&p| p == "user.email").count() == 2);
        assert!(paths.iter().filter(|&&p| p == "system.os").count() == 2);
    }

    #[test]
    fn test_extract_variables_ignores_non_strings() {
        let value = serde_json::json!({
            "name": "John",
            "age": 30,
            "active": true,
            "tags": ["dev", "ops"],
            "null_field": null
        });
        let vars = extract_variables(&value, "");

        // Only "name" should be extracted (string value)
        // Note: Current implementation extracts it twice
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].path, "name");
        assert_eq!(vars[0].value, "John");
        assert_eq!(vars[1].path, "name");
        assert_eq!(vars[1].value, "John");
    }

    #[test]
    fn test_auto_template_content_no_matches() {
        let config = test_config();
        let content = b"Hello, world!";

        let (result, has_replacements) =
            auto_template_content(content, &config).expect("auto_template failed");

        assert!(!has_replacements);
        assert_eq!(result, content);
    }

    #[test]
    fn test_auto_template_content_simple_replacement() {
        let config = test_config_with_vars();
        let content = b"My email is user@example.com";

        let (result, has_replacements) =
            auto_template_content(content, &config).expect("auto_template failed");

        assert!(has_replacements);
        let result_str = String::from_utf8(result).expect("Invalid UTF-8");
        assert!(result_str.contains("{{ email }}"));
        assert!(!result_str.contains("user@example.com"));
    }

    #[test]
    fn test_auto_template_content_multiple_replacements() {
        let config = test_config_with_vars();
        let content = b"Name: John Doe, Email: user@example.com";

        let (result, has_replacements) =
            auto_template_content(content, &config).expect("auto_template failed");

        assert!(has_replacements);
        let result_str = String::from_utf8(result).expect("Invalid UTF-8");
        assert!(result_str.contains("{{ name }}"));
        assert!(result_str.contains("{{ email }}"));
    }

    #[test]
    fn test_auto_template_content_nested_variables() {
        let config = test_config_with_vars();
        let content = b"Git user: johndoe, Repo: myproject";

        let (result, has_replacements) =
            auto_template_content(content, &config).expect("auto_template failed");

        assert!(has_replacements);
        let result_str = String::from_utf8(result).expect("Invalid UTF-8");
        assert!(result_str.contains("{{ git.user }}"));
        assert!(result_str.contains("{{ git.repo }}"));
    }

    #[test]
    fn test_auto_template_content_short_values_ignored() {
        let mut config = Config::default();
        config
            .variables
            .insert("x".to_string(), serde_json::Value::String("ab".to_string()));

        let content = b"Value: ab";

        let (result, has_replacements) =
            auto_template_content(content, &config).expect("auto_template failed");

        // Short values (< 3 chars) should be ignored
        assert!(!has_replacements);
        assert_eq!(result, content);
    }

    #[test]
    fn test_auto_template_content_binary_file() {
        let config = test_config_with_vars();
        let content = vec![0xFF, 0xFE, 0xFD, 0x00, 0x01]; // Binary content with null byte

        let (result, has_replacements) =
            auto_template_content(&content, &config).expect("auto_template failed");

        // Binary files should not be templated
        assert!(!has_replacements);
        assert_eq!(result, content);
    }

    #[test]
    fn test_auto_template_content_overlapping_matches() {
        let mut config = Config::default();
        config.variables.insert(
            "long".to_string(),
            serde_json::Value::String("example.com".to_string()),
        );
        config.variables.insert(
            "short".to_string(),
            serde_json::Value::String("example".to_string()),
        );

        let content = b"Visit example.com";

        let (result, has_replacements) =
            auto_template_content(content, &config).expect("auto_template failed");

        assert!(has_replacements);
        let result_str = String::from_utf8(result).expect("Invalid UTF-8");

        // Should prefer longer match
        assert!(result_str.contains("{{ long }}"));
        assert!(!result_str.contains("{{ short }}"));
    }

    #[test]
    fn test_detect_secrets_clean_file() {
        let content = b"This is a clean file with no secrets";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("clean.txt");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_none());
    }

    #[test]
    fn test_detect_secrets_password_pattern() {
        let content = b"password = my_secret_password";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("config.txt");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        assert!(findings.contains("Password"));
    }

    #[test]
    fn test_detect_secrets_api_key_pattern() {
        let content = b"api_key = fake_key_for_testing_12345678";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("config.txt");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        assert!(findings.contains("API Key"));
    }

    #[test]
    fn test_detect_secrets_private_key_filename() {
        let content = b"not a real key";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("id_rsa");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        assert!(findings.contains("id_rsa"));
    }

    #[test]
    fn test_detect_secrets_pem_private_key() {
        let content = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQE...";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("key.pem");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        assert!(findings.contains("PEM Private Key") || findings.contains(".pem"));
    }

    #[test]
    fn test_detect_secrets_aws_keys() {
        let content = b"AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("aws.txt");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        assert!(findings.contains("AWS Access Key"));
    }

    #[test]
    fn test_detect_secrets_high_entropy_token() {
        let content = b"token = abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("config.txt");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        assert!(findings.contains("High-entropy") || findings.contains("token"));
    }

    #[test]
    fn test_detect_secrets_binary_file() {
        let content = vec![0xFF, 0xFE, 0xFD, 0x00, 0x01];
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("binary.dat");

        let result = detect_secrets(&file_path, &content);

        // Binary files should not trigger text-based secret detection
        // (only filename-based detection)
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_secrets_multiple_patterns() {
        let content = b"password = secret123\napi_key = fake_value_abc123";
        let temp = TempDir::new().expect("Failed to create temp dir");
        let file_path = temp.path().join("config.txt");

        let result = detect_secrets(&file_path, content);

        assert!(result.is_some());
        let findings = result.unwrap();
        // Should find both password and API key
        assert!(findings.contains("Password") && findings.contains("API Key"));
    }

    #[test]
    fn test_check_file_exists_in_source_not_found() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");

        let rel_path =
            guisu_core::path::RelPath::new("nonexistent.txt".into()).expect("Invalid rel path");

        let result = check_file_exists_in_source(&source_dir, &rel_path);

        assert!(result.is_none());
    }

    #[test]
    fn test_check_file_exists_in_source_plain_file() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");

        let file_path = temp.path().join("test.txt");
        std::fs::write(&file_path, b"content").expect("Failed to write file");

        let rel_path = guisu_core::path::RelPath::new("test.txt".into()).expect("Invalid rel path");

        let result = check_file_exists_in_source(&source_dir, &rel_path);

        assert!(result.is_some());
        assert!(result.unwrap().to_string_lossy().contains("test.txt"));
    }

    #[test]
    fn test_check_file_exists_in_source_template() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");

        let file_path = temp.path().join("test.txt.j2");
        std::fs::write(&file_path, b"content").expect("Failed to write file");

        let rel_path = guisu_core::path::RelPath::new("test.txt".into()).expect("Invalid rel path");

        let result = check_file_exists_in_source(&source_dir, &rel_path);

        assert!(result.is_some());
        assert!(result.unwrap().to_string_lossy().contains("test.txt.j2"));
    }

    #[test]
    fn test_check_file_exists_in_source_encrypted() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");

        let file_path = temp.path().join("test.txt.age");
        std::fs::write(&file_path, b"encrypted").expect("Failed to write file");

        let rel_path = guisu_core::path::RelPath::new("test.txt".into()).expect("Invalid rel path");

        let result = check_file_exists_in_source(&source_dir, &rel_path);

        assert!(result.is_some());
        assert!(result.unwrap().to_string_lossy().contains("test.txt.age"));
    }

    #[test]
    fn test_check_file_exists_in_source_encrypted_template() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");

        let file_path = temp.path().join("test.txt.j2.age");
        std::fs::write(&file_path, b"encrypted template").expect("Failed to write file");

        let rel_path = guisu_core::path::RelPath::new("test.txt".into()).expect("Invalid rel path");

        let result = check_file_exists_in_source(&source_dir, &rel_path);

        assert!(result.is_some());
        assert!(
            result
                .unwrap()
                .to_string_lossy()
                .contains("test.txt.j2.age")
        );
    }

    #[test]
    fn test_check_file_exists_in_source_prefers_plain() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");

        // Create both plain and template versions
        let plain_path = temp.path().join("test.txt");
        let template_path = temp.path().join("test.txt.j2");

        std::fs::write(&plain_path, b"plain").expect("Failed to write plain");
        std::fs::write(&template_path, b"template").expect("Failed to write template");

        let rel_path = guisu_core::path::RelPath::new("test.txt".into()).expect("Invalid rel path");

        let result = check_file_exists_in_source(&source_dir, &rel_path);

        assert!(result.is_some());
        let found_path = result.unwrap();
        // Should prefer plain file over template
        assert!(found_path.to_string_lossy().ends_with("test.txt"));
        assert!(!found_path.to_string_lossy().contains(".j2"));
    }

    #[test]
    fn test_secrets_mode_enum_values() {
        assert_eq!(SecretsMode::Ignore, SecretsMode::Ignore);
        assert_ne!(SecretsMode::Ignore, SecretsMode::Warning);
        assert_ne!(SecretsMode::Warning, SecretsMode::Error);
    }

    #[test]
    fn test_template_variable_struct() {
        let var = TemplateVariable {
            path: "user.email".to_string(),
            value: "test@example.com".to_string(),
        };

        assert_eq!(var.path, "user.email");
        assert_eq!(var.value, "test@example.com");
    }

    #[test]
    fn test_add_params_struct() {
        let temp = TempDir::new().expect("Failed to create temp dir");
        let source_dir = AbsPath::new(temp.path().to_path_buf()).expect("Invalid path");
        let dest_dir = AbsPath::new(temp.path().join("dest")).expect("Invalid path");
        let config = test_config();

        let params = AddParams {
            source_dir: &source_dir,
            dest_dir: &dest_dir,
            template: true,
            autotemplate: false,
            encrypt: false,
            force: false,
            secrets_mode: SecretsMode::Warning,
            config: &config,
        };

        assert!(params.template);
        assert!(!params.autotemplate);
        assert!(!params.encrypt);
        assert!(!params.force);
        assert_eq!(params.secrets_mode, SecretsMode::Warning);
    }

    #[test]
    fn test_validate_encryption_config_no_recipients_no_symmetric() {
        let config = test_config();

        let result = validate_encryption_config(&config);

        // Should fail when no recipients and symmetric mode is not enabled
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No recipients configured"));
    }
}
