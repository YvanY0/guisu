//! Configuration management
//!
//! This module handles loading and saving guisu configuration.

use crate::Result;
use crate::variables::load_variables;
use guisu_core::platform::CURRENT_PLATFORM;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Auto boolean type supporting "auto", true, or false
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AutoBool {
    /// Automatically determine the appropriate value
    #[default]
    Auto,
    /// Explicitly enable
    #[serde(rename = "true")]
    True,
    /// Explicitly disable
    #[serde(rename = "false")]
    False,
}

/// Icon display mode (similar to eza's --icons option)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IconMode {
    /// Automatically show icons when output is a terminal
    #[default]
    #[serde(alias = "automatic")]
    Auto,
    /// Always show icons
    Always,
    /// Never show icons
    Never,
}

impl IconMode {
    /// Determine if icons should be shown based on mode and terminal detection
    #[must_use]
    pub fn should_show_icons(&self, is_tty: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => is_tty,
        }
    }
}

/// General configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Source directory path (simplified name)
    #[serde(default, rename = "srcDir")]
    pub src_dir: Option<PathBuf>,

    /// Destination directory path (simplified name)
    #[serde(default, rename = "dstDir")]
    pub dst_dir: Option<PathBuf>,

    /// Subdirectory within source directory where dotfiles are stored
    /// Defaults to "home" to separate dotfiles from repository metadata (.git, .guisu)
    #[serde(default = "default_root_entry", rename = "rootEntry")]
    pub root_entry: PathBuf,

    /// Enable colored output
    #[serde(default = "default_color")]
    pub color: bool,

    /// Show progress bars
    #[serde(default = "default_progress")]
    pub progress: bool,

    /// Use builtin age encryption (auto, true, or false)
    #[serde(default, rename = "useBuiltinAge")]
    pub use_builtin_age: AutoBool,

    /// Use builtin git (auto, true, or false)
    #[serde(default, rename = "useBuiltinGit")]
    pub use_builtin_git: AutoBool,

    /// Custom editor command
    #[serde(default)]
    pub editor: Option<String>,

    /// Arguments to pass to the editor
    #[serde(default, rename = "editorArgs")]
    pub editor_args: Vec<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            src_dir: None,
            dst_dir: None,
            root_entry: default_root_entry(),
            color: default_color(),
            progress: default_progress(),
            use_builtin_age: AutoBool::Auto,
            use_builtin_git: AutoBool::Auto,
            editor: None,
            editor_args: Vec::new(),
        }
    }
}

/// Ignore configuration section
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IgnoreConfig {
    /// Global ignore patterns for all platforms
    #[serde(default)]
    pub global: Vec<String>,

    /// Darwin (macOS) specific ignore patterns
    #[serde(default)]
    pub darwin: Vec<String>,

    /// Linux specific ignore patterns
    #[serde(default)]
    pub linux: Vec<String>,

    /// Windows specific ignore patterns
    #[serde(default)]
    pub windows: Vec<String>,
}

/// Bitwarden configuration
///
/// Configure which Bitwarden CLI to use: bw (official Node.js CLI) or rbw (Rust CLI)
///
/// ```toml
/// [bitwarden]
/// provider = "rbw"  # or "bw" (default)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfig {
    /// Which Bitwarden CLI to use: "bw" or "rbw"
    /// - "bw": Official Bitwarden CLI (Node.js based)
    /// - "rbw": Rust Bitwarden CLI (faster, daemon-based)
    #[serde(default = "default_bitwarden_provider")]
    pub provider: String,
}

fn default_bitwarden_provider() -> String {
    "bw".to_string()
}

impl Default for BitwardenConfig {
    fn default() -> Self {
        Self {
            provider: default_bitwarden_provider(),
        }
    }
}

/// UI configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Icon display mode: "auto", "always", or "never"
    /// - auto: Show icons when output is a terminal (default)
    /// - always: Always show icons
    /// - never: Never show icons
    #[serde(default)]
    pub icons: IconMode,

    /// Diff format: "unified", "split", "inline"
    #[serde(default = "default_diff_format", rename = "diffFormat")]
    pub diff_format: String,

    /// Number of context lines for diffs
    #[serde(default = "default_context_lines", rename = "contextLines")]
    pub context_lines: usize,

    /// Number of lines to show in preview
    #[serde(default = "default_preview_lines", rename = "previewLines")]
    pub preview_lines: usize,
}

fn default_diff_format() -> String {
    "unified".to_string()
}

fn default_context_lines() -> usize {
    3
}

fn default_preview_lines() -> usize {
    10
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            icons: IconMode::default(),
            diff_format: default_diff_format(),
            context_lines: default_context_lines(),
            preview_lines: default_preview_lines(),
        }
    }
}

/// Age encryption configuration
///
/// Supports both chezmoi-compatible and simplified configurations:
///
/// ```toml
/// # Single identity and recipient
/// [age]
/// identity = "~/.config/guisu/key.txt"
/// recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
///
/// # Multiple identities and recipients
/// [age]
/// identities = ["~/.config/guisu/key1.txt", "~/.config/guisu/key2.txt"]
/// recipients = ["age1...", "age2..."]
///
/// # Symmetric encryption (same key for encryption and decryption)
/// [age]
/// identity = "~/.config/guisu/key.txt"
/// symmetric = true
///
/// # SSH key support
/// [age]
/// identity = "~/.ssh/id_ed25519"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgeConfig {
    /// Single identity file path (age or SSH key)
    /// Can use ~ for home directory
    /// Mutually exclusive with `identities`
    pub identity: Option<PathBuf>,

    /// Multiple identity file paths
    /// Mutually exclusive with `identity`
    pub identities: Option<Vec<PathBuf>>,

    /// Single recipient public key
    /// Mutually exclusive with `recipients`
    pub recipient: Option<String>,

    /// Multiple recipient public keys
    #[serde(default)]
    pub recipients: Vec<String>,

    /// Derive recipient from identity
    ///
    /// When true, automatically derives the public key from `identity` for encryption.
    /// This is required when no `recipient/recipients` are specified.
    ///
    /// Note: This still uses asymmetric age encryption - the identity's public key
    /// is derived and used as the recipient. The name `derive` accurately reflects
    /// this behavior (vs the misleading `symmetric` used by chezmoi).
    ///
    /// Configuration accepts both `derive` (recommended) and `symmetric` (legacy):
    /// ```toml
    /// [age]
    /// identity = "~/.config/guisu/key.txt"
    /// derive = true      # Recommended: derive recipient from identity
    /// # symmetric = true # Legacy name (still supported for backward compatibility)
    /// ```
    #[serde(default, alias = "symmetric")]
    pub derive: bool,

    /// Fail on decryption errors
    ///
    /// When true (default), decryption failures will cause the apply command to fail.
    /// When false, decryption failures will log a warning and continue with encrypted content.
    ///
    /// Default: true (matches chezmoi behavior - fail loudly for security)
    ///
    /// ```toml
    /// [age]
    /// identity = "~/.config/guisu/key.txt"
    /// fail_on_decrypt_error = true   # Default: fail on decrypt errors
    /// # fail_on_decrypt_error = false # Warn and continue (insecure)
    /// ```
    #[serde(
        default = "default_fail_on_decrypt_error",
        rename = "failOnDecryptError"
    )]
    pub fail_on_decrypt_error: bool,
}

/// Edit command configuration
///
/// Configure default behavior for the edit command.
///
/// ```toml
/// [edit]
/// apply = true  # Automatically apply changes after editing (default: false)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EditConfig {
    /// Apply changes immediately after editing
    ///
    /// When true, automatically runs `apply` after editing files.
    /// This is equivalent to always passing `--apply` to `guisu edit`.
    ///
    /// Default: false (matches chezmoi's default behavior)
    ///
    /// ```toml
    /// [edit]
    /// apply = true  # Auto-apply after editing
    /// ```
    #[serde(default)]
    pub apply: bool,
}

/// Guisu configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// General configuration section
    #[serde(default)]
    pub general: GeneralConfig,

    /// Age encryption configuration
    #[serde(default)]
    pub age: AgeConfig,

    /// Edit command configuration
    #[serde(default)]
    pub edit: EditConfig,

    /// Bitwarden configuration
    #[serde(default)]
    pub bitwarden: BitwardenConfig,

    /// UI configuration
    #[serde(default)]
    pub ui: UiConfig,

    /// Ignore patterns configuration
    #[serde(default)]
    pub ignore: IgnoreConfig,

    /// Template variables
    #[serde(default)]
    pub variables: IndexMap<String, serde_json::Value>,

    /// Base directory for resolving relative paths (not serialized)
    /// This is set internally when loading config from source directory
    #[serde(skip)]
    base_dir: Option<PathBuf>,
}

fn default_color() -> bool {
    true
}

fn default_progress() -> bool {
    true
}

fn default_root_entry() -> PathBuf {
    PathBuf::from("home")
}

fn default_fail_on_decrypt_error() -> bool {
    true // Default to failing loudly for security (matches chezmoi)
}

impl Config {
    /// Load configuration from a file
    ///
    /// This is primarily used for testing. In production, use `load_from_source()` instead.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or TOML parsing fails
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| {
            guisu_core::Error::Message(format!(
                "Failed to read config file {}: {e}",
                path.as_ref().display()
            ))
        })?;

        let mut config: Self = toml::from_str(&content).map_err(|e| {
            guisu_core::Error::Message(format!(
                "Failed to parse config file {}: {e}",
                path.as_ref().display()
            ))
        })?;

        // Resolve relative paths using the config file's directory as base
        if let Some(parent) = path.as_ref().parent() {
            config.resolve_relative_paths(parent);
        }

        Ok(config)
    }

    /// Load configuration from TOML string
    ///
    /// This method parses configuration from a TOML string and resolves paths
    /// relative to the provided source directory.
    ///
    /// This is useful for loading configuration from rendered templates.
    ///
    /// # Errors
    ///
    /// Returns error if TOML parsing fails
    pub fn from_toml_str(toml_content: &str, source_dir: &Path) -> Result<Self> {
        let mut config: Self = toml::from_str(toml_content)
            .map_err(|e| guisu_core::Error::Message(format!("Failed to parse config TOML: {e}")))?;

        // Store the source directory for relative path resolution
        config.resolve_relative_paths(source_dir);

        Ok(config)
    }

    /// Load configuration from source directory (.guisu.toml)
    ///
    /// This method looks for .guisu.toml in the source directory and parses it directly.
    ///
    /// Note: For template support (.guisu.toml.j2), use the CLI wrapper which handles
    /// template rendering before calling this method.
    ///
    /// No syncing to ~/.config/guisu - config only exists in the repo.
    ///
    /// # Errors
    ///
    /// Returns error if config file is missing or cannot be read/parsed
    pub fn load_from_source(source_dir: &Path) -> Result<Self> {
        let config_path = source_dir.join(".guisu.toml");
        let template_path = source_dir.join(".guisu.toml.j2");

        // Check if .guisu.toml exists
        if !config_path.exists() {
            // If .guisu.toml.j2 exists, provide helpful error
            if template_path.exists() {
                return Err(guisu_core::Error::Message(
                    "Found .guisu.toml.j2 template but .guisu.toml is missing.\n\
                     \n\
                     Template rendering should be handled by CLI layer.\n\
                     This is likely a bug - please use Config::load_with_variables() instead."
                        .to_string(),
                ));
            }

            return Err(guisu_core::Error::Message(format!(
                "Configuration file not found in source directory.\n\
                 Expected: .guisu.toml in {}\n\
                 \n\
                 Create one with:\n\
                 cat > .guisu.toml << 'EOF'\n\
                 # Guisu configuration\n\
                 \n\
                 [age]\n\
                 identity = \"~/.config/guisu/key.txt\"\n\
                 # Or use a key in the repo:\n\
                 # identity = \"./key.txt\"\n\
                 EOF",
                source_dir.display()
            )));
        }

        // Read and parse TOML config
        let content = fs::read_to_string(&config_path).map_err(|e| {
            guisu_core::Error::Message(format!(
                "Failed to read config file {}: {e}",
                config_path.display()
            ))
        })?;

        Self::from_toml_str(&content, source_dir)
    }

    /// Resolve relative paths in configuration
    ///
    /// Converts relative paths (starting with `./ ` or `../`) to absolute paths
    /// based on the source directory. Also expands `~/` to home directory.
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.base_dir = Some(base_dir.to_path_buf());

        // Resolve general config paths
        if let Some(ref src_dir) = self.general.src_dir {
            self.general.src_dir = Some(Self::resolve_path(src_dir, base_dir));
        }
        if let Some(ref dst_dir) = self.general.dst_dir {
            self.general.dst_dir = Some(Self::resolve_path(dst_dir, base_dir));
        }
        // Note: root_entry should NOT be resolved - it's a relative subdirectory name
        // used with join() operations, not an absolute path

        // Resolve age identity paths
        if let Some(ref identity) = self.age.identity {
            self.age.identity = Some(Self::resolve_path(identity, base_dir));
        }
        if let Some(ref identities) = self.age.identities {
            self.age.identities = Some(
                identities
                    .iter()
                    .map(|p| Self::resolve_path(p, base_dir))
                    .collect(),
            );
        }
    }

    /// Resolve a single path: expand ~/ and resolve relative paths
    fn resolve_path(path: &PathBuf, base_dir: &Path) -> PathBuf {
        let path_str = path.to_string_lossy();

        // First expand ~/
        if let Some(stripped) = path_str.strip_prefix("~/") {
            if let Some(home) = ::dirs::home_dir() {
                return home.join(stripped);
            }
        } else if path_str == "~"
            && let Some(home) = ::dirs::home_dir()
        {
            return home;
        }

        // Then resolve relative paths (./ or ../)
        if path.is_relative() {
            base_dir.join(path)
        } else {
            path.clone()
        }
    }

    /// Load configuration with platform-aware variables
    ///
    /// This method extends the standard configuration loading with automatic
    /// variables loading from multiple sources. Variables are merged with
    /// section-based smart merge logic.
    ///
    /// # Variable Sources:
    ///
    /// 1. `.guisu.toml[variables]` - Global variables (no section)
    /// 2. `.guisu.toml[variables.section]` - Sectioned variables
    /// 3. `.guisu/{platform}/*.yaml` - Platform-specific YAML files
    /// 4. `.guisu/{platform}/*.toml` - Platform-specific TOML files
    ///
    /// # Smart Merge Behavior:
    ///
    /// Platform files override global config **within the same section only**.
    /// Different sections remain independent. This allows you to:
    /// - Define common variables in `.guisu.toml[variables]`
    /// - Organize variables by section (e.g., `[variables.visual]`)
    /// - Override specific sections per platform (e.g., `darwin/visual.yaml`)
    ///
    /// # Arguments
    ///
    /// * `config_path` - Optional path to config file (.guisu.toml)
    /// * `source_dir` - Path to source directory
    ///
    /// # Error Handling
    ///
    /// If loading platform variables fails (e.g., file not found, invalid TOML),
    /// the error is logged as debug and an empty variables map is used. This
    /// ensures that configuration loading never fails solely due to missing or
    /// invalid variables files.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_config::Config;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Load config with variables from default locations
    /// let config = Config::load_with_variables(
    ///     None,
    ///     Path::new("/home/user/dotfiles"),
    /// )?;
    ///
    /// // Access merged variables
    /// if let Some(email) = config.variables.get("email") {
    ///     println!("Email: {}", email);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Difference from `load()` and `load_from_source()`
    ///
    /// - `load()`: Loads only .guisu.toml, no variables merging
    /// - `load_from_source()`: Loads .guisu.toml from source directory, no variables merging
    /// - `load_with_variables()`: Loads config AND merges variables from all sources
    ///
    /// Use this method when you need full template variable support across
    /// multiple configuration sources.
    ///
    /// # Errors
    ///
    /// Returns error if config loading or variable merging fails
    pub fn load_with_variables(_config_path: Option<&Path>, source_dir: &Path) -> Result<Self> {
        // 1. Load config from source directory (.guisu.toml or .guisu.toml.j2)
        // This already includes [variables] from the config file
        let mut config = Self::load_from_source(source_dir)?;

        // 2. Load platform-specific variables from .guisu/variables/*.toml
        // These will be merged with the variables from the config file
        let platform = CURRENT_PLATFORM.os;

        // Load variables from .guisu/variables directory
        let guisu_dir = source_dir.join(".guisu");
        if guisu_dir.exists() {
            match load_variables(&guisu_dir, platform) {
                Ok(loaded_vars) => {
                    // Merge platform variables with config variables
                    // Platform files override config file within the same section
                    for (key, value) in loaded_vars {
                        config.variables.insert(key, value);
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to load platform variables: {}", e);
                }
            }

            // 3. Load ignore patterns from .guisu/ignores.toml
            match crate::ignores::IgnoresConfig::load(source_dir) {
                Ok(ignores_config) => {
                    // Merge loaded ignores with config ignores
                    // .guisu/ignores.toml patterns are appended to config file patterns
                    config.ignore.global.extend(ignores_config.global);
                    config.ignore.darwin.extend(ignores_config.darwin);
                    config.ignore.linux.extend(ignores_config.linux);
                    config.ignore.windows.extend(ignores_config.windows);
                }
                Err(e) => {
                    tracing::debug!("Failed to load ignores: {}", e);
                }
            }
        }

        Ok(config)
    }

    /// Save configuration to a file
    ///
    /// # Errors
    ///
    /// Returns error if serialization or file write fails
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| guisu_core::Error::Message(format!("Failed to serialize config: {e}")))?;

        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|e| {
                guisu_core::Error::Message(format!(
                    "Failed to create config directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        fs::write(path.as_ref(), content).map_err(|e| {
            guisu_core::Error::Message(format!(
                "Failed to write config file {}: {e}",
                path.as_ref().display()
            ))
        })?;

        Ok(())
    }

    /// Get age recipients from configuration
    ///
    /// Returns recipients from either `recipient` (single) or `recipients` (multiple).
    /// Returns None if no recipients are configured.
    ///
    /// Merges both `recipient` and `recipients` fields to support flexible configurations.
    ///
    /// # Examples
    ///
    /// Single recipient:
    /// ```toml
    /// [age]
    /// identity = "~/.config/guisu/key.txt"
    /// recipient = "age1ql3z..."
    /// ```
    ///
    /// Multiple recipients:
    /// ```toml
    /// [age]
    /// identity = "~/.config/guisu/key.txt"
    /// recipients = [
    ///     "age1ql3z...",  # Alice
    ///     "age1zvk...",  # Bob
    /// ]
    /// ```
    ///
    /// Combined (both fields):
    /// ```toml
    /// [age]
    /// recipient = "age1ql3z..."
    /// recipients = ["age1zvk..."]  # Will be merged
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if recipient string parsing fails
    pub fn age_recipients(&self) -> Result<Vec<guisu_crypto::Recipient>> {
        // Collect recipients from both fields
        let mut recipient_strings = Vec::new();

        // Add single recipient if configured
        if let Some(ref recipient) = self.age.recipient {
            recipient_strings.push(recipient.clone());
        }

        // Add multiple recipients if configured
        if !self.age.recipients.is_empty() {
            recipient_strings.extend(self.age.recipients.clone());
        }

        if recipient_strings.is_empty() {
            return Ok(Vec::new());
        }

        // Parse all recipient strings
        let mut recipients = Vec::new();
        for recipient_str in recipient_strings {
            let recipient = recipient_str
                .parse::<guisu_crypto::Recipient>()
                .map_err(|e| {
                    guisu_core::Error::Message(format!(
                        "Failed to parse recipient '{recipient_str}': {e}"
                    ))
                })?;
            recipients.push(recipient);
        }

        Ok(recipients)
    }

    /// Load all age identities from configuration
    ///
    /// Loads identities from all configured identity files, supporting both
    /// single `identity` and multiple `identities` configurations.
    /// Each identity file may contain multiple keys.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<Identity>)` - All loaded identities from all configured files
    /// - `Err(_)` - If no identities are configured or loading fails
    ///
    /// # Examples
    ///
    /// Single identity file:
    /// ```toml
    /// [age]
    /// identity = "~/.config/guisu/key.txt"
    /// ```
    ///
    /// Multiple identity files:
    /// ```toml
    /// [age]
    /// identities = [
    ///     "~/.config/guisu/key1.txt",
    ///     "~/.config/guisu/key2.txt",
    /// ]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if no identities are configured or loading fails
    pub fn age_identities(&self) -> Result<Vec<guisu_crypto::Identity>> {
        use guisu_crypto::load_identities;

        // Collect all configured identity paths
        let mut identity_paths = Vec::new();

        if let Some(ref identity) = self.age.identity {
            identity_paths.push(identity.clone());
        }

        if let Some(ref identities) = self.age.identities {
            identity_paths.extend(identities.clone());
        }

        // Check if any identities are configured
        if identity_paths.is_empty() {
            return Err(guisu_core::Error::Message(
                "No identity file configured. Add to your .guisu.toml:\n\n\
                 [age]\n\
                 identity = \"~/.config/guisu/key.txt\"\n\n\
                 Or use SSH key:\n\
                 identity = \"~/.ssh/id_ed25519\"\n\n\
                 Generate age key with: guisu age generate"
                    .to_string(),
            ));
        }

        let mut all_identities = Vec::new();

        for identity_path in identity_paths {
            if !identity_path.exists() {
                return Err(guisu_core::Error::Message(format!(
                    "Identity file not found: {}\n\
                     \n\
                     For age key: guisu age generate\n\
                     For SSH key: use existing SSH private key",
                    identity_path.display()
                )));
            }

            let is_ssh = Self::is_ssh_identity(&identity_path);
            let identities = load_identities(&identity_path, is_ssh).map_err(|e| {
                guisu_core::Error::Message(format!(
                    "Failed to load identity from {}: {}",
                    identity_path.display(),
                    e
                ))
            })?;

            if identities.is_empty() {
                return Err(guisu_core::Error::Message(format!(
                    "No identities found in {}",
                    identity_path.display()
                )));
            }

            all_identities.extend(identities);
        }

        if all_identities.is_empty() {
            return Err(guisu_core::Error::Message(
                "No identities loaded from configured files".to_string(),
            ));
        }

        Ok(all_identities)
    }

    /// Check if an identity file is an SSH key
    ///
    /// Simple rule: SSH keys are in `.ssh` directory.
    /// For keys in other locations, users should set `symmetric = true` in config.
    ///
    /// # Examples
    ///
    /// SSH keys (auto-detected):
    /// - `~/.ssh/id_ed25519` → SSH key
    /// - `~/.ssh/age` → SSH key
    /// - `/home/user/.ssh/my_key` → SSH key
    ///
    /// Age keys (default):
    /// - `~/.config/guisu/key.txt` → Age key
    /// - `/etc/age/key.txt` → Age key (use symmetric=true if it's SSH)
    #[must_use]
    pub fn is_ssh_identity(path: &Path) -> bool {
        // Simple check: if path contains "/.ssh/" or ends with "/.ssh", it's an SSH key
        let path_str = path.to_string_lossy();
        path_str.contains("/.ssh/") || path_str.ends_with("/.ssh")
    }

    /// Get the actual dotfiles directory
    ///
    /// Returns `source_dir/root_entry` (defaults to `source_dir/home`).
    /// This separates dotfiles from repository metadata (`.git`, `.guisu`).
    #[must_use]
    pub fn dotfiles_dir(&self, source_dir: &Path) -> PathBuf {
        source_dir.join(&self.general.root_entry)
    }

    /// Get the source directory from general config
    #[must_use]
    pub fn source_dir(&self) -> Option<&PathBuf> {
        self.general.src_dir.as_ref()
    }

    /// Get the destination directory from general config
    #[must_use]
    pub fn dest_dir(&self) -> Option<&PathBuf> {
        self.general.dst_dir.as_ref()
    }

    /// Get the editor command with arguments
    ///
    /// Returns None if no editor is configured.
    /// Returns a Vec with the editor command as first element and args following.
    #[must_use]
    pub fn editor_command(&self) -> Option<Vec<String>> {
        self.general.editor.as_ref().map(|editor| {
            let mut cmd = vec![editor.clone()];
            cmd.extend(self.general.editor_args.clone());
            cmd
        })
    }

    /// Get platform-specific ignore patterns for the current platform
    ///
    /// Returns the patterns from the ignore section that apply to the current platform.
    /// This combines global patterns with platform-specific patterns.
    #[must_use]
    pub fn platform_ignore_patterns(&self) -> (Vec<String>, Vec<String>) {
        let platform = CURRENT_PLATFORM.os;
        let platform_patterns = match platform {
            "darwin" => &self.ignore.darwin,
            "linux" => &self.ignore.linux,
            "windows" => &self.ignore.windows,
            _ => &vec![],
        };

        (self.ignore.global.clone(), platform_patterns.clone())
    }
}

// Implement ConfigProvider trait for Config
impl guisu_core::ConfigProvider for Config {
    fn source_dir(&self) -> Option<&PathBuf> {
        self.general.src_dir.as_ref()
    }

    fn dest_dir(&self) -> Option<&PathBuf> {
        self.general.dst_dir.as_ref()
    }

    fn variables(&self) -> &IndexMap<String, serde_json::Value> {
        &self.variables
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // Helper function to create a test directory with a config file
    fn create_test_config(toml_content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".guisu.toml");
        fs::write(&config_path, toml_content).unwrap();
        (temp_dir, config_path)
    }

    #[test]
    fn test_icon_mode_always() {
        let mode = IconMode::Always;
        assert!(mode.should_show_icons(true));
        assert!(mode.should_show_icons(false));
    }

    #[test]
    fn test_icon_mode_never() {
        let mode = IconMode::Never;
        assert!(!mode.should_show_icons(true));
        assert!(!mode.should_show_icons(false));
    }

    #[test]
    fn test_icon_mode_auto() {
        let mode = IconMode::Auto;
        assert!(mode.should_show_icons(true));
        assert!(!mode.should_show_icons(false));
    }

    #[test]
    fn test_icon_mode_default() {
        let mode = IconMode::default();
        assert_eq!(mode, IconMode::Auto);
    }

    #[test]
    fn test_auto_bool_default() {
        let ab = AutoBool::default();
        matches!(ab, AutoBool::Auto);
    }

    #[test]
    fn test_general_config_defaults() {
        let config = GeneralConfig::default();
        assert_eq!(config.root_entry, PathBuf::from("home"));
        assert!(config.color);
        assert!(config.progress);
        assert!(config.src_dir.is_none());
        assert!(config.dst_dir.is_none());
        assert!(config.editor.is_none());
        assert!(config.editor_args.is_empty());
    }

    #[test]
    fn test_bitwarden_config_default() {
        let config = BitwardenConfig::default();
        assert_eq!(config.provider, "bw");
    }

    #[test]
    fn test_ui_config_defaults() {
        let config = UiConfig::default();
        assert_eq!(config.icons, IconMode::Auto);
        assert_eq!(config.diff_format, "unified");
        assert_eq!(config.context_lines, 3);
        assert_eq!(config.preview_lines, 10);
    }

    #[test]
    fn test_age_config_default() {
        let config = AgeConfig::default();
        assert!(config.identity.is_none());
        assert!(config.identities.is_none());
        assert!(config.recipient.is_none());
        assert!(config.recipients.is_empty());
        assert!(!config.derive);
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.general.color);
        assert!(config.variables.is_empty());
        assert!(config.base_dir.is_none());
    }

    #[test]
    fn test_load_empty_config() {
        let (_temp_dir, config_path) = create_test_config("");
        let config = Config::load(&config_path).unwrap();

        // Should use defaults
        assert_eq!(config.general.root_entry, PathBuf::from("home"));
        assert!(config.general.color);
        assert!(config.general.progress);
    }

    #[test]
    fn test_load_config_with_general_section() {
        let toml = r#"
[general]
rootEntry = "dotfiles"
color = false
progress = false
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        assert_eq!(config.general.root_entry, PathBuf::from("dotfiles"));
        assert!(!config.general.color);
        assert!(!config.general.progress);
    }

    #[test]
    fn test_load_config_with_age_section() {
        let toml = r#"
[age]
identity = "~/.config/guisu/key.txt"
recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        // Path should be expanded
        assert!(config.age.identity.is_some());
        assert_eq!(
            config.age.recipient.as_deref(),
            Some("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
        );
    }

    #[test]
    fn test_load_config_with_multiple_recipients() {
        let toml = r#"
[age]
identity = "~/.config/guisu/key.txt"
recipients = [
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    "age1p3kwk3994wdjked7gn888c6vdljmwjj5admq3cjyp87emtdswc4q294pha",
]
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        assert_eq!(config.age.recipients.len(), 2);
    }

    #[test]
    fn test_load_config_with_symmetric_alias() {
        let toml = r#"
[age]
identity = "~/.config/guisu/key.txt"
symmetric = true
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        // symmetric is an alias for derive
        assert!(config.age.derive);
    }

    #[test]
    fn test_load_config_with_ui_section() {
        let toml = r#"
[ui]
icons = "always"
diffFormat = "split"
contextLines = 5
previewLines = 20
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        assert_eq!(config.ui.icons, IconMode::Always);
        assert_eq!(config.ui.diff_format, "split");
        assert_eq!(config.ui.context_lines, 5);
        assert_eq!(config.ui.preview_lines, 20);
    }

    #[test]
    fn test_load_config_with_bitwarden_section() {
        let toml = r#"
[bitwarden]
provider = "rbw"
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        assert_eq!(config.bitwarden.provider, "rbw");
    }

    #[test]
    fn test_load_config_with_ignore_section() {
        let toml = r#"
[ignore]
global = ["*.tmp", "*.log"]
darwin = [".DS_Store"]
linux = ["*.swp"]
windows = ["Thumbs.db"]
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        assert_eq!(config.ignore.global, vec!["*.tmp", "*.log"]);
        assert_eq!(config.ignore.darwin, vec![".DS_Store"]);
        assert_eq!(config.ignore.linux, vec!["*.swp"]);
        assert_eq!(config.ignore.windows, vec!["Thumbs.db"]);
    }

    #[test]
    fn test_load_config_with_variables() {
        let toml = r#"
[variables]
email = "user@example.com"
name = "Test User"
"#;
        let (_temp_dir, config_path) = create_test_config(toml);
        let config = Config::load(&config_path).unwrap();

        assert_eq!(config.variables.len(), 2);
        assert_eq!(
            config.variables.get("email").and_then(|v| v.as_str()),
            Some("user@example.com")
        );
        assert_eq!(
            config.variables.get("name").and_then(|v| v.as_str()),
            Some("Test User")
        );
    }

    #[test]
    fn test_resolve_tilde_path() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let path = PathBuf::from("~/test/file.txt");
        let resolved = Config::resolve_path(&path, base);

        // Should expand to home directory
        if let Some(home) = ::dirs::home_dir() {
            assert_eq!(resolved, home.join("test/file.txt"));
        }
    }

    #[test]
    fn test_resolve_tilde_only() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let path = PathBuf::from("~");
        let resolved = Config::resolve_path(&path, base);

        // Should expand to home directory
        if let Some(home) = ::dirs::home_dir() {
            assert_eq!(resolved, home);
        }
    }

    #[test]
    fn test_resolve_relative_path() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let path = PathBuf::from("./relative/path");
        let resolved = Config::resolve_path(&path, base);

        assert_eq!(resolved, base.join("relative/path"));
    }

    #[test]
    fn test_resolve_absolute_path() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();

        let path = PathBuf::from("/absolute/path");
        let resolved = Config::resolve_path(&path, base);

        // Absolute paths should remain unchanged
        assert_eq!(resolved, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");

        let mut config = Config::default();
        config.general.color = false;
        config.general.root_entry = PathBuf::from("dotfiles");
        config
            .variables
            .insert("test".to_string(), serde_json::json!("value"));

        // Save
        config.save(&config_path).unwrap();

        // Load
        let loaded = Config::load(&config_path).unwrap();

        assert!(!loaded.general.color);
        assert_eq!(loaded.general.root_entry, PathBuf::from("dotfiles"));
        assert_eq!(
            loaded.variables.get("test").and_then(|v| v.as_str()),
            Some("value")
        );
    }

    #[test]
    fn test_is_ssh_identity() {
        assert!(Config::is_ssh_identity(Path::new(
            "/home/user/.ssh/id_ed25519"
        )));
        assert!(Config::is_ssh_identity(Path::new("~/.ssh/id_rsa")));
        assert!(Config::is_ssh_identity(Path::new("/Users/user/.ssh/age")));

        assert!(!Config::is_ssh_identity(Path::new(
            "/home/user/.config/guisu/key.txt"
        )));
        assert!(!Config::is_ssh_identity(Path::new("~/key.txt")));
        assert!(!Config::is_ssh_identity(Path::new("/etc/age/key.txt")));
    }

    #[test]
    fn test_dotfiles_dir_default() {
        let config = Config::default();
        let source_dir = PathBuf::from("/home/user/dotfiles");

        let dotfiles = config.dotfiles_dir(&source_dir);
        assert_eq!(dotfiles, PathBuf::from("/home/user/dotfiles/home"));
    }

    #[test]
    fn test_dotfiles_dir_custom() {
        let mut config = Config::default();
        config.general.root_entry = PathBuf::from("files");
        let source_dir = PathBuf::from("/home/user/dotfiles");

        let dotfiles = config.dotfiles_dir(&source_dir);
        assert_eq!(dotfiles, PathBuf::from("/home/user/dotfiles/files"));
    }

    #[test]
    fn test_editor_command_none() {
        let config = Config::default();
        assert!(config.editor_command().is_none());
    }

    #[test]
    fn test_editor_command_no_args() {
        let mut config = Config::default();
        config.general.editor = Some("vim".to_string());

        let cmd = config.editor_command().unwrap();
        assert_eq!(cmd, vec!["vim"]);
    }

    #[test]
    fn test_editor_command_with_args() {
        let mut config = Config::default();
        config.general.editor = Some("code".to_string());
        config.general.editor_args = vec!["--wait".to_string(), "--new-window".to_string()];

        let cmd = config.editor_command().unwrap();
        assert_eq!(cmd, vec!["code", "--wait", "--new-window"]);
    }

    #[test]
    fn test_platform_ignore_patterns() {
        let mut config = Config::default();
        config.ignore.global = vec!["*.tmp".to_string()];
        config.ignore.darwin = vec![".DS_Store".to_string()];
        config.ignore.linux = vec!["*.swp".to_string()];
        config.ignore.windows = vec!["Thumbs.db".to_string()];

        let (global, platform) = config.platform_ignore_patterns();

        assert_eq!(global, vec!["*.tmp"]);

        // Platform-specific depends on current platform
        let current_platform = CURRENT_PLATFORM.os;
        match current_platform {
            "darwin" => assert_eq!(platform, vec![".DS_Store"]),
            "linux" => assert_eq!(platform, vec!["*.swp"]),
            "windows" => assert_eq!(platform, vec!["Thumbs.db"]),
            _ => assert!(platform.is_empty()),
        }
    }

    #[test]
    fn test_icon_mode_serialization() {
        assert_eq!(
            serde_json::to_value(IconMode::Auto).unwrap(),
            serde_json::json!("auto")
        );
        assert_eq!(
            serde_json::to_value(IconMode::Always).unwrap(),
            serde_json::json!("always")
        );
        assert_eq!(
            serde_json::to_value(IconMode::Never).unwrap(),
            serde_json::json!("never")
        );
    }

    #[test]
    fn test_icon_mode_deserialization() {
        assert_eq!(
            serde_json::from_value::<IconMode>(serde_json::json!("auto")).unwrap(),
            IconMode::Auto
        );
        assert_eq!(
            serde_json::from_value::<IconMode>(serde_json::json!("always")).unwrap(),
            IconMode::Always
        );
        assert_eq!(
            serde_json::from_value::<IconMode>(serde_json::json!("never")).unwrap(),
            IconMode::Never
        );
        // Test automatic alias
        assert_eq!(
            serde_json::from_value::<IconMode>(serde_json::json!("automatic")).unwrap(),
            IconMode::Auto
        );
    }

    #[test]
    fn test_auto_bool_serialization() {
        assert_eq!(
            serde_json::to_value(&AutoBool::Auto).unwrap(),
            serde_json::json!("auto")
        );
        assert_eq!(
            serde_json::to_value(&AutoBool::True).unwrap(),
            serde_json::json!("true")
        );
        assert_eq!(
            serde_json::to_value(&AutoBool::False).unwrap(),
            serde_json::json!("false")
        );
    }

    #[test]
    fn test_from_toml_str() {
        let temp_dir = TempDir::new().unwrap();
        let toml = r#"
[general]
color = false

[age]
identity = "./key.txt"
"#;

        let config = Config::from_toml_str(toml, temp_dir.path()).unwrap();
        assert!(!config.general.color);

        // Relative path should be resolved
        assert_eq!(
            config.age.identity.as_ref().unwrap(),
            &temp_dir.path().join("key.txt")
        );
    }

    #[test]
    fn test_load_from_source_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let result = Config::load_from_source(temp_dir.path());

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Configuration file not found"));
    }

    #[test]
    fn test_load_from_source_with_template_exists() {
        let temp_dir = TempDir::new().unwrap();
        let template_path = temp_dir.path().join(".guisu.toml.j2");
        fs::write(&template_path, "# template config").unwrap();

        let result = Config::load_from_source(temp_dir.path());

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Found .guisu.toml.j2 template"));
    }

    #[test]
    fn test_load_from_source_success() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".guisu.toml");
        fs::write(&config_path, "[general]\ncolor = false").unwrap();

        let config = Config::load_from_source(temp_dir.path()).unwrap();
        assert!(!config.general.color);
    }

    #[test]
    fn test_source_dir_and_dest_dir_accessors() {
        let mut config = Config::default();
        assert!(config.source_dir().is_none());
        assert!(config.dest_dir().is_none());

        config.general.src_dir = Some(PathBuf::from("/src"));
        config.general.dst_dir = Some(PathBuf::from("/dst"));

        assert_eq!(config.source_dir(), Some(&PathBuf::from("/src")));
        assert_eq!(config.dest_dir(), Some(&PathBuf::from("/dst")));
    }

    #[test]
    fn test_config_provider_trait() {
        use guisu_core::ConfigProvider;

        let mut config = Config::default();
        config.general.src_dir = Some(PathBuf::from("/src"));
        config.general.dst_dir = Some(PathBuf::from("/dst"));
        config
            .variables
            .insert("key".to_string(), serde_json::json!("value"));

        // Test trait methods
        assert_eq!(config.source_dir(), Some(&PathBuf::from("/src")));
        assert_eq!(config.dest_dir(), Some(&PathBuf::from("/dst")));
        assert_eq!(config.variables().len(), 1);
    }

    #[test]
    fn test_load_invalid_toml() {
        let (_temp_dir, config_path) = create_test_config("invalid toml {{");
        let result = Config::load(&config_path);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to parse config file"));
    }

    #[test]
    fn test_save_creates_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested/dir/config.toml");

        let config = Config::default();
        config.save(&nested_path).unwrap();

        assert!(nested_path.exists());
    }

    #[test]
    fn test_age_recipients_none() {
        let config = Config::default();
        let result = config.age_recipients().unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_age_identities_none_configured() {
        let config = Config::default();
        let result = config.age_identities();

        assert!(result.is_err());
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(err_msg.contains("No identity file configured"));
        }
    }

    #[test]
    fn test_age_identities_file_not_found() {
        let mut config = Config::default();
        config.age.identity = Some(PathBuf::from("/nonexistent/key.txt"));

        let result = config.age_identities();

        assert!(result.is_err());
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(err_msg.contains("Identity file not found"));
        }
    }

    #[test]
    fn test_ignore_config_default() {
        let config = IgnoreConfig::default();
        assert!(config.global.is_empty());
        assert!(config.darwin.is_empty());
        assert!(config.linux.is_empty());
        assert!(config.windows.is_empty());
    }

    #[test]
    fn test_complex_config_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("complex.toml");

        let mut config = Config::default();
        config.general.color = false;
        config.general.progress = true;
        config.general.root_entry = PathBuf::from("files");
        config.general.editor = Some("nvim".to_string());
        config.general.editor_args = vec!["-u".to_string(), "NONE".to_string()];

        config.ui.icons = IconMode::Always;
        config.ui.diff_format = "split".to_string();
        config.ui.context_lines = 5;

        config.ignore.global = vec!["*.log".to_string()];
        config.ignore.darwin = vec![".DS_Store".to_string()];

        config
            .variables
            .insert("name".to_string(), serde_json::json!("test"));
        config
            .variables
            .insert("email".to_string(), serde_json::json!("test@example.com"));

        config.bitwarden.provider = "rbw".to_string();

        // Save and reload
        config.save(&config_path).unwrap();
        let loaded = Config::load(&config_path).unwrap();

        assert_eq!(loaded.general.color, config.general.color);
        assert_eq!(loaded.general.progress, config.general.progress);
        assert_eq!(loaded.general.root_entry, config.general.root_entry);
        assert_eq!(loaded.general.editor, config.general.editor);
        assert_eq!(loaded.general.editor_args, config.general.editor_args);
        assert_eq!(loaded.ui.icons, config.ui.icons);
        assert_eq!(loaded.ui.diff_format, config.ui.diff_format);
        assert_eq!(loaded.ui.context_lines, config.ui.context_lines);
        assert_eq!(loaded.ignore.global, config.ignore.global);
        assert_eq!(loaded.ignore.darwin, config.ignore.darwin);
        assert_eq!(loaded.bitwarden.provider, config.bitwarden.provider);
        assert_eq!(loaded.variables.len(), 2);
    }
}
