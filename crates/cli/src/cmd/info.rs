//! Info command implementation
//!
//! Display current guisu status information.

use anyhow::Result;
use clap::Args;
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use tracing::debug;

use crate::command::Command;
use crate::common::RuntimeContext;
use guisu_config::Config;

use serde::Serialize;

const NOT_FOUND: &str = "not found";
const SOME_FILES_NOT_FOUND: &str = "some files not found";
const UNCOMMITTED_CHANGES: &str = "uncommitted changes";
const BUILTIN: &str = "builtin";

/// Information about guisu status
#[derive(Debug, Serialize)]
struct InfoData {
    guisu: GuisuInfo,
    build: Option<BuildInfo>,
    system: SystemInfo,
    git: GitInfo,
    age: AgeInfo,
    bitwarden: BitwardenInfo,
}

#[derive(Debug, Serialize)]
struct GuisuInfo {
    version: String,
    config: String,
    config_exists: bool,
    editor: Option<String>,
}

#[derive(Debug, Serialize)]
struct BuildInfo {
    rustc: String,
    timestamp: Option<String>,
    git_sha: Option<String>,
}

#[derive(Debug, Serialize)]
struct SystemInfo {
    os: String,
    architecture: String,
    kernel: Option<String>,
}

#[derive(Debug, Serialize)]
struct GitInfo {
    version: Option<&'static str>,
    repository: Option<String>,
    branch: Option<String>,
    sha: Option<String>,
    dirty: bool,
}

#[derive(Debug, Serialize)]
struct AgeInfo {
    identities: Vec<String>,
    all_files_exist: bool,
    derive: String,
    public_keys: Vec<String>,
    recipient_count: Option<usize>,
    version: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct BitwardenInfo {
    provider: Option<String>,
    version: Option<String>,
}

/// Info command
#[derive(Args)]
pub struct InfoCommand {
    /// Show all details (build info, versions, public keys, configuration, etc.)
    #[arg(long)]
    pub all: bool,

    /// Output in JSON format (default: table format)
    #[arg(long)]
    pub json: bool,
}

impl Command for InfoCommand {
    type Output = ();
    fn execute(&self, context: &RuntimeContext) -> crate::error::Result<()> {
        run_impl(context.source_dir(), &context.config, self.all, self.json).map_err(Into::into)
    }
}

/// Run the info command implementation
fn run_impl(source_dir: &Path, config: &Config, all: bool, json: bool) -> Result<()> {
    // Validate configuration
    validate_configuration(source_dir)?;

    let info = gather_info(source_dir, config, all);

    if json {
        display_json(&info, config, all)?;
    } else {
        display_table(&info);
    }

    Ok(())
}

/// Gather all system information
fn gather_info(source_dir: &Path, config: &Config, all: bool) -> InfoData {
    debug!("Gathering system information");

    let guisu_version = env!("CARGO_PKG_VERSION").to_string();
    let config_file_path = find_config_file(source_dir);

    let build_info = if all {
        Some(BuildInfo {
            rustc: option_env!("VERGEN_RUSTC_SEMVER")
                .unwrap_or(env!("CARGO_PKG_RUST_VERSION"))
                .to_string(),
            timestamp: option_env!("VERGEN_BUILD_TIMESTAMP").and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            }),
            git_sha: option_env!("VERGEN_GIT_SHA").map(str::to_string),
        })
    } else {
        None
    };

    let os = get_os_name();
    let architecture = std::env::consts::ARCH.to_string();
    let kernel = all.then(get_kernel_version);

    let git = get_git_info(source_dir, all);
    let age = get_age_info(config, all);
    let bitwarden = get_bitwarden_info(config, all);

    let (config_display, config_exists) = match config_file_path {
        Some(ref path) => {
            let display = if all {
                path.display().to_string()
            } else {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_else(|| path.to_str().unwrap_or(NOT_FOUND))
                    .to_string()
            };
            (display, true)
        }
        None => (NOT_FOUND.to_string(), false),
    };

    InfoData {
        guisu: GuisuInfo {
            version: guisu_version,
            config: config_display,
            config_exists,
            editor: all.then(|| config.general.editor.clone()).flatten(),
        },
        build: build_info,
        system: SystemInfo {
            os,
            architecture,
            kernel,
        },
        git,
        age,
        bitwarden,
    }
}

/// Find config file path
fn find_config_file(source_dir: &Path) -> Option<PathBuf> {
    let config_path = source_dir.join(".guisu.toml");
    let template_path = source_dir.join(".guisu.toml.j2");

    if config_path.exists() {
        Some(config_path)
    } else if template_path.exists() {
        Some(template_path)
    } else {
        None
    }
}

/// Get git repository information
fn get_git_info(source_dir: &Path, all: bool) -> GitInfo {
    if !source_dir.join(".git").exists() {
        return GitInfo {
            version: None,
            repository: None,
            branch: None,
            sha: None,
            dirty: false,
        };
    }

    match git2::Repository::open(source_dir) {
        Ok(repo) => {
            let repository = repo
                .find_remote("origin")
                .ok()
                .and_then(|remote| remote.url().map(str::to_string));

            let branch = repo
                .head()
                .ok()
                .and_then(|head| head.shorthand().map(str::to_string))
                .or_else(|| {
                    let git_head = source_dir.join(".git").join("HEAD");
                    std::fs::read_to_string(git_head).ok().and_then(|content| {
                        content
                            .strip_prefix("ref: refs/heads/")
                            .map(|s| s.trim().to_string())
                    })
                });

            let sha = if all {
                repo.head().ok().and_then(|head| {
                    head.peel_to_commit()
                        .ok()
                        .map(|commit| commit.id().to_string()[..8].to_string())
                })
            } else {
                None
            };

            let dirty = if all {
                let mut opts = git2::StatusOptions::new();
                opts.include_untracked(true);
                opts.include_ignored(false);
                repo.statuses(Some(&mut opts))
                    .is_ok_and(|statuses| !statuses.is_empty())
            } else {
                false
            };

            GitInfo {
                version: None,
                repository,
                branch,
                sha,
                dirty,
            }
        }
        Err(_) => GitInfo {
            version: None,
            repository: Some("local repository".to_string()),
            branch: None,
            sha: None,
            dirty: false,
        },
    }
}

/// Get bitwarden provider and command version
fn get_bitwarden_info(config: &Config, all: bool) -> BitwardenInfo {
    let provider = &config.bitwarden.provider;
    let version = ProcessCommand::new(provider)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let version_str = String::from_utf8_lossy(&output.stdout);
            let trimmed = version_str.trim();
            let cleaned = trimmed
                .strip_prefix("rbw ")
                .or_else(|| trimmed.strip_prefix("bw "))
                .unwrap_or(trimmed);
            all.then(|| cleaned.to_string())
        });

    BitwardenInfo {
        provider: version.as_ref().map(|_| provider.clone()),
        version,
    }
}

/// Get kernel version
fn get_kernel_version() -> String {
    #[cfg(unix)]
    {
        let info = rustix::system::uname();
        let release = info.release().to_string_lossy().to_string();
        if release.is_empty() {
            "unknown".to_string()
        } else {
            release
        }
    }

    #[cfg(not(unix))]
    {
        "unknown".to_string()
    }
}

/// Get OS name with version if possible using `os_info` crate
fn get_os_name() -> String {
    let info = os_info::get();

    // Format: "OS Type Version"
    let version = info.version();
    if version == &os_info::Version::Unknown {
        info.os_type().to_string()
    } else {
        format!("{} {}", info.os_type(), version)
    }
}

/// Get age encryption information
fn get_age_info(config: &Config, all: bool) -> AgeInfo {
    let identity_paths: Vec<&PathBuf> = config
        .age
        .identity
        .iter()
        .chain(config.age.identities.iter().flatten())
        .collect();

    if identity_paths.is_empty() {
        let default_path = guisu_config::dirs::default_age_identity()
            .unwrap_or_else(|| PathBuf::from("~/.config/guisu/key.txt"));
        return AgeInfo {
            identities: vec![default_path.display().to_string()],
            all_files_exist: false,
            derive: config.age.derive.to_string(),
            public_keys: vec![],
            recipient_count: None,
            version: None,
        };
    }

    let identity_files: Vec<String> = identity_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let all_files_exist = identity_paths.iter().all(|p| p.exists());

    let public_keys = if all {
        extract_public_keys(config)
    } else {
        Vec::new()
    };

    let recipient_count =
        (all && !config.age.recipients.is_empty()).then_some(config.age.recipients.len());

    AgeInfo {
        identities: identity_files,
        all_files_exist,
        derive: config.age.derive.to_string(),
        public_keys,
        recipient_count,
        version: all.then_some(BUILTIN),
    }
}

/// Extract all public keys from configured identities
fn extract_public_keys(config: &Config) -> Vec<String> {
    match config.age_identities() {
        Ok(identities) => identities
            .iter()
            .map(|id| id.to_public().to_string())
            .collect(),
        Err(e) => {
            debug!("Failed to load identities: {}", e);
            vec![]
        }
    }
}

/// Print a section header
fn print_section_header(name: &str) {
    println!("{}", name.bright_white().bold());
}

/// Display information in table format
fn display_table(info: &InfoData) {
    display_guisu_section(&info.guisu);
    display_build_section(info.build.as_ref());
    display_system_section(&info.system);
    display_git_section(&info.git);
    display_age_section(&info.age);
    display_bitwarden_section(&info.bitwarden);
}

/// Display guisu version and configuration
fn display_guisu_section(guisu: &GuisuInfo) {
    print_section_header("Guisu");
    print_row("Version", &guisu.version, true, None);
    print_row(
        "Config",
        &guisu.config,
        guisu.config_exists,
        (!guisu.config_exists).then_some(NOT_FOUND),
    );
    if let Some(ref editor) = guisu.editor {
        print_row("Editor", editor, true, None);
    }
    println!();
}

/// Display build information (if present)
fn display_build_section(build: Option<&BuildInfo>) {
    if let Some(build) = build {
        print_section_header("Build");
        print_row("Rustc", &build.rustc, true, None);
        if let Some(time) = build.timestamp.as_ref() {
            print_row("Timestamp", time, true, None);
        }
        if let Some(sha) = build.git_sha.as_ref() {
            print_row("Git SHA", sha, true, None);
        }
        println!();
    }
}

/// Display system information
fn display_system_section(system: &SystemInfo) {
    print_section_header("System");
    print_row("OS", &system.os, true, None);
    print_row("Architecture", &system.architecture, true, None);
    if let Some(kernel) = system.kernel.as_ref() {
        print_row("Kernel", kernel, true, None);
    }
    println!();
}

/// Display git repository information
fn display_git_section(git: &GitInfo) {
    if git.version.is_some()
        || git.repository.is_some()
        || git.branch.is_some()
        || git.sha.is_some()
    {
        print_section_header("Git");

        if let Some(version) = git.version {
            print_row("Version", version, true, None);
        }

        if let Some(repo) = git.repository.as_ref() {
            print_row("Repository", repo, true, None);
        }

        if let Some(branch) = git.branch.as_ref() {
            print_row("Branch", branch, true, None);
        }

        if let Some(sha) = git.sha.as_ref() {
            let note = git.dirty.then_some(UNCOMMITTED_CHANGES);
            print_row("SHA", sha, !git.dirty, note);
        }

        println!();
    }
}

/// Display age encryption information
fn display_age_section(age: &AgeInfo) {
    print_section_header("Age");

    if let Some(version) = age.version {
        print_row("Version", version, true, None);
    }

    display_age_identity_files(age);

    print_row("Derive", &age.derive, true, None);

    display_age_public_keys(&age.public_keys);

    if let Some(count) = age.recipient_count {
        let recipients_str = format!("{count} keys");
        print_row("Recipients", &recipients_str, true, None);
    }

    println!();
}

/// Display age identity files (single or multiple)
fn display_age_identity_files(age: &AgeInfo) {
    if age.identities.len() == 1 {
        print_row(
            "Identity",
            &age.identities[0],
            age.all_files_exist,
            (!age.all_files_exist).then_some(SOME_FILES_NOT_FOUND),
        );
    } else {
        for (i, file) in age.identities.iter().enumerate() {
            let label = if i == 0 { "Identities" } else { "" };
            print_row(
                label,
                file,
                age.all_files_exist,
                (i == 0 && !age.all_files_exist).then_some(SOME_FILES_NOT_FOUND),
            );
        }
    }
}

/// Display age public keys
fn display_age_public_keys(public_keys: &[String]) {
    if !public_keys.is_empty() {
        for (i, key) in public_keys.iter().enumerate() {
            let label = if i == 0 {
                if public_keys.len() == 1 {
                    "Public key"
                } else {
                    "Public keys"
                }
            } else {
                ""
            };
            print_row(label, key, true, None);
        }
    }
}

/// Display bitwarden information
fn display_bitwarden_section(bitwarden: &BitwardenInfo) {
    if bitwarden.provider.is_some() || bitwarden.version.is_some() {
        print_section_header("Bitwarden");
        if let Some(provider) = bitwarden.provider.as_ref() {
            print_row("Provider", provider, true, None);
        }
        if let Some(version) = bitwarden.version.as_ref() {
            print_row("Version", version, true, None);
        }
        println!();
    }
}

/// Print a single table row with status indicator
fn print_row(label: &str, value: &str, ok: bool, note: Option<&str>) {
    let symbol = if ok {
        "✓".bright_green().to_string()
    } else if note.is_some() {
        "✗".bright_red().to_string()
    } else {
        "⚠".yellow().to_string()
    };

    let formatted_value = if ok {
        value.bright_white().to_string()
    } else {
        value.dimmed().to_string()
    };

    if let Some(note_text) = note {
        println!(
            "  {} {:14} {} {}",
            symbol,
            label,
            formatted_value,
            format!("({note_text})").dimmed()
        );
    } else {
        println!("  {symbol} {label:14} {formatted_value}");
    }
}

/// Validate configuration file
fn validate_configuration(source_dir: &Path) -> Result<()> {
    // Check if .guisu.toml or .guisu.toml.j2 exists
    let config_file = source_dir.join(".guisu.toml");
    let config_template = source_dir.join(".guisu.toml.j2");

    if !config_template.exists() && !config_file.exists() {
        anyhow::bail!(
            "Configuration file not found.\n\
             Expected: .guisu.toml or .guisu.toml.j2 in {}",
            source_dir.display()
        );
    }

    // Try to load config to validate it
    crate::load_config_with_template_support(None, source_dir, None)
        .map_err(|e| anyhow::anyhow!("Configuration validation failed: {e}"))?;

    Ok(())
}

/// Display info data in JSON format
fn display_json(info: &InfoData, config: &Config, all: bool) -> Result<()> {
    if all {
        // Include configuration in JSON output
        use serde::Serialize;

        #[derive(Serialize)]
        struct InfoWithConfig<'a> {
            #[serde(flatten)]
            info: &'a InfoData,
            config: ConfigDisplay<'a>,
        }

        #[derive(Serialize)]
        struct ConfigDisplay<'a> {
            general: &'a guisu_config::GeneralConfig,
            age: &'a guisu_config::AgeConfig,
            bitwarden: &'a guisu_config::BitwardenConfig,
            ignore: &'a guisu_config::IgnoreConfig,
        }

        let output = InfoWithConfig {
            info,
            config: ConfigDisplay {
                general: &config.general,
                age: &config.age,
                bitwarden: &config.bitwarden,
                ignore: &config.ignore,
            },
        };

        let json = serde_json::to_string_pretty(&output)?;
        println!("{json}");
    } else {
        let json = serde_json::to_string_pretty(info)?;
        println!("{json}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    // Tests for InfoCommand

    #[test]
    fn test_info_command_default() {
        let cmd = InfoCommand {
            all: false,
            json: false,
        };

        assert!(!cmd.all);
        assert!(!cmd.json);
    }

    #[test]
    fn test_info_command_all_flag() {
        let cmd = InfoCommand {
            all: true,
            json: false,
        };

        assert!(cmd.all);
        assert!(!cmd.json);
    }

    #[test]
    fn test_info_command_json_flag() {
        let cmd = InfoCommand {
            all: false,
            json: true,
        };

        assert!(!cmd.all);
        assert!(cmd.json);
    }

    #[test]
    fn test_info_command_both_flags() {
        let cmd = InfoCommand {
            all: true,
            json: true,
        };

        assert!(cmd.all);
        assert!(cmd.json);
    }

    // Tests for InfoData structures

    #[test]
    fn test_info_data_debug() {
        let info = InfoData {
            guisu: GuisuInfo {
                version: "test".to_string(),
                config: "/test/.guisu.toml".to_string(),
                config_exists: true,
                editor: None,
            },
            build: Some(BuildInfo {
                rustc: "1.70.0".to_string(),
                timestamp: Some("2025-01-01".to_string()),
                git_sha: Some("abc123".to_string()),
            }),
            system: SystemInfo {
                os: "Linux".to_string(),
                architecture: "x86_64".to_string(),
                kernel: Some("6.0.0".to_string()),
            },
            git: GitInfo {
                version: Some("builtin"),
                repository: Some("repo".to_string()),
                branch: Some("main".to_string()),
                sha: Some("abc".to_string()),
                dirty: false,
            },
            age: AgeInfo {
                identities: vec!["/path".to_string()],
                all_files_exist: true,
                derive: "true".to_string(),
                public_keys: vec!["key1".to_string()],
                recipient_count: Some(3),
                version: Some("1.0"),
            },
            bitwarden: BitwardenInfo {
                provider: Some("bw".to_string()),
                version: Some("1.0".to_string()),
            },
        };

        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("InfoData"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_info_data_serialize() {
        let info = InfoData {
            guisu: GuisuInfo {
                version: "test".to_string(),
                config: "/config".to_string(),
                config_exists: true,
                editor: None,
            },
            build: None,
            system: SystemInfo {
                os: "Linux".to_string(),
                architecture: "x86_64".to_string(),
                kernel: None,
            },
            git: GitInfo {
                version: None,
                repository: None,
                branch: None,
                sha: None,
                dirty: false,
            },
            age: AgeInfo {
                identities: vec![],
                all_files_exist: true,
                derive: "false".to_string(),
                public_keys: vec![],
                recipient_count: None,
                version: None,
            },
            bitwarden: BitwardenInfo {
                provider: None,
                version: None,
            },
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"version\":\"test\""));
        assert!(json.contains("\"os\":\"Linux\""));
    }

    #[test]
    fn test_guisu_info_debug() {
        let guisu = GuisuInfo {
            version: "1.0.0".to_string(),
            config: "/config/.guisu.toml".to_string(),
            config_exists: true,
            editor: None,
        };

        let debug_str = format!("{guisu:?}");
        assert!(debug_str.contains("GuisuInfo"));
        assert!(debug_str.contains("1.0.0"));
    }

    #[test]
    fn test_guisu_info_serialize() {
        let guisu = GuisuInfo {
            version: "1.0.0".to_string(),
            config: "/config/.guisu.toml".to_string(),
            config_exists: true,
            editor: None,
        };

        let json = serde_json::to_string(&guisu).unwrap();
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"config\":\"/config/.guisu.toml\""));
    }

    #[test]
    fn test_build_info_debug() {
        let build = BuildInfo {
            rustc: "1.70.0".to_string(),
            timestamp: Some("2025-01-01T00:00:00Z".to_string()),
            git_sha: Some("abc123".to_string()),
        };

        let debug_str = format!("{build:?}");
        assert!(debug_str.contains("BuildInfo"));
        assert!(debug_str.contains("abc123"));
    }

    #[test]
    fn test_build_info_serialize() {
        let build = BuildInfo {
            rustc: "1.70.0".to_string(),
            timestamp: None,
            git_sha: None,
        };

        let json = serde_json::to_string(&build).unwrap();
        assert!(json.contains("\"rustc\":\"1.70.0\""));
    }

    #[test]
    fn test_system_info_debug() {
        let system = SystemInfo {
            os: "Linux".to_string(),
            architecture: "x86_64".to_string(),
            kernel: Some("6.0.0".to_string()),
        };

        let debug_str = format!("{system:?}");
        assert!(debug_str.contains("SystemInfo"));
        assert!(debug_str.contains("Linux"));
    }

    #[test]
    fn test_system_info_serialize() {
        let system = SystemInfo {
            os: "macOS".to_string(),
            architecture: "aarch64".to_string(),
            kernel: None,
        };

        let json = serde_json::to_string(&system).unwrap();
        assert!(json.contains("\"os\":\"macOS\""));
        assert!(json.contains("\"architecture\":\"aarch64\""));
    }

    #[test]
    fn test_git_info_debug() {
        let git = GitInfo {
            version: Some("builtin"),
            repository: Some("repo".to_string()),
            branch: Some("main".to_string()),
            sha: Some("abc123".to_string()),
            dirty: false,
        };

        let debug_str = format!("{git:?}");
        assert!(debug_str.contains("GitInfo"));
        assert!(debug_str.contains("main"));
    }

    #[test]
    fn test_git_info_serialize() {
        let git = GitInfo {
            version: None,
            repository: None,
            branch: None,
            sha: None,
            dirty: false,
        };

        let json = serde_json::to_string(&git).unwrap();
        assert!(json.contains("\"dirty\":false"));
    }

    #[test]
    fn test_age_info_debug() {
        let age = AgeInfo {
            identities: vec!["/path1".to_string(), "/path2".to_string()],
            all_files_exist: true,
            derive: "key".to_string(),
            public_keys: vec!["age1...".to_string()],
            recipient_count: Some(3),
            version: Some("1.0"),
        };

        let debug_str = format!("{age:?}");
        assert!(debug_str.contains("AgeInfo"));
        assert!(debug_str.contains("identities"));
    }

    #[test]
    fn test_age_info_serialize() {
        let age = AgeInfo {
            identities: vec!["/identity".to_string()],
            all_files_exist: true,
            derive: "false".to_string(),
            public_keys: vec![],
            recipient_count: None,
            version: None,
        };

        let json = serde_json::to_string(&age).unwrap();
        assert!(json.contains("\"identities\":[\"/identity\"]"));
    }

    #[test]
    fn test_bitwarden_info_debug() {
        let bw = BitwardenInfo {
            provider: Some("bw".to_string()),
            version: Some("1.0.0".to_string()),
        };

        let debug_str = format!("{bw:?}");
        assert!(debug_str.contains("BitwardenInfo"));
        assert!(debug_str.contains("bw"));
    }

    #[test]
    fn test_bitwarden_info_serialize() {
        let bw = BitwardenInfo {
            provider: None,
            version: None,
        };

        let json = serde_json::to_string(&bw).unwrap();
        assert!(json.contains("null"));
    }

    // Tests for pure functions

    #[test]
    fn test_get_os_name_from_os_info() {
        // This function uses os_info::get() which returns the actual OS
        let os_name = get_os_name();

        // Just verify it returns a non-empty string
        assert!(!os_name.is_empty());
    }

    #[test]
    fn test_get_kernel_version() {
        // This function returns String (not Option)
        let kernel = get_kernel_version();

        // Just verify it returns a non-empty string
        assert!(!kernel.is_empty());
    }
}
