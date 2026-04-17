//! Hook management commands
//!
//! This module provides commands for managing and executing hooks.
//! Hooks are executed before and after applying dotfiles.

use anyhow::{Context, Result};
use guisu_config::Config;
use guisu_core::platform::CURRENT_PLATFORM;
use guisu_engine::hooks::{HookLoader, HookRunner, HookStage, TemplateRenderer};
use guisu_engine::state::{HookStatePersistence, RedbPersistentState};
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::ui::icons::StatusIcon;
use crate::utils::path::SourceDirExt;

/// Run hooks
///
/// # Errors
///
/// Returns an error if:
/// - Loading hooks from the hooks directory fails
/// - Database operations fail (saving state)
/// - User confirmation input fails (when not skipped)
/// - Template engine creation fails
/// - Hook execution fails
pub fn run_hooks(
    source_dir: &Path,
    config: &Config,
    db: &RedbPersistentState,
    skip_confirm: bool,
    hook_filter: Option<&str>,
) -> Result<()> {
    let is_tty = std::io::stdout().is_terminal();
    let use_nerd_fonts = config.ui.icons.should_show_icons(is_tty);
    // Load hooks using HookLoader
    let loader = HookLoader::new(source_dir);

    if !loader.exists() {
        println!("{}", "No hooks directory found.".yellow());
        println!("Create .guisu/hooks/pre/ and .guisu/hooks/post/ directories to get started.");
        println!("\nExample structure:");
        println!(
            "{}",
            r"
.guisu/hooks/
  pre/
    01-setup.sh          # Script to run before applying
    02-install.toml      # Hook configuration
  post/
    01-cleanup.sh        # Script to run after applying
    99-notify.toml       # Notification hook
"
            .dimmed()
        );
        return Ok(());
    }

    let mut collections = loader.load().context("Failed to load hooks")?;

    // Filter hooks if a specific hook name is provided
    if let Some(filter_name) = hook_filter {
        collections.pre.retain(|h| h.name.as_str() == filter_name);
        collections.post.retain(|h| h.name.as_str() == filter_name);

        if collections.is_empty() {
            println!("{}", format!("Hook '{filter_name}' not found.").yellow());
            return Ok(());
        }

        println!(
            "{} Running hook: {}",
            StatusIcon::Hook.get(use_nerd_fonts),
            filter_name.cyan()
        );
    }

    if collections.is_empty() {
        println!("{}", "No hooks configured.".yellow());
        return Ok(());
    }

    let platform = CURRENT_PLATFORM.os;
    let total_hooks = collections.total();

    println!(
        "{} Hooks directory: {}",
        StatusIcon::Hook.get(use_nerd_fonts),
        source_dir.hooks_dir().display().cyan()
    );
    println!("Platform: {}", platform.cyan());
    println!("Total hooks: {total_hooks}");
    println!("  Pre hooks: {}", collections.pre.len());
    println!("  Post hooks: {}", collections.post.len());

    // Confirm unless --yes is specified
    if !skip_confirm {
        use dialoguer::{Confirm, theme::ColorfulTheme};

        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Run hooks?")
            .default(true)
            .interact()?;

        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Load persistent state for hook execution tracking (using provided database)
    let persistence = HookStatePersistence::new(db);
    let mut state = persistence.load()?;

    // Create template renderer
    let renderer = create_template_engine(source_dir, config)?;

    // Create hook runner with builder pattern
    // For `hooks run`, always run hooks regardless of state (once/onchange)
    let runner = HookRunner::builder(&collections, source_dir)
        .template_renderer(renderer)
        .build();

    // Run hooks in stages
    println!("\n{}", "Running pre hooks...".bold());
    runner
        .run_stage(HookStage::Pre)
        .context("Pre hooks failed")?;

    println!("\n{}", "Running post hooks...".bold());
    runner
        .run_stage(HookStage::Post)
        .context("Post hooks failed")?;

    // Get newly executed hooks and merge with state
    for hook_name in runner.get_once_executed() {
        state.mark_executed_once(hook_name);
    }
    for (hook_name, content_hash) in runner.get_onchange_hashes() {
        state.update_onchange_hash(hook_name, content_hash);
    }
    for (hook_name, rendered_content) in runner.get_onchange_rendered() {
        state.update_onchange_rendered(hook_name, rendered_content);
    }

    // Update state in database
    let hooks_dir = source_dir.hooks_dir();
    state
        .update(&hooks_dir)
        .context("Failed to update hook state")?;

    persistence
        .save(&state)
        .context("Failed to save hook state")?;

    println!(
        "\n{} {}",
        StatusIcon::Success.get(use_nerd_fonts),
        "All hooks completed!".green().bold()
    );

    Ok(())
}

/// List configured hooks
///
/// # Errors
///
/// Returns an error if:
/// - Loading hooks from the hooks directory fails
/// - JSON serialization fails (when format is "json")
pub fn run_list(source_dir: &Path, _config: &Config, format: &str) -> Result<()> {
    // Load hooks using HookLoader
    let loader = HookLoader::new(source_dir);

    if !loader.exists() {
        println!("{}", "No hooks directory found.".yellow());
        return Ok(());
    }

    let collections = loader.load().context("Failed to load hooks")?;

    let platform = CURRENT_PLATFORM.os;

    if format == "json" {
        // JSON output
        let json = serde_json::json!({
            "hooks_dir": source_dir.hooks_dir(),
            "platform": platform,
            "hooks": {
                "pre": collections.pre,
                "post": collections.post,
            },
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        // Simple output
        println!(
            "Hooks directory: {}",
            source_dir.hooks_dir().display().cyan()
        );
        println!("Platform: {}", platform.cyan());
        println!();

        println!("{} ({} hooks)", "Pre hooks:".bold(), collections.pre.len());
        for hook in &collections.pre {
            if hook.should_run_on(platform) {
                println!("  • {} (order: {})", hook.name.green(), hook.order);
            } else {
                println!(
                    "  • {} (order: {}) {}",
                    hook.name.dimmed(),
                    hook.order,
                    "[skipped]".dimmed()
                );
            }
        }

        println!(
            "\n{} ({} hooks)",
            "Post hooks:".bold(),
            collections.post.len()
        );
        for hook in &collections.post {
            if hook.should_run_on(platform) {
                println!("  • {} (order: {})", hook.name.green(), hook.order);
            } else {
                println!(
                    "  • {} (order: {}) {}",
                    hook.name.dimmed(),
                    hook.order,
                    "[skipped]".dimmed()
                );
            }
        }
    }

    Ok(())
}

/// Check hook configuration status
///
/// # Errors
///
/// Returns an error if:
/// - Loading hooks from the hooks directory fails
/// - Database operations fail (loading state)
/// - Checking for changes in hooks directory fails
/// - JSON serialization fails (when format is "json")
pub fn run_check(
    source_dir: &Path,
    config: &Config,
    db: &RedbPersistentState,
    format: &str,
) -> Result<()> {
    let is_tty = std::io::stdout().is_terminal();
    let use_nerd_fonts = config.ui.icons.should_show_icons(is_tty);
    // Load hooks using HookLoader
    let loader = HookLoader::new(source_dir);

    if !loader.exists() {
        println!("{}", "No hooks directory found.".yellow());
        return Ok(());
    }

    let collections = loader.load().context("Failed to load hooks")?;

    // Load state from database (using provided database)
    let persistence = HookStatePersistence::new(db);
    let state = persistence.load()?;

    let hooks_dir = source_dir.hooks_dir();
    let has_changed = state.has_changed(&hooks_dir)?;
    let platform = CURRENT_PLATFORM.os;

    if format == "json" {
        let json = serde_json::json!({
            "hooks_dir": hooks_dir,
            "platform": platform,
            "has_changed": has_changed,
            "last_executed": state.last_executed,
            "total_hooks": collections.total(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("Hooks directory: {}", hooks_dir.display().cyan());
        println!("Platform: {}", platform.cyan());
        println!();

        if has_changed {
            println!(
                "{} {}",
                StatusIcon::Warning.get(use_nerd_fonts),
                "Hooks have changed since last execution".yellow().bold()
            );
            println!("Run {} to execute hooks", "guisu hooks run".cyan());
        } else {
            println!(
                "{} {}",
                StatusIcon::Success.get(use_nerd_fonts),
                "Hooks are up to date".green()
            );
        }

        let total_hooks = collections.total();

        println!("\nTotal hooks: {total_hooks}");
        println!("  Pre: {}", collections.pre.len());
        println!("  Post: {}", collections.post.len());
    }

    Ok(())
}

/// Show detailed information about a specific hook
///
/// # Errors
///
/// Returns an error if loading hooks from the hooks directory fails
pub fn run_show(source_dir: &Path, config: &Config, hook_name: &str) -> Result<()> {
    let is_tty = std::io::stdout().is_terminal();
    let use_nerd_fonts = config.ui.icons.should_show_icons(is_tty);

    let collections = load_hooks_or_return(source_dir)?;

    let hook = collections
        .pre
        .iter()
        .chain(collections.post.iter())
        .find(|h| h.name.as_str() == hook_name);

    if let Some(hook) = hook {
        let stage = determine_hook_stage(&collections, hook_name);

        display_basic_hook_info(hook, stage);
        display_platform_info(hook);
        display_hook_settings(hook);
        display_script_or_command(hook, source_dir, config);
        display_environment_variables(hook);

        println!();
    } else {
        display_hook_not_found(hook_name, use_nerd_fonts);
    }

    Ok(())
}

/// Load hooks from directory or return early if directory doesn't exist
fn load_hooks_or_return(source_dir: &Path) -> Result<guisu_engine::hooks::HookCollections> {
    let loader = HookLoader::new(source_dir);

    if !loader.exists() {
        println!("{}", "No hooks directory found.".yellow());
        return Ok(guisu_engine::hooks::HookCollections::default());
    }

    loader.load().context("Failed to load hooks")
}

/// Determine whether hook is in pre or post stage
fn determine_hook_stage(
    collections: &guisu_engine::hooks::HookCollections,
    hook_name: &str,
) -> &'static str {
    if collections.pre.iter().any(|h| h.name.as_str() == hook_name) {
        "pre"
    } else {
        "post"
    }
}

/// Display basic hook information (name, stage, order, mode)
fn display_basic_hook_info(hook: &guisu_engine::hooks::config::Hook, stage: &str) {
    println!();
    println!("{} {}", "Hook:".bold(), hook.name.cyan());
    println!("{} {}", "Stage:".bold(), stage);
    println!("{} {}", "Order:".bold(), hook.order);
    println!("{} {:?}", "Mode:".bold(), hook.mode);
}

/// Display platform compatibility information
fn display_platform_info(hook: &guisu_engine::hooks::config::Hook) {
    if hook.platforms.is_empty() {
        println!("{} All platforms", "Platforms:".bold());
    } else {
        println!(
            "{} {}",
            "Platforms:".bold(),
            hook.platforms
                .iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

/// Display command or script content
fn display_script_or_command(
    hook: &guisu_engine::hooks::config::Hook,
    source_dir: &Path,
    config: &Config,
) {
    if let Some(ref cmd) = hook.cmd {
        println!("{} {}", "Command:".bold(), cmd);
    } else if let Some(ref script) = hook.script {
        println!("{} {}", "Script:".bold(), script);

        let script_path = source_dir.join(script);

        if script_path.exists()
            && let Ok(content) = std::fs::read_to_string(&script_path)
        {
            display_script_file_content(&script_path, &content, source_dir, config);
        }
    }
}

/// Display the content of a script file (with template rendering if needed)
fn display_script_file_content(
    script_path: &Path,
    content: &str,
    source_dir: &Path,
    config: &Config,
) {
    let is_template = script_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "j2");

    let display_content = if is_template {
        render_template_or_show_error(content, source_dir, config)
    } else {
        content.to_string()
    };

    println!("\n{}", "Script content:".bold());
    if is_template {
        println!("{}", "(rendered from template)".dimmed());
    }
    println!("{}", "─".repeat(60).dimmed());
    println!("{}", display_content.dimmed());
    println!("{}", "─".repeat(60).dimmed());
}

/// Render template content or return error message with raw template
fn render_template_or_show_error(content: &str, source_dir: &Path, config: &Config) -> String {
    match create_template_engine(source_dir, config) {
        Ok(template_renderer) => match template_renderer.render(content) {
            Ok(rendered) => rendered,
            Err(e) => format!("Template rendering failed: {e}\n\nRaw template:\n{content}"),
        },
        Err(e) => format!("Failed to create template engine: {e}\n\nRaw template:\n{content}"),
    }
}

/// Display environment variables
fn display_environment_variables(hook: &guisu_engine::hooks::config::Hook) {
    if !hook.env.is_empty() {
        println!("\n{}", "Environment variables:".bold());
        for (key, value) in &hook.env {
            println!("  {} = {}", key.cyan(), value);
        }
    }
}

/// Display timeout and failfast settings
fn display_hook_settings(hook: &guisu_engine::hooks::config::Hook) {
    // Only display timeout if it's set (non-zero)
    if hook.timeout > 0 {
        println!("{} {} seconds", "Timeout:".bold(), hook.timeout);
    }

    println!("{} {}", "Failfast:".bold(), hook.failfast);
}

/// Display message when hook is not found
fn display_hook_not_found(hook_name: &str, use_nerd_fonts: bool) {
    println!(
        "{} {}",
        StatusIcon::Warning.get(use_nerd_fonts),
        format!("Hook '{hook_name}' not found.").yellow()
    );
    println!(
        "\nUse {} to list all available hooks.",
        "guisu hooks list".cyan()
    );
}

/// Handle hooks during apply (auto-run if hooks changed)
///
/// # Errors
///
/// Returns an error if:
/// - Loading hooks from the hooks directory fails
/// - Database operations fail (loading or saving state)
/// - Template engine creation fails
/// - Pre hook execution fails
pub fn handle_hooks_pre(
    source_dir: &Path,
    config: &Config,
    db: &RedbPersistentState,
) -> Result<()> {
    use guisu_engine::hooks::config::HookMode;

    // Load hooks using HookLoader
    let loader = HookLoader::new(source_dir);

    if !loader.exists() {
        tracing::debug!("No hooks directory found, skipping");
        return Ok(());
    }

    let collections = loader.load().context("Failed to load hooks")?;

    if collections.pre.is_empty() {
        tracing::debug!("No pre hooks configured, skipping");
        return Ok(());
    }

    // Load persistent state for hook execution tracking (using provided database)
    let persistence = HookStatePersistence::new(db);
    let mut state = persistence.load()?;

    // Show which hooks will run
    let platform = guisu_core::platform::CURRENT_PLATFORM.os;
    let active_hooks: Vec<_> = collections
        .pre
        .iter()
        .filter(|h| {
            // Check platform compatibility
            if !h.should_run_on(platform) {
                return false;
            }

            // Check if hook will actually execute based on mode
            // Note: OnChange mode requires template rendering, which is done in the executor
            // We skip the pre-check here and let the executor handle it
            match h.mode {
                HookMode::Once => !state.once_executed.contains(h.name.as_str()),
                HookMode::Always | HookMode::OnChange => true, // Let executor decide after rendering templates
            }
        })
        .collect();

    // Only run hooks if there are active ones, but always update state
    if !active_hooks.is_empty() {
        // Create template renderer
        let renderer = create_template_engine(source_dir, config)?;

        // Create hook runner with builder pattern and run pre hooks
        // Pass persistent state to respect mode=once and mode=onchange
        let runner = HookRunner::builder(&collections, source_dir)
            .template_renderer(renderer)
            .persistent_state(state.once_executed.clone(), state.onchange_hashes.clone())
            .build();
        runner.run_stage(HookStage::Pre)?;

        // Get newly executed hooks and merge with state
        for hook_name in runner.get_once_executed() {
            state.mark_executed_once(hook_name);
        }
        for (hook_name, content_hash) in runner.get_onchange_hashes() {
            state.update_onchange_hash(hook_name, content_hash);
        }
        for (hook_name, rendered_content) in runner.get_onchange_rendered() {
            state.update_onchange_rendered(hook_name, rendered_content);
        }
    }

    // Always update state in database, even if no hooks ran
    // This marks the hooks directory as "checked" and prevents repeated warnings
    let hooks_dir = source_dir.hooks_dir();
    state.update_with_collections(&hooks_dir, collections)?;
    persistence.save(&state)?;

    Ok(())
}

/// Handle hooks after apply
///
/// # Errors
///
/// Returns an error if:
/// - Loading hooks from the hooks directory fails
/// - Database operations fail (loading or saving state)
/// - Template engine creation fails
/// - Post hook execution fails
pub fn handle_hooks_post(
    source_dir: &Path,
    config: &Config,
    db: &RedbPersistentState,
) -> Result<()> {
    use guisu_engine::hooks::config::HookMode;

    // Load hooks using HookLoader
    let loader = HookLoader::new(source_dir);

    if !loader.exists() {
        tracing::debug!("No hooks directory found, skipping");
        return Ok(());
    }

    let collections = loader.load().context("Failed to load hooks")?;

    if collections.post.is_empty() {
        tracing::debug!("No post hooks configured, skipping");
        return Ok(());
    }

    // Load persistent state for hook execution tracking (using provided database)
    let persistence = HookStatePersistence::new(db);
    let mut state = persistence.load()?;

    // Show which hooks will run
    let platform = guisu_core::platform::CURRENT_PLATFORM.os;
    let active_hooks: Vec<_> = collections
        .post
        .iter()
        .filter(|h| {
            // Check platform compatibility
            if !h.should_run_on(platform) {
                return false;
            }

            // Check if hook will actually execute based on mode
            // Note: OnChange mode requires template rendering, which is done in the executor
            // We skip the pre-check here and let the executor handle it
            match h.mode {
                HookMode::Once => !state.once_executed.contains(h.name.as_str()),
                HookMode::Always | HookMode::OnChange => true, // Let executor decide after rendering templates
            }
        })
        .collect();

    // Only run hooks if there are active ones, but always update state
    if !active_hooks.is_empty() {
        // Create template renderer
        let renderer = create_template_engine(source_dir, config)?;

        // Create hook runner with builder pattern and run post hooks
        // Pass persistent state to respect mode=once and mode=onchange
        let runner = HookRunner::builder(&collections, source_dir)
            .template_renderer(renderer)
            .persistent_state(state.once_executed.clone(), state.onchange_hashes.clone())
            .build();
        runner.run_stage(HookStage::Post)?;

        // Get newly executed hooks and merge with state
        for hook_name in runner.get_once_executed() {
            state.mark_executed_once(hook_name);
        }
        for (hook_name, content_hash) in runner.get_onchange_hashes() {
            state.update_onchange_hash(hook_name, content_hash);
        }
        for (hook_name, rendered_content) in runner.get_onchange_rendered() {
            state.update_onchange_rendered(hook_name, rendered_content);
        }
    }

    // Always update state in database, even if no hooks ran
    // This marks the hooks directory as "checked" and prevents repeated warnings
    let hooks_dir = source_dir.hooks_dir();
    state.update_with_collections(&hooks_dir, collections)?;
    persistence.save(&state)?;

    Ok(())
}

/// Create a template renderer closure for hooks
fn create_template_engine(source_dir: &Path, config: &Config) -> Result<impl TemplateRenderer> {
    use guisu_template::TemplateContext;
    use std::sync::Arc;

    // Load age identities for encryption support in templates
    let identities = Arc::new(config.age_identities().unwrap_or_else(|_| Vec::new()));

    // Create template engine with bitwarden provider support
    let engine = crate::create_template_engine(source_dir, &identities, config);

    // Get destination directory (use home_dir as default if not configured)
    let dst_dir = config
        .general
        .dst_dir
        .clone()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("~"));

    // Create template context with guisu info and all variables
    let working_tree = guisu_engine::git::find_working_tree(source_dir)
        .unwrap_or_else(|| source_dir.to_path_buf());
    let dotfiles_dir = config.dotfiles_dir(source_dir);
    let context = TemplateContext::new()
        .with_guisu_info(
            crate::path_to_string(&dotfiles_dir),
            crate::path_to_string(&working_tree),
            crate::path_to_string(&dst_dir),
            crate::path_to_string(&config.general.root_entry),
        )
        .with_loaded_variables(source_dir, config)
        .map_err(|e| anyhow::anyhow!("Failed to load variables: {e}"))?;

    // Return a closure that captures both engine and context
    // No Box needed - the closure implements TemplateRenderer directly
    Ok(move |content: &str| {
        engine
            .render_str(content, &context)
            .map_err(|e| guisu_core::Error::Message(format!("Template rendering error: {e}")))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper to create a basic test directory with hooks
    fn setup_hooks_test_env() -> (TempDir, Config) {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // Create hooks directory structure
        let hooks_dir = source_dir.hooks_dir();
        fs::create_dir_all(hooks_dir.join("pre")).unwrap();
        fs::create_dir_all(hooks_dir.join("post")).unwrap();

        // Create pre hooks
        fs::write(
            hooks_dir.join("pre/10-setup.toml"),
            r#"
name = "setup"
cmd = "echo setup"
order = 10
"#,
        )
        .unwrap();

        fs::write(
            hooks_dir.join("pre/20-install.toml"),
            r#"
name = "install"
cmd = "echo install"
order = 20
"#,
        )
        .unwrap();

        // Create post hooks
        fs::write(
            hooks_dir.join("post/90-cleanup.toml"),
            r#"
name = "cleanup"
cmd = "echo cleanup"
order = 90
"#,
        )
        .unwrap();

        let config = Config::default();
        (temp, config)
    }

    #[test]
    fn test_run_list_no_hooks_directory() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();
        let config = Config::default();

        // No .guisu/hooks directory
        let result = run_list(source_dir, &config, "simple");
        assert!(result.is_ok(), "Should succeed with no hooks directory");
    }

    #[test]
    fn test_run_list_empty_hooks() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        // Create empty hooks directory
        let hooks_dir = source_dir.hooks_dir();
        fs::create_dir_all(hooks_dir.join("pre")).unwrap();
        fs::create_dir_all(hooks_dir.join("post")).unwrap();

        let config = Config::default();

        let result = run_list(source_dir, &config, "simple");
        assert!(result.is_ok(), "Should handle empty hooks directory");
    }

    #[test]
    fn test_run_list_simple_format() {
        let (temp, config) = setup_hooks_test_env();
        let source_dir = temp.path();

        let result = run_list(source_dir, &config, "simple");
        assert!(
            result.is_ok(),
            "Should list hooks in simple format: {result:?}"
        );
    }

    #[test]
    fn test_run_list_json_format() {
        let (temp, config) = setup_hooks_test_env();
        let source_dir = temp.path();

        let result = run_list(source_dir, &config, "json");
        assert!(
            result.is_ok(),
            "Should list hooks in JSON format: {result:?}"
        );
    }

    #[test]
    fn test_run_list_with_platform_filtering() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let hooks_dir = source_dir.hooks_dir();
        fs::create_dir_all(hooks_dir.join("pre")).unwrap();

        // Create hook that only runs on Linux
        fs::write(
            hooks_dir.join("pre/linux-only.toml"),
            r#"
name = "linux-only"
cmd = "echo linux"
platforms = ["linux"]
"#,
        )
        .unwrap();

        // Create hook that runs on all platforms
        fs::write(
            hooks_dir.join("pre/all-platforms.toml"),
            r#"
name = "all-platforms"
cmd = "echo all"
"#,
        )
        .unwrap();

        let config = Config::default();

        // Both formats should handle platform filtering
        let result_simple = run_list(source_dir, &config, "simple");
        assert!(
            result_simple.is_ok(),
            "Simple format should handle platform filtering"
        );

        let result_json = run_list(source_dir, &config, "json");
        assert!(
            result_json.is_ok(),
            "JSON format should handle platform filtering"
        );
    }

    #[test]
    fn test_run_list_with_multiple_hooks() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let hooks_dir = source_dir.hooks_dir();
        fs::create_dir_all(hooks_dir.join("pre")).unwrap();
        fs::create_dir_all(hooks_dir.join("post")).unwrap();

        // Create multiple pre hooks
        for i in 1..=5 {
            fs::write(
                hooks_dir.join(format!("pre/hook{i}.toml")),
                format!(
                    r#"
name = "hook{}"
cmd = "echo {}"
order = {}
"#,
                    i,
                    i,
                    i * 10
                ),
            )
            .unwrap();
        }

        // Create multiple post hooks
        for i in 1..=3 {
            fs::write(
                hooks_dir.join(format!("post/post{i}.toml")),
                format!(
                    r#"
name = "post{}"
cmd = "echo post {}"
order = {}
"#,
                    i,
                    i,
                    i * 10
                ),
            )
            .unwrap();
        }

        let config = Config::default();

        let result = run_list(source_dir, &config, "json");
        assert!(result.is_ok(), "Should handle multiple hooks");
    }

    #[test]
    fn test_run_list_with_invalid_toml() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path();

        let hooks_dir = source_dir.hooks_dir();
        fs::create_dir_all(hooks_dir.join("pre")).unwrap();

        // Create invalid TOML file
        fs::write(hooks_dir.join("pre/invalid.toml"), "invalid toml {{{").unwrap();

        let config = Config::default();

        let result = run_list(source_dir, &config, "simple");
        assert!(result.is_err(), "Should fail with invalid TOML");
    }

    #[test]
    fn test_run_list_unknown_format() {
        let (temp, config) = setup_hooks_test_env();
        let source_dir = temp.path();

        // Unknown format should default to simple format
        let result = run_list(source_dir, &config, "unknown");
        assert!(
            result.is_ok(),
            "Should default to simple format for unknown format"
        );
    }
}
