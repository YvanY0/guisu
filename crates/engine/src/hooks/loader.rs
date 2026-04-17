//! Hook discovery and loading
//!
//! Loads hook definitions from the .guisu/hooks directory structure.

use super::config::{Hook, HookCollections, HookMode};
use super::types::HookName;
use guisu_core::{Error, Result};
use indexmap::IndexMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Discover and load hooks from the hooks directory
pub struct HookLoader {
    hooks_dir: PathBuf,
}

impl HookLoader {
    /// Create a new hook loader for the given source directory
    #[must_use]
    pub fn new(source_dir: &Path) -> Self {
        Self {
            hooks_dir: source_dir.join(".guisu/hooks"),
        }
    }

    /// Check if hooks directory exists
    #[must_use]
    pub fn exists(&self) -> bool {
        self.hooks_dir.exists()
    }

    /// Load all hooks from the hooks directory
    ///
    /// # Errors
    ///
    /// Returns an error if hook loading fails (e.g., invalid TOML syntax, I/O error, validation failure)
    pub fn load(&self) -> Result<HookCollections> {
        if !self.hooks_dir.exists() {
            tracing::debug!(
                "Hooks directory does not exist: {}",
                self.hooks_dir.display()
            );
            return Ok(HookCollections::default());
        }

        let mut collections = HookCollections::default();

        // Load pre hooks
        let pre_dir = self.hooks_dir.join("pre");
        if pre_dir.exists() {
            collections.pre = self
                .load_hooks_from_dir(&pre_dir)
                .map_err(|e| Error::HookConfig(format!("Failed to load pre hooks: {e}")))?;
        }

        // Load post hooks
        let post_dir = self.hooks_dir.join("post");
        if post_dir.exists() {
            collections.post = self
                .load_hooks_from_dir(&post_dir)
                .map_err(|e| Error::HookConfig(format!("Failed to load post hooks: {e}")))?;
        }

        Ok(collections)
    }

    /// Load hooks from a specific directory (pre or post)
    fn load_hooks_from_dir(&self, dir: &Path) -> Result<Vec<Hook>> {
        use rayon::prelude::*;

        // First pass: Collect and sort file paths (must be sequential)
        let mut file_paths: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|e| {
                Error::HookConfig(format!("Failed to read directory {}: {}", dir.display(), e))
            })?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().is_file())
            .map(|e| e.path())
            .filter(|path| {
                // Skip hidden files and editor backups
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    !file_name.starts_with('.')
                        && !file_name.ends_with('~')
                        && !file_name.to_lowercase().ends_with(".swp")
                } else {
                    false
                }
            })
            .collect();

        // Sort by filename for consistent ordering (important for numeric prefixes)
        file_paths.sort();

        // Second pass: Parallel file loading and parsing
        // Each file gets an order value based on its position (0, 10, 20, 30...)
        let hooks_result: Result<Vec<Vec<Hook>>> = file_paths
            .par_iter()
            .enumerate()
            .map(|(idx, path)| {
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let base_order = (idx * 10) as i32;
                tracing::debug!(
                    "Loading hook file: {} (order: {})",
                    path.display(),
                    base_order
                );
                self.load_hook_file(path, base_order)
            })
            .collect();

        // Flatten results into single vector
        let hooks = hooks_result?.into_iter().flatten().collect();

        Ok(hooks)
    }

    /// Load hooks from a single file
    fn load_hook_file(&self, path: &Path, base_order: i32) -> Result<Vec<Hook>> {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Get the extension
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Configuration files - parse and load hooks
        if ext == "toml" {
            return self.load_toml_hooks(path, base_order);
        }

        // Check if file is executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(path) {
                let permissions = metadata.permissions();
                if permissions.mode() & 0o111 != 0 {
                    // Read script content for diffing
                    let script_content = fs::read_to_string(path).ok();

                    // File is executable - create hook
                    let hook = Hook {
                        name: HookName::new(file_name.to_string())?,
                        order: base_order,
                        platforms: vec![],
                        cmd: Some(path.to_string_lossy().to_string()),
                        script: None,
                        script_content,
                        env: IndexMap::default(),
                        failfast: true,
                        mode: HookMode::default(),
                        timeout: 0, // No timeout by default
                    };
                    return Ok(vec![hook]);
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, skip executable check
            tracing::warn!(
                "Executable check not supported on this platform: {}",
                path.display()
            );
        }

        tracing::warn!("Skipping non-executable file: {}", path.display());
        Ok(vec![])
    }

    /// Load hooks from TOML file
    fn load_toml_hooks(&self, path: &Path, base_order: i32) -> Result<Vec<Hook>> {
        let content = fs::read_to_string(path).map_err(|e| {
            Error::HookConfig(format!(
                "Failed to read TOML file {}: {}",
                path.display(),
                e
            ))
        })?;

        // Parse as raw TOML value to check if order field exists
        let toml_value: toml::Value = toml::from_str(&content).map_err(|e| {
            Error::HookConfig(format!(
                "Failed to parse TOML from {}: {}",
                path.display(),
                e
            ))
        })?;

        // Try to parse as array of hooks first
        if let Ok(mut hooks) = toml::from_str::<Vec<Hook>>(&content) {
            // Check if order was explicitly set in TOML
            if let toml::Value::Array(arr) = &toml_value {
                for (idx, hook) in hooks.iter_mut().enumerate() {
                    if let Some(toml::Value::Table(table)) = arr.get(idx) {
                        // Only use base_order if 'order' field is not present in TOML
                        if !table.contains_key("order") {
                            hook.order = base_order;
                        }
                    }
                    self.resolve_script_path(hook, path)?;
                }
            }
            return Ok(hooks);
        }

        // Try to parse as single hook
        if let Ok(mut hook) = toml::from_str::<Hook>(&content) {
            // Only use base_order if 'order' field is not present in TOML
            if let toml::Value::Table(table) = &toml_value
                && !table.contains_key("order")
            {
                hook.order = base_order;
            }
            // Resolve script path relative to hook file directory
            self.resolve_script_path(&mut hook, path)?;
            return Ok(vec![hook]);
        }

        Err(Error::HookConfig(format!(
            "Failed to parse TOML hooks from: {}",
            path.display()
        )))
    }

    /// Resolve script path relative to hook file directory
    ///
    /// This function supports automatic .j2 template detection:
    /// - If script = "script.sh.j2", uses it directly as a template
    /// - If script = "script.sh" and "script.sh.j2" exists, uses the template version
    /// - Otherwise, uses the specified path as-is
    fn resolve_script_path(&self, hook: &mut Hook, hook_file_path: &Path) -> Result<()> {
        if let Some(script) = &hook.script {
            // Skip absolute paths
            if script.starts_with('/') {
                return Ok(());
            }

            // Get hook file directory
            let hook_dir = hook_file_path.parent().ok_or_else(|| {
                Error::HookConfig(format!(
                    "Cannot get parent directory of hook file: {}",
                    hook_file_path.display()
                ))
            })?;

            // Resolve script path relative to hook directory
            let script_abs = hook_dir.join(script);

            // Auto-detect .j2 template version
            let final_script_abs = if script.to_lowercase().ends_with(".j2") {
                // Explicitly specified as template
                script_abs
            } else {
                // Check if .j2 version exists
                let template_version = hook_dir.join(format!("{script}.j2"));
                if template_version.exists() {
                    tracing::debug!(
                        "Auto-detected template version: {} -> {}",
                        script,
                        template_version.display()
                    );
                    template_version
                } else {
                    // Use original path
                    script_abs
                }
            };

            // Get source directory (.guisu/hooks -> .guisu -> source_dir)
            let source_dir = self
                .hooks_dir
                .parent()
                .and_then(|p| p.parent())
                .ok_or_else(|| {
                    Error::HookConfig(format!(
                        "Cannot determine source directory from hooks dir: {}",
                        self.hooks_dir.display()
                    ))
                })?;

            // Convert to relative path from source_dir
            let script_rel = final_script_abs.strip_prefix(source_dir).map_err(|_| {
                Error::HookConfig(format!(
                    "Script path is outside source directory: {}",
                    final_script_abs.display()
                ))
            })?;

            hook.script = Some(script_rel.display().to_string());

            // Read and store script content for diffing
            if final_script_abs.exists() {
                if let Ok(content) = fs::read_to_string(&final_script_abs) {
                    hook.script_content = Some(content);
                } else {
                    tracing::warn!(
                        "Failed to read script content for diffing: {}",
                        final_script_abs.display()
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_hooks_dir_structure(source_dir: &Path) -> PathBuf {
        let hooks_dir = source_dir.join(".guisu/hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        hooks_dir
    }

    #[test]
    fn test_hook_loader_new() {
        let temp = TempDir::new().unwrap();
        let loader = HookLoader::new(temp.path());

        assert_eq!(loader.hooks_dir, temp.path().join(".guisu/hooks"));
    }

    #[test]
    fn test_exists_no_directory() {
        let temp = TempDir::new().unwrap();
        let loader = HookLoader::new(temp.path());

        assert!(!loader.exists());
    }

    #[test]
    fn test_exists_with_directory() {
        let temp = TempDir::new().unwrap();
        create_hooks_dir_structure(temp.path());
        let loader = HookLoader::new(temp.path());

        assert!(loader.exists());
    }

    #[test]
    fn test_load_no_hooks_directory() {
        let temp = TempDir::new().unwrap();
        let loader = HookLoader::new(temp.path());

        let result = loader.load().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_empty_hooks_directory() {
        let temp = TempDir::new().unwrap();
        create_hooks_dir_structure(temp.path());
        let loader = HookLoader::new(temp.path());

        let result = loader.load().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_toml_single_hook() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        let toml_content = r#"
name = "test-hook"
cmd = "echo test"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].name.as_str(), "test-hook");
        assert_eq!(result.pre[0].cmd, Some("echo test".to_string()));
    }

    #[test]
    fn test_load_toml_hooks_in_order() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let post_dir = hooks_dir.join("post");
        fs::create_dir_all(&post_dir).unwrap();

        // Create multiple TOML files with numeric prefixes, each with a single hook
        fs::write(
            post_dir.join("01-hook1.toml"),
            "name = 'hook1'\ncmd = 'echo 1'",
        )
        .unwrap();
        fs::write(
            post_dir.join("02-hook2.toml"),
            "name = 'hook2'\ncmd = 'echo 2'",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.post.len(), 2);
        assert_eq!(result.post[0].name.as_str(), "hook1");
        assert_eq!(result.post[1].name.as_str(), "hook2");
    }

    #[test]
    fn test_load_skips_hidden_files() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create hidden file
        fs::write(
            pre_dir.join(".hidden.toml"),
            "name = 'hidden'\ncmd = 'test'",
        )
        .unwrap();

        // Create normal file
        fs::write(
            pre_dir.join("visible.toml"),
            "name = 'visible'\ncmd = 'test'",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        // Should only load the visible file
        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].name.as_str(), "visible");
    }

    #[test]
    fn test_load_skips_backup_files() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create backup files
        fs::write(pre_dir.join("hook.toml~"), "name = 'backup'\ncmd = 'test'").unwrap();
        fs::write(pre_dir.join("hook.toml.swp"), "name = 'swp'\ncmd = 'test'").unwrap();

        // Create normal file
        fs::write(pre_dir.join("hook.toml"), "name = 'normal'\ncmd = 'test'").unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        // Should only load the normal file
        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].name.as_str(), "normal");
    }

    #[test]
    fn test_load_pre_and_post_hooks() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());

        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::write(
            pre_dir.join("pre-hook.toml"),
            "name = 'pre'\ncmd = 'echo pre'",
        )
        .unwrap();

        let post_dir = hooks_dir.join("post");
        fs::create_dir_all(&post_dir).unwrap();
        fs::write(
            post_dir.join("post-hook.toml"),
            "name = 'post'\ncmd = 'echo post'",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.post.len(), 1);
        assert_eq!(result.pre[0].name.as_str(), "pre");
        assert_eq!(result.post[0].name.as_str(), "post");
    }

    #[test]
    fn test_load_ordering_by_filename() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create files in non-alphabetical order
        fs::write(
            pre_dir.join("30-third.toml"),
            "name = 'third'\ncmd = 'echo 3'",
        )
        .unwrap();
        fs::write(
            pre_dir.join("10-first.toml"),
            "name = 'first'\ncmd = 'echo 1'",
        )
        .unwrap();
        fs::write(
            pre_dir.join("20-second.toml"),
            "name = 'second'\ncmd = 'echo 2'",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 3);
        // Should be sorted by filename
        assert_eq!(result.pre[0].name.as_str(), "first");
        assert_eq!(result.pre[1].name.as_str(), "second");
        assert_eq!(result.pre[2].name.as_str(), "third");
    }

    #[test]
    fn test_load_assigns_order_based_on_position() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        fs::write(pre_dir.join("a.toml"), "name = 'a'\ncmd = 'echo a'").unwrap();
        fs::write(pre_dir.join("b.toml"), "name = 'b'\ncmd = 'echo b'").unwrap();
        fs::write(pre_dir.join("c.toml"), "name = 'c'\ncmd = 'echo c'").unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        // Order should be 0, 10, 20, 30...
        assert_eq!(result.pre[0].order, 0);
        assert_eq!(result.pre[1].order, 10);
        assert_eq!(result.pre[2].order, 20);
    }

    #[test]
    fn test_load_toml_invalid_syntax() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        fs::write(pre_dir.join("invalid.toml"), "invalid toml [[").unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load();

        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_script_path_relative() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create script file
        let script_path = pre_dir.join("install.sh");
        fs::write(&script_path, "#!/bin/bash\necho installing").unwrap();

        // Create TOML with relative script path
        let toml_content = r#"
name = "installer"
script = "install.sh"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        // Script path should be resolved relative to source_dir
        assert!(result.pre[0].script.is_some());
        let script = result.pre[0].script.as_ref().unwrap();
        assert!(script.contains("install.sh"));
    }

    #[test]
    fn test_resolve_script_path_absolute() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create TOML with absolute script path
        let toml_content = r#"
name = "system-hook"
script = "/usr/local/bin/some-script.sh"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        // Absolute path should remain unchanged
        assert_eq!(
            result.pre[0].script,
            Some("/usr/local/bin/some-script.sh".to_string())
        );
    }

    #[test]
    fn test_auto_detect_j2_template() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create both script and template version
        fs::write(pre_dir.join("script.sh"), "#!/bin/bash\necho normal").unwrap();
        fs::write(pre_dir.join("script.sh.j2"), "#!/bin/bash\necho {{ var }}").unwrap();

        // Reference without .j2
        let toml_content = r#"
name = "templated"
script = "script.sh"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        // Should auto-detect and use .j2 version
        let script = result.pre[0].script.as_ref().unwrap();
        assert!(script.ends_with("script.sh.j2"));
    }

    #[test]
    fn test_explicit_j2_template() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        fs::write(
            pre_dir.join("template.sh.j2"),
            "#!/bin/bash\necho {{ var }}",
        )
        .unwrap();

        // Explicitly reference .j2
        let toml_content = r#"
name = "explicit-template"
script = "template.sh.j2"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        let script = result.pre[0].script.as_ref().unwrap();
        assert!(script.ends_with("template.sh.j2"));
    }

    #[test]
    fn test_script_content_loaded() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        let script_content = "#!/bin/bash\necho test content";
        fs::write(pre_dir.join("script.sh"), script_content).unwrap();

        let toml_content = r#"
name = "content-test"
script = "script.sh"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(
            result.pre[0].script_content,
            Some(script_content.to_string())
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_load_executable_file_as_hook() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create executable script
        let script_path = pre_dir.join("executable.sh");
        fs::write(&script_path, "#!/bin/bash\necho executable").unwrap();

        // Make it executable
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].name.as_str(), "executable.sh");
        assert!(result.pre[0].cmd.is_some());
    }

    #[test]
    #[cfg(unix)]
    fn test_skip_non_executable_file() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        // Create non-executable script
        let script_path = pre_dir.join("not-executable.sh");
        fs::write(&script_path, "#!/bin/bash\necho test").unwrap();
        // Don't set executable permission

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        // Should be skipped
        assert_eq!(result.pre.len(), 0);
    }

    #[test]
    fn test_load_multiple_toml_files() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        fs::write(pre_dir.join("first.toml"), "name = 'first'\ncmd = 'echo 1'").unwrap();
        fs::write(
            pre_dir.join("second.toml"),
            "name = 'second'\ncmd = 'echo 2'",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 2);
    }

    #[test]
    fn test_hook_mode_preserved() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        let toml_content = r#"
name = "once-hook"
cmd = "echo once"
mode = "once"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].mode, HookMode::Once);
    }

    #[test]
    fn test_hook_platforms_preserved() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        let toml_content = r#"
name = "platform-hook"
cmd = "echo platform"
platforms = ["darwin", "linux"]
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(
            result.pre[0].platforms,
            vec!["darwin".to_string(), "linux".to_string()]
        );
    }

    #[test]
    fn test_hook_env_preserved() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        let toml_content = r#"
name = "env-hook"
cmd = "echo $VAR"

[env]
VAR = "value"
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].env.get("VAR"), Some(&"value".to_string()));
    }

    #[test]
    fn test_hook_timeout_preserved() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        let toml_content = r#"
name = "timeout-hook"
cmd = "sleep 10"
timeout = 5
"#;
        fs::write(pre_dir.join("hook.toml"), toml_content).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].timeout, 5);
    }

    #[test]
    fn test_empty_pre_and_post_directories() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());

        // Create empty pre and post directories
        fs::create_dir_all(hooks_dir.join("pre")).unwrap();
        fs::create_dir_all(hooks_dir.join("post")).unwrap();

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert!(result.pre.is_empty());
        assert!(result.post.is_empty());
    }

    #[test]
    fn test_load_only_pre_hooks() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        fs::write(pre_dir.join("hook.toml"), "name = 'pre'\ncmd = 'echo pre'").unwrap();
        // Don't create post directory

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.post.len(), 0);
    }

    #[test]
    fn test_load_only_post_hooks() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let post_dir = hooks_dir.join("post");
        fs::create_dir_all(&post_dir).unwrap();

        fs::write(
            post_dir.join("hook.toml"),
            "name = 'post'\ncmd = 'echo post'",
        )
        .unwrap();
        // Don't create pre directory

        let loader = HookLoader::new(temp.path());
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 0);
        assert_eq!(result.post.len(), 1);
    }
}
