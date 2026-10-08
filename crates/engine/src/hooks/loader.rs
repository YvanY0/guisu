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
    /// Current platform (e.g. `"linux"`, `"darwin"`); used to resolve
    /// platform-specific script overrides under `scripts/{platform}/`.
    platform: String,
}

impl HookLoader {
    /// Create a new hook loader for the given source directory and platform.
    ///
    /// A hook that declares `platforms` resolves its script under
    /// `scripts/{platform}/` only (see [`Self::resolve_script_path`]);
    /// pass `""` to disable that (used by unit tests).
    #[must_use]
    pub fn new(source_dir: &Path, platform: &str) -> Self {
        Self {
            hooks_dir: source_dir.join(".guisu/hooks"),
            platform: platform.to_string(),
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

    /// Resolve script path relative to hook file directory.
    ///
    /// The `.j2` suffix is stripped to get the logical name, then the
    /// directory is probed for `{logical}.j2` first, else `{logical}`.
    /// Hooks declaring `platforms` probe `scripts/{platform}/` only
    /// (missing script = error; other platforms are skipped before
    /// resolution); hooks without `platforms` probe `scripts/` only.
    /// Full rules: docs/user-guide/hooks.md.
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

            // Strip an explicit `.j2` suffix to get the logical name.
            let script_rel = Path::new(script);
            let rel_dir = script_rel
                .parent()
                .ok_or_else(|| Error::HookConfig(format!("Invalid script path: {script}")))?;
            let raw_name = script_rel
                .file_name()
                .ok_or_else(|| Error::HookConfig(format!("Invalid script path: {script}")))?;
            let raw_name = raw_name.to_string_lossy();
            let logical_name = if raw_name.to_lowercase().ends_with(".j2") {
                &raw_name[..raw_name.len() - 3]
            } else {
                &raw_name
            };

            // Probe one candidate directory: prefer the adjacent `.j2`
            // template version if it exists, else the plain path.
            let probe = |candidate: &Path| -> PathBuf {
                let template = candidate.with_file_name(format!("{logical_name}.j2"));
                if template.exists() {
                    template
                } else {
                    candidate.to_path_buf()
                }
            };

            let base_candidate = hook_dir.join(rel_dir).join(logical_name);

            // Probing is directory-symmetric: prefer the adjacent `.j2`
            // template if it exists, else the plain path. Which directory
            // is probed depends solely on the hook's `platforms` field:
            // hooks that declare platforms resolve inside the platform
            // directory (no fallback to the shared base path); hooks
            // without `platforms` are platform-agnostic and resolve in
            // the base directory.
            let final_script_abs = if hook.platforms.is_empty() {
                probe(&base_candidate)
            } else if !hook.platforms.iter().any(|p| p == &self.platform) {
                // Not runnable on this machine; the executor filters the
                // hook out, so skip script resolution entirely.
                tracing::debug!(
                    "Hook '{}' declares platforms {:?}; skipping script resolution on '{}'",
                    hook.name,
                    hook.platforms,
                    self.platform
                );
                return Ok(());
            } else {
                let platform_candidate = inject_platform_subdir(&base_candidate, &self.platform)
                    .ok_or_else(|| {
                        Error::HookConfig(format!(
                            "Cannot build platform script path for hook '{}' (script: {script})",
                            hook.name
                        ))
                    })?;
                let platform_resolved = probe(&platform_candidate);
                if platform_resolved.exists() {
                    tracing::debug!(
                        "Using platform-specific script: {} -> {}",
                        script,
                        platform_resolved.display()
                    );
                    platform_resolved
                } else {
                    return Err(Error::HookConfig(format!(
                        "Hook '{}' declares platforms {:?} but no script exists for platform '{}': expected {} or {} next to the hook file",
                        hook.name,
                        hook.platforms,
                        self.platform,
                        platform_candidate.display(),
                        platform_candidate
                            .with_file_name(format!("{logical_name}.j2"))
                            .display(),
                    )));
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

/// Inject a platform subdirectory segment into a script path.
///
/// Transforms the logical candidate `scripts/foo.sh` into
/// `scripts/linux/foo.sh`. The input is the logical path (any explicit
/// `.j2` suffix already stripped), so callers only ever inject once.
/// Returns `None` if the input has no parent directory (e.g. a bare
/// filename), since there is nowhere to insert the platform segment.
///
/// Platform names containing path separators or `..` are rejected to
/// prevent path traversal: a malicious TOML cannot escape the script
/// root via this mechanism.
fn inject_platform_subdir(script_path: &Path, platform: &str) -> Option<PathBuf> {
    if platform.is_empty()
        || platform.contains('/')
        || platform.contains('\\')
        || platform.contains("..")
    {
        return None;
    }
    let parent = script_path.parent()?;
    let file_name = script_path.file_name()?;
    Some(parent.join(platform).join(file_name))
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
        let loader = HookLoader::new(temp.path(), "linux");

        assert_eq!(loader.hooks_dir, temp.path().join(".guisu/hooks"));
    }

    #[test]
    fn test_exists_no_directory() {
        let temp = TempDir::new().unwrap();
        let loader = HookLoader::new(temp.path(), "linux");

        assert!(!loader.exists());
    }

    #[test]
    fn test_exists_with_directory() {
        let temp = TempDir::new().unwrap();
        create_hooks_dir_structure(temp.path());
        let loader = HookLoader::new(temp.path(), "linux");

        assert!(loader.exists());
    }

    #[test]
    fn test_load_no_hooks_directory() {
        let temp = TempDir::new().unwrap();
        let loader = HookLoader::new(temp.path(), "linux");

        let result = loader.load().unwrap();
        assert_eq!(result.pre.len() + result.post.len(), 0);
    }

    #[test]
    fn test_load_empty_hooks_directory() {
        let temp = TempDir::new().unwrap();
        create_hooks_dir_structure(temp.path());
        let loader = HookLoader::new(temp.path(), "linux");

        let result = loader.load().unwrap();
        assert_eq!(result.pre.len() + result.post.len(), 0);
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 0);
        assert_eq!(result.post.len(), 0);
    }

    #[test]
    fn test_load_only_pre_hooks() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        fs::create_dir_all(&pre_dir).unwrap();

        fs::write(pre_dir.join("hook.toml"), "name = 'pre'\ncmd = 'echo pre'").unwrap();
        // Don't create post directory

        let loader = HookLoader::new(temp.path(), "linux");
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

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 0);
        assert_eq!(result.post.len(), 1);
    }

    // ── Platform-specific script resolution ────────────────────────
    //
    // The loader should look for `scripts/{platform}/foo.sh` before
    // falling back to `scripts/foo.sh`. Mirrors the chezmoi convention
    // of `run_*` scripts under `.chezmoiscripts/{linux,darwin}/`.

    #[test]
    fn test_platform_specific_script_overrides_default() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(scripts_dir.join("linux")).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install.sh.j2'\nplatforms = ['linux']\n",
        )
        .unwrap();
        // Both versions exist; the linux one should win on linux.
        fs::write(scripts_dir.join("install.sh.j2"), "default\n").unwrap();
        fs::write(scripts_dir.join("linux").join("install.sh.j2"), "linux\n").unwrap();

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert!(
            result.pre[0]
                .script
                .as_deref()
                .unwrap()
                .ends_with("scripts/linux/install.sh.j2"),
            "linux script should win, got {:?}",
            result.pre[0].script,
        );
        assert_eq!(result.pre[0].script_content.as_deref().unwrap(), "linux\n",);
    }

    #[test]
    fn test_platform_hook_without_platform_script_is_an_error() {
        // Hooks that declare `platforms` must provide the script inside
        // the platform directory — the shared base path is NOT a
        // fallback.
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(&scripts_dir).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install.sh'\nplatforms = ['linux']\n",
        )
        .unwrap();
        // Only the shared base script exists; loading must fail.
        fs::write(scripts_dir.join("install.sh"), "default\n").unwrap();

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load();

        let err = result.expect_err("missing platform script should be an error");
        assert!(
            err.to_string()
                .contains("no script exists for platform 'linux'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_platform_hook_skipped_on_other_platform() {
        // A darwin-only hook on a linux machine is skipped entirely:
        // resolution is skipped (no error for the missing linux script),
        // and the executor filters the hook out.
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(scripts_dir.join("darwin")).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install.sh'\nplatforms = ['darwin']\n",
        )
        .unwrap();
        fs::write(
            scripts_dir.join("darwin").join("install.sh"),
            "#!/bin/sh\necho darwin\n",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert_eq!(result.pre[0].script.as_deref(), Some("scripts/install.sh"));
        assert_eq!(result.pre[0].script_content, None);
    }

    #[test]
    fn test_darwin_loader_picks_darwin_script() {
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(scripts_dir.join("linux")).unwrap();
        fs::create_dir_all(scripts_dir.join("darwin")).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install.sh.j2'\nplatforms = ['linux','darwin']\n",
        )
        .unwrap();
        fs::write(scripts_dir.join("linux").join("install.sh.j2"), "linux\n").unwrap();
        fs::write(scripts_dir.join("darwin").join("install.sh.j2"), "darwin\n").unwrap();

        let loader = HookLoader::new(temp.path(), "darwin");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert!(
            result.pre[0]
                .script
                .as_deref()
                .unwrap()
                .ends_with("scripts/darwin/install.sh.j2"),
            "darwin loader should pick darwin script, got {:?}",
            result.pre[0].script,
        );
        assert_eq!(result.pre[0].script_content.as_deref().unwrap(), "darwin\n",);
    }

    #[test]
    fn test_j2_autodetect_extensionless_script_after_platform_override() {
        // Extensionless scripts must resolve to `install.j2` (not
        // `install..j2`, which `with_extension` would produce), and the
        // lookup must happen next to the platform-overridden path.
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(scripts_dir.join("linux")).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install'\nplatforms = ['linux']\n",
        )
        .unwrap();
        fs::write(
            scripts_dir.join("linux").join("install"),
            "#!/bin/sh\necho linux\n",
        )
        .unwrap();
        fs::write(
            scripts_dir.join("linux").join("install.j2"),
            "echo {{ name }}\n",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert!(
            result.pre[0]
                .script
                .as_deref()
                .unwrap()
                .ends_with("scripts/linux/install.j2"),
            "adjacent .j2 next to the platform override should win, got {:?}",
            result.pre[0].script,
        );
        assert_eq!(
            result.pre[0].script_content.as_deref().unwrap(),
            "echo {{ name }}\n",
        );
    }

    #[test]
    fn test_platform_override_with_j2_only() {
        // Only the platform directory holds a `.j2` template (no plain
        // file): the probe must still hit it and resolve to the template.
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(scripts_dir.join("linux")).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install.sh'\nplatforms = ['linux']\n",
        )
        .unwrap();
        fs::write(
            scripts_dir.join("linux").join("install.sh.j2"),
            "echo {{ name }}\n",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path(), "linux");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert!(
            result.pre[0]
                .script
                .as_deref()
                .unwrap()
                .ends_with("scripts/linux/install.sh.j2"),
            "platform .j2-only override should resolve, got {:?}",
            result.pre[0].script,
        );
        assert_eq!(
            result.pre[0].script_content.as_deref().unwrap(),
            "echo {{ name }}\n",
        );
    }

    #[test]
    fn test_explicit_j2_script_falls_back_to_platform_plain_script() {
        // The TOML names the `.j2` variant but the platform directory
        // only holds the plain script: probing must be identical in both
        // directories, so the platform plain script is used.
        let temp = TempDir::new().unwrap();
        let hooks_dir = create_hooks_dir_structure(temp.path());
        let pre_dir = hooks_dir.join("pre");
        let scripts_dir = pre_dir.join("scripts");
        fs::create_dir_all(&pre_dir).unwrap();
        fs::create_dir_all(scripts_dir.join("darwin")).unwrap();

        fs::write(
            pre_dir.join("01-foo.toml"),
            "name = 'foo'\nscript = 'scripts/install.sh.j2'\nplatforms = ['darwin']\n",
        )
        .unwrap();
        fs::write(
            scripts_dir.join("darwin").join("install.sh"),
            "#!/bin/sh\necho darwin\n",
        )
        .unwrap();

        let loader = HookLoader::new(temp.path(), "darwin");
        let result = loader.load().unwrap();

        assert_eq!(result.pre.len(), 1);
        assert!(
            result.pre[0]
                .script
                .as_deref()
                .unwrap()
                .ends_with("scripts/darwin/install.sh"),
            "platform plain script should win over nonexistent .j2, got {:?}",
            result.pre[0].script,
        );
        assert_eq!(
            result.pre[0].script_content.as_deref().unwrap(),
            "#!/bin/sh\necho darwin\n",
        );
    }

    #[test]
    fn test_inject_platform_subdir_rejects_traversal() {
        // Path-traversal guard: a malicious platform name must not be
        // used to escape the script root.
        assert!(inject_platform_subdir(Path::new("scripts/foo.sh"), "../etc").is_none());
        assert!(inject_platform_subdir(Path::new("scripts/foo.sh"), "foo/bar").is_none());
        assert!(inject_platform_subdir(Path::new("scripts/foo.sh"), "").is_none());
        // Happy path: typical case.
        assert_eq!(
            inject_platform_subdir(Path::new("scripts/foo.sh"), "linux"),
            Some(PathBuf::from("scripts/linux/foo.sh")),
        );
        // Bare filename with no parent segment: parent() returns Some(""),
        // so the result is `linux/foo.sh` (relative to cwd). That's
        // not a security issue, just unusual; we still produce a path
        // so the caller can check existence.
        assert_eq!(
            inject_platform_subdir(Path::new("foo.sh"), "linux"),
            Some(PathBuf::from("linux/foo.sh")),
        );
    }
}
