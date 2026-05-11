//! Hook execution engine
//!
//! Provides parallel hook execution with template rendering support.

use super::config::{Hook, HookCollections, HookMode, HookStage};
use super::env;
use super::script;
use guisu_core::platform::CURRENT_PLATFORM;
use guisu_core::{Error, Result};
use indexmap::IndexMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Result tuple from hook execution: (`cached_hash`, `rendered_content`, `execution_result`)
type HookExecutionResult = (Option<[u8; 32]>, Option<String>, Result<()>);

/// Result from skip check to avoid redundant recomputation
struct SkipCheckResult {
    should_skip: bool,
    reason: &'static str,
    cached_hash: Option<[u8; 32]>,
    rendered_content: Option<String>,
}

/// Template rendering trait for hook scripts
pub trait TemplateRenderer {
    /// Render a template string
    ///
    /// # Errors
    ///
    /// Returns an error if template rendering fails (e.g., syntax error, undefined variable)
    fn render(&self, input: &str) -> Result<String>;
}

/// No-op template renderer (returns input unchanged)
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpRenderer;

impl TemplateRenderer for NoOpRenderer {
    fn render(&self, input: &str) -> Result<String> {
        Ok(input.to_string())
    }
}

/// Implement `TemplateRenderer` for closures
impl<F> TemplateRenderer for F
where
    F: Fn(&str) -> Result<String>,
{
    fn render(&self, input: &str) -> Result<String> {
        self(input)
    }
}

/// Hook execution runner with parallel execution support
///
/// Executes hooks in parallel within each order group, utilizing multi-core CPUs
/// for improved performance. Thread-safe state tracking ensures correct execution
/// for mode=once and mode=onchange hooks.
pub struct HookRunner<'a, R = NoOpRenderer>
where
    R: TemplateRenderer,
{
    collections: &'a HookCollections,
    source_dir: &'a Path,
    /// Shared environment variables (Arc to avoid cloning for each hook)
    env_vars: std::sync::Arc<IndexMap<String, String>>,
    template_renderer: R,
    /// Track which hooks with mode=once have been executed in this session (thread-safe)
    once_executed: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// State from persistent storage (for checking already executed once hooks)
    persistent_once: std::collections::HashSet<String>,
    /// Content hashes for onchange hooks from persistent storage (blake3 hashes, 32 bytes)
    persistent_onchange: std::collections::HashMap<String, [u8; 32]>,
    /// Content hashes for onchange hooks executed in this session (thread-safe, blake3 hashes, 32 bytes)
    onchange_hashes: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>>,
    /// Rendered content for onchange hooks executed in this session (thread-safe)
    onchange_rendered: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

impl<'a> HookRunner<'a, NoOpRenderer> {
    /// Create a new hook runner with no template renderer
    ///
    /// This is a convenience method that immediately builds a runner with default settings.
    /// For custom configuration, use [`HookRunner::builder`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Simple usage - no template rendering needed
    /// let runner = HookRunner::new(&collections, source_dir);
    /// runner.run_stage(HookStage::Pre)?;
    ///
    /// // For custom configuration, use builder:
    /// let runner = HookRunner::builder(&collections, source_dir)
    ///     .template_renderer(my_renderer)
    ///     .build();
    /// ```
    #[must_use]
    pub fn new(collections: &'a HookCollections, source_dir: &'a Path) -> Self {
        Self::builder(collections, source_dir).build()
    }

    /// Create a builder for configuring a `HookRunner`
    ///
    /// This is the primary way to create a `HookRunner` with custom configuration.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let runner = HookRunner::builder(&collections, source_dir)
    ///     .template_renderer(my_renderer)
    ///     .persistent_state(once_executed, onchange_hashes)
    ///     .env("CUSTOM_VAR", "value")
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder(
        collections: &'a HookCollections,
        source_dir: &'a Path,
    ) -> HookRunnerBuilder<'a, NoOpRenderer> {
        HookRunnerBuilder::new(collections, source_dir)
    }
}

impl<R> HookRunner<'_, R>
where
    R: TemplateRenderer + Sync,
{
    /// Get the set of hooks with mode=once that were executed in this session
    ///
    /// This should be saved to persistent state after running hooks
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned (should never happen in normal operation)
    pub fn get_once_executed(&self) -> std::collections::HashSet<String> {
        self.once_executed
            .lock()
            .expect("Once-executed mutex poisoned")
            .clone()
    }

    /// Get the content hashes for hooks with mode=onchange from this session
    ///
    /// This should be saved to persistent state after running hooks
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned (should never happen in normal operation)
    pub fn get_onchange_hashes(&self) -> std::collections::HashMap<String, [u8; 32]> {
        self.onchange_hashes
            .lock()
            .expect("OnChange hashes mutex poisoned")
            .clone()
    }

    /// Get the rendered content for hooks with mode=onchange from this session
    ///
    /// This should be saved to persistent state after running hooks for diff display
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned (should never happen in normal operation)
    pub fn get_onchange_rendered(&self) -> std::collections::HashMap<String, String> {
        self.onchange_rendered
            .lock()
            .expect("OnChange rendered mutex poisoned")
            .clone()
    }

    /// Check if a hook should be skipped based on its mode
    ///
    /// Returns `SkipCheckResult` containing skip decision and cached data for state tracking.
    /// The `cached_hash` and `rendered_content` are only computed for `OnChange` mode to avoid redundant work.
    #[tracing::instrument(skip(self), fields(hook_name = %hook.name, hook_mode = ?hook.mode))]
    fn should_skip_hook(&self, hook: &Hook) -> SkipCheckResult {
        match hook.mode {
            HookMode::Always => {
                tracing::trace!("Hook will run (mode=always)");
                SkipCheckResult {
                    should_skip: false,
                    reason: "",
                    cached_hash: None,
                    rendered_content: None,
                }
            }

            HookMode::Once => {
                if self
                    .once_executed
                    .lock()
                    .expect("Once-executed mutex poisoned")
                    .contains(hook.name.as_str())
                {
                    tracing::debug!("Skipping hook: already executed in this session");
                    return SkipCheckResult {
                        should_skip: true,
                        reason: "already executed in this session (mode=once)",
                        cached_hash: None,
                        rendered_content: None,
                    };
                }

                if self.persistent_once.contains(hook.name.as_str()) {
                    tracing::debug!("Skipping hook: already executed previously");
                    return SkipCheckResult {
                        should_skip: true,
                        reason: "already executed previously (mode=once)",
                        cached_hash: None,
                        rendered_content: None,
                    };
                }

                tracing::trace!("Hook will run (mode=once, first execution)");
                SkipCheckResult {
                    should_skip: false,
                    reason: "",
                    cached_hash: None,
                    rendered_content: None,
                }
            }

            HookMode::OnChange => {
                let content = hook.get_content();
                let content_to_hash = if let Some(script) = &hook.script {
                    if script.to_lowercase().ends_with(".j2") {
                        match self.template_renderer.render(&content) {
                            Ok(rendered) => rendered,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to render template for onchange detection: {}",
                                    e
                                );
                                content
                            }
                        }
                    } else {
                        content
                    }
                } else {
                    content
                };
                let current_hash = crate::hash::hash_content(content_to_hash.as_bytes());

                if let Some(session_hash) = self
                    .onchange_hashes
                    .lock()
                    .expect("OnChange hashes mutex poisoned")
                    .get(hook.name.as_str())
                    && session_hash == &current_hash
                {
                    tracing::debug!("Skipping hook: content unchanged in this session");
                    return SkipCheckResult {
                        should_skip: true,
                        reason: "content unchanged in this session (mode=onchange)",
                        cached_hash: Some(current_hash),
                        rendered_content: Some(content_to_hash.clone()),
                    };
                }

                if let Some(stored_hash) = self.persistent_onchange.get(hook.name.as_str()) {
                    use subtle::ConstantTimeEq;
                    if bool::from(stored_hash.ct_eq(&current_hash)) {
                        tracing::debug!("Skipping hook: content unchanged from previous session");
                        return SkipCheckResult {
                            should_skip: true,
                            reason: "content unchanged (mode=onchange)",
                            cached_hash: Some(current_hash),
                            rendered_content: Some(content_to_hash.clone()),
                        };
                    }
                }

                tracing::trace!("Hook will run (mode=onchange, content changed)");
                SkipCheckResult {
                    should_skip: false,
                    reason: "",
                    cached_hash: Some(current_hash),
                    rendered_content: Some(content_to_hash),
                }
            }
        }
    }

    /// Mark a hook as executed based on its mode
    ///
    /// Accepts a `cached_hash` and `rendered_content` from `should_skip_hook` to avoid redundant work
    fn mark_hook_executed(
        &self,
        hook: &Hook,
        cached_hash: Option<[u8; 32]>,
        rendered_content: Option<String>,
    ) {
        match hook.mode {
            HookMode::Always => {
                // No tracking needed
            }

            HookMode::Once => {
                self.once_executed
                    .lock()
                    .expect("Once-executed mutex poisoned")
                    .insert(hook.name.to_string());
            }

            HookMode::OnChange => {
                // Use cached hash if available, otherwise compute
                let content_hash = cached_hash.unwrap_or_else(|| {
                    let content = hook.get_content();
                    crate::hash::hash_content(content.as_bytes())
                });

                self.onchange_hashes
                    .lock()
                    .expect("OnChange hashes mutex poisoned")
                    .insert(hook.name.to_string(), content_hash);

                // Save rendered content if available (for diff display)
                if let Some(content) = rendered_content {
                    self.onchange_rendered
                        .lock()
                        .expect("OnChange rendered mutex poisoned")
                        .insert(hook.name.to_string(), content);
                }
            }
        }
    }

    /// Run all hooks for a specific stage
    ///
    /// # Errors
    ///
    /// Returns an error if any hook execution fails (e.g., hook script fails, template rendering error, execution timeout)
    #[tracing::instrument(skip(self), fields(stage = %stage.name()))]
    #[allow(clippy::too_many_lines)]
    pub fn run_stage(&self, stage: HookStage) -> Result<()> {
        use rayon::prelude::*;
        use std::collections::BTreeMap;

        let hooks = match stage {
            HookStage::Pre => &self.collections.pre,
            HookStage::Post => &self.collections.post,
        };

        if hooks.is_empty() {
            tracing::debug!("No hooks defined for stage");
            return Ok(());
        }

        tracing::debug!(hook_count = hooks.len(), "Running hooks for stage");

        // Get current platform
        let platform = CURRENT_PLATFORM.os;

        // Filter and validate hooks, then group by order
        // Store skip check results to avoid recomputation in parallel execution phase
        let mut hooks_by_order: BTreeMap<i32, Vec<(&Hook, SkipCheckResult)>> = BTreeMap::new();

        for hook in hooks {
            // Skip if not for this platform
            if !hook.should_run_on(platform) {
                tracing::debug!("Skipping hook '{}' (platform mismatch)", hook.name);
                continue;
            }

            // Check skip status and store result to avoid recomputation
            let skip_result = self.should_skip_hook(hook);
            if skip_result.should_skip {
                tracing::debug!("Skipping hook '{}' ({})", hook.name, skip_result.reason);
                // Save state even for skipped hooks (for diff display)
                self.mark_hook_executed(
                    hook,
                    skip_result.cached_hash,
                    skip_result.rendered_content,
                );
                continue;
            }

            // Validate hook
            if let Err(e) = hook.validate() {
                if hook.failfast {
                    return Err(e);
                }
                tracing::warn!("Invalid hook '{}': {}", hook.name, e);
                continue;
            }

            hooks_by_order
                .entry(hook.order)
                .or_default()
                .push((hook, skip_result));
        }

        // Execute hooks in order, parallelizing within each order group
        for (order, order_hooks) in hooks_by_order {
            tracing::debug!(
                order = order,
                count = order_hooks.len(),
                "Executing hooks in parallel for order group"
            );

            // Parallel execution within same order group
            // Skip results are reused from filtering phase to avoid redundant hash/template work
            let results: Vec<HookExecutionResult> = order_hooks
                .par_iter()
                .map(|(hook, skip_result)| {
                    // Reuse cached hash and rendered content from skip check
                    let cached_hash = skip_result.cached_hash;
                    let rendered_content = skip_result.rendered_content.clone();

                    // Create a span for this hook execution with structured fields
                    let span = tracing::info_span!(
                        "hook_execution",
                        hook_name = %hook.name,
                        hook_order = hook.order,
                        hook_mode = ?hook.mode,
                        timeout = hook.timeout,
                        failfast = hook.failfast,
                    );
                    let _guard = span.enter();

                    let start = std::time::Instant::now();
                    tracing::debug!("Starting hook execution");

                    // Execute hook
                    let result = self.execute_hook(hook);

                    let elapsed = start.elapsed();
                    match &result {
                        Ok(()) => {
                            tracing::debug!(
                                elapsed_ms = elapsed.as_millis(),
                                "Hook completed successfully"
                            );
                        }
                        Err(e) => {
                            if hook.failfast {
                                tracing::error!(
                                    elapsed_ms = elapsed.as_millis(),
                                    error = %e,
                                    "Hook failed"
                                );
                            } else {
                                tracing::warn!(
                                    elapsed_ms = elapsed.as_millis(),
                                    error = %e,
                                    "Hook failed but continuing (failfast=false)"
                                );
                            }
                        }
                    }

                    (cached_hash, rendered_content, result)
                })
                .collect();

            // Process results: mark hooks as executed and check for errors
            for ((cached_hash, rendered_content, result), (hook, _skip_result)) in
                results.into_iter().zip(order_hooks.iter())
            {
                match result {
                    Ok(()) => {
                        // Mark hook as executed based on mode (with cached hash and rendered content)
                        self.mark_hook_executed(hook, cached_hash, rendered_content);
                    }
                    Err(e) => {
                        if hook.failfast {
                            // Fail-fast: return first error
                            return Err(Error::HookExecution(format!(
                                "Hook '{}' failed: {}",
                                hook.name, e
                            )));
                        }
                        // Still mark as executed for non-failfast hooks
                        self.mark_hook_executed(hook, cached_hash, rendered_content);
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute a single hook
    fn execute_hook(&self, hook: &Hook) -> Result<()> {
        // If hook uses 'script' and is a template (.j2 extension), process it specially
        if let Some(script) = &hook.script
            && script.to_lowercase().ends_with(".j2")
        {
            return self.execute_template_script(hook);
        }

        // Determine working directory
        // Working directory is always source_dir
        let working_dir = self.source_dir.to_path_buf();

        // Build environment variables (only clone if hook has custom env)
        let env = if hook.env.is_empty() {
            // No custom env vars, use shared Arc (just increment refcount)
            self.env_vars.clone()
        } else {
            // Clone-on-write: only allocate when hook has custom env vars
            let mut env = (*self.env_vars).clone();
            for (k, v) in &hook.env {
                let expanded_value = env::expand_env_vars(v, &self.env_vars);
                env.insert(k.clone(), expanded_value.into_owned());
            }
            std::sync::Arc::new(env)
        };

        // Execute based on hook type
        match (&hook.cmd, &hook.script) {
            (Some(cmd), None) => {
                // Direct command execution (no shell)
                self.execute_command(cmd, &working_dir, &env, hook.timeout)
                    .map_err(|e| {
                        Error::HookExecution(format!("Hook '{}' command failed: {}", hook.name, e))
                    })
            }
            (None, Some(script_path)) => {
                // Script execution via shebang
                let script_abs = if script_path.starts_with('/') {
                    PathBuf::from(script_path)
                } else {
                    self.source_dir.join(script_path)
                };
                script::execute_script(&script_abs, &working_dir, &env, hook.timeout).map_err(|e| {
                    Error::HookExecution(format!(
                        "Hook '{}' script '{}' failed: {}",
                        hook.name, script_path, e
                    ))
                })
            }
            (None, None) => Err(Error::HookExecution(format!(
                "Hook '{}' has neither cmd nor script (validation should have caught this)",
                hook.name
            ))),
            (Some(_), Some(_)) => {
                // This should be impossible due to validation
                unreachable!(
                    "Hook '{}' validation ensures only cmd or script, not both",
                    hook.name
                )
            }
        }
    }

    /// Execute a command directly without shell
    ///
    /// Parses the command string into program and arguments, then executes
    /// without invoking a shell. This prevents shell injection vulnerabilities.
    ///
    /// Supports quoted arguments: `git commit -m "Initial commit"`
    #[tracing::instrument(skip(self, env), fields(cmd = %cmd, working_dir = %working_dir.display(), timeout))]
    fn execute_command(
        &self,
        cmd: &str,
        working_dir: &Path,
        env: &IndexMap<String, String>,
        timeout: u64,
    ) -> Result<()> {
        use std::time::Duration;

        // Expand environment variables in command
        let expanded_cmd = env::expand_env_vars(cmd, &self.env_vars);

        // Parse command using shell-words for proper quote handling
        // Handles: git commit -m "Initial commit" → ["git", "commit", "-m", "Initial commit"]
        let parts = shell_words::split(&expanded_cmd)
            .map_err(|e| Error::HookExecution(format!("Failed to parse command '{cmd}': {e}")))?;

        if parts.is_empty() {
            return Err(Error::HookExecution("Empty command".to_string()));
        }

        let program = &parts[0];
        let args = &parts[1..];

        tracing::debug!("Executing command: {} {:?}", program, args);
        tracing::debug!("Working directory: {}", working_dir.display());
        if timeout > 0 {
            tracing::debug!("Timeout: {} seconds", timeout);
        }

        // Build command - inherits parent env by default
        let mut cmd_builder = duct::cmd(program, args).dir(working_dir).stderr_to_stdout();

        // Add custom environment variables (guisu-specific + hook-specific)
        for (key, value) in env {
            cmd_builder = cmd_builder.env(key, value);
        }

        let cmd_builder = cmd_builder;

        // Execute with or without timeout
        if timeout > 0 {
            let handle = cmd_builder.start().map_err(|e| {
                Error::HookExecution(format!("Failed to start command '{program}': {e}"))
            })?;

            match handle.wait_timeout(Duration::from_secs(timeout)) {
                Ok(Some(_output)) => Ok(()),
                Ok(None) => Err(Error::HookExecution(format!(
                    "Command '{program}' timed out after {timeout} seconds"
                ))),
                Err(e) => Err(Error::HookExecution(format!(
                    "Command '{program}' failed: {e}"
                ))),
            }
        } else {
            cmd_builder
                .run()
                .map(|_| ())
                .map_err(|e| Error::HookExecution(format!("Command '{program}' failed: {e}")))
        }
    }

    /// Execute a template script by rendering it first
    fn execute_template_script(&self, hook: &Hook) -> Result<()> {
        let script_path = hook
            .script
            .as_ref()
            .ok_or_else(|| Error::HookExecution("Template hook missing script path".to_string()))?;

        // Resolve full script path
        let full_script_path = if script_path.starts_with('/') {
            PathBuf::from(script_path)
        } else {
            self.source_dir.join(script_path)
        };

        tracing::debug!("Reading template script: {}", full_script_path.display());

        // Read script content
        let content = fs::read_to_string(&full_script_path).map_err(|e| {
            Error::HookExecution(format!(
                "Failed to read script {}: {}",
                full_script_path.display(),
                e
            ))
        })?;

        // Render template using the renderer
        tracing::debug!("Rendering template for hook '{}'", hook.name);
        let processed_content = self
            .template_renderer
            .render(&content)
            .map_err(|e| Error::HookExecution(format!("Failed to render template: {e}")))?;

        // Execute the processed script
        let working_dir = self.source_dir.to_path_buf();

        // Build environment variables (only clone if hook has custom env)
        let env = if hook.env.is_empty() {
            self.env_vars.clone()
        } else {
            let mut env = (*self.env_vars).clone();
            for (k, v) in &hook.env {
                let expanded_value = env::expand_env_vars(v, &self.env_vars);
                env.insert(k.clone(), expanded_value.into_owned());
            }
            std::sync::Arc::new(env)
        };

        script::execute_processed_script(&processed_content, &working_dir, &env, hook.timeout)
    }
}

// ======================================================================
// HookRunnerBuilder - Type-safe builder pattern for HookRunner
// ======================================================================

/// Builder for creating a `HookRunner` with custom configuration
///
/// This builder provides a fluent API for configuring a `HookRunner` before
/// creating it. It ensures all necessary configuration is provided while
/// making optional configuration clear.
///
/// # Examples
///
/// ```ignore
/// use guisu_engine::hooks::{HookRunner, HookStage};
///
/// let runner = HookRunner::builder(&collections, source_dir)
///     .template_renderer(my_renderer)
///     .persistent_state(once_executed, onchange_hashes)
///     .env("CUSTOM_VAR", "custom_value")
///     .build();
///
/// runner.run_stage(HookStage::Pre)?;
/// ```
pub struct HookRunnerBuilder<'a, R = NoOpRenderer>
where
    R: TemplateRenderer,
{
    collections: &'a HookCollections,
    source_dir: &'a Path,
    env_vars: IndexMap<String, String>,
    template_renderer: R,
    persistent_once: std::collections::HashSet<String>,
    persistent_onchange: std::collections::HashMap<String, [u8; 32]>,
}

impl<'a> HookRunnerBuilder<'a, NoOpRenderer> {
    /// Create a new builder with required parameters
    ///
    /// This is typically called via [`HookRunner::builder`].
    #[must_use]
    pub fn new(collections: &'a HookCollections, source_dir: &'a Path) -> Self {
        let mut env_vars = IndexMap::new();

        // Inherit all environment variables from parent shell (like chezmoi does)
        for (key, value) in std::env::vars() {
            env_vars.insert(key, value);
        }

        // Override/add guisu-specific variables
        env_vars.insert("GUISU_SOURCE".to_string(), source_dir.display().to_string());

        if let Some(home) = dirs::home_dir() {
            env_vars.insert("HOME".to_string(), home.display().to_string());
        }

        Self {
            collections,
            source_dir,
            env_vars,
            template_renderer: NoOpRenderer,
            persistent_once: std::collections::HashSet::new(),
            persistent_onchange: std::collections::HashMap::new(),
        }
    }

    /// Set the template renderer for processing template scripts
    ///
    /// Transforms the builder to use a specific renderer type.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = HookRunner::builder(&collections, source_dir)
    ///     .template_renderer(|content| {
    ///         // Custom template rendering logic
    ///         Ok(content.to_string())
    ///     });
    /// ```
    pub fn template_renderer<F>(self, renderer: F) -> HookRunnerBuilder<'a, F>
    where
        F: TemplateRenderer,
    {
        HookRunnerBuilder {
            collections: self.collections,
            source_dir: self.source_dir,
            env_vars: self.env_vars,
            template_renderer: renderer,
            persistent_once: self.persistent_once,
            persistent_onchange: self.persistent_onchange,
        }
    }
}

impl<'a, R> HookRunnerBuilder<'a, R>
where
    R: TemplateRenderer,
{
    /// Set persistent state for mode=once and mode=onchange hooks
    ///
    /// This tells the runner which hooks have already been executed and
    /// what their content hashes were.
    ///
    /// # Parameters
    ///
    /// * `once_executed` - Set of hook names that have been executed with mode=once
    /// * `onchange_hashes` - Map of hook names to their content hashes for mode=onchange
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let runner = HookRunner::builder(&collections, source_dir)
    ///     .persistent_state(
    ///         HashSet::from(["setup-once".to_string()]),
    ///         HashMap::from([("config-update".to_string(), vec![0x12, 0x34])])
    ///     )
    ///     .build();
    /// ```
    #[must_use]
    pub fn persistent_state(
        mut self,
        once_executed: std::collections::HashSet<String>,
        onchange_hashes: std::collections::HashMap<String, [u8; 32]>,
    ) -> Self {
        self.persistent_once = once_executed;
        self.persistent_onchange = onchange_hashes;
        self
    }

    /// Add a custom environment variable
    ///
    /// This environment variable will be available to all hooks.
    /// Can be called multiple times to add multiple variables.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let runner = HookRunner::builder(&collections, source_dir)
    ///     .env("DEPLOY_ENV", "production")
    ///     .env("REGION", "us-west-2")
    ///     .build();
    /// ```
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Add multiple environment variables at once
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use indexmap::IndexMap;
    ///
    /// let mut vars = IndexMap::new();
    /// vars.insert("VAR1".to_string(), "value1".to_string());
    /// vars.insert("VAR2".to_string(), "value2".to_string());
    ///
    /// let runner = HookRunner::builder(&collections, source_dir)
    ///     .env_vars(vars)
    ///     .build();
    /// ```
    #[must_use]
    pub fn env_vars(mut self, vars: IndexMap<String, String>) -> Self {
        self.env_vars.extend(vars);
        self
    }

    /// Build the `HookRunner`
    ///
    /// Consumes the builder and creates a configured `HookRunner`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let runner = HookRunner::builder(&collections, source_dir)
    ///     .template_renderer(my_renderer)
    ///     .persistent_state(once_executed, onchange_hashes)
    ///     .build();
    /// ```
    pub fn build(self) -> HookRunner<'a, R> {
        HookRunner {
            collections: self.collections,
            source_dir: self.source_dir,
            env_vars: std::sync::Arc::new(self.env_vars),
            template_renderer: self.template_renderer,
            once_executed: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            persistent_once: self.persistent_once,
            persistent_onchange: self.persistent_onchange,
            onchange_hashes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            onchange_rendered: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::hooks::config::{Hook, HookCollections, HookMode};
    use crate::hooks::types::HookName;
    use indexmap::IndexMap;
    use std::collections::{HashMap, HashSet};
    use tempfile::TempDir;

    // ======================================================================
    // NoOpRenderer Tests
    // ======================================================================

    #[test]
    fn test_noop_renderer_returns_input_unchanged() {
        let renderer = NoOpRenderer;
        let input = "Hello, {{ name }}!";

        let result = renderer.render(input).expect("Render failed");
        assert_eq!(result, input);
    }

    #[test]
    fn test_noop_renderer_empty_string() {
        let renderer = NoOpRenderer;
        let result = renderer.render("").expect("Render failed");
        assert_eq!(result, "");
    }

    #[test]
    fn test_noop_renderer_with_special_chars() {
        let renderer = NoOpRenderer;
        let input = "#!/bin/bash\necho $VAR\n{{ template }}";

        let result = renderer.render(input).expect("Render failed");
        assert_eq!(result, input);
    }

    // ======================================================================
    // HookRunnerBuilder Tests
    // ======================================================================

    #[test]
    fn test_builder_new_creates_default_env() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let builder = HookRunnerBuilder::new(&collections, temp.path());

        // Should have GUISU_SOURCE env var
        assert!(builder.env_vars.contains_key("GUISU_SOURCE"));
        assert_eq!(
            builder.env_vars.get("GUISU_SOURCE").unwrap(),
            &temp.path().display().to_string()
        );

        // Should have HOME env var (if dirs::home_dir() returns Some)
        if dirs::home_dir().is_some() {
            assert!(builder.env_vars.contains_key("HOME"));
        }
    }

    #[test]
    fn test_builder_template_renderer() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let custom_renderer = |input: &str| -> Result<String> { Ok(format!("RENDERED: {input}")) };

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .template_renderer(custom_renderer)
            .build();

        // Verify renderer works
        let result = runner
            .template_renderer
            .render("test")
            .expect("Render failed");
        assert_eq!(result, "RENDERED: test");
    }

    #[test]
    fn test_builder_persistent_state() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let mut once_executed = HashSet::new();
        once_executed.insert("hook1".to_string());

        let mut onchange_hashes = HashMap::new();
        let mut hash = [0u8; 32];
        hash[0] = 0x12;
        hash[1] = 0x34;
        onchange_hashes.insert("hook2".to_string(), hash);

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .persistent_state(once_executed.clone(), onchange_hashes.clone())
            .build();

        assert_eq!(runner.persistent_once, once_executed);
        assert_eq!(runner.persistent_onchange, onchange_hashes);
    }

    #[test]
    fn test_builder_env() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .env("CUSTOM_VAR", "custom_value")
            .env("ANOTHER_VAR", "another_value")
            .build();

        assert_eq!(runner.env_vars.get("CUSTOM_VAR").unwrap(), "custom_value");
        assert_eq!(runner.env_vars.get("ANOTHER_VAR").unwrap(), "another_value");
    }

    #[test]
    fn test_builder_env_vars() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let mut custom_vars = IndexMap::new();
        custom_vars.insert("VAR1".to_string(), "value1".to_string());
        custom_vars.insert("VAR2".to_string(), "value2".to_string());

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .env_vars(custom_vars)
            .build();

        assert_eq!(runner.env_vars.get("VAR1").unwrap(), "value1");
        assert_eq!(runner.env_vars.get("VAR2").unwrap(), "value2");
    }

    #[test]
    fn test_builder_build_creates_runner() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let runner = HookRunnerBuilder::new(&collections, temp.path()).build();

        // Verify Arc-wrapped fields are initialized
        assert!(runner.once_executed.lock().unwrap().is_empty());
        assert!(runner.onchange_hashes.lock().unwrap().is_empty());
    }

    // ======================================================================
    // Hook Execution Mode Tests
    // ======================================================================

    fn create_test_hook(name: &str, mode: HookMode) -> Hook {
        Hook {
            name: HookName::new(name).unwrap(),
            order: 100,
            platforms: vec![],
            cmd: Some("echo test".to_string()),
            script: None,
            script_content: None,
            env: IndexMap::new(),
            failfast: true,
            mode,
            timeout: 0,
        }
    }

    #[test]
    fn test_should_skip_hook_always() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::Always);
        let result = runner.should_skip_hook(&hook);

        assert!(!result.should_skip);
        assert!(result.cached_hash.is_none());
    }

    #[test]
    fn test_should_skip_hook_once_first_execution() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::Once);
        let result = runner.should_skip_hook(&hook);

        assert!(!result.should_skip);
        assert!(result.cached_hash.is_none());
    }

    #[test]
    fn test_should_skip_hook_once_already_in_session() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::Once);

        runner
            .once_executed
            .lock()
            .unwrap()
            .insert("test".to_string());

        let result = runner.should_skip_hook(&hook);

        assert!(result.should_skip);
        assert!(result.reason.contains("already executed in this session"));
    }

    #[test]
    fn test_should_skip_hook_once_already_in_persistent() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let mut persistent_once = HashSet::new();
        persistent_once.insert("test".to_string());

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .persistent_state(persistent_once, HashMap::new())
            .build();

        let hook = create_test_hook("test", HookMode::Once);
        let result = runner.should_skip_hook(&hook);

        assert!(result.should_skip);
        assert!(result.reason.contains("already executed previously"));
    }

    #[test]
    fn test_should_skip_hook_onchange_first_execution() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::OnChange);
        let result = runner.should_skip_hook(&hook);

        assert!(!result.should_skip);
        assert!(result.cached_hash.is_some());
    }

    #[test]
    fn test_should_skip_hook_onchange_unchanged_in_session() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::OnChange);

        let result = runner.should_skip_hook(&hook);
        let hash = result.cached_hash.unwrap();

        runner
            .onchange_hashes
            .lock()
            .unwrap()
            .insert("test".to_string(), hash);

        let result = runner.should_skip_hook(&hook);

        assert!(result.should_skip);
        assert!(result.reason.contains("content unchanged in this session"));
    }

    #[test]
    fn test_should_skip_hook_onchange_unchanged_in_persistent() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let hook = create_test_hook("test", HookMode::OnChange);

        let expected_hash = crate::hash::hash_content(hook.get_content().as_bytes());

        let mut persistent_onchange = HashMap::new();
        persistent_onchange.insert("test".to_string(), expected_hash);

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .persistent_state(HashSet::new(), persistent_onchange)
            .build();

        let result = runner.should_skip_hook(&hook);

        assert!(result.should_skip);
        assert!(result.reason.contains("content unchanged"));
    }

    #[test]
    fn test_should_skip_hook_onchange_content_changed() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let mut persistent_onchange = HashMap::new();
        let mut different_hash = [0u8; 32];
        different_hash[0] = 0x00;
        different_hash[1] = 0x11;
        different_hash[2] = 0x22;
        persistent_onchange.insert("test".to_string(), different_hash);

        let runner = HookRunnerBuilder::new(&collections, temp.path())
            .persistent_state(HashSet::new(), persistent_onchange)
            .build();

        let hook = create_test_hook("test", HookMode::OnChange);
        let result = runner.should_skip_hook(&hook);

        assert!(!result.should_skip);
        assert!(result.cached_hash.is_some());
    }

    #[test]
    fn test_mark_hook_executed_always() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::Always);
        runner.mark_hook_executed(&hook, None, None);

        // Should not be tracked
        assert!(runner.once_executed.lock().unwrap().is_empty());
        assert!(runner.onchange_hashes.lock().unwrap().is_empty());
    }

    #[test]
    fn test_mark_hook_executed_once() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::Once);
        runner.mark_hook_executed(&hook, None, None);

        // Should be in once_executed
        assert!(runner.once_executed.lock().unwrap().contains("test"));
    }

    #[test]
    fn test_mark_hook_executed_onchange_with_cached_hash() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::OnChange);
        let mut cached_hash = [0u8; 32];
        cached_hash[0] = 0x12;
        cached_hash[1] = 0x34;
        cached_hash[2] = 0x56;

        runner.mark_hook_executed(&hook, Some(cached_hash), None);

        // Should be in onchange_hashes
        let hashes = runner.onchange_hashes.lock().unwrap();
        assert_eq!(hashes.get("test"), Some(&cached_hash));
    }

    #[test]
    fn test_mark_hook_executed_onchange_without_cached_hash() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let hook = create_test_hook("test", HookMode::OnChange);
        runner.mark_hook_executed(&hook, None, None);

        // Should compute and store hash
        let hashes = runner.onchange_hashes.lock().unwrap();
        assert!(hashes.contains_key("test"));
        assert!(!hashes.get("test").unwrap().is_empty());
    }

    #[test]
    fn test_get_once_executed() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        runner
            .once_executed
            .lock()
            .unwrap()
            .insert("hook1".to_string());
        runner
            .once_executed
            .lock()
            .unwrap()
            .insert("hook2".to_string());

        let executed = runner.get_once_executed();
        assert_eq!(executed.len(), 2);
        assert!(executed.contains("hook1"));
        assert!(executed.contains("hook2"));
    }

    #[test]
    fn test_get_onchange_hashes() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        let mut hash1 = [0u8; 32];
        hash1[0] = 0x12;
        let mut hash2 = [0u8; 32];
        hash2[0] = 0x34;

        runner
            .onchange_hashes
            .lock()
            .unwrap()
            .insert("hook1".to_string(), hash1);
        runner
            .onchange_hashes
            .lock()
            .unwrap()
            .insert("hook2".to_string(), hash2);

        let hashes = runner.get_onchange_hashes();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes.get("hook1"), Some(&hash1));
        assert_eq!(hashes.get("hook2"), Some(&hash2));
    }

    // ======================================================================
    // HookRunner Stage Tests
    // ======================================================================

    #[test]
    fn test_run_stage_empty_hooks() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();
        let runner = HookRunner::new(&collections, temp.path());

        // Should succeed with no hooks
        let result = runner.run_stage(HookStage::Pre);
        assert!(result.is_ok());

        let result = runner.run_stage(HookStage::Post);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hook_runner_new() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let runner = HookRunner::new(&collections, temp.path());

        // Should have empty execution state
        assert!(runner.once_executed.lock().unwrap().is_empty());
        assert!(runner.onchange_hashes.lock().unwrap().is_empty());

        // Should have GUISU_SOURCE env var
        assert!(runner.env_vars.get("GUISU_SOURCE").is_some());
    }

    #[test]
    fn test_hook_runner_builder_creates_runner() {
        let temp = TempDir::new().unwrap();
        let collections = HookCollections::default();

        let runner = HookRunner::builder(&collections, temp.path()).build();

        // Should have env vars set
        assert!(runner.env_vars.get("GUISU_SOURCE").is_some());
    }
}
