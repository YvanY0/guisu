//! Hook script body resolution shared by `diff`, `status`, and `hooks show`
//!
//! Rendering a hook's script body needs the full template context (age
//! identities, `.guisu/variables/`, guisu paths). That setup was previously
//! copy-pasted into `cmd/diff.rs` (`render_hook_template`), `cmd/status.rs`
//! (`render_script_content`), and `cmd/hooks.rs` (`create_template_engine`).
//! `HookBodies` is the single owner: the template engine is built once per
//! command run instead of once per hook render, and the body-resolution
//! rules match [`guisu_engine::hooks`] selection exactly.

use anyhow::{Context, Result};
use guisu_config::Config;
use guisu_core::Result as CoreResult;
use guisu_engine::hooks::{Hook, TemplateRenderer, render_script_body};
use guisu_template::TemplateContext;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Template renderer closure: `(template source) -> rendered text`.
type Renderer = Box<dyn Fn(&str) -> CoreResult<String> + Send + Sync>;

/// Resolves rendered script bodies for hook display and diffing.
pub(crate) struct HookBodies {
    /// `None` when the template context could not be built; renders then
    /// fail and callers fall back to raw content (mirrors the historical
    /// per-render warning-and-continue behavior).
    renderer: Option<Renderer>,
}

impl HookBodies {
    /// Build the template engine + context shared by every hook render.
    ///
    /// # Errors
    ///
    /// Returns an error if template variables cannot be loaded from the
    /// source directory.
    pub fn new(source_dir: &Path, config: &Config) -> Result<Self> {
        // Load age identities for encryption support in templates.
        let identities =
            std::sync::Arc::new(config.age_identities().unwrap_or_else(|_| Vec::new()));

        // Engine with template directory + bitwarden provider support.
        let engine = crate::create_template_engine(source_dir, &identities, config);

        let dst_dir = config
            .general
            .dst_dir
            .clone()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("~"));

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
            .context("Failed to load variables")?;

        Ok(Self {
            renderer: Some(Box::new(move |content: &str| {
                engine.render_str(content, &context).map_err(|e| {
                    guisu_core::Error::Message(format!("Template rendering error: {e}"))
                })
            })),
        })
    }

    /// Build for read-only display, degrading to raw content on failure.
    ///
    /// `diff` and `status` must not drop their hooks section (or error out)
    /// because of a broken `.guisu/variables/` file — the old code rendered
    /// per hook and warned on each failure; this keeps that behavior with a
    /// single one-time warning.
    #[must_use]
    pub fn with_fallback(source_dir: &Path, config: &Config) -> Self {
        Self::new(source_dir, config).unwrap_or_else(|e| {
            tracing::warn!("Failed to set up hook template renderer: {e:#}");
            Self { renderer: None }
        })
    }

    /// Render template content directly (used by `hooks show`).
    ///
    /// # Errors
    ///
    /// Returns an error if template rendering fails or the renderer could
    /// not be built.
    pub fn render(&self, content: &str) -> CoreResult<String> {
        match &self.renderer {
            Some(render) => render(content),
            None => Err(guisu_core::Error::Message(
                "hook template renderer unavailable".to_string(),
            )),
        }
    }

    /// Current-side bodies: an entry per hook with both a script and loaded
    /// content, rendered through the template engine when applicable.
    pub fn current_bodies<'h>(
        &self,
        hooks: impl IntoIterator<Item = &'h Hook>,
    ) -> HashMap<&'h str, String> {
        let mut bodies = HashMap::new();
        for hook in hooks {
            if let (Some(script), Some(raw)) = (&hook.script, &hook.script_content) {
                bodies.insert(
                    hook.name.as_str(),
                    render_script_body(script, raw, &|content| self.render(content)),
                );
            }
        }
        bodies
    }

    /// Previous-side bodies: rendered content from the snapshot when
    /// present, falling back to the content recorded at the last run
    /// (`HookState::onchange_rendered`, since `script_content` is
    /// `#[serde(skip)]` and never round-trips through the state DB).
    pub fn previous_bodies<'h>(
        &self,
        hooks: impl IntoIterator<Item = &'h Hook>,
        onchange_rendered: &HashMap<String, String>,
    ) -> HashMap<&'h str, String> {
        let mut bodies = HashMap::new();
        for hook in hooks {
            let body = match (&hook.script, &hook.script_content) {
                (Some(script), Some(raw)) => Some(render_script_body(script, raw, &|content| {
                    self.render(content)
                })),
                _ => onchange_rendered.get(hook.name.as_str()).cloned(),
            };
            if let Some(body) = body {
                bodies.insert(hook.name.as_str(), body);
            }
        }
        bodies
    }
}

impl TemplateRenderer for HookBodies {
    fn render(&self, input: &str) -> CoreResult<String> {
        HookBodies::render(self, input)
    }
}
