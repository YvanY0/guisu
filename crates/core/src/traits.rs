//! Core behavioral traits for guisu components
//!
//! This module defines the abstract interfaces that decouple high-level modules
//! from concrete implementations, following the Dependency Inversion Principle.
//!
//! By depending on these traits instead of concrete types, we achieve:
//! - **Reduced coupling**: Changes to implementations don't trigger recompilation of dependents
//! - **Better testability**: Easy to mock implementations for testing
//! - **Flexibility**: Can swap implementations at runtime if needed

use crate::Result;

/// Template renderer interface
///
/// Abstracts template rendering to decouple from specific template engines
/// (Jinja2, Handlebars, etc.).
///
/// Uses `serde_json::Value` for context to ensure trait object safety.
/// Any struct implementing `serde::Serialize` can be converted to `Value` with `serde_json::to_value()`.
///
/// # Examples
///
/// ```ignore
/// use guisu_core::TemplateRenderer;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct MyContext {
///     name: String,
/// }
///
/// fn render_greeting(renderer: &dyn TemplateRenderer) -> Result<String> {
///     let context = MyContext { name: "Alice".to_string() };
///     let value = serde_json::to_value(&context)?;
///     renderer.render_str("Hello {{ name }}!", &value)
/// }
/// ```
pub trait TemplateRenderer {
    /// Render a template string with the given context
    ///
    /// # Arguments
    ///
    /// * `template` - The template source code
    /// * `context` - Context data as a JSON value
    ///
    /// # Errors
    ///
    /// Returns error if template syntax is invalid or rendering fails
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let context = serde_json::json!({"username": "Alice"});
    /// let result = renderer.render_str("Hello {{ username }}!", &context)?;
    /// ```
    fn render_str(&self, template: &str, context: &serde_json::Value) -> Result<String>;

    /// Render a template string with a specific name for better error messages
    ///
    /// # Arguments
    ///
    /// * `name` - Template name to use in error messages (e.g., file path)
    /// * `template` - The template source code
    /// * `context` - Context data as a JSON value
    ///
    /// # Errors
    ///
    /// Returns error if template syntax is invalid or rendering fails
    fn render_named_str(
        &self,
        name: &str,
        template: &str,
        context: &serde_json::Value,
    ) -> Result<String>;
}
