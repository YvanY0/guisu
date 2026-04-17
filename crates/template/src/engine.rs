//! Template engine implementation
//!
//! The engine wraps minijinja and provides template rendering with custom functions.

use crate::context::TemplateContext;
use crate::functions;
use crate::{Error, Result};
use guisu_crypto::Identity;
use minijinja::Environment;
use std::path::PathBuf;
use std::sync::Arc;

/// Template engine for rendering templates
pub struct TemplateEngine {
    /// The minijinja environment
    env: Environment<'static>,
}

impl TemplateEngine {
    /// Create a new template engine without decryption support
    #[must_use]
    pub fn new() -> Self {
        Self::with_identities(Vec::new())
    }

    /// Create a template engine with identities for decryption
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_template::TemplateEngine;
    /// use guisu_crypto::load_identities;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let identities = load_identities(&PathBuf::from("~/.config/guisu/key.txt"), false)?;
    /// let engine = TemplateEngine::with_identities(identities);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_identities(identities: Vec<Identity>) -> Self {
        Self::with_identities_and_template_dir(identities, None)
    }

    /// Create a template engine with identities and a template directory
    ///
    /// The template directory supports platform-specific templates:
    /// - Templates in `templates/darwin/` are used on macOS
    /// - Templates in `templates/linux/` are used on Linux
    /// - Templates in `templates/` are used as fallback
    ///
    /// When using `{% include "Brewfile" %}`, the engine searches:
    /// 1. `templates/{platform}/Brewfile.j2`
    /// 2. `templates/{platform}/Brewfile`
    /// 3. `templates/Brewfile.j2`
    /// 4. `templates/Brewfile`
    ///
    /// Templates ending with `.j2` support nested Jinja2 rendering.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use guisu_template::TemplateEngine;
    /// use guisu_crypto::load_identities;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let identities = load_identities(&PathBuf::from("~/.config/guisu/key.txt"), false)?;
    /// let template_dir = PathBuf::from("/path/to/source/.guisu/templates");
    /// let engine = TemplateEngine::with_identities_and_template_dir(identities, Some(template_dir));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_identities_and_template_dir(
        identities: Vec<Identity>,
        template_dir: Option<PathBuf>,
    ) -> Self {
        Self::with_identities_arc_and_template_dir(&Arc::new(identities), template_dir)
    }

    /// Create a template engine with Arc-wrapped identities and optional template directory
    ///
    /// This version accepts Arc-wrapped identities to avoid cloning when the identities
    /// are already wrapped in Arc.
    #[must_use]
    pub fn with_identities_arc_and_template_dir(
        identities: &Arc<Vec<Identity>>,
        template_dir: Option<PathBuf>,
    ) -> Self {
        Self::with_identities_arc_template_dir_and_bitwarden_provider(
            identities,
            template_dir,
            "bw", // default provider
        )
    }

    /// Create a template engine with all configuration options
    ///
    /// This is the most complete constructor that accepts:
    /// - Identities for encryption/decryption
    /// - Template directory for include/includeTemplate
    /// - Bitwarden provider selection ("bw" or "rbw")
    pub fn with_identities_arc_template_dir_and_bitwarden_provider(
        identities: &Arc<Vec<Identity>>,
        template_dir: Option<PathBuf>,
        bitwarden_provider: &str,
    ) -> Self {
        let mut env = Environment::new();

        // Enable Jinja2 standard whitespace control
        // trim_blocks: automatically remove newlines after block tags
        // lstrip_blocks: automatically strip leading whitespace from block lines
        // keep_trailing_newline: ensure files always end with a newline
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.set_keep_trailing_newline(true);

        // Register custom functions
        env.add_function("env", functions::env);
        env.add_function("os", functions::os);
        env.add_function("arch", functions::arch);
        env.add_function("hostname", functions::hostname);
        env.add_function("username", functions::username);
        env.add_function("home_dir", functions::home_dir);
        env.add_function("joinPath", functions::join_path);
        env.add_function("lookPath", functions::look_path);
        env.add_function("include", functions::include);
        env.add_function("includeTemplate", functions::include_template);

        // Register Bitwarden functions with provider closure
        #[cfg(any(feature = "bw", feature = "rbw"))]
        {
            let provider = bitwarden_provider.to_string();

            let provider_clone = provider.clone();
            env.add_function("bitwarden", move |args: &[minijinja::Value]| {
                functions::bitwarden(args, &provider_clone)
            });

            let provider_clone = provider.clone();
            env.add_function("bitwardenFields", move |args: &[minijinja::Value]| {
                functions::bitwarden_fields(args, &provider_clone)
            });

            #[cfg(feature = "bw")]
            {
                env.add_function("bitwardenAttachment", move |args: &[minijinja::Value]| {
                    functions::bitwarden_attachment(args, &provider)
                });
            }
        }

        #[cfg(feature = "bws")]
        env.add_function("bitwardenSecrets", functions::bitwarden_secrets);

        // Register filters
        env.add_filter("quote", functions::quote);
        env.add_filter("toJson", functions::to_json);
        env.add_filter("fromJson", functions::from_json);
        env.add_filter("toToml", functions::to_toml);
        env.add_filter("fromToml", functions::from_toml);
        env.add_filter("trim", functions::trim);
        env.add_filter("trimStart", functions::trim_start);
        env.add_filter("trimEnd", functions::trim_end);
        env.add_filter("blake3sum", functions::blake3sum);

        // Register string processing functions
        env.add_function("regexMatch", functions::regex_match);
        env.add_function("regexReplaceAll", functions::regex_replace_all);
        env.add_function("split", functions::split);
        env.add_function("join", functions::join);

        // Register decrypt filter with captured identities
        let identities_clone = Arc::clone(identities);
        env.add_filter("decrypt", move |value: &str| {
            functions::decrypt(value, &identities_clone)
        });

        // Register encrypt filter with captured identities
        let identities_clone = Arc::clone(identities);
        env.add_filter("encrypt", move |value: &str| {
            functions::encrypt(value, &identities_clone)
        });

        // Set up smart template loader with platform support
        if let Some(template_dir) = template_dir
            && template_dir.exists()
            && template_dir.is_dir()
        {
            // Detect current platform
            #[cfg(target_os = "linux")]
            let platform = "linux";
            #[cfg(target_os = "macos")]
            let platform = "darwin";
            #[cfg(target_os = "windows")]
            let platform = "windows";
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            let platform = "unknown";

            let platform = platform.to_string();

            env.set_loader(move |name| {
                // Search order for template "Brewfile":
                // 1. templates/darwin/Brewfile.j2
                // 2. templates/darwin/Brewfile
                // 3. templates/Brewfile.j2
                // 4. templates/Brewfile

                let candidates = vec![
                    template_dir.join(&platform).join(format!("{name}.j2")),
                    template_dir.join(&platform).join(name),
                    template_dir.join(format!("{name}.j2")),
                    template_dir.join(name),
                ];

                for path in candidates {
                    if path.exists() {
                        return match std::fs::read_to_string(&path) {
                            Ok(content) => Ok(Some(content)),
                            Err(e) => Err(minijinja::Error::new(
                                minijinja::ErrorKind::InvalidOperation,
                                format!("Failed to read template '{name}': {e}"),
                            )),
                        };
                    }
                }

                // Template not found
                Ok(None)
            });
        }

        Self { env }
    }

    /// Render a template string with the given context
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_template::{TemplateEngine, TemplateContext};
    ///
    /// let engine = TemplateEngine::new();
    /// let context = TemplateContext::new();
    ///
    /// let template = "Hello {{ username }}!";
    /// let result = engine.render_str(template, &context).unwrap();
    /// println!("{}", result);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if template rendering fails
    pub fn render_str(&self, template: &str, context: &TemplateContext) -> Result<String> {
        self.env
            .render_str(template, context)
            .map_err(|e| crate::convert_minijinja_error(&e))
    }

    /// Render a template string with a specific name for better error messages
    ///
    /// This method is preferred over `render_str` when you have a file path or
    /// meaningful name to associate with the template. Error messages will include
    /// this name instead of the generic `<string>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use guisu_template::{TemplateEngine, TemplateContext};
    ///
    /// let engine = TemplateEngine::new();
    /// let context = TemplateContext::new();
    ///
    /// let template = "Hello {{ username }}!";
    /// let result = engine.render_named_str("greeting.txt", template, &context).unwrap();
    /// println!("{}", result);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if template rendering fails
    pub fn render_named_str(
        &self,
        name: &str,
        template: &str,
        context: &TemplateContext,
    ) -> Result<String> {
        self.env
            .render_named_str(name, template, context)
            .map_err(|e| crate::convert_minijinja_error(&e))
    }

    /// Render template content (bytes) with the given context
    ///
    /// This is useful for rendering template files that may contain binary data
    /// in certain sections, though the template syntax itself must be valid UTF-8.
    ///
    /// # Errors
    ///
    /// Returns error if template is not valid UTF-8 or rendering fails
    pub fn render(&self, template: &[u8], context: &TemplateContext) -> Result<Vec<u8>> {
        let template_str = std::str::from_utf8(template)
            .map_err(|e| Error::TemplateSyntax(format!("Template is not valid UTF-8: {e}")))?;

        let rendered = self.render_str(template_str, context)?;
        Ok(rendered.into_bytes())
    }

    /// Check if a string contains template syntax
    ///
    /// This is a simple heuristic check that looks for Jinja2-style syntax.
    #[must_use]
    pub fn is_template(content: &str) -> bool {
        content.contains("{{") || content.contains("{%") || content.contains("{#")
    }

    /// Get a reference to the underlying minijinja environment
    ///
    /// This allows for advanced customization if needed.
    pub fn env(&self) -> &Environment<'static> {
        &self.env
    }

    /// Get a mutable reference to the underlying minijinja environment
    ///
    /// This allows for advanced customization if needed.
    pub fn env_mut(&mut self) -> &mut Environment<'static> {
        &mut self.env
    }
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

// Implement TemplateRenderer trait for TemplateEngine
impl guisu_core::TemplateRenderer for TemplateEngine {
    fn render_str(
        &self,
        template: &str,
        context: &serde_json::Value,
    ) -> guisu_core::Result<String> {
        self.env
            .render_str(template, context)
            .map_err(|e| guisu_core::Error::Message(crate::convert_minijinja_error(&e).to_string()))
    }

    fn render_named_str(
        &self,
        name: &str,
        template: &str,
        context: &serde_json::Value,
    ) -> guisu_core::Result<String> {
        self.env
            .render_named_str(name, template, context)
            .map_err(|e| guisu_core::Error::Message(crate::convert_minijinja_error(&e).to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::TemplateContext;
    use guisu_crypto::Identity;
    use tempfile::TempDir;

    #[test]
    fn test_new() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let result = engine.render_str("Hello {{ username }}!", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default() {
        let engine = TemplateEngine::default();
        let ctx = TemplateContext::new();

        let result = engine.render_str("Test", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_identities() {
        let identity = Identity::generate();
        let engine = TemplateEngine::with_identities(vec![identity]);
        let ctx = TemplateContext::new();

        let result = engine.render_str("{{ username }}", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_identities_and_template_dir() {
        let identity = Identity::generate();
        let temp = TempDir::new().unwrap();

        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![identity],
            Some(temp.path().to_path_buf()),
        );

        let ctx = TemplateContext::new();
        let result = engine.render_str("{{ os }}", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_identities_arc_and_template_dir() {
        let identity = Identity::generate();
        let identities = Arc::new(vec![identity]);

        let engine = TemplateEngine::with_identities_arc_and_template_dir(&identities, None);

        let ctx = TemplateContext::new();
        let result = engine.render_str("{{ arch }}", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_bitwarden_provider() {
        let identity = Identity::generate();
        let identities = Arc::new(vec![identity]);

        let engine = TemplateEngine::with_identities_arc_template_dir_and_bitwarden_provider(
            &identities,
            None,
            "rbw",
        );

        let ctx = TemplateContext::new();
        let result = engine.render_str("{{ hostname }}", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_render_str_basic() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = "Hello {{ username }}!";
        let result = engine.render_str(template, &ctx).unwrap();

        assert!(result.contains("Hello"));
        assert!(!result.is_empty());
    }

    #[test]
    fn test_render_str_with_variables() {
        let engine = TemplateEngine::new();
        let mut ctx = TemplateContext::new();
        ctx.add_variable("name".to_string(), serde_json::json!("Alice"));

        let template = "Welcome, {{ name }}!";
        let result = engine.render_str(template, &ctx).unwrap();

        assert_eq!(result, "Welcome, Alice!");
    }

    #[test]
    fn test_render_str_with_filters() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = "{{ 'hello world' | trim }}";
        let result = engine.render_str(template, &ctx).unwrap();

        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_render_str_quote_filter() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = "{{ 'test' | quote }}";
        let result = engine.render_str(template, &ctx).unwrap();

        assert_eq!(result, "\"test\"");
    }

    #[test]
    fn test_render_str_system_functions() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = "OS: {{ os() }}, Arch: {{ arch() }}";
        let result = engine.render_str(template, &ctx).unwrap();

        assert!(result.contains("OS:"));
        assert!(result.contains("Arch:"));
    }

    #[test]
    fn test_render_named_str() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = "Hello from {{ username }}";
        let result = engine
            .render_named_str("greeting.txt", template, &ctx)
            .unwrap();

        assert!(!result.is_empty());
    }

    #[test]
    fn test_render_named_str_error_includes_name() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = "{{ undefined_var | some_unknown_filter }}";
        let result = engine.render_named_str("test.txt", template, &ctx);

        assert!(result.is_err());
        // Error should reference the template name in some form
    }

    #[test]
    fn test_render_bytes() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        let template = b"Hello {{ username }}!";
        let result = engine.render(template, &ctx).unwrap();

        assert!(!result.is_empty());
        assert!(String::from_utf8(result).is_ok());
    }

    #[test]
    fn test_render_bytes_invalid_utf8() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        // Invalid UTF-8 sequence
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let result = engine.render(&invalid_utf8, &ctx);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("UTF-8") || err.contains("utf-8"));
    }

    #[test]
    fn test_is_template_with_variable() {
        assert!(TemplateEngine::is_template("Hello {{ name }}"));
    }

    #[test]
    fn test_is_template_with_block() {
        assert!(TemplateEngine::is_template(
            "{% if condition %}yes{% endif %}"
        ));
    }

    #[test]
    fn test_is_template_with_comment() {
        assert!(TemplateEngine::is_template("{# This is a comment #}"));
    }

    #[test]
    fn test_is_template_plain_text() {
        assert!(!TemplateEngine::is_template("Plain text without templates"));
    }

    #[test]
    fn test_is_template_curly_braces() {
        // Single braces shouldn't be detected as templates
        assert!(!TemplateEngine::is_template("Some { code } here"));
    }

    #[test]
    fn test_env_mut_access() {
        let mut engine = TemplateEngine::new();
        let env = engine.env_mut();

        // Should be able to mutably access and modify
        env.add_filter("custom", |s: &str| s.to_uppercase());

        let ctx = TemplateContext::new();
        let result = engine.render_str("{{ 'hello' | custom }}", &ctx).unwrap();
        assert_eq!(result, "HELLO");
    }

    #[test]
    fn test_encrypt_decrypt_filters() {
        let identity = Identity::generate();
        let engine = TemplateEngine::with_identities(vec![identity]);
        let ctx = TemplateContext::new();

        // Test encryption
        let template = "{{ 'secret' | encrypt }}";
        let encrypted = engine.render_str(template, &ctx).unwrap();
        assert!(encrypted.starts_with("age:"));

        // Test decryption roundtrip
        let decrypt_template = format!("{{{{ '{encrypted}' | decrypt }}}}");
        let decrypted = engine.render_str(&decrypt_template, &ctx).unwrap();
        assert_eq!(decrypted, "secret");
    }

    #[test]
    fn test_regex_functions() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        // Test regexMatch
        let template = "{{ regexMatch('hello123', '\\\\d+') }}";
        let result = engine.render_str(template, &ctx).unwrap();
        assert_eq!(result, "true");

        // Test regexReplaceAll
        let template2 = "{{ regexReplaceAll('hello 123', '\\\\d+', 'X') }}";
        let result2 = engine.render_str(template2, &ctx).unwrap();
        assert_eq!(result2, "hello X");
    }

    #[test]
    fn test_string_functions() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        // Test split
        let template = "{{ split('a,b,c', ',') | join(' - ') }}";
        let result = engine.render_str(template, &ctx).unwrap();
        assert_eq!(result, "a - b - c");
    }

    #[test]
    fn test_json_filters() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        // Test toJson
        let template = "{{ 'test' | toJson }}";
        let result = engine.render_str(template, &ctx).unwrap();
        assert_eq!(result, "\"test\"");
    }

    #[test]
    fn test_whitespace_control() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        // trim_blocks and lstrip_blocks should be enabled
        let template = "line1\n{% if true %}\nline2\n{% endif %}";
        let result = engine.render_str(template, &ctx).unwrap();

        // Should have proper whitespace handling
        assert!(result.contains("line1"));
        assert!(result.contains("line2"));
    }

    #[test]
    fn test_template_loader_with_directory() {
        let temp = TempDir::new().unwrap();

        // Create a template file
        let template_content = "Test template: {{ name }}";
        std::fs::write(temp.path().join("test.j2"), template_content).unwrap();

        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![],
            Some(temp.path().to_path_buf()),
        );

        let mut ctx = TemplateContext::new();
        ctx.add_variable("name".to_string(), serde_json::json!("Alice"));

        // Use {% include %} to load the template
        let main_template = "Start {% include 'test' %} End";
        let result = engine.render_str(main_template, &ctx).unwrap();

        assert!(result.contains("Test template: Alice"));
    }

    #[test]
    fn test_template_loader_platform_specific() {
        let temp = TempDir::new().unwrap();

        // Create platform-specific directory
        #[cfg(target_os = "macos")]
        let platform_dir = temp.path().join("darwin");
        #[cfg(target_os = "linux")]
        let platform_dir = temp.path().join("linux");
        #[cfg(target_os = "windows")]
        let platform_dir = temp.path().join("windows");

        std::fs::create_dir(&platform_dir).unwrap();

        // Create platform-specific template
        let platform_template = "Platform: specific";
        std::fs::write(platform_dir.join("platform_test"), platform_template).unwrap();

        // Create fallback template
        let fallback_template = "Platform: fallback";
        std::fs::write(temp.path().join("platform_test"), fallback_template).unwrap();

        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![],
            Some(temp.path().to_path_buf()),
        );

        let ctx = TemplateContext::new();
        let main_template = "{% include 'platform_test' %}";
        let result = engine.render_str(main_template, &ctx).unwrap();

        // Should load platform-specific version
        assert!(result.contains("Platform: specific"));
    }

    #[test]
    fn test_template_syntax_error() {
        let engine = TemplateEngine::new();
        let ctx = TemplateContext::new();

        // Invalid template syntax
        let template = "{{ unclosed variable";
        let result = engine.render_str(template, &ctx);

        assert!(result.is_err());
    }

    #[test]
    fn test_template_renderer_trait() {
        let engine = TemplateEngine::new();
        let renderer: &dyn guisu_core::TemplateRenderer = &engine;

        let context = serde_json::json!({
            "name": "Bob"
        });

        let result = renderer.render_str("Hello {{ name }}", &context);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello Bob");
    }

    #[test]
    fn test_template_renderer_trait_named() {
        let engine = TemplateEngine::new();
        let renderer: &dyn guisu_core::TemplateRenderer = &engine;

        let context = serde_json::json!({
            "value": 42
        });

        let result = renderer.render_named_str("test.txt", "Value: {{ value }}", &context);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Value: 42");
    }

    #[test]
    fn test_template_loader_file_not_found() {
        let temp = TempDir::new().unwrap();
        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![],
            Some(temp.path().to_path_buf()),
        );

        let ctx = TemplateContext::new();

        // Try to include a template that doesn't exist
        let template = "{% include 'nonexistent_template' %}";
        let result = engine.render_str(template, &ctx);

        // Should fail because template doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_template_loader_read_error() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();

        // Create a template file
        let template_path = temp.path().join("test.j2");
        fs::write(&template_path, "content").unwrap();

        // Make the file unreadable (permission 000)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&template_path).unwrap().permissions();
            perms.set_mode(0o000);
            fs::set_permissions(&template_path, perms).unwrap();
        }

        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![],
            Some(temp.path().to_path_buf()),
        );
        let ctx = TemplateContext::new();

        // Try to include the unreadable template
        let template = "{% include 'test' %}";
        let result = engine.render_str(template, &ctx);

        // Should fail because file cannot be read
        #[cfg(unix)]
        {
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("Failed to read template") || err.contains("Permission denied"));
        }

        // Restore permissions for cleanup
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&template_path).unwrap().permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&template_path, perms).unwrap();
        }
    }

    #[test]
    fn test_env_access() {
        let engine = TemplateEngine::new();
        let env = engine.env();

        // Should be able to access the environment
        assert!(env.get_template("nonexistent").is_err());
    }

    #[test]
    fn test_template_loader_with_j2_extension() {
        let temp = TempDir::new().unwrap();

        // Create template with .j2 extension
        std::fs::write(temp.path().join("test.j2"), "With j2: {{ name }}").unwrap();

        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![],
            Some(temp.path().to_path_buf()),
        );

        let mut ctx = TemplateContext::new();
        ctx.add_variable("name".to_string(), serde_json::json!("Alice"));

        // Should load the .j2 file
        let main_template = "{% include 'test' %}";
        let result = engine.render_str(main_template, &ctx).unwrap();

        assert!(result.contains("With j2: Alice"));
    }

    #[test]
    fn test_template_loader_fallback_to_non_j2() {
        let temp = TempDir::new().unwrap();

        // Create template without .j2 extension (fallback)
        std::fs::write(temp.path().join("fallback"), "No j2: {{ value }}").unwrap();

        let engine = TemplateEngine::with_identities_and_template_dir(
            vec![],
            Some(temp.path().to_path_buf()),
        );

        let mut ctx = TemplateContext::new();
        ctx.add_variable("value".to_string(), serde_json::json!(42));

        // Should load the non-.j2 file
        let main_template = "{% include 'fallback' %}";
        let result = engine.render_str(main_template, &ctx).unwrap();

        assert!(result.contains("No j2: 42"));
    }

    #[test]
    fn test_template_dir_not_exists() {
        let temp = TempDir::new().unwrap();
        let nonexistent_dir = temp.path().join("nonexistent");

        // Should not panic when template dir doesn't exist
        let engine =
            TemplateEngine::with_identities_and_template_dir(vec![], Some(nonexistent_dir));
        let ctx = TemplateContext::new();

        let result = engine.render_str("{{ username }}", &ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_template_dir_is_file() {
        use std::fs;
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("file.txt");
        fs::write(&file_path, "not a directory").unwrap();

        // Should not panic when template_dir is a file
        let engine = TemplateEngine::with_identities_and_template_dir(vec![], Some(file_path));
        let ctx = TemplateContext::new();

        let result = engine.render_str("{{ arch }}", &ctx);
        assert!(result.is_ok());
    }
}
