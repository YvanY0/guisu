//! Template adapter that implements the `TemplateRenderer` trait from engine

use crate::content::TemplateRenderer;
use guisu_core::{Error, Result};
use guisu_template::{TemplateContext, TemplateEngine};
use std::sync::Arc;

/// Adapter that wraps `TemplateEngine` to implement `engine::content::TemplateRenderer`
pub struct TemplateRendererAdapter {
    engine: Arc<TemplateEngine>,
}

impl TemplateRendererAdapter {
    /// Create a new template adapter
    pub fn new(engine: TemplateEngine) -> Self {
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Get a reference to the underlying `TemplateEngine`
    #[must_use]
    pub fn inner(&self) -> &TemplateEngine {
        &self.engine
    }
}

impl TemplateRenderer for TemplateRendererAdapter {
    type Error = Error;

    fn render(&self, template: &str, context: &serde_json::Value) -> Result<String> {
        // Convert serde_json::Value to TemplateContext
        let variables = if let serde_json::Value::Object(map) = context {
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        } else {
            return Err(Error::TemplateContextConversion(
                "Context must be a JSON object".to_string(),
            ));
        };

        let template_context = TemplateContext::new().with_variables(variables);

        self.engine.render_str(template, &template_context)
    }
}

impl Clone for TemplateRendererAdapter {
    fn clone(&self) -> Self {
        Self {
            engine: Arc::clone(&self.engine),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::content::TemplateRenderer;
    use serde_json::json;

    #[test]
    fn test_template_adapter_new() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        // Verify we can get a reference to the inner engine
        let _inner = adapter.inner();
    }

    #[test]
    fn test_render_simple_template() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "Hello, {{ name }}!";
        let context = json!({
            "name": "World"
        });

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "Hello, World!");
    }

    #[test]
    fn test_render_with_multiple_variables() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "{{ greeting }}, {{ name }}! You are {{ age }} years old.";
        let context = json!({
            "greeting": "Hi",
            "name": "Alice",
            "age": 25
        });

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "Hi, Alice! You are 25 years old.");
    }

    #[test]
    fn test_render_with_undefined_variable() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "Hello, {{ missing_var }}!";
        let context = json!({
            "name": "World"
        });

        let result = adapter.render(template, &context);
        // MiniJinja by default renders undefined variables as empty strings
        // This test verifies the behavior but doesn't require error
        // (The actual behavior depends on MiniJinja configuration)
        if let Ok(rendered) = result {
            // If it renders successfully, undefined var should be empty or "undefined"
            assert!(rendered.contains("Hello,"));
        }
        // If it errors, that's also valid behavior depending on config
        // We just verify it doesn't panic
    }

    #[test]
    fn test_render_with_non_object_context() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "Hello!";

        // Try with array context
        let array_context = json!(["item1", "item2"]);
        let result = adapter.render(template, &array_context);
        assert!(result.is_err(), "Should fail with array context");
        if let Err(Error::TemplateContextConversion(msg)) = result {
            assert!(msg.contains("JSON object"));
        } else {
            panic!("Expected TemplateContextConversion error");
        }

        // Try with string context
        let string_context = json!("string");
        let result = adapter.render(template, &string_context);
        assert!(result.is_err(), "Should fail with string context");

        // Try with number context
        let number_context = json!(42);
        let result = adapter.render(template, &number_context);
        assert!(result.is_err(), "Should fail with number context");
    }

    #[test]
    fn test_render_empty_template() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "";
        let context = json!({});

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "");
    }

    #[test]
    fn test_render_no_variables() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "This is a plain text template.";
        let context = json!({});

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "This is a plain text template.");
    }

    #[test]
    fn test_render_with_filters() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "{{ name | upper }}";
        let context = json!({
            "name": "alice"
        });

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "ALICE");
    }

    #[test]
    fn test_render_with_conditionals() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "{% if enabled %}Yes{% else %}No{% endif %}";

        let context_true = json!({ "enabled": true });
        let result = adapter
            .render(template, &context_true)
            .expect("Rendering failed");
        assert_eq!(result, "Yes");

        let context_false = json!({ "enabled": false });
        let result = adapter
            .render(template, &context_false)
            .expect("Rendering failed");
        assert_eq!(result, "No");
    }

    #[test]
    fn test_render_with_loops() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "{% for item in items %}{{ item }},{% endfor %}";
        let context = json!({
            "items": ["a", "b", "c"]
        });

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "a,b,c,");
    }

    #[test]
    fn test_clone() {
        let engine = TemplateEngine::new();
        let adapter1 = TemplateRendererAdapter::new(engine);
        let adapter2 = adapter1.clone();

        // Verify both can render independently
        let template = "{{ msg }}";
        let context = json!({ "msg": "Hello" });

        let result1 = adapter1
            .render(template, &context)
            .expect("Rendering 1 failed");
        let result2 = adapter2
            .render(template, &context)
            .expect("Rendering 2 failed");

        assert_eq!(result1, "Hello");
        assert_eq!(result2, "Hello");
    }

    #[test]
    fn test_render_with_nested_objects() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        let template = "{{ user.name }} is {{ user.age }} years old";
        let context = json!({
            "user": {
                "name": "Bob",
                "age": 30
            }
        });

        let result = adapter
            .render(template, &context)
            .expect("Rendering failed");
        assert_eq!(result, "Bob is 30 years old");
    }

    #[test]
    fn test_error_conversion() {
        let engine = TemplateEngine::new();
        let adapter = TemplateRendererAdapter::new(engine);

        // Invalid template syntax
        let template = "{{ unclosed";
        let context = json!({});

        let result = adapter.render(template, &context);
        assert!(result.is_err());

        assert!(result.is_err(), "Expected template rendering error");
    }
}
