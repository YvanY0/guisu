//! Benchmark for template rendering performance
//!
//! Tests the performance of:
//! - Template function optimizations (trim, `trim_start`, `trim_end`)
//! - Regex cache with LRU eviction
//! - String allocation patterns
#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use guisu_template::{TemplateContext, TemplateEngine};
use indexmap::IndexMap;
use serde_json::json;

/// Benchmark trim functions with various input patterns
fn bench_trim_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("trim_functions");

    // Test cases: (name, input, should_trim)
    let long_no_trim = "a".repeat(1000);
    let long_with_trim = format!("  {}  ", "a".repeat(1000));
    let test_cases: [(&str, &str, bool); 6] = [
        ("no_whitespace", "hello_world", false),
        ("leading_space", "  hello", true),
        ("trailing_space", "hello  ", true),
        ("both_spaces", "  hello  ", true),
        ("long_no_trim", &long_no_trim, false),
        ("long_with_trim", &long_with_trim, true),
    ];

    for (name, input, _) in test_cases {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::new("trim", name), &input, |b, input| {
            let engine = TemplateEngine::new();
            let ctx = TemplateContext::new();
            let template = format!("{{{{ '{input}' | trim }}}}");
            b.iter(|| {
                black_box(
                    engine
                        .render_str(&template, &ctx)
                        .expect("template rendering failed"),
                );
            });
        });
    }

    group.finish();
}

/// Benchmark regex cache with LRU eviction
fn bench_regex_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_cache");

    let engine = TemplateEngine::new();
    let ctx = TemplateContext::new();

    // Test cache hits (same pattern repeated)
    group.bench_function("cache_hit_single_pattern", |b| {
        let template = r#"{{ regexMatch("test@example.com", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$") }}"#;
        b.iter(|| {
            engine.render_str(template, &ctx).expect("template rendering failed");
            black_box(());
        });
    });

    // Test cache with multiple patterns (within LRU size)
    group.bench_function("cache_hit_multiple_patterns", |b| {
        let templates = [
            r#"{{ regexMatch("123", "\\d+") }}"#,
            r#"{{ regexMatch("abc", "[a-z]+") }}"#,
            r#"{{ regexMatch("ABC", "[A-Z]+") }}"#,
            r#"{{ regexMatch("test@example.com", "^[a-zA-Z0-9._%+-]+@") }}"#,
        ];
        let mut idx = 0;
        b.iter(|| {
            let template = templates[idx % templates.len()];
            idx += 1;
            engine
                .render_str(template, &ctx)
                .expect("template rendering failed");
            black_box(());
        });
    });

    // Test cache eviction (patterns exceeding LRU size)
    group.bench_function("cache_eviction", |b| {
        // Generate 100 unique patterns (exceeds LRU cache size of 64)
        let templates: Vec<String> = (0..100)
            .map(|i| format!(r#"{{{{ regexMatch("test{i}", "test{i}") }}}}"#))
            .collect();
        let mut idx = 0;
        b.iter(|| {
            let template = &templates[idx % templates.len()];
            idx += 1;
            engine
                .render_str(template, &ctx)
                .expect("template rendering failed");
            black_box(());
        });
    });

    group.finish();
}

/// Benchmark complex template rendering
fn bench_template_rendering(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_rendering");

    let engine = TemplateEngine::new();

    // Simple variable substitution
    group.bench_function("simple_variables", |b| {
        let template = "Hello {{ name }}, you are {{ age }} years old!";
        let mut vars = IndexMap::new();
        vars.insert("name".to_string(), json!("Alice"));
        vars.insert("age".to_string(), json!(30));
        let ctx = TemplateContext::new().with_variables(vars);
        b.iter(|| {
            engine
                .render_str(template, &ctx)
                .expect("template rendering failed");
            black_box(());
        });
    });

    // Template with filters
    group.bench_function("with_filters", |b| {
        let template = "{{ name | trim | upper }}: {{ email | trim }}";
        let mut vars = IndexMap::new();
        vars.insert("name".to_string(), json!("  alice  "));
        vars.insert("email".to_string(), json!("alice@example.com  "));
        let ctx = TemplateContext::new().with_variables(vars);
        b.iter(|| {
            black_box(
                engine
                    .render_str(template, &ctx)
                    .expect("template rendering failed"),
            );
        });
    });

    // Template with conditionals
    group.bench_function("with_conditionals", |b| {
        let template = r"
            {% if enabled %}
                User {{ name }} is enabled
            {% else %}
                User {{ name }} is disabled
            {% endif %}
        ";
        let mut vars = IndexMap::new();
        vars.insert("enabled".to_string(), json!(true));
        vars.insert("name".to_string(), json!("Alice"));
        let ctx = TemplateContext::new().with_variables(vars);
        b.iter(|| {
            black_box(
                engine
                    .render_str(template, &ctx)
                    .expect("template rendering failed"),
            );
        });
    });

    // Template with loops
    group.bench_function("with_loops", |b| {
        let template = r"
            {% for item in items %}
                - {{ item | trim }}
            {% endfor %}
        ";
        let mut vars = IndexMap::new();
        vars.insert(
            "items".to_string(),
            json!(vec!["item1", "item2", "item3", "item4", "item5"]),
        );
        let ctx = TemplateContext::new().with_variables(vars);
        b.iter(|| {
            black_box(
                engine
                    .render_str(template, &ctx)
                    .expect("template rendering failed"),
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_trim_functions,
    bench_regex_cache,
    bench_template_rendering
);
criterion_main!(benches);
