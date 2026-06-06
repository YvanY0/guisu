//! Benchmarks for state building and processing
//!
//! These benchmarks measure the performance of hot paths in guisu:
//! - Source state reading (file I/O + attribute parsing)
//! - Target state building (template rendering + processing)
//! - Destination state reading (file metadata queries)

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use tempfile::TempDir;

/// Create a test repository with N files
fn create_test_repo(num_files: usize) -> TempDir {
    let temp = TempDir::new().expect("Failed to create temp directory");
    let source = temp.path().join("source");
    std::fs::create_dir_all(&source).expect("Failed to create source directory");

    // Create various file types
    for i in 0..num_files {
        let filename = match i % 4 {
            0 => format!("file_{i}.txt"),
            1 => format!(".config_{i}"),   // Dotfile
            2 => format!("data_{i}.json"), // Regular file
            3 => format!("script_{i}.sh"), // Script file
            _ => unreachable!(),
        };

        let content = format!("Content for file {i}\n");
        std::fs::write(source.join(&filename), content)
            .unwrap_or_else(|_| panic!("Failed to write file: {filename}"));
    }

    temp
}

/// Benchmark source state reading
fn bench_source_state_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_state_read");

    for size in &[10, 50, 100, 500] {
        let temp = create_test_repo(*size);
        let source = temp.path().join("source");

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &source,
            |b, source_path| {
                b.iter(|| {
                    // This would call SourceState::read
                    // For now, just measure file walking
                    let count = walkdir::WalkDir::new(std::hint::black_box(source_path))
                        .into_iter()
                        .filter_map(Result::ok)
                        .filter(|e| e.file_type().is_file())
                        .count();
                    std::hint::black_box(count)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark attribute parsing (hot path in source state reading)
fn bench_attribute_parsing(c: &mut Criterion) {
    use guisu_engine::attr::FileAttributes;

    // Test cases: (filename, optional mode)
    // Guisu uses actual filenames (like .bashrc) not prefixes (like dot_bashrc)
    // Attributes come from file extensions (.j2, .age) and Unix permissions (mode)
    let test_cases = vec![
        (".bashrc", None),
        (".ssh", Some(0o700)),      // Private directory
        ("script.sh", Some(0o755)), // Executable script
        ("config.toml.j2", None),   // Template file
        ("key.age", Some(0o600)),   // Encrypted private file
        (".config", None),
        (".vimrc", None),
        ("README.md", None),
    ];

    c.bench_function("attribute_parsing", |b| {
        b.iter(|| {
            for (filename, mode) in &test_cases {
                let _ = FileAttributes::parse_from_source(filename, *mode);
                std::hint::black_box(filename);
            }
        });
    });
}

/// Benchmark path operations (very hot path)
fn bench_path_operations(c: &mut Criterion) {
    use guisu_core::path::{AbsPath, RelPath};

    let base =
        AbsPath::new("/home/user/.local/share/guisu".into()).expect("Failed to create AbsPath");
    let rel = RelPath::new(".config/nvim/init.lua".into()).expect("Failed to create RelPath");

    c.bench_function("path_join", |b| {
        b.iter(|| {
            let joined = std::hint::black_box(&base).join(std::hint::black_box(&rel));
            std::hint::black_box(joined)
        });
    });
}

// Allow missing docs for criterion-generated code
#[allow(missing_docs)]
#[allow(clippy::wildcard_imports)]
mod bench_groups {
    use super::*;

    criterion_group!(
        benches,
        bench_source_state_read,
        bench_attribute_parsing,
        bench_path_operations,
    );
}

criterion_main!(bench_groups::benches);
