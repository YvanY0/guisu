//! Benchmarks for hash operations
//!
//! Tests the performance of blake3 hashing at various input sizes,
//! covering the hot paths in status/apply pipelines.
#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use guisu_engine::{hash_content, hash_file};
use std::io::Write;
use tempfile::NamedTempFile;

/// Benchmark `hash_content` with different input sizes
fn bench_hash_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_content");

    let sizes: &[(&str, usize)] = &[
        ("small_100B", 100),
        ("medium_10KB", 10 * 1024),
        ("large_1MB", 1024 * 1024),
    ];

    for (label, size) in sizes {
        let content = vec![0xAB; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &content, |b, data| {
            b.iter(|| hash_content(std::hint::black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark `hash_file` with a temporary file
fn bench_hash_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_file");

    for (label, size) in &[
        ("small_100B", 100),
        ("medium_10KB", 10 * 1024),
        ("large_1MB", 1024 * 1024),
    ] {
        let mut temp_file = NamedTempFile::new().expect("failed to create temp file");
        let content = vec![0xAB; *size];
        temp_file
            .write_all(&content)
            .expect("failed to write temp file");
        temp_file.flush().expect("failed to flush temp file");

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            temp_file.path(),
            |b, path| {
                b.iter(|| hash_file(std::hint::black_box(path)).expect("failed to hash file"));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_hash_content, bench_hash_file);
criterion_main!(benches);
