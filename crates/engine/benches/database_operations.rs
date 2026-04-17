//! Benchmark for database operations
//!
//! Tests the performance of:
//! - Batch database transactions
//! - Single entry saves
//! - Database reads
#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use guisu_engine::database::{get_entry_state, save_entry_state, save_entry_states_batch};
use guisu_engine::state::RedbPersistentState;

use tempfile::TempDir;

/// Helper to create a temporary database
fn create_temp_db() -> (TempDir, RedbPersistentState) {
    let temp_dir = TempDir::new().expect("failed to create temp directory");
    let db_path = temp_dir.path().join("test.db");
    let db = RedbPersistentState::new(&db_path).expect("failed to create database");
    (temp_dir, db)
}

/// Benchmark single entry saves vs batch saves
#[allow(clippy::cast_sign_loss)]
fn bench_save_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("save_operations");

    // Benchmark single entry save
    group.bench_function("single_entry_save", |b| {
        let (_temp_dir, db) = create_temp_db();
        let content = b"test content";
        let mut counter = 0;
        b.iter(|| {
            let path = format!("file_{counter}.txt");
            counter += 1;
            save_entry_state(&db, &path, content, Some(0o644)).expect("failed to save entry");
            black_box(());
        });
    });

    // Benchmark batch saves with different sizes
    for batch_size in [10, 50, 100, 500] {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_save", batch_size),
            &batch_size,
            |b, &size| {
                let (_temp_dir, db) = create_temp_db();
                let content = b"test content";
                b.iter(|| {
                    let entries: Vec<_> = (0..size)
                        .map(|i| (format!("file_{i}.txt"), content.to_vec(), Some(0o644)))
                        .collect();
                    save_entry_states_batch(&db, &entries).expect("failed to save batch");
                    black_box(());
                });
            },
        );
    }

    group.finish();
}

/// Benchmark database read operations
fn bench_read_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_operations");

    // Setup: create database with 1000 entries
    let (_temp_dir, db) = create_temp_db();
    let content = b"test content";
    let entries: Vec<_> = (0..1000)
        .map(|i| (format!("file_{i}.txt"), content.to_vec(), Some(0o644)))
        .collect();
    save_entry_states_batch(&db, &entries).expect("failed to save batch");

    // Benchmark single entry read
    group.bench_function("single_entry_read", |b| {
        let mut counter = 0;
        b.iter(|| {
            let path = format!("file_{}.txt", counter % 1000);
            counter += 1;
            get_entry_state(&db, &path).expect("failed to get entry");
            black_box(());
        });
    });

    // Benchmark reading missing entries
    group.bench_function("missing_entry_read", |b| {
        b.iter(|| {
            get_entry_state(&db, "nonexistent.txt").expect("failed to get entry");
            black_box(());
        });
    });

    group.finish();
}

/// Benchmark mixed read/write workload
fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_workload");

    group.bench_function("read_write_mixed", |b| {
        let (_temp_dir, db) = create_temp_db();
        let content = b"test content";
        let mut counter = 0;

        b.iter(|| {
            // Write 10 entries
            let entries: Vec<_> = (0..10)
                .map(|i| {
                    let idx = counter + i;
                    (format!("file_{idx}.txt"), content.to_vec(), Some(0o644))
                })
                .collect();
            save_entry_states_batch(&db, &entries).expect("failed to save batch");

            // Read 5 entries
            for i in 0..5 {
                let idx = counter + i;
                let path = format!("file_{idx}.txt");
                get_entry_state(&db, &path).expect("failed to get entry");
                black_box(());
            }

            counter += 10;
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_save_operations,
    bench_read_operations,
    bench_mixed_workload
);
criterion_main!(benches);
