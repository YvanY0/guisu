//! Logging configuration for guisu CLI
//!
//! Provides beautiful terminal output and optional file logging using tracing.

use anyhow::Result;
use std::path::Path;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the logging system
///
/// # Arguments
/// * `verbose` - Enable debug/trace level logging
/// * `log_file` - Optional path to write logs to a file
///
/// # Errors
///
/// Returns an error if:
/// - The log file cannot be created or opened for writing
/// - The tracing subscriber fails to initialize
///
/// # Panics
///
/// Panics if:
/// - The default environment filter cannot be created (hardcoded filter string is invalid)
/// - The hardcoded "debug" filter string is invalid for file logging
///
/// These panics should never happen as the filter strings are validated at compile time.
pub fn init(verbose: bool, log_file: Option<&Path>) -> Result<()> {
    // Determine log level based on verbose flag
    let level = if verbose { "debug" } else { "info" };

    // Create environment filter
    // Allows overriding with RUST_LOG env var
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| {
            EnvFilter::try_new(format!(
                "guisu={level},engine={level},crypto={level},template={level}"
            ))
        })
        .expect("failed to create default env filter");

    // Build different subscribers based on verbose mode and log file
    match (verbose, log_file) {
        (true, Some(log_path)) => {
            // Verbose mode with file logging
            let stdout_layer = fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .compact()
                .with_ansi(true)
                .with_filter(env_filter);

            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)?;

            let file_layer = fmt::layer()
                .with_writer(file)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .pretty()
                .with_filter(EnvFilter::try_new("debug").expect("'debug' is a valid filter"));

            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
        (true, None) => {
            // Verbose mode without file logging
            let stdout_layer = fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .compact()
                .with_ansi(true)
                .with_filter(env_filter);

            tracing_subscriber::registry().with(stdout_layer).init();
        }
        (false, Some(log_path)) => {
            // Normal mode with file logging
            let stdout_layer = fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .without_time() // No timestamps in normal mode
                .compact()
                .with_ansi(true)
                .with_filter(env_filter);

            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)?;

            let file_layer = fmt::layer()
                .with_writer(file)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .pretty()
                .with_filter(EnvFilter::try_new("debug").expect("'debug' is a valid filter"));

            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
        (false, None) => {
            // Normal mode without file logging
            let stdout_layer = fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .without_time() // No timestamps in normal mode
                .compact()
                .with_ansi(true)
                .with_filter(env_filter);

            tracing_subscriber::registry().with(stdout_layer).init();
        }
    }

    Ok(())
}
