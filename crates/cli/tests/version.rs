//! Integration tests that exercise the compiled `guisu` binary end-to-end.
//!
//! These use `pretty_assertions::assert_eq` rather than the std macro
//! so assertion failures print a coloured diff of expected vs actual,
//! which makes regressions in CLI output format much easier to triage.

#![allow(clippy::unwrap_used, clippy::panic)]

use assert_cmd::Command;
use pretty_assertions::assert_eq;
use serial_test::serial;

/// `guisu --version` should print "guisu <version>" matching the
/// workspace version. Pinning this guards against accidental version
/// drift between `Cargo.toml` and what `vergen` bakes into the binary.
#[test]
#[serial]
fn version_matches_workspace_version() {
    let expected_version = env!("CARGO_PKG_VERSION");

    let output = Command::cargo_bin("guisu")
        .expect("guisu binary should build")
        .arg("--version")
        .output()
        .expect("run --version");

    assert!(
        output.status.success(),
        "--version failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let actual = stdout.trim();

    assert_eq!(actual, format!("guisu {expected_version}"));
}

/// `guisu --help` should mention the binary's own name and a one-line
/// description; helps catch regressions in the clap derive layer
/// (e.g. `description = ""` accidentally getting removed).
#[test]
#[serial]
fn help_mentions_binary_name_and_description() {
    let output = Command::cargo_bin("guisu")
        .expect("guisu binary should build")
        .arg("--help")
        .output()
        .expect("run --help");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let help = stdout.to_lowercase();

    assert!(help.contains("guisu"), "--help should mention 'guisu'");
    assert!(
        help.contains("dotfile") || help.contains("config") || help.contains("manage"),
        "--help should describe what guisu does; got first 200 chars: {}",
        &stdout[..stdout.len().min(200)]
    );
}
