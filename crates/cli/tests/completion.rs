//! Integration tests for the `guisu completion` subcommand

#![allow(clippy::unwrap_used, clippy::panic)]

use assert_cmd::Command;
use serial_test::serial;

#[test]
#[serial]
fn completion_bash_emits_register_line() {
    let output = Command::cargo_bin("guisu")
        .expect("guisu binary should build")
        .args(["completion", "bash"])
        .output()
        .expect("run completion bash");

    assert!(
        output.status.success(),
        "exit non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("complete -F"),
        "bash completion should contain 'complete -F' directive; got {} bytes",
        stdout.len()
    );
}

#[test]
#[serial]
fn completion_zsh_emits_compdef() {
    let output = Command::cargo_bin("guisu")
        .expect("guisu binary should build")
        .args(["completion", "zsh"])
        .output()
        .expect("run completion zsh");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("#compdef guisu"),
        "zsh completion should contain '#compdef guisu'; got {} bytes",
        stdout.len()
    );
}

#[test]
#[serial]
fn completion_fish_emits_complete_line() {
    let output = Command::cargo_bin("guisu")
        .expect("guisu binary should build")
        .args(["completion", "fish"])
        .output()
        .expect("run completion fish");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("complete -c guisu"),
        "fish completion should contain 'complete -c guisu'; got {} bytes",
        stdout.len()
    );
}

#[test]
#[serial]
fn completion_rejects_unknown_shell() {
    Command::cargo_bin("guisu")
        .expect("guisu binary should build")
        .args(["completion", "notashell"])
        .assert()
        .failure();
}
