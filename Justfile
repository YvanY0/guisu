# Guisu Development Tasks

# List available commands
default:
    @just --list

# Run clippy with pedantic lints
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run tests
test:
    cargo test --workspace

# Analyze binary size (requires: cargo install cargo-bloat)
bloat:
    cargo bloat --release -n 10
    cargo bloat --release --crates

# Check for unused dependencies (requires: cargo install cargo-udeps --locked)
udeps:
    cargo +nightly udeps --workspace

# Build release binary
build:
    cargo build --release
    @ls -lh target/release/guisu | awk '{print $$5, $$9}'

# Clean build artifacts
clean:
    cargo clean

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run cargo check
check:
    cargo check --workspace --all-targets --all-features

# Release a patch version (0.2.1 -> 0.2.2).
# Bumps workspace.version, commits, pushes main, tags and pushes tag.
# The tag push triggers .github/workflows/release.yml (cargo-dist) which
# builds artifacts, publishes the GitHub Release, and updates the
# homebrew tap formula. See Cargo.toml [workspace.metadata.release].
release-patch:
    cargo release patch --execute --no-confirm

# Release a minor version (0.2.1 -> 0.3.0).
release-minor:
    cargo release minor --execute --no-confirm

# Release a major version (0.2.1 -> 1.0.0).
release-major:
    cargo release major --execute --no-confirm
