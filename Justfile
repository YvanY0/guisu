# Guisu Development Tasks

# List available commands
default:
    @just --list

# Run clippy with pedantic lints
clippy:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Run tests
test:
    cargo test --workspace

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

# Build the docs site into site/ (strict mode catches broken links).
docs-build:
	uvx --from zensical zensical build --strict
	# Generate llms.txt + llms-full.txt so LLM tools can fetch guisu docs
	# as plain markdown. Re-run whenever you add/change a doc page.
	uvx --from llmstxt-standalone llmstxt-standalone build --site-dir site/

# Serve the docs site at http://localhost:3000 with live reload.
docs-serve:
	uvx --from zensical zensical serve -a 127.0.0.1:3000
