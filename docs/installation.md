# Installation

## From source

Requires the Rust toolchain (edition 2024, stable):

```bash
git clone https://github.com/YvanY0/guisu.git
cd guisu
cargo install --path crates/cli
```

The resulting binary is at `~/.cargo/bin/guisu`. Add `~/.cargo/bin` to your `$PATH` if it is not already.

## Binary releases

Pre-built binaries for macOS, Linux, and Windows are linked from the [releases page](https://github.com/YvanY0/guisu/releases) once they ship. Each release archives a static binary plus a SHA-256 checksum.

## Verifying the install

```bash
guisu --version
guisu info
```

The `info` command prints the resolved source directory, working tree, and destination directory so you can confirm Guisu sees your repository correctly. Add `--all` for build info, version, public keys, and configuration; add `--json` for machine-readable output.

!!! tip "Check the source dir"

    `guisu info` will print the **resolved** source dir, which is `.` if you run it inside a source repo, or `~/.local/share/guisu` if you do not. If the resolved value is not what you expect, fix it with `guisu init` or by setting `[general] src_dir` in your `.guisu.toml`.



## Next step

[Getting Started — init](getting-started/init.md).
