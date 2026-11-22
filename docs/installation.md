# Installation

## Nix (without flakes)

The `guisu` package builds from GitHub's `main` branch using `Cargo.lock`.
No flakes or local checkout are needed. Use Nixpkgs with Rust 1.96 or newer
(for example, `nixos-unstable`). The examples work once the package definition
lands on `main`.

### NixOS system-wide

Add `guisuPackages.guisu` to your existing `environment.systemPackages`:

```nix
{ pkgs, ... }:
let
  guisuRepo = builtins.fetchTarball
    "https://github.com/YvanY0/guisu/archive/refs/heads/main.tar.gz";
  guisuPackages = import "${guisuRepo}/default.nix" { inherit pkgs; };
in
{
  environment.systemPackages = [ guisuPackages.guisu ];
}
```

This uses the `pkgs` already supplied by your NixOS configuration. Apply the
configuration with `sudo nixos-rebuild switch` and run `guisu --version`.
The branch is not pinned: Nix picks up changes to `main` when it refreshes
its tarball cache.

### User profile or local build

Use the same GitHub `main` branch URL:

```sh
repo='https://github.com/YvanY0/guisu/archive/refs/heads/main.tar.gz'
nix-env -f "$repo" -iA guisu   # install into your user profile
```

To build without installing into a profile:

```sh
nix-build "$repo" -A guisu
./result/bin/guisu --version
```

These commands use `<nixpkgs>` from your Nix search path. If it is not set,
add `-I nixpkgs=/path/to/nixpkgs`, pointing to a suitable Nixpkgs checkout.

## From source

Requires the Rust toolchain (edition 2024, stable):

```bash
git clone https://github.com/YvanY0/guisu.git
cd guisu
cargo install --path crates/cli
```

The resulting binary is at `~/.cargo/bin/guisu`. Add `~/.cargo/bin` to your `$PATH` if it is not already.

## Binary releases

Pre-built binaries for macOS, Linux, and Windows are available on the
[releases page](https://github.com/YvanY0/guisu/releases) with SHA-256 checksums.
On NixOS, use the source package above instead of running the Linux release
binary directly.

## Verifying the install

```bash
guisu --version
guisu info
```

The `info` command prints the resolved source directory, working tree, and destination directory so you can confirm Guisu sees your repository correctly. Add `--all` for build info, version, public keys, and configuration; add `--json` for machine-readable output.

!!! tip "Check the source dir"

    `guisu info` will print the **resolved** source dir, which is `.` if you run it inside a source repo, or `~/.local/share/guisu` if you do not. If the resolved value is not what you expect, fix it with `guisu init` or by setting `[general] srcDir` in your `.guisu.toml`.

## Shell completion

Load the completion script for your shell with `eval`:

```sh
eval "$(guisu completion zsh)"   # zsh
eval "$(guisu completion bash)"  # bash
eval "$(guisu completion fish)"  # fish
```

This works immediately but does not persist across shells. To make it permanent,
add the matching line to `~/.zshrc`, `~/.bashrc`, or `~/.config/fish/config.fish`
respectively. The script is generated from the clap derive tree, so adding or
removing subcommands requires no manual maintenance.

## Next step

[Getting Started — init](getting-started/init.md).
