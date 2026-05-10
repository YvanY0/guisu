# Guisu (归宿)

> **Guisu** (归宿, pronounced "gwee-soo") — A haven for your dotfiles, inspired by the Chinese phrase meaning "home" or "destination". Just as 归宿 represents a place of belonging, Guisu provides a safe harbor for managing your configuration files across all your machines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)](#project-status)

**[中文文档 / Chinese Documentation](README-zh.md)**

**Early Development Notice**: Guisu is currently in early development (pre-1.0). APIs and features are subject to change. Production use is not recommended yet.

## What is Guisu?

Guisu is a **Rust-based dotfile manager** inspired by [chezmoi](https://www.chezmoi.io/), designed to help you manage your configuration files (dotfiles) across multiple machines with:

- **Blazing Fast**: Rust native binary with parallel processing
- **Secure by Default**: Built-in age encryption without external dependencies
- **Template-Based**: Powerful Jinja2-like templates via minijinja
- **Type-Safe**: Leverages Rust's type system to prevent runtime errors
- **Smart State Tracking**: Persistent state management using redb
- **Interactive Conflict Resolution**: Beautiful TUI for handling conflicts
- **Cross-Platform**: Works on macOS, Linux, and Windows

## Why Guisu?

| Feature | Guisu | Chezmoi | Advantage |
|---------|-------|---------|-----------|
| **Performance** | Native Rust | Go (with cgo) | 2-5x faster |
| **Binary Size** | ~3-5 MB | ~20 MB | 4x smaller |
| **Encryption** | Built-in only (age crate) | Built-in or external age | Simpler, no config needed |
| **Git** | Built-in only (git2) | Built-in or external git | Simpler, no config needed |
| **Database** | redb (pure Rust) | BoltDB (cgo) | Simpler build |
| **Type Safety** | Compile-time path types | Runtime checks | Fewer bugs |
| **Templates** | minijinja (Jinja2) | Go text/template | More familiar |

## Quick Start

### Installation

**From source** (requires Rust toolchain):

```bash
git clone https://github.com/PaulYuuu/guisu.git
cd guisu
cargo install --path crates/cli
```

**Binary releases**: Coming soon

### Initialize from GitHub

```bash
# Clone your dotfiles repository
guisu init username

# Or use full URL
guisu init https://github.com/username/dotfiles.git
```

### Initialize locally

```bash
# Create a new dotfiles repository
guisu init
```

## Basic Usage

### Add files to management

```bash
# Add a file
guisu add ~/.bashrc

# Add with encryption
guisu add --encrypt ~/.ssh/id_rsa

# Add entire directory
guisu add ~/.config/nvim
```

### Apply changes

```bash
# Apply all changes
guisu apply

# Interactive mode (resolve conflicts manually)
guisu apply --interactive

# Dry run (preview changes)
guisu apply --dry-run
```

### View status

```bash
# Show managed files status
guisu status

# Show differences
guisu diff

# Preview rendered content
guisu cat ~/.bashrc
```

### Edit files

```bash
# Edit source file (transparently handles encryption)
guisu edit ~/.bashrc

# Opens in your configured editor
```

### Update from repository

```bash
# Pull latest changes and apply
guisu update

# Pull without applying
guisu update --no-apply
```

### View system information

```bash
# Show basic status and validate configuration
guisu info

# Show detailed information (build info, versions, public keys, configuration)
guisu info --all

# Output in JSON format
guisu info --json
guisu info --all --json
```

### View template variables

```bash
# Show all variables (system, guisu, and user-defined)
guisu variables

# Show only builtin variables (system + guisu)
guisu variables --builtin

# Show only user-defined variables
guisu variables --user

# Output in JSON format
guisu variables --json
```

## Core Concepts

### Three-State Model

Guisu manages files through three distinct states:

```
Source State          Target State         Destination State
(Repository)          (After Processing)   (Actual Files)
     ↓                      ↓                     ↓
  .bashrc.j2     →     .bashrc (rendered)  →  ~/.bashrc
  key.txt.age    →     key.txt (decrypted) →  ~/key.txt
```

**Persistent State** (redb database) tracks what was last applied to detect external changes.

### File Attributes

Guisu uses filename extensions to encode file attributes. Source and destination filenames are the same, except for special extensions:

```bash
# Template files (rendered with Jinja2)
.bashrc.j2                       → ~/.bashrc (rendered)

# Encrypted files (age encryption)
private_key.age                  → private_key (decrypted)

# Combined: template + encryption
.bashrc.j2.age                   → ~/.bashrc (decrypted, then rendered)

# Regular files (no transformation)
.bashrc                          → ~/.bashrc
.ssh/config                      → ~/.ssh/config
scripts/deploy.sh                → scripts/deploy.sh
```

### Templates

Guisu uses **minijinja** (Jinja2-compatible) for templates:

```jinja2
# ~/.local/share/guisu/.bashrc.j2

# Platform-specific configuration
{% if os == "darwin" %}
export HOMEBREW_PREFIX="/opt/homebrew"
alias ls="gls --color=auto"
{% elif os == "linux" %}
alias ls="ls --color=auto"
{% endif %}

# User variables
export EDITOR="{{ editor }}"
export EMAIL="{{ email }}"

# Secrets from Bitwarden
export GITHUB_TOKEN="{{ bitwarden("GitHub").login.password }}"
# Or use bitwardenFields for custom fields
export API_KEY="{{ bitwardenFields("GitHub", "APIKey") }}"
```

### Configuration

Create `.guisu.toml` in your dotfiles repository:

```toml
[general]
color = true
progress = true
editor = "nvim"

[age]
identity = "~/.config/guisu/key.txt"
derive = true  # Derive public key from identity for encryption

[bitwarden]
provider = "rbw"  # or "bw"

[variables]
email = "user@example.com"
editor = "nvim"

[ignore]
# Files/directories to exclude from guisu management (not a .gitignore replacement)
global = [".git", ".DS_Store"]
darwin = ["Thumbs.db"]
linux = ["*~"]
```

## Advanced Features

### Encryption

```bash
# Generate age identity
guisu age generate -o ~/.config/guisu/key.txt

# Add encrypted file
guisu add --encrypt ~/.ssh/id_rsa

# Edit encrypted file (automatic decryption)
guisu edit ~/.ssh/id_rsa
```

### Platform-Specific Variables

Organize variables in `.guisu/variables/` directory:

```
.guisu/variables/
├── user.toml               # Global user variables
├── visual.toml             # UI/appearance settings
├── darwin/
│   ├── git.toml           # macOS-specific git config
│   └── terminal.toml      # macOS-specific terminal
└── linux/
    ├── git.toml           # Linux-specific git config
    └── terminal.toml      # Linux-specific terminal
```

### Interactive Conflict Resolution

When local files differ from your dotfiles:

```bash
guisu apply --interactive
```

Beautiful TUI shows:
- Side-by-side diff
- Three-way comparison (Source, Target, Destination, Database)
- Options: Overwrite, Skip, View Diff, Preview

## Project Status

### Implemented Features

- File management (files, directories, symlinks)
- Template processing (minijinja, ~30 functions)
- Age encryption (file + inline)
- Git integration (clone, pull, push)
- Interactive conflict resolution (TUI)
- Persistent state tracking (redb)
- Parallel processing (rayon)
- Platform-specific configuration
- Bitwarden integration (bw, rbw, bws)
- **Hooks system** (pre/post scripts with mode: always/once/onchange)
- **Modify file type** (`modify_*` prefix for in-place modification)
- **Remove file type** (`remove_*` prefix)

### Missing Features vs Chezmoi

**High Priority**:
- External resources (`.chezmoiexternal` equivalent)
- Create-only files (`create_*` prefix)
- Limited password manager support (only Bitwarden; missing 1Password, LastPass, Pass, Vault, etc.)
- Limited template functions (~30 vs 200+ in chezmoi)

**Medium Priority**:
- Missing commands: `doctor`, `unmanaged`, `re-add`, `archive`, `verify`, `merge`

See [ROADMAP.md](docs/development/ROADMAP.md) for detailed development plan.

## Documentation

- [Architecture Overview](docs/architecture/containers.md) - System architecture and design
- [Container Architecture](docs/architecture/containers.md) - Crate structure
- [Component Design](docs/architecture/components.md) - Internal components
- [Data Flow](docs/architecture/data-flow.md) - Processing pipeline
- [Contributing Guide](docs/development/CONTRIBUTING.md) - How to contribute
- [Roadmap](docs/development/ROADMAP.md) - Feature roadmap

## Contributing

Guisu is in early development and welcomes contributions! Please see [CONTRIBUTING.md](docs/development/CONTRIBUTING.md) for:

- Development setup
- Code structure
- Testing guidelines
- Pull request process

## Inspiration

Guisu is heavily inspired by [chezmoi](https://www.chezmoi.io/), with the goal of providing similar functionality in a Rust-native package.

## License

MIT License - see [LICENSE](LICENSE) for details.
