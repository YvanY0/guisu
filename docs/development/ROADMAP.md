# Guisu Development Roadmap

This document outlines the development roadmap for Guisu, organized by priority and target quarters.

**Current Status**: Active Development (v0.1.x)
**Target v1.0**: TBD (roadmap dates need refresh)

### Priority Legend

- **P0 (Critical)**: Blocking v1.0 release
- **P1 (High)**: Important for feature parity
- **P2 (Medium)**: Nice to have
- **P3 (Low)**: Future enhancements

---

### Q1 2025 (January - March): Core Features

#### P0: Script Execution System

**Status**: Completed ✅ (Implemented as Hooks System)
**Effort**: 4-6 weeks
**Owner**: Implemented

**Description**: Implemented as the Hooks System with directory-based structure under `.guisu/hooks/`.

**Implementation**:
- Pre/post hook directories (`pre/`, `post/`)
- Execution modes: `always`, `once`, `onchange`
- Platform filtering
- Template rendering in hook commands
- Parallel execution with rayon

**Migration from chezmoi**:
```bash
# chezmoi
.run_before_10-install-packages.sh.tmpl

# guisu
.guisu/hooks/pre/10-install-packages.sh.j2
```

---

#### P0: Doctor Command

**Status**: Partially Implemented ⚠️ (`info` command exists, full diagnostics planned)
**Effort**: 1 week
**Owner**: TBD

**Description**: Implement system diagnostics command to verify installation and configuration.

**Tasks**:
- [ ] Check guisu version
- [ ] Verify configuration file
- [ ] Check age identity files
- [ ] Verify git repository
- [ ] Test vault provider availability
- [ ] Check template engine
- [ ] Verify persistent state database
- [ ] Display summary report

**Acceptance Criteria**:
- Clear diagnostic output
- Identifies common issues
- Suggests fixes for problems

---

#### P1: Template Functions Expansion (Phase 1)

**Status**: ~80% Complete (16/20 functions + blake3 as alternative to SHA)
**Effort**: 2-3 weeks
**Owner**: Implemented (partial)

**Description**: Add 20 most commonly used template functions from chezmoi.

**Tasks**:
- [x] File operations (2/5 functions)
  - [x] `include(path)` - Include file contents
  - [x] `includeTemplate(path)` - Include and render
  - [ ] `readFile(path)` - Read arbitrary file
  - [ ] `glob(pattern)` - Match file patterns
  - [ ] `stat(path)` - File information
- [x] Data formats (4/4 functions)
  - [x] `toJson(value)` - Convert to JSON
  - [x] `fromJson(string)` - Parse JSON
  - [x] `toToml(value)` - Convert to TOML
  - [x] `fromToml(string)` - Parse TOML
- [ ] String processing (4/5 functions)
  - [x] `regexMatch(pattern, string)` - Regex matching
  - [x] `regexReplaceAll(pattern, replacement, string)` - Regex replacement
  - [x] `split(separator, string)` - String splitting
  - [x] `join(separator, array)` - String joining
  - [ ] `base64Encode/Decode(string)` - Base64 encoding/decoding
- [x] Encryption (alternative implementation)
  - [x] `blake3sum(content)` - Compute BLAKE3 (faster, more secure than SHA)
  - [x] `encrypt(value)` - Encrypt with age
  - [x] `decrypt(value)` - Decrypt with age
  - Note: SHA variants not implemented; blake3sum is the preferred hash function

**Acceptance Criteria**:
- All functions working correctly
- Comprehensive tests
- Documentation with examples

---

### Q2 2025 (April - June): High-Value Features

#### P0: External Resources System

**Status**: Not Started
**Effort**: 3-4 weeks
**Owner**: TBD

**Description**: Implement `.guisu.external.toml` for downloading and managing external files/archives.

**Tasks**:
- [ ] Design ExternalConfig data structure
- [ ] Implement HTTP client with caching
- [ ] Add archive extraction support (tar.gz, zip)
- [ ] Implement refresh logic (time-based)
- [ ] Add checksum verification
- [ ] Add file type support
- [ ] Add archive type support with filters
- [ ] Integrate into apply pipeline
- [ ] Add configuration examples
- [ ] Write tests

**Acceptance Criteria**:
- Can download files from URLs
- Can extract archives with filtering
- Respects refresh periods
- Verifies checksums
- Updates persistent state

**Example Usage**:
```toml
# .guisu.external.toml
[".oh-my-zsh"]
    type = "archive"
    url = "https://github.com/ohmyzsh/ohmyzsh/archive/master.tar.gz"
    stripComponents = 1
    refreshPeriod = "168h"

["bin/kubectl"]
    type = "file"
    url = "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"
    executable = true
```

---

#### P0: Modify File Type

**Status**: Completed ✅
**Effort**: 2 weeks
**Owner**: Implemented

**Description**: Implemented as `modify_*` prefix for in-place file modification.

**Implementation**:
- `modify_*` prefix parsed in `attr.rs`
- `ModifyExecutor` in `engine/modify.rs`
- Target file path passed via `$GUISU_TARGET` env var
- Script interpreter auto-detected from shebang

**Usage**:
```bash
# Source: modify_config.toml → Target: config.toml (modified in place)
# Script receives target path and modifies file contents
```

---

#### P1: Password Manager Expansion

**Status**: Not Started
**Effort**: 4 weeks (1 week per provider)
**Owner**: TBD

**Description**: Add support for major password managers.

**Priority Order**:
1. **1Password** (High - very popular)
   - CLI: `op`
   - Functions: `onepasswordRead`, `onepasswordDocument`
2. **Pass** (High - Unix standard)
   - CLI: `pass`
   - Functions: `pass(path)`
3. **System Keychain** (Medium)
   - macOS: `security`
   - Linux: `secret-tool`
   - Functions: `keychain(service, account)`
4. **HashiCorp Vault** (Medium - enterprise)
   - CLI: `vault`
   - Functions: `vault(path)`

**Tasks per Provider**:
- [ ] Implement provider trait
- [ ] Add CLI command execution
- [ ] Parse JSON responses
- [ ] Add caching support
- [ ] Register template functions
- [ ] Add feature flag
- [ ] Write tests
- [ ] Document usage

---

#### P1: Unmanaged Command

**Status**: Not Started
**Effort**: 1 week
**Owner**: TBD

**Description**: List files in destination that aren't managed by guisu.

**Tasks**:
- [ ] Build set of managed paths
- [ ] Walk destination directory
- [ ] Filter managed files
- [ ] Apply ignore patterns
- [ ] Display unmanaged files
- [ ] Add filtering options
- [ ] Write tests

---

#### ~~P1: Re-add Command~~ — Covered by `add --force`

**Status**: Not Needed
**Description**: The `add --force` flag already overwrites source with destination content. Templates and encryption flags compose with `--force`. No separate command is needed.

---

### Q3 2025 (July - September): Quality & Completeness

#### P1: Template Functions Expansion (Phase 2)

**Status**: Not Started
**Effort**: 3-4 weeks
**Owner**: TBD

**Description**: Add remaining commonly used template functions.

**Tasks**:
- [ ] Git integration (5 functions)
  - [ ] `gitHead()` - Current commit
  - [ ] `gitBranch()` - Current branch
  - [ ] `gitStatus()` - Working tree status
  - [ ] `gitTag()` - Latest tag
  - [ ] `gitRemote()` - Remote URL
- [ ] System info (5 functions)
  - [ ] `kernel()` - Kernel version
  - [ ] `kernelVersion()` - Kernel version number
  - [ ] `osRelease()` - OS release info
  - [ ] `cpuCores()` - CPU core count
  - [ ] `timezone()` - System timezone
- [ ] Advanced filters (10 functions)
  - [ ] `indent(n)` - Indent text
  - [ ] `nindent(n)` - Indent with newline
  - [ ] `trim(chars)` - Trim characters
  - [ ] `replace(old, new)` - String replacement
  - [ ] `default(value)` - Default value
  - [ ] `empty()` - Check if empty
  - [ ] `list()` - Create list
  - [ ] `dict()` - Create dictionary
  - [ ] `merge()` - Merge dictionaries
  - [ ] `keys()` - Dictionary keys

---

#### P2: Archive Command

**Status**: Not Started
**Effort**: 1 week
**Owner**: TBD

**Description**: Create tar/zip archives of managed files.

**Tasks**:
- [ ] Collect managed files
- [ ] Support tar.gz format
- [ ] Support zip format
- [ ] Include/exclude filters
- [ ] Preserve permissions
- [ ] Write tests

---

#### P2: Verify Command

**Status**: Not Started
**Effort**: 1 week
**Owner**: TBD

**Description**: Verify all files match expected state.

**Tasks**:
- [ ] Read target state
- [ ] Read destination state
- [ ] Compare all files
- [ ] Report mismatches
- [ ] Return exit code
- [ ] Write tests

---

#### P2: Merge Command

**Status**: Not Started
**Effort**: 2 weeks
**Owner**: TBD

**Description**: Three-way merge tool for resolving conflicts.

**Tasks**:
- [ ] Implement three-way merge algorithm
- [ ] Create merge UI
- [ ] Handle conflicts
- [ ] Update files
- [ ] Write tests

---

### Q4 2025 (October - December): Polish & v1.0

#### P0: Documentation

**Status**: In Progress
**Effort**: Ongoing
**Owner**: Current

**Tasks**:
- [x] Architecture documentation
- [x] C4 model diagrams
- [x] Data flow documentation
- [x] Contributing guide
- [x] Roadmap
- [ ] User guide
- [ ] Tutorial
- [ ] API documentation (rustdoc)
- [ ] Migration guide (from chezmoi)

---

#### P0: Testing & Quality

**Status**: Ongoing
**Effort**: Ongoing
**Owner**: All

**Tasks**:
- [ ] Increase unit test coverage (target: 80%)
- [ ] Add integration tests
- [ ] Add property-based tests
- [ ] Performance benchmarks
- [ ] Memory profiling
- [ ] Security audit
- [ ] Fuzzing

---

#### P1: Windows Support

**Status**: Not Started
**Effort**: 2-3 weeks
**Owner**: TBD

**Description**: Improve Windows compatibility.

**Tasks**:
- [ ] Test on Windows
- [ ] Handle Windows paths
- [ ] Handle Windows permissions
- [ ] Handle line endings
- [ ] Add Windows-specific ignores
- [ ] CI/CD for Windows
- [ ] Documentation for Windows users

---

#### P2: Performance Optimization

**Status**: Ongoing
**Effort**: 2-3 weeks
**Owner**: TBD

**Tasks**:
- [ ] Profile hot paths
- [ ] Optimize file I/O
- [ ] Optimize template rendering
- [ ] Optimize database operations
- [ ] Reduce memory allocations
- [ ] Benchmark against chezmoi
- [ ] Document performance characteristics

---

#### P3: Create File Type

**Status**: Not Started
**Effort**: 1 week
**Owner**: TBD

**Description**: Implement `create_*` prefix for create-only files.

**Tasks**:
- [ ] Add Create entry type
- [ ] Check if file exists
- [ ] Create only if missing
- [ ] Skip if exists
- [ ] Write tests

---

### Future (Post v1.0)

#### Plugin System

**Status**: Research
**Effort**: TBD
**Owner**: TBD

**Description**: WASM-based plugin system for extensibility.

**Possible Features**:
- Custom template functions
- Custom entry types
- Custom vault providers
- Custom template loaders

---

#### Distributed State

**Status**: Research
**Effort**: TBD
**Owner**: TBD

**Description**: Multi-machine state synchronization.

**Research Topics**:
- Conflict-free replicated data types (CRDTs)
- Eventually consistent state
- P2P synchronization
- Central state server

---

#### GUI/TUI

**Status**: Research
**Effort**: TBD
**Owner**: TBD

**Description**: Graphical user interface or full-screen TUI.

**Possible Features**:
- File browser
- Diff viewer
- Configuration editor
- Template editor

---

### Release Schedule

| Version | Target Date | Key Features | Status |
|---------|------------|--------------|--------|
| v0.2.0 | Q1 2025 | Script execution, doctor command | Hooks ✅, Doctor ❌ |
| v0.3.0 | Q2 2025 | External resources, modify files, 1Password | Modify ✅, External ❌, 1Password ❌ |
| v0.4.0 | Q3 2025 | Remaining template functions, more commands | Phase 1 ~80% ✅, Phase 2 ❌ |
| v0.5.0 | TBD | Polish, testing, documentation | — |
| v1.0.0 | TBD | Stable release | — |

---

### How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

**High-Impact Areas**:
1. External resources system (P0)
2. Doctor command (P0)
3. Password manager integrations (P1)
4. Template functions phase 2 (P1)
5. Testing and documentation (P0)

**Good First Issues**:
- Add template functions (start with simple ones)
- Improve error messages
- Add tests
- Fix documentation typos

