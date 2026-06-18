# Code Patterns

This file documents recurring patterns and conventions used in the codebase.

## Error Handling

```rust
// Use anyhow::Context for fallible I/O
let content = fs::read_to_string(path)
    .context(format!("Failed to read {}", path.display()))?;
```

## Newtype Wrappers

```rust
// Use newtype for type-safe paths
pub struct AbsPath(PathBuf);

impl AbsPath {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
}
```

## Module Visibility

- Internal modules: `pub(crate)`
- Public API: `pub` at crate root, re-exported from `lib.rs`

## Testing

- Complex logic → write `#[test]` first
- Bug fix → write a test that reproduces the bug before fixing
- Use `tempfile::TempDir` for filesystem tests

## Last Updated

<!-- Auto-updated by memory system -->
