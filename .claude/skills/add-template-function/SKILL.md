---
name: add-template-function
description: Add a new template function or filter to guisu's minijinja template engine. Use when extending the template engine's built-in functions.
---

# Add a Template Function or Filter

## Architecture

Template functions live in `crates/template/src/functions/`. The engine registers them in `template/src/engine.rs` lines 121-185.

Two types:
- **Function**: `{{ funcName(args) }}` — returns a value
- **Filter**: `{{ value | filterName }}` — transforms a value

## Steps

### 1. Implement the function

Add to the appropriate module in `template/src/functions/`:

| Module | Purpose |
|--------|---------|
| `system.rs` | OS, arch, hostname, env, paths |
| `strings.rs` | Trim, regex, split, join, quote |
| `data.rs` | JSON, TOML conversion |
| `files.rs` | File inclusion |
| `crypto.rs` | Hash, encrypt, decrypt |
| `vault.rs` | Bitwarden integration |

Function signature:
```rust
pub fn my_func(args: &[Value]) -> Result<Value, Error> {
    // Validate args
    let arg = args.first()
        .ok_or_else(|| Error::new(ErrorKind::MissingArgument, "missing arg"))?;
    // ... logic
    Ok(Value::from(result))
}
```

Filter signature:
```rust
pub fn my_filter(value: &Value, args: &[Value]) -> Result<Value, Error> {
    let input = value.as_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "expected string"))?;
    // ... transform
    Ok(Value::from(result))
}
```

### 2. Register in engine.rs

In `template/src/engine.rs`, find `register_functions()` (~line 121):

```rust
// Function
engine.add_function("myFunc", functions::my_module::my_func);

// Filter
engine.add_filter("myFilter", functions::my_module::my_filter);
```

### 3. Re-export in mod.rs

Add to `template/src/functions/mod.rs`:
```rust
pub mod my_module;
```

### 4. Add tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::Environment;

    #[test]
    fn test_my_func() {
        let result = my_func(&[Value::from("input")]).unwrap();
        assert_eq!(result.as_str().unwrap(), "expected");
    }
}
```

## Reference

- `template/src/functions/` — existing function implementations
- `template/src/engine.rs` — registration site
- `domain-knowledge` skill — template engine overview
