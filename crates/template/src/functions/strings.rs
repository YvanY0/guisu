//! String manipulation functions
//!
//! Provides functions for string processing including trimming, quoting,
//! regex operations, and splitting/joining.

use minijinja::Value;
use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

// Regex cache - stores compiled regexes to avoid repeated compilation
// Limited to 64 entries with LRU eviction to prevent unbounded memory growth
// Uses LRU (Least Recently Used) eviction strategy for better cache hit率
static REGEX_CACHE: OnceLock<Mutex<lru::LruCache<String, regex::Regex>>> = OnceLock::new();
const MAX_REGEX_CACHE_SIZE: usize = 64;

/// Quote a string for shell usage
///
/// Escapes backslashes and quotes.
///
/// # Usage
///
/// ```jinja2
/// {{ quote(filename) }}
/// ```
///
/// # Examples
///
/// - `hello` → `"hello"`
/// - `say "hi"` → `"say \"hi\""`
/// - `path\to\file` → `"path\\to\\file"`
#[must_use]
pub fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Trim whitespace from both ends of a string
///
/// Removes leading and trailing whitespace (spaces, tabs, newlines, etc.).
///
/// # Usage
///
/// ```jinja2
/// {{ "  hello  " | trim }}  {# Output: "hello" #}
/// {{ someVar | trim }}
/// {{ bitwarden("item", "id").field | trim }}
/// ```
///
/// # Performance
///
/// Uses pointer comparison to detect when no trimming occurred, avoiding
/// redundant processing of the same string data.
#[must_use]
pub fn trim(value: &str) -> String {
    let trimmed = value.trim();
    // Use pointer comparison - if same pointer, no trimming occurred
    // This is faster than length comparison for this check
    if std::ptr::eq(trimmed.as_ptr(), value.as_ptr()) && trimmed.len() == value.len() {
        value.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Trim whitespace from the start (left) of a string
///
/// Removes only leading whitespace.
///
/// # Usage
///
/// ```jinja2
/// {{ "  hello  " | trimStart }}  {# Output: "hello  " #}
/// {{ someVar | trimStart }}
/// ```
///
/// # Performance
///
/// Uses pointer comparison to detect when no trimming occurred.
#[must_use]
pub fn trim_start(value: &str) -> String {
    let trimmed = value.trim_start();
    // Use pointer comparison for fast path detection
    if std::ptr::eq(trimmed.as_ptr(), value.as_ptr()) {
        value.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Trim whitespace from the end (right) of a string
///
/// Removes only trailing whitespace.
///
/// # Usage
///
/// ```jinja2
/// {{ "  hello  " | trimEnd }}  {# Output: "  hello" #}
/// {{ someVar | trimEnd }}
/// ```
///
/// # Performance
///
/// Uses pointer comparison to detect when no trimming occurred.
#[must_use]
pub fn trim_end(value: &str) -> String {
    let trimmed = value.trim_end();
    // Use pointer comparison and length check for fast path detection
    if std::ptr::eq(trimmed.as_ptr(), value.as_ptr()) && trimmed.len() == value.len() {
        value.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Test if a string matches a regular expression
///
/// Returns true if the pattern matches anywhere in the string.
///
/// # Usage
///
/// ```jinja2
/// {{ regexMatch("hello123", "\\d+") }}  {# Output: true #}
/// {{ regexMatch(email, "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$") }}
/// ```
///
/// # Security
///
/// To prevent `ReDoS` (Regular Expression Denial of Service) attacks:
/// - Pattern length is limited to 200 characters
/// - Regex size is limited to 10MB
/// - DFA size is limited to 2MB
///
/// # Errors
///
/// Returns error if pattern is invalid or exceeds complexity limits
pub fn regex_match(text: &str, pattern: &str) -> Result<bool, minijinja::Error> {
    // Limit regex pattern complexity
    if pattern.len() > 200 {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Regex pattern too long ({} chars, max 200)", pattern.len()),
        ));
    }

    // Get or compile regex (with caching for performance)
    let re = get_compiled_regex(pattern)?;
    Ok(re.is_match(text))
}

/// Get a compiled regex from cache or compile and cache it
///
/// Uses LRU (Least Recently Used) cache with automatic eviction of old patterns.
/// This provides better cache hit rates compared to clearing the entire cache.
fn get_compiled_regex(pattern: &str) -> Result<regex::Regex, minijinja::Error> {
    let cache = REGEX_CACHE.get_or_init(|| {
        let capacity =
            NonZeroUsize::new(MAX_REGEX_CACHE_SIZE).expect("Cache size must be non-zero");
        Mutex::new(lru::LruCache::new(capacity))
    });

    let mut cache_guard = cache.lock().expect("Regex cache poisoned");

    // Try to get from cache (this updates LRU position if found)
    if let Some(re) = cache_guard.get(pattern) {
        return Ok(re.clone());
    }

    // Cache miss - compile new regex
    let re = regex::RegexBuilder::new(pattern)
        .size_limit(10 * (1 << 20)) // 10MB
        .dfa_size_limit(2 * (1 << 20)) // 2MB
        .build()
        .map_err(|e| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                format!("Invalid regex pattern: {e}"),
            )
        })?;

    // Store in cache (LRU automatically evicts least recently used entry if full)
    cache_guard.put(pattern.to_string(), re.clone());
    Ok(re)
}

/// Replace all matches of a regular expression with a replacement string
///
/// # Usage
///
/// ```jinja2
/// {{ regexReplaceAll("hello 123 world 456", "\\d+", "X") }}  {# Output: "hello X world X" #}
/// {{ regexReplaceAll(text, "[aeiou]", "*") }}  {# Replace all vowels #}
/// ```
///
/// # Security
///
/// To prevent `ReDoS` (Regular Expression Denial of Service) attacks:
/// - Pattern length is limited to 200 characters
/// - Regex size is limited to 10MB
/// - DFA size is limited to 2MB
///
/// # Errors
///
/// Returns error if pattern is invalid or exceeds complexity limits
pub fn regex_replace_all(
    text: &str,
    pattern: &str,
    replacement: &str,
) -> Result<String, minijinja::Error> {
    // Limit regex pattern complexity
    if pattern.len() > 200 {
        return Err(minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            format!("Regex pattern too long ({} chars, max 200)", pattern.len()),
        ));
    }

    // Get or compile regex (with caching for performance)
    let re = get_compiled_regex(pattern)?;
    Ok(re.replace_all(text, replacement).to_string())
}

/// Split a string by a delimiter
///
/// Returns a list of strings.
///
/// # Usage
///
/// ```jinja2
/// {{ split("a,b,c", ",") }}  {# Output: ["a", "b", "c"] #}
/// {{ split("one:two:three", ":") | join(" - ") }}
/// {% for item in split(path, "/") %}
///   {{ item }}
/// {% endfor %}
/// ```
pub fn split(text: &str, delimiter: &str) -> Vec<String> {
    text.split(delimiter)
        .map(std::string::ToString::to_string)
        .collect()
}

/// Join a list of strings with a delimiter
///
/// # Usage
///
/// ```jinja2
/// {{ join(["a", "b", "c"], ", ") }}  {# Output: "a, b, c" #}
/// {{ items | join(" - ") }}
/// ```
#[must_use]
pub fn join(items: &[Value], delimiter: &str) -> String {
    items
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(delimiter)
}
