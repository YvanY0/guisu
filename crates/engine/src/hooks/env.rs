//! Environment variable expansion for hook scripts
//!
//! Provides simple `${VAR}` expansion using an `IndexMap` of variables.

use indexmap::IndexMap;
use std::borrow::Cow;

/// Expand environment variables in a string (simple `${VAR}` expansion)
///
/// Uses `Cow` to avoid allocation when no substitution is needed.
pub(crate) fn expand_env_vars<'a>(
    input: &'a str,
    env_vars: &IndexMap<String, String>,
) -> Cow<'a, str> {
    if !input.contains("${") {
        return Cow::Borrowed(input);
    }

    let chars: Vec<char> = input.chars().collect();
    let mut result = String::with_capacity(input.len());
    let mut last_end = 0;
    let mut i = 0;

    while i < chars.len() {
        if i + 1 < chars.len() && chars[i] == '$' && chars[i + 1] == '{' {
            result.push_str(&input[last_end..i]);

            if let Some(close_idx) = chars[i + 2..].iter().position(|&c| c == '}') {
                let var_start = i + 2;
                let var_end = i + 2 + close_idx;

                let var_name: String = chars[var_start..var_end].iter().collect();

                if let Some(value) = env_vars.get(&var_name) {
                    result.push_str(value);
                } else {
                    result.push_str(&input[i..=var_end]);
                }

                last_end = var_end + 1;
                i = var_end + 1;
                continue;
            }
        }

        i += 1;
    }

    if last_end == 0 {
        Cow::Borrowed(input)
    } else {
        result.push_str(&input[last_end..]);
        Cow::Owned(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use indexmap::IndexMap;

    fn env_with(vars: &[(&str, &str)]) -> IndexMap<String, String> {
        let mut map = IndexMap::new();
        for (k, v) in vars {
            map.insert((*k).to_string(), (*v).to_string());
        }
        map
    }

    #[test]
    fn test_expand_env_vars_no_variables() {
        let env = IndexMap::new();
        let input = "plain text without variables";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, input);
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_expand_env_vars_single_variable() {
        let env = env_with(&[("NAME", "Alice")]);
        let input = "Hello, ${NAME}!";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "Hello, Alice!");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_expand_env_vars_multiple_variables() {
        let env = env_with(&[("FIRST", "John"), ("LAST", "Doe")]);
        let input = "${FIRST} ${LAST}";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "John Doe");
    }

    #[test]
    fn test_expand_env_vars_undefined_variable() {
        let env = IndexMap::new();
        let input = "Value: ${UNDEFINED}";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "Value: ${UNDEFINED}");
    }

    #[test]
    fn test_expand_env_vars_unclosed_brace() {
        let env = env_with(&[("VAR", "value")]);
        let input = "Unclosed: ${VAR";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "Unclosed: ${VAR");
    }

    #[test]
    fn test_expand_env_vars_empty_variable_name() {
        let env = IndexMap::new();
        let input = "Empty: ${}";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "Empty: ${}");
    }

    #[test]
    fn test_expand_env_vars_nested_braces() {
        let env = env_with(&[("OUTER", "outer")]);
        let input = "${OUTER} and ${INNER}";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "outer and ${INNER}");
    }

    #[test]
    fn test_expand_env_vars_at_start() {
        let env = env_with(&[("VAR", "start")]);
        let input = "${VAR} text";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "start text");
    }

    #[test]
    fn test_expand_env_vars_at_end() {
        let env = env_with(&[("VAR", "end")]);
        let input = "text ${VAR}";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "text end");
    }

    #[test]
    fn test_expand_env_vars_only_variable() {
        let env = env_with(&[("VAR", "value")]);
        let input = "${VAR}";
        let result = expand_env_vars(input, &env);

        assert_eq!(result, "value");
    }
}
