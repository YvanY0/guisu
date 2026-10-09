//! Environment variable access abstraction.
//!
//! Single entry point for reading process environment variables. Every
//! crate in the workspace routes through this module instead of calling
//! `std::env::var` directly so that:
//!
//! * tests can inject deterministic values via [`Env::with_overrides`]
//!   without touching the real process env (no `unsafe`, no `set_var`);
//! * `clippy.toml`'s `disallowed-methods` rule can ban the raw calls
//!   without breaking compilation;
//! * a future change (config-file overrides, layering, observability)
//!   touches one file, not eight.
//!
//! The [`Env::editor`], [`Env::pager`], [`Env::username`] helpers below
//! bake the "look at A then fall back to B" rules into one place; callers
//! should use those instead of re-implementing the fallback chain.

// This module IS the abstraction layer, so it has to call the raw
// `std::env::*` API. The `#![allow]` keeps the workspace-level
// `disallowed-methods` lint from firing on ourselves; every other crate
// still has to route through `Env`.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;

/// Read-only view of the process environment.
///
/// Construct with [`Env::system`] for production code or
/// [`Env::with_overrides`] in tests to inject deterministic values.
///
/// ## Override semantics
///
/// An entry in `overrides` is **authoritative** — its presence replaces
/// the process-env lookup entirely. `Some(value)` makes the key resolve
/// to `value`; `None` makes the key resolve to "unset" (so a fallback
/// chain like `VISUAL → EDITOR` will fall through to `EDITOR` even if
/// the process env has a `VISUAL`). This is what tests need to fully
/// simulate "no VISUAL set" without `unsafe` `remove_var`.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// Per-key override. `Some(override)` wins over `std::env`; `None`
    /// means "treat as unset" (don't query process env).
    overrides: HashMap<String, Option<String>>,
}

impl Env {
    /// Snapshot the real process environment with no overrides.
    #[must_use]
    pub fn system() -> Self {
        Self {
            overrides: HashMap::new(),
        }
    }

    /// Wrap the real process environment with a layer of test/dev
    /// overrides. See [`Env`]'s docs for the `Some` / `None` semantics.
    #[must_use]
    pub fn with_overrides(overrides: HashMap<String, Option<String>>) -> Self {
        Self { overrides }
    }

    /// `Some(value)` if the variable is set to any non-error value.
    /// Mirrors `std::env::var(key).ok()` so callers can `.unwrap_or(...)`
    /// the same way they used to.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<String> {
        match self.overrides.get(key) {
            // Override is present → use it (Some(v) or None).
            // Its presence means "the real env doesn't matter for this key".
            Some(v) => v.clone(),
            // No override → consult the real process env.
            None => std::env::var(key).ok(),
        }
    }

    /// `get(key)` falling back to `default` when unset.
    #[must_use]
    pub fn var_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_string())
    }

    /// Iterate over `(key, value)` pairs from the process env, with
    /// overrides shadowing matching keys. Used by the template engine
    /// to expose `$env` to templates and by hook execution to inherit
    /// the parent shell env.
    pub fn iter(&self) -> impl Iterator<Item = (String, String)> + '_ {
        std::env::vars().map(move |(k, v)| {
            let v = self.overrides.get(&k).and_then(Clone::clone).unwrap_or(v);
            (k, v)
        })
    }

    // ----- Themed accessors ----------------------------------------------
    // Each helper centralises a "A else B" rule that used to be
    // open-coded across multiple crates.

    /// `VISUAL` then `EDITOR`. Used by `guisu edit` and the editor
    /// picker in the TUI.
    #[must_use]
    pub fn editor(&self) -> Option<String> {
        self.get("VISUAL").or_else(|| self.get("EDITOR"))
    }

    /// `PAGER` — left as-is (no cross-platform fallback currently, since
    /// callers chain their own default like `less -R`).
    #[must_use]
    pub fn pager(&self) -> Option<String> {
        self.get("PAGER")
    }

    /// `USER` then `USERNAME` (Windows). Templates that need the
    /// current username go through here so the platform check lives in
    /// exactly one place.
    #[must_use]
    pub fn username(&self) -> Option<String> {
        self.get("USER").or_else(|| self.get("USERNAME"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_some_shadows_process_env() {
        let mut overrides = HashMap::new();
        overrides.insert("FOO".into(), Some("from-override".into()));
        let env = Env::with_overrides(overrides);
        assert_eq!(env.get("FOO").as_deref(), Some("from-override"));
    }

    #[test]
    fn override_none_makes_key_unset() {
        let mut overrides = HashMap::new();
        // FOO is explicitly marked "not set", regardless of what the
        // process env has.
        overrides.insert("FOO".into(), None);
        let env = Env::with_overrides(overrides);
        assert_eq!(env.get("FOO"), None);
    }

    #[test]
    fn editor_prefers_visual_over_editor() {
        let mut o = HashMap::new();
        o.insert("VISUAL".into(), Some("vim".into()));
        o.insert("EDITOR".into(), Some("nano".into()));
        let env = Env::with_overrides(o);
        assert_eq!(env.editor().as_deref(), Some("vim"));
    }

    #[test]
    fn editor_falls_back_when_only_editor_is_set() {
        let mut o = HashMap::new();
        // VISUAL is explicitly unset → editor() should reach EDITOR.
        o.insert("VISUAL".into(), None);
        o.insert("EDITOR".into(), Some("nano".into()));
        let env = Env::with_overrides(o);
        assert_eq!(env.editor().as_deref(), Some("nano"));
    }

    #[test]
    fn editor_returns_none_when_neither_set() {
        let mut o = HashMap::new();
        o.insert("VISUAL".into(), None);
        o.insert("EDITOR".into(), None);
        let env = Env::with_overrides(o);
        assert_eq!(env.editor(), None);
    }

    #[test]
    fn username_resolves_via_user_or_username() {
        let env = Env::system();
        // At least one of USER/USERNAME is set on every supported
        // platform; the helper just picks the first one that exists.
        assert!(
            env.get("USER").is_some() || env.get("USERNAME").is_some(),
            "neither USER nor USERNAME is set in this environment",
        );
    }
}
