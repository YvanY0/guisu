//! Display-agnostic hook selection, change detection, and classification
//!
//! `guisu diff`, `guisu status`, and the `guisu hooks` commands all need the
//! same answers to the same questions — "which hooks run here?", "what
//! changed since the last snapshot?", "is this hook Steady / Latent /
//! Behind?" — and previously each derived them independently, with the
//! derivations drifting apart. This module is the single source of truth for
//! those decisions; the CLI layer only formats the results.
//!
//! Script bodies are supplied by the caller as pre-resolved maps (keyed by
//! hook name). That keeps this layer pure: no filesystem access, no template
//! engine, no coloring.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use super::config::{Hook, HookMode};
use crate::state::HookState;

/// Hooks that run on the given platform, in their original order.
#[must_use]
pub fn filter_for_platform<'a>(hooks: &'a [Hook], platform: &str) -> Vec<&'a Hook> {
    hooks.iter().filter(|h| h.should_run_on(platform)).collect()
}

/// Whether a hook will actually execute: platform-compatible and, for
/// `mode=once`, not already recorded as executed.
///
/// `mode=onchange` hooks return `true` here — the executor makes the final
/// decision after rendering the template, which this layer never sees.
#[must_use]
pub fn will_run<H: BuildHasher>(
    hook: &Hook,
    platform: &str,
    once_executed: &HashSet<String, H>,
) -> bool {
    if !hook.should_run_on(platform) {
        return false;
    }
    match hook.mode {
        HookMode::Once => !once_executed.contains(hook.name.as_str()),
        HookMode::Always | HookMode::OnChange => true,
    }
}

/// Whether two hooks differ in any metadata field visible in diffs.
///
/// `script_content` is intentionally excluded: it is a runtime-only field
/// (`#[serde(skip)]`) that never round-trips through the persisted
/// `last_collections`, so comparing it would register a false change after
/// every run.
#[must_use]
pub fn metadata_changed(previous: &Hook, current: &Hook) -> bool {
    current.order != previous.order
        || current.mode != previous.mode
        || current.cmd != previous.cmd
        || current.script != previous.script
}

/// A single change between the current hook definitions and the snapshot
/// recorded in the state database.
#[derive(Debug, Clone)]
pub enum HookChange<'a> {
    /// Present now, absent from the last snapshot.
    Added {
        /// The current hook definition.
        current: &'a Hook,
        /// Rendered script body, when the hook has a script.
        current_body: Option<String>,
    },
    /// Present in the last snapshot, gone now.
    Removed {
        /// The last-known hook definition.
        previous: &'a Hook,
        /// Script body recorded at the last run, when available.
        previous_body: Option<String>,
    },
    /// Present on both sides with a metadata or rendered-content change.
    Modified {
        /// The last-known hook definition.
        previous: &'a Hook,
        /// The current hook definition.
        current: &'a Hook,
        /// Script body recorded at the last run, when available.
        previous_body: Option<String>,
        /// Rendered script body now, when available.
        current_body: Option<String>,
    },
}

/// Diff one stage's hook lists, restricted to hooks relevant to `platform`.
///
/// Change order follows the historical CLI output: additions first (current
/// order), then removals (previous order), then modifications (current
/// order).
///
/// `current_bodies` must contain an entry for a hook only when the hook has
/// both a `script` and loaded `script_content`; `previous_bodies` follows the
/// old-side recovery rule (rendered content from the snapshot, falling back
/// to the last-run render cache). Both are produced by the CLI, which owns
/// the template renderer.
#[must_use]
pub fn diff_collections<'a, S: BuildHasher>(
    current: &'a [Hook],
    previous: &'a [Hook],
    platform: &str,
    current_bodies: &HashMap<&str, String, S>,
    previous_bodies: &HashMap<&str, String, S>,
) -> Vec<HookChange<'a>> {
    let previous_names: HashSet<&str> = previous.iter().map(|h| h.name.as_str()).collect();
    let current_names: HashSet<&str> = current.iter().map(|h| h.name.as_str()).collect();
    let mut changes = Vec::new();

    for hook in current {
        if !previous_names.contains(hook.name.as_str()) && hook.should_run_on(platform) {
            changes.push(HookChange::Added {
                current: hook,
                current_body: current_bodies.get(hook.name.as_str()).cloned(),
            });
        }
    }

    for hook in previous {
        if !current_names.contains(hook.name.as_str()) && hook.should_run_on(platform) {
            changes.push(HookChange::Removed {
                previous: hook,
                previous_body: previous_bodies.get(hook.name.as_str()).cloned(),
            });
        }
    }

    for hook in current {
        if !hook.should_run_on(platform) {
            continue;
        }
        let Some(previous_hook) = previous.iter().find(|h| h.name == hook.name) else {
            continue;
        };
        let current_body = current_bodies.get(hook.name.as_str()).cloned();
        let previous_body = previous_bodies.get(hook.name.as_str()).cloned();
        let content_changed = matches!(
            (&current_body, &previous_body),
            (Some(new), Some(old)) if new != old
        );

        if metadata_changed(previous_hook, hook) || content_changed {
            changes.push(HookChange::Modified {
                previous: previous_hook,
                current: hook,
                previous_body,
                current_body,
            });
        }
    }

    changes
}

/// Per-hook lifecycle status, as reported by `guisu status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookLifecycle {
    /// Definition matches the last run and the hook is up to date.
    Steady,
    /// Hook never ran (or is `onchange` without a recorded hash) — it would
    /// execute on the next run.
    Latent,
    /// Definition or rendered content changed since the last snapshot.
    Behind,
}

/// Classify one hook against the persisted [`HookState`].
///
/// The lookup mirrors `guisu status`: the previous definition is searched in
/// `state.last_collections` across both stages by name. Callers are expected
/// to pre-filter by platform with [`filter_for_platform`].
#[must_use]
pub fn classify<S: BuildHasher>(
    current: &Hook,
    state: &HookState,
    current_bodies: &HashMap<&str, String, S>,
    previous_bodies: &HashMap<&str, String, S>,
) -> HookLifecycle {
    let previous = state.last_collections.as_ref().and_then(|last| {
        last.pre
            .iter()
            .chain(last.post.iter())
            .find(|h| h.name == current.name)
    });
    let Some(previous) = previous else {
        // No snapshot at all (first run), or a hook that was not present at
        // the last execution: either way it has never run in this state.
        return HookLifecycle::Latent;
    };

    let current_body = current_bodies.get(current.name.as_str());
    let previous_body = previous_bodies.get(current.name.as_str());
    let content_changed = matches!(
        (current_body, previous_body),
        (Some(new), Some(old)) if new != old
    );

    if metadata_changed(previous, current) || content_changed {
        return HookLifecycle::Behind;
    }

    // Definition matches the last run, but the hook may still be pending:
    // an `onchange` hook without a recorded hash, or a `once` hook that has
    // never executed. Without this check a never-run `mode=once` hook would
    // show as Steady as soon as its definition round-trips through
    // `last_collections`.
    if (current.mode == HookMode::OnChange
        && !state.onchange_hashes.contains_key(current.name.as_str()))
        || (current.mode == HookMode::Once && !state.once_executed.contains(current.name.as_str()))
    {
        HookLifecycle::Latent
    } else {
        HookLifecycle::Steady
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::hooks::config::HookEnvVars;
    use crate::hooks::types::HookName;

    fn hook(name: &str, platforms: &[&str]) -> Hook {
        Hook {
            name: HookName::new(name).unwrap(),
            order: 10,
            platforms: platforms.iter().map(|p| (*p).to_string()).collect(),
            cmd: Some(format!("echo {name}")),
            script: None,
            script_content: None,
            env: HookEnvVars::new(),
            failfast: true,
            mode: HookMode::Always,
            timeout: 0,
        }
    }

    fn bodies<'a>(pairs: &[(&'a str, &'a str)]) -> HashMap<&'a str, String> {
        pairs
            .iter()
            .map(|(name, body)| (*name, (*body).to_string()))
            .collect()
    }

    #[test]
    fn filter_for_platform_keeps_matching_and_unrestricted() {
        let hooks = vec![hook("any", &[]), hook("mac", &["darwin"])];
        let on_linux = filter_for_platform(&hooks, "linux");
        assert_eq!(on_linux.len(), 1);
        assert_eq!(on_linux[0].name.as_str(), "any");

        let on_darwin = filter_for_platform(&hooks, "darwin");
        assert_eq!(on_darwin.len(), 2);
    }

    #[test]
    fn will_run_respects_platform_and_once_mode() {
        let mut once_executed = HashSet::new();
        let mut once = hook("once", &[]);
        once.mode = HookMode::Once;
        assert!(will_run(&once, "linux", &once_executed));

        once_executed.insert("once".to_string());
        assert!(!will_run(&once, "linux", &once_executed));

        let mac_only = hook("mac", &["darwin"]);
        assert!(!will_run(&mac_only, "linux", &HashSet::new()));

        let mut onchange = hook("change", &[]);
        onchange.mode = HookMode::OnChange;
        // Executor makes the final onchange decision; selection defers.
        assert!(will_run(&onchange, "linux", &HashSet::new()));
    }

    #[test]
    fn metadata_changed_covers_visible_fields() {
        let base = hook("a", &[]);
        let mut changed = base.clone();
        assert!(!metadata_changed(&base, &changed));

        changed.order = 20;
        assert!(metadata_changed(&base, &changed));

        let mut changed = base.clone();
        changed.cmd = Some("echo different".to_string());
        assert!(metadata_changed(&base, &changed));

        // `script_content` is runtime-only and must not register.
        let mut with_content = base.clone();
        with_content.script_content = Some("body".to_string());
        assert!(!metadata_changed(&base, &with_content));
    }

    #[test]
    fn diff_orders_added_then_removed_then_modified() {
        let current = vec![
            hook("unchanged", &[]),
            hook("modified", &[]), // order 10 (default)
            hook("added", &[]),
        ];
        let previous = vec![hook("unchanged", &[]), hook("removed", &[]), {
            let mut modified = hook("modified", &[]);
            modified.order = 20;
            modified
        }];

        let changes = diff_collections(&current, &previous, "linux", &bodies(&[]), &bodies(&[]));
        let kinds: Vec<&str> = changes
            .iter()
            .map(|c| match c {
                HookChange::Added { .. } => "added",
                HookChange::Removed { .. } => "removed",
                HookChange::Modified { .. } => "modified",
            })
            .collect();
        assert_eq!(kinds, vec!["added", "removed", "modified"]);

        let HookChange::Added { current, .. } = &changes[0] else {
            panic!("expected Added")
        };
        assert_eq!(current.name.as_str(), "added");
    }

    #[test]
    fn diff_skips_platform_mismatch_on_both_sides() {
        let current = vec![hook("new-mac", &["darwin"])];
        let previous = vec![hook("gone-mac", &["darwin"])];
        let changes = diff_collections(&current, &previous, "linux", &bodies(&[]), &bodies(&[]));
        assert!(changes.is_empty());

        // Same hooks, relevant platform: both reported.
        let changes = diff_collections(&current, &previous, "darwin", &bodies(&[]), &bodies(&[]));
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn diff_detects_content_only_changes() {
        let current = vec![hook("a", &[])];
        let previous = vec![hook("a", &[])];
        let changes = diff_collections(
            &current,
            &previous,
            "linux",
            &bodies(&[("a", "rendered now")]),
            &bodies(&[("a", "rendered before")]),
        );
        assert_eq!(changes.len(), 1);
        let HookChange::Modified {
            current_body,
            previous_body,
            ..
        } = &changes[0]
        else {
            panic!("expected Modified")
        };
        assert_eq!(current_body.as_deref(), Some("rendered now"));
        assert_eq!(previous_body.as_deref(), Some("rendered before"));
    }

    #[test]
    fn diff_ignores_uncomparable_content_sides() {
        // Metadata equal, one side missing → no change (matches the old
        // "only compare when both bodies exist" rule).
        let current = vec![hook("a", &[])];
        let previous = vec![hook("a", &[])];
        let changes = diff_collections(
            &current,
            &previous,
            "linux",
            &bodies(&[("a", "new")]),
            &bodies(&[]),
        );
        assert!(changes.is_empty());
    }

    #[test]
    fn added_and_removed_carry_bodies() {
        let current = vec![hook("fresh", &[])];
        let previous = vec![hook("gone", &[])];
        let changes = diff_collections(
            &current,
            &previous,
            "linux",
            &bodies(&[("fresh", "fresh body")]),
            &bodies(&[("gone", "gone body")]),
        );
        assert_eq!(changes.len(), 2);
        let HookChange::Added { current_body, .. } = &changes[0] else {
            panic!("expected Added")
        };
        assert_eq!(current_body.as_deref(), Some("fresh body"));
        let HookChange::Removed { previous_body, .. } = &changes[1] else {
            panic!("expected Removed")
        };
        assert_eq!(previous_body.as_deref(), Some("gone body"));
    }

    #[test]
    fn classify_first_run_is_latent() {
        let state = HookState::new();
        let current = hook("a", &[]);
        assert_eq!(
            classify(&current, &state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Latent
        );
    }

    #[test]
    fn classify_matches_pending_modes_after_snapshot_roundtrip() {
        let current = hook("a", &[]);
        let mut collections = crate::hooks::config::HookCollections::default();
        collections.pre.push(current.clone());
        let mut state = HookState::new();
        state.last_collections = Some(collections);

        // Always-mode, no changes → steady.
        assert_eq!(
            classify(&current, &state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Steady
        );

        // `once` without execution record → latent.
        let mut once = hook("once", &[]);
        once.mode = HookMode::Once;
        let mut once_collections = crate::hooks::config::HookCollections::default();
        once_collections.pre.push(once.clone());
        let mut once_state = HookState::new();
        once_state.last_collections = Some(once_collections);
        assert_eq!(
            classify(&once, &once_state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Latent
        );
        once_state.mark_executed_once("once".to_string());
        assert_eq!(
            classify(&once, &once_state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Steady
        );

        // `onchange` without a recorded hash → latent.
        let mut onchange = hook("change", &[]);
        onchange.mode = HookMode::OnChange;
        let mut onchange_collections = crate::hooks::config::HookCollections::default();
        onchange_collections.pre.push(onchange.clone());
        let mut onchange_state = HookState::new();
        onchange_state.last_collections = Some(onchange_collections);
        assert_eq!(
            classify(&onchange, &onchange_state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Latent
        );
        onchange_state.update_onchange_hash("change".to_string(), [1; 32]);
        assert_eq!(
            classify(&onchange, &onchange_state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Steady
        );
    }

    #[test]
    fn classify_behind_on_metadata_or_body_change() {
        let current = hook("a", &[]);
        let mut previous = hook("a", &[]);
        let mut collections = crate::hooks::config::HookCollections::default();
        collections.pre.push(previous.clone());
        let mut state = HookState::new();
        state.last_collections = Some(collections);

        assert_eq!(
            classify(&current, &state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Steady
        );

        // metadata drift
        previous.order = 40;
        let mut collections = crate::hooks::config::HookCollections::default();
        collections.pre.push(previous.clone());
        state.last_collections = Some(collections);
        assert_eq!(
            classify(&current, &state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Behind
        );

        // rendered-content drift only
        let mut previous = hook("a", &[]);
        previous.order = 10;
        let mut collections = crate::hooks::config::HookCollections::default();
        collections.pre.push(previous);
        state.last_collections = Some(collections);
        assert_eq!(
            classify(
                &current,
                &state,
                &bodies(&[("a", "now")]),
                &bodies(&[("a", "before")])
            ),
            HookLifecycle::Behind
        );
    }

    #[test]
    fn classify_finds_previous_across_stages() {
        let current = hook("post-a", &[]);
        let mut collections = crate::hooks::config::HookCollections::default();
        collections.post.push(current.clone());
        let mut state = HookState::new();
        state.last_collections = Some(collections);

        // Matching snapshot in post, identical definition → Steady, not
        // Latent (the lookup spans both stages, like the old status loop).
        let mut onchange = current.clone();
        onchange.mode = HookMode::Always;
        assert_eq!(
            classify(&onchange, &state, &bodies(&[]), &bodies(&[])),
            HookLifecycle::Steady
        );
    }
}
