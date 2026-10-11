//! Shared hook list formatting
//!
//! One implementation of the "list hooks, dim platform-skipped entries"
//! line used by the `guisu hooks run` overview and `guisu hooks list`, so
//! the two views cannot drift apart again.

use guisu_engine::hooks::Hook;
use owo_colors::OwoColorize;

/// Print one `  {marker} <name> (order: N)` line per hook.
///
/// Hooks that do not run on `platform` are dimmed and tagged `[skipped]`;
/// active hooks show their name in green.
pub(crate) fn format_hook_list(hooks: &[Hook], platform: &str, marker: &str) {
    for hook in hooks {
        if hook.should_run_on(platform) {
            println!("  {marker} {} (order: {})", hook.name.green(), hook.order);
        } else {
            println!(
                "  {marker} {} (order: {}) {}",
                hook.name.dimmed(),
                hook.order,
                "[skipped]".dimmed()
            );
        }
    }
}
