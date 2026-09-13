//! Guisu CLI application entry point
//!
//! This is the minimal main entry point that delegates to the library.

use clap::Parser;

fn main() -> std::process::ExitCode {
    // Fancy miette handler: box-drawing characters on, no URL links.
    // `set_hook` is best-effort and returns Err if a hook is already set
    // (e.g. by a test harness), which we ignore.
    miette::set_hook(Box::new(|_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .terminal_links(false)
                .unicode(true)
                .context_lines(2)
                .tab_width(4)
                .build(),
        )
    }))
    .ok();

    let cli = guisu::Cli::parse();

    match guisu::run(cli) {
        Ok(()) => std::process::ExitCode::from(0),
        // `{e:#}` collapses the anyhow chain into `top: cause1: cause2`
        // which miette splits back out for its chain walk.
        Err(e) => {
            eprint!("{:?}", miette::Report::msg(format!("{e:#}")));
            std::process::ExitCode::from(1)
        }
    }
}
