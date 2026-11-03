//! The terminal as a [`bussard_service::setup::Output`]: `say` on stdout,
//! `warn` on stderr, a line each, exactly as the commands print.

use bussard_service::setup::Output;

/// Prints the lines of a library step as they come.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Console;

impl Output for Console {
    fn say(&mut self, line: &str) {
        println!("{line}");
    }

    fn warn(&mut self, line: &str) {
        eprintln!("{line}");
    }
}
