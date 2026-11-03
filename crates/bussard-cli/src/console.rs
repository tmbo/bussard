//! The terminal as a [`bussard_service::setup::Output`]: `say` on stdout,
//! `warn` on stderr, a line each, exactly as the commands print; and as the
//! [`bussard_service::files::import::ConflictPrompt`] of `--interactive`.

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

impl bussard_service::files::import::ConflictPrompt for Console {
    fn can_ask(&self) -> bool {
        std::io::IsTerminal::is_terminal(&std::io::stdin())
    }

    fn take_theirs(&mut self, sentence: &str) -> Result<bool, bussard_service::setup::SetupError> {
        use std::io::{BufRead, Write};
        print!("  {sentence}\n    keep [m]ine or take [t]heirs? [m] ");
        std::io::stdout()
            .flush()
            .map_err(bussard_service::setup::SetupError::source)?;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(bussard_service::setup::SetupError::source)?;
        Ok(matches!(line.trim(), "t" | "T" | "theirs"))
    }
}
