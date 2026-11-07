//! The terminal as a [`bussard_service::observer::ProgressSink`] for the
//! lines a flow says: `Say` on stdout, `Warn` on stderr, a line each,
//! exactly as the commands print.

use bussard_service::observer::{Event, Note, ProgressSink};

/// Prints the lines of a library step as they come.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Console;

impl ProgressSink for Console {
    fn event(&mut self, event: Event<'_>) {
        if let Event::Note(note) = event {
            print_note(note);
        }
    }
}

/// Prints `note`: `Say` on stdout, `Warn` on stderr.
pub(crate) fn print_note(note: Note) {
    match note {
        Note::Say(line) => println!("{line}"),
        Note::Warn(line) => eprintln!("{line}"),
    }
}
