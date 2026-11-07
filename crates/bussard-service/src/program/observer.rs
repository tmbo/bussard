//! The one observer a programming flow reports to (issue #901): the CLI
//! implements it with its progress display and `confirm::confirm`, the MCP
//! tier with its job table and the plan-digest handshake.

use bussard_download::{FlashPlan, Progress};

/// What a surface asks the human before a flow writes: the question and the
/// action a refusal names when no one can be asked (no terminal, no `--yes`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Question {
    /// The text before ` [y/N] `; a note above it goes on its own line.
    pub prompt: String,
    /// What a refusal without a terminal names (`flash 1.1.4 via …`).
    pub action: String,
}

/// The human's answer to a [`Question`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Go ahead.
    Yes,
    /// Stop; nothing is written.
    No,
    /// Nobody could be asked: the refusal sentence.
    Refused(String),
}

/// A step of a programming flow, as an observer names it.
#[derive(Debug, Clone, Copy)]
pub enum Step<'a> {
    /// The link tables (with the group-object table reload and the security
    /// object they carry) are written and read back.
    WriteTables,
    /// A System 7 device restarts after its table write.
    WaitRestart,
    /// The parameter octets that differ are downloaded (`plan`).
    WriteParameters {
        /// The parameter-only download.
        plan: &'a FlashPlan,
    },
    /// A full application download (`plan`), its restart and its read-back.
    Download {
        /// The download.
        plan: &'a FlashPlan,
    },
    /// The independent read-back after a write.
    ReadBack,
}

/// A line a flow says while it runs, before its outcome is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// For the human, on the main output (the CLI's stdout).
    Say(String),
    /// A notice or a warning (the CLI's stderr).
    Warn(String),
}

/// Watches a programming flow: the steps it takes, the lines it says, the
/// download's progress, and the one question before a write.
pub trait Observer {
    /// The flow starts a step.
    fn step(&mut self, step: Step<'_>) {
        let _ = step;
    }
    /// A step ended; `verified` when what it wrote reads back as meant.
    fn done(&mut self, step: Step<'_>, verified: bool) {
        let _ = (step, verified);
    }
    /// The flow says something.
    fn note(&mut self, note: Note) {
        let _ = note;
    }
    /// One progress event of a download.
    fn progress(&mut self, event: Progress) {
        let _ = event;
    }
    /// A download ended; `verified` when it verified.
    fn finished(&mut self, verified: bool) {
        let _ = verified;
    }
    /// Asks the human before the flow writes. The default refuses: a flow
    /// never writes for an observer that cannot ask.
    fn confirm(&mut self, question: &Question) -> Answer {
        let _ = question;
        Answer::No
    }
    /// The human said yes; the flow writes next (the CLI records its history
    /// snapshot here).
    fn approved(&mut self) {}
}

/// Why a flow did not write after its question.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Declined {
    /// The human said no.
    #[error("declined")]
    No,
    /// No one could be asked: the refusal sentence.
    #[error("{0}")]
    Refused(String),
}

/// Asks `question` and, on a yes, tells the observer the write follows.
///
/// # Errors
///
/// [`Declined`] when the answer is not yes.
pub fn ask(observer: &mut impl Observer, question: &Question) -> Result<(), Declined> {
    match observer.confirm(question) {
        Answer::Yes => {
            observer.approved();
            Ok(())
        }
        Answer::No => Err(Declined::No),
        Answer::Refused(refusal) => Err(Declined::Refused(refusal)),
    }
}

/// An observer that ignores everything and answers no.
impl Observer for () {}
