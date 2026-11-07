//! One progress and prompt vocabulary for every flow (issues #901, #910).
//!
//! A flow reports what it does as [`Event`]s to a [`ProgressSink`] and asks
//! the human through a [`Prompt`]. The CLI implements both once with its
//! terminal display and `confirm::confirm`, the MCP server once with its job
//! table, and the viz hub adapts the events it streams. The programming
//! flows ([`crate::program`]), the addressing flows
//! ([`crate::program::assign`]), the download ([`crate::download`]), the
//! setup steps ([`crate::setup`]), the file imports ([`crate::files`]) and
//! the KNXnet/IP Secure switch ([`crate::ip_secure`]) all speak it.

use std::time::Duration;

use bussard_download::{FlashPlan, Progress};
use bussard_model::IndividualAddress;

use crate::program::assign::Assigned;

/// What kind of answer a [`Question`] wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ask {
    /// Consent to a bus write (`--yes` answers it).
    Write,
    /// Consent to download vendor product data (`--yes-download` answers
    /// it, never `--yes`).
    Download,
    /// A hand-edited field differs from an import: [`Answer::Yes`] takes the
    /// incoming value, [`Answer::No`] keeps the local one.
    Conflict,
}

/// What a flow asks the human: the kind, the question and the action a
/// refusal names when no one can be asked (no terminal, no `--yes`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Question {
    /// What kind of answer it wants.
    pub kind: Ask,
    /// The text before ` [y/N] `; a note above it goes on its own line.
    pub prompt: String,
    /// What a refusal without a terminal names (`flash 1.1.4 via …`,
    /// `2 file(s)`).
    pub action: String,
}

impl Question {
    /// A [`Ask::Write`] question.
    pub fn write(prompt: impl Into<String>, action: impl Into<String>) -> Question {
        Question {
            kind: Ask::Write,
            prompt: prompt.into(),
            action: action.into(),
        }
    }
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

impl From<bool> for Answer {
    /// `true` is [`Answer::Yes`], `false` [`Answer::No`].
    fn from(yes: bool) -> Answer {
        if yes { Answer::Yes } else { Answer::No }
    }
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
    /// The flow waits for a device in programming mode: the human presses
    /// its programming button.
    PressButton,
    /// One device answered the programming-mode broadcast, at `current`.
    Found {
        /// Its current address.
        current: IndividualAddress,
    },
    /// Nothing may answer at `target` before it is given away (or, for a
    /// replacement, the dead device must be gone).
    CheckFree {
        /// The address probed.
        target: IndividualAddress,
    },
    /// What the device at `at` is, read before anything is written.
    Identify {
        /// Where it answers.
        at: IndividualAddress,
    },
    /// The individual address `target` is broadcast.
    WriteAddress {
        /// The new address.
        target: IndividualAddress,
    },
    /// The independent read-back at the new address.
    ReadAddress {
        /// The new address.
        target: IndividualAddress,
    },
    /// The address took (or was kept): what the read-back said.
    Assigned(&'a Assigned),
    /// A Data Secure-activated device is read over `A_SecureData`.
    ReadSecured {
        /// The device.
        target: IndividualAddress,
    },
    /// The device file is written.
    DeviceFile,
}

/// A line a flow says while it runs, before its outcome is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// For the human, on the main output (the CLI's stdout).
    Say(String),
    /// A notice or a warning (the CLI's stderr).
    Warn(String),
}

impl Note {
    /// The line.
    pub fn text(&self) -> &str {
        match self {
            Note::Say(line) | Note::Warn(line) => line,
        }
    }
}

/// A wait for the human (the programming button), as it goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// The first polls found nothing: time to remind the human (sent once).
    Remind,
    /// Still waiting after the reminder, with this much budget left.
    Left(Duration),
}

/// What a flow reports while it runs.
#[derive(Debug, Clone)]
pub enum Event<'a> {
    /// The flow enters a phase named in words (an IP Secure switch's next
    /// write): the text a surface shows as the current step.
    Phase(String),
    /// The flow starts a typed step.
    Step(Step<'a>),
    /// A step ended; `verified` when what it wrote reads back as meant.
    Done {
        /// The step.
        step: Step<'a>,
        /// Whether it verified.
        verified: bool,
    },
    /// The flow says something.
    Note(Note),
    /// A wait for the human goes on.
    Wait(Wait),
    /// One progress event of a download (its step and bytes).
    Progress(Progress),
    /// A download ended; `verified` when it verified.
    Finished {
        /// Whether it verified.
        verified: bool,
    },
    /// The human said yes; the flow writes next (the CLI records its
    /// history snapshot here).
    Approved,
}

/// Where a flow's [`Event`]s go. A closure over `Event` is a sink.
pub trait ProgressSink {
    /// One event.
    fn event(&mut self, event: Event<'_>);

    /// Says `line` ([`Note::Say`]).
    fn say(&mut self, line: &str) {
        self.event(Event::Note(Note::Say(line.to_string())));
    }

    /// Warns `line` ([`Note::Warn`]).
    fn warn(&mut self, line: &str) {
        self.event(Event::Note(Note::Warn(line.to_string())));
    }
}

impl<F: FnMut(Event<'_>)> ProgressSink for F {
    fn event(&mut self, event: Event<'_>) {
        self(event);
    }
}

/// A sink that ignores everything.
impl ProgressSink for () {
    fn event(&mut self, _event: Event<'_>) {}
}

/// A sink that keeps the lines said and warned, in order (the MCP tools
/// return them in their results).
#[derive(Debug, Default, Clone)]
pub struct Collected {
    /// The lines said and warned, in order.
    pub lines: Vec<String>,
}

impl ProgressSink for Collected {
    fn event(&mut self, event: Event<'_>) {
        if let Event::Note(note) = event {
            self.lines.push(match note {
                Note::Say(line) | Note::Warn(line) => line,
            });
        }
    }
}

/// How a surface answers a flow's [`Question`]s. Every default is the
/// answer of a caller that cannot ask: no.
pub trait Prompt {
    /// Asks the human. The default refuses: a flow never writes for a
    /// surface that cannot ask.
    fn ask(&mut self, question: &Question) -> Answer {
        let _ = question;
        Answer::No
    }

    /// Whether [`Prompt::ask`] reaches a human (a terminal is attached); a
    /// flow that would ask many questions refuses up front without one.
    fn can_ask(&self) -> bool {
        false
    }

    /// Why questions of `kind` are answered no without asking
    /// (`--no-download`), or `None` to ask.
    fn skips(&self, kind: Ask) -> Option<String> {
        let _ = kind;
        None
    }
}

/// A prompt that never asks.
impl Prompt for () {}

/// A prompt that answers every question yes: the caller's arguments
/// already carry the human's consent (the MCP plan digest with `yes: true`,
/// `download: true`).
#[derive(Debug, Default, Clone, Copy)]
pub struct Consented;

impl Prompt for Consented {
    fn ask(&mut self, _question: &Question) -> Answer {
        Answer::Yes
    }
}

/// A flow's observer: where its events go and who answers its questions.
pub trait Observer: ProgressSink + Prompt {}

impl<T: ProgressSink + Prompt + ?Sized> Observer for T {}

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
    match observer.ask(question) {
        Answer::Yes => {
            observer.event(Event::Approved);
            Ok(())
        }
        Answer::No => Err(Declined::No),
        Answer::Refused(refusal) => Err(Declined::Refused(refusal)),
    }
}
