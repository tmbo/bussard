//! The terminal side of the addressing flows (issue #902): `assign`,
//! `adopt`, `replace` and `commission` run
//! [`bussard_service::program::assign`] through [`Bench`], the observer that
//! prints their progress and asks their one question, and word a
//! [`Stop`] with [`stopped`].

use std::io::Write;
use std::process::ExitCode;

use anyhow::anyhow;
use bussard_model::IndividualAddress;
use bussard_service::assign::Occupant;
use bussard_service::program::assign::Stop;
use bussard_service::program::{Answer, Declined, Note, Observer, Question, Step};

/// Prints an addressing flow's progress on the terminal and asks its
/// question there.
pub(crate) struct Bench {
    /// `--yes`: the question is answered yes.
    yes: bool,
    /// The indent of the progress lines (`commission` nests them under the
    /// device).
    indent: &'static str,
    /// The line printed when the wait for the programming button starts.
    press: Option<String>,
    /// `adopt`'s wizard: the step heading before the device file.
    wizard: bool,
    /// The address was broadcast in this run.
    wrote: bool,
}

impl Bench {
    /// A bench that asks unless `yes`.
    pub(crate) fn new(yes: bool) -> Bench {
        Bench {
            yes,
            indent: "",
            press: None,
            wizard: false,
            wrote: false,
        }
    }

    /// Indents the progress lines.
    pub(crate) fn indent(mut self, indent: &'static str) -> Bench {
        self.indent = indent;
        self
    }

    /// Prints `line` when the wait for the programming button starts.
    pub(crate) fn press(mut self, line: String) -> Bench {
        self.press = Some(line);
        self
    }

    /// Prints `adopt`'s step headings.
    pub(crate) fn wizard(mut self) -> Bench {
        self.wizard = true;
        self
    }
}

impl Observer for Bench {
    fn step(&mut self, step: Step<'_>) {
        let indent = self.indent;
        match step {
            Step::PressButton => {
                if let Some(line) = &self.press {
                    eprintln!("{line}");
                }
            }
            Step::Remind => eprintln!(
                "no device in programming mode yet — press the programming button on the \
                 device, then keep waiting (or re-run)."
            ),
            Step::Waiting { remaining } => {
                eprint!("\rwaiting for a device… {}s left   ", remaining.as_secs());
                let _ = std::io::stderr().flush();
            }
            Step::Found { current } => {
                eprintln!("{indent}device in programming mode: {current} (its current address)");
            }
            Step::WriteAddress { .. } => self.wrote = true,
            Step::ReadAddress { target } if !self.wrote => {
                eprintln!(
                    "{indent}{target} already has the address {target}; no address write; verifying…"
                );
            }
            Step::Assigned(assigned) => {
                let target = assigned.target;
                for warning in &assigned.verified.warnings {
                    eprintln!("{warning}");
                }
                if assigned.verified.programming_mode_cleared {
                    eprintln!(
                        "{indent}cleared programming mode on {target} (PID_PROGMODE = 0), as ETS \
                         does."
                    );
                }
                if assigned.still_in_programming_mode {
                    eprintln!();
                    for line in bussard_service::assign::still_in_programming_mode_warning(target) {
                        eprintln!("{line}");
                    }
                }
                if !assigned.written {
                    eprintln!(
                        "note: {target} stays in programming mode (nothing was written to it); \
                         press its programming button to leave it"
                    );
                }
            }
            Step::ReadSecured { .. } => println!(
                "  reading the secured device over A_SecureData (tables, security object, \
                 parameters)"
            ),
            Step::DeviceFile if self.wizard => crate::adopt_cmd::step(3, "write the device file"),
            _ => {}
        }
    }

    fn done(&mut self, step: Step<'_>, _verified: bool) {
        if let Step::WriteAddress { target } = step {
            eprintln!("{}wrote {target}; verifying…", self.indent);
        }
    }

    fn note(&mut self, note: Note) {
        match note {
            Note::Say(line) => println!("{line}"),
            Note::Warn(line) => eprintln!("{line}"),
        }
    }

    fn confirm(&mut self, question: &Question) -> Answer {
        match crate::confirm::confirm(self.yes, &question.prompt, &question.action) {
            Ok(true) => Answer::Yes,
            Ok(false) => Answer::No,
            Err(err) => Answer::Refused(format!("{err:#}")),
        }
    }
}

/// The question before an address write: `<verb> <current> → <target> via
/// <gateway>?`.
pub(crate) fn question(
    verb: &str,
    current: IndividualAddress,
    target: IndividualAddress,
    gateway: &str,
) -> Question {
    Question {
        prompt: format!("{verb} {current} → {target} via {gateway}?"),
        action: format!("{verb} {current} → {target} via {gateway}"),
    }
}

/// The warning for an occupied address `--force` overrode.
pub(crate) fn warn_forced(target: IndividualAddress, occupant: &Occupant) {
    eprintln!(
        "warning: {target} already answers on the bus ({}); --force given, continuing",
        occupant.describe()
    );
}

/// Words a [`Stop`] of `bussard <verb>`: a refusal or a wait that found no
/// single device is a clean failure; anything else is an error.
///
/// # Errors
///
/// A stop that is an error (the bus, the read-back, a refusal without a
/// terminal).
pub(crate) fn stopped(stop: Stop, verb: &str) -> anyhow::Result<ExitCode> {
    match stop {
        Stop::Several(found) => {
            eprintln!("{} devices are in programming mode:", found.len());
            for address in &found {
                eprintln!("  {address}");
            }
            eprintln!(
                "{verb} works on one device at a time — leave programming mode on all but the one \
                 you want, then re-run."
            );
        }
        Stop::Nothing { waited } => {
            eprintln!();
            eprintln!(
                "no device entered programming mode within {}s.",
                waited.as_secs()
            );
            eprintln!(
                "press the programming button on the new device (its LED usually lights up), \
                 then re-run `bussard {verb}`."
            );
        }
        Stop::Occupied { target, occupant } => eprintln!(
            "{}",
            bussard_service::assign::occupied_refusal(target, &occupant, verb)
        ),
        Stop::Declined(Declined::No) => eprintln!("aborted; no address was written."),
        Stop::Declined(Declined::Refused(refusal)) => return Err(anyhow!(refusal)),
        other => return Err(other.into()),
    }
    Ok(ExitCode::FAILURE)
}
