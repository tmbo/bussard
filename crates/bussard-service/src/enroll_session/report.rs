//! What a surface tells the human about an enrolment session (issue #784):
//! how the labels travel before the link, and a summary with the next steps
//! that apply at the end. `bussard keys enroll` prints it, the MCP tools
//! return it, so both say the same.

use serde::Serialize;

use super::{CertificateOutcome, EnrollStatus};

/// The page that explains the data path, the session code and local mode.
pub const DOCS_URL: &str =
    "https://bussard.tmbo.dev/docs/explanation/knx-secure/#certificate-entry-from-a-phone";

/// How the labels travel, in plain lines, for the hosted page (`local`
/// false) or the page bussard serves on this computer (`local` true).
#[must_use]
pub fn data_path(local: bool) -> &'static [&'static str] {
    if local {
        &[
            "The page and its relay run inside this bussard on 127.0.0.1.",
            "The browser encrypts each certificate and hands it to this bussard, which",
            "saves it in your encrypted key store. Nothing leaves this machine.",
        ]
    } else {
        &[
            "The phone reads each certificate, encrypts it on the phone and sends it to a",
            "relay that cannot decrypt it. The relay forwards it to this bussard, which",
            "decrypts it and saves it in your encrypted key store.",
        ]
    }
}

/// How many labels ended in each status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EnrollTally {
    /// Saved on a device of the model (`stored`).
    pub stored: u32,
    /// Saved under its serial, waiting for a device (`unassigned`).
    pub waiting: u32,
    /// The store already had the same key (`already_stored`).
    pub already_known: u32,
    /// The store holds another key for the serial; nothing written.
    pub conflicts: u32,
    /// Not a certificate, or its check failed.
    pub invalid: u32,
    /// Something else went wrong.
    pub errors: u32,
}

impl EnrollTally {
    /// The tally of `outcomes`.
    #[must_use]
    pub fn of(outcomes: &[CertificateOutcome]) -> Self {
        let mut tally = EnrollTally::default();
        for outcome in outcomes {
            tally.add(outcome.status);
        }
        tally
    }

    /// Counts one more label with `status`.
    pub fn add(&mut self, status: EnrollStatus) {
        let count = match status {
            EnrollStatus::Stored => &mut self.stored,
            EnrollStatus::Unassigned => &mut self.waiting,
            EnrollStatus::AlreadyStored => &mut self.already_known,
            EnrollStatus::Conflict => &mut self.conflicts,
            EnrollStatus::Invalid => &mut self.invalid,
            EnrollStatus::Error => &mut self.errors,
        };
        *count += 1;
    }

    /// All labels counted.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.stored
            + self.waiting
            + self.already_known
            + self.conflicts
            + self.invalid
            + self.errors
    }

    /// One line in the words of `dev/glossary.md`: the total sent, then
    /// each certificate state that occurred, e.g.
    /// `6 sent · 1 added · 4 already known · 1 no device yet`.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.total() == 0 {
            return "No certificates received.".to_string();
        }
        std::iter::once(format!("{} sent", self.total()))
            .chain(
                self.states()
                    .iter()
                    .filter(|(n, _)| *n > 0)
                    .map(|(n, badge)| format!("{n} {badge}")),
            )
            .collect::<Vec<_>>()
            .join(" \u{00B7} ")
    }

    /// Each count with its certificate state as the glossary names it
    /// (`added`, `no device yet`, `already known`, `conflict`, `invalid`,
    /// `failed`), in that order, zeros included.
    #[must_use]
    pub fn states(&self) -> [(u32, &'static str); 6] {
        [
            (self.stored, "added"),
            (self.waiting, "no device yet"),
            (self.already_known, "already known"),
            (
                self.conflicts,
                if self.conflicts == 1 {
                    "conflict"
                } else {
                    "conflicts"
                },
            ),
            (self.invalid, "invalid"),
            (self.errors, "failed"),
        ]
    }

    /// The steps that apply, in the order to take them; empty when nothing
    /// is left to do.
    #[must_use]
    pub fn next_steps(&self) -> Vec<NextStep> {
        let mut steps = Vec::new();
        if self.waiting > 0 {
            steps.push(NextStep {
                command: "bussard scan <LINE>, or bussard adopt <ADDRESS>",
                why: "saves the serial number of each device to your project and matches the \
                      certificates that have no device yet",
            });
        }
        if self.stored + self.waiting > 0 {
            steps.push(NextStep {
                command: "bussard keys export <FILE>",
                why: "if ETS or Home Assistant should know the new keys too",
            });
        }
        if self.conflicts > 0 {
            steps.push(NextStep {
                command: "bussard keys show",
                why: "shows what your key store holds for the devices in conflict",
            });
        }
        if self.invalid + self.errors > 0 {
            steps.push(NextStep {
                command: "bussard keys enroll",
                why: "scan the invalid or failed certificates again in a new session",
            });
        }
        steps
    }
}

/// One next step: a command and why to run it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NextStep {
    /// The command line, placeholders in `<...>`.
    pub command: &'static str,
    /// What it does for this session's labels.
    pub why: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: EnrollStatus) -> CertificateOutcome {
        CertificateOutcome {
            status,
            serial: Some("00FA01020304".to_string()),
            ia: None,
            name: None,
            message: None,
        }
    }

    fn commands(tally: &EnrollTally) -> Vec<&'static str> {
        tally.next_steps().iter().map(|s| s.command).collect()
    }

    #[test]
    fn test_summary_lists_only_statuses_that_occurred() {
        let tally = EnrollTally::of(&[
            outcome(EnrollStatus::Stored),
            outcome(EnrollStatus::Stored),
            outcome(EnrollStatus::Unassigned),
        ]);
        assert_eq!(
            tally.summary(),
            "3 sent \u{00B7} 2 added \u{00B7} 1 no device yet"
        );
    }

    #[test]
    fn test_summary_empty_session() {
        assert_eq!(
            EnrollTally::default().summary(),
            "No certificates received."
        );
        assert!(EnrollTally::default().next_steps().is_empty());
    }

    #[test]
    fn test_next_steps_stored_only_suggests_export() {
        let tally = EnrollTally::of(&[outcome(EnrollStatus::Stored)]);
        assert_eq!(commands(&tally), ["bussard keys export <FILE>"]);
    }

    #[test]
    fn test_next_steps_waiting_suggests_scan_or_adopt_and_export() {
        let tally = EnrollTally::of(&[outcome(EnrollStatus::Unassigned)]);
        assert_eq!(
            commands(&tally),
            [
                "bussard scan <LINE>, or bussard adopt <ADDRESS>",
                "bussard keys export <FILE>"
            ]
        );
    }

    #[test]
    fn test_next_steps_already_known_needs_nothing() {
        let tally = EnrollTally::of(&[outcome(EnrollStatus::AlreadyStored)]);
        assert_eq!(tally.summary(), "1 sent \u{00B7} 1 already known");
        assert!(tally.next_steps().is_empty());
    }

    #[test]
    fn test_next_steps_conflict_suggests_keys_show() {
        let tally = EnrollTally::of(&[outcome(EnrollStatus::Conflict)]);
        assert_eq!(commands(&tally), ["bussard keys show"]);
    }

    #[test]
    fn test_next_steps_invalid_or_error_suggests_new_session() {
        let tally =
            EnrollTally::of(&[outcome(EnrollStatus::Invalid), outcome(EnrollStatus::Error)]);
        assert_eq!(
            tally.summary(),
            "2 sent \u{00B7} 1 invalid \u{00B7} 1 failed"
        );
        assert_eq!(commands(&tally), ["bussard keys enroll"]);
    }

    #[test]
    fn test_data_path_local_says_nothing_leaves() {
        assert!(
            data_path(true)
                .join(" ")
                .contains("Nothing leaves this machine")
        );
        assert!(data_path(false).join(" ").contains("cannot decrypt"));
    }
}
