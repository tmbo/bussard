//! How `keys enroll` and `keys add-certificate` show a certificate's outcome
//! (issue #792): the states and detail lines of `dev/glossary.md`
//! ("Certificate states"), coloured by state. A certificate is shown by its
//! serial number and device only, never by its code or key.

use bussard_service::enroll_session::{CertificateOutcome, EnrollStatus, EnrollTally};

use crate::style::{Style, Tone};

/// The widest badge, `no device yet`: badges pad to it so lines align.
const BADGE_WIDTH: usize = 13;

/// The badge of `status` and its tone.
pub(crate) fn badge(status: EnrollStatus) -> (&'static str, Tone) {
    let tone = match status {
        EnrollStatus::Stored => Tone::Ok,
        EnrollStatus::Unassigned => Tone::Warn,
        EnrollStatus::AlreadyStored => Tone::Dim,
        EnrollStatus::Conflict | EnrollStatus::Invalid | EnrollStatus::Error => Tone::Error,
    };
    (status.badge(), tone)
}

/// One line per certificate: serial number, state badge, detail.
pub(crate) fn line(outcome: &CertificateOutcome, style: Style) -> String {
    let serial = outcome.serial.as_deref().unwrap_or("-");
    let (text, tone) = badge(outcome.status);
    let padded = format!("{text:<BADGE_WIDTH$}");
    let mut line = format!("{serial:<12}  {}", style.paint(&padded, tone));
    match outcome.detail() {
        Some(detail) => {
            line.push_str("  ");
            line.push_str(&detail);
        }
        None => line.truncate(line.trim_end().len()),
    }
    line
}

/// The summary line: `6 sent · 1 added · 4 already known · 1 no device yet`,
/// each state in its colour.
pub(crate) fn summary(tally: &EnrollTally, style: Style) -> String {
    if tally.total() == 0 {
        return style.bold("No certificates received.");
    }
    let states = [
        EnrollStatus::Stored,
        EnrollStatus::Unassigned,
        EnrollStatus::AlreadyStored,
        EnrollStatus::Conflict,
        EnrollStatus::Invalid,
        EnrollStatus::Error,
    ];
    let mut parts = vec![(format!("{} sent", tally.total()), Tone::Plain)];
    for (status, (n, word)) in states.iter().zip(tally.states()) {
        if n > 0 {
            parts.push((format!("{n} {word}"), badge(*status).1));
        }
    }
    style.summary(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: EnrollStatus) -> CertificateOutcome {
        CertificateOutcome {
            status,
            serial: Some("00FA01020304".to_string()),
            ia: Some("1.1.3".to_string()),
            name: Some("Kitchen actuator".to_string()),
            message: None,
        }
    }

    #[test]
    fn test_line_added_names_the_device() {
        assert_eq!(
            line(&outcome(EnrollStatus::Stored), Style::plain()),
            "00FA01020304  added          for 1.1.3 Kitchen actuator"
        );
    }

    #[test]
    fn test_line_already_known_has_no_detail() {
        assert_eq!(
            line(&outcome(EnrollStatus::AlreadyStored), Style::plain()),
            "00FA01020304  already known"
        );
    }

    #[test]
    fn test_line_states_follow_the_glossary() {
        let text = line(&outcome(EnrollStatus::Unassigned), Style::plain());
        assert!(
            text.contains("no device yet  no device in your project"),
            "{text}"
        );
        let text = line(&outcome(EnrollStatus::Conflict), Style::plain());
        assert!(
            text.ends_with("conflict       your key store holds a different key for this device")
        );
        let text = line(&outcome(EnrollStatus::Invalid), Style::plain());
        assert!(text.ends_with("invalid        check the code"), "{text}");
        let mut failed = outcome(EnrollStatus::Error);
        failed.message = Some("disk full".to_string());
        assert!(line(&failed, Style::plain()).ends_with("failed         disk full"));
        for status in [EnrollStatus::AlreadyStored, EnrollStatus::Unassigned] {
            let text = line(&outcome(status), Style::plain());
            assert!(!text.contains("already_stored") && !text.contains("unassigned"));
        }
    }

    #[test]
    fn test_line_colours_the_badge() {
        let text = line(&outcome(EnrollStatus::Conflict), Style::rich());
        assert!(text.contains("\u{1b}[31m"), "{text:?}");
    }

    #[test]
    fn test_summary_counts_each_state() {
        let mut tally = EnrollTally::default();
        for status in [
            EnrollStatus::Stored,
            EnrollStatus::AlreadyStored,
            EnrollStatus::AlreadyStored,
            EnrollStatus::Unassigned,
        ] {
            tally.add(status);
        }
        assert_eq!(
            summary(&tally, Style::plain()),
            "4 sent, 1 added, 1 no device yet, 2 already known"
        );
        assert_eq!(
            summary(&EnrollTally::default(), Style::plain()),
            "No certificates received."
        );
    }
}
