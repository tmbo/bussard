//! Where a session stands, as every surface reports it (issue #911): the
//! [`SessionProgress`] a surface records the events of
//! [`super::EnrollSession::run`] into, and the [`SessionStatus`] built from
//! it, which `knx_enroll_status` returns as is. The end sentence is
//! [`EnrollEnd::describe`]; the counts and next steps are [`EnrollTally`]'s.

use std::time::{Duration, Instant};

use serde::Serialize;

use super::{
    CertificateOutcome, EnrollEnd, EnrollEvent, EnrollStatus, EnrollSummary, EnrollTally, NextStep,
    Timeouts,
};

/// What a session reported so far, and how it ended.
#[derive(Debug, Clone)]
pub struct SessionProgress {
    /// The page and relay run on this computer (local mode).
    pub local: bool,
    /// The session's connect, idle and maximum timeouts.
    pub timeouts: Timeouts,
    /// Where a stop comes from (`the chat`, `this terminal`), for the end
    /// sentence.
    pub stopped_from: &'static str,
    /// When the session started.
    pub started: Instant,
    /// Phones (page loads) that joined.
    pub phones: usize,
    /// Other phones that tried to join and were refused.
    pub refused_phones: usize,
    /// One outcome per certificate, in arrival order.
    pub results: Vec<CertificateOutcome>,
    /// Messages dropped (not an envelope, not for this session).
    pub ignored: u32,
    /// How the session ended; `None` while it runs or when it failed.
    pub end: Option<EnrollEnd>,
    /// Why the session failed, when it did.
    pub error: Option<String>,
}

impl SessionProgress {
    /// A session that starts now.
    #[must_use]
    pub fn new(local: bool, timeouts: Timeouts, stopped_from: &'static str) -> Self {
        SessionProgress {
            local,
            timeouts,
            stopped_from,
            started: Instant::now(),
            phones: 0,
            refused_phones: 0,
            results: Vec::new(),
            ignored: 0,
            end: None,
            error: None,
        }
    }

    /// Records one event of the session.
    pub fn record(&mut self, event: EnrollEvent) {
        match event {
            EnrollEvent::PhoneJoined => self.phones = 1,
            EnrollEvent::PhoneRefused { phones } => self.refused_phones = phones,
            EnrollEvent::Certificate(outcome) => self.results.push(outcome),
            EnrollEvent::Ignored { reason } => {
                self.ignored += 1;
                tracing::debug!(%reason, "enrolment: ignored a message");
            }
            EnrollEvent::PhoneDone => {}
        }
    }

    /// Records how [`super::EnrollSession::run`] ended.
    pub fn finish(&mut self, result: Result<EnrollSummary, crate::ServiceError>) {
        match result {
            Ok(summary) => self.end = Some(summary.end),
            Err(err) => self.error = Some(err.to_string()),
        }
    }

    /// Whether the session still runs.
    #[must_use]
    pub fn running(&self) -> bool {
        self.end.is_none() && self.error.is_none()
    }

    /// How many certificates ended in each state.
    #[must_use]
    pub fn tally(&self) -> EnrollTally {
        EnrollTally::of(&self.results)
    }

    /// How the session ended as a key (`phone_done`, ..., `error`); `None`
    /// while it runs.
    #[must_use]
    pub fn end_key(&self) -> Option<&'static str> {
        if self.error.is_some() {
            return Some("error");
        }
        self.end.map(EnrollEnd::key)
    }

    /// Why the session ended, in one sentence; `None` while it runs.
    #[must_use]
    pub fn end_reason(&self) -> Option<String> {
        if let Some(error) = &self.error {
            return Some(format!("The session failed: {error}."));
        }
        self.end
            .map(|end| end.describe(&self.timeouts, self.stopped_from))
    }

    /// The warning when another phone tried to join, `None` otherwise.
    #[must_use]
    pub fn refused_warning(&self) -> Option<String> {
        (self.refused_phones > 0).then(|| {
            format!(
                "Another phone tried to join this session and was refused ({} so far); nothing \
                 it sent was saved. If it was not the human's, someone else has the link: stop \
                 the session (stop: true) and start a new one.",
                self.refused_phones
            )
        })
    }

    /// The status: counts while the session runs (`results` too with
    /// `details`), counts, `results` and `serials` once it ended.
    #[must_use]
    pub fn status(&self, details: bool) -> SessionStatus {
        let running = self.running();
        let tally = self.tally();
        let warning = self.refused_warning();
        let summary = match self.end_reason() {
            Some(reason) => format!("{reason} {}", tally.summary()),
            None => format!("The certificate page is open. {}", tally.summary()),
        };
        let summary = match &warning {
            Some(warning) => format!("{warning} {summary}"),
            None => summary,
        };
        SessionStatus {
            ok: self.error.is_none(),
            session: if running { "running" } else { "ended" },
            end: self.end_key(),
            error: self.error.clone(),
            local: self.local,
            phones: self.phones,
            refused_phones: self.refused_phones,
            warning,
            certificates: self.results.len(),
            stored: self.results.iter().filter(|r| r.status.is_stored()).count(),
            ignored: self.ignored,
            expires_in_seconds: running.then(|| {
                self.timeouts
                    .max
                    .saturating_sub(self.started.elapsed())
                    .as_secs()
            }),
            summary,
            next_steps: if running {
                Vec::new()
            } else {
                tally.next_steps()
            },
            tally,
            results: (details || !running)
                .then(|| self.results.iter().map(CertificateResult::of).collect()),
            serials: (!running).then(|| self.serials()),
        }
    }

    /// The certificates in one line: serial number and badge
    /// (`00FA01020304 added · 0083A1B2C3D4 no device yet`).
    fn serials(&self) -> String {
        self.results
            .iter()
            .map(|r| {
                format!(
                    "{} {}",
                    r.serial.as_deref().unwrap_or("-"),
                    r.status.badge()
                )
            })
            .collect::<Vec<_>>()
            .join(" \u{00B7} ")
    }
}

/// Where a session stands, as `knx_enroll_status` reports it. Never a link,
/// a session code, a certificate or a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionStatus {
    /// The session did not fail.
    pub ok: bool,
    /// `running` or `ended`.
    pub session: &'static str,
    /// How it ended ([`SessionProgress::end_key`]); `None` while it runs.
    pub end: Option<&'static str>,
    /// Why it failed, when it did.
    pub error: Option<String>,
    /// Local mode.
    pub local: bool,
    /// Phones that joined.
    pub phones: usize,
    /// Other phones that were refused.
    pub refused_phones: usize,
    /// The warning about refused phones, when there were any.
    pub warning: Option<String>,
    /// Certificates handled.
    pub certificates: usize,
    /// Certificates whose key is now in the store.
    pub stored: usize,
    /// Messages dropped.
    pub ignored: u32,
    /// The count per certificate state.
    pub tally: EnrollTally,
    /// While it runs: the seconds left before its maximum duration.
    pub expires_in_seconds: Option<u64>,
    /// One line: the warning, why it ended, the counts.
    pub summary: String,
    /// Once ended: the CLI commands that apply.
    pub next_steps: Vec<NextStep>,
    /// One entry per certificate, once ended or on request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<CertificateResult>>,
    /// Once ended: serial numbers and badges in one line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serials: Option<String>,
}

/// The chat's view of an enrolment session (issue #904): the
/// [`SessionStatus`] and what the pairing page adds, the result of
/// `knx_enroll_certificates` and `knx_enroll_status`.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollView {
    /// The session.
    #[serde(flatten)]
    pub status: SessionStatus,
    /// Whether bussard's pairing page was opened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_page_opened: Option<bool>,
    /// The path the certificates travel, while the session runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_path: Option<String>,
    /// Where to read more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_more: Option<String>,
    /// What the session warned about.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// A note about the key store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// What the assistant does next.
    #[serde(skip)]
    pub next: Option<String>,
}

impl crate::report::Report for EnrollView {
    const SCHEMA: u32 = 1;

    fn next_step(&self) -> Option<String> {
        self.next.clone()
    }
}

/// An enrolment the chat could not start or the human declined: nothing
/// was changed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EnrollRefusal {
    /// Always `false`.
    pub ok: bool,
    /// A check refused it.
    #[serde(skip_serializing_if = "crate::report::is_false")]
    pub refused: bool,
    /// The human declined the page.
    #[serde(skip_serializing_if = "crate::report::is_false")]
    pub declined: bool,
    /// Whether the pairing page was opened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_page_opened: Option<bool>,
    /// `none` (no session) or `ended`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<&'static str>,
    /// Why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The sentence for the human.
    #[serde(skip)]
    pub said: String,
    /// What the assistant does next.
    #[serde(skip)]
    pub next: Option<String>,
}

impl crate::report::Report for EnrollRefusal {
    const SCHEMA: u32 = 1;

    fn summary(&self, _model: &bussard_model::Model) -> Option<String> {
        Some(self.said.clone())
    }

    fn next_step(&self) -> Option<String> {
        self.next.clone()
    }
}

/// One certificate as a status reports it: never its code or key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertificateResult {
    /// The serial number.
    pub serial: Option<String>,
    /// The individual address of the matched device.
    #[serde(rename = "address")]
    pub ia: Option<String>,
    /// The matched device's name.
    pub name: Option<String>,
    /// What happened.
    pub status: EnrollStatus,
    /// Why, for `invalid`, `conflict` and `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CertificateResult {
    /// The entry of `outcome`.
    #[must_use]
    pub fn of(outcome: &CertificateOutcome) -> Self {
        CertificateResult {
            serial: outcome.serial.clone(),
            ia: outcome.ia.clone(),
            name: outcome.name.clone(),
            status: outcome.status,
            message: outcome.message.clone(),
        }
    }
}

/// `span` in words: `4 hours`, `10 minutes`, `1 minute`, `30 seconds`.
#[must_use]
pub fn span_words(span: Duration) -> String {
    let secs = span.as_secs();
    let (n, unit) = if secs >= 3600 && secs.is_multiple_of(3600) {
        (secs / 3600, "hour")
    } else if secs >= 60 && secs.is_multiple_of(60) {
        (secs / 60, "minute")
    } else {
        (secs, "second")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(statuses: &[EnrollStatus], end: Option<EnrollEnd>) -> SessionProgress {
        let mut progress = SessionProgress::new(false, Timeouts::default(), "the chat");
        for status in statuses {
            progress.record(EnrollEvent::Certificate(CertificateOutcome {
                status: *status,
                serial: Some("00FA01020304".to_string()),
                ia: None,
                name: None,
                message: None,
            }));
        }
        progress.end = end;
        progress
    }

    #[test]
    fn test_status_ended_has_summary_serials_and_next_steps() -> serde_json::Result<()> {
        let status = progress(
            &[EnrollStatus::Unassigned, EnrollStatus::Conflict],
            Some(EnrollEnd::PhoneDone),
        )
        .status(false);
        let json = serde_json::to_value(&status)?;
        assert_eq!(
            json["summary"],
            "Finished on the phone. 2 sent \u{00B7} 1 no device yet \u{00B7} 1 conflict"
        );
        assert_eq!(
            json["serials"],
            "00FA01020304 no device yet \u{00B7} 00FA01020304 conflict"
        );
        assert_eq!(json["end"], "phone_done");
        assert_eq!(json["tally"]["conflicts"], 1);
        assert_eq!(json["results"][0]["address"], serde_json::Value::Null);
        assert_eq!(json["results"][0]["status"], "unassigned");
        assert_eq!(json["expires_in_seconds"], serde_json::Value::Null);
        let commands: Vec<&str> = status.next_steps.iter().map(|s| s.command).collect();
        assert_eq!(
            commands,
            [
                "bussard scan <LINE>, or bussard adopt <ADDRESS>",
                "bussard keys export <FILE>",
                "bussard keys show"
            ]
        );
        Ok(())
    }

    #[test]
    fn test_status_running_gives_counts_not_results() {
        let running = progress(&[EnrollStatus::Stored, EnrollStatus::Unassigned], None);
        let status = running.status(false);
        assert_eq!(
            (status.session, status.certificates, status.stored),
            ("running", 2, 2)
        );
        assert!(status.results.is_none() && status.serials.is_none());
        assert!(status.next_steps.is_empty());
        assert!(status.expires_in_seconds.is_some());
        assert!(
            status
                .summary
                .starts_with("The certificate page is open. 2 sent")
        );
        assert_eq!(running.status(true).results.map(|r| r.len()), Some(2));
    }

    #[test]
    fn test_end_reason_names_each_end() {
        let mut progress = progress(&[], Some(EnrollEnd::ConnectTimeout));
        assert_eq!(
            progress.end_reason().as_deref(),
            Some("No phone joined within 10 minutes, so the session was closed.")
        );
        progress.timeouts.connect = Duration::from_secs(1);
        assert_eq!(
            progress.end_reason().as_deref(),
            Some("No phone joined within 1 second, so the session was closed.")
        );
        progress.end = Some(EnrollEnd::Stopped);
        assert_eq!(
            progress.end_reason().as_deref(),
            Some("The session was ended from the chat.")
        );
        progress.end = None;
        assert_eq!(progress.end_reason(), None);
        progress.error = Some("the relay failed".to_string());
        assert_eq!(progress.end_key(), Some("error"));
        assert!(!progress.status(false).ok);
    }

    #[test]
    fn test_refused_phone_leads_the_summary() {
        let mut progress = progress(&[], None);
        progress.record(EnrollEvent::PhoneRefused { phones: 1 });
        let status = progress.status(false);
        assert!(status.summary.starts_with("Another phone tried to join"));
        assert_eq!(
            status.warning.as_deref().map(|w| w.contains("(1 so far)")),
            Some(true)
        );
    }

    #[test]
    fn test_span_words_picks_the_largest_unit() {
        assert_eq!(span_words(Duration::from_secs(4 * 3600)), "4 hours");
        assert_eq!(span_words(Duration::from_secs(600)), "10 minutes");
        assert_eq!(span_words(Duration::from_secs(60)), "1 minute");
        assert_eq!(span_words(Duration::from_secs(90)), "90 seconds");
    }
}
