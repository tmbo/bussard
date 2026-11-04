//! `bussard keys enroll`: take KNX Secure device certificates from a phone
//! (issue #729, protocol `dev/enroll-protocol.md`).
//!
//! Prints how the labels travel with a docs link, the link, a terminal QR
//! code of it and the session code (the fingerprint), then one line per
//! certificate the phone sends until the phone sends `done`, the
//! user types `q` (and Enter) or presses Ctrl-C. The relay comes from
//! `--relay`, then `[enroll] relay` in `bussard.toml`, then the hosted relay
//! ([`bussard_service::enroll_session::DEFAULT_RELAY`]). `--local` (#732) serves the page and the relay on
//! 127.0.0.1 instead ([`bussard_viz::enroll_local`]), for a browser on this
//! computer. Never prints a certificate or a key: only serials, addresses,
//! names and statuses. At the end it prints a summary and the next steps
//! that apply (issue #784, [`EnrollTally`]).

use std::io::BufRead;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use bussard_service::enroll_session::{
    DOCS_URL, EnrollEnd, EnrollEvent, EnrollSession, EnrollTally, HttpRelay, RunOptions, data_path,
    hosted_endpoints,
};

use crate::certificate_view;
use crate::style::Style;
use serde_json::json;

/// The long-poll wait: how long a `q` or Ctrl-C takes at most to be noticed.
const WAIT_SECS: u64 = 3;

/// The options of `bussard keys enroll`.
#[derive(Debug)]
pub struct EnrollOptions {
    /// `--relay`: the relay base URL.
    pub relay: Option<String>,
    /// `--page`: the enrolment page the link opens.
    pub page: Option<String>,
    /// `--no-qr`: leave the QR code out.
    pub no_qr: bool,
    /// `--local`: serve the page and the relay on loopback.
    pub local: bool,
}

/// Runs `bussard keys enroll`.
pub fn run(dir: &Path, options: EnrollOptions, json_out: bool) -> anyhow::Result<ExitCode> {
    let config = bussard_model::loader::load_config(dir)
        .with_context(|| format!("reading {}", dir.join("bussard.toml").display()))?
        .enroll
        .unwrap_or_default();
    // Local mode serves its own page and relay.
    let hosted = (!options.local).then(|| hosted_endpoints(options.relay, options.page, &config));

    // Password, store and write access are checked before the link is shown.
    let password = bussard_secure::Password::new(crate::keys_cmd::password()?);
    let mut store = bussard_service::CertificateEnrolment::open(dir, password.expose())?;
    drop(password);

    let mut session = EnrollSession::new().context("starting the enrolment session")?;
    let (local, relay, link) = match hosted {
        Some((relay_url, page)) => {
            let relay = HttpRelay::new(&relay_url, &session)?;
            let link = session.link(&page, Some(relay.base()));
            (None, relay, link)
        }
        None => {
            let server = bussard_viz::enroll_local::LocalEnrollServer::start()
                .context("starting the local enrolment page")?;
            let relay = HttpRelay::new(&server.relay_url(), &session)?;
            // Same origin: the link names no relay.
            let link = session.link(&server.page_url(), None);
            (Some(server), relay, link)
        }
    };
    let fingerprint = session.fingerprint();

    if json_out {
        crate::output::print(
            crate::output::schema::KEYS_ENROLL,
            &json!({
                "event": "session",
                "link": link,
                "fingerprint": fingerprint,
                "local": local.is_some(),
            }),
        )?;
    } else {
        // A phone cannot reach 127.0.0.1: no QR code in local mode.
        let code = if options.no_qr || local.is_some() {
            None
        } else {
            Some(qr(&link)?)
        };
        print!(
            "{}",
            intro_text(
                local.is_some(),
                &link,
                &fingerprint,
                code.as_deref(),
                Style::stdout()
            )
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    watch_stdin(Arc::clone(&stop));
    watch_ctrl_c(Arc::clone(&stop));

    let mut print_error = None;
    let mut tally = EnrollTally::default();
    let summary = session.run(
        &relay,
        &mut store,
        RunOptions {
            wait_secs: WAIT_SECS,
        },
        &stop,
        &mut |event| {
            if let EnrollEvent::Certificate(outcome) = &event {
                tally.add(outcome.status);
            }
            if let Err(err) = show(&event, json_out) {
                print_error.get_or_insert(err);
            }
        },
    )?;
    if let Some(server) = local {
        server.finish();
    }
    if let Some(err) = print_error {
        return Err(err);
    }

    let why = match summary.end {
        EnrollEnd::PhoneDone => "the phone finished",
        EnrollEnd::Stopped => "stopped",
        EnrollEnd::Expired => "the relay session expired",
    };
    if json_out {
        crate::output::print(
            crate::output::schema::KEYS_ENROLL,
            &json!({
                "event": "end",
                "end": why,
                "stored": summary.stored,
                "certificates": summary.certificates,
                "tally": tally,
                "summary": tally.summary(),
                "next_steps": tally.next_steps(),
            }),
        )?;
    } else {
        print!("{}", ending_text(why, &tally, Style::stdout()));
    }
    Ok(ExitCode::SUCCESS)
}

/// The text before the session runs: how the labels travel, the docs link,
/// the link (and its QR code), the session code to compare, how to finish.
fn intro_text(
    local: bool,
    link: &str,
    fingerprint: &str,
    qr: Option<&str>,
    style: Style,
) -> String {
    let mut out = String::new();
    for line in data_path(local) {
        out.push_str(&style.dim(line));
        out.push('\n');
    }
    out.push_str(&format!("{} {DOCS_URL}\n\n", style.dim("Read more:")));
    out.push_str(&style.bold(if local {
        "Open this link in a browser on this computer and scan or type the certificates:"
    } else {
        "Open this link on your phone and scan the certificates:"
    }));
    out.push_str("\n\n");
    if let Some(qr) = qr {
        out.push_str(qr);
    }
    out.push_str(&format!("{link}\n\n"));
    out.push_str(&format!(
        "Session code: {}\n",
        style.ok(&style.bold(fingerprint))
    ));
    out.push_str(if local {
        "Check that the page shows the same code.\n"
    } else {
        "Check that your phone shows the same code.\n"
    });
    out.push_str(&style.dim("Type q and Enter, or press Ctrl-C, to finish."));
    out.push_str("\n\n");
    out
}

/// The text after the session: why it ended, the summary of the labels and
/// the next steps that apply.
fn ending_text(why: &str, tally: &EnrollTally, style: Style) -> String {
    let mut out = format!("\n{}\n", style.dim(&format!("Session closed ({why}).")));
    out.push_str(&certificate_view::summary(tally, style));
    out.push('\n');
    let steps: Vec<(&str, &str)> = tally
        .next_steps()
        .iter()
        .map(|step| (step.command, step.why))
        .collect();
    let block = style.next_steps(&steps);
    if !block.is_empty() {
        out.push('\n');
        out.push_str(&block);
    }
    out
}

/// One event as a line. Never a key: events carry none.
fn show(event: &EnrollEvent, json_out: bool) -> anyhow::Result<()> {
    if json_out {
        let line = match event {
            EnrollEvent::PhoneJoined { phones } => json!({ "event": "phone", "phones": phones }),
            EnrollEvent::Certificate(outcome) => {
                json!({ "event": "certificate", "result": outcome })
            }
            EnrollEvent::Ignored { reason } => json!({ "event": "ignored", "reason": reason }),
            EnrollEvent::PhoneDone => json!({ "event": "done" }),
        };
        return crate::output::print(crate::output::schema::KEYS_ENROLL, &line);
    }
    let style = Style::stdout();
    match event {
        EnrollEvent::PhoneJoined { phones } => {
            println!("{}", style.dim(&format!("phone {phones} connected")));
        }
        EnrollEvent::Certificate(outcome) => {
            println!("{}", certificate_view::line(outcome, style));
        }
        EnrollEvent::Ignored { reason } => {
            println!(
                "{}",
                style.warning_line(&format!("ignored a message: {reason}"))
            );
        }
        EnrollEvent::PhoneDone => println!("{}", style.dim("the phone finished")),
    }
    Ok(())
}

/// The link as a QR code in Unicode half blocks, light on dark.
fn qr(link: &str) -> anyhow::Result<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(link.as_bytes()).context("encoding the link as a QR code")?;
    let mut out = code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    out.push('\n');
    Ok(out)
}

/// Sets `stop` when the user types `q`. A closed stdin (a pipe, `/dev/null`)
/// stops nothing: the phone's `done` or Ctrl-C ends the session then.
fn watch_stdin(stop: Arc<AtomicBool>) {
    let spawned = std::thread::Builder::new()
        .name("enroll-stdin".to_owned())
        .spawn(move || {
            for line in std::io::stdin().lock().lines() {
                match line {
                    Ok(line) if line.trim().eq_ignore_ascii_case("q") => {
                        stop.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
    // Without the thread, Ctrl-C and the phone's `done` still end it.
    drop(spawned);
}

/// Sets `stop` on Ctrl-C, so the session still closes on the relay.
fn watch_ctrl_c(stop: Arc<AtomicBool>) {
    let spawned = std::thread::Builder::new()
        .name("enroll-ctrl-c".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            if runtime.block_on(tokio::signal::ctrl_c()).is_ok() {
                eprintln!("\nclosing the session...");
                stop.store(true, Ordering::SeqCst);
            }
        });
    drop(spawned);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_service::enroll_session::EnrollStatus;

    fn tally(statuses: &[EnrollStatus]) -> EnrollTally {
        let mut tally = EnrollTally::default();
        for status in statuses {
            tally.add(*status);
        }
        tally
    }

    #[test]
    fn test_intro_text_hosted_explains_relay_and_code() {
        let text = intro_text(
            false,
            "https://page.invalid/#x",
            "ABCD-1234",
            None,
            Style::plain(),
        );
        assert!(text.contains("relay"), "{text}");
        assert!(text.contains("cannot decrypt"), "{text}");
        assert!(text.contains(&format!("Read more: {DOCS_URL}")), "{text}");
        assert!(text.contains("\nSession code: ABCD-1234\n"), "{text}");
        assert!(text.contains("Check that your phone shows the same code."));
        assert!(!text.contains("Nothing leaves this machine"));
        assert!(
            !text.contains('\u{1b}'),
            "no escapes without colour: {text}"
        );
    }

    #[test]
    fn test_intro_text_local_says_nothing_leaves() {
        let text = intro_text(
            true,
            "http://127.0.0.1:1/enroll/#x",
            "ABCD-1234",
            None,
            Style::plain(),
        );
        assert!(text.contains("Nothing leaves this machine."), "{text}");
        assert!(text.contains("http://127.0.0.1:1/enroll/#x"), "{text}");
        assert!(text.contains("Check that the page shows the same code."));
        assert!(!text.contains("cannot decrypt"), "{text}");
    }

    #[test]
    fn test_intro_text_colour_highlights_the_code() {
        let text = intro_text(
            false,
            "https://page.invalid/#x",
            "ABCD-1234",
            None,
            Style::rich(),
        );
        let line = text
            .lines()
            .find(|l| l.contains("Session code"))
            .unwrap_or_default();
        assert!(line.starts_with("Session code: \u{1b}"), "{line:?}");
        assert!(line.contains("ABCD-1234"));
    }

    #[test]
    fn test_ending_text_lists_only_applying_steps() {
        let text = ending_text(
            "the phone finished",
            &tally(&[EnrollStatus::Stored, EnrollStatus::Unassigned]),
            Style::plain(),
        );
        assert!(
            text.contains("Session closed (the phone finished)."),
            "{text}"
        );
        assert!(
            text.contains("\n2 sent, 1 added, 1 no device yet\n"),
            "{text}"
        );
        assert!(text.contains("bussard adopt <ADDRESS>"), "{text}");
        assert!(text.contains("bussard keys export <FILE>"), "{text}");
        assert!(!text.contains("bussard keys show"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[test]
    fn test_ending_text_conflict_and_invalid() {
        let text = ending_text(
            "stopped",
            &tally(&[EnrollStatus::Conflict, EnrollStatus::Invalid]),
            Style::plain(),
        );
        assert!(text.contains("bussard keys show"), "{text}");
        assert!(text.contains("bussard keys enroll"), "{text}");
        assert!(!text.contains("keys export"), "{text}");
    }

    #[test]
    fn test_ending_text_nothing_to_do_has_no_steps() {
        let text = ending_text(
            "stopped",
            &tally(&[EnrollStatus::AlreadyStored]),
            Style::plain(),
        );
        assert!(text.contains("1 sent, 1 already known"), "{text}");
        assert!(!text.contains("Next steps"), "{text}");
    }

    #[test]
    fn test_qr_renders_the_link() -> anyhow::Result<()> {
        let out = qr("https://page.invalid/enroll/#v=1")?;
        assert!(out.lines().count() > 10);
        Ok(())
    }
}
