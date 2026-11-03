//! `bussard keys enroll`: take KNX Secure device certificates from a phone
//! (issue #729, protocol `dev/enroll-protocol.md`).
//!
//! Prints the link, a terminal QR code of it and the fingerprint, then one
//! line per certificate the phone sends until the phone sends `done`, the
//! user types `q` (and Enter) or presses Ctrl-C. The relay comes from
//! `--relay` or `[enroll] relay` in `bussard.toml`; there is no built-in
//! default yet. Never prints a certificate or a key: only serials,
//! addresses, names and statuses.

use std::io::BufRead;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use bussard_service::enroll_session::{
    CertificateOutcome, DEFAULT_PAGE, EnrollEnd, EnrollEvent, EnrollSession, HttpRelay, RunOptions,
};
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
}

/// Runs `bussard keys enroll`.
pub fn run(dir: &Path, options: EnrollOptions, json_out: bool) -> anyhow::Result<ExitCode> {
    let config = bussard_model::loader::load_config(dir)
        .with_context(|| format!("reading {}", dir.join("bussard.toml").display()))?
        .enroll
        .unwrap_or_default();
    let Some(relay_url) = options.relay.or(config.relay) else {
        bail!(
            "no enrolment relay: pass --relay <URL> or set `relay` in the [enroll] table of bussard.toml"
        );
    };
    let page = options
        .page
        .or(config.page)
        .unwrap_or_else(|| DEFAULT_PAGE.to_string());

    // Password, store and write access are checked before the link is shown.
    let password = bussard_secure::Password::new(crate::keys_cmd::password()?);
    let mut store = bussard_service::CertificateEnrolment::open(dir, password.expose())?;
    drop(password);

    let mut session = EnrollSession::new().context("starting the enrolment session")?;
    let relay = HttpRelay::new(&relay_url, &session)?;
    let link = session.link(&page, Some(relay.base()));
    let fingerprint = session.fingerprint();

    if json_out {
        crate::output::print(
            crate::output::schema::KEYS_ENROLL,
            &json!({ "event": "session", "link": link, "fingerprint": fingerprint }),
        )?;
    } else {
        println!("Open this link on the phone and scan the certificate labels:\n");
        if !options.no_qr {
            print!("{}", qr(&link)?);
        }
        println!("{link}\n");
        println!("Fingerprint: {fingerprint} (the page must show the same)");
        println!("Type q and Enter, or press Ctrl-C, to finish.\n");
    }

    let stop = Arc::new(AtomicBool::new(false));
    watch_stdin(Arc::clone(&stop));
    watch_ctrl_c(Arc::clone(&stop));

    let mut print_error = None;
    let summary = session.run(
        &relay,
        &mut store,
        RunOptions {
            wait_secs: WAIT_SECS,
        },
        &stop,
        &mut |event| {
            if let Err(err) = show(&event, json_out) {
                print_error.get_or_insert(err);
            }
        },
    )?;
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
            }),
        )?;
    } else {
        println!(
            "\nSession closed ({why}): {} of {} certificate(s) stored.",
            summary.stored, summary.certificates
        );
    }
    Ok(ExitCode::SUCCESS)
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
    match event {
        EnrollEvent::PhoneJoined { phones } => println!("phone {phones} connected"),
        EnrollEvent::Certificate(outcome) => println!("{}", certificate_line(outcome)),
        EnrollEvent::Ignored { reason } => println!("ignored a message: {reason}"),
        EnrollEvent::PhoneDone => println!("the phone finished"),
    }
    Ok(())
}

/// `<serial>  <status>  [<ia> <name>]  [(<message>)]`.
fn certificate_line(outcome: &CertificateOutcome) -> String {
    let mut line = format!(
        "{:<12}  {}",
        outcome.serial.as_deref().unwrap_or("?"),
        outcome.status.as_str()
    );
    if let Some(ia) = &outcome.ia {
        line.push_str(&format!("  {ia}"));
    }
    if let Some(name) = &outcome.name {
        line.push_str(&format!(" {name}"));
    }
    if let Some(message) = &outcome.message {
        line.push_str(&format!("  ({message})"));
    }
    line
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

    #[test]
    fn test_certificate_line_shows_serial_status_and_device() {
        let line = certificate_line(&CertificateOutcome {
            status: EnrollStatus::Stored,
            serial: Some("00FA01020304".to_string()),
            ia: Some("1.1.20".to_string()),
            name: Some("Test actuator".to_string()),
            message: None,
        });
        assert_eq!(line, "00FA01020304  stored  1.1.20 Test actuator");
    }

    #[test]
    fn test_qr_renders_the_link() -> anyhow::Result<()> {
        let out = qr("https://page.invalid/enroll/#v=1")?;
        assert!(out.lines().count() > 10);
        Ok(())
    }

    #[test]
    fn test_run_without_relay_names_the_settings() -> anyhow::Result<()> {
        // A directory without bussard.toml: the default config.
        let dir = Path::new("/nonexistent/bussard-enroll-test");
        let options = EnrollOptions {
            relay: None,
            page: None,
            no_qr: true,
        };
        let Err(err) = run(dir, options, false) else {
            anyhow::bail!("ran without a relay");
        };
        let text = err.to_string();
        assert!(
            text.contains("--relay") && text.contains("[enroll]"),
            "{text}"
        );
        Ok(())
    }
}
