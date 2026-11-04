//! Certificate enrolment over MCP (issue #732, part of #201): the
//! `knx_enroll_certificates` and `knx_enroll_status` tools.
//!
//! `knx_enroll_certificates` starts the enrolment session of
//! [`bussard_service::enroll_session`] (the one `bussard keys enroll` runs)
//! in a thread of the server process and returns the link and the
//! fingerprint. The human opens the link on a phone (or, with `local: true`,
//! in a browser on the computer running the server) and scans the labels;
//! each one is entered into the key store exactly as `bussard keys
//! add-certificate` enters it. `knx_enroll_status` reports the results so
//! far: serial, address, name and status per label.
//!
//! # Key hygiene
//!
//! No tool input or output carries a certificate text or a key. The labels
//! travel from the page to this process end to end encrypted; the tools see
//! only [`CertificateOutcome`]s, which hold none. The link carries the
//! session's public key, which is meant to be shown.
//!
//! The tools write the key store, never the model or the bus: they are
//! withheld with `--no-model-edits` like the model edits and registered in
//! every bus tier, `--passive` included.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::args::Parameters;
use bussard_secure::Password;
use bussard_service::enroll_session::{
    CertificateOutcome, CertificateSink, DOCS_URL, EnrollEnd, EnrollEvent, EnrollSession,
    EnrollTally, HttpRelay, RunOptions, data_path, hosted_endpoints,
};
use bussard_viz::enroll_local::LocalEnrollServer;
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::server::BussardMcp;

/// The enrolment tools, withheld with `--no-model-edits` (they write the
/// key store).
pub const ENROLL_TOOLS: [&str; 2] = ["knx_enroll_certificates", "knx_enroll_status"];

/// The relay's session lifetime, which bounds a session.
const SESSION_LIFETIME_SECS: u64 = 30 * 60;

/// The longest `wait_seconds` of `knx_enroll_status`.
const MAX_STATUS_WAIT_SECS: u64 = 120;

/// The long-poll wait of the session loop: how long a `stop` takes at most
/// to be noticed.
const RUN_WAIT_SECS: u64 = 3;

/// Arguments for `knx_enroll_certificates`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct EnrollArgs {
    /// Serve the enrolment page and its relay on 127.0.0.1 from this
    /// server, for a browser on the same computer (a webcam, or labels typed
    /// in). Default false: the hosted page and relay (or the ones the
    /// `[enroll]` table of bussard.toml names), for a phone.
    #[serde(default)]
    pub local: bool,
}

/// Arguments for `knx_enroll_status`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct EnrollStatusArgs {
    /// Wait up to this many seconds (at most 120) for the next label or the
    /// end of the session before answering. Default 0: answer now.
    #[serde(default)]
    pub wait_seconds: Option<u64>,
    /// End the running session (the phone's page shows it closed), then
    /// answer with the final results.
    #[serde(default)]
    pub stop: bool,
}

/// What the session thread reports, shared with the status tool.
#[derive(Debug, Default)]
struct Progress {
    /// Phones (page loads) that joined.
    phones: usize,
    /// One outcome per label, in arrival order.
    results: Vec<CertificateOutcome>,
    /// Messages dropped (not an envelope, not for this session).
    ignored: u32,
    /// How the session ended; `None` while it runs.
    end: Option<&'static str>,
    /// Why the session failed, when it did.
    error: Option<String>,
}

/// One enrolment session of this server.
#[derive(Debug)]
struct EnrollJob {
    link: String,
    fingerprint: String,
    local: bool,
    started: Instant,
    stop: Arc<AtomicBool>,
    progress: Arc<Mutex<Progress>>,
    /// Bumped on every change of `progress`, to wake a waiting status call.
    changed: Arc<watch::Sender<u64>>,
}

impl EnrollJob {
    fn progress(&self) -> MutexGuard<'_, Progress> {
        lock(&self.progress)
    }

    fn running(&self) -> bool {
        self.progress().end.is_none()
    }
}

/// The server's enrolment session: at most one at a time, shared by every
/// clone of the handler.
#[derive(Debug, Clone, Default)]
pub struct EnrollJobs(Arc<Mutex<Option<Arc<EnrollJob>>>>);

impl EnrollJobs {
    /// No session yet.
    pub fn new() -> Self {
        Self::default()
    }

    fn current(&self) -> Option<Arc<EnrollJob>> {
        lock(&self.0).clone()
    }
}

/// A lock that survives a panicked holder: the data is a report.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The key store of the model in `dir`, opened afresh for every label, so a
/// long session never writes back a stale copy over another edit of the
/// store (`knx_set_group` switching Data Secure, a `keys import`).
struct FreshKeyStore {
    dir: PathBuf,
    password: Password,
}

impl CertificateSink for FreshKeyStore {
    fn enroll(&mut self, text: &str) -> CertificateOutcome {
        match bussard_service::enroll::enroll_certificate(&self.dir, self.password.expose(), text) {
            Ok(outcome) => outcome.into(),
            Err(err) => CertificateOutcome::error(err.to_string()),
        }
    }
}

/// Turns a JSON value into a structured tool result.
fn ok(value: Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::structured(value))
}

/// A refusal: `ok: false` and the reason, as a normal result.
fn refusal(reason: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    ok(json!({
        "ok": false,
        "refused": true,
        "reason": reason.into(),
        "summary": "Nothing was changed and no certificate page was opened (`reason` says why).",
    }))
}

/// One label as the tools report it: never a key.
fn result_json(outcome: &CertificateOutcome) -> Value {
    let mut entry = json!({
        "serial": outcome.serial,
        "address": outcome.ia,
        "name": outcome.name,
        "status": outcome.status.as_str(),
    });
    if let Some(message) = &outcome.message {
        entry["message"] = json!(message);
    }
    entry
}

/// The status of `job` as `knx_enroll_status` returns it.
fn status_json(job: &EnrollJob) -> Value {
    let progress = job.progress();
    let stored = progress
        .results
        .iter()
        .filter(|r| r.status.is_stored())
        .count();
    let running = progress.end.is_none();
    let elapsed = job.started.elapsed().as_secs();
    let tally = EnrollTally::of(&progress.results);
    let steps = tally.next_steps();
    let next_step = if running {
        "The session is open. Tell the human how many labels arrived and what became of each \
         (quote serial, address, name and status), and ask whether more labels are to come. \
         Call knx_enroll_status again (wait_seconds to wait for the next one), and with \
         stop: true once the human is done."
    } else if steps.is_empty() {
        "The session is closed. Give the human `summary`; nothing else is left to do."
    } else {
        "The session is closed. Give the human `summary` and each entry of `next_steps` \
         (command and why). Those commands run at the CLI."
    };
    let summary = format!(
        "{} {}",
        if running {
            "The certificate page is open."
        } else {
            "The certificate page is closed."
        },
        tally.summary()
    );
    json!({
        "ok": progress.error.is_none(),
        "session": if running { "running" } else { "ended" },
        "end": progress.end,
        "error": progress.error,
        "link": job.link,
        "fingerprint": job.fingerprint,
        "local": job.local,
        "phones": progress.phones,
        "certificates": progress.results.len(),
        "stored": stored,
        "ignored": progress.ignored,
        "tally": tally,
        "results": progress.results.iter().map(result_json).collect::<Vec<_>>(),
        "expires_in_seconds": if running {
            Some(SESSION_LIFETIME_SECS.saturating_sub(elapsed))
        } else {
            None
        },
        "summary": summary,
        "next_steps": if running { Vec::new() } else { steps },
        "next_step": next_step,
    })
}

/// How the session's relay is reached: the hosted page and relay of
/// bussard.toml, or the local server.
enum Endpoint {
    Hosted { relay: String, page: String },
    Local(LocalEnrollServer),
}

/// The relay and page of a hosted session for the model in `dir`: the
/// `[enroll]` table of bussard.toml, else the hosted relay and page.
fn hosted_endpoint(dir: &Path) -> Result<Endpoint, String> {
    let config = bussard_model::loader::load_config(dir)
        .map_err(|e| format!("reading {}: {e}", dir.join("bussard.toml").display()))?
        .enroll
        .unwrap_or_default();
    let (relay, page) = hosted_endpoints(None, None, &config);
    Ok(Endpoint::Hosted { relay, page })
}

/// Runs `session` to its end in this thread, recording into `job`.
fn run_session(
    mut session: EnrollSession,
    relay: HttpRelay,
    mut sink: FreshKeyStore,
    local: Option<LocalEnrollServer>,
    job: &EnrollJob,
) {
    let bump = || job.changed.send_modify(|v| *v += 1);
    let result = session.run(
        &relay,
        &mut sink,
        RunOptions {
            wait_secs: RUN_WAIT_SECS,
        },
        &job.stop,
        &mut |event| {
            {
                let mut progress = job.progress();
                match event {
                    EnrollEvent::PhoneJoined { phones } => progress.phones = phones,
                    EnrollEvent::Certificate(outcome) => progress.results.push(outcome),
                    EnrollEvent::Ignored { reason } => {
                        progress.ignored += 1;
                        tracing::debug!(%reason, "enrolment: ignored a message");
                    }
                    EnrollEvent::PhoneDone => {}
                }
            }
            bump();
        },
    );
    if let Some(server) = local {
        server.finish();
    }
    {
        let mut progress = job.progress();
        match result {
            Ok(summary) => {
                progress.end = Some(match summary.end {
                    EnrollEnd::PhoneDone => "phone_done",
                    EnrollEnd::Stopped => "stopped",
                    EnrollEnd::Expired => "expired",
                });
            }
            Err(err) => {
                progress.end = Some("error");
                progress.error = Some(err.to_string());
            }
        }
    }
    bump();
}

#[tool_router(router = enroll_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_enroll_certificates`: start a certificate enrolment session.
    #[tool(
        description = "Start a session that takes KNX Secure device certificates (the \
        36-character FDSK labels printed on Secure devices) from a phone camera into the key \
        store, without the labels passing through this chat. Returns `link` and \
        `fingerprint`. Give the human both: they open the link on the phone, check that the \
        page shows the same fingerprint, and scan the labels. Each label is matched to a \
        device by its serial number and stored, end to end encrypted on the way; this tool \
        and knx_enroll_status never return a label or a key. NEVER ask the human to paste a \
        label into the chat. Follow up with knx_enroll_status. `local: true` serves the page \
        from this server on 127.0.0.1 instead, for a browser on the same computer (a webcam \
        or typed labels); without it the hosted page and relay (or the [enroll] table of \
        bussard.toml) are used. One \
        session at a time; it ends when the human finishes on the phone, on \
        knx_enroll_status with stop: true, or after 30 minutes. Writes the key store only \
        (needs BUSSARD_KEYRING_PASSWORD on the server), never the model or the bus."
    )]
    async fn knx_enroll_certificates(
        &self,
        Parameters(args): Parameters<EnrollArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(job) = self.enroll.current()
            && job.running()
        {
            return ok(json!({
                "ok": false,
                "refused": true,
                "reason": "an enrolment session is already running; finish it with \
                           knx_enroll_status (stop: true) before starting another",
                "link": job.link,
                "fingerprint": job.fingerprint,
                "local": job.local,
                "summary": "A certificate page is already open; finish it first.",
            }));
        }
        let dir = self.state().dir.clone();
        let Ok(password) =
            bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV)
        else {
            return refusal(format!(
                "{}; the server needs it to write the key store (ask the human to set it and \
                 restart the server; never ask for the password in chat)",
                bussard_service::secure::SecureKeyError::MissingPassword
            ));
        };
        let password = Password::new(password);
        // The store must load and be writable before the link is shown.
        if let Err(err) =
            bussard_service::CertificateEnrolment::open(&dir, password.expose()).map(drop)
        {
            return refusal(format!("{err}; no session was started"));
        }
        let endpoint = if args.local {
            match LocalEnrollServer::start() {
                Ok(server) => Endpoint::Local(server),
                Err(err) => return refusal(format!("starting the local enrolment page: {err}")),
            }
        } else {
            match hosted_endpoint(&dir) {
                Ok(endpoint) => endpoint,
                Err(reason) => return refusal(reason),
            }
        };
        let session = match EnrollSession::new() {
            Ok(session) => session,
            Err(err) => return refusal(format!("starting the enrolment session: {err}")),
        };
        let (relay_url, page, relay_in_link, local) = match endpoint {
            Endpoint::Hosted { relay, page } => (relay, page, true, None),
            Endpoint::Local(server) => (server.relay_url(), server.page_url(), false, Some(server)),
        };
        let relay = match HttpRelay::new(&relay_url, &session) {
            Ok(relay) => relay,
            Err(err) => return refusal(err.to_string()),
        };
        // Local mode: page and relay share the origin, so the link names no relay.
        let link = session.link(&page, relay_in_link.then(|| relay.base()));
        let fingerprint = session.fingerprint();
        let is_local = local.is_some();
        let (changed, _) = watch::channel(0u64);
        let job = Arc::new(EnrollJob {
            link: link.clone(),
            fingerprint: fingerprint.clone(),
            local: is_local,
            started: Instant::now(),
            stop: Arc::new(AtomicBool::new(false)),
            progress: Arc::default(),
            changed: Arc::new(changed),
        });
        let sink = FreshKeyStore {
            dir: dir.clone(),
            password,
        };
        let thread_job = Arc::clone(&job);
        let spawned = std::thread::Builder::new()
            .name("enroll-session".to_owned())
            .spawn(move || run_session(session, relay, sink, local, &thread_job));
        if let Err(err) = spawned {
            return refusal(format!("starting the enrolment session: {err}"));
        }
        *lock(&self.enroll.0) = Some(job);

        let mut result = json!({
            "ok": true,
            "link": link,
            "fingerprint": fingerprint,
            "local": is_local,
            "expires_in_seconds": SESSION_LIFETIME_SECS,
            "data_path": data_path(is_local).join(" "),
            "read_more": DOCS_URL,
            "summary": format!(
                "The certificate page is ready. Open the link {}, check that it shows the code \
                 {fingerprint}, and scan the labels on the Secure devices. Each one is saved in \
                 the key store; nothing is sent to the devices.",
                if is_local { "in a browser on this computer" } else { "on your phone" }
            ),
            "next_step": if is_local {
                "Give the human the link, the fingerprint (the session code), `data_path` and \
                 the `read_more` link. They open the link in a browser \
                 on the computer running this server (it is served on 127.0.0.1; a phone cannot \
                 reach it), check that the page shows the same fingerprint, and scan or type \
                 the labels there, never in this chat. Then call knx_enroll_status \
                 (wait_seconds to wait for labels)."
            } else {
                "Give the human the link, the fingerprint (the session code), `data_path` and \
                 the `read_more` link. They open the link on the phone, \
                 check that the page shows the same fingerprint, and scan the labels there, \
                 never in this chat. Then call knx_enroll_status (wait_seconds to wait for \
                 labels)."
            },
        });
        // A server reading another keyring does not see what this stores.
        if let Some(keyring) = &self.state().keyring {
            let store = bussard_project::KeyStore::path(&dir);
            if !same_file(keyring, &store) {
                result["note"] = json!(format!(
                    "this server reads its keys from {}, not from the key store {} the labels \
                     go to; restart it without --keyring to use them",
                    keyring.display(),
                    store.display()
                ));
            }
        }
        ok(result)
    }

    /// `knx_enroll_status`: the results of the enrolment session so far.
    #[tool(
        description = "The certificate enrolment session started by knx_enroll_certificates: \
        `session` (`running`, `ended` or `none`), `end` (`phone_done`, `stopped`, `expired` or \
        `error`), `phones`, `certificates`, `stored`, and `results`, one entry per label in \
        arrival order with `serial`, `address` and `name` of the matched device, `status` \
        (`stored`: saved on that device; `unassigned`: saved under its serial until a device \
        reports it; `already_stored`; `conflict`: the store holds another key for the serial, \
        nothing written; `invalid`; `error`) and `message`. Never a label or a key. \
        `tally` counts the statuses (`stored`, `waiting`, `already_known`, `conflicts`, \
        `invalid`, `errors`); `summary` says it in one line, and once the session has ended \
        `next_steps` lists the CLI commands that apply (`command`, `why`). \
        `wait_seconds` (at most 120) waits for the next label or the end first; `stop: true` \
        ends the session. Reads nothing from the bus."
    )]
    async fn knx_enroll_status(
        &self,
        Parameters(args): Parameters<EnrollStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let Some(job) = self.enroll.current() else {
            return ok(json!({
                "ok": true,
                "session": "none",
                "summary": "No certificate page is open.",
                "next_step": "No enrolment session was started; knx_enroll_certificates \
                              starts one.",
            }));
        };
        if args.stop && job.running() {
            job.stop.store(true, Ordering::SeqCst);
            // The loop notices within one long poll and closes the session.
            wait_for_change(&job, Duration::from_secs(RUN_WAIT_SECS + 15), true).await;
        } else if let Some(wait) = args.wait_seconds.filter(|w| *w > 0) {
            let wait = Duration::from_secs(wait.min(MAX_STATUS_WAIT_SECS));
            wait_for_change(&job, wait, false).await;
        }
        ok(status_json(&job))
    }
}

/// Waits up to `wait` for `job` to change (a new label, a phone, the end),
/// or with `until_end` for it to end.
async fn wait_for_change(job: &EnrollJob, wait: Duration, until_end: bool) {
    let mut changes = job.changed.subscribe();
    let deadline = tokio::time::Instant::now() + wait;
    let seen = job.progress().results.len();
    loop {
        {
            let progress = job.progress();
            if progress.end.is_some() || (!until_end && progress.results.len() > seen) {
                return;
            }
        }
        match tokio::time::timeout_at(deadline, changes.changed()).await {
            Ok(Ok(())) => {}
            // Timed out, or the sender is gone.
            _ => return,
        }
    }
}

/// Whether `a` and `b` name the same file.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_service::enroll_session::EnrollStatus;

    #[test]
    fn test_result_json_names_serial_address_name_status() {
        let entry = result_json(&CertificateOutcome {
            status: EnrollStatus::Stored,
            serial: Some("00FA01020304".to_string()),
            ia: Some("1.1.20".to_string()),
            name: Some("Actuator".to_string()),
            message: None,
        });
        assert_eq!(
            entry,
            json!({
                "serial": "00FA01020304",
                "address": "1.1.20",
                "name": "Actuator",
                "status": "stored",
            })
        );
    }

    fn job_with(statuses: &[EnrollStatus], end: Option<&'static str>) -> EnrollJob {
        let (changed, _) = watch::channel(0u64);
        let results = statuses
            .iter()
            .map(|status| CertificateOutcome {
                status: *status,
                serial: Some("00FA01020304".to_string()),
                ia: None,
                name: None,
                message: None,
            })
            .collect();
        EnrollJob {
            link: "https://page.invalid/#x".to_string(),
            fingerprint: "ABCD-1234".to_string(),
            local: false,
            started: Instant::now(),
            stop: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(Progress {
                results,
                end,
                ..Progress::default()
            })),
            changed: Arc::new(changed),
        }
    }

    #[test]
    fn test_status_json_ended_has_summary_and_next_steps() {
        let job = job_with(
            &[EnrollStatus::Unassigned, EnrollStatus::Conflict],
            Some("phone_done"),
        );
        let status = status_json(&job);
        assert_eq!(
            status["summary"],
            "The certificate page is closed. 2 sent \u{00B7} 1 no device yet \u{00B7} 1 conflict"
        );
        assert_eq!(status["tally"]["waiting"], 1);
        assert_eq!(status["tally"]["conflicts"], 1);
        let commands: Vec<&str> = status["next_steps"]
            .as_array()
            .map(|steps| steps.iter().filter_map(|s| s["command"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(
            commands,
            [
                "bussard scan <LINE>, or bussard adopt <ADDRESS>",
                "bussard keys export <FILE>",
                "bussard keys show"
            ]
        );
    }

    #[test]
    fn test_status_json_running_has_no_next_steps() {
        let status = status_json(&job_with(&[EnrollStatus::Stored], None));
        assert_eq!(status["next_steps"], json!([]));
        assert_eq!(status["session"], "running");
    }

    #[test]
    fn test_hosted_endpoint_reads_the_enroll_table() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("bussard.toml"), "")?;
        let Ok(Endpoint::Hosted { relay, page }) = hosted_endpoint(dir.path()) else {
            return Err("no hosted endpoint".into());
        };
        assert_eq!(relay, bussard_service::enroll_session::DEFAULT_RELAY);
        assert_eq!(page, bussard_service::enroll_session::DEFAULT_PAGE);
        std::fs::write(
            dir.path().join("bussard.toml"),
            "[enroll]\nrelay = \"https://relay.example\"\n",
        )?;
        let Ok(Endpoint::Hosted { relay, .. }) = hosted_endpoint(dir.path()) else {
            return Err("no hosted endpoint".into());
        };
        assert_eq!(relay, "https://relay.example");
        Ok(())
    }
}
