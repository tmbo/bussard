//! Certificate enrolment over MCP (issue #732, part of #201): the
//! `knx_enroll_certificates` and `knx_enroll_status` tools.
//!
//! `knx_enroll_certificates` starts the enrolment session of
//! [`bussard_service::enroll_session`] (the one `bussard keys enroll` runs)
//! in a thread of the server process and opens a **pairing page** in the
//! human's browser (issue #809): [`bussard_viz::pairing_page`] on
//! 127.0.0.1, which shows the session code, a QR code of the phone link and
//! the certificates as they arrive. The human opens the link on a phone (or,
//! with `local: true`, the certificate page in a browser on the computer
//! running the server) and scans the labels; each one is entered into the
//! key store exactly as `bussard keys add-certificate` enters it.
//! `knx_enroll_status` reports the counts so far, and serial, address,
//! name and status per certificate once the session ended or on request.
//! The pairing page lists the certificates, so the results tell the
//! assistant to keep the chat to one line (#820).
//!
//! # The call waits for the end (#831)
//!
//! `knx_enroll_certificates` keeps the call open until the session ends
//! (Finish on the phone, `stop`, a timeout) and then returns the end
//! summary, so the chat continues by itself. While it waits it sends an MCP
//! progress notification on every change (a phone, a certificate) and every
//! [`PROGRESS_INTERVAL_SECS`], when the client sent a progress token.
//! Claude Code (2.1.280, `code.claude.com/docs/en/mcp`) sends one, allows a
//! call about 28 hours (`MCP_TOOL_TIMEOUT`; progress does not extend that),
//! aborts a call that sends nothing for its idle window (5 minutes over
//! HTTP, 30 over stdio; progress resets it) and moves a call that runs past
//! 2 minutes to a background task whose result arrives as a notification.
//! A client without a progress token gets an answer after
//! [`SILENT_WAIT_SECS`], under the shortest idle window, saying the session
//! still runs; the assistant then waits with `knx_enroll_status`
//! (`until_end: true`). A cancelled call (`notifications/cancelled`) stops
//! waiting and leaves the session running.
//!
//! # The link never passes through the assistant
//!
//! A link and session code the assistant relays prove nothing: a prompt
//! injection could hand the human an attacker's link with a matching code
//! (#798, finding F1 of the #201 security review). So the phone link, the
//! session code and the pairing page's URL never appear in a tool result.
//! bussard opens the pairing page itself (`open`, `xdg-open`, `start`, see
//! [`crate::browser`]); when nobody can see a browser here (SSH, no
//! display) the tool refuses with a pointer to `bussard keys enroll`, and no
//! session starts.
//!
//! A client that declares URL-mode elicitation (#798) gets the pairing
//! page's URL as an elicitation instead, a consent step before the page
//! opens. Two transports of that request (MCP 2026-07-28, client features):
//! from protocol 2026-07-28 the tool answers with an `InputRequiredResult`
//! holding the `elicitation/create` request and the client calls the tool
//! again with the human's answer (multi round-trip, SEP-2322); before it,
//! the server sends `elicitation/create` to the client while the call runs.
//!
//! # Key hygiene
//!
//! No tool input or output carries a certificate text or a key. The labels
//! travel from the page to this process end to end encrypted; the tools see
//! only [`CertificateOutcome`]s, which hold none.
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
    EnrollTally, HttpRelay, RunOptions, Timeouts, data_path, endpoint_warnings, hosted_endpoints,
};
use bussard_viz::enroll_local::LocalEnrollServer;
use bussard_viz::pairing_page::{
    PairingCertificate, PairingContent, PairingPage, PairingStatus, StatusFn,
};
use rmcp::handler::server::tool::{InputResponses, RequestState};
use rmcp::model::{
    CallToolResponse, CallToolResult, ElicitRequest, ElicitRequestParams, ElicitResult,
    ElicitationAction, InputRequest, InputRequests, InputRequiredResult, ProgressNotificationParam,
    ProgressToken, ProtocolVersion,
};
use rmcp::schemars::{self, JsonSchema};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use rmcp::{tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::server::BussardMcp;

/// The enrolment tools, withheld with `--no-model-edits` (they write the
/// key store).
pub const ENROLL_TOOLS: [&str; 2] = ["knx_enroll_certificates", "knx_enroll_status"];

/// The relay's session lifetime, which bounds a session.
const SESSION_LIFETIME_SECS: u64 = 4 * 60 * 60;

/// The longest `wait_seconds` of `knx_enroll_status` for the next
/// certificate; `until_end` waits up to the session's lifetime.
const MAX_STATUS_WAIT_SECS: u64 = 120;

/// How often a waiting call sends a progress notification when nothing
/// changed: well inside the shortest idle window of Claude Code (5 minutes,
/// HTTP servers), which a progress notification resets.
pub const PROGRESS_INTERVAL_SECS: u64 = 60;

/// How long a call waits for the end when the client sent no progress
/// token, so nothing resets its idle timer: under Claude Code's shortest
/// idle window (5 minutes).
pub const SILENT_WAIT_SECS: u64 = 4 * 60;

/// What a waiting call says to the chat app once the pairing page is open.
const OPENED_PROGRESS: &str = "The pairing page is open in your browser. Follow the steps there.";

/// The line the pairing page ends with: the human goes back to the chat,
/// which continues by itself (#831).
const BACK_TO_CHAT: &str = "You can close this tab and go back to your chat.";

/// The `requestState` prefix of a multi round-trip enrolment call; the rest
/// is the session's elicitation id.
const REQUEST_STATE_PREFIX: &str = "enroll:";

/// The key of the elicitation in `InputRequiredResult.inputRequests`.
const INPUT_KEY: &str = "enroll_page";

/// The long-poll wait of the session loop: how long a `stop` takes at most
/// to be noticed.
const RUN_WAIT_SECS: u64 = 3;

/// Arguments for `knx_enroll_certificates`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct EnrollArgs {
    /// Serve the enrolment page and its relay on 127.0.0.1 from this
    /// server, for a browser on the same computer (a webcam, or codes typed
    /// in). Default false: the hosted page and relay (or the ones the
    /// `[enroll]` table of bussard.toml names), for a phone.
    #[serde(default)]
    pub local: bool,
}

/// Arguments for `knx_enroll_status`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct EnrollStatusArgs {
    /// Wait up to this many seconds (at most 120) for the next certificate or the
    /// end of the session before answering. Default 0: answer now.
    #[serde(default)]
    pub wait_seconds: Option<u64>,
    /// End the running session (the phone's page shows it closed), then
    /// answer with the final results.
    #[serde(default)]
    pub stop: bool,
    /// Include `results`, one entry per certificate, while the session
    /// runs. Only when the human asks which certificates arrived; the
    /// pairing page lists them. An ended session always includes them.
    #[serde(default)]
    pub details: bool,
    /// Wait for the end of the session rather than the next certificate,
    /// for as long as the chat app allows (`wait_seconds` caps it).
    #[serde(default)]
    pub until_end: bool,
}

/// What the session thread reports, shared with the status tool.
#[derive(Debug, Default)]
struct Progress {
    /// Phones (page loads) that joined.
    phones: usize,
    /// Other phones that tried to join and were refused.
    refused_phones: usize,
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
    /// The id of the elicitation that showed the link, and the handle a
    /// multi round-trip retry names the session by.
    elicitation_id: String,
    local: bool,
    /// F13: the page or relay is not the default (empty otherwise).
    warnings: Vec<String>,
    /// The session's connect, idle and maximum timeouts.
    timeouts: Timeouts,
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
pub struct EnrollJobs {
    current: Arc<Mutex<Option<Arc<EnrollJob>>>>,
    /// The timeouts of every session this server starts.
    timeouts: Timeouts,
}

impl EnrollJobs {
    /// No session yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// No session yet; sessions run with `timeouts` (the tests shorten
    /// them).
    pub fn with_timeouts(timeouts: Timeouts) -> Self {
        Self {
            timeouts,
            ..Self::default()
        }
    }

    fn current(&self) -> Option<Arc<EnrollJob>> {
        lock(&self.current).clone()
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
fn refused(reason: impl Into<String>) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": false,
        "refused": true,
        "reason": reason.into(),
        "summary": "Nothing was changed and no certificate page was opened (`reason` says why).",
    }))
}

/// The refusal when bussard cannot show its pairing page to the human:
/// `reason` says why (no display, the opener failed).
fn no_pairing_page(reason: impl Into<String>) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": false,
        "refused": true,
        "pairing_page_opened": false,
        "reason": reason.into(),
        "summary": "bussard cannot open its pairing page here. Run `bussard keys enroll` in a \
                    terminal in your project folder instead; it shows a QR code for your phone \
                    and the session code.",
        "next_step": "Tell the human to run `bussard keys enroll` in a terminal in the project \
                      folder. Do not offer a link or a session code yourself, and never ask \
                      for a certificate in chat.",
    }))
}

/// Whether the client of this call declared URL-mode elicitation: only then
/// can the link reach the human without passing through the assistant.
fn shows_urls(context: &RequestContext<RoleServer>) -> bool {
    context
        .client_capabilities()
        .and_then(|caps| caps.elicitation)
        .is_some_and(|elicitation| elicitation.url.is_some())
}

/// The host of `link` (`bussard.tmbo.dev`, `127.0.0.1:8123`), for the
/// elicitation message.
fn link_host(link: &str) -> &str {
    let rest = link.split_once("://").map_or(link, |(_, rest)| rest);
    rest.split(['/', '#', '?']).next().unwrap_or(rest)
}

/// The elicitation message: what the pairing page is and where it is
/// served from. Written by the server and shown by the client; the
/// assistant never sees it.
fn elicitation_message(host: &str, warnings: &[String]) -> String {
    let mut message = format!(
        "bussard asks you to open its pairing page, served by bussard on this computer \
         ({host}). It shows the session code and the link for your phone, and lists the \
         certificates you scan. They go into your key store, never into the chat."
    );
    // F13: say so when the page or relay is not the project's.
    for warning in warnings {
        message.push_str(&format!(" Warning: {warning}."));
    }
    message
}

/// A fresh random elicitation id.
fn new_elicitation_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("drawing a random id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Ends `job`'s session and waits for it to close.
async fn close(job: &EnrollJob) {
    if job.running() {
        job.stop.store(true, Ordering::SeqCst);
        wait_for_change(job, Duration::from_secs(RUN_WAIT_SECS + 15), true).await;
    }
}

/// A started session: the job and its pairing page's URL.
struct Started {
    job: Arc<EnrollJob>,
    pairing_url: String,
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

/// `span` in words: `10 minutes`, `1 minute`, `30 seconds`.
fn span_words(span: Duration) -> String {
    let secs = span.as_secs();
    let (n, unit) = if secs >= 60 && secs.is_multiple_of(60) {
        (secs / 60, "minute")
    } else {
        (secs, "second")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// Why the session of `job` ended, in one sentence of the glossary's words;
/// `None` while it runs.
fn end_reason(job: &EnrollJob, progress: &Progress) -> Option<String> {
    let end = progress.end?;
    Some(match end {
        "phone_done" => "Finished on the phone.".to_string(),
        "stopped" => "The session was ended from the chat.".to_string(),
        "connect_timeout" => format!(
            "No phone joined within {}, so the session was closed.",
            span_words(job.timeouts.connect)
        ),
        "idle_timeout" => format!(
            "Nothing happened for {}, so the session was closed.",
            span_words(job.timeouts.idle)
        ),
        "max_duration" | "expired" => "The session ran out of time.".to_string(),
        _ => format!(
            "The session failed: {}.",
            progress.error.as_deref().unwrap_or("for an unknown reason")
        ),
    })
}

/// The certificates of `progress` in one line: serial number and badge
/// (`00FA01020304 added · 0083A1B2C3D4 no device yet`).
fn serials_line(progress: &Progress) -> String {
    progress
        .results
        .iter()
        .map(|outcome| {
            let certificate = PairingCertificate::of(outcome);
            format!("{} {}", certificate.serial, certificate.badge)
        })
        .collect::<Vec<_>>()
        .join(" \u{00B7} ")
}

/// The status of `job` as `knx_enroll_status` returns it: counts while it
/// runs (`results` too with `details`), counts and `results` once ended.
/// The pairing page lists the certificates, so the chat does not (#820).
fn status_json(job: &EnrollJob, details: bool) -> Value {
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
        "The session is open and the pairing page lists each certificate as it arrives, so \
         do not list them or repeat the page in the chat. Say nothing unless the human asks; \
         then give `summary` (the counts) in one line, and serial numbers only when the human \
         asks for them (call again with details: true). To wait for the end, call \
         knx_enroll_status with until_end: true, without a message to the human, and again \
         while it answers `running`; call it with stop: true once the human says they are \
         done."
    } else if steps.is_empty() {
        "The session ended. Give the human `summary` in one or two lines; name serial numbers \
         (`serials`) only if the human asks. Do not repeat the pairing page. Nothing else is \
         left to do."
    } else {
        "The session ended. Give the human `summary` in one or two lines and suggest the first \
         entry of `next_steps` (command and why; those commands run at the CLI). Name serial \
         numbers (`serials`) only if the human asks. Do not repeat the pairing page."
    };
    let mut summary = match end_reason(job, &progress) {
        Some(reason) => format!("{reason} {}", tally.summary()),
        None => format!("The certificate page is open. {}", tally.summary()),
    };
    let refused_warning = (progress.refused_phones > 0).then(|| {
        format!(
            "Another phone tried to join this session and was refused ({} so far); nothing it \
             sent was saved. If it was not the human's, someone else has the link: stop the \
             session (stop: true) and start a new one.",
            progress.refused_phones
        )
    });
    if let Some(warning) = &refused_warning {
        summary = format!("{warning} {summary}");
    }
    let next_step = if refused_warning.is_some() {
        "Tell the human first, plainly, that another phone tried to join this session \
         (`warning`), and ask whether that was them; if not, call knx_enroll_status with \
         stop: true and start a new session."
    } else {
        next_step
    };
    let mut status = json!({
        "ok": progress.error.is_none(),
        "session": if running { "running" } else { "ended" },
        "end": progress.end,
        "error": progress.error,
        "local": job.local,
        "phones": progress.phones,
        "refused_phones": progress.refused_phones,
        "warning": refused_warning,
        "certificates": progress.results.len(),
        "stored": stored,
        "ignored": progress.ignored,
        "tally": tally,
        "expires_in_seconds": if running {
            Some(SESSION_LIFETIME_SECS.saturating_sub(elapsed))
        } else {
            None
        },
        "summary": summary,
        "next_steps": if running { Vec::new() } else { steps },
        "next_step": next_step,
    });
    if details || !running {
        status["results"] = progress.results.iter().map(result_json).collect();
    }
    if !running {
        status["serials"] = json!(serials_line(&progress));
    }
    status
}

/// The progress message of a waiting call: counts only, never a link, a
/// session code or a certificate (#831).
fn progress_message(job: &EnrollJob, progress: &Progress) -> String {
    let device = if job.local {
        "The certificate page"
    } else {
        "Your phone"
    };
    let mut message = if progress.phones == 0 {
        OPENED_PROGRESS.to_string()
    } else if progress.results.is_empty() {
        format!("{device} is connected. Nothing sent yet.")
    } else {
        format!(
            "{device} is connected. {}",
            EnrollTally::of(&progress.results).summary()
        )
    };
    if progress.refused_phones > 0 {
        message.push_str(" Another phone tried to join and was refused.");
    }
    message
}

/// The live part of the pairing page, from `progress`.
fn pairing_status(job: &EnrollJob, progress: &Progress) -> PairingStatus {
    let tally = EnrollTally::of(&progress.results);
    let ended = end_reason(job, progress).map(|reason| {
        if progress.end == Some("phone_done") {
            format!("Done. {BACK_TO_CHAT}")
        } else {
            format!("{reason} {BACK_TO_CHAT}")
        }
    });
    PairingStatus {
        running: ended.is_none(),
        phones: progress.phones,
        refused_phones: progress.refused_phones,
        certificates: progress
            .results
            .iter()
            .map(PairingCertificate::of)
            .collect(),
        summary: tally.summary(),
        next_steps: if ended.is_some() {
            tally.next_steps()
        } else {
            Vec::new()
        },
        ended,
    }
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
    pairing: PairingPage,
    job: &EnrollJob,
) {
    let bump = || job.changed.send_modify(|v| *v += 1);
    let result = session.run(
        &relay,
        &mut sink,
        RunOptions {
            wait_secs: RUN_WAIT_SECS,
            timeouts: job.timeouts,
        },
        &job.stop,
        &mut |event| {
            {
                let mut progress = job.progress();
                match event {
                    EnrollEvent::PhoneJoined => progress.phones = 1,
                    EnrollEvent::PhoneRefused { phones } => progress.refused_phones = phones,
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
                    EnrollEnd::ConnectTimeout => "connect_timeout",
                    EnrollEnd::IdleTimeout => "idle_timeout",
                    EnrollEnd::MaxDuration => "max_duration",
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
    pairing.finish();
}

#[tool_router(router = enroll_router, vis = "pub(crate)")]
impl BussardMcp {
    /// `knx_enroll_certificates`: start a certificate enrolment session.
    #[tool(
        description = "Start a session that takes KNX Secure device certificates (the \
        36-character codes printed on Secure devices) from a phone camera into the key store, \
        without them passing through this chat. bussard opens its pairing page in the human's \
        browser on this computer: it shows the steps, a QR code for the phone, the session \
        code and the certificates as they arrive. Before calling, tell the human in one line \
        that the pairing page opens in their browser and to follow it there; do not repeat its \
        steps or its list in the chat. The call stays open until the session ends (your chat \
        app may move it to the background) and then returns the summary: wait for it, do not \
        poll. The link and the session code never reach you. NEVER \
        write, repeat or guess a link or a session code for this: one coming from you proves \
        nothing. The human scans the QR code, checks the session code on the phone and scans \
        the certificates. Each one is matched to a device by its serial number and stored, \
        end to end encrypted on the way; this tool and knx_enroll_status never return a \
        certificate or a key. NEVER ask the human to paste a certificate into the chat. When \
        bussard cannot open a page here (an SSH session, no display), the tool refuses: tell \
        the human to run `bussard keys enroll` in a terminal. When the result says `session: \
        running` (the call stopped waiting first), wait with knx_enroll_status (until_end: \
        true). `local: true` serves the certificate page from this server on \
        127.0.0.1 too, for a browser on the same computer (a webcam or typed codes); without \
        it the hosted page and relay (or the [enroll] table of bussard.toml) are used. One \
        session at a time; it ends when the human finishes on the phone, on \
        knx_enroll_status with stop: true, when no phone joins within 10 minutes, after 15 \
        minutes without a certificate or the page open, or after 4 hours. One phone per \
        session: another phone that opens the link is refused, and knx_enroll_status reports \
        it in `refused_phones` and `warning`. Writes the key store only \
        (needs BUSSARD_KEYRING_PASSWORD on the server), never the project or the bus."
    )]
    async fn knx_enroll_certificates(
        &self,
        Parameters(args): Parameters<EnrollArgs>,
        context: RequestContext<RoleServer>,
        RequestState(request_state): RequestState,
        InputResponses(input_responses): InputResponses,
    ) -> Result<CallToolResponse, ErrorData> {
        // The client's second round of a 2026-07-28 call: the human's answer.
        if let Some(state) = request_state {
            let answer = input_responses
                .and_then(|responses| responses.get(INPUT_KEY).cloned())
                .and_then(|value| serde_json::from_value::<ElicitResult>(value).ok());
            return Ok(self.enroll_answered(&state, answer, &context).await.into());
        }
        // Nobody would see the page: refuse before a session starts.
        if let Some(reason) = self.browser.no_display() {
            return Ok(no_pairing_page(format!("{reason}; no session was started")).into());
        }
        let started = match self.start_enrolment(args.local) {
            Ok(started) => started,
            Err(refused) => return Ok(refused.into()),
        };
        if !shows_urls(&context) {
            return Ok(self.open_pairing_page(started, &context).await.into());
        }
        let id = started.job.elicitation_id.clone();
        let params = ElicitRequestParams::UrlElicitationParams {
            meta: None,
            message: elicitation_message(link_host(&started.pairing_url), &started.job.warnings),
            url: started.pairing_url,
            elicitation_id: id.clone(),
        };
        if context
            .protocol_version()
            .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28)
        {
            let mut requests = InputRequests::new();
            requests.insert(
                INPUT_KEY.to_owned(),
                InputRequest::Elicitation(ElicitRequest::new(params)),
            );
            return Ok(InputRequiredResult::new(
                Some(requests),
                Some(format!("{REQUEST_STATE_PREFIX}{id}")),
            )
            .into());
        }
        let action = match context.peer.create_elicitation(params).await {
            Ok(result) => result.action,
            Err(err) => {
                // Logged only: a client's error text could echo the URL.
                tracing::warn!(%err, "enrolment: the client did not show the pairing page");
                close(&started.job).await;
                return Ok(no_pairing_page(
                    "the chat app did not show the pairing page; the session was closed",
                )
                .into());
            }
        };
        Ok(self
            .after_elicitation(&started.job, action, &context)
            .await
            .into())
    }

    /// `knx_enroll_status`: the results of the enrolment session so far.
    #[tool(
        description = "The certificate enrolment session started by knx_enroll_certificates: \
        `session` (`running`, `ended` or `none`), `end` (`phone_done`, `stopped`, \
        `connect_timeout`, `idle_timeout`, `max_duration`, `expired` or `error`), `phones`, \
        `refused_phones` and `warning` (another phone tried to join: tell the human first), \
        `certificates` and `stored` (counts), and `results` once the session ended or with \
        `details: true` (only when the human asks; the pairing page lists them), one entry \
        per certificate in arrival order with `serial`, `address` and `name` of the matched device, `status` \
        (`stored`: saved on that device; `unassigned`: saved under its serial until a device \
        reports it; `already_stored`; `conflict`: the store holds another key for the serial, \
        nothing written; `invalid`; `error`) and `message`. Never a certificate's code or a key. \
        `tally` counts the statuses (`stored`, `waiting`, `already_known`, `conflicts`, \
        `invalid`, `errors`); `summary` says it in one line, and once the session has ended \
        `next_steps` lists the CLI commands that apply (`command`, `why`). \
        `wait_seconds` (at most 120) waits for the next certificate or the end first; \
        `until_end: true` waits for the end of the session instead, as long as the chat app \
        allows (`wait_seconds` caps it); `stop: true` ends the session. Reads nothing from the \
        bus."
    )]
    async fn knx_enroll_status(
        &self,
        Parameters(args): Parameters<EnrollStatusArgs>,
        context: RequestContext<RoleServer>,
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
        } else if args.until_end {
            let limit = wait_limit(&job, context.meta.get_progress_token().is_some());
            let limit = args
                .wait_seconds
                .filter(|w| *w > 0)
                .map_or(limit, |w| limit.min(Duration::from_secs(w)));
            wait_for_end(&job, &context, limit).await;
        } else if let Some(wait) = args.wait_seconds.filter(|w| *w > 0) {
            let wait = Duration::from_secs(wait.min(MAX_STATUS_WAIT_SECS));
            wait_for_change(&job, wait, false).await;
        }
        ok(status_json(&job, args.details))
    }
}

impl BussardMcp {
    /// Starts an enrolment session after checking its preconditions; the
    /// error is the refusal to return.
    fn start_enrolment(&self, local: bool) -> Result<Started, CallToolResult> {
        if self.enroll.current().is_some_and(|job| job.running()) {
            return Err(CallToolResult::structured(json!({
                "ok": false,
                "refused": true,
                "reason": "an enrolment session is already running; finish it with \
                           knx_enroll_status (stop: true) before starting another",
                "summary": "A certificate page is already open; finish it first.",
            })));
        }
        let dir = self.state().dir.clone();
        let Ok(password) =
            bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV)
        else {
            return Err(refused(format!(
                "{}; the server needs it to write the key store (ask the human to set it and \
                 restart the server; never ask for the password in chat)",
                bussard_service::secure::SecureKeyError::MissingPassword
            )));
        };
        let password = Password::new(password);
        // The store must load and be writable before the link is shown.
        if let Err(err) =
            bussard_service::CertificateEnrolment::open(&dir, password.expose()).map(drop)
        {
            return Err(refused(format!("{err}; no session was started")));
        }
        let elicitation_id = new_elicitation_id().map_err(refused)?;
        let endpoint = if local {
            LocalEnrollServer::start()
                .map(Endpoint::Local)
                .map_err(|err| refused(format!("starting the local enrolment page: {err}")))?
        } else {
            hosted_endpoint(&dir).map_err(refused)?
        };
        let session = EnrollSession::new()
            .map_err(|err| refused(format!("starting the enrolment session: {err}")))?;
        let (relay_url, page, relay_in_link, local) = match endpoint {
            Endpoint::Hosted { relay, page } => (relay, page, true, None),
            Endpoint::Local(server) => (server.relay_url(), server.page_url(), false, Some(server)),
        };
        let relay = HttpRelay::new(&relay_url, &session).map_err(|err| refused(err.to_string()))?;
        // Local mode: page and relay share the origin, so the link names no relay.
        let link = session.link(&page, relay_in_link.then(|| relay.base()));
        let is_local = local.is_some();
        // F13: say so when the page or relay is not the project's.
        let warnings = if relay_in_link {
            endpoint_warnings(&relay_url, &page)
        } else {
            Vec::new()
        };
        let (changed, _) = watch::channel(0u64);
        let job = Arc::new(EnrollJob {
            elicitation_id,
            local: is_local,
            warnings,
            timeouts: self.enroll.timeouts,
            started: Instant::now(),
            stop: Arc::new(AtomicBool::new(false)),
            progress: Arc::default(),
            changed: Arc::new(changed),
        });
        let page_job = Arc::clone(&job);
        let status: StatusFn = Arc::new(move || pairing_status(&page_job, &page_job.progress()));
        let pairing = PairingPage::start(
            &PairingContent {
                code: session.fingerprint(),
                phone_link: link,
                local: is_local,
                warnings: job.warnings.clone(),
            },
            status,
            job.changed.subscribe(),
        )
        .map_err(|err| refused(format!("starting the pairing page: {err}")))?;
        let pairing_url = pairing.url();
        let sink = FreshKeyStore {
            dir: dir.clone(),
            password,
        };
        let thread_job = Arc::clone(&job);
        std::thread::Builder::new()
            .name("enroll-session".to_owned())
            .spawn(move || run_session(session, relay, sink, local, pairing, &thread_job))
            .map_err(|err| refused(format!("starting the enrolment session: {err}")))?;
        *lock(&self.enroll.current) = Some(Arc::clone(&job));
        Ok(Started { job, pairing_url })
    }

    /// The second round of a multi round-trip call: `state` names the
    /// session, `answer` is the human's answer to the elicitation.
    async fn enroll_answered(
        &self,
        state: &str,
        answer: Option<ElicitResult>,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let job = state.strip_prefix(REQUEST_STATE_PREFIX).and_then(|id| {
            self.enroll
                .current()
                .filter(|job| job.elicitation_id == id && job.running())
        });
        let Some(job) = job else {
            return refused(
                "that certificate page is no longer the current one; call \
                 knx_enroll_certificates again to start a new session",
            );
        };
        // No answer counts as dismissed: the link was not shown.
        let action = answer.map_or(ElicitationAction::Cancel, |answer| answer.action);
        self.after_elicitation(&job, action, context).await
    }

    /// The result once the human answered the elicitation of `job`. Carries
    /// neither the link nor the session code.
    async fn after_elicitation(
        &self,
        job: &EnrollJob,
        action: ElicitationAction,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        if action != ElicitationAction::Accept {
            close(job).await;
            return CallToolResult::structured(json!({
                "ok": false,
                "declined": true,
                "pairing_page_opened": false,
                "session": "ended",
                "summary": "You did not open the pairing page, so the session was closed. \
                            Nothing was changed.",
                "next_step": "The human declined or dismissed the pairing page. Do not offer a \
                              link or a session code yourself. Call knx_enroll_certificates \
                              again only if the human asks to.",
            }));
        }
        self.wait_and_report(job, context).await
    }

    /// Opens the pairing page of `started` in the browser; closes the
    /// session when that fails.
    async fn open_pairing_page(
        &self,
        started: Started,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let browser = Arc::clone(&self.browser);
        let url = started.pairing_url;
        let opened = tokio::task::spawn_blocking(move || browser.open(&url))
            .await
            .unwrap_or_else(|err| Err(format!("opening the browser: {err}")));
        match opened {
            Ok(()) => self.wait_and_report(&started.job, context).await,
            Err(err) => {
                close(&started.job).await;
                no_pairing_page(format!("{err}; the session was closed"))
            }
        }
    }

    /// The result once the pairing page of `job` is open: waits for the end
    /// of the session (#831) and returns its summary, or that it still runs
    /// when the wait stopped first. Carries neither the link, nor the
    /// session code, nor the page's URL.
    async fn wait_and_report(
        &self,
        job: &EnrollJob,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let limit = wait_limit(job, context.meta.get_progress_token().is_some());
        if wait_for_end(job, context, limit).await == Waited::Cancelled {
            tracing::debug!("enrolment: the call was cancelled; the session keeps running");
        }
        let mut result = status_json(job, false);
        result["pairing_page_opened"] = json!(true);
        if job.running() {
            result["data_path"] = json!(data_path(job.local).join(" "));
            result["read_more"] = json!(DOCS_URL);
            result["summary"] = json!(format!(
                "{OPENED_PROGRESS} {}",
                result["summary"].as_str().unwrap_or_default()
            ));
            if result["warning"].is_null() {
                result["next_step"] = json!(STILL_RUNNING);
            }
        }
        if !job.warnings.is_empty() {
            result["warnings"] = json!(job.warnings);
        }
        if let Some(note) = self.keyring_note() {
            result["note"] = json!(note);
        }
        CallToolResult::structured(result)
    }

    /// A note when this server reads its keys from another file than the
    /// key store the certificates go to.
    fn keyring_note(&self) -> Option<String> {
        let state = self.state();
        let keyring = state.keyring.as_ref()?;
        let store = bussard_project::KeyStore::path(&state.dir);
        (!same_file(keyring, &store)).then(|| {
            format!(
                "this server reads its keys from {}, not from the key store {} the certificates \
                 go to; restart it without --keyring to use them",
                keyring.display(),
                store.display()
            )
        })
    }
}

/// The `next_step` of a `knx_enroll_certificates` call that stopped
/// waiting before the session ended.
const STILL_RUNNING: &str = "bussard opened the pairing page in the human's browser and the \
    session still runs; this call stopped waiting so the chat app does not time it out. If you \
    have not yet told the human that the page is open, say so in one line, plus `warnings` and \
    `note` when present; otherwise say nothing. Then call knx_enroll_status with until_end: true \
    at once, and again while it answers `running`. Do not repeat the page's steps, `data_path` \
    or `read_more` unless the human asks. Never write, repeat or guess a link or a session code: \
    if the human closed the page, stop this session (knx_enroll_status, stop: true) and start a \
    new one.";

/// How a wait for the end of a session stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waited {
    /// The session ended.
    Ended,
    /// The client cancelled the call; the session keeps running.
    Cancelled,
    /// The wait's limit passed first; the session keeps running.
    TimedOut,
}

/// The longest a call waits for the end of `job`: past the session's
/// maximum when the client sent a progress token (the notifications keep
/// its idle timer from firing), else [`SILENT_WAIT_SECS`].
fn wait_limit(job: &EnrollJob, has_progress_token: bool) -> Duration {
    if has_progress_token {
        job.timeouts.max + Duration::from_secs(RUN_WAIT_SECS + 60)
    } else {
        Duration::from_secs(SILENT_WAIT_SECS)
    }
}

/// Sends progress notification number `seq` with `message` for `token`.
async fn notify_progress(
    context: &RequestContext<RoleServer>,
    token: &ProgressToken,
    seq: u32,
    message: &str,
) {
    let param = ProgressNotificationParam::new(token.clone(), f64::from(seq)).with_message(message);
    if let Err(err) = context.peer.notify_progress(param).await {
        tracing::debug!(%err, "enrolment: a progress notification was not sent");
    }
}

/// Waits up to `limit` for `job` to end. When the client of `context` sent
/// a progress token, sends a progress notification on every change (a
/// phone, a certificate) and every [`PROGRESS_INTERVAL_SECS`] without one;
/// the progress value counts the notifications, so it always increases.
/// Returns early when the client cancels the call.
async fn wait_for_end(
    job: &EnrollJob,
    context: &RequestContext<RoleServer>,
    limit: Duration,
) -> Waited {
    let token = context.meta.get_progress_token();
    let mut changes = job.changed.subscribe();
    let deadline = tokio::time::Instant::now() + limit;
    let interval = Duration::from_secs(PROGRESS_INTERVAL_SECS);
    let mut sent = 0u32;
    let mut last: Option<String> = None;
    loop {
        let message = {
            let progress = job.progress();
            if progress.end.is_some() {
                return Waited::Ended;
            }
            progress_message(job, &progress)
        };
        if let Some(token) = &token
            && last.as_deref() != Some(message.as_str())
        {
            sent = sent.saturating_add(1);
            notify_progress(context, token, sent, &message).await;
            last = Some(message);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Waited::TimedOut;
        }
        let wake = deadline.min(now + interval);
        tokio::select! {
            () = context.ct.cancelled() => return Waited::Cancelled,
            changed = tokio::time::timeout_at(wake, changes.changed()) => match changed {
                Ok(Ok(())) => {}
                // Nothing changed for an interval: send the same line again.
                Err(_) => last = None,
                // The sender is gone: nothing changes any more.
                Ok(Err(_)) => {
                    return if job.running() { Waited::TimedOut } else { Waited::Ended };
                }
            },
        }
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
            elicitation_id: "00".to_string(),
            local: false,
            warnings: Vec::new(),
            timeouts: Timeouts::default(),
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
        let status = status_json(&job, false);
        assert_eq!(
            status["summary"],
            "Finished on the phone. 2 sent \u{00B7} 1 no device yet \u{00B7} 1 conflict"
        );
        assert_eq!(
            status["serials"],
            "00FA01020304 no device yet \u{00B7} 00FA01020304 conflict"
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
        let status = status_json(&job_with(&[EnrollStatus::Stored], None), false);
        assert_eq!(status["next_steps"], json!([]));
        assert_eq!(status["session"], "running");
    }

    #[test]
    fn test_status_json_running_gives_counts_not_serials() {
        let job = job_with(&[EnrollStatus::Stored, EnrollStatus::Unassigned], None);
        let status = status_json(&job, false);
        assert_eq!(status["certificates"], 2);
        assert_eq!(status["stored"], 2);
        assert!(status.get("results").is_none(), "{status}");
        let next = status["next_step"].as_str().unwrap_or_default();
        assert!(next.contains("do not list them"), "{next}");
        let detailed = status_json(&job, true);
        assert_eq!(detailed["results"].as_array().map(Vec::len), Some(2));
        let ended = status_json(
            &job_with(&[EnrollStatus::Stored], Some("phone_done")),
            false,
        );
        assert_eq!(ended["results"].as_array().map(Vec::len), Some(1));
        let next = ended["next_step"].as_str().unwrap_or_default();
        assert!(next.contains("in one or two lines"), "{next}");
    }

    #[test]
    fn test_end_reason_names_each_end() {
        let mut job = job_with(&[], Some("connect_timeout"));
        let reason = |job: &EnrollJob| end_reason(job, &job.progress());
        assert_eq!(
            reason(&job).as_deref(),
            Some("No phone joined within 10 minutes, so the session was closed.")
        );
        job.timeouts.connect = Duration::from_secs(1);
        assert_eq!(
            reason(&job).as_deref(),
            Some("No phone joined within 1 second, so the session was closed.")
        );
        job.progress().end = Some("phone_done");
        assert_eq!(reason(&job).as_deref(), Some("Finished on the phone."));
        job.progress().end = None;
        assert_eq!(reason(&job), None);
    }

    #[test]
    fn test_pairing_status_ended_points_back_to_the_chat() {
        let job = job_with(&[EnrollStatus::Stored], Some("phone_done"));
        let status = pairing_status(&job, &job.progress());
        assert_eq!(
            status.ended.as_deref(),
            Some("Done. You can close this tab and go back to your chat.")
        );
        let job = job_with(&[], Some("stopped"));
        let status = pairing_status(&job, &job.progress());
        assert_eq!(
            status.ended.as_deref(),
            Some(
                "The session was ended from the chat. You can close this tab and go back to \
                 your chat."
            )
        );
        let running = job_with(&[], None);
        assert!(pairing_status(&running, &running.progress()).running);
    }

    #[test]
    fn test_progress_message_has_counts_and_no_link() {
        let job = job_with(&[], None);
        assert_eq!(progress_message(&job, &job.progress()), OPENED_PROGRESS);
        let job = job_with(&[EnrollStatus::Stored, EnrollStatus::Unassigned], None);
        job.progress().phones = 1;
        let message = progress_message(&job, &job.progress());
        assert_eq!(
            message,
            "Your phone is connected. 2 sent \u{00B7} 1 added \u{00B7} 1 no device yet"
        );
        assert!(!message.contains("http"), "{message}");
    }

    #[test]
    fn test_wait_limit_without_progress_token_stays_under_the_idle_window() {
        let job = job_with(&[], None);
        assert_eq!(
            wait_limit(&job, false),
            Duration::from_secs(SILENT_WAIT_SECS)
        );
        const { assert!(SILENT_WAIT_SECS < 5 * 60) };
        const { assert!(PROGRESS_INTERVAL_SECS < 5 * 60) };
        assert!(wait_limit(&job, true) > job.timeouts.max);
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
