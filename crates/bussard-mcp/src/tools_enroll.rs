//! Certificate enrolment over MCP (issue #732, part of #201): the
//! `knx_enroll_certificates` and `knx_enroll_status` tools.
//!
//! `knx_enroll_certificates` starts the enrolment session of
//! [`bussard_service::enroll_session`] (the one `bussard keys enroll` runs)
//! in a thread of the server process and shows the link to the human with
//! URL-mode elicitation (issue #798). The human opens the link on a phone
//! (or, with `local: true`, in a browser on the computer running the server)
//! and scans the labels; each one is entered into the key store exactly as
//! `bussard keys add-certificate` enters it. `knx_enroll_status` reports the
//! results so far: serial, address, name and status per label.
//!
//! # The link never passes through the assistant
//!
//! A link and session code the assistant relays prove nothing: a prompt
//! injection could hand the human an attacker's link with a matching code
//! (#798, finding F1 of the #201 security review). So the link and the
//! session code go to the human only in the elicitation, which the client
//! shows with the full URL and asks consent for; no tool result carries
//! either. A client that does not declare URL-mode elicitation gets a
//! refusal pointing at `bussard keys enroll`, and no session starts.
//!
//! Two transports of the same request (MCP 2026-07-28, client features):
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
    EnrollTally, HttpRelay, RunOptions, data_path, hosted_endpoints,
};
use bussard_viz::enroll_local::LocalEnrollServer;
use rmcp::handler::server::tool::{InputResponses, RequestState};
use rmcp::model::{
    CallToolResponse, CallToolResult, ElicitRequest, ElicitRequestParams, ElicitResult,
    ElicitationAction, InputRequest, InputRequests, InputRequiredResult, ProtocolVersion,
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
const SESSION_LIFETIME_SECS: u64 = 30 * 60;

/// The longest `wait_seconds` of `knx_enroll_status`.
const MAX_STATUS_WAIT_SECS: u64 = 120;

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
    /// The id of the elicitation that showed the link, and the handle a
    /// multi round-trip retry names the session by.
    elicitation_id: String,
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
fn refused(reason: impl Into<String>) -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": false,
        "refused": true,
        "reason": reason.into(),
        "summary": "Nothing was changed and no certificate page was opened (`reason` says why).",
    }))
}

/// The refusal for a client that cannot show a link to the human itself.
fn no_url_elicitation() -> CallToolResult {
    CallToolResult::structured(json!({
        "ok": false,
        "refused": true,
        "reason": "this chat app cannot show a link to the human directly (it does not \
                   declare URL-mode elicitation), and the certificate page link must never \
                   pass through the assistant",
        "summary": "This chat app cannot open the certificate page for you. Run \
                    `bussard keys enroll` in a terminal in your project folder instead; it \
                    shows the link, a QR code for your phone and the session code.",
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

/// The elicitation message: what the page is, where it is served from and
/// the session code to check. Written by the server and shown by the
/// client; the assistant never sees it.
fn elicitation_message(host: &str, code: &str, local: bool) -> String {
    let open = if local {
        "Open it in a browser on this computer"
    } else {
        "Open it on the phone you scan with"
    };
    format!(
        "bussard asks you to open its certificate page on {host}. {open}, check that the page \
         shows the session code {code}, then scan the certificates on your Secure devices. \
         They go into your key store, never into the chat."
    )
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

/// A started session: the job and what the elicitation shows.
struct Started {
    job: Arc<EnrollJob>,
    link: String,
    message: String,
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
        36-character codes printed on Secure devices) from a phone camera into the key store, \
        without them passing through this chat. The chat app shows the human the certificate \
        page link and the session code itself (MCP URL elicitation) and asks before opening \
        it; neither ever reaches you. NEVER write, repeat or guess a link or a session code \
        for this: one coming from you proves nothing. The human opens the page, checks the \
        session code and scans the certificates. Each one is matched to a device by its \
        serial number and stored, end to end encrypted on the way; this tool and \
        knx_enroll_status never return a certificate or a key. NEVER ask the human to paste \
        a certificate into the chat. When the chat app cannot show a link, the tool refuses: \
        tell the human to run `bussard keys enroll` in a terminal. Follow up with \
        knx_enroll_status. `local: true` serves the page from this server on 127.0.0.1 \
        instead, for a browser on the same computer (a webcam or typed codes); without it \
        the hosted page and relay (or the [enroll] table of bussard.toml) are used. One \
        session at a time; it ends when the human finishes on the phone, declines the link, \
        on knx_enroll_status with stop: true, or after 30 minutes. Writes the key store only \
        (needs BUSSARD_KEYRING_PASSWORD on the server), never the model or the bus."
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
            return Ok(self.enroll_answered(&state, answer).await.into());
        }
        if !shows_urls(&context) {
            return Ok(no_url_elicitation().into());
        }
        let started = match self.start_enrolment(args.local) {
            Ok(started) => started,
            Err(refused) => return Ok(refused.into()),
        };
        let id = started.job.elicitation_id.clone();
        let params = ElicitRequestParams::UrlElicitationParams {
            meta: None,
            message: started.message,
            url: started.link,
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
                // Logged only: a client's error text could echo the link.
                tracing::warn!(%err, "enrolment: the client did not show the link");
                close(&started.job).await;
                return Ok(refused(
                    "the chat app did not show the certificate page link; the session was \
                     closed. Run `bussard keys enroll` in a terminal instead",
                )
                .into());
            }
        };
        Ok(self.after_elicitation(&started.job, action).await.into())
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
        let message = elicitation_message(link_host(&link), &session.fingerprint(), is_local);
        let (changed, _) = watch::channel(0u64);
        let job = Arc::new(EnrollJob {
            elicitation_id,
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
        std::thread::Builder::new()
            .name("enroll-session".to_owned())
            .spawn(move || run_session(session, relay, sink, local, &thread_job))
            .map_err(|err| refused(format!("starting the enrolment session: {err}")))?;
        *lock(&self.enroll.0) = Some(Arc::clone(&job));
        Ok(Started { job, link, message })
    }

    /// The second round of a multi round-trip call: `state` names the
    /// session, `answer` is the human's answer to the elicitation.
    async fn enroll_answered(&self, state: &str, answer: Option<ElicitResult>) -> CallToolResult {
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
        self.after_elicitation(&job, action).await
    }

    /// The result once the human answered the elicitation of `job`. Carries
    /// neither the link nor the session code.
    async fn after_elicitation(
        &self,
        job: &EnrollJob,
        action: ElicitationAction,
    ) -> CallToolResult {
        if action != ElicitationAction::Accept {
            close(job).await;
            return CallToolResult::structured(json!({
                "ok": false,
                "declined": true,
                "session": "ended",
                "summary": "You did not open the certificate page, so it was closed. Nothing \
                            was changed.",
                "next_step": "The human declined or dismissed the certificate page link. Do \
                              not offer a link or a session code yourself. Call \
                              knx_enroll_certificates again only if the human asks to.",
            }));
        }
        let local = job.local;
        let mut result = json!({
            "ok": true,
            "session": "running",
            "link_shown": true,
            "local": local,
            "expires_in_seconds": SESSION_LIFETIME_SECS,
            "data_path": data_path(local).join(" "),
            "read_more": DOCS_URL,
            "summary": format!(
                "The certificate page link and its session code were shown to you by your chat \
                 app. Open the link {}, check that the page shows the same session code, and \
                 scan the certificates on your Secure devices. Each one is saved in the key \
                 store; nothing is sent to the devices.",
                if local { "in a browser on this computer" } else { "on your phone" }
            ),
            "next_step": "Your chat app showed the human the link and the session code \
                          directly; you never see them. Never write, repeat or guess a link or \
                          a session code: if the human lost the link, stop this session \
                          (knx_enroll_status, stop: true) and start a new one. Give the human \
                          `summary`, `data_path` and the `read_more` link, then call \
                          knx_enroll_status (wait_seconds to wait for certificates).",
        });
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
