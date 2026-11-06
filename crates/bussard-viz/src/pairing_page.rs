//! The pairing page (issue #809): the page bussard opens in the browser of
//! the computer it runs on when the MCP server starts a certificate
//! enrolment session. One column of numbered steps (issue #820): the QR
//! code of the phone link with the link as text, the session code, then a
//! live list of the certificates received; once the phone joined the first
//! two steps fold into one line. The link reaches the human without passing
//! through the assistant.
//!
//! The page binds `127.0.0.1` on a free port and answers only under a
//! random 128-bit token path, only to the exact `Host` it was opened
//! under (`127.0.0.1:<port>`), with no CORS headers. The QR code is drawn
//! server-side as an inline SVG; the page makes no third-party request.
//! Its files are embedded from `web/pairing/` at build time.
//!
//! The live list is a long poll on `<token>/status`: the caller bumps a
//! [`watch`] counter on every change and [`PairingPage`] answers a waiting
//! request with a fresh [`PairingStatus`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bussard_model::text::escape_html;
use bussard_service::enroll_session::{
    CertificateOutcome, EnrollEnd, EnrollStatus, NextStep, SessionProgress,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::local_server::{self, CSS, JS, JSON, LocalServer, Policy};

/// How long a status request waits for a change before it answers with the
/// unchanged status.
pub const STATUS_WAIT: Duration = Duration::from_secs(20);

/// How long [`PairingPage::finish`] keeps serving after the session ended,
/// so a waiting status request delivers the final state.
pub const FINISH_GRACE: Duration = Duration::from_secs(2);

/// The headers of the page: its own files only, the network only to this
/// origin, no framing, no referrer.
const POLICY: Policy = Policy {
    csp: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
        connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
        object-src 'none'",
    referrer: "no-referrer",
};

const BODY: &str = include_str!("../../../web/pairing/body.html");
const SCRIPT: &str = include_str!("../../../web/pairing/pairing.js");
const STYLE: &str = include_str!("../../../web/pairing/pairing.css");

/// What the pairing page shows for one session. Holds the phone link: the
/// page is the one place it is shown.
#[derive(Clone)]
pub struct PairingContent {
    /// The session code (`XXXX-XXXX`).
    pub code: String,
    /// The link the phone opens.
    pub phone_link: String,
    /// Local mode: the certificate page is served on this computer, so the
    /// pairing page offers a button to open it instead of a QR code.
    pub local: bool,
    /// Warnings shown above everything else, such as a page or relay that
    /// is not the default one (F13 of the #201 review).
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for PairingContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingContent")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// One certificate as the pairing page lists it, in the words of
/// `dev/glossary.md` ("Certificate states"): serial number, badge, detail
/// line. Never any part of the certificate's code or key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairingCertificate {
    /// The serial number, or `-` when the text did not decode that far.
    pub serial: String,
    /// The wire value (`stored`, `unassigned`, ...).
    pub state: &'static str,
    /// The badge (`added`, `no device yet`, ...).
    pub badge: &'static str,
    /// The detail line; empty when the badge says it all.
    pub detail: String,
    /// The row tone: `good`, `wait` or `bad`.
    pub tone: &'static str,
}

impl PairingCertificate {
    /// The row of `outcome`.
    #[must_use]
    pub fn of(outcome: &CertificateOutcome) -> Self {
        let tone = match outcome.status {
            EnrollStatus::Stored | EnrollStatus::AlreadyStored => "good",
            EnrollStatus::Unassigned => "wait",
            EnrollStatus::Conflict | EnrollStatus::Invalid | EnrollStatus::Error => "bad",
        };
        PairingCertificate {
            serial: outcome.serial.clone().unwrap_or_else(|| "-".to_string()),
            state: outcome.status.as_str(),
            badge: outcome.status.badge(),
            detail: outcome.detail().unwrap_or_default(),
            tone,
        }
    }
}

/// The live part of the pairing page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PairingStatus {
    /// The session is open.
    pub running: bool,
    /// Phones that joined.
    pub phones: usize,
    /// Other phones that tried to join and were refused (one phone per
    /// session, #796).
    pub refused_phones: usize,
    /// One row per certificate, in arrival order.
    pub certificates: Vec<PairingCertificate>,
    /// The running summary (`6 sent · 1 added · ...`).
    pub summary: String,
    /// Once ended: the headline, which points back to the chat (`Done. You
    /// can close this tab and go back to your chat.`, #831).
    pub ended: Option<String>,
    /// Once ended: what is left to do, as CLI commands.
    pub next_steps: Vec<NextStep>,
}

/// The line the pairing page ends with: the human goes back to the chat,
/// which continues by itself (#831).
const BACK_TO_CHAT: &str = "You can close this tab and go back to your chat.";

impl PairingStatus {
    /// The live part of the page for a session at `progress`.
    #[must_use]
    pub fn of(progress: &SessionProgress) -> Self {
        let tally = progress.tally();
        let ended = progress.end_reason().map(|reason| {
            if progress.end == Some(EnrollEnd::PhoneDone) {
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
}

/// The current [`PairingStatus`], asked for on every status request.
pub type StatusFn = Arc<dyn Fn() -> PairingStatus + Send + Sync>;

/// The pairing page served on `127.0.0.1` at a free port, until dropped.
pub struct PairingPage {
    server: LocalServer,
    token: String,
}

impl std::fmt::Debug for PairingPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingPage")
            .field("addr", &self.addr())
            .finish_non_exhaustive()
    }
}

/// What the request handlers share.
struct Shared {
    html: String,
    status: StatusFn,
    changes: watch::Receiver<u64>,
}

/// The query of a status request: the version the page already shows.
#[derive(Debug, Deserialize)]
struct StatusQuery {
    #[serde(default)]
    after: Option<u64>,
}

/// The body of a status answer.
#[derive(Debug, Serialize)]
struct StatusBody {
    version: u64,
    status: PairingStatus,
}

impl PairingPage {
    /// Binds `127.0.0.1` at a free port under a fresh random token and
    /// serves the page of `content`. `status` gives the live part;
    /// `changes` is bumped whenever it changes.
    ///
    /// # Errors
    ///
    /// No randomness, the QR code cannot hold the link, the socket cannot
    /// be bound or the server thread cannot start.
    pub fn start(
        content: &PairingContent,
        status: StatusFn,
        changes: watch::Receiver<u64>,
    ) -> std::io::Result<Self> {
        let token = local_server::token()?;
        let shared = Shared {
            html: render(content).map_err(std::io::Error::other)?,
            status,
            changes,
        };
        let server = LocalServer::start("pairing-page", FINISH_GRACE, |addr| {
            router(&token, shared, addr)
        })?;
        Ok(PairingPage { server, token })
    }

    /// The page URL, `http://127.0.0.1:<port>/<token>/`. Never put it in a
    /// tool result: whoever has it sees the phone link.
    #[must_use]
    pub fn url(&self) -> String {
        self.server.url(&format!("/{}/", self.token))
    }

    /// The loopback address the page listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.server.addr()
    }

    /// Keeps serving for [`FINISH_GRACE`] so the page shows the end, then
    /// stops.
    pub fn finish(self) {
        self.server.finish();
    }
}

/// The page's routes under `/<token>/`, behind the exact-`Host` check.
/// Every other path is a 404.
fn router(token: &str, shared: Shared, addr: SocketAddr) -> Router {
    let routes = Router::new()
        .route(&format!("/{token}/"), get(page))
        .route(
            &format!("/{token}/pairing.js"),
            get(|| async { POLICY.file(SCRIPT, JS) }),
        )
        .route(
            &format!("/{token}/pairing.css"),
            get(|| async { POLICY.file(STYLE, CSS) }),
        )
        .route(&format!("/{token}/status"), get(status))
        .with_state(Arc::new(shared));
    local_server::only_hosts(routes, vec![local_server::host(addr)])
}

async fn page(State(shared): State<Arc<Shared>>) -> Response {
    POLICY.html(shared.html.clone())
}

async fn status(State(shared): State<Arc<Shared>>, Query(query): Query<StatusQuery>) -> Response {
    let mut changes = shared.changes.clone();
    let mut version = *changes.borrow_and_update();
    if query.after == Some(version) {
        // Wait for a change; a closed sender or the timeout answers as is.
        if let Ok(Ok(())) = tokio::time::timeout(STATUS_WAIT, changes.changed()).await {
            version = *changes.borrow_and_update();
        }
    }
    let body = StatusBody {
        version,
        status: (shared.status)(),
    };
    match serde_json::to_string(&body) {
        Ok(json) => POLICY.file(json, JSON),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The page of `content`: the template with the code, the link and the QR
/// code filled in.
fn render(content: &PairingContent) -> Result<String, qrcode::types::QrError> {
    let qr = if content.local {
        String::new()
    } else {
        qr_svg(&content.phone_link)?
    };
    let (mode, hosted_hidden, local_hidden) = if content.local {
        ("local", "hidden", "")
    } else {
        ("hosted", "", "hidden")
    };
    let body = BODY
        .replace("{{code}}", &escape_html(&content.code))
        .replace("{{link}}", &escape_html(&content.phone_link))
        .replace("{{qr}}", &qr)
        .replace("{{warnings}}", &warnings_html(&content.warnings))
        .replace("{{hosted_hidden}}", hosted_hidden)
        .replace("{{local_hidden}}", local_hidden);
    Ok(POLICY.page(
        "add certificates",
        "pairing.css",
        Some("pairing.js"),
        mode,
        &body,
    ))
}

/// The warning banner of `warnings`, empty without any.
fn warnings_html(warnings: &[String]) -> String {
    if warnings.is_empty() {
        return String::new();
    }
    let items: String = warnings
        .iter()
        .map(|w| format!("<li>{}</li>", escape_html(w)))
        .collect();
    format!(
        "<div class=\"banner warn\" role=\"alert\"><span class=\"banner-title\">Check \
         before you scan</span><ul class=\"next-steps\">{items}</ul></div>"
    )
}

/// `data` as a QR code in an inline SVG: dark modules on white with a
/// four-module quiet zone, whatever the page's colour scheme, so a phone
/// camera reads it in dark mode too.
fn qr_svg(data: &str) -> Result<String, qrcode::types::QrError> {
    const QUIET: usize = 4;
    let code = qrcode::QrCode::new(data.as_bytes())?;
    let width = code.width();
    let size = width + 2 * QUIET;
    let mut path = String::new();
    for y in 0..width {
        let mut x = 0;
        while x < width {
            if code[(x, y)] == qrcode::Color::Dark {
                let start = x;
                while x < width && code[(x, y)] == qrcode::Color::Dark {
                    x += 1;
                }
                path.push_str(&format!(
                    "M{} {}h{}v1h-{}z",
                    start + QUIET,
                    y + QUIET,
                    x - start,
                    x - start
                ));
            } else {
                x += 1;
            }
        }
    }
    Ok(format!(
        "<svg class=\"qr\" viewBox=\"0 0 {size} {size}\" role=\"img\" \
         aria-label=\"QR code of the phone link\" shape-rendering=\"crispEdges\" \
         xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"{size}\" height=\"{size}\" \
         fill=\"#fff\"/><path fill=\"#000\" d=\"{path}\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const LINK: &str = "https://relay.example/enroll/#s=AAAA&k=BBBB&r=https%3A%2F%2Frelay.example";

    fn content(local: bool) -> PairingContent {
        PairingContent {
            code: "ABCD-EFGH".to_string(),
            phone_link: LINK.to_string(),
            local,
            warnings: vec!["the relay <b> is not the default".to_string()],
        }
    }

    fn start(local: bool) -> Result<(PairingPage, watch::Sender<u64>), Box<dyn std::error::Error>> {
        let (changes, receiver) = watch::channel(0u64);
        let status: StatusFn = Arc::new(|| PairingStatus {
            running: true,
            certificates: vec![PairingCertificate::of(&CertificateOutcome {
                status: EnrollStatus::Stored,
                serial: Some("00FA01020304".to_string()),
                ia: Some("1.1.20".to_string()),
                name: Some("Actuator".to_string()),
                message: None,
            })],
            ..PairingStatus::default()
        });
        Ok((
            PairingPage::start(&content(local), status, receiver)?,
            changes,
        ))
    }

    #[test]
    fn test_render_hosted_shows_code_link_and_qr() -> TestResult {
        let html = render(&content(false))?;
        assert!(html.contains("ABCD-EFGH"), "{html}");
        assert!(html.contains("<li>the relay &lt;b&gt; is not the default</li>"));
        assert!(html.contains("<svg class=\"qr\""));
        assert!(html.contains("<body class=\"hosted\">"));
        // The session code is in step 2 and in the compact line.
        assert_eq!(html.matches("ABCD-EFGH").count(), 2, "{html}");
        // The link is escaped, never raw.
        assert!(html.contains("#s=AAAA&amp;k=BBBB&amp;r="));
        assert!(!html.contains("&k=BBBB"));
        assert!(!html.contains("{{"), "a placeholder is left");
        Ok(())
    }

    #[test]
    fn test_render_local_has_no_qr() -> TestResult {
        let html = render(&content(true))?;
        assert!(!html.contains("<svg class=\"qr\""));
        assert!(html.contains("ABCD-EFGH"));
        assert!(html.contains("<body class=\"local\">"));
        assert!(!html.contains("{{"), "a placeholder is left");
        Ok(())
    }

    #[test]
    fn test_script_ends_by_pointing_back_to_the_chat() {
        // #831: the end banner shows the summary, and the page tries to
        // close a tab it watched end; the message stays when that fails.
        assert!(BODY.contains("id=\"end-summary\""));
        assert!(SCRIPT.contains("window.close()"));
        assert!(SCRIPT.contains("go back to your chat"));
    }

    #[test]
    fn test_qr_svg_has_quiet_zone_and_modules() -> TestResult {
        let svg = qr_svg(LINK)?;
        // A finder pattern's top row starts at the quiet zone: a 7-module run.
        assert!(svg.contains("M4 4h7v1h-7z"), "{svg}");
        Ok(())
    }

    #[test]
    fn test_pairing_status_of_ended_points_back_to_the_chat() {
        let timeouts = bussard_service::enroll_session::Timeouts::default();
        let mut progress = SessionProgress::new(false, timeouts, "the chat");
        assert!(PairingStatus::of(&progress).running);
        progress.end = Some(EnrollEnd::PhoneDone);
        assert_eq!(
            PairingStatus::of(&progress).ended.as_deref(),
            Some("Done. You can close this tab and go back to your chat.")
        );
        progress.end = Some(EnrollEnd::Stopped);
        assert_eq!(
            PairingStatus::of(&progress).ended.as_deref(),
            Some(
                "The session was ended from the chat. You can close this tab and go back to \
                 your chat."
            )
        );
    }

    #[test]
    fn test_pairing_certificate_of_uses_glossary_words() {
        let row = PairingCertificate::of(&CertificateOutcome {
            status: EnrollStatus::Unassigned,
            serial: Some("0083A1B2C3D4".to_string()),
            ia: None,
            name: None,
            message: None,
        });
        assert_eq!(row.badge, "no device yet");
        assert_eq!(row.tone, "wait");
        assert!(row.detail.starts_with("no device in your project"));
        let row = PairingCertificate::of(&CertificateOutcome::error("disk full"));
        assert_eq!((row.badge, row.serial.as_str()), ("failed", "-"));
        assert_eq!(row.detail, "disk full");
    }

    #[test]
    fn test_pairing_page_serves_page_under_token() -> TestResult {
        let (page, _changes) = start(false)?;
        let url = page.url();
        let token = url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .ok_or("no token")?;
        assert_eq!(token.len(), 32, "128 bits as hex: {url}");
        let response = ureq::get(&url).call()?;
        assert_eq!(response.content_type(), "text/html");
        let csp = response
            .header("content-security-policy")
            .ok_or("no CSP")?
            .to_string();
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(response.header("access-control-allow-origin").is_none());
        assert_eq!(response.header("referrer-policy"), Some("no-referrer"));
        assert!(response.into_string()?.contains("ABCD-EFGH"));
        for file in ["pairing.js", "pairing.css"] {
            assert_eq!(ureq::get(&format!("{url}{file}")).call()?.status(), 200);
        }
        Ok(())
    }

    #[test]
    fn test_pairing_page_refuses_other_paths() -> TestResult {
        let (page, _changes) = start(false)?;
        let root = format!("http://{}", page.addr());
        let url = page.url();
        let wrong_token = format!("{root}/{}/", "0".repeat(32));
        let short = &url[..url.len() - 2];
        for path in [format!("{root}/"), wrong_token, short.to_string()] {
            match ureq::get(&path).call() {
                Err(ureq::Error::Status(404, _)) => {}
                other => return Err(format!("{path}: expected 404, got {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn test_pairing_page_refuses_other_hosts() -> TestResult {
        let (page, _changes) = start(false)?;
        let port = page.addr().port();
        for host in [
            "attacker.example".to_string(),
            format!("localhost:{port}"),
            format!("127.0.0.1:{}", port.wrapping_add(1)),
        ] {
            match ureq::get(&page.url()).set("Host", &host).call() {
                Err(ureq::Error::Status(421, _)) => {}
                other => return Err(format!("{host}: expected 421, got {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn test_pairing_page_status_waits_for_a_change() -> TestResult {
        let (page, changes) = start(false)?;
        let url = format!("{}status", page.url());
        let first: serde_json::Value =
            serde_json::from_str(&ureq::get(&url).call()?.into_string()?)?;
        assert_eq!(first["version"], 0);
        assert_eq!(first["status"]["certificates"][0]["badge"], "added");
        assert_eq!(
            first["status"]["certificates"][0]["detail"],
            "for 1.1.20 Actuator"
        );
        let bump = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            changes.send_modify(|v| *v += 1);
            changes
        });
        let started = std::time::Instant::now();
        let next: serde_json::Value =
            serde_json::from_str(&ureq::get(&format!("{url}?after=0")).call()?.into_string()?)?;
        assert_eq!(next["version"], 1);
        assert!(started.elapsed() < STATUS_WAIT);
        drop(bump.join());
        Ok(())
    }
}
