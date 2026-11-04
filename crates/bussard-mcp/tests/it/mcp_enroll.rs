//! Issue #732: `knx_enroll_certificates` and `knx_enroll_status` against a
//! fake phone, in local mode (the page and the relay on the server's own
//! loopback origin) and through a relay named in bussard.toml. The labels
//! land in a test key store; no tool schema or result ever carries a label
//! or a key. Synthetic keys only (`dev/enroll/vectors-v2.json`); no bus.
//!
//! Issue #809: bussard opens a pairing page in the human's browser (a fake
//! browser here) that shows the session code, the phone link and the
//! certificates received. A client with URL-mode elicitation (#798, a fake
//! human) gets the pairing page as an elicitation instead. No tool result
//! carries the link, the session code or the pairing page's URL, and
//! without a display the tool refuses with a pointer to `bussard keys
//! enroll`.
//!
//! Issue #831: `knx_enroll_certificates` keeps the call open until the
//! session ends (Finish on the phone, `stop`, a timeout) and returns the end
//! summary, sending progress notifications meanwhile; a cancelled call
//! leaves the session running.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bussard_mcp::SharedState;
use bussard_mcp::browser::BrowserOpener;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_project::KeyStore;
use bussard_project::keystore::SerialNumber;
use bussard_secure::enroll::{Direction, EnrollKeyPair, SessionKey};
use bussard_service::enroll_session::Timeouts;
use bussard_service::enroll_session::{DownMessage, EnrollStatus, Envelope};
use bussard_transport::TransportKind;
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientInfo,
    ClientRequest, ElicitRequestParams, ElicitResult, ElicitationAction, ElicitationCapability,
    FormElicitationCapability, Implementation, InputRequest, ProgressNotificationParam,
    ProtocolVersion, RequestMetaObject, UrlElicitationCapability,
};
use rmcp::service::{NotificationContext, PeerRequestOptions, RequestContext};
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::{Value, json};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;
type Client = rmcp::service::RunningService<rmcp::RoleClient, Human>;

/// One URL elicitation as the client showed it.
#[derive(Debug, Clone)]
struct Shown {
    message: String,
    url: String,
}

/// The chat app with its human: declares URL elicitation (or not), records
/// every link it shows and answers with `action`.
#[derive(Clone)]
struct Human {
    url_mode: bool,
    action: ElicitationAction,
    shown: Arc<Mutex<Vec<Shown>>>,
    /// The message of every progress notification received.
    progress: Arc<Mutex<Vec<String>>>,
}

impl Human {
    fn new(url_mode: bool, action: ElicitationAction) -> Self {
        Self {
            url_mode,
            action,
            shown: Arc::default(),
            progress: Arc::default(),
        }
    }

    /// The progress messages so far.
    fn progress(&self) -> Vec<String> {
        self.progress.lock().map(|p| p.clone()).unwrap_or_default()
    }

    /// The links shown so far.
    fn shown(&self) -> Vec<Shown> {
        self.shown.lock().map(|s| s.clone()).unwrap_or_default()
    }

    fn capabilities(&self) -> ClientCapabilities {
        let mut elicitation =
            ElicitationCapability::new().with_form(FormElicitationCapability::new());
        if self.url_mode {
            elicitation = elicitation.with_url(UrlElicitationCapability::new());
        }
        let mut capabilities = ClientCapabilities::default();
        capabilities.elicitation = Some(elicitation);
        capabilities
    }

    /// Records a URL elicitation and answers it.
    fn answer(&self, request: ElicitRequestParams) -> ElicitResult {
        if let ElicitRequestParams::UrlElicitationParams { message, url, .. } = request
            && let Ok(mut shown) = self.shown.lock()
        {
            shown.push(Shown { message, url });
        }
        ElicitResult::new(self.action.clone())
    }
}

impl ClientHandler for Human {
    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        Ok(self.answer(request))
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.push(params.message.unwrap_or_default());
        }
    }

    fn get_info(&self) -> ClientInfo {
        ClientInfo::new(
            self.capabilities(),
            Implementation::new("fake-chat", "0.0.0"),
        )
    }
}

/// A human who opens every link the chat app shows.
fn accepting() -> Human {
    Human::new(true, ElicitationAction::Accept)
}

/// The browser of the computer the server runs on: records the pages it
/// opens, with no display or a failing opener on request.
#[derive(Clone, Default)]
struct FakeBrowser {
    no_display: Option<String>,
    fails: bool,
    opened: Arc<Mutex<Vec<String>>>,
}

impl FakeBrowser {
    fn opened(&self) -> Vec<String> {
        self.opened.lock().map(|o| o.clone()).unwrap_or_default()
    }
}

impl BrowserOpener for FakeBrowser {
    fn no_display(&self) -> Option<String> {
        self.no_display.clone()
    }

    fn open(&self, url: &str) -> Result<(), String> {
        if self.fails {
            return Err("xdg-open failed (exit status: 3)".to_string());
        }
        if let Ok(mut opened) = self.opened.lock() {
            opened.push(url.to_string());
        }
        Ok(())
    }
}

/// The key store's made-up password.
const PASSWORD: &str = "synthetic-store-password";
/// Synthetic certificates of `dev/enroll/vectors-v2.json`.
const CERT_A: &str = "AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2XR";
const SERIAL_A: [u8; 6] = [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04];
const FDSK_A: &str = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";
const CERT_B: &str = "ACB2DMWD2QAAAAAAAAAAAAAAAAAAAAAAAAAD";
const FDSK_B: &str = "00000000000000000000000000000000";

/// A model with 1.1.20 "Test actuator", whose serial the key store knows.
/// `bussard_toml` is the content of bussard.toml.
fn write_model(dir: &Path, bussard_toml: &str) -> Result<(), BoxError> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(dir.join("bussard.toml"), bussard_toml)?;
    std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
    std::fs::write(
        dir.join("devices").join("1.1.20.toml"),
        "address = \"1.1.20\"\nname = \"Test actuator\"\n",
    )?;
    let mut store = KeyStore::new("Synthetic");
    store.devices.entry("1.1.20".parse()?).or_default().serial = Some(SerialNumber(SERIAL_A));
    store.save(dir, PASSWORD)?;
    Ok(())
}

async fn start(dir: &Path, human: Human) -> Result<Client, BoxError> {
    start_with(dir, human, FakeBrowser::default()).await
}

async fn start_with(dir: &Path, human: Human, browser: FakeBrowser) -> Result<Client, BoxError> {
    start_with_timeouts(dir, human, browser, Timeouts::default()).await
}

async fn start_with_timeouts(
    dir: &Path,
    human: Human,
    browser: FakeBrowser,
    timeouts: Timeouts,
) -> Result<Client, BoxError> {
    bussard_model::dotenv::install(vec![(
        bussard_service::secure::KEYRING_PASSWORD_ENV.to_string(),
        PASSWORD.to_string(),
    )]);
    let model = Model::load(dir)?;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: true,
        allow_writes: false,
        no_model_edits: false,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
        programming: None,
        keyring: None,
        home_assistant: None,
        jobs: Default::default(),
        viz: Default::default(),
    });
    let server = BussardMcp::new(state)
        .with_browser(Arc::new(browser))
        .with_enroll_timeouts(timeouts);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    Ok(human.serve(client_io).await?)
}

/// Calls one tool and returns its structured result.
async fn call(client: &Client, tool: &'static str, args: Value) -> Result<Value, BoxError> {
    let Value::Object(map) = args else {
        return Err("tool arguments must be an object".into());
    };
    client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(map))
        .await?
        .structured_content
        .ok_or_else(|| format!("{tool} returned no structured content").into())
}

/// Calls one tool in the background: `knx_enroll_certificates` answers
/// only when the session ends (#831).
fn spawn_call(
    client: &Arc<Client>,
    tool: &'static str,
    args: Value,
) -> tokio::task::JoinHandle<Result<Value, BoxError>> {
    let client = Arc::clone(client);
    tokio::spawn(async move { call(&client, tool, args).await })
}

/// Waits until `pages` returns a page, the pairing page opened.
async fn opened_page(pages: impl Fn() -> Vec<String>) -> Result<String, BoxError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(page) = pages().first() {
            return Ok(page.clone());
        }
        if Instant::now() > deadline {
            return Err("the pairing page did not open".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The fragment parameters of an enrolment link.
fn fragment(link: &str) -> Result<HashMap<String, String>, BoxError> {
    let (_, fragment) = link.split_once('#').ok_or("no fragment")?;
    Ok(fragment
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

fn percent_decode(text: &str) -> Result<String, BoxError> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3).ok_or("short escape")?;
            out.push(u8::from_str_radix(hex, 16)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

/// The enrolment page, minus the camera: the protocol crypto over the
/// relay's phone-side endpoints, as `web/enroll/` does it.
struct FakePhone {
    keys: EnrollKeyPair,
    key: SessionKey,
    sid: [u8; 16],
    session_url: String,
    after: u64,
}

impl FakePhone {
    /// Joins the session of `link`; without `r` the relay is the page's
    /// origin (local mode).
    fn join(link: &str) -> Result<Self, BoxError> {
        let params = fragment(link)?;
        let relay = match params.get("r") {
            Some(r) => percent_decode(r)?,
            None => {
                let rest = link.strip_prefix("http://").ok_or("not an http link")?;
                let host = rest.split('/').next().ok_or("no host")?;
                format!("http://{host}")
            }
        };
        let sid_text = params.get("s").ok_or("no sid")?;
        let sid: [u8; 16] = URL_SAFE_NO_PAD.decode(sid_text)?.as_slice().try_into()?;
        let b_pk: [u8; 32] = URL_SAFE_NO_PAD
            .decode(params.get("k").ok_or("no key")?)?
            .as_slice()
            .try_into()?;
        let keys = EnrollKeyPair::generate()?;
        let key = keys.phone_key(&sid, &b_pk)?;
        Ok(FakePhone {
            keys,
            key,
            sid,
            session_url: format!("{relay}/v1/sessions/{sid_text}"),
            after: 0,
        })
    }

    fn send(&self, message: &Value) -> Result<(), BoxError> {
        let (nonce, c) =
            self.key
                .seal_random(Direction::Up, &self.sid, message.to_string().as_bytes())?;
        let envelope = json!({
            "v": 2,
            "pk": URL_SAFE_NO_PAD.encode(self.keys.public()),
            "n": URL_SAFE_NO_PAD.encode(nonce),
            "c": URL_SAFE_NO_PAD.encode(c),
        });
        // The session thread may not have created the session yet.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match ureq::post(&format!("{}/up", self.session_url))
                .set("Content-Type", "application/json")
                .send_string(&envelope.to_string())
            {
                Ok(_) => return Ok(()),
                Err(ureq::Error::Status(404, _)) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Waits for `count` `result` messages.
    fn results(&mut self, count: usize) -> Result<Vec<DownMessage>, BoxError> {
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        while got.len() < count && Instant::now() < deadline {
            let text = ureq::get(&format!(
                "{}/down?after={}&wait=5",
                self.session_url, self.after
            ))
            .call()?
            .into_string()?;
            let body: Value = serde_json::from_str(&text)?;
            for m in body["messages"].as_array().ok_or("messages")? {
                self.after = m["seq"].as_u64().ok_or("seq")?;
                let envelope: Envelope = serde_json::from_value(m["body"].clone())?;
                let nonce: [u8; 12] = URL_SAFE_NO_PAD.decode(&envelope.n)?.as_slice().try_into()?;
                let plain = self.key.open(
                    Direction::Down,
                    &self.sid,
                    &nonce,
                    &URL_SAFE_NO_PAD.decode(&envelope.c)?,
                )?;
                got.push(serde_json::from_slice(&plain)?);
            }
        }
        Ok(got)
    }
}

/// The one pairing page shown so far through elicitation, after checking
/// its message names the page's host but not its URL.
fn shown_pairing_page(human: &Human) -> Result<String, BoxError> {
    let shown = human.shown();
    let [one] = shown.as_slice() else {
        return Err(format!("expected one page shown, got {shown:?}").into());
    };
    let host = one
        .url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .ok_or("no host")?;
    assert!(host.starts_with("127.0.0.1:"), "{}", one.url);
    assert!(one.message.contains(host), "{}", one.message);
    assert!(!one.message.contains(&one.url), "{}", one.message);
    Ok(one.url.clone())
}

/// The text of the element `<tag id="{id}" ...>text</tag>` in `html`.
fn element_text<'a>(html: &'a str, id: &str) -> Result<&'a str, BoxError> {
    let start = html
        .find(&format!("id=\"{id}\""))
        .ok_or(format!("no #{id}"))?;
    let rest = &html[start..];
    let open = rest.find('>').ok_or("unclosed tag")? + 1;
    let close = rest[open..].find('<').ok_or("no end tag")?;
    Ok(&rest[open..open + close])
}

/// The key and the session code of `link`.
fn key_and_code(link: &str) -> Result<(String, String), BoxError> {
    let params = fragment(link)?;
    let key = params.get("k").cloned().ok_or("no key")?;
    let b_pk: [u8; 32] = URL_SAFE_NO_PAD.decode(&key)?.as_slice().try_into()?;
    let sid: [u8; 16] = URL_SAFE_NO_PAD
        .decode(params.get("s").ok_or("no sid")?)?
        .as_slice()
        .try_into()?;
    let code = bussard_secure::enroll::fingerprint(&sid, &b_pk);
    Ok((key, code))
}

/// The pairing page at `url`: the phone link it shows, after checking the
/// page's session code is the one of the link's key.
fn pairing_link(url: &str) -> Result<String, BoxError> {
    let html = ureq::get(url).call()?.into_string()?;
    let link = element_text(&html, "phone-link")?
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    let (_, code) = key_and_code(&link)?;
    assert_eq!(element_text(&html, "code")?, code);
    assert_no_secret(&html);
    Ok(link)
}

/// The pairing page's live status.
fn pairing_status(url: &str) -> Result<Value, BoxError> {
    let body: Value =
        serde_json::from_str(&ureq::get(&format!("{url}status")).call()?.into_string()?)?;
    Ok(body["status"].clone())
}

/// Asserts that neither `link`, nor its session code, nor its key, nor the
/// pairing page's URL or token appears in `results`, the tool results the
/// assistant saw.
fn assert_no_link(results: &str, link: &str, pairing: &str) -> TestResult {
    let (key, code) = key_and_code(link)?;
    let token = pairing
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .ok_or("no token")?;
    for secret in [link, key.as_str(), code.as_str(), pairing, token] {
        assert!(!results.contains(secret), "{secret} leaked: {results}");
    }
    Ok(())
}

/// Asserts no label and no key appears in `shown`.
fn assert_no_secret(shown: &str) {
    for secret in [
        CERT_A,
        CERT_B,
        FDSK_A,
        &FDSK_A.to_lowercase(),
        FDSK_B,
        PASSWORD,
    ] {
        assert!(!shown.contains(secret), "a label or key leaked: {shown}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_certificates_local_mode_stores_labels() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    let human = accepting();
    let client = Arc::new(start(dir.path(), human.clone()).await?);
    let mut shown = String::new();

    // No tool takes a label or a key as input.
    let tools = client.list_all_tools().await?;
    for name in ["knx_enroll_certificates", "knx_enroll_status"] {
        let tool = tools
            .iter()
            .find(|t| t.name == name)
            .ok_or(format!("{name} is not registered"))?;
        let schema = serde_json::to_value(&tool.input_schema)?;
        let properties: Vec<&String> = schema["properties"]
            .as_object()
            .map(|p| p.keys().collect())
            .unwrap_or_default();
        for property in properties {
            let lower = property.to_lowercase();
            assert!(
                ["text", "label", "certificate", "fdsk", "key", "password"]
                    .iter()
                    .all(|word| !lower.contains(word)),
                "{name} takes {property:?}"
            );
        }
        assert!(tool.output_schema.is_none(), "{name} declares an output");
    }

    let none = call(&client, "knx_enroll_status", json!({})).await?;
    assert_eq!(none["session"], "none", "{none}");

    // The call stays open until the phone finishes (#831).
    let call_human = human.clone();
    let enrolment = spawn_call(&client, "knx_enroll_certificates", json!({"local": true}));
    opened_page(|| call_human.shown().into_iter().map(|s| s.url).collect()).await?;
    let pairing = shown_pairing_page(&human)?;
    let link = pairing_link(&pairing)?;
    assert!(link.starts_with("http://127.0.0.1:"), "{link}");
    assert!(
        !fragment(&link)?.contains_key("r"),
        "a local link names no relay: {link}"
    );

    // One session at a time; the refusal shows no link.
    let again = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    shown.push_str(&again.to_string());
    assert_eq!(again["refused"], true, "{again}");
    assert_eq!(human.shown().len(), 1);

    // The page is served on the link's origin, and the phone stores labels.
    let phone_link = link.clone();
    let results = tokio::task::spawn_blocking(move || -> Result<_, BoxError> {
        let page = phone_link.split('#').next().ok_or("no page")?;
        let html = ureq::get(page).call()?.into_string()?;
        assert!(html.contains("app.js"), "{html}");
        let mut phone = FakePhone::join(&phone_link)?;
        phone.send(&json!({"type": "certificate", "id": 1, "text": CERT_A}))?;
        phone.send(&json!({"type": "certificate", "id": 2, "text": CERT_B}))?;
        phone.send(&json!({"type": "certificate", "id": 3, "text": CERT_A}))?;
        let results = phone.results(3)?;
        phone.send(&json!({"type": "done"}))?;
        Ok(results)
    })
    .await??;
    let statuses: Vec<EnrollStatus> = results
        .iter()
        .filter_map(|m| match m {
            DownMessage::Result { outcome, .. } => Some(outcome.status),
            DownMessage::Closed { .. } | DownMessage::Refused => None,
        })
        .collect();
    assert_eq!(
        statuses,
        [
            EnrollStatus::Stored,
            EnrollStatus::Unassigned,
            EnrollStatus::AlreadyStored
        ]
    );

    // Finish on the phone ends the call with the summary.
    let started = tokio::time::timeout(Duration::from_secs(30), enrolment).await???;
    shown.push_str(&started.to_string());
    assert_eq!(started["ok"], true, "{started}");
    assert_eq!(started["local"], true, "{started}");
    assert_eq!(started["pairing_page_opened"], true, "{started}");
    assert_eq!(started["session"], "ended", "{started}");
    assert_eq!(started["end"], "phone_done", "{started}");
    assert_eq!(
        started["summary"],
        "Finished on the phone. 3 sent \u{00B7} 1 added \u{00B7} 1 no device yet \u{00B7} 1 \
         already known",
        "{started}"
    );
    assert_eq!(
        started["serials"],
        "00FA01020304 added \u{00B7} 0083A1B2C3D4 no device yet \u{00B7} 00FA01020304 already \
         known",
        "{started}"
    );
    assert_eq!(
        started["next_steps"][0]["command"], "bussard scan <LINE>, or bussard adopt <ADDRESS>",
        "{started}"
    );
    let next = started["next_step"].as_str().ok_or("no next_step")?;
    assert!(next.contains("one or two lines"), "{next}");

    // The chat app saw progress while it waited: counts, never a link.
    let progress = human.progress();
    assert_eq!(
        progress.first().map(String::as_str),
        Some("The pairing page is open in your browser. Follow the steps there.")
    );
    assert!(
        progress.iter().any(|m| m.contains("3 sent")),
        "{progress:?}"
    );
    shown.push_str(&progress.join(" "));

    let status = call(&client, "knx_enroll_status", json!({"until_end": true})).await?;
    shown.push_str(&status.to_string());
    assert_eq!(status["session"], "ended", "{status}");
    assert_eq!(status["end"], "phone_done", "{status}");
    assert_eq!(status["stored"], 2, "{status}");
    assert_eq!(
        status["results"][0],
        json!({
            "serial": "00FA01020304",
            "address": "1.1.20",
            "name": "Test actuator",
            "status": "stored",
        }),
        "{status}"
    );
    assert_eq!(status["results"][1]["serial"], "0083A1B2C3D4");
    assert_eq!(status["results"][1]["status"], "unassigned");
    assert_eq!(status["results"][2]["status"], "already_stored");

    let store = KeyStore::load(dir.path(), PASSWORD)?.ok_or("no key store")?;
    assert!(store.fdsk_for_serial(SerialNumber(SERIAL_A)).is_some());

    // The pairing page lists the same certificates by serial number, in
    // the glossary's words, and shows the end; it is gone shortly after.
    let page_url = pairing.clone();
    let page = tokio::task::spawn_blocking(move || pairing_status(&page_url)).await??;
    assert_eq!(page["running"], false, "{page}");
    assert_eq!(page["certificates"][0]["serial"], "00FA01020304", "{page}");
    assert_eq!(page["certificates"][0]["badge"], "added", "{page}");
    assert_eq!(
        page["certificates"][0]["detail"], "for 1.1.20 Test actuator",
        "{page}"
    );
    assert_eq!(page["certificates"][1]["badge"], "no device yet", "{page}");
    assert_eq!(page["certificates"][2]["badge"], "already known", "{page}");
    assert_eq!(
        page["ended"], "Done. You can close this tab and go back to your chat.",
        "{page}"
    );
    assert_no_secret(&page.to_string());

    assert_no_secret(&shown);
    assert_no_link(&shown, &link, &pairing)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_status_stop_closes_hosted_session() -> TestResult {
    // A relay as the hosted one would be, named in bussard.toml.
    let relay = bussard_viz::enroll_local::LocalEnrollServer::start()?;
    let dir = tempfile::tempdir()?;
    write_model(
        dir.path(),
        &format!(
            "[enroll]\nrelay = \"{}\"\npage = \"https://page.invalid/enroll/\"\n",
            relay.relay_url()
        ),
    )?;
    // Form elicitation only, as Claude Code before 2.1.287 declares it:
    // bussard opens the pairing page itself.
    let human = Human::new(false, ElicitationAction::Accept);
    let browser = FakeBrowser::default();
    let client = Arc::new(start_with(dir.path(), human.clone(), browser.clone()).await?);

    let enrolment = spawn_call(&client, "knx_enroll_certificates", json!({}));
    let opened = browser.clone();
    let pairing = opened_page(|| opened.opened()).await?;
    assert!(human.shown().is_empty());
    let page_url = pairing.clone();
    let (link, html) = tokio::task::spawn_blocking(move || -> Result<_, BoxError> {
        let html = ureq::get(&page_url).call()?.into_string()?;
        Ok((pairing_link(&page_url)?, html))
    })
    .await??;
    assert!(
        html.contains("<svg class=\"qr\""),
        "the page has no QR code"
    );
    assert!(link.starts_with("https://page.invalid/enroll/#"), "{link}");
    assert!(fragment(&link)?.contains_key("r"), "{link}");

    let phone_link = link.clone();
    tokio::task::spawn_blocking(move || -> TestResult {
        let mut phone = FakePhone::join(&phone_link)?;
        phone.send(&json!({"type": "certificate", "id": 1, "text": CERT_A}))?;
        phone.results(1)?;
        Ok(())
    })
    .await??;

    // The phone may read its result before the status records it: wait.
    let running = call(&client, "knx_enroll_status", json!({"wait_seconds": 10})).await?;
    assert_eq!(running["session"], "running", "{running}");
    assert_eq!(running["certificates"], 1, "{running}");
    // Counts only while it runs; serial numbers on request.
    assert!(running.get("results").is_none(), "{running}");
    let detailed = call(&client, "knx_enroll_status", json!({"details": true})).await?;
    assert_eq!(detailed["results"][0]["status"], "stored", "{detailed}");

    let stopped = call(&client, "knx_enroll_status", json!({"stop": true})).await?;
    assert_eq!(stopped["session"], "ended", "{stopped}");
    assert_eq!(stopped["end"], "stopped", "{stopped}");
    assert_eq!(stopped["results"][0]["status"], "stored", "{stopped}");

    // The waiting call returns at the stop, with the end summary.
    let started = tokio::time::timeout(Duration::from_secs(30), enrolment).await???;
    assert_eq!(started["ok"], true, "{started}");
    assert_eq!(started["local"], false, "{started}");
    assert_eq!(started["pairing_page_opened"], true, "{started}");
    assert_eq!(started["end"], "stopped", "{started}");
    assert_eq!(
        started["summary"], "The session was ended from the chat. 1 sent \u{00B7} 1 added",
        "{started}"
    );
    assert_eq!(started["serials"], "00FA01020304 added", "{started}");
    let next = started["next_step"].as_str().ok_or("no next_step")?;
    assert!(next.contains("Do not repeat the pairing page"), "{next}");

    // A new session can start once the last one ended, on a new page.
    let second = spawn_call(&client, "knx_enroll_certificates", json!({}));
    let opened = browser.clone();
    let next_pairing = opened_page(|| opened.opened().into_iter().skip(1).collect()).await?;
    assert_ne!(next_pairing, pairing);
    let page_url = next_pairing.clone();
    let next_link = tokio::task::spawn_blocking(move || pairing_link(&page_url)).await??;
    assert_ne!(next_link, link);
    let stopped = call(&client, "knx_enroll_status", json!({"stop": true})).await?;
    assert_eq!(stopped["end"], "stopped", "{stopped}");
    let next = tokio::time::timeout(Duration::from_secs(30), second).await???;
    assert_eq!(next["end"], "stopped", "{next}");
    let progress = human.progress().join(" ");

    let results = format!("{started} {running} {detailed} {stopped} {next} {progress}");
    assert_no_secret(&results);
    assert_no_link(&results, &link, &pairing)?;
    assert_no_link(&results, &next_link, &next_pairing)?;
    Ok(())
}

#[tokio::test]
async fn test_knx_enroll_certificates_wrong_password_refuses() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    // The store was saved with another password: no session, no link.
    let mut store = KeyStore::new("Synthetic");
    store.devices.entry("1.1.20".parse()?).or_default().serial = Some(SerialNumber(SERIAL_A));
    store.save(dir.path(), "another-synthetic-password")?;
    let human = accepting();
    let client = start(dir.path(), human.clone()).await?;
    let refused = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    assert!(human.shown().is_empty());
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(refused.get("link").is_none(), "{refused}");
    let reason = refused["reason"].as_str().ok_or("no reason")?;
    assert!(reason.contains("no session was started"), "{reason}");
    assert_no_secret(reason);
    let status = call(&client, "knx_enroll_status", json!({})).await?;
    assert_eq!(status["session"], "none", "{status}");
    Ok(())
}

#[tokio::test]
async fn test_knx_enroll_certificates_without_display_refuses() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    // An SSH session: whatever the chat app can do, nobody sees the page.
    for human in [accepting(), Human::new(false, ElicitationAction::Accept)] {
        let browser = FakeBrowser {
            no_display: Some("bussard runs in an SSH session".to_string()),
            ..FakeBrowser::default()
        };
        let client = start_with(dir.path(), human.clone(), browser.clone()).await?;
        let refused = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
        assert_eq!(refused["refused"], true, "{refused}");
        assert_eq!(refused["pairing_page_opened"], false, "{refused}");
        let summary = refused["summary"].as_str().ok_or("no summary")?;
        assert!(summary.contains("`bussard keys enroll`"), "{summary}");
        let reason = refused["reason"].as_str().ok_or("no reason")?;
        assert!(reason.contains("SSH"), "{reason}");
        assert!(!refused.to_string().contains("http"), "{refused}");
        assert!(human.shown().is_empty());
        assert!(browser.opened().is_empty());
        let status = call(&client, "knx_enroll_status", json!({})).await?;
        assert_eq!(status["session"], "none", "{status}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_certificates_opener_failure_closes_session() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    let browser = FakeBrowser {
        fails: true,
        ..FakeBrowser::default()
    };
    let human = Human::new(false, ElicitationAction::Accept);
    let client = start_with(dir.path(), human, browser).await?;
    let refused = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert_eq!(refused["pairing_page_opened"], false, "{refused}");
    let summary = refused["summary"].as_str().ok_or("no summary")?;
    assert!(summary.contains("`bussard keys enroll`"), "{summary}");
    assert!(!refused.to_string().contains("http"), "{refused}");
    let status = call(&client, "knx_enroll_status", json!({})).await?;
    assert_eq!(status["session"], "ended", "{status}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_certificates_declined_closes_session() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    let human = Human::new(true, ElicitationAction::Decline);
    let client = start(dir.path(), human.clone()).await?;
    let declined = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    assert_eq!(declined["ok"], false, "{declined}");
    assert_eq!(declined["declined"], true, "{declined}");
    let pairing = shown_pairing_page(&human)?;
    let status = call(&client, "knx_enroll_status", json!({})).await?;
    assert_eq!(status["session"], "ended", "{status}");
    assert_eq!(status["end"], "stopped", "{status}");
    let results = format!("{declined} {status}");
    assert!(!results.contains(&pairing), "{results}");
    assert!(!results.contains("http"), "{results}");
    Ok(())
}

/// `params` with `meta` as its `_meta`.
fn with_meta(mut params: CallToolRequestParams, meta: RequestMetaObject) -> CallToolRequestParams {
    params.meta = Some(meta);
    params
}

/// The `_meta` of a request from a client speaking protocol 2026-07-28.
fn meta_2026(human: &Human) -> Result<RequestMetaObject, BoxError> {
    let mut meta = RequestMetaObject::default();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    meta.set_client_info(Implementation::new("fake-chat", "0.0.0"));
    meta.set_client_capabilities(human.capabilities());
    Ok(meta)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_certificates_multi_round_trip_shows_link() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    let human = accepting();
    let client = Arc::new(start(dir.path(), human.clone()).await?);
    let mut args = serde_json::Map::new();
    args.insert("local".to_string(), json!(true));
    let first = client
        .call_tool_once(with_meta(
            CallToolRequestParams::new("knx_enroll_certificates").with_arguments(args.clone()),
            meta_2026(&human)?,
        ))
        .await?;
    let CallToolResponse::InputRequired(input) = first else {
        return Err(format!("expected input_required, got {first:?}").into());
    };
    // The client shows the elicitation; the server sent no request itself.
    assert!(human.shown().is_empty());
    let requests = input.input_requests.clone().ok_or("no input requests")?;
    let state = input.request_state.clone().ok_or("no request state")?;
    let mut responses = rmcp::model::InputResponses::new();
    for (key, request) in requests {
        let InputRequest::Elicitation(request) = request else {
            return Err("not an elicitation".into());
        };
        let answer = human.answer(request.params);
        responses.insert(key, serde_json::to_value(answer)?);
    }
    let pairing = shown_pairing_page(&human)?;
    let page_url = pairing.clone();
    let link = tokio::task::spawn_blocking(move || pairing_link(&page_url)).await??;
    // The second round waits for the end of the session (#831).
    let params = with_meta(
        CallToolRequestParams::new("knx_enroll_certificates")
            .with_arguments(args)
            .with_input_responses(responses)
            .with_request_state(state.clone()),
        meta_2026(&human)?,
    );
    let round = Arc::clone(&client);
    let second = tokio::spawn(async move { round.call_tool_once(params).await });
    // Its first progress notification says it waits.
    let waiting = human.clone();
    opened_page(|| waiting.progress()).await?;
    let status = call(&client, "knx_enroll_status", json!({"stop": true})).await?;
    assert_eq!(status["end"], "stopped", "{status}");
    let second = tokio::time::timeout(Duration::from_secs(30), second).await???;
    let CallToolResponse::Complete(result) = second else {
        return Err(format!("expected a result, got {second:?}").into());
    };
    let started = result.structured_content.ok_or("no structured content")?;
    assert_eq!(started["ok"], true, "{started}");
    assert_eq!(started["pairing_page_opened"], true, "{started}");
    assert_eq!(started["end"], "stopped", "{started}");

    // A stale request state starts nothing.
    let stale = call_with_state(&client, &state).await?;
    assert_eq!(stale["refused"], true, "{stale}");

    let first_json = serde_json::to_string(&input.request_state)?;
    assert_no_link(
        &format!("{started} {status} {stale} {first_json}"),
        &link,
        &pairing,
    )?;
    Ok(())
}

/// Calls `knx_enroll_certificates` as the second round of `state`, with no
/// answer.
async fn call_with_state(client: &Client, state: &str) -> Result<Value, BoxError> {
    let response = client
        .call_tool_once(
            CallToolRequestParams::new("knx_enroll_certificates").with_request_state(state),
        )
        .await?;
    let CallToolResponse::Complete(result) = response else {
        return Err("expected a result".into());
    };
    result
        .structured_content
        .ok_or_else(|| "no structured content".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_certificates_returns_on_connect_timeout() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    let human = Human::new(false, ElicitationAction::Accept);
    let browser = FakeBrowser::default();
    let timeouts = Timeouts {
        connect: Duration::from_secs(1),
        ..Timeouts::default()
    };
    let client = start_with_timeouts(dir.path(), human.clone(), browser.clone(), timeouts).await?;
    // No phone joins: the call returns when the session times out.
    let ended = tokio::time::timeout(
        Duration::from_secs(30),
        call(&client, "knx_enroll_certificates", json!({"local": true})),
    )
    .await??;
    assert_eq!(ended["session"], "ended", "{ended}");
    assert_eq!(ended["end"], "connect_timeout", "{ended}");
    assert_eq!(
        ended["summary"],
        "No phone joined within 1 second, so the session was closed. No certificates received.",
        "{ended}"
    );
    assert_eq!(ended["next_steps"], json!([]), "{ended}");
    assert_eq!(browser.opened().len(), 1);
    let progress = human.progress().join(" ");
    for text in [ended.to_string(), progress] {
        assert!(!text.contains("http"), "{text}");
        assert!(!text.contains("127.0.0.1"), "{text}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_knx_enroll_certificates_cancel_leaves_session_running() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path(), "")?;
    let human = Human::new(false, ElicitationAction::Accept);
    let browser = FakeBrowser::default();
    let client = start_with(dir.path(), human.clone(), browser.clone()).await?;
    let mut args = serde_json::Map::new();
    args.insert("local".to_string(), json!(true));
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(
        CallToolRequestParams::new("knx_enroll_certificates").with_arguments(args),
    ));
    let handle = client
        .peer()
        .send_cancellable_request(request, PeerRequestOptions::no_options())
        .await?;
    let waiting = human.clone();
    opened_page(|| waiting.progress()).await?;
    let opened = browser.clone();
    let pairing = opened_page(|| opened.opened()).await?;

    // Esc in the chat app: the call ends, the session does not.
    handle
        .cancel(Some("the human pressed Esc".to_string()))
        .await?;
    let status = call(&client, "knx_enroll_status", json!({})).await?;
    assert_eq!(status["session"], "running", "{status}");
    // knx_enroll_status picks the session up again.
    let page_url = pairing.clone();
    let link = tokio::task::spawn_blocking(move || pairing_link(&page_url)).await??;
    let phone_link = link.clone();
    tokio::task::spawn_blocking(move || -> TestResult {
        let mut phone = FakePhone::join(&phone_link)?;
        phone.send(&json!({"type": "certificate", "id": 1, "text": CERT_A}))?;
        phone.results(1)?;
        phone.send(&json!({"type": "done"}))?;
        Ok(())
    })
    .await??;
    let ended = tokio::time::timeout(
        Duration::from_secs(30),
        call(&client, "knx_enroll_status", json!({"until_end": true})),
    )
    .await??;
    assert_eq!(ended["session"], "ended", "{ended}");
    assert_eq!(ended["end"], "phone_done", "{ended}");
    assert_eq!(ended["stored"], 1, "{ended}");
    let progress = human.progress().join(" ");
    assert_no_link(&format!("{status} {ended} {progress}"), &link, &pairing)?;
    Ok(())
}
