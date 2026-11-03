//! Issue #732: `knx_enroll_certificates` and `knx_enroll_status` against a
//! fake phone, in local mode (the page and the relay on the server's own
//! loopback origin) and through a relay named in bussard.toml. The labels
//! land in a test key store; no tool schema or result ever carries a label
//! or a key. Synthetic keys only (`dev/enroll/vectors-v1.json`); no bus.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bussard_mcp::SharedState;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_project::KeyStore;
use bussard_project::keystore::SerialNumber;
use bussard_secure::enroll::{Direction, EnrollKeyPair, SessionKey};
use bussard_service::enroll_session::{DownMessage, EnrollStatus, Envelope};
use bussard_transport::TransportKind;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;
type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// The key store's made-up password.
const PASSWORD: &str = "synthetic-store-password";
/// Synthetic certificates of `dev/enroll/vectors-v1.json`.
const CERT_A: &str = "AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2X5";
const SERIAL_A: [u8; 6] = [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04];
const FDSK_A: &str = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";
const CERT_B: &str = "ACB2DMWD2QAAAAAAAAAAAAAAAAAAAAAAAAAG";
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

async fn start(dir: &Path) -> Result<Client, BoxError> {
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
    });
    let server = BussardMcp::new(state);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    Ok(().serve(client_io).await?)
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
            "v": 1,
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
    let client = start(dir.path()).await?;
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

    let started = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    shown.push_str(&started.to_string());
    assert_eq!(started["ok"], true, "{started}");
    assert_eq!(started["local"], true, "{started}");
    let link = started["link"].as_str().ok_or("no link")?.to_string();
    assert!(link.starts_with("http://127.0.0.1:"), "{link}");
    let params = fragment(&link)?;
    assert!(
        !params.contains_key("r"),
        "a local link names no relay: {link}"
    );
    let b_pk: [u8; 32] = URL_SAFE_NO_PAD
        .decode(params.get("k").ok_or("no key")?)?
        .as_slice()
        .try_into()?;
    assert_eq!(
        started["fingerprint"],
        bussard_secure::enroll::fingerprint(&b_pk)
    );

    // One session at a time.
    let again = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    shown.push_str(&again.to_string());
    assert_eq!(again["refused"], true, "{again}");
    assert_eq!(again["link"], link.as_str());

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
            DownMessage::Closed { .. } => None,
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

    // Each wait returns on the next label or the end; the last label may
    // still be on its way into the status when the phone has its result.
    let mut status = Value::Null;
    for _ in 0..5 {
        status = call(&client, "knx_enroll_status", json!({"wait_seconds": 30})).await?;
        shown.push_str(&status.to_string());
        if status["session"] == "ended" {
            break;
        }
    }
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

    assert_no_secret(&shown);
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
    let client = start(dir.path()).await?;

    let started = call(&client, "knx_enroll_certificates", json!({})).await?;
    assert_eq!(started["ok"], true, "{started}");
    assert_eq!(started["local"], false, "{started}");
    let link = started["link"].as_str().ok_or("no link")?.to_string();
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

    let stopped = call(&client, "knx_enroll_status", json!({"stop": true})).await?;
    assert_eq!(stopped["session"], "ended", "{stopped}");
    assert_eq!(stopped["end"], "stopped", "{stopped}");
    assert_eq!(stopped["results"][0]["status"], "stored", "{stopped}");

    // A new session can start once the last one ended.
    let next = call(&client, "knx_enroll_certificates", json!({})).await?;
    assert_eq!(next["ok"], true, "{next}");
    assert_ne!(next["link"], link.as_str());
    let stopped = call(&client, "knx_enroll_status", json!({"stop": true})).await?;
    assert_eq!(stopped["end"], "stopped", "{stopped}");

    assert_no_secret(&format!("{started} {running} {stopped} {next}"));
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
    let client = start(dir.path()).await?;
    let refused = call(&client, "knx_enroll_certificates", json!({"local": true})).await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(refused.get("link").is_none(), "{refused}");
    let reason = refused["reason"].as_str().ok_or("no reason")?;
    assert!(reason.contains("no session was started"), "{reason}");
    assert_no_secret(reason);
    let status = call(&client, "knx_enroll_status", json!({})).await?;
    assert_eq!(status["session"], "none", "{status}");
    Ok(())
}
