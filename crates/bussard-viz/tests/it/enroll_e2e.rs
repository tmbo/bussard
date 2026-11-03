//! Certificate enrolment end to end (issue #729): a fake phone, written
//! against the protocol crypto only, posts certificates through the
//! in-process relay over real HTTP; bussard's session decrypts them into a
//! test key store and answers per certificate.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bussard_secure::enroll::{Direction, EnrollKeyPair, SessionKey};
use bussard_service::enroll_session::{
    CertificateOutcome, CertificateSink, DownMessage, EnrollEnd, EnrollEvent, EnrollSession,
    EnrollStatus, Envelope, HttpRelay, RunOptions,
};
use bussard_viz::enroll_relay::EnrollRelay;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Synthetic certificates from `dev/enroll/vectors-v1.json`.
const CERT_A: &str = "AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2X5";
const SERIAL_A: &str = "00FA01020304";
const FDSK_A: &str = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";
const CERT_B: &str = "ACB2DMWD2QAAAAAAAAAAAAAAAAAAAAAAAAAG";
const SERIAL_B: &str = "0083A1B2C3D4";

/// A test key store: knows the vector certificates' serials, stores each
/// once, and has one device (`1.1.20`) in its model.
#[derive(Clone, Default)]
struct TestStore {
    stored: Arc<Mutex<HashMap<String, String>>>,
}

impl CertificateSink for TestStore {
    fn enroll(&mut self, text: &str) -> CertificateOutcome {
        let serial = match text {
            CERT_A => SERIAL_A,
            CERT_B => SERIAL_B,
            _ => {
                return CertificateOutcome {
                    status: EnrollStatus::Invalid,
                    serial: None,
                    ia: None,
                    name: None,
                    message: Some("not a certificate".to_string()),
                };
            }
        };
        let Ok(mut stored) = self.stored.lock() else {
            return CertificateOutcome::error("store lock poisoned");
        };
        let status = if stored.contains_key(serial) {
            EnrollStatus::AlreadyStored
        } else if serial == SERIAL_A {
            EnrollStatus::Stored
        } else {
            EnrollStatus::Unassigned
        };
        stored.insert(serial.to_string(), text.to_string());
        let device = serial == SERIAL_A;
        CertificateOutcome {
            status,
            serial: Some(serial.to_string()),
            ia: device.then(|| "1.1.20".to_string()),
            name: device.then(|| "Test actuator".to_string()),
            message: None,
        }
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

/// The phone page, minus the camera.
struct FakePhone {
    keys: EnrollKeyPair,
    key: SessionKey,
    sid: [u8; 16],
    session_url: String,
    after: u64,
}

impl FakePhone {
    fn join(link: &str) -> Result<Self, BoxError> {
        let params = fragment(link)?;
        assert_eq!(params.get("v").map(String::as_str), Some("1"));
        let relay = percent_decode(params.get("r").ok_or("no relay")?)?;
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
        // The session may not be created yet: retry a 404 for a while.
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

    /// The next down messages, decrypted, and whether the session closed.
    fn receive(&mut self) -> Result<(Vec<DownMessage>, bool), BoxError> {
        let text = ureq::get(&format!(
            "{}/down?after={}&wait=10",
            self.session_url, self.after
        ))
        .call()?
        .into_string()?;
        let body: Value = serde_json::from_str(&text)?;
        let mut out = Vec::new();
        for m in body["messages"].as_array().ok_or("messages")? {
            self.after = m["seq"].as_u64().ok_or("seq")?;
            let envelope: Envelope = serde_json::from_value(m["body"].clone())?;
            if envelope.pk != URL_SAFE_NO_PAD.encode(self.keys.public()) {
                continue; // another phone's message
            }
            let nonce: [u8; 12] = URL_SAFE_NO_PAD.decode(&envelope.n)?.as_slice().try_into()?;
            let plain = self.key.open(
                Direction::Down,
                &self.sid,
                &nonce,
                &URL_SAFE_NO_PAD.decode(&envelope.c)?,
            )?;
            out.push(serde_json::from_slice(&plain)?);
        }
        Ok((out, body["closed"].as_bool().unwrap_or(false)))
    }

    /// Wait for `count` results.
    fn results(&mut self, count: usize) -> Result<Vec<DownMessage>, BoxError> {
        let mut got = Vec::new();
        while got.len() < count {
            let (messages, closed) = self.receive()?;
            got.extend(messages);
            if closed {
                break;
            }
        }
        Ok(got)
    }
}

fn result(id: u64, status: EnrollStatus, serial: &str, device: bool) -> DownMessage {
    DownMessage::Result {
        id,
        outcome: CertificateOutcome {
            status,
            serial: Some(serial.to_string()),
            ia: device.then(|| "1.1.20".to_string()),
            name: device.then(|| "Test actuator".to_string()),
            message: None,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_enroll_session_end_to_end_through_local_relay() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let relay_url = format!("http://{}", listener.local_addr()?);
    let router = EnrollRelay::new().router();
    tokio::spawn(async move { axum::serve(listener, router).await });

    let store = TestStore::default();
    let mut session = EnrollSession::new()?;
    let link = session.link("https://page.invalid/enroll/", Some(&relay_url));
    let fingerprint = session.fingerprint();

    let bussard = {
        let mut store = store.clone();
        let relay_url = relay_url.clone();
        tokio::task::spawn_blocking(move || -> Result<_, BoxError> {
            let relay = HttpRelay::new(&relay_url, &session)?;
            let stop = AtomicBool::new(false);
            let mut events = Vec::new();
            let summary = session.run(
                &relay,
                &mut store,
                RunOptions { wait_secs: 2 },
                &stop,
                &mut |event| events.push(event),
            )?;
            Ok((summary, events))
        })
    };

    let phone = tokio::task::spawn_blocking(move || -> Result<_, BoxError> {
        let mut phone = FakePhone::join(&link)?;
        assert_eq!(
            bussard_secure::enroll::fingerprint(
                &URL_SAFE_NO_PAD
                    .decode(fragment(&link)?.get("k").ok_or("k")?)?
                    .as_slice()
                    .try_into()?
            ),
            fingerprint
        );
        phone.send(&json!({"type": "certificate", "id": 1, "text": CERT_A}))?;
        phone.send(&json!({"type": "certificate", "id": 2, "text": CERT_B}))?;
        phone.send(&json!({"type": "certificate", "id": 3, "text": CERT_A}))?;
        phone.send(&json!({"type": "certificate", "id": 4, "text": "AAAA"}))?;
        let results = phone.results(4)?;
        phone.send(&json!({"type": "done"}))?;
        // After `done` bussard closes the session.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut closed = false;
        let mut tail = Vec::new();
        while !closed && Instant::now() < deadline {
            let (messages, is_closed) = phone.receive()?;
            tail.extend(messages);
            closed = is_closed;
        }
        Ok((results, tail, closed))
    });

    let (results, tail, closed) = phone.await??;
    let (summary, events) = bussard.await??;

    assert_eq!(
        results[..3],
        [
            result(1, EnrollStatus::Stored, SERIAL_A, true),
            result(2, EnrollStatus::Unassigned, SERIAL_B, false),
            result(3, EnrollStatus::AlreadyStored, SERIAL_A, true),
        ]
    );
    let DownMessage::Result { id: 4, outcome } = &results[3] else {
        return Err(format!("unexpected fourth result {:?}", results[3]).into());
    };
    assert_eq!(outcome.status, EnrollStatus::Invalid);
    assert!(closed, "the relay session was not deleted");
    // `closed` may or may not be read before the delete empties the mailbox.
    assert!(
        tail.iter().all(|m| *m == DownMessage::Closed { stored: 2 }),
        "{tail:?}"
    );

    assert_eq!(summary.end, EnrollEnd::PhoneDone);
    assert_eq!((summary.stored, summary.certificates), (2, 4));
    assert_eq!(
        store
            .stored
            .lock()
            .map_err(|e| e.to_string())?
            .get(SERIAL_A)
            .map(String::as_str),
        Some(CERT_A)
    );
    assert_eq!(
        events.first(),
        Some(&EnrollEvent::PhoneJoined { phones: 1 })
    );
    assert_eq!(events.last(), Some(&EnrollEvent::PhoneDone));

    // Nothing bussard reports carries the certificate text or the key.
    let shown = format!("{events:?} {summary:?} {results:?}");
    for secret in [CERT_A, CERT_B, FDSK_A, &FDSK_A.to_lowercase()] {
        assert!(!shown.contains(secret), "{secret} leaked into the output");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_enroll_session_stop_flag_closes_session() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let relay_url = format!("http://{}", listener.local_addr()?);
    let router = EnrollRelay::new().router();
    tokio::spawn(async move { axum::serve(listener, router).await });

    let mut session = EnrollSession::new()?;
    let sid = session.session_id();
    let stop = Arc::new(AtomicBool::new(false));
    let bussard = {
        let stop = stop.clone();
        let relay_url = relay_url.clone();
        tokio::task::spawn_blocking(move || -> Result<_, BoxError> {
            let relay = HttpRelay::new(&relay_url, &session)?;
            Ok(session.run(
                &relay,
                &mut TestStore::default(),
                RunOptions { wait_secs: 1 },
                &stop,
                &mut |_| {},
            )?)
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let summary = bussard.await??;
    assert_eq!(summary.end, EnrollEnd::Stopped);
    let down = format!("{relay_url}/v1/sessions/{sid}/down");
    let body = tokio::task::spawn_blocking(move || -> Result<String, BoxError> {
        Ok(ureq::get(&down).call()?.into_string()?)
    })
    .await??;
    assert_eq!(
        serde_json::from_str::<Value>(&body)?,
        json!({"messages": [], "closed": true})
    );
    Ok(())
}
