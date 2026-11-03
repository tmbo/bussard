//! The certificate enrolment session (issue #729, part of #201).
//!
//! A phone scans a KNX Secure device's certificate label and sends it, end to
//! end encrypted, through a mailbox relay to bussard. This module is
//! bussard's side of `dev/enroll-protocol.md`:
//!
//! - [`EnrollSession`]: the one-time X25519 key pair, session id and relay
//!   owner token; the link and fingerprint to show; and
//!   [`EnrollSession::handle`], which opens an `up` envelope, hands a
//!   `certificate` to a [`CertificateSink`] and seals the `result`.
//! - [`EnrollSession::run`]: the loop over a [`Relay`] (create, long-poll
//!   `up`, post `down`, close and delete) that every surface drives.
//! - [`relay`]: the [`Relay`] trait and its outbound HTTP client
//!   [`HttpRelay`].
//!
//! The session never decodes a certificate and never writes the key store:
//! the [`CertificateSink`] does. [`crate::CertificateEnrolment`] (#728) is
//! the sink every surface uses; tests use a fake.
//!
//! # Key hygiene
//!
//! No key and no certificate text reaches an event, an error, a log line or
//! a `Debug` output. The certificate text is zeroized once the sink returns.

pub mod relay;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bussard_secure::enroll::{
    Direction, EnrollError, EnrollKeyPair, NONCE_LEN, PUBLIC_KEY_LEN, SESSION_ID_LEN, SessionKey,
    VERSION,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub use relay::{HttpRelay, Relay, RelayError, RelayMessage, RelayPoll};

/// The enrolment page a link opens unless the surface names another
/// (`dev/enroll-protocol.md`, "Parties"). Only the page; the relay has no
/// default until the hosted relay's host is decided.
pub const DEFAULT_PAGE: &str = "https://bussard.tmbo.dev/enroll/";

/// The largest serialized envelope the protocol allows, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 4096;

/// The longest long poll the relay API allows, in seconds.
pub const MAX_WAIT_SECS: u64 = 25;

/// An encrypted message as it travels through the relay, in both directions.
///
/// `pk` is always the phone's public key; all binary fields are base64url
/// without padding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The protocol version, `1`.
    pub v: u8,
    /// The phone's X25519 public key.
    pub pk: String,
    /// The 12-byte AES-GCM nonce.
    pub n: String,
    /// The ciphertext with the 16-byte tag appended.
    pub c: String,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("v", &self.v)
            .field("pk", &self.pk)
            .field("c_len", &self.c.len())
            .finish_non_exhaustive()
    }
}

/// What became of one certificate, as the `result` message reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollStatus {
    /// Matched to a device in the model and saved.
    Stored,
    /// Saved under its serial; no device in the model has it yet.
    Unassigned,
    /// The same FDSK is already in the store.
    AlreadyStored,
    /// The store holds a different FDSK for this serial; nothing written.
    Conflict,
    /// The format or the check failed.
    Invalid,
    /// Something else went wrong; `message` says what.
    Error,
}

impl EnrollStatus {
    /// The status as the protocol spells it (`stored`, `already_stored`, ...).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollStatus::Stored => "stored",
            EnrollStatus::Unassigned => "unassigned",
            EnrollStatus::AlreadyStored => "already_stored",
            EnrollStatus::Conflict => "conflict",
            EnrollStatus::Invalid => "invalid",
            EnrollStatus::Error => "error",
        }
    }

    /// Whether the certificate's key is in the store after this outcome.
    #[must_use]
    pub fn is_stored(self) -> bool {
        matches!(self, EnrollStatus::Stored | EnrollStatus::Unassigned)
    }
}

/// A [`CertificateSink`]'s answer for one certificate: the `result` message
/// without its `id`. It never carries a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateOutcome {
    /// What happened.
    pub status: EnrollStatus,
    /// The certificate's serial number, 12 uppercase hex digits. `None` only
    /// when the text did not decode far enough to have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// The individual address of the matched device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ia: Option<String>,
    /// The matched device's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Why, for `invalid`, `conflict` and `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CertificateOutcome {
    /// An `error` outcome with `message` and no serial.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        CertificateOutcome {
            status: EnrollStatus::Error,
            serial: None,
            ia: None,
            name: None,
            message: Some(message.into()),
        }
    }
}

/// Where a decrypted certificate goes: [`crate::CertificateEnrolment`]
/// (#728), or a test's fake store.
pub trait CertificateSink {
    /// Decode, match and store one certificate. `text` is the certificate as
    /// the page normalized it (36 base32 characters); it holds the FDSK, so
    /// an implementation never logs, prints or returns it.
    fn enroll(&mut self, text: &str) -> CertificateOutcome;
}

/// The key store enrolment of #728 behind a session: every surface enters a
/// certificate through the same [`crate::CertificateEnrolment`].
impl CertificateSink for crate::enroll::CertificateEnrolment {
    fn enroll(&mut self, text: &str) -> CertificateOutcome {
        CertificateOutcome::from(self.enroll_certificate(text))
    }
}

impl From<crate::enroll::EnrolOutcome> for CertificateOutcome {
    fn from(outcome: crate::enroll::EnrolOutcome) -> Self {
        use crate::enroll::EnrolStatus as S;
        CertificateOutcome {
            status: match outcome.status {
                S::Stored => EnrollStatus::Stored,
                S::Unassigned => EnrollStatus::Unassigned,
                S::AlreadyStored => EnrollStatus::AlreadyStored,
                S::Conflict => EnrollStatus::Conflict,
                S::Invalid => EnrollStatus::Invalid,
                S::Error => EnrollStatus::Error,
            },
            serial: outcome.serial,
            ia: outcome.ia,
            name: outcome.name,
            message: outcome.message,
        }
    }
}

/// A message from the page to bussard (the plaintext of an `up` envelope).
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UpMessage {
    Certificate { id: u64, text: String },
    Done,
}

/// A message from bussard to the page (the plaintext of a `down` envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DownMessage {
    /// The outcome of the certificate the page numbered `id`.
    Result {
        /// The page's id of the certificate.
        id: u64,
        /// The outcome.
        #[serde(flatten)]
        outcome: CertificateOutcome,
    },
    /// bussard ended the session after storing `stored` certificates.
    Closed {
        /// How many certificates the session stored.
        stored: u32,
    },
}

/// What [`EnrollSession::run`] reports as it goes. Never a key or a
/// certificate text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollEvent {
    /// A new phone key sent its first valid message; `phones` is the count.
    PhoneJoined {
        /// Phones that joined so far.
        phones: usize,
    },
    /// A certificate was handled.
    Certificate(CertificateOutcome),
    /// An `up` message was dropped (`reason` names why, never its content).
    Ignored {
        /// Why the message was dropped.
        reason: String,
    },
    /// A phone sent `done`.
    PhoneDone,
}

/// How [`EnrollSession::run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollEnd {
    /// A phone sent `done`.
    PhoneDone,
    /// The caller's stop flag was set.
    Stopped,
    /// The relay no longer knows the session (expired after 30 minutes, or
    /// closed by someone else).
    Expired,
}

/// The summary of a finished [`EnrollSession::run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollSummary {
    /// Why the session ended.
    pub end: EnrollEnd,
    /// How many certificates were stored (`stored` or `unassigned`).
    pub stored: u32,
    /// How many certificates were handled in total.
    pub certificates: u32,
}

/// Errors of an enrolment session. None carries a key or certificate text.
#[derive(Debug, thiserror::Error)]
pub enum EnrollSessionError {
    /// The session crypto failed (the random source, a seal).
    #[error(transparent)]
    Crypto(#[from] EnrollError),
    /// The relay failed.
    #[error(transparent)]
    Relay(#[from] RelayError),
}

/// What [`EnrollSession::handle`] made of one `up` envelope.
#[derive(Debug)]
pub enum Handled {
    /// A certificate: post `reply` (the sealed `result`) down.
    Certificate {
        /// The sealed `result` for the phone.
        reply: Envelope,
        /// The outcome, for the surface to show.
        outcome: CertificateOutcome,
    },
    /// The phone sent `done`.
    Done,
    /// The message was dropped; `reason` says why without its content.
    Ignored(String),
}

/// Options of [`EnrollSession::run`].
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    /// The long-poll wait per `GET up`, in seconds (at most
    /// [`MAX_WAIT_SECS`]). Bounds how long a stop takes to be noticed.
    pub wait_secs: u64,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions { wait_secs: 5 }
    }
}

/// bussard's side of one enrolment session.
pub struct EnrollSession {
    sid: [u8; SESSION_ID_LEN],
    keys: EnrollKeyPair,
    owner_token: Zeroizing<[u8; 32]>,
    phones: BTreeMap<[u8; PUBLIC_KEY_LEN], SessionKey>,
    stored: u32,
    certificates: u32,
}

impl std::fmt::Debug for EnrollSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollSession")
            .field("sid", &self.session_id())
            .field("phones", &self.phones.len())
            .field("stored", &self.stored)
            .finish_non_exhaustive()
    }
}

impl EnrollSession {
    /// A new session: random session id, one-time X25519 key pair and owner
    /// token.
    ///
    /// # Errors
    ///
    /// [`EnrollSessionError::Crypto`] when the OS random source fails.
    pub fn new() -> Result<Self, EnrollSessionError> {
        Ok(Self::from_parts(
            bussard_secure::enroll::random()?,
            EnrollKeyPair::generate()?,
            bussard_secure::enroll::random()?,
        ))
    }

    /// A session from fixed parts (the test vectors).
    fn from_parts(sid: [u8; SESSION_ID_LEN], keys: EnrollKeyPair, owner_token: [u8; 32]) -> Self {
        EnrollSession {
            sid,
            keys,
            owner_token: Zeroizing::new(owner_token),
            phones: BTreeMap::new(),
            stored: 0,
            certificates: 0,
        }
    }

    /// The session id, base64url.
    #[must_use]
    pub fn session_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.sid)
    }

    /// The owner token, base64url: the relay's bearer credential for this
    /// session. Not a key, but nothing else should see it either.
    fn owner_token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.owner_token.as_ref())
    }

    /// The fingerprint both sides show (`XXXX-XXXX`).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        bussard_secure::enroll::fingerprint(&self.keys.public())
    }

    /// The link to open on the phone: `page` with the session in its
    /// fragment, and `relay` unless the page's origin serves the relay.
    #[must_use]
    pub fn link(&self, page: &str, relay: Option<&str>) -> String {
        bussard_secure::enroll::link(page, &self.sid, &self.keys.public(), relay)
    }

    /// How many certificates were stored so far.
    #[must_use]
    pub fn stored(&self) -> u32 {
        self.stored
    }

    /// Open one `up` envelope; a `certificate` goes to `sink` and its sealed
    /// `result` comes back to post down.
    ///
    /// # Errors
    ///
    /// [`EnrollSessionError::Crypto`] only when sealing the reply fails (the
    /// random source). A message that does not open is
    /// [`Handled::Ignored`], not an error: anyone with the link can post.
    pub fn handle(
        &mut self,
        envelope: &Envelope,
        sink: &mut dyn CertificateSink,
    ) -> Result<Handled, EnrollSessionError> {
        let (phone, plaintext) = match self.open(envelope) {
            Ok(opened) => opened,
            Err(reason) => return Ok(Handled::Ignored(reason)),
        };
        let message: UpMessage = match serde_json::from_slice(&plaintext) {
            Ok(message) => message,
            // serde_json's message can quote the input; keep only the class.
            Err(_) => return Ok(Handled::Ignored("not a protocol message".to_string())),
        };
        match message {
            UpMessage::Done => Ok(Handled::Done),
            UpMessage::Certificate { id, mut text } => {
                let outcome = sink.enroll(&text);
                text.zeroize();
                self.certificates += 1;
                if outcome.status.is_stored() {
                    self.stored += 1;
                }
                let reply = self.seal(
                    &phone,
                    &DownMessage::Result {
                        id,
                        outcome: outcome.clone(),
                    },
                )?;
                Ok(Handled::Certificate { reply, outcome })
            }
        }
    }

    /// The `closed` message for every phone that joined.
    ///
    /// # Errors
    ///
    /// [`EnrollSessionError::Crypto`] when sealing fails.
    pub fn closing(&self) -> Result<Vec<Envelope>, EnrollSessionError> {
        let closed = DownMessage::Closed {
            stored: self.stored,
        };
        self.phones
            .keys()
            .map(|phone| self.seal(phone, &closed))
            .collect()
    }

    /// Run the session over `relay` until a phone sends `done`, `stop` is
    /// set or the relay drops the session; then post `closed` to every phone
    /// and delete the session. `on_event` sees each step.
    ///
    /// # Errors
    ///
    /// [`EnrollSessionError::Relay`] when the relay refuses or cannot be
    /// reached (the session is still deleted on a best-effort basis), or
    /// [`EnrollSessionError::Crypto`] when sealing fails.
    pub fn run(
        &mut self,
        relay: &dyn Relay,
        sink: &mut dyn CertificateSink,
        options: RunOptions,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(EnrollEvent),
    ) -> Result<EnrollSummary, EnrollSessionError> {
        relay.create()?;
        let outcome = self.poll_loop(relay, sink, options, stop, on_event);
        let end = match outcome {
            Ok(end) => end,
            Err(err) => {
                // Best effort: the relay also expires the session.
                let _ = relay.delete();
                return Err(err);
            }
        };
        if end != EnrollEnd::Expired {
            for envelope in self.closing()? {
                // The phone also learns from `closed: true` once deleted.
                let _ = relay.post_down(&envelope);
            }
            relay.delete()?;
        }
        Ok(EnrollSummary {
            end,
            stored: self.stored,
            certificates: self.certificates,
        })
    }

    fn poll_loop(
        &mut self,
        relay: &dyn Relay,
        sink: &mut dyn CertificateSink,
        options: RunOptions,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(EnrollEvent),
    ) -> Result<EnrollEnd, EnrollSessionError> {
        let wait = options.wait_secs.min(MAX_WAIT_SECS);
        let mut after = 0;
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(EnrollEnd::Stopped);
            }
            let poll = match relay.poll_up(after, wait) {
                Ok(poll) => poll,
                Err(RelayError::NotFound) => return Ok(EnrollEnd::Expired),
                Err(err) => return Err(err.into()),
            };
            for message in poll.messages {
                after = after.max(message.seq);
                let Some(envelope) = message.envelope else {
                    on_event(EnrollEvent::Ignored {
                        reason: "not an envelope".to_string(),
                    });
                    continue;
                };
                let phones = self.phones.len();
                let handled = self.handle(&envelope, sink)?;
                if self.phones.len() > phones {
                    on_event(EnrollEvent::PhoneJoined {
                        phones: self.phones.len(),
                    });
                }
                match handled {
                    Handled::Certificate { reply, outcome } => {
                        relay.post_down(&reply)?;
                        on_event(EnrollEvent::Certificate(outcome));
                    }
                    Handled::Done => {
                        on_event(EnrollEvent::PhoneDone);
                        return Ok(EnrollEnd::PhoneDone);
                    }
                    Handled::Ignored(reason) => on_event(EnrollEvent::Ignored { reason }),
                }
            }
            if poll.closed {
                return Ok(EnrollEnd::Expired);
            }
        }
    }

    /// Decrypt an `up` envelope; the phone key joins on its first message
    /// that opens. The error is a reason without content.
    fn open(
        &mut self,
        envelope: &Envelope,
    ) -> Result<([u8; PUBLIC_KEY_LEN], Zeroizing<Vec<u8>>), String> {
        if envelope.v != VERSION {
            return Err(format!("unsupported version {}", envelope.v));
        }
        let phone: [u8; PUBLIC_KEY_LEN] = decode_fixed(&envelope.pk)
            .ok_or_else(|| "the phone key is not 32 bytes of base64url".to_string())?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&envelope.n)
            .ok_or_else(|| "the nonce is not 12 bytes of base64url".to_string())?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.c)
            .map_err(|_| "the ciphertext is not base64url".to_string())?;
        let opened = match self.phones.get(&phone) {
            Some(key) => key.open(Direction::Up, &self.sid, &nonce, &ciphertext),
            None => {
                let key = self
                    .keys
                    .bussard_key(&self.sid, &phone)
                    .map_err(|e| e.to_string())?;
                let opened = key.open(Direction::Up, &self.sid, &nonce, &ciphertext);
                if opened.is_ok() {
                    self.phones.insert(phone, key);
                }
                opened
            }
        };
        opened
            .map(|plaintext| (phone, plaintext))
            .map_err(|e| e.to_string())
    }

    /// Seal a down message for `phone` under a fresh nonce.
    fn seal(
        &self,
        phone: &[u8; PUBLIC_KEY_LEN],
        message: &DownMessage,
    ) -> Result<Envelope, EnrollSessionError> {
        let key = match self.phones.get(phone) {
            Some(key) => key,
            None => return Err(EnrollError::Seal.into()),
        };
        let plaintext = encode_down(message);
        let (nonce, sealed) = key.seal_random(Direction::Down, &self.sid, plaintext.as_bytes())?;
        Ok(Envelope {
            v: VERSION,
            pk: URL_SAFE_NO_PAD.encode(phone),
            n: URL_SAFE_NO_PAD.encode(nonce),
            c: URL_SAFE_NO_PAD.encode(sealed),
        })
    }
}

/// The plaintext JSON of a down message.
fn encode_down(message: &DownMessage) -> String {
    // A DownMessage is strings, integers and enums: serializing cannot fail.
    serde_json::to_string(message).unwrap_or_default()
}

fn decode_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes.as_slice()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn vectors() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../dev/enroll/vectors-v1.json"
        );
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    fn hex32(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let bytes = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        Ok(<[u8; 32]>::try_from(bytes.as_slice())?)
    }

    fn str_of<'a>(v: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
        v[name]
            .as_str()
            .ok_or_else(|| format!("vector field {name}"))
    }

    /// The vectors' session and phone.
    fn vector_session(
        v: &serde_json::Value,
    ) -> Result<(EnrollSession, EnrollKeyPair), Box<dyn std::error::Error>> {
        let s = &v["session"];
        let sid = decode_fixed(str_of(s, "session_id")?).ok_or("sid")?;
        let keys = EnrollKeyPair::from_secret(hex32(str_of(s, "bussard_secret")?)?);
        let phone = EnrollKeyPair::from_secret(hex32(str_of(s, "phone_secret")?)?);
        Ok((EnrollSession::from_parts(sid, keys, [0x42; 32]), phone))
    }

    fn envelope(v: &serde_json::Value) -> Result<Envelope, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(v.clone())?)
    }

    /// Records the texts it sees and answers like the vectors' device.
    #[derive(Default)]
    struct FakeStore {
        texts: Vec<String>,
    }

    impl CertificateSink for FakeStore {
        fn enroll(&mut self, text: &str) -> CertificateOutcome {
            self.texts.push(text.to_string());
            CertificateOutcome {
                status: EnrollStatus::Stored,
                serial: Some("00FA01020304".to_string()),
                ia: Some("1.1.20".to_string()),
                name: Some("Test actuator".to_string()),
                message: None,
            }
        }
    }

    #[test]
    fn test_session_link_and_fingerprint_match_vectors() -> TestResult {
        let v = vectors()?;
        let (session, _) = vector_session(&v)?;
        assert_eq!(session.session_id(), str_of(&v["session"], "session_id")?);
        assert_eq!(session.fingerprint(), str_of(&v["session"], "fingerprint")?);
        assert_eq!(
            session.link(
                "https://bussard.tmbo.dev/enroll/",
                Some("https://relay.example")
            ),
            str_of(&v["session"], "link")?
        );
        Ok(())
    }

    #[test]
    fn test_handle_vector_certificate_and_done() -> TestResult {
        let v = vectors()?;
        let (mut session, phone) = vector_session(&v)?;
        let messages = v["messages"].as_array().ok_or("messages")?;
        let mut store = FakeStore::default();

        let Handled::Certificate { reply, outcome } =
            session.handle(&envelope(&messages[0]["envelope"])?, &mut store)?
        else {
            return Err("the vector certificate was not handled".into());
        };
        assert_eq!(store.texts, ["AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2XR"]);
        assert_eq!(outcome.status, EnrollStatus::Stored);
        assert_eq!(session.stored(), 1);

        // The reply opens on the phone to exactly the vector's plaintext.
        let key = phone.phone_key(&session.sid, &session.keys.public())?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&reply.n).ok_or("nonce")?;
        let opened = key.open(
            Direction::Down,
            &session.sid,
            &nonce,
            &URL_SAFE_NO_PAD.decode(&reply.c)?,
        )?;
        assert_eq!(
            std::str::from_utf8(&opened)?,
            str_of(&messages[1], "plaintext")?
        );
        assert_eq!(reply.pk, str_of(&messages[1]["envelope"], "pk")?);

        assert!(matches!(
            session.handle(&envelope(&messages[2]["envelope"])?, &mut store)?,
            Handled::Done
        ));
        Ok(())
    }

    #[test]
    fn test_handle_vector_certificate_into_key_store() -> TestResult {
        use bussard_project::keystore::{KeyStore, SerialNumber};
        const PASSWORD: &str = "synthetic-enroll-session-pw";
        let serial = SerialNumber([0x00, 0xFA, 0x01, 0x02, 0x03, 0x04]);
        let dir = std::env::temp_dir().join(format!(
            "bussard-enroll-session-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        let mut store = KeyStore::new("synthetic");
        store.devices.entry("1.1.20".parse()?).or_default().serial = Some(serial);
        store.save(&dir, PASSWORD)?;

        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let mut sink = crate::CertificateEnrolment::open(&dir, PASSWORD)?;
        let Handled::Certificate { outcome, .. } =
            session.handle(&envelope(&v["messages"][0]["envelope"])?, &mut sink)?
        else {
            return Err("the vector certificate was not handled".into());
        };
        assert_eq!(outcome.status, EnrollStatus::Stored);
        assert_eq!(outcome.serial.as_deref(), Some("00FA01020304"));
        assert_eq!(outcome.ia.as_deref(), Some("1.1.20"));
        let back = KeyStore::load(&dir, PASSWORD)?.ok_or("no store")?;
        assert_eq!(
            back.fdsk_for_serial(serial),
            Some(&bussard_secure::Key16::new([
                0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
                0xAE, 0xAF,
            ]))
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_encode_down_matches_vector_plaintext() -> TestResult {
        let v = vectors()?;
        let message = DownMessage::Result {
            id: 1,
            outcome: FakeStore::default().enroll(""),
        };
        assert_eq!(
            encode_down(&message),
            str_of(&v["messages"][1], "plaintext")?
        );
        let parsed: DownMessage = serde_json::from_str(str_of(&v["messages"][1], "plaintext")?)?;
        assert_eq!(parsed, message);
        assert_eq!(
            encode_down(&DownMessage::Closed { stored: 2 }),
            r#"{"type":"closed","stored":2}"#
        );
        Ok(())
    }

    #[test]
    fn test_handle_ignores_tampered_and_foreign_envelopes() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let mut store = FakeStore::default();
        let mut tampered = envelope(&v["messages"][0]["envelope"])?;
        tampered.c.replace_range(0..1, "J");
        assert!(matches!(
            session.handle(&tampered, &mut store)?,
            Handled::Ignored(_)
        ));
        // A down envelope posted up does not open (the direction is in the AAD).
        let down = envelope(&v["messages"][1]["envelope"])?;
        assert!(matches!(
            session.handle(&down, &mut store)?,
            Handled::Ignored(_)
        ));
        let mut bad = down.clone();
        bad.pk = "short".to_string();
        let Handled::Ignored(reason) = session.handle(&bad, &mut store)? else {
            return Err("a malformed key was accepted".into());
        };
        assert!(!reason.contains("short"), "{reason}");
        assert!(store.texts.is_empty());
        assert!(session.phones.is_empty(), "a failed message joined a phone");
        Ok(())
    }

    #[test]
    fn test_envelope_debug_hides_ciphertext() -> TestResult {
        let v = vectors()?;
        let env = envelope(&v["messages"][0]["envelope"])?;
        assert!(!format!("{env:?}").contains(&env.c));
        Ok(())
    }
}
