//! The certificate enrolment session (issue #729, part of #201).
//!
//! A phone scans a KNX Secure device's certificate label and sends it, end to
//! end encrypted, through a mailbox relay to bussard. This module is
//! bussard's side of `dev/enroll-protocol.md`:
//!
//! - [`EnrollSession`]: the one-time X25519 key pair, session id and relay
//!   owner token; the link and session code (fingerprint) to show; and
//!   [`EnrollSession::handle`], which opens an `up` envelope, lets the first
//!   phone own the session and refuses every other, hands a `certificate`
//!   to a [`CertificateSink`] and seals the `result`.
//! - [`EnrollSession::run`]: the loop over a [`Relay`] (create, long-poll
//!   `up`, post `down`, the connect, idle and maximum timeouts, close and
//!   delete) that every surface drives.
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
pub mod report;

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bussard_secure::enroll::{
    Direction, EnrollError, EnrollKeyPair, NONCE_LEN, PUBLIC_KEY_LEN, SESSION_ID_LEN, SessionKey,
    VERSION,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub use relay::{HttpRelay, Relay, RelayError, RelayMessage, RelayPoll};
pub use report::{DOCS_URL, EnrollTally, NextStep, data_path};

/// The enrolment page a link opens unless the surface names another
/// (`dev/enroll-protocol.md`, "Parties"). The relay's Worker serves it, so
/// page and [`DEFAULT_RELAY`] share one origin (#797).
pub const DEFAULT_PAGE: &str = "https://bussard-relay.tmbo.dev/enroll/";

/// The hosted relay a session uses unless the surface names another
/// (`--relay`, then `[enroll] relay`). The hosted page's CSP allows only
/// its own origin, this relay: a self-hosted relay needs a self-hosted page
/// (`[enroll] page`).
pub const DEFAULT_RELAY: &str = "https://bussard-relay.tmbo.dev";

/// The relay and page of a hosted session: each the first of the
/// surface's own setting (`--relay`, `--page`), the `[enroll]` table of
/// bussard.toml, and the default ([`DEFAULT_RELAY`], [`DEFAULT_PAGE`]).
#[must_use]
pub fn hosted_endpoints(
    relay: Option<String>,
    page: Option<String>,
    config: &bussard_model::schema::EnrollConfig,
) -> (String, String) {
    (
        relay
            .or_else(|| config.relay.clone())
            .unwrap_or_else(|| DEFAULT_RELAY.to_string()),
        page.or_else(|| config.page.clone())
            .unwrap_or_else(|| DEFAULT_PAGE.to_string()),
    )
}

/// Warnings for a hosted session whose relay or page is not the project's
/// default (finding F13, `dev/enroll-protocol.md`, "Parties"): the page's
/// JavaScript sees every label in plaintext, so a user should know when it
/// is not the project's. Empty for the defaults.
#[must_use]
pub fn endpoint_warnings(relay: &str, page: &str) -> Vec<String> {
    let mut out = Vec::new();
    if page.trim_end_matches('/') != DEFAULT_PAGE.trim_end_matches('/') {
        out.push(format!(
            "the enrolment page is {page}, not the default {DEFAULT_PAGE}; it sees every label \
             in plaintext, so use it only if you trust whoever serves it"
        ));
    }
    if relay.trim_end_matches('/') != DEFAULT_RELAY {
        out.push(format!(
            "the relay is {relay}, not the default {DEFAULT_RELAY}; it sees only ciphertext, \
             but it can delay or drop messages"
        ));
    }
    out
}

/// The timeouts of a session (`dev/enroll-protocol.md`, "Timeouts").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// How long a phone has to join after the session starts.
    pub connect: Duration,
    /// How long the owning phone may stay silent.
    pub idle: Duration,
    /// The longest a session runs.
    pub max: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(10 * 60),
            idle: Duration::from_secs(15 * 60),
            max: Duration::from_secs(4 * 60 * 60),
        }
    }
}

/// How many refused phone keys bussard answers with `refused`; beyond this
/// it only counts them, so a flood of keys cannot fill the `down` queue.
pub const MAX_REFUSED_ANSWERS: usize = 16;

/// How many refused phone keys a session remembers, to report each once.
const MAX_REFUSED_TRACKED: usize = 1024;

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
    /// The protocol version, `2`.
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
    Hello,
    Certificate { id: u64, text: String },
    Done,
}

/// Why bussard ended a session, as the `closed` message reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// The phone sent `done`.
    Done,
    /// The user ended the session on bussard's side.
    Stopped,
    /// The owning phone was silent for the idle timeout.
    IdleTimeout,
    /// The session reached its maximum duration.
    MaxDuration,
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
    /// This session belongs to another phone; nothing this phone sends is
    /// processed.
    Refused,
    /// bussard ended the session after storing `stored` certificates.
    Closed {
        /// How many certificates the session stored.
        stored: u32,
        /// Why it ended.
        reason: CloseReason,
    },
}

/// What [`EnrollSession::run`] reports as it goes. Never a key or a
/// certificate text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollEvent {
    /// A phone sent its first message that opens and now owns the session.
    PhoneJoined,
    /// Another phone sent a message that opens and was refused (one phone
    /// per session). Reported once per phone key; `phones` counts them.
    PhoneRefused {
        /// Refused phones so far.
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
    /// No phone joined within the connect timeout.
    ConnectTimeout,
    /// The owning phone was silent for the idle timeout.
    IdleTimeout,
    /// The session reached its maximum duration.
    MaxDuration,
    /// The relay no longer knows the session (it expired there, or someone
    /// else closed it).
    Expired,
}

impl EnrollEnd {
    /// The `reason` of the `closed` message, when the phone gets one.
    fn close_reason(self) -> Option<CloseReason> {
        match self {
            EnrollEnd::PhoneDone => Some(CloseReason::Done),
            EnrollEnd::Stopped => Some(CloseReason::Stopped),
            EnrollEnd::IdleTimeout => Some(CloseReason::IdleTimeout),
            EnrollEnd::MaxDuration => Some(CloseReason::MaxDuration),
            EnrollEnd::ConnectTimeout | EnrollEnd::Expired => None,
        }
    }

    /// A short phrase for a person: why the session ended.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            EnrollEnd::PhoneDone => "the phone finished",
            EnrollEnd::Stopped => "stopped",
            EnrollEnd::ConnectTimeout => "no phone joined within 10 minutes",
            EnrollEnd::IdleTimeout => "no label or sign of the page for 15 minutes",
            EnrollEnd::MaxDuration => "the 4-hour limit was reached",
            EnrollEnd::Expired => "the relay session expired",
        }
    }
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
    /// How many other phones tried to join and were refused.
    pub refused_phones: usize,
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
    /// The owning phone's `hello`: the page is open.
    Hello,
    /// A certificate: post `reply` (the sealed `result`) down.
    Certificate {
        /// The sealed `result` for the phone.
        reply: Envelope,
        /// The outcome, for the surface to show.
        outcome: CertificateOutcome,
    },
    /// The phone sent `done`.
    Done,
    /// Another phone's message, refused and not processed.
    Refused {
        /// The sealed `refused` for that phone, the first time it is seen
        /// and while fewer than [`MAX_REFUSED_ANSWERS`] were answered.
        reply: Option<Envelope>,
        /// Whether this phone key was refused for the first time.
        first: bool,
    },
    /// The message was dropped; `reason` says why without its content.
    Ignored(String),
}

/// Options of [`EnrollSession::run`].
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    /// The long-poll wait per `GET up`, in seconds (at most
    /// [`MAX_WAIT_SECS`]). Bounds how long a stop takes to be noticed.
    pub wait_secs: u64,
    /// The connect, idle and maximum timeouts.
    pub timeouts: Timeouts,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            wait_secs: 5,
            timeouts: Timeouts::default(),
        }
    }
}

/// The phone that owns a session: its public key and session key.
struct Owner {
    phone: [u8; PUBLIC_KEY_LEN],
    key: SessionKey,
}

/// An `up` envelope that opened.
enum Opened {
    /// From the owning phone (possibly just now claimed).
    Owner(Zeroizing<Vec<u8>>),
    /// From another phone key.
    Other {
        phone: [u8; PUBLIC_KEY_LEN],
        key: SessionKey,
    },
}

/// bussard's side of one enrolment session.
pub struct EnrollSession {
    sid: [u8; SESSION_ID_LEN],
    keys: EnrollKeyPair,
    owner_token: Zeroizing<[u8; 32]>,
    /// The session code, derived once (it is slow on purpose).
    code: OnceLock<String>,
    owner: Option<Owner>,
    refused: BTreeSet<[u8; PUBLIC_KEY_LEN]>,
    refused_answers: usize,
    stored: u32,
    certificates: u32,
}

impl std::fmt::Debug for EnrollSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollSession")
            .field("sid", &self.session_id())
            .field("owned", &self.owner.is_some())
            .field("refused", &self.refused.len())
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
            code: OnceLock::new(),
            owner: None,
            refused: BTreeSet::new(),
            refused_answers: 0,
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

    /// The session code both sides show (`XXXX-XXXX`), the fingerprint.
    /// Derived on the first call (a few hundred milliseconds, on purpose)
    /// and remembered.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.code
            .get_or_init(|| bussard_secure::enroll::fingerprint(&self.sid, &self.keys.public()))
            .clone()
    }

    /// How many other phones tried to join and were refused.
    #[must_use]
    pub fn refused_phones(&self) -> usize {
        self.refused.len()
    }

    /// The link to open on the phone: `page` with the session in its
    /// fragment, and `relay` (`r`) unless the relay sits at the root of the
    /// page's origin (the hosted page, served by the relay Worker, and local
    /// mode): the page then uses its own origin.
    #[must_use]
    pub fn link(&self, page: &str, relay: Option<&str>) -> String {
        let relay = relay.filter(|relay| relay.trim_end_matches('/') != origin(page));
        bussard_secure::enroll::link(page, &self.sid, &self.keys.public(), relay)
    }

    /// How many certificates were stored so far.
    #[must_use]
    pub fn stored(&self) -> u32 {
        self.stored
    }

    /// Open one `up` envelope. The first phone key whose message opens owns
    /// the session; another phone's message is [`Handled::Refused`] and not
    /// processed. The owner's `certificate` goes to `sink` and its sealed
    /// `result` comes back to post down.
    ///
    /// # Errors
    ///
    /// [`EnrollSessionError::Crypto`] only when sealing a reply fails (the
    /// random source). A message that does not open is
    /// [`Handled::Ignored`], not an error: anyone with the link can post.
    pub fn handle(
        &mut self,
        envelope: &Envelope,
        sink: &mut dyn CertificateSink,
    ) -> Result<Handled, EnrollSessionError> {
        let plaintext = match self.open(envelope) {
            Ok(Opened::Owner(plaintext)) => plaintext,
            Ok(Opened::Other { phone, key }) => return self.refuse(phone, &key),
            Err(reason) => return Ok(Handled::Ignored(reason)),
        };
        let message: UpMessage = match serde_json::from_slice(&plaintext) {
            Ok(message) => message,
            // serde_json's message can quote the input; keep only the class.
            Err(_) => return Ok(Handled::Ignored("not a protocol message".to_string())),
        };
        match message {
            UpMessage::Hello => Ok(Handled::Hello),
            UpMessage::Done => Ok(Handled::Done),
            UpMessage::Certificate { id, mut text } => {
                let outcome = sink.enroll(&text);
                text.zeroize();
                self.certificates += 1;
                if outcome.status.is_stored() {
                    self.stored += 1;
                }
                let mut sent = outcome.clone();
                if sent.status == EnrollStatus::Invalid {
                    // F7: a label that does not check names no device.
                    sent.ia = None;
                    sent.name = None;
                }
                let reply = self.seal_owner(&DownMessage::Result { id, outcome: sent })?;
                Ok(Handled::Certificate { reply, outcome })
            }
        }
    }

    /// Refuse a message from a phone that does not own the session.
    fn refuse(
        &mut self,
        phone: [u8; PUBLIC_KEY_LEN],
        key: &SessionKey,
    ) -> Result<Handled, EnrollSessionError> {
        if self.refused.contains(&phone) {
            return Ok(Handled::Refused {
                reply: None,
                first: false,
            });
        }
        if self.refused.len() < MAX_REFUSED_TRACKED {
            self.refused.insert(phone);
        }
        let reply = if self.refused_answers < MAX_REFUSED_ANSWERS {
            self.refused_answers += 1;
            Some(self.seal(key, &phone, &DownMessage::Refused)?)
        } else {
            None
        };
        Ok(Handled::Refused { reply, first: true })
    }

    /// The `closed` message for the owning phone, if one joined.
    ///
    /// # Errors
    ///
    /// [`EnrollSessionError::Crypto`] when sealing fails.
    pub fn closing(&self, reason: CloseReason) -> Result<Option<Envelope>, EnrollSessionError> {
        if self.owner.is_none() {
            return Ok(None);
        }
        self.seal_owner(&DownMessage::Closed {
            stored: self.stored,
            reason,
        })
        .map(Some)
    }

    /// Run the session over `relay` until the owning phone sends `done`,
    /// `stop` is set, a timeout of `options` runs out or the relay drops the
    /// session; then post `closed` to the owning phone and delete the
    /// session. `on_event` sees each step.
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
            if let Some(reason) = end.close_reason()
                && let Some(envelope) = self.closing(reason)?
            {
                // The phone also learns from `closed: true` once deleted.
                let _ = relay.post_down(&envelope);
            }
            match relay.delete() {
                // The relay's own expiry may have come first.
                Ok(()) | Err(RelayError::NotFound) => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(EnrollSummary {
            end,
            stored: self.stored,
            certificates: self.certificates,
            refused_phones: self.refused.len(),
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
        let started = Instant::now();
        // When the owning phone last sent a message; `None` until one joins.
        let mut last_seen: Option<Instant> = None;
        let mut after = 0;
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(EnrollEnd::Stopped);
            }
            let (deadline, timeout) = deadline(started, last_seen, &options.timeouts);
            let now = Instant::now();
            if now >= deadline {
                return Ok(timeout);
            }
            // Never wait past the deadline (rounded up to a whole second).
            let left = (deadline - now).as_millis().div_ceil(1000);
            let wait = wait.min(u64::try_from(left).unwrap_or(u64::MAX));
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
                let owned = self.owner.is_some();
                let handled = self.handle(&envelope, sink)?;
                if !owned && self.owner.is_some() {
                    on_event(EnrollEvent::PhoneJoined);
                }
                match handled {
                    Handled::Hello => last_seen = Some(Instant::now()),
                    Handled::Certificate { reply, outcome } => {
                        last_seen = Some(Instant::now());
                        relay.post_down(&reply)?;
                        on_event(EnrollEvent::Certificate(outcome));
                    }
                    Handled::Done => {
                        on_event(EnrollEvent::PhoneDone);
                        return Ok(EnrollEnd::PhoneDone);
                    }
                    Handled::Refused { reply, first } => {
                        if let Some(reply) = reply {
                            // Best effort: the refused page is a courtesy.
                            let _ = relay.post_down(&reply);
                        }
                        if first {
                            on_event(EnrollEvent::PhoneRefused {
                                phones: self.refused.len(),
                            });
                        }
                    }
                    Handled::Ignored(reason) => on_event(EnrollEvent::Ignored { reason }),
                }
            }
            if poll.closed {
                return Ok(EnrollEnd::Expired);
            }
        }
    }

    /// Decrypt an `up` envelope. The first phone key whose message opens
    /// becomes the owner; another key's message that opens is
    /// [`Opened::Other`] (its plaintext dropped unread). The error is a
    /// reason without content.
    fn open(&mut self, envelope: &Envelope) -> Result<Opened, String> {
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
        if let Some(owner) = &self.owner
            && owner.phone == phone
        {
            return owner
                .key
                .open(Direction::Up, &self.sid, &nonce, &ciphertext)
                .map(Opened::Owner)
                .map_err(|e| e.to_string());
        }
        let key = self
            .keys
            .bussard_key(&self.sid, &phone)
            .map_err(|e| e.to_string())?;
        let plaintext = key
            .open(Direction::Up, &self.sid, &nonce, &ciphertext)
            .map_err(|e| e.to_string())?;
        if self.owner.is_some() {
            return Ok(Opened::Other { phone, key });
        }
        self.owner = Some(Owner { phone, key });
        Ok(Opened::Owner(plaintext))
    }

    /// Seal a down message for the owning phone.
    fn seal_owner(&self, message: &DownMessage) -> Result<Envelope, EnrollSessionError> {
        match &self.owner {
            Some(owner) => self.seal(&owner.key, &owner.phone, message),
            None => Err(EnrollError::Seal.into()),
        }
    }

    /// Seal a down message for `phone` under `key` and a fresh nonce.
    fn seal(
        &self,
        key: &SessionKey,
        phone: &[u8; PUBLIC_KEY_LEN],
        message: &DownMessage,
    ) -> Result<Envelope, EnrollSessionError> {
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

/// The origin of a URL: scheme, host and port, without a trailing slash.
fn origin(url: &str) -> &str {
    let start = url.find("://").map_or(0, |i| i + 3);
    match url[start..].find(['/', '?', '#']) {
        Some(end) => &url[..start + end],
        None => url,
    }
}

/// The next deadline of a session and the end it means: the connect
/// timeout until a phone joins, then the idle timeout, never past the
/// maximum.
fn deadline(
    started: Instant,
    last_seen: Option<Instant>,
    timeouts: &Timeouts,
) -> (Instant, EnrollEnd) {
    let max = (started + timeouts.max, EnrollEnd::MaxDuration);
    let next = match last_seen {
        None => (started + timeouts.connect, EnrollEnd::ConnectTimeout),
        Some(seen) => (seen + timeouts.idle, EnrollEnd::IdleTimeout),
    };
    if next.0 < max.0 { next } else { max }
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

    #[test]
    fn test_default_page_is_served_by_default_relay() {
        // The hosted page's CSP allows only its own origin (#797).
        assert_eq!(DEFAULT_PAGE, format!("{DEFAULT_RELAY}/enroll/"));
    }

    #[test]
    fn test_hosted_endpoints_flag_then_config_then_default() {
        use bussard_model::schema::EnrollConfig;
        let none = EnrollConfig::default();
        assert_eq!(
            hosted_endpoints(None, None, &none),
            (DEFAULT_RELAY.to_string(), DEFAULT_PAGE.to_string())
        );
        let config = EnrollConfig {
            relay: Some("https://relay.example".to_string()),
            page: Some("https://page.example/enroll/".to_string()),
        };
        assert_eq!(
            hosted_endpoints(None, None, &config),
            (
                "https://relay.example".to_string(),
                "https://page.example/enroll/".to_string()
            )
        );
        assert_eq!(
            hosted_endpoints(Some("https://flag.example".to_string()), None, &config).0,
            "https://flag.example"
        );
    }

    #[test]
    fn test_link_omits_a_relay_on_the_page_origin() -> Result<(), Box<dyn std::error::Error>> {
        let session =
            EnrollSession::from_parts([1; 16], EnrollKeyPair::from_secret([2; 32]), [3; 32]);
        let same = session.link(
            "https://relay.example/enroll/",
            Some("https://relay.example/"),
        );
        assert!(!same.contains("&r="), "{same}");
        let other = session.link(
            "https://page.example/enroll/",
            Some("https://relay.example"),
        );
        assert!(other.ends_with("&r=https%3A%2F%2Frelay.example"), "{other}");
        // A relay under a path of the page's origin is not the origin.
        let path = session.link("https://x.example/enroll/", Some("https://x.example/relay"));
        assert!(path.contains("&r="), "{path}");
        assert_eq!(
            origin("http://127.0.0.1:8123/enroll/#v=2"),
            "http://127.0.0.1:8123"
        );
        assert_eq!(origin("https://relay.example"), "https://relay.example");
        Ok(())
    }

    #[test]
    fn test_endpoint_warnings_only_for_non_defaults() {
        assert!(endpoint_warnings(DEFAULT_RELAY, DEFAULT_PAGE).is_empty());
        assert!(endpoint_warnings("https://bussard-relay.tmbo.dev/", DEFAULT_PAGE).is_empty());
        let warnings = endpoint_warnings("https://relay.example", "https://page.example/enroll/");
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("https://page.example/enroll/"));
        assert!(warnings[1].contains("https://relay.example"));
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn vectors() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../dev/enroll/vectors-v2.json"
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

    /// Records the texts it sees and answers like the vectors' device:
    /// `stored` for a label whose check matches, `invalid` (still naming the
    /// device, as the key store's enrolment does) for the bad-check vector.
    #[derive(Default)]
    struct FakeStore {
        texts: Vec<String>,
    }

    const BAD_CHECK: &str = "AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2XQ";

    impl CertificateSink for FakeStore {
        fn enroll(&mut self, text: &str) -> CertificateOutcome {
            self.texts.push(text.to_string());
            let invalid = text == BAD_CHECK;
            CertificateOutcome {
                status: if invalid {
                    EnrollStatus::Invalid
                } else {
                    EnrollStatus::Stored
                },
                serial: Some("00FA01020304".to_string()),
                ia: Some("1.1.20".to_string()),
                name: Some("Test actuator".to_string()),
                message: invalid.then(|| {
                    "the label's check does not match; re-check the text (nothing was written)"
                        .to_string()
                }),
            }
        }
    }

    /// Opens a down envelope with `phone`'s key; returns the plaintext.
    fn open_down(
        session: &EnrollSession,
        phone: &EnrollKeyPair,
        envelope: &Envelope,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let key = phone.phone_key(&session.sid, &session.keys.public())?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&envelope.n).ok_or("nonce")?;
        let opened = key.open(
            Direction::Down,
            &session.sid,
            &nonce,
            &URL_SAFE_NO_PAD.decode(&envelope.c)?,
        )?;
        Ok(std::str::from_utf8(&opened)?.to_string())
    }

    #[test]
    fn test_session_link_and_fingerprint_match_vectors() -> TestResult {
        let v = vectors()?;
        let (session, _) = vector_session(&v)?;
        assert_eq!(session.session_id(), str_of(&v["session"], "session_id")?);
        assert_eq!(
            session.fingerprint(),
            str_of(&v["session"], "session_code")?
        );
        // The hosted page lives on the relay's origin: no `r`.
        assert_eq!(
            session.link(
                "https://bussard-relay.tmbo.dev/enroll/",
                Some("https://bussard-relay.tmbo.dev")
            ),
            str_of(&v["session"], "link")?
        );
        assert_eq!(
            session.link(
                "https://page.example/enroll/",
                Some("https://relay.example")
            ),
            str_of(&v["session"], "link_other_relay")?
        );
        Ok(())
    }

    #[test]
    fn test_handle_vector_certificate_and_done() -> TestResult {
        let v = vectors()?;
        let (mut session, phone) = vector_session(&v)?;
        let messages = v["messages"].as_array().ok_or("messages")?;
        let mut store = FakeStore::default();

        assert!(matches!(
            session.handle(&envelope(&messages[0]["envelope"])?, &mut store)?,
            Handled::Hello
        ));
        let Handled::Certificate { reply, outcome } =
            session.handle(&envelope(&messages[1]["envelope"])?, &mut store)?
        else {
            return Err("the vector certificate was not handled".into());
        };
        assert_eq!(store.texts, ["AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2XR"]);
        assert_eq!(outcome.status, EnrollStatus::Stored);
        assert_eq!(session.stored(), 1);

        // The reply opens on the phone to exactly the vector's plaintext.
        assert_eq!(
            open_down(&session, &phone, &reply)?,
            str_of(&messages[2], "plaintext")?
        );
        assert_eq!(reply.pk, str_of(&messages[2]["envelope"], "pk")?);

        // F7: the invalid result names no device, though the sink did.
        let Handled::Certificate { reply, outcome } =
            session.handle(&envelope(&messages[3]["envelope"])?, &mut store)?
        else {
            return Err("the bad-check certificate was not handled".into());
        };
        assert_eq!(outcome.status, EnrollStatus::Invalid);
        assert_eq!(
            open_down(&session, &phone, &reply)?,
            str_of(&messages[4], "plaintext")?
        );

        assert!(matches!(
            session.handle(&envelope(&messages[5]["envelope"])?, &mut store)?,
            Handled::Done
        ));
        let closed = session.closing(CloseReason::Done)?.ok_or("no closed")?;
        assert_eq!(
            open_down(&session, &phone, &closed)?,
            str_of(&messages[6], "plaintext")?
        );
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
            session.handle(&envelope(&v["messages"][1]["envelope"])?, &mut sink)?
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
            str_of(&v["messages"][2], "plaintext")?
        );
        let parsed: DownMessage = serde_json::from_str(str_of(&v["messages"][2], "plaintext")?)?;
        assert_eq!(parsed, message);
        assert_eq!(
            encode_down(&DownMessage::Closed {
                stored: 1,
                reason: CloseReason::Done
            }),
            str_of(&v["messages"][6], "plaintext")?
        );
        assert_eq!(
            encode_down(&DownMessage::Refused),
            str_of(&v["other_phone"]["messages"][1], "plaintext")?
        );
        assert_eq!(
            encode_down(&DownMessage::Closed {
                stored: 0,
                reason: CloseReason::IdleTimeout
            }),
            r#"{"type":"closed","stored":0,"reason":"idle_timeout"}"#
        );
        Ok(())
    }

    #[test]
    fn test_handle_ignores_tampered_and_foreign_envelopes() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let mut store = FakeStore::default();
        let mut tampered = envelope(&v["messages"][1]["envelope"])?;
        tampered.c.replace_range(0..1, "J");
        assert!(matches!(
            session.handle(&tampered, &mut store)?,
            Handled::Ignored(_)
        ));
        // A down envelope posted up does not open (the direction is in the AAD).
        let down = envelope(&v["messages"][2]["envelope"])?;
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
        assert!(session.owner.is_none(), "a failed message joined a phone");
        Ok(())
    }

    #[test]
    fn test_handle_refuses_second_phone() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let other = EnrollKeyPair::from_secret(hex32(str_of(&v["other_phone"], "phone_secret")?)?);
        let mut store = FakeStore::default();
        let messages = v["messages"].as_array().ok_or("messages")?;
        let other_hello = envelope(&v["other_phone"]["messages"][0]["envelope"])?;

        // The vector phone joins first and owns the session.
        assert!(matches!(
            session.handle(&envelope(&messages[0]["envelope"])?, &mut store)?,
            Handled::Hello
        ));
        // The other phone is refused once, with a `refused` it can open.
        let Handled::Refused {
            reply: Some(reply),
            first: true,
        } = session.handle(&other_hello, &mut store)?
        else {
            return Err("the second phone was not refused".into());
        };
        assert_eq!(
            open_down(&session, &other, &reply)?,
            str_of(&v["other_phone"]["messages"][1], "plaintext")?
        );
        assert_eq!(reply.pk, other_hello.pk);
        // Again: refused, no second answer.
        assert!(matches!(
            session.handle(&other_hello, &mut store)?,
            Handled::Refused {
                reply: None,
                first: false
            }
        ));
        // Its certificate and its done are not processed.
        let key = other.phone_key(&session.sid, &session.keys.public())?;
        for plaintext in [
            r#"{"type":"certificate","id":1,"text":"AD5ACAQDASQKDIVDUSS2NJ5IVGVKXLFNV2XR"}"#,
            r#"{"type":"done"}"#,
        ] {
            let (nonce, sealed) =
                key.seal_random(Direction::Up, &session.sid, plaintext.as_bytes())?;
            let forged = Envelope {
                v: VERSION,
                pk: other_hello.pk.clone(),
                n: URL_SAFE_NO_PAD.encode(nonce),
                c: URL_SAFE_NO_PAD.encode(sealed),
            };
            assert!(matches!(
                session.handle(&forged, &mut store)?,
                Handled::Refused { reply: None, .. }
            ));
        }
        assert!(store.texts.is_empty());
        assert_eq!(session.refused_phones(), 1);
        // The owner still works.
        assert!(matches!(
            session.handle(&envelope(&messages[1]["envelope"])?, &mut store)?,
            Handled::Certificate { .. }
        ));
        Ok(())
    }

    #[test]
    fn test_handle_answers_at_most_sixteen_refused_phones() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let mut store = FakeStore::default();
        session.handle(&envelope(&v["messages"][0]["envelope"])?, &mut store)?;
        let mut answered = 0;
        for i in 0..20u8 {
            let phone = EnrollKeyPair::from_secret([i + 1; 32]);
            let key = phone.phone_key(&session.sid, &session.keys.public())?;
            let (nonce, sealed) = key.seal_random(Direction::Up, &session.sid, b"{}")?;
            let env = Envelope {
                v: VERSION,
                pk: URL_SAFE_NO_PAD.encode(phone.public()),
                n: URL_SAFE_NO_PAD.encode(nonce),
                c: URL_SAFE_NO_PAD.encode(sealed),
            };
            if let Handled::Refused {
                reply: Some(_),
                first: true,
            } = session.handle(&env, &mut store)?
            {
                answered += 1;
            }
        }
        assert_eq!(answered, MAX_REFUSED_ANSWERS);
        assert_eq!(session.refused_phones(), 20);
        Ok(())
    }

    #[test]
    fn test_deadline_connect_then_idle_never_past_max() {
        let t = Timeouts {
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(15),
            max: Duration::from_secs(100),
        };
        let start = Instant::now();
        assert_eq!(
            deadline(start, None, &t),
            (start + t.connect, EnrollEnd::ConnectTimeout)
        );
        let seen = start + Duration::from_secs(50);
        assert_eq!(
            deadline(start, Some(seen), &t),
            (seen + t.idle, EnrollEnd::IdleTimeout)
        );
        let late = start + Duration::from_secs(90);
        assert_eq!(
            deadline(start, Some(late), &t),
            (start + t.max, EnrollEnd::MaxDuration)
        );
    }

    /// An in-memory relay: `up` is a fixed queue released one per poll.
    struct FakeRelay {
        up: std::sync::Mutex<Vec<Envelope>>,
        down: std::sync::Mutex<Vec<Envelope>>,
        deleted: AtomicBool,
    }

    impl FakeRelay {
        fn new(up: Vec<Envelope>) -> Self {
            FakeRelay {
                up: std::sync::Mutex::new(up),
                down: std::sync::Mutex::default(),
                deleted: AtomicBool::new(false),
            }
        }
    }

    impl Relay for FakeRelay {
        fn create(&self) -> Result<(), RelayError> {
            Ok(())
        }

        fn poll_up(&self, after: u64, _wait_secs: u64) -> Result<RelayPoll, RelayError> {
            std::thread::sleep(Duration::from_millis(20));
            let up = self.up.lock().map_err(|_| RelayError::NotFound)?;
            let next = usize::try_from(after).map_err(|_| RelayError::NotFound)?;
            Ok(RelayPoll {
                messages: up
                    .get(next)
                    .map(|envelope| RelayMessage {
                        seq: after + 1,
                        envelope: Some(envelope.clone()),
                    })
                    .into_iter()
                    .collect(),
                closed: false,
            })
        }

        fn post_down(&self, envelope: &Envelope) -> Result<u64, RelayError> {
            let mut down = self.down.lock().map_err(|_| RelayError::NotFound)?;
            down.push(envelope.clone());
            Ok(down.len() as u64)
        }

        fn delete(&self) -> Result<(), RelayError> {
            self.deleted.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn short(connect_ms: u64, idle_ms: u64, max_ms: u64) -> RunOptions {
        RunOptions {
            wait_secs: 1,
            timeouts: Timeouts {
                connect: Duration::from_millis(connect_ms),
                idle: Duration::from_millis(idle_ms),
                max: Duration::from_millis(max_ms),
            },
        }
    }

    fn run_fake(
        session: &mut EnrollSession,
        relay: &FakeRelay,
        options: RunOptions,
    ) -> Result<(EnrollSummary, Vec<EnrollEvent>), EnrollSessionError> {
        let mut events = Vec::new();
        let summary = session.run(
            relay,
            &mut FakeStore::default(),
            options,
            &AtomicBool::new(false),
            &mut |e| events.push(e),
        )?;
        Ok((summary, events))
    }

    #[test]
    fn test_run_connect_timeout_without_a_phone() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let relay = FakeRelay::new(Vec::new());
        let (summary, events) = run_fake(&mut session, &relay, short(200, 5_000, 10_000))?;
        assert_eq!(summary.end, EnrollEnd::ConnectTimeout);
        assert!(events.is_empty());
        // No phone, no closed message; the session is deleted.
        assert!(relay.down.lock().map_err(|_| "lock")?.is_empty());
        assert!(relay.deleted.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn test_run_idle_timeout_after_hello_closes_the_phone() -> TestResult {
        let v = vectors()?;
        let (mut session, phone) = vector_session(&v)?;
        let relay = FakeRelay::new(vec![envelope(&v["messages"][0]["envelope"])?]);
        let (summary, events) = run_fake(&mut session, &relay, short(5_000, 200, 10_000))?;
        assert_eq!(summary.end, EnrollEnd::IdleTimeout);
        assert_eq!(events, [EnrollEvent::PhoneJoined]);
        let down = relay.down.lock().map_err(|_| "lock")?;
        assert_eq!(down.len(), 1);
        assert_eq!(
            open_down(&session, &phone, &down[0])?,
            r#"{"type":"closed","stored":0,"reason":"idle_timeout"}"#
        );
        Ok(())
    }

    #[test]
    fn test_run_max_duration_despite_activity() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        // A hello every poll keeps the idle timer fresh.
        let hello = envelope(&v["messages"][0]["envelope"])?;
        let relay = FakeRelay::new(vec![hello; 200]);
        let started = Instant::now();
        let (summary, _) = run_fake(&mut session, &relay, short(5_000, 300, 600))?;
        assert_eq!(summary.end, EnrollEnd::MaxDuration);
        assert!(started.elapsed() < Duration::from_secs(3));
        Ok(())
    }

    #[test]
    fn test_run_reports_a_refused_phone_and_keeps_going() -> TestResult {
        let v = vectors()?;
        let (mut session, _) = vector_session(&v)?;
        let m = &v["messages"];
        let relay = FakeRelay::new(vec![
            envelope(&m[0]["envelope"])?,
            envelope(&v["other_phone"]["messages"][0]["envelope"])?,
            envelope(&m[1]["envelope"])?,
            envelope(&m[5]["envelope"])?,
        ]);
        let (summary, events) = run_fake(&mut session, &relay, short(5_000, 5_000, 10_000))?;
        assert_eq!(summary.end, EnrollEnd::PhoneDone);
        assert_eq!(summary.refused_phones, 1);
        assert_eq!(summary.stored, 1);
        assert_eq!(events[0], EnrollEvent::PhoneJoined);
        assert_eq!(events[1], EnrollEvent::PhoneRefused { phones: 1 });
        // refused, result, closed.
        assert_eq!(relay.down.lock().map_err(|_| "lock")?.len(), 3);
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
