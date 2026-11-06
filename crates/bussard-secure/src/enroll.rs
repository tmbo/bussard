//! The session crypto of the certificate enrolment protocol v2 (issues #729,
//! #796).
//!
//! The contract is `dev/enroll-protocol.md`; `dev/enroll/vectors-v2.json`
//! holds the vectors the tests below reproduce byte for byte. bussard and the
//! phone page each hold an X25519 key pair; the session key is
//!
//! ```text
//! HKDF-SHA256(salt = sid, ikm = X25519 shared secret,
//!             info = "bussard-enroll-v2" || b_pk || p_pk, L = 32)
//! ```
//!
//! and every message is AES-256-GCM sealed under it with the AAD
//! `bussard-enroll-v2/<up|down>/<sid base64url>`.
//!
//! # Key hygiene
//!
//! [`X25519KeyPair`] and [`SessionKey`] zeroize on drop, have a redacted
//! `Debug` and no accessor for their bytes outside this module. Decrypted
//! plaintext comes back as [`Zeroizing`] because it carries the certificate
//! text, which holds the device's FDSK.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, X25519KeyPair};

/// The protocol label: the HKDF `info` prefix and the AAD prefix.
pub const PROTOCOL: &str = "bussard-enroll-v2";
/// The protocol version carried in the link (`v=2`) and every envelope.
pub const VERSION: u8 = 2;
/// Length of the session id `sid` in bytes.
pub const SESSION_ID_LEN: usize = 16;
/// Length of an X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// The PBKDF2 salt prefix of the session code; `sid` follows it.
const SESSION_CODE_LABEL: &[u8] = b"bussard-enroll-v2 session code";
/// PBKDF2 iterations of the session code: about a second on a mid-range
/// phone (`dev/enroll-protocol.md`, "Session code", has the measurement).
pub const SESSION_CODE_ITERATIONS: u32 = 1_000_000;

/// The direction of an enrolment message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Phone page to bussard.
    Up,
    /// bussard to phone page.
    Down,
}

impl Direction {
    /// The direction's name in the AAD and the relay path (`up`, `down`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Up => "up",
            Direction::Down => "down",
        }
    }
}

/// Errors of the enrolment crypto. None carries key or plaintext bytes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollError {
    /// The OS random source failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The X25519 shared secret was all zero (a low-order peer key).
    #[error("the peer public key is not contributory (all-zero shared secret)")]
    NonContributory,
    /// AES-GCM refused to seal (only possible for an absurd plaintext length).
    #[error("AES-GCM encryption failed")]
    Seal,
    /// The HKDF's HMAC refused its key (unreachable: HMAC takes any length).
    #[error("HKDF key derivation failed")]
    Kdf,
    /// The ciphertext, tag, nonce, AAD or key did not match.
    #[error("the message did not decrypt (wrong key, session, direction or a tampered envelope)")]
    Open,
}

impl X25519KeyPair {
    /// bussard's side: the session key for the phone whose public key is
    /// `phone_pk`, in session `sid`.
    ///
    /// # Errors
    ///
    /// [`EnrollError::NonContributory`] for a low-order `phone_pk`.
    pub fn bussard_key(
        &self,
        sid: &[u8; SESSION_ID_LEN],
        phone_pk: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<SessionKey, EnrollError> {
        let shared = self.shared(phone_pk)?;
        derive_key(&shared, sid, &self.public(), phone_pk)
    }

    /// A phone's side: the session key towards bussard's `bussard_pk` in
    /// session `sid`.
    ///
    /// # Errors
    ///
    /// [`EnrollError::NonContributory`] for a low-order `bussard_pk`.
    pub fn phone_key(
        &self,
        sid: &[u8; SESSION_ID_LEN],
        bussard_pk: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<SessionKey, EnrollError> {
        let shared = self.shared(bussard_pk)?;
        derive_key(&shared, sid, bussard_pk, &self.public())
    }

    /// The X25519 shared secret with `peer`, refusing the all-zero result.
    fn shared(&self, peer: &[u8; PUBLIC_KEY_LEN]) -> Result<Zeroizing<[u8; 32]>, EnrollError> {
        let shared = self.shared_secret(peer);
        if !shared.was_contributory() {
            return Err(EnrollError::NonContributory);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// The AES-256-GCM key of one (session, phone key) pair.
pub struct SessionKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

impl SessionKey {
    /// Seal `plaintext` for `direction` in session `sid` under `nonce`;
    /// returns the ciphertext with the 16-byte tag appended.
    ///
    /// A message needs a fresh random nonce: use [`SessionKey::seal_random`].
    /// This form exists for the vectors.
    ///
    /// # Errors
    ///
    /// [`EnrollError::Seal`] only for a plaintext AES-GCM cannot take.
    pub fn seal(
        &self,
        direction: Direction,
        sid: &[u8; SESSION_ID_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnrollError> {
        let aad = aad(direction, sid);
        self.cipher()
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| EnrollError::Seal)
    }

    /// Seal `plaintext` under a fresh random nonce; returns `(nonce,
    /// ciphertext+tag)`.
    ///
    /// # Errors
    ///
    /// [`EnrollError::Crypto`] or [`EnrollError::Seal`].
    pub fn seal_random(
        &self,
        direction: Direction,
        sid: &[u8; SESSION_ID_LEN],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), EnrollError> {
        let nonce = crate::crypto::random_bytes::<NONCE_LEN>()?;
        let sealed = self.seal(direction, sid, &nonce, plaintext)?;
        Ok((nonce, sealed))
    }

    /// Open a message sealed for `direction` in session `sid`.
    ///
    /// # Errors
    ///
    /// [`EnrollError::Open`] when the key, session, direction, nonce or
    /// ciphertext do not match.
    pub fn open(
        &self,
        direction: Direction,
        sid: &[u8; SESSION_ID_LEN],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnrollError> {
        let aad = aad(direction, sid);
        self.cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| EnrollError::Open)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(self.0.as_ref().into())
    }
}

/// The AAD of a message: `bussard-enroll-v1/<dir>/<sid base64url>`.
#[must_use]
pub fn aad(direction: Direction, sid: &[u8; SESSION_ID_LEN]) -> String {
    format!(
        "{PROTOCOL}/{}/{}",
        direction.as_str(),
        URL_SAFE_NO_PAD.encode(sid)
    )
}

/// The session code both sides show (the fingerprint), `XXXX-XXXX`: 4 bytes
/// of `PBKDF2-HMAC-SHA256(b_pk, "bussard-enroll-v2 session code" || sid,
/// 1 000 000)`. Slow on purpose: it prices a search for a key pair whose code
/// matches (finding F2, #796). Takes a few hundred milliseconds; call it once
/// per session.
#[must_use]
pub fn fingerprint(sid: &[u8; SESSION_ID_LEN], bussard_pk: &[u8; PUBLIC_KEY_LEN]) -> String {
    let mut salt = Vec::with_capacity(SESSION_CODE_LABEL.len() + SESSION_ID_LEN);
    salt.extend_from_slice(SESSION_CODE_LABEL);
    salt.extend_from_slice(sid);
    let mut code = [0u8; 4];
    pbkdf2::pbkdf2_hmac::<Sha256>(bussard_pk, &salt, SESSION_CODE_ITERATIONS, &mut code);
    format!(
        "{:02X}{:02X}-{:02X}{:02X}",
        code[0], code[1], code[2], code[3]
    )
}

/// The enrolment link: `<page>#v=2&s=<sid>&k=<b_pk>&r=<relay>`, with `r`
/// percent-encoded and left out when `relay` is `None` (page and relay on
/// one origin).
#[must_use]
pub fn link(
    page: &str,
    sid: &[u8; SESSION_ID_LEN],
    bussard_pk: &[u8; PUBLIC_KEY_LEN],
    relay: Option<&str>,
) -> String {
    let mut out = format!(
        "{page}#v={VERSION}&s={}&k={}",
        URL_SAFE_NO_PAD.encode(sid),
        URL_SAFE_NO_PAD.encode(bussard_pk)
    );
    if let Some(relay) = relay {
        out.push_str("&r=");
        out.push_str(&percent_encode(relay));
    }
    out
}

/// Percent-encode everything but the RFC 3986 unreserved characters.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// HKDF-SHA256 (RFC 5869) with a 32-byte output: one expand block.
fn derive_key(
    shared: &[u8; 32],
    sid: &[u8; SESSION_ID_LEN],
    bussard_pk: &[u8; PUBLIC_KEY_LEN],
    phone_pk: &[u8; PUBLIC_KEY_LEN],
) -> Result<SessionKey, EnrollError> {
    let prk = hmac_sha256(sid, &[shared])?;
    let okm = hmac_sha256(
        prk.as_ref(),
        &[PROTOCOL.as_bytes(), bussard_pk, phone_pk, &[1]],
    )?;
    Ok(SessionKey(okm))
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, EnrollError> {
    // HMAC takes a key of any length; the error is unreachable in practice.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| EnrollError::Kdf)?;
    for part in parts {
        mac.update(part);
    }
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn vectors() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../dev/enroll/vectors-v2.json"
        );
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    fn field<'a>(v: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
        v[name]
            .as_str()
            .ok_or_else(|| format!("vector field {name}"))
    }

    fn hex<const N: usize>(text: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
        let bytes = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        Ok(<[u8; N]>::try_from(bytes.as_slice())?)
    }

    fn b64<const N: usize>(text: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
        Ok(<[u8; N]>::try_from(
            URL_SAFE_NO_PAD.decode(text)?.as_slice(),
        )?)
    }

    struct Session {
        bussard: X25519KeyPair,
        phone: X25519KeyPair,
        sid: [u8; SESSION_ID_LEN],
    }

    fn session(v: &serde_json::Value) -> Result<Session, Box<dyn std::error::Error>> {
        let s = &v["session"];
        Ok(Session {
            bussard: X25519KeyPair::from_secret(hex(field(s, "bussard_secret")?)?),
            phone: X25519KeyPair::from_secret(hex(field(s, "phone_secret")?)?),
            sid: b64(field(s, "session_id")?)?,
        })
    }

    #[test]
    fn test_session_vectors() -> TestResult {
        let v = vectors()?;
        let s = &v["session"];
        let session = session(&v)?;
        let b_pk = session.bussard.public();
        let p_pk = session.phone.public();
        assert_eq!(URL_SAFE_NO_PAD.encode(b_pk), field(s, "bussard_public")?);
        assert_eq!(URL_SAFE_NO_PAD.encode(p_pk), field(s, "phone_public")?);

        let shared: [u8; 32] = hex(field(s, "shared_secret")?)?;
        assert_eq!(*session.bussard.shared(&p_pk)?, shared);
        assert_eq!(*session.phone.shared(&b_pk)?, shared);

        let key: [u8; 32] = hex(field(s, "key")?)?;
        assert_eq!(*session.bussard.bussard_key(&session.sid, &p_pk)?.0, key);
        assert_eq!(*session.phone.phone_key(&session.sid, &b_pk)?.0, key);

        assert_eq!(
            s["session_code_iterations"].as_u64(),
            Some(u64::from(SESSION_CODE_ITERATIONS))
        );
        assert_eq!(fingerprint(&session.sid, &b_pk), field(s, "session_code")?);
        assert_eq!(
            link(
                "https://bussard-relay.tmbo.dev/enroll/",
                &session.sid,
                &b_pk,
                None
            ),
            field(s, "link")?
        );
        assert_eq!(
            link(
                "https://page.example/enroll/",
                &session.sid,
                &b_pk,
                Some("https://relay.example")
            ),
            field(s, "link_other_relay")?
        );
        Ok(())
    }

    #[test]
    fn test_seal_message_vectors() -> TestResult {
        let v = vectors()?;
        let session = session(&v)?;
        let key = session
            .bussard
            .bussard_key(&session.sid, &session.phone.public())?;
        let other = X25519KeyPair::from_secret(hex(field(&v["other_phone"], "phone_secret")?)?);
        let other_key: [u8; 32] = hex(field(&v["other_phone"], "key")?)?;
        assert_eq!(
            *session
                .bussard
                .bussard_key(&session.sid, &other.public())?
                .0,
            other_key
        );
        let other_key = session.bussard.bussard_key(&session.sid, &other.public())?;
        let own = v["messages"].as_array().ok_or("messages")?;
        let others = v["other_phone"]["messages"].as_array().ok_or("other")?;
        assert_eq!((own.len(), others.len()), (7, 2));
        let all = own
            .iter()
            .map(|m| (m, &key, session.phone.public()))
            .chain(others.iter().map(|m| (m, &other_key, other.public())));
        for (m, key, phone) in all {
            let direction = match field(m, "direction")? {
                "up" => Direction::Up,
                "down" => Direction::Down,
                other => return Err(format!("direction {other}").into()),
            };
            assert_eq!(aad(direction, &session.sid), field(m, "aad")?);
            let env = &m["envelope"];
            assert_eq!(env["v"].as_u64(), Some(u64::from(VERSION)));
            assert_eq!(field(env, "pk")?, URL_SAFE_NO_PAD.encode(phone));
            let nonce: [u8; NONCE_LEN] = b64(field(env, "n")?)?;
            let plaintext = field(m, "plaintext")?;
            let sealed = key.seal(direction, &session.sid, &nonce, plaintext.as_bytes())?;
            assert_eq!(URL_SAFE_NO_PAD.encode(&sealed), field(env, "c")?);
            let opened = key.open(direction, &session.sid, &nonce, &sealed)?;
            assert_eq!(opened.as_slice(), plaintext.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn test_open_rejects_wrong_direction_and_tamper() -> TestResult {
        let v = vectors()?;
        let session = session(&v)?;
        let key = session
            .phone
            .phone_key(&session.sid, &session.bussard.public())?;
        let (nonce, mut sealed) = key.seal_random(Direction::Up, &session.sid, b"{}")?;
        assert_eq!(
            key.open(Direction::Down, &session.sid, &nonce, &sealed)
                .map(|_| ()),
            Err(EnrollError::Open)
        );
        let other_sid = [0u8; SESSION_ID_LEN];
        assert_eq!(
            key.open(Direction::Up, &other_sid, &nonce, &sealed)
                .map(|_| ()),
            Err(EnrollError::Open)
        );
        sealed[0] ^= 1;
        assert_eq!(
            key.open(Direction::Up, &session.sid, &nonce, &sealed)
                .map(|_| ()),
            Err(EnrollError::Open)
        );
        Ok(())
    }

    #[test]
    fn test_bussard_key_rejects_low_order_point() -> TestResult {
        let pair = X25519KeyPair::generate()?;
        let sid = [7u8; SESSION_ID_LEN];
        assert_eq!(
            pair.bussard_key(&sid, &[0u8; PUBLIC_KEY_LEN]).map(|_| ()),
            Err(EnrollError::NonContributory)
        );
        Ok(())
    }

    #[test]
    fn test_link_without_relay_omits_r() {
        let link = link("http://127.0.0.1:1/enroll/", &[0; 16], &[0; 32], None);
        assert!(!link.contains("&r="), "{link}");
        assert!(link.starts_with("http://127.0.0.1:1/enroll/#v=2&s="));
    }

    #[test]
    fn test_debug_redacts_keys() -> TestResult {
        let pair = X25519KeyPair::from_secret([9; 32]);
        let key = pair.bussard_key(&[1; 16], &X25519KeyPair::generate()?.public())?;
        assert_eq!(format!("{key:?}"), "SessionKey(<redacted>)");
        assert!(!format!("{pair:?}").contains("secret"));
        Ok(())
    }
}
