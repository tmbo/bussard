//! The session crypto of the certificate enrolment protocol v1 (issue #729).
//!
//! The contract is `dev/enroll-protocol.md`; `dev/enroll/vectors-v1.json`
//! holds the vectors the tests below reproduce byte for byte. bussard and the
//! phone page each hold an X25519 key pair; the session key is
//!
//! ```text
//! HKDF-SHA256(salt = sid, ikm = X25519 shared secret,
//!             info = "bussard-enroll-v1" || b_pk || p_pk, L = 32)
//! ```
//!
//! and every message is AES-256-GCM sealed under it with the AAD
//! `bussard-enroll-v1/<up|down>/<sid base64url>`.
//!
//! # Key hygiene
//!
//! [`EnrollKeyPair`] and [`SessionKey`] zeroize on drop, have a redacted
//! `Debug` and no accessor for their bytes outside this module. Decrypted
//! plaintext comes back as [`Zeroizing`] because it carries the certificate
//! text, which holds the device's FDSK.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// The protocol label: the HKDF `info` prefix and the AAD prefix.
pub const PROTOCOL: &str = "bussard-enroll-v1";
/// The protocol version carried in the link (`v=1`) and every envelope.
pub const VERSION: u8 = 1;
/// Length of the session id `sid` in bytes.
pub const SESSION_ID_LEN: usize = 16;
/// Length of an X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// The prefix hashed before `b_pk` to form the fingerprint.
const FINGERPRINT_LABEL: &[u8] = b"bussard-enroll-v1 fingerprint";

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
    /// The operating system's random source failed.
    #[error("the OS random source failed: {0}")]
    Random(String),
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

/// An X25519 key pair of one side of a session: bussard's one-time pair
/// `(b_sk, b_pk)` or a phone page's `(p_sk, p_pk)`.
pub struct EnrollKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for EnrollKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollKeyPair")
            .field("public", &URL_SAFE_NO_PAD.encode(self.public.as_bytes()))
            .finish_non_exhaustive()
    }
}

impl EnrollKeyPair {
    /// A fresh key pair from the OS random source.
    ///
    /// # Errors
    ///
    /// [`EnrollError::Random`] when the random source fails.
    pub fn generate() -> Result<Self, EnrollError> {
        let mut bytes = random::<32>()?;
        let pair = Self::from_secret(bytes);
        bytes.zeroize();
        Ok(pair)
    }

    /// The key pair whose secret scalar is `secret` (the test vectors and a
    /// test's fake phone; production code calls [`EnrollKeyPair::generate`]).
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key.
    #[must_use]
    pub fn public(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public.to_bytes()
    }

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
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
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
    /// [`EnrollError::Random`] or [`EnrollError::Seal`].
    pub fn seal_random(
        &self,
        direction: Direction,
        sid: &[u8; SESSION_ID_LEN],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), EnrollError> {
        let nonce = random::<NONCE_LEN>()?;
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

/// The fingerprint both sides show: the first 4 bytes of
/// `SHA-256("bussard-enroll-v1 fingerprint" || b_pk)` as `XXXX-XXXX`.
#[must_use]
pub fn fingerprint(bussard_pk: &[u8; PUBLIC_KEY_LEN]) -> String {
    let digest = Sha256::new()
        .chain_update(FINGERPRINT_LABEL)
        .chain_update(bussard_pk)
        .finalize();
    format!(
        "{:02X}{:02X}-{:02X}{:02X}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// The enrolment link: `<page>#v=1&s=<sid>&k=<b_pk>&r=<relay>`, with `r`
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

/// `N` bytes from the OS random source (a session id, an owner token).
///
/// # Errors
///
/// [`EnrollError::Random`] when the random source fails.
pub fn random<const N: usize>() -> Result<[u8; N], EnrollError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| EnrollError::Random(e.to_string()))?;
    Ok(out)
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
            "/../../dev/enroll/vectors-v1.json"
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
        bussard: EnrollKeyPair,
        phone: EnrollKeyPair,
        sid: [u8; SESSION_ID_LEN],
    }

    fn session(v: &serde_json::Value) -> Result<Session, Box<dyn std::error::Error>> {
        let s = &v["session"];
        Ok(Session {
            bussard: EnrollKeyPair::from_secret(hex(field(s, "bussard_secret")?)?),
            phone: EnrollKeyPair::from_secret(hex(field(s, "phone_secret")?)?),
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

        assert_eq!(fingerprint(&b_pk), field(s, "fingerprint")?);
        let relay = "https://relay.example";
        assert_eq!(
            link(
                "https://bussard.tmbo.dev/enroll/",
                &session.sid,
                &b_pk,
                Some(relay)
            ),
            field(s, "link")?
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
        let messages = v["messages"].as_array().ok_or("messages")?;
        assert_eq!(messages.len(), 3);
        for m in messages {
            let direction = match field(m, "direction")? {
                "up" => Direction::Up,
                "down" => Direction::Down,
                other => return Err(format!("direction {other}").into()),
            };
            assert_eq!(aad(direction, &session.sid), field(m, "aad")?);
            let env = &m["envelope"];
            assert_eq!(env["v"].as_u64(), Some(u64::from(VERSION)));
            assert_eq!(
                field(env, "pk")?,
                URL_SAFE_NO_PAD.encode(session.phone.public())
            );
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
        let pair = EnrollKeyPair::generate()?;
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
        assert!(link.starts_with("http://127.0.0.1:1/enroll/#v=1&s="));
    }

    #[test]
    fn test_debug_redacts_keys() -> TestResult {
        let pair = EnrollKeyPair::from_secret([9; 32]);
        let key = pair.bussard_key(&[1; 16], &EnrollKeyPair::generate()?.public())?;
        assert_eq!(format!("{key:?}"), "SessionKey(<redacted>)");
        assert!(!format!("{pair:?}").contains("secret"));
        Ok(())
    }
}
