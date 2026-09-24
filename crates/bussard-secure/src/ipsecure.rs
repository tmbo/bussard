//! KNXnet/IP Secure: the session handshake and the SECURE_WRAPPER codec
//! (issue #71 Phase B, spec §7-§9).
//!
//! Pure and I/O-free: the transport owns the TCP stream and calls in here to
//! build and check every secure frame. The layout was reimplemented from the
//! public KNX specification (03_08_03 "KNXnet/IP Secure") and the MIT XKNX
//! reference (behaviour only). What the ETS capture of a Jung IP interface
//! confirmed (`ipsecure-1-1-200.pcapng`, issue #90 S4.1) is noted per item:
//!
//! - SESSION_REQUEST body = TCP route-back HPAI (`08 02 00000000 0000`) + the
//!   32-byte client X25519 public key (46 octets on the wire). CONFIRMED.
//! - SESSION_RESPONSE body = secure session id (2) + server public key (32) +
//!   MAC (16), 56 octets on the wire. CONFIRMED layout; the MAC input (§7.4) is
//!   checked by the capture oracle test with the interface's device
//!   authentication code.
//! - SESSION_AUTHENTICATE travels **inside** a SECURE_WRAPPER (24 plain octets,
//!   the first wrapper of each session) and SESSION_STATUS comes back wrapped
//!   too (8 plain octets). CONFIRMED by the wrapper sizes.
//! - The sequence information of each direction starts at 0 and increments by
//!   one per wrapper; the message tag is `0000` for unicast. CONFIRMED.
//! - The client serial number ETS uses is `00 FA` + 4 random octets, new per
//!   session. CONFIRMED; bussard does the same.
//!
//! # Key hygiene
//!
//! The session key and the derived password keys are [`Key16`]s (redacting
//! `Debug`, zeroized on drop). The X25519 private key is an
//! [`x25519_dalek::StaticSecret`], which zeroizes itself on drop.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{BLOCK, CryptoError, cbc_mac, constant_time_eq, encrypt_ctr};
use crate::key::Key16;

/// KNXnet/IP header length.
const HEADER_LEN: usize = 6;

/// SECURE_WRAPPER service type.
pub const SECURE_WRAPPER: u16 = 0x0950;
/// SESSION_REQUEST service type.
pub const SESSION_REQUEST: u16 = 0x0951;
/// SESSION_RESPONSE service type.
pub const SESSION_RESPONSE: u16 = 0x0952;
/// SESSION_AUTHENTICATE service type.
pub const SESSION_AUTHENTICATE: u16 = 0x0953;
/// SESSION_STATUS service type.
pub const SESSION_STATUS: u16 = 0x0954;
/// TIMER_NOTIFY service type (secure routing only; unicast ignores it).
pub const TIMER_NOTIFY: u16 = 0x0955;

/// Length of an X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a KNXnet/IP Secure MAC.
pub const MAC_LEN: usize = 16;
/// Session id + sequence information + serial number + message tag.
pub const SECURITY_INFO_LEN: usize = 16;
/// The smallest SECURE_WRAPPER: header + security information + MAC.
pub const MIN_WRAPPER_LEN: usize = HEADER_LEN + SECURITY_INFO_LEN + MAC_LEN;

/// The largest 48-bit sequence information value.
const MAX_SEQUENCE: u64 = 0xFFFF_FFFF_FFFF;

/// `counter_0` of the handshake MACs (spec §7.4/§7.5).
const COUNTER_0_HANDSHAKE: [u8; BLOCK] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0x00];

/// The KNX Association manufacturer code ETS puts in front of its random client
/// serial number (CONFIRMED from the capture, see the module docs).
pub const CLIENT_SERIAL_PREFIX: [u8; 2] = [0x00, 0xFA];

/// SESSION_STATUS codes (spec §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// The session is authenticated.
    Success,
    /// The user id or password was not accepted.
    AuthenticationFailed,
    /// A frame arrived for a session that is not authenticated.
    Unauthenticated,
    /// The session timed out on the server.
    Timeout,
    /// The session is alive (client keepalive).
    KeepAlive,
    /// The session is being closed.
    Close,
    /// A code this implementation does not know.
    Other(u8),
}

impl SessionStatus {
    /// Decodes a status byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => SessionStatus::Success,
            0x01 => SessionStatus::AuthenticationFailed,
            0x02 => SessionStatus::Unauthenticated,
            0x03 => SessionStatus::Timeout,
            0x04 => SessionStatus::KeepAlive,
            0x05 => SessionStatus::Close,
            other => SessionStatus::Other(other),
        }
    }

    /// The wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            SessionStatus::Success => 0x00,
            SessionStatus::AuthenticationFailed => 0x01,
            SessionStatus::Unauthenticated => 0x02,
            SessionStatus::Timeout => 0x03,
            SessionStatus::KeepAlive => 0x04,
            SessionStatus::Close => 0x05,
            SessionStatus::Other(b) => b,
        }
    }
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Success => f.write_str("STATUS_AUTHENTICATION_SUCCESS"),
            SessionStatus::AuthenticationFailed => f.write_str("STATUS_AUTHENTICATION_FAILED"),
            SessionStatus::Unauthenticated => f.write_str("STATUS_UNAUTHENTICATED"),
            SessionStatus::Timeout => f.write_str("STATUS_TIMEOUT"),
            SessionStatus::KeepAlive => f.write_str("STATUS_KEEPALIVE"),
            SessionStatus::Close => f.write_str("STATUS_CLOSE"),
            SessionStatus::Other(b) => write!(f, "status {b:#04x}"),
        }
    }
}

/// Errors from the KNXnet/IP Secure codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IpSecureError {
    /// A frame was shorter than its fixed layout.
    #[error("KNXnet/IP Secure frame too short: {what} needs {needed} octets, had {had}")]
    Truncated {
        /// What was being decoded.
        what: &'static str,
        /// Octets needed.
        needed: usize,
        /// Octets present.
        had: usize,
    },
    /// The frame is not the expected service.
    #[error("unexpected KNXnet/IP service {found:#06x}, expected {expected:#06x}")]
    WrongService {
        /// The expected service type.
        expected: u16,
        /// The service type found.
        found: u16,
    },
    /// The MAC did not verify: wrong key or a tampered frame.
    #[error("{0}: MAC mismatch")]
    BadMac(&'static str),
    /// A wrapper named a different secure session.
    #[error("SECURE_WRAPPER for session {found:#06x}, this session is {expected:#06x}")]
    WrongSession {
        /// The session id of this session.
        expected: u16,
        /// The session id in the frame.
        found: u16,
    },
    /// A wrapper's sequence information was not newer than the last accepted
    /// one (replay protection, spec §9.2).
    #[error("SECURE_WRAPPER replay: sequence {found} is below the next expected {expected}")]
    Replay {
        /// The lowest sequence still acceptable.
        expected: u64,
        /// The sequence in the frame.
        found: u64,
    },
    /// The send sequence ran out of 48-bit values (never in practice).
    #[error("KNXnet/IP Secure send sequence exhausted")]
    SequenceExhausted,
    /// The operating system's randomness source failed.
    #[error("no randomness for the X25519 key pair: {0}")]
    Random(String),
    /// A crypto primitive rejected its input.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Wraps a service body in a KNXnet/IP header.
fn knxip_frame(service: u16, body: &[u8]) -> Vec<u8> {
    let total = (HEADER_LEN + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&[0x06, 0x10]);
    out.extend_from_slice(&service.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Splits a KNXnet/IP frame into service type and body, checking the header.
fn split_frame<'a>(frame: &'a [u8], what: &'static str) -> Result<(u16, &'a [u8]), IpSecureError> {
    if frame.len() < HEADER_LEN {
        return Err(IpSecureError::Truncated {
            what,
            needed: HEADER_LEN,
            had: frame.len(),
        });
    }
    let service = u16::from_be_bytes([frame[2], frame[3]]);
    let total = usize::from(u16::from_be_bytes([frame[4], frame[5]]));
    if total < HEADER_LEN || total > frame.len() {
        return Err(IpSecureError::Truncated {
            what,
            needed: total.max(HEADER_LEN),
            had: frame.len(),
        });
    }
    Ok((service, &frame[HEADER_LEN..total]))
}

/// An ephemeral X25519 key pair for one SESSION_REQUEST.
pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public: [u8; PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EphemeralKeyPair {
    /// Generates a fresh key pair from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// [`IpSecureError::Random`] when the OS randomness source fails.
    pub fn generate() -> Result<Self, IpSecureError> {
        let mut raw = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::getrandom(raw.as_mut_slice())
            .map_err(|e| IpSecureError::Random(e.to_string()))?;
        Ok(Self::from_secret_bytes(*raw))
    }

    /// A key pair from fixed secret bytes (tests and the simulator's vectors).
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret).to_bytes();
        EphemeralKeyPair { secret, public }
    }

    /// The public key sent in SESSION_REQUEST.
    pub fn public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// The session key: `SHA-256(X25519(secret, peer_public))[..16]` (spec
    /// §7.2).
    pub fn session_key(&self, peer_public: &[u8; PUBLIC_KEY_LEN]) -> Key16 {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        session_key_from_shared(shared.as_bytes())
    }
}

/// `SHA-256(shared)[..16]`, the session key from an ECDH shared secret.
pub fn session_key_from_shared(shared: &[u8; 32]) -> Key16 {
    let digest = Sha256::digest(shared);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    Key16::new(key)
}

/// Random octets from the OS (the client serial number).
///
/// # Errors
///
/// [`IpSecureError::Random`] when the OS randomness source fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], IpSecureError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| IpSecureError::Random(e.to_string()))?;
    Ok(out)
}

/// A client serial number in the ETS form: `00 FA` + 4 random octets.
///
/// # Errors
///
/// [`IpSecureError::Random`] when the OS randomness source fails.
pub fn client_serial() -> Result<[u8; 6], IpSecureError> {
    let tail: [u8; 4] = random_bytes()?;
    Ok([
        CLIENT_SERIAL_PREFIX[0],
        CLIENT_SERIAL_PREFIX[1],
        tail[0],
        tail[1],
        tail[2],
        tail[3],
    ])
}

/// Builds a SESSION_REQUEST frame: `hpai` (8 octets; the TCP route-back HPAI
/// `08 02 00 00 00 00 00 00` over TCP) + the client public key.
pub fn session_request(hpai: &[u8; 8], client_public: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + PUBLIC_KEY_LEN);
    body.extend_from_slice(hpai);
    body.extend_from_slice(client_public);
    knxip_frame(SESSION_REQUEST, &body)
}

/// A parsed SESSION_REQUEST (the server side, used by mocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    /// The client's HPAI.
    pub hpai: [u8; 8],
    /// The client's public key.
    pub client_public: [u8; PUBLIC_KEY_LEN],
}

/// Parses a SESSION_REQUEST frame.
///
/// # Errors
///
/// A short frame or another service.
pub fn parse_session_request(frame: &[u8]) -> Result<SessionRequest, IpSecureError> {
    let (service, body) = split_frame(frame, "SESSION_REQUEST")?;
    if service != SESSION_REQUEST {
        return Err(IpSecureError::WrongService {
            expected: SESSION_REQUEST,
            found: service,
        });
    }
    if body.len() < 8 + PUBLIC_KEY_LEN {
        return Err(IpSecureError::Truncated {
            what: "SESSION_REQUEST",
            needed: 8 + PUBLIC_KEY_LEN,
            had: body.len(),
        });
    }
    let mut hpai = [0u8; 8];
    hpai.copy_from_slice(&body[..8]);
    let mut client_public = [0u8; PUBLIC_KEY_LEN];
    client_public.copy_from_slice(&body[8..8 + PUBLIC_KEY_LEN]);
    Ok(SessionRequest {
        hpai,
        client_public,
    })
}

/// A parsed SESSION_RESPONSE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResponse {
    /// The secure session id the server assigned.
    pub session_id: u16,
    /// The server's public key.
    pub server_public: [u8; PUBLIC_KEY_LEN],
    /// The (encrypted) MAC that proves the server knows the device
    /// authentication code.
    pub mac: [u8; MAC_LEN],
}

/// Parses a SESSION_RESPONSE frame.
///
/// # Errors
///
/// A short frame or another service.
pub fn parse_session_response(frame: &[u8]) -> Result<SessionResponse, IpSecureError> {
    let (service, body) = split_frame(frame, "SESSION_RESPONSE")?;
    if service != SESSION_RESPONSE {
        return Err(IpSecureError::WrongService {
            expected: SESSION_RESPONSE,
            found: service,
        });
    }
    let needed = 2 + PUBLIC_KEY_LEN + MAC_LEN;
    if body.len() < needed {
        return Err(IpSecureError::Truncated {
            what: "SESSION_RESPONSE",
            needed,
            had: body.len(),
        });
    }
    let session_id = u16::from_be_bytes([body[0], body[1]]);
    let mut server_public = [0u8; PUBLIC_KEY_LEN];
    server_public.copy_from_slice(&body[2..2 + PUBLIC_KEY_LEN]);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&body[2 + PUBLIC_KEY_LEN..needed]);
    Ok(SessionResponse {
        session_id,
        server_public,
        mac,
    })
}

/// `client_public XOR server_public`, the handshake MACs' key binding.
fn xor_keys(a: &[u8; PUBLIC_KEY_LEN], b: &[u8; PUBLIC_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let mut out = [0u8; PUBLIC_KEY_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = a[i] ^ b[i];
    }
    out
}

/// The encrypted SESSION_RESPONSE MAC (spec §7.4): CBC-MAC with the device
/// authentication key over `06 10 09 52 00 38 || session id || (client_pub XOR
/// server_pub)`, then CTR-encrypted with the handshake `counter_0`.
///
/// # Errors
///
/// Only a crypto primitive failure (never for these fixed sizes).
pub fn session_response_mac(
    device_auth_key: &Key16,
    session_id: u16,
    client_public: &[u8; PUBLIC_KEY_LEN],
    server_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; MAC_LEN], IpSecureError> {
    let total = (HEADER_LEN + 2 + PUBLIC_KEY_LEN + MAC_LEN) as u16;
    let mut ad = Vec::with_capacity(HEADER_LEN + 2 + PUBLIC_KEY_LEN);
    ad.extend_from_slice(&[0x06, 0x10]);
    ad.extend_from_slice(&SESSION_RESPONSE.to_be_bytes());
    ad.extend_from_slice(&total.to_be_bytes());
    ad.extend_from_slice(&session_id.to_be_bytes());
    ad.extend_from_slice(&xor_keys(client_public, server_public));
    handshake_mac(device_auth_key, &ad)
}

/// CBC-MAC over `ad` with a zero `block_0`, CTR-encrypted with
/// [`COUNTER_0_HANDSHAKE`].
fn handshake_mac(key: &Key16, ad: &[u8]) -> Result<[u8; MAC_LEN], IpSecureError> {
    let mac_cbc = cbc_mac(key, ad, &[], &[0u8; BLOCK])?;
    let (_, enc_mac) = encrypt_ctr(key, &COUNTER_0_HANDSHAKE, &mac_cbc, &[])?;
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&enc_mac);
    Ok(out)
}

/// Checks a SESSION_RESPONSE's MAC against the device authentication key.
///
/// # Errors
///
/// [`IpSecureError::BadMac`] when the server does not know the device
/// authentication code (or the frame was altered).
pub fn verify_session_response(
    response: &SessionResponse,
    device_auth_key: &Key16,
    client_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), IpSecureError> {
    let expected = session_response_mac(
        device_auth_key,
        response.session_id,
        client_public,
        &response.server_public,
    )?;
    if constant_time_eq(&expected, &response.mac) {
        Ok(())
    } else {
        Err(IpSecureError::BadMac("SESSION_RESPONSE"))
    }
}

/// Builds a SESSION_RESPONSE frame (the server side, used by mocks).
///
/// # Errors
///
/// Only a crypto primitive failure.
pub fn session_response(
    device_auth_key: &Key16,
    session_id: u16,
    client_public: &[u8; PUBLIC_KEY_LEN],
    server_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<Vec<u8>, IpSecureError> {
    let mac = session_response_mac(device_auth_key, session_id, client_public, server_public)?;
    let mut body = Vec::with_capacity(2 + PUBLIC_KEY_LEN + MAC_LEN);
    body.extend_from_slice(&session_id.to_be_bytes());
    body.extend_from_slice(server_public);
    body.extend_from_slice(&mac);
    Ok(knxip_frame(SESSION_RESPONSE, &body))
}

/// The encrypted SESSION_AUTHENTICATE MAC (spec §7.5): CBC-MAC with the user
/// password key over `06 10 09 53 00 18 || 00 || user id || (client_pub XOR
/// server_pub)`, CTR-encrypted with the handshake `counter_0`.
///
/// # Errors
///
/// Only a crypto primitive failure.
pub fn authenticate_mac(
    user_key: &Key16,
    user_id: u8,
    client_public: &[u8; PUBLIC_KEY_LEN],
    server_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; MAC_LEN], IpSecureError> {
    let total = (HEADER_LEN + 2 + MAC_LEN) as u16;
    let mut ad = Vec::with_capacity(HEADER_LEN + 2 + PUBLIC_KEY_LEN);
    ad.extend_from_slice(&[0x06, 0x10]);
    ad.extend_from_slice(&SESSION_AUTHENTICATE.to_be_bytes());
    ad.extend_from_slice(&total.to_be_bytes());
    ad.push(0x00);
    ad.push(user_id);
    ad.extend_from_slice(&xor_keys(client_public, server_public));
    handshake_mac(user_key, &ad)
}

/// Builds the plain SESSION_AUTHENTICATE frame (24 octets); it is sent inside
/// a SECURE_WRAPPER.
///
/// # Errors
///
/// Only a crypto primitive failure.
pub fn session_authenticate(
    user_key: &Key16,
    user_id: u8,
    client_public: &[u8; PUBLIC_KEY_LEN],
    server_public: &[u8; PUBLIC_KEY_LEN],
) -> Result<Vec<u8>, IpSecureError> {
    let mac = authenticate_mac(user_key, user_id, client_public, server_public)?;
    let mut body = Vec::with_capacity(2 + MAC_LEN);
    body.push(0x00);
    body.push(user_id);
    body.extend_from_slice(&mac);
    Ok(knxip_frame(SESSION_AUTHENTICATE, &body))
}

/// A parsed SESSION_AUTHENTICATE (the server side, used by mocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticate {
    /// The user id.
    pub user_id: u8,
    /// The encrypted MAC.
    pub mac: [u8; MAC_LEN],
}

/// Parses a plain SESSION_AUTHENTICATE frame.
///
/// # Errors
///
/// A short frame or another service.
pub fn parse_session_authenticate(frame: &[u8]) -> Result<SessionAuthenticate, IpSecureError> {
    let (service, body) = split_frame(frame, "SESSION_AUTHENTICATE")?;
    if service != SESSION_AUTHENTICATE {
        return Err(IpSecureError::WrongService {
            expected: SESSION_AUTHENTICATE,
            found: service,
        });
    }
    if body.len() < 2 + MAC_LEN {
        return Err(IpSecureError::Truncated {
            what: "SESSION_AUTHENTICATE",
            needed: 2 + MAC_LEN,
            had: body.len(),
        });
    }
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&body[2..2 + MAC_LEN]);
    Ok(SessionAuthenticate {
        user_id: body[1],
        mac,
    })
}

/// Builds a plain SESSION_STATUS frame (status + one reserved octet; 8 octets,
/// matching the capture).
pub fn session_status(status: SessionStatus) -> Vec<u8> {
    knxip_frame(SESSION_STATUS, &[status.to_byte(), 0x00])
}

/// Parses a plain SESSION_STATUS frame.
///
/// # Errors
///
/// A short frame or another service.
pub fn parse_session_status(frame: &[u8]) -> Result<SessionStatus, IpSecureError> {
    let (service, body) = split_frame(frame, "SESSION_STATUS")?;
    if service != SESSION_STATUS {
        return Err(IpSecureError::WrongService {
            expected: SESSION_STATUS,
            found: service,
        });
    }
    match body.first() {
        Some(&b) => Ok(SessionStatus::from_byte(b)),
        None => Err(IpSecureError::Truncated {
            what: "SESSION_STATUS",
            needed: 1,
            had: 0,
        }),
    }
}

/// The clear-text fields of a SECURE_WRAPPER (readable without the key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperHeader {
    /// The secure session id.
    pub session_id: u16,
    /// The 48-bit sequence information.
    pub sequence: u64,
    /// The sender's serial number.
    pub serial: [u8; 6],
    /// The message tag.
    pub tag: u16,
    /// Length of the encrypted payload.
    pub payload_len: usize,
}

/// Reads a SECURE_WRAPPER's clear-text header without decrypting.
///
/// # Errors
///
/// A short frame or another service.
pub fn peek_wrapper(frame: &[u8]) -> Result<WrapperHeader, IpSecureError> {
    let (service, body) = split_frame(frame, "SECURE_WRAPPER")?;
    if service != SECURE_WRAPPER {
        return Err(IpSecureError::WrongService {
            expected: SECURE_WRAPPER,
            found: service,
        });
    }
    if body.len() < SECURITY_INFO_LEN + MAC_LEN {
        return Err(IpSecureError::Truncated {
            what: "SECURE_WRAPPER",
            needed: SECURITY_INFO_LEN + MAC_LEN,
            had: body.len(),
        });
    }
    let session_id = u16::from_be_bytes([body[0], body[1]]);
    let mut seq = [0u8; 8];
    seq[2..].copy_from_slice(&body[2..8]);
    let mut serial = [0u8; 6];
    serial.copy_from_slice(&body[8..14]);
    Ok(WrapperHeader {
        session_id,
        sequence: u64::from_be_bytes(seq),
        serial,
        tag: u16::from_be_bytes([body[14], body[15]]),
        payload_len: body.len() - SECURITY_INFO_LEN - MAC_LEN,
    })
}

/// The 16-octet `block_0`/`counter_0` prefix: sequence(6) + serial(6) + tag(2).
fn security_prefix(sequence: u64, serial: &[u8; 6], tag: u16) -> [u8; 14] {
    let mut out = [0u8; 14];
    out[..6].copy_from_slice(&sequence.to_be_bytes()[2..]);
    out[6..12].copy_from_slice(serial);
    out[12..].copy_from_slice(&tag.to_be_bytes());
    out
}

/// Wraps a plain KNXnet/IP frame in a SECURE_WRAPPER (spec §8).
///
/// `block_0 = seq || serial || tag || len(payload)`, `counter_0 = seq || serial
/// || tag || FF 00`, additional data = the wrapper header (6) + session id (2).
///
/// # Errors
///
/// Only a crypto primitive failure.
pub fn wrap(
    session_key: &Key16,
    session_id: u16,
    sequence: u64,
    serial: &[u8; 6],
    tag: u16,
    payload: &[u8],
) -> Result<Vec<u8>, IpSecureError> {
    let total =
        u16::try_from(MIN_WRAPPER_LEN + payload.len()).map_err(|_| IpSecureError::Truncated {
            what: "SECURE_WRAPPER payload (too long)",
            needed: usize::from(u16::MAX),
            had: MIN_WRAPPER_LEN + payload.len(),
        })?;
    let payload_len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut header = Vec::with_capacity(HEADER_LEN + 2);
    header.extend_from_slice(&[0x06, 0x10]);
    header.extend_from_slice(&SECURE_WRAPPER.to_be_bytes());
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&session_id.to_be_bytes());

    let prefix = security_prefix(sequence, serial, tag);
    let mut block_0 = [0u8; BLOCK];
    block_0[..14].copy_from_slice(&prefix);
    block_0[14..].copy_from_slice(&payload_len.to_be_bytes());
    let mut counter_0 = [0u8; BLOCK];
    counter_0[..14].copy_from_slice(&prefix);
    counter_0[14] = 0xFF;
    counter_0[15] = 0x00;

    let mac_cbc = cbc_mac(session_key, &header, payload, &block_0)?;
    let (enc_payload, enc_mac) = encrypt_ctr(session_key, &counter_0, &mac_cbc, payload)?;

    let mut out = header;
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&enc_payload);
    out.extend_from_slice(&enc_mac);
    Ok(out)
}

/// Decrypts and verifies a SECURE_WRAPPER, returning its header and the plain
/// inner KNXnet/IP frame. Does not check the session id or replay; see
/// [`IpSecureSession::open`] for that.
///
/// # Errors
///
/// A short frame, another service, or [`IpSecureError::BadMac`].
pub fn unwrap(
    session_key: &Key16,
    frame: &[u8],
) -> Result<(WrapperHeader, Vec<u8>), IpSecureError> {
    let header = peek_wrapper(frame)?;
    let (_, body) = split_frame(frame, "SECURE_WRAPPER")?;
    let enc_payload = &body[SECURITY_INFO_LEN..body.len() - MAC_LEN];
    let enc_mac = &body[body.len() - MAC_LEN..];

    let prefix = security_prefix(header.sequence, &header.serial, header.tag);
    let mut counter_0 = [0u8; BLOCK];
    counter_0[..14].copy_from_slice(&prefix);
    counter_0[14] = 0xFF;
    let (payload, mac_cbc_rx) = encrypt_ctr(session_key, &counter_0, enc_mac, enc_payload)?;

    let mut block_0 = [0u8; BLOCK];
    block_0[..14].copy_from_slice(&prefix);
    let payload_len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    block_0[14..].copy_from_slice(&payload_len.to_be_bytes());
    let ad = &frame[..HEADER_LEN + 2];
    let mac_cbc = cbc_mac(session_key, ad, &payload, &block_0)?;
    if !constant_time_eq(&mac_cbc, &mac_cbc_rx) {
        return Err(IpSecureError::BadMac("SECURE_WRAPPER"));
    }
    Ok((header, payload))
}

/// One established KNXnet/IP Secure unicast session: the session key and id,
/// our serial number, the send counter and the replay floor.
///
/// Sequence rules (spec §8.3/§9.2, CONFIRMED against the capture): each
/// direction numbers its wrappers from 0, one per frame, so a receiver accepts
/// a wrapper only when its sequence is at least the next expected value.
pub struct IpSecureSession {
    key: Key16,
    session_id: u16,
    serial: [u8; 6],
    tx_seq: u64,
    rx_next: u64,
}

impl std::fmt::Debug for IpSecureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpSecureSession")
            .field("session_id", &self.session_id)
            .field("tx_seq", &self.tx_seq)
            .field("rx_next", &self.rx_next)
            .finish_non_exhaustive()
    }
}

impl IpSecureSession {
    /// A session from the handshake result.
    pub fn new(key: Key16, session_id: u16, serial: [u8; 6]) -> Self {
        IpSecureSession {
            key,
            session_id,
            serial,
            tx_seq: 0,
            rx_next: 0,
        }
    }

    /// The secure session id.
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// The next send sequence.
    pub fn tx_sequence(&self) -> u64 {
        self.tx_seq
    }

    /// Wraps `payload` with the next send sequence (message tag 0).
    ///
    /// # Errors
    ///
    /// [`IpSecureError::SequenceExhausted`] after 2^48 frames, or a crypto
    /// failure.
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, IpSecureError> {
        if self.tx_seq > MAX_SEQUENCE {
            return Err(IpSecureError::SequenceExhausted);
        }
        let out = wrap(
            &self.key,
            self.session_id,
            self.tx_seq,
            &self.serial,
            0,
            payload,
        )?;
        self.tx_seq += 1;
        Ok(out)
    }

    /// Verifies and decrypts an inbound wrapper, enforcing the session id and
    /// the replay floor. Returns the plain inner KNXnet/IP frame.
    ///
    /// # Errors
    ///
    /// Another session, a replayed sequence, or a MAC mismatch. A rejected
    /// frame leaves the replay floor unchanged.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, IpSecureError> {
        let header = peek_wrapper(frame)?;
        if header.session_id != self.session_id {
            return Err(IpSecureError::WrongSession {
                expected: self.session_id,
                found: header.session_id,
            });
        }
        if header.sequence < self.rx_next {
            return Err(IpSecureError::Replay {
                expected: self.rx_next,
                found: header.sequence,
            });
        }
        let (_, payload) = unwrap(&self.key, frame)?;
        self.rx_next = header.sequence.saturating_add(1);
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// RFC 7748 §6.1 test vector: Alice's and Bob's keys and the shared secret.
    #[test]
    fn test_x25519_rfc7748_vector() -> TestResult {
        let alice_secret: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?;
        let bob_secret: [u8; 32] =
            hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")?;
        let alice = EphemeralKeyPair::from_secret_bytes(alice_secret);
        let bob = EphemeralKeyPair::from_secret_bytes(bob_secret);
        let alice_pub: [u8; 32] =
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")?;
        assert_eq!(alice.public(), &alice_pub);
        // Both sides derive the same session key.
        assert_eq!(
            alice.session_key(bob.public()),
            bob.session_key(alice.public())
        );
        // The session key is sha256(shared)[..16] of the RFC shared secret.
        let shared: [u8; 32] =
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")?;
        assert_eq!(
            alice.session_key(bob.public()),
            session_key_from_shared(&shared)
        );
        Ok(())
    }

    /// Independent vectors, computed with Python's `cryptography` package from
    /// spec §7.4/§7.5/§8.2 (a 30-line script, reproduced in docs/knx-secure-spec.md §12.1), so a divergence of
    /// the Rust decomposition shows up here.
    #[test]
    fn test_handshake_macs_match_independent_vectors() -> TestResult {
        let client: [u8; 32] = [0x11; 32];
        let server: [u8; 32] = [0x22; 32];
        let dev = Key16::new([0x01; 16]);
        let user = Key16::new([0x02; 16]);
        let resp_mac = session_response_mac(&dev, 0x0001, &client, &server)?;
        assert_eq!(resp_mac, hex::<16>(RESPONSE_MAC_VECTOR)?);
        let auth_mac = authenticate_mac(&user, 2, &client, &server)?;
        assert_eq!(auth_mac, hex::<16>(AUTH_MAC_VECTOR)?);
        Ok(())
    }

    #[test]
    fn test_wrap_matches_independent_vector() -> TestResult {
        let key = Key16::new([0x03; 16]);
        let inner = session_status(SessionStatus::Success);
        let wrapped = wrap(&key, 0x0001, 0, &[0x00, 0xFA, 1, 2, 3, 4], 0, &inner)?;
        assert_eq!(wrapped.len(), MIN_WRAPPER_LEN + 8);
        assert_eq!(hex_string(&wrapped), WRAPPER_VECTOR);
        Ok(())
    }

    const RESPONSE_MAC_VECTOR: &str = "3651034f87ba7fdad9675c2db8a9e52c";
    const AUTH_MAC_VECTOR: &str = "a2a7bc462ef36fb1d8a6df0df38f20a1";
    const WRAPPER_VECTOR: &str = "06100950002e000100000000000000fa010203040000\
                                  ebb209450bfa0d24f46fc31ebbe5f744fe21ea882aea3d19";

    #[test]
    fn test_session_response_roundtrip_and_verify() -> TestResult {
        let client = EphemeralKeyPair::from_secret_bytes([7; 32]);
        let server = EphemeralKeyPair::from_secret_bytes([9; 32]);
        let dev = Key16::new([0x44; 16]);
        let frame = session_response(&dev, 0x0102, client.public(), server.public())?;
        assert_eq!(frame.len(), 56);
        let parsed = parse_session_response(&frame)?;
        assert_eq!(parsed.session_id, 0x0102);
        verify_session_response(&parsed, &dev, client.public())?;
        let wrong = Key16::new([0x45; 16]);
        assert_eq!(
            verify_session_response(&parsed, &wrong, client.public()),
            Err(IpSecureError::BadMac("SESSION_RESPONSE"))
        );
        Ok(())
    }

    #[test]
    fn test_session_authenticate_layout() -> TestResult {
        let user = Key16::new([0x02; 16]);
        let frame = session_authenticate(&user, 3, &[1; 32], &[2; 32])?;
        assert_eq!(frame.len(), 24);
        assert_eq!(&frame[..6], &[0x06, 0x10, 0x09, 0x53, 0x00, 0x18]);
        let parsed = parse_session_authenticate(&frame)?;
        assert_eq!(parsed.user_id, 3);
        assert_eq!(parsed.mac, authenticate_mac(&user, 3, &[1; 32], &[2; 32])?);
        Ok(())
    }

    #[test]
    fn test_session_request_layout() -> TestResult {
        let hpai = [0x08, 0x02, 0, 0, 0, 0, 0, 0];
        let frame = session_request(&hpai, &[0xAB; 32]);
        assert_eq!(frame.len(), 46);
        assert_eq!(&frame[..6], &[0x06, 0x10, 0x09, 0x51, 0x00, 0x2E]);
        let parsed = parse_session_request(&frame)?;
        assert_eq!(parsed.hpai, hpai);
        assert_eq!(parsed.client_public, [0xAB; 32]);
        Ok(())
    }

    #[test]
    fn test_session_status_roundtrip() -> TestResult {
        for status in [
            SessionStatus::Success,
            SessionStatus::AuthenticationFailed,
            SessionStatus::KeepAlive,
            SessionStatus::Close,
        ] {
            let frame = session_status(status);
            assert_eq!(frame.len(), 8);
            assert_eq!(parse_session_status(&frame)?, status);
        }
        Ok(())
    }

    #[test]
    fn test_session_seal_open_roundtrip_and_replay() -> TestResult {
        let key = Key16::new([0x33; 16]);
        let mut client = IpSecureSession::new(key.clone(), 7, [0, 0xFA, 1, 2, 3, 4]);
        let mut server = IpSecureSession::new(key, 7, [0, 0xA6, 0, 0, 0, 1]);
        let first = client.seal(b"\x06\x10\x02\x07\x00\x10hello world!")?;
        let second = client.seal(b"\x06\x10\x02\x07\x00\x08ab")?;
        assert_eq!(peek_wrapper(&first)?.sequence, 0);
        assert_eq!(peek_wrapper(&second)?.sequence, 1);
        assert_eq!(
            server.open(&first)?,
            b"\x06\x10\x02\x07\x00\x10hello world!"
        );
        assert_eq!(server.open(&second)?, b"\x06\x10\x02\x07\x00\x08ab");
        // Replaying the first frame is refused.
        assert!(matches!(
            server.open(&first),
            Err(IpSecureError::Replay {
                expected: 2,
                found: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn test_open_rejects_tampering_and_wrong_session() -> TestResult {
        let key = Key16::new([0x33; 16]);
        let mut client = IpSecureSession::new(key.clone(), 7, [0; 6]);
        let mut frame = client.seal(b"\x06\x10\x02\x07\x00\x08ab")?;
        let mut server = IpSecureSession::new(key.clone(), 8, [0; 6]);
        assert!(matches!(
            server.open(&frame),
            Err(IpSecureError::WrongSession { .. })
        ));
        let mut server = IpSecureSession::new(key, 7, [0; 6]);
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(
            server.open(&frame),
            Err(IpSecureError::BadMac("SECURE_WRAPPER"))
        );
        // The failed frame did not raise the replay floor.
        let good = client.seal(b"\x06\x10\x02\x07\x00\x08cd")?;
        assert_eq!(server.open(&good)?, b"\x06\x10\x02\x07\x00\x08cd");
        Ok(())
    }

    #[test]
    fn test_client_serial_has_ets_prefix() -> TestResult {
        let serial = client_serial()?;
        assert_eq!(&serial[..2], &CLIENT_SERIAL_PREFIX);
        Ok(())
    }

    fn hex<const N: usize>(s: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if s.len() != 2 * N {
            return Err(format!("hex of {} chars, want {}", s.len(), 2 * N).into());
        }
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
        }
        Ok(out)
    }

    fn hex_string(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
