//! The KNXnet/IP Secure **server** side (docs/knx-secure-spec.md §7-§9), an
//! independent implementation for the cross-implementation conformance loop
//! (issue #71 Phase B). No code is shared with bussard.
//!
//! What a real secure interface does, and what this module does:
//!
//! - answer a SESSION_REQUEST (client HPAI + X25519 public key) with a
//!   SESSION_RESPONSE: session id, its own X25519 public key and a MAC under
//!   the device authentication code (CBC-MAC over `header || session id ||
//!   client_pub ^ server_pub`, CTR with `counter_0 = 0^14 FF 00`);
//! - derive the session key `SHA-256(shared)[..16]`;
//! - accept a SESSION_AUTHENTICATE inside a SECURE_WRAPPER when its MAC
//!   verifies under one of its users' password keys, answer SESSION_STATUS
//!   inside a SECURE_WRAPPER;
//! - wrap and unwrap every later frame (`block_0 = seq || serial || tag ||
//!   len`, `counter_0 = seq || serial || tag || FF 00`, additional data =
//!   wrapper header + session id), refusing a MAC mismatch or a replayed
//!   sequence.
//!
//! Synthetic credentials only; nothing here logs a key or a password.

use sha2::{Digest, Sha256};

use super::crypto::{cbc_mac, ct_eq, decrypt_data_ctr, encrypt_data_ctr};

/// SECURE_WRAPPER.
pub const SECURE_WRAPPER: u16 = 0x0950;
/// SESSION_REQUEST.
pub const SESSION_REQUEST: u16 = 0x0951;
/// SESSION_RESPONSE.
pub const SESSION_RESPONSE: u16 = 0x0952;
/// SESSION_AUTHENTICATE.
pub const SESSION_AUTHENTICATE: u16 = 0x0953;
/// SESSION_STATUS.
pub const SESSION_STATUS: u16 = 0x0954;

/// SESSION_STATUS: authentication success.
pub const STATUS_SUCCESS: u8 = 0x00;
/// SESSION_STATUS: authentication failed.
pub const STATUS_AUTH_FAILED: u8 = 0x01;
/// SESSION_STATUS: the session timed out (idle).
pub const STATUS_TIMEOUT: u8 = 0x03;
/// SESSION_STATUS: keepalive.
pub const STATUS_KEEPALIVE: u8 = 0x04;
/// SESSION_STATUS: close.
pub const STATUS_CLOSE: u8 = 0x05;

/// PBKDF2 salt of a user password.
const SALT_USER: &[u8] = b"user-password.1.secure.ip.knx.org";
/// PBKDF2 salt of the device authentication code.
const SALT_DEVICE: &[u8] = b"device-authentication-code.1.secure.ip.knx.org";

/// `counter_0` of the two handshake MACs.
const HANDSHAKE_CTR: [u8; 16] = {
    let mut c = [0u8; 16];
    c[14] = 0xFF;
    c
};

/// PBKDF2-HMAC-SHA256, 65536 rounds, 16 octets, over the Latin-1 password.
fn pbkdf2_16(password: &str, salt: &[u8]) -> [u8; 16] {
    let latin1: Vec<u8> = password
        .chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect();
    let mut out = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha256>(&latin1, salt, 65_536, &mut out);
    out
}

/// The key of a user password.
pub fn user_password_key(password: &str) -> [u8; 16] {
    pbkdf2_16(password, SALT_USER)
}

/// The key of a device authentication code.
pub fn device_authentication_key(code: &str) -> [u8; 16] {
    pbkdf2_16(code, SALT_DEVICE)
}

/// A KNXnet/IP frame: header + body.
fn frame(service: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06, 0x10];
    out.extend_from_slice(&service.to_be_bytes());
    out.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The SESSION_RESPONSE MAC (spec §7.4).
fn response_mac(
    device_key: &[u8; 16],
    session_id: u16,
    client: &[u8; 32],
    server: &[u8; 32],
) -> Vec<u8> {
    // Header of the 56-octet SESSION_RESPONSE.
    let mut ad = vec![0x06, 0x10, 0x09, 0x52, 0x00, 0x38];
    ad.extend_from_slice(&session_id.to_be_bytes());
    ad.extend(client.iter().zip(server.iter()).map(|(a, b)| a ^ b));
    let tag = cbc_mac(device_key, &ad, &[], &[0u8; 16]);
    encrypt_data_ctr(device_key, &HANDSHAKE_CTR, &tag, &[]).1
}

/// The SESSION_AUTHENTICATE MAC (spec §7.5).
fn authenticate_mac(
    user_key: &[u8; 16],
    user_id: u8,
    client: &[u8; 32],
    server: &[u8; 32],
) -> Vec<u8> {
    // Header of the 24-octet SESSION_AUTHENTICATE, reserved octet, user id.
    let mut ad = vec![0x06, 0x10, 0x09, 0x53, 0x00, 0x18, 0x00, user_id];
    ad.extend(client.iter().zip(server.iter()).map(|(a, b)| a ^ b));
    let tag = cbc_mac(user_key, &ad, &[], &[0u8; 16]);
    encrypt_data_ctr(user_key, &HANDSHAKE_CTR, &tag, &[]).1
}

/// The server half of one session handshake.
pub struct Handshake {
    /// The session id this server assigned.
    pub session_id: u16,
    client_public: [u8; 32],
    server_public: [u8; 32],
    session_key: [u8; 16],
}

/// Why a secure frame was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpSecureRefusal {
    /// Too short for its layout.
    #[error("secure frame too short")]
    Short,
    /// The MAC did not verify.
    #[error("MAC mismatch")]
    BadMac,
    /// The wrapper's session id is not this session's.
    #[error("wrong secure session id")]
    WrongSession,
    /// A replayed or reordered sequence number.
    #[error("replayed sequence {0}")]
    Replay(u64),
    /// No configured user matched the authenticate MAC.
    #[error("no user matched")]
    NoUser,
    /// Randomness unavailable.
    #[error("no randomness")]
    Random,
}

impl Handshake {
    /// Answers a SESSION_REQUEST body (HPAI(8) + client public key(32)) and
    /// returns the handshake state plus the SESSION_RESPONSE frame.
    pub fn respond(
        request_body: &[u8],
        session_id: u16,
        device_auth_key: &[u8; 16],
    ) -> Result<(Handshake, Vec<u8>), IpSecureRefusal> {
        let key_bytes = request_body.get(8..40).ok_or(IpSecureRefusal::Short)?;
        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(key_bytes);
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|_| IpSecureRefusal::Random)?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let server_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(client_public));
        let digest = Sha256::digest(shared.as_bytes());
        let mut session_key = [0u8; 16];
        session_key.copy_from_slice(&digest[..16]);

        let mac = response_mac(device_auth_key, session_id, &client_public, &server_public);

        let mut body = session_id.to_be_bytes().to_vec();
        body.extend_from_slice(&server_public);
        body.extend_from_slice(&mac);
        Ok((
            Handshake {
                session_id,
                client_public,
                server_public,
                session_key,
            },
            frame(SESSION_RESPONSE, &body),
        ))
    }

    /// Checks a plain SESSION_AUTHENTICATE frame against `users` (id, password
    /// key) and returns the matching user id.
    pub fn authenticate(
        &self,
        authenticate_frame: &[u8],
        users: &[(u8, [u8; 16])],
    ) -> Result<u8, IpSecureRefusal> {
        if authenticate_frame.len() < 24
            || u16::from_be_bytes([authenticate_frame[2], authenticate_frame[3]])
                != SESSION_AUTHENTICATE
        {
            return Err(IpSecureRefusal::Short);
        }
        let user_id = authenticate_frame[7];
        let mac = &authenticate_frame[8..24];
        for (id, key) in users.iter().filter(|(id, _)| *id == user_id) {
            let expected = authenticate_mac(key, user_id, &self.client_public, &self.server_public);
            if ct_eq(&expected, mac) {
                return Ok(*id);
            }
        }
        Err(IpSecureRefusal::NoUser)
    }

    /// The session keyed by this handshake, with the server's serial.
    pub fn session(&self, serial: [u8; 6]) -> SecureSession {
        SecureSession {
            key: self.session_key,
            session_id: self.session_id,
            serial,
            next_tx: 0,
            next_rx: 0,
        }
    }
}

/// An established secure session (server side).
pub struct SecureSession {
    key: [u8; 16],
    session_id: u16,
    serial: [u8; 6],
    next_tx: u64,
    next_rx: u64,
}

/// `seq(6) || serial(6) || tag(2)`.
fn nonce_prefix(seq: u64, serial: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut out = seq.to_be_bytes()[2..].to_vec();
    out.extend_from_slice(serial);
    out.extend_from_slice(tag);
    out
}

impl SecureSession {
    /// Wraps a plain KNXnet/IP frame.
    pub fn seal(&mut self, inner: &[u8]) -> Vec<u8> {
        let total = (6 + 16 + inner.len() + 16) as u16;
        let mut head = vec![0x06, 0x10];
        head.extend_from_slice(&SECURE_WRAPPER.to_be_bytes());
        head.extend_from_slice(&total.to_be_bytes());
        head.extend_from_slice(&self.session_id.to_be_bytes());
        let prefix = nonce_prefix(self.next_tx, &self.serial, &[0, 0]);
        let mut block_0 = [0u8; 16];
        block_0[..14].copy_from_slice(&prefix);
        block_0[14..].copy_from_slice(&(inner.len() as u16).to_be_bytes());
        let mut counter_0 = [0u8; 16];
        counter_0[..14].copy_from_slice(&prefix);
        counter_0[14] = 0xFF;
        let tag = cbc_mac(&self.key, &head, inner, &block_0);
        let (enc, mac) = encrypt_data_ctr(&self.key, &counter_0, &tag, inner);
        self.next_tx += 1;
        let mut out = head;
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&mac);
        out
    }

    /// Verifies and unwraps a SECURE_WRAPPER frame into the plain inner frame.
    pub fn open(&mut self, wrapper: &[u8]) -> Result<Vec<u8>, IpSecureRefusal> {
        if wrapper.len() < 38 {
            return Err(IpSecureRefusal::Short);
        }
        if u16::from_be_bytes([wrapper[6], wrapper[7]]) != self.session_id {
            return Err(IpSecureRefusal::WrongSession);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes[2..].copy_from_slice(&wrapper[8..14]);
        let seq = u64::from_be_bytes(seq_bytes);
        if seq < self.next_rx {
            return Err(IpSecureRefusal::Replay(seq));
        }
        let prefix = &wrapper[8..22];
        let enc = &wrapper[22..wrapper.len() - 16];
        let enc_mac = &wrapper[wrapper.len() - 16..];
        let mut counter_0 = [0u8; 16];
        counter_0[..14].copy_from_slice(prefix);
        counter_0[14] = 0xFF;
        let (inner, tag_rx) = decrypt_data_ctr(&self.key, &counter_0, enc_mac, enc);
        let mut block_0 = [0u8; 16];
        block_0[..14].copy_from_slice(prefix);
        block_0[14..].copy_from_slice(&(inner.len() as u16).to_be_bytes());
        let tag = cbc_mac(&self.key, &wrapper[..8], &inner, &block_0);
        if !ct_eq(&tag, &tag_rx) {
            return Err(IpSecureRefusal::BadMac);
        }
        self.next_rx = seq + 1;
        Ok(inner)
    }
}

/// A plain SESSION_STATUS frame.
pub fn session_status(status: u8) -> Vec<u8> {
    frame(SESSION_STATUS, &[status, 0x00])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client written from spec §7 against the server above: handshake,
    /// authenticate, wrapped exchange both ways.
    #[test]
    fn test_handshake_authenticate_and_wrap_roundtrip() {
        let device = device_authentication_key("sim-device-auth");
        let user = user_password_key("sim-user-2");
        let client_secret = x25519_dalek::StaticSecret::from([0x42u8; 32]);
        let client_public = x25519_dalek::PublicKey::from(&client_secret).to_bytes();
        let mut request = vec![0x08, 0x02, 0, 0, 0, 0, 0, 0];
        request.extend_from_slice(&client_public);
        let (hs, response) = Handshake::respond(&request, 7, &device).expect("respond");
        assert_eq!(response.len(), 56);

        // Client: check the server MAC with the device key.
        let server_public: [u8; 32] = response[8..40].try_into().expect("32");
        let mut ad = response[..6].to_vec();
        ad.extend_from_slice(&7u16.to_be_bytes());
        ad.extend(
            client_public
                .iter()
                .zip(server_public.iter())
                .map(|(a, b)| a ^ b),
        );
        let tag = cbc_mac(&device, &ad, &[], &[0u8; 16]);
        let (_, mac) = encrypt_data_ctr(&device, &HANDSHAKE_CTR, &tag, &[]);
        assert_eq!(&response[40..56], mac.as_slice());

        // Client: the session key and a SESSION_AUTHENTICATE for user 2.
        let shared = client_secret.diffie_hellman(&x25519_dalek::PublicKey::from(server_public));
        let key: [u8; 16] = Sha256::digest(shared.as_bytes())[..16]
            .try_into()
            .expect("16");
        let mut auth_ad = vec![0x06, 0x10, 0x09, 0x53, 0x00, 0x18, 0x00, 0x02];
        auth_ad.extend(
            client_public
                .iter()
                .zip(server_public.iter())
                .map(|(a, b)| a ^ b),
        );
        let tag = cbc_mac(&user, &auth_ad, &[], &[0u8; 16]);
        let (_, auth_mac) = encrypt_data_ctr(&user, &HANDSHAKE_CTR, &tag, &[]);
        let mut auth = vec![0x06, 0x10, 0x09, 0x53, 0x00, 0x18, 0x00, 0x02];
        auth.extend_from_slice(&auth_mac);
        assert_eq!(hs.authenticate(&auth, &[(2, user)]), Ok(2));
        assert_eq!(
            hs.authenticate(&auth, &[(2, user_password_key("wrong"))]),
            Err(IpSecureRefusal::NoUser)
        );

        // Both directions through one key.
        let mut server = hs.session([0, 0xA6, 0, 0, 0, 1]);
        let mut client = SecureSession {
            key,
            session_id: 7,
            serial: [0, 0xFA, 1, 2, 3, 4],
            next_tx: 0,
            next_rx: 0,
        };
        let wrapped = client.seal(&auth);
        assert_eq!(server.open(&wrapped), Ok(auth.clone()));
        assert_eq!(server.open(&wrapped), Err(IpSecureRefusal::Replay(0)));
        let status = server.seal(&session_status(STATUS_SUCCESS));
        assert_eq!(client.open(&status), Ok(session_status(STATUS_SUCCESS)));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The vectors a third implementation (Python `cryptography`, script in
    /// docs/knx-secure-spec.md §12.1) produced; bussard asserts the same ones.
    #[test]
    fn test_matches_the_reference_vectors() {
        let client = [0x11u8; 32];
        let server = [0x22u8; 32];
        assert_eq!(
            response_mac(&[0x01; 16], 1, &client, &server),
            hex("3651034f87ba7fdad9675c2db8a9e52c")
        );
        assert_eq!(
            authenticate_mac(&[0x02; 16], 2, &client, &server),
            hex("a2a7bc462ef36fb1d8a6df0df38f20a1")
        );
        let mut session = SecureSession {
            key: [0x03; 16],
            session_id: 1,
            serial: [0x00, 0xFA, 1, 2, 3, 4],
            next_tx: 0,
            next_rx: 0,
        };
        assert_eq!(
            session.seal(&session_status(STATUS_SUCCESS)),
            hex(concat!(
                "06100950002e000100000000000000fa010203040000",
                "ebb209450bfa0d24f46fc31ebbe5f744fe21ea882aea3d19"
            ))
        );
    }
}
