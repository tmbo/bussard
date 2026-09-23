//! The KNX Data Secure A_SecureData ASDU codec (spec §5).
//!
//! `A_SecureData` (APCI `0x03F1`) wraps an ordinary management APDU behind a
//! Security Control Field, a 6-byte sequence number and a 4-byte MAC, optionally
//! encrypting the inner APDU. The MAC/encryption is the decomposed AES-CCM from
//! [`crate::crypto`] with the TP `block_0`/`counter_0` layouts (§5.4, §5.5).
//!
//! This module is pure and I/O-free. It does not own the tool key, the sequence
//! counter, or the freshness table: those live in the session
//! ([`crate::session`]). Here we only assemble and verify wire bytes for a given
//! `(scf, sequence, key, addresses)`.

use crate::crypto::{self, CryptoError};
use crate::key::Key16;
use crate::sequence::Sequence;

/// The APCI of `A_SecureData` / `S-A_Data` (spec §5.1). Standard extended APCI
/// in the `0x03F…` family; the low byte `0xF1` is what the house captures show.
pub const A_SECURE_DATA: u16 = 0x03F1;

/// The high APCI octet of `A_SecureData` (`0x03`), as it appears in `block_0`
/// (spec §5.4).
pub const APCI_SEC_HIGH: u8 = 0x03;
/// The low APCI octet of `A_SecureData` (`0xF1`).
pub const APCI_SEC_LOW: u8 = 0xF1;

/// The Data-Secure MAC length on TP: 4 bytes, the truncated `mac[..4]`
/// (spec §5.3). CONFIRMED on the tunnel management path (secure-1-1-12 capture,
/// 2026-09-23): every ETS and device frame carries a 4-byte MAC.
pub const TP_MAC_LEN: usize = 4;

/// The CCM security algorithm carried in SCF bits 6-4 (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAlgorithm {
    /// `0b000`: CCM authentication only — the APDU travels in the clear with a
    /// MAC appended (spec §5.6).
    AuthenticationOnly,
    /// `0b001`: CCM authentication + encryption — the APDU and the MAC are both
    /// encrypted (spec §5.6). The default for wrapped management APDUs (§6.2).
    AuthenticationEncryption,
}

impl SecurityAlgorithm {
    /// The 3-bit algorithm code (SCF bits 6-4).
    pub fn code(self) -> u8 {
        match self {
            SecurityAlgorithm::AuthenticationOnly => 0b000,
            SecurityAlgorithm::AuthenticationEncryption => 0b001,
        }
    }

    /// Parses the 3-bit algorithm code, if recognised.
    pub fn from_code(code: u8) -> Option<Self> {
        match code & 0b111 {
            0b000 => Some(SecurityAlgorithm::AuthenticationOnly),
            0b001 => Some(SecurityAlgorithm::AuthenticationEncryption),
            _ => None,
        }
    }

    /// Whether this algorithm encrypts the inner APDU.
    pub fn encrypts(self) -> bool {
        matches!(self, SecurityAlgorithm::AuthenticationEncryption)
    }
}

/// The S-A service selector carried in SCF bits 2-0 (spec §5.2).
///
/// Data = 0, Sync_Req = 2, Sync_Res = 3. CONFIRMED by decrypting the
/// secure-1-1-12 capture (2026-09-23): `0x92` frames carry the serial +
/// challenge request layout, `0x93` frames the two-sequence response, `0x90`
/// frames wrapped management APDUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureService {
    /// S-A_Data (selector `0`): a wrapped data/management APDU.
    Data,
    /// S-A_Sync_Req (selector `2`): a sequence-number sync request (§6.3).
    SyncReq,
    /// S-A_Sync_Res (selector `3`): a sequence-number sync response (§6.3).
    SyncRes,
}

impl SecureService {
    /// The 3-bit service selector (SCF bits 2-0).
    pub fn code(self) -> u8 {
        match self {
            SecureService::Data => 0,
            SecureService::SyncReq => 2,
            SecureService::SyncRes => 3,
        }
    }

    /// Parses the 3-bit service selector, if recognised.
    pub fn from_code(code: u8) -> Option<Self> {
        match code & 0b111 {
            0 => Some(SecureService::Data),
            2 => Some(SecureService::SyncReq),
            3 => Some(SecureService::SyncRes),
            _ => None,
        }
    }
}

/// The Security Control Field (SCF) — one byte (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scf {
    /// Bit 7: tool/management access (uses the tool key).
    pub tool_access: bool,
    /// Bits 6-4: the CCM algorithm.
    pub algorithm: SecurityAlgorithm,
    /// Bit 3: system broadcast.
    pub system_broadcast: bool,
    /// Bits 2-0: the S-A service selector.
    pub service: SecureService,
}

impl Scf {
    /// The SCF byte for a tool-access data frame with the given algorithm — the
    /// Phase A management default (spec §6.2).
    pub fn tool_data(algorithm: SecurityAlgorithm) -> Self {
        Scf {
            tool_access: true,
            algorithm,
            system_broadcast: false,
            service: SecureService::Data,
        }
    }

    /// The SCF byte of a tool-access Sync frame, `0x92` (Sync_Req) or `0x93`
    /// (Sync_Res): authentication + encryption, system-broadcast bit clear.
    /// CONFIRMED (secure-1-1-12 capture, 2026-09-23): ETS and the device use
    /// exactly these two bytes, on the connection-oriented exchange and on the
    /// broadcast one to `0/0/0` alike.
    pub fn tool_sync(service: SecureService) -> Self {
        Scf {
            tool_access: true,
            algorithm: SecurityAlgorithm::AuthenticationEncryption,
            system_broadcast: false,
            service,
        }
    }

    /// Serializes the SCF to its wire byte (spec §5.2).
    pub fn to_byte(self) -> u8 {
        ((self.tool_access as u8) << 7)
            | (self.algorithm.code() << 4)
            | ((self.system_broadcast as u8) << 3)
            | self.service.code()
    }

    /// Parses an SCF wire byte.
    ///
    /// # Errors
    ///
    /// Returns [`AsduError::UnknownScf`] if the algorithm or service bits are not
    /// recognised.
    pub fn from_byte(b: u8) -> Result<Self, AsduError> {
        let algorithm =
            SecurityAlgorithm::from_code((b >> 4) & 0b111).ok_or(AsduError::UnknownScf(b))?;
        let service = SecureService::from_code(b & 0b111).ok_or(AsduError::UnknownScf(b))?;
        Ok(Scf {
            tool_access: (b & 0x80) != 0,
            algorithm,
            system_broadcast: (b & 0x08) != 0,
            service,
        })
    }
}

/// The addressing context needed to build the CCM nonce for a TP frame
/// (spec §5.4, §5.5).
///
/// These are the raw wire values of the frame that will carry the secured APDU:
/// the source and destination address halves, the address-type bit, the extended
/// frame-format nibble, and the TPCI value. Only Ctrl2 is protected, and only as
/// `A000EEEEb` (verbatim XKNX comment, §5.4).
#[derive(Debug, Clone, Copy)]
pub struct TpAddressing {
    /// The source individual address, raw 16-bit.
    pub source: u16,
    /// The destination address, raw 16-bit (individual or group).
    pub destination: u16,
    /// The destination address-type bit (Ctrl2 bit 7): `true` = group.
    pub address_type_group: bool,
    /// The extended frame-format nibble (Ctrl2 bits 3-0), `0` for standard
    /// frames.
    pub extended_frame_format: u8,
    /// The **full TPCI octet** of the carrying frame — octet 6 of the telegram,
    /// e.g. `0x40 | seq << 2` for a numbered data telegram (its low two bits are
    /// the APCI high bits and are ignored here).
    ///
    /// Spec §5.4 writes the nonce octet as `(tpci_int << 2) + 0x03`, where
    /// `tpci_int` is the 6-bit transport-control field; `tpci & 0xFC` is exactly
    /// `tpci_int << 2`, so the octet is reconstructed as
    /// `(tpci & 0xFC) | APCI_SEC_HIGH` whichever form the caller holds.
    pub tpci: u8,
}

impl TpAddressing {
    /// The 4 raw address bytes: `source(2 BE) || destination(2 BE)` (spec §5.4).
    fn address_fields(&self) -> [u8; 4] {
        let s = self.source.to_be_bytes();
        let d = self.destination.to_be_bytes();
        [s[0], s[1], d[0], d[1]]
    }

    /// The Ctrl2-derived byte `A000EEEEb`: address-type bit in bit 7, extended
    /// frame-format nibble in the low 4 bits (spec §5.4).
    fn ctrl2_byte(&self) -> u8 {
        ((self.address_type_group as u8) << 7) | (self.extended_frame_format & 0x0F)
    }
}

/// Builds the CCM `block_0` for a TP frame (spec §5.4).
///
/// ```text
/// block_0 = seq(6) || src(2) || dst(2) || 0x00
///         || ctrl2_byte || (tpci<<2)+0x03 || 0xF1 || 0x00 || payload_len
/// ```
pub fn tp_block_0(seq: Sequence, addr: &TpAddressing, payload_len: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&seq.to_bytes());
    b[6..10].copy_from_slice(&addr.address_fields());
    b[10] = 0x00;
    b[11] = addr.ctrl2_byte();
    // Spec §5.4: `(tpci_int << 2) + 0x03`, i.e. the carrier's octet 6 with its
    // APCI high bits forced to the A_SecureData 0x03. `tpci & 0xFC` is the 6-bit
    // TPCI field back in place — never shift the already-positioned octet again.
    b[12] = (addr.tpci & 0xFC) | APCI_SEC_HIGH;
    b[13] = APCI_SEC_LOW;
    b[14] = 0x00;
    b[15] = payload_len;
    b
}

/// Builds the CCM `counter_0` for a TP frame (spec §5.5).
///
/// ```text
/// counter_0 = seq(6) || src(2) || dst(2) || 00 00 00 00 01 00
/// ```
pub fn tp_counter_0(seq: Sequence, addr: &TpAddressing) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&seq.to_bytes());
    b[6..10].copy_from_slice(&addr.address_fields());
    b[10..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    b
}

/// The wire bytes of a built A_SecureData ASDU: the payload of the `0x03F1`
/// APDU (spec §5.3), laid out `SCF(1) || seq(6) || secured(var) || MAC(4)`.
///
/// This is exactly what [`crate::session`] hands to the transport as the data
/// octets of the `A_SECURE_DATA` APCI.
pub type SecureAsdu = Vec<u8>;

/// CCM-seals `payload` under the TP nonce for `seq` (spec §5.6).
///
/// `ad` is the additional data that precedes the payload in the CBC-MAC (the
/// SCF, plus the serial number for an S-A_Sync_Req). In encrypt mode the payload
/// is encrypted and the `block_0` length octet is its length; in auth-only mode
/// the payload joins the additional data, travels in the clear, and the length
/// octet is 0 (RFC 3610 §2.2: the field counts the encrypted payload only).
///
/// The CBC-MAC is truncated to [`TP_MAC_LEN`] **before** the CTR stage, so the
/// payload keystream starts right after the 4 MAC bytes (see
/// [`crypto::encrypt_ctr`]). Returns `(secured_payload, mac4)`.
fn seal(
    key: &Key16,
    seq: Sequence,
    addr: &TpAddressing,
    ad: &[u8],
    payload: &[u8],
    encrypt: bool,
) -> Result<(Vec<u8>, [u8; TP_MAC_LEN]), AsduError> {
    let counter_0 = tp_counter_0(seq, addr);
    let (secured, enc_mac) = if encrypt {
        let len =
            u8::try_from(payload.len()).map_err(|_| AsduError::PayloadTooLong(payload.len()))?;
        let block_0 = tp_block_0(seq, addr, len);
        let mac_cbc = crypto::cbc_mac(key, ad, payload, &block_0)?;
        crypto::encrypt_ctr(key, &counter_0, &mac_cbc[..TP_MAC_LEN], payload)?
    } else {
        let mut full_ad = Vec::with_capacity(ad.len() + payload.len());
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(payload);
        let block_0 = tp_block_0(seq, addr, 0);
        let mac_cbc = crypto::cbc_mac(key, &full_ad, &[], &block_0)?;
        let (_empty, enc_mac) = crypto::encrypt_ctr(key, &counter_0, &mac_cbc[..TP_MAC_LEN], &[])?;
        (payload.to_vec(), enc_mac)
    };
    let mut mac4 = [0u8; TP_MAC_LEN];
    mac4.copy_from_slice(&enc_mac[..TP_MAC_LEN]);
    Ok((secured, mac4))
}

/// Inverse of [`seal`]: recovers the plaintext payload and checks the MAC in
/// constant time.
///
/// # Errors
///
/// [`AsduError::MacMismatch`] when the recomputed MAC differs.
fn open(
    key: &Key16,
    seq: Sequence,
    addr: &TpAddressing,
    ad: &[u8],
    secured: &[u8],
    received_mac: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, AsduError> {
    let plain = if encrypt {
        let counter_0 = tp_counter_0(seq, addr);
        let (plain, _mac) = crypto::decrypt_ctr(key, &counter_0, received_mac, secured)?;
        plain
    } else {
        secured.to_vec()
    };
    let (_resealed, expected) = seal(key, seq, addr, ad, &plain, encrypt)?;
    if !crypto::constant_time_eq(&expected, received_mac) {
        return Err(AsduError::MacMismatch);
    }
    Ok(plain)
}

/// An ASDU split into `(scf, seq_field, body, mac)`.
type SplitAsdu<'a> = (Scf, [u8; SEQ_LEN], &'a [u8], &'a [u8]);

/// Splits an ASDU into `(scf, seq_field, body, mac)` after the length check.
fn split_asdu(asdu: &[u8]) -> Result<SplitAsdu<'_>, AsduError> {
    // SCF(1) + seq(6) + at least the MAC(4).
    if asdu.len() < 1 + SEQ_LEN + TP_MAC_LEN {
        return Err(AsduError::TooShort(asdu.len()));
    }
    let scf = Scf::from_byte(asdu[0])?;
    let mut seq = [0u8; SEQ_LEN];
    seq.copy_from_slice(&asdu[1..1 + SEQ_LEN]);
    let body = &asdu[1 + SEQ_LEN..asdu.len() - TP_MAC_LEN];
    let mac = &asdu[asdu.len() - TP_MAC_LEN..];
    Ok((scf, seq, body, mac))
}

/// Encodes an A_SecureData ASDU wrapping `inner_apci` + `inner_data` (spec §5.6).
///
/// `inner_apci` is the plain management APCI (e.g. `A_Memory_Write`); it is
/// serialized with its data by [`inner_apdu_bytes`], and that byte string is the
/// "apdu" the CCM authenticates (auth-only) or authenticates and encrypts.
///
/// # Errors
///
/// Propagates [`CryptoError`] from the CCM primitives, or [`AsduError`] if the
/// payload is too long for the length field.
pub fn encode(
    key: &Key16,
    scf: Scf,
    seq: Sequence,
    addr: &TpAddressing,
    inner_apci: u16,
    inner_data: &[u8],
) -> Result<SecureAsdu, AsduError> {
    let apdu = inner_apdu_bytes(inner_apci, inner_data);
    if u8::try_from(apdu.len()).is_err() {
        return Err(AsduError::PayloadTooLong(apdu.len()));
    }
    let scf_byte = scf.to_byte();
    let (secured_apdu, mac4) = seal(key, seq, addr, &[scf_byte], &apdu, scf.algorithm.encrypts())?;

    let mut out = Vec::with_capacity(1 + SEQ_LEN + secured_apdu.len() + TP_MAC_LEN);
    out.push(scf_byte);
    out.extend_from_slice(&seq.to_bytes());
    out.extend_from_slice(&secured_apdu);
    out.extend_from_slice(&mac4);
    Ok(out)
}

/// The decoded inner APDU of a verified A_SecureData ASDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInner {
    /// The SCF that was authenticated.
    pub scf: Scf,
    /// The sequence number carried in the ASDU.
    pub sequence: Sequence,
    /// The recovered inner management APCI.
    pub apci: u16,
    /// The recovered inner data octets.
    pub data: Vec<u8>,
}

/// Decodes and verifies an S-A_Data ASDU, returning the inner APDU
/// (spec §5.6). The MAC is checked constant-time; a mismatch is rejected.
///
/// # Errors
///
/// - [`AsduError::TooShort`] if the ASDU is shorter than `SCF+seq+MAC`.
/// - [`AsduError::UnexpectedService`] if the SCF names a Sync service (use
///   [`decode_sync_req`] / [`decode_sync_res`] for those).
/// - [`AsduError::MacMismatch`] if the recomputed MAC does not match.
/// - [`AsduError::UnknownScf`] / [`CryptoError`] for malformed input.
pub fn decode(key: &Key16, asdu: &[u8], addr: &TpAddressing) -> Result<DecodedInner, AsduError> {
    let (scf, seq_bytes, secured_apdu, received_mac) = split_asdu(asdu)?;
    if scf.service != SecureService::Data {
        return Err(AsduError::UnexpectedService(asdu[0]));
    }
    let seq = Sequence::from_bytes(seq_bytes);
    let apdu = open(
        key,
        seq,
        addr,
        &[asdu[0]],
        secured_apdu,
        received_mac,
        scf.algorithm.encrypts(),
    )?;
    let (apci, data) = parse_inner_apdu(&apdu)?;
    Ok(DecodedInner {
        scf,
        sequence: seq,
        apci,
        data,
    })
}

/// The length of the serial-number field of an S-A_Sync_Req (spec §6.3).
pub const SERIAL_LEN: usize = 6;
/// The length of the S-A_Sync_Req challenge (spec §6.3).
pub const CHALLENGE_LEN: usize = 6;
/// The length of the sequence-number field of every secure ASDU (spec §5.3).
pub const SEQ_LEN: usize = 6;

/// A 6-byte S-A_Sync_Req challenge (spec §6.3).
pub type Challenge = [u8; CHALLENGE_LEN];

/// The content of an S-A_Sync_Req (spec §6.3). CONFIRMED layout (secure-1-1-12
/// capture, 2026-09-23):
///
/// ```text
/// SCF(0x92) || seq(6) || serial(6, clear) || challenge(6, encrypted) || MAC(4)
/// ```
///
/// The CCM nonce is the frame's own `seq` field and the carrier addressing. The
/// additional data is `SCF || serial`; the payload is the challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRequest {
    /// The requester's current send sequence. The responder answers with the
    /// sequence it will accept next from the requester (normally this value), and
    /// ETS then sends its first S-A_Data with exactly this value.
    pub sequence: Sequence,
    /// The target's KNX serial number, or all zeros on a connection-oriented
    /// (individually addressed) request. ETS fills it only on the broadcast form
    /// sent to `0/0/0`.
    pub serial: [u8; SERIAL_LEN],
    /// A fresh random challenge that binds the S-A_Sync_Res to this request.
    pub challenge: Challenge,
}

/// The content of an S-A_Sync_Res (spec §6.3). CONFIRMED layout (secure-1-1-12
/// capture, 2026-09-23):
///
/// ```text
/// SCF(0x93) || masked(6) || enc(responder_seq(6) || requester_seq(6)) || MAC(4)
/// ```
///
/// The six bytes in the sequence slot are NOT a sequence: they are the CCM nonce
/// sequence XOR the request's challenge. The receiver recovers the nonce as
/// `masked XOR challenge` and verifies/decrypts with it, so a response only
/// verifies against the request whose challenge it answers. The additional data
/// is the SCF alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncResponse {
    /// The responder's own next send sequence. The device's next S-A_Data
    /// carries exactly this value.
    pub responder_sequence: Sequence,
    /// The sequence the responder accepts next from the requester. In the
    /// capture it equals the request's `sequence`.
    pub requester_sequence: Sequence,
}

/// Encodes an S-A_Sync_Req ASDU (spec §6.3). `scf.service` must be
/// [`SecureService::SyncReq`].
///
/// # Errors
///
/// [`AsduError::UnexpectedService`] for a non-Sync_Req SCF, or a
/// [`CryptoError`] from the CCM primitives.
pub fn encode_sync_req(
    key: &Key16,
    scf: Scf,
    req: &SyncRequest,
    addr: &TpAddressing,
) -> Result<SecureAsdu, AsduError> {
    let scf_byte = scf.to_byte();
    if scf.service != SecureService::SyncReq {
        return Err(AsduError::UnexpectedService(scf_byte));
    }
    let mut ad = Vec::with_capacity(1 + SERIAL_LEN);
    ad.push(scf_byte);
    ad.extend_from_slice(&req.serial);
    let (secured, mac4) = seal(
        key,
        req.sequence,
        addr,
        &ad,
        &req.challenge,
        scf.algorithm.encrypts(),
    )?;
    let mut out = Vec::with_capacity(1 + SEQ_LEN + SERIAL_LEN + CHALLENGE_LEN + TP_MAC_LEN);
    out.push(scf_byte);
    out.extend_from_slice(&req.sequence.to_bytes());
    out.extend_from_slice(&req.serial);
    out.extend_from_slice(&secured);
    out.extend_from_slice(&mac4);
    Ok(out)
}

/// Decodes and verifies an S-A_Sync_Req ASDU (spec §6.3).
///
/// # Errors
///
/// [`AsduError::UnexpectedService`] if the SCF is not a Sync_Req,
/// [`AsduError::TooShort`] on a wrong length, [`AsduError::MacMismatch`] on a
/// bad MAC.
pub fn decode_sync_req(
    key: &Key16,
    asdu: &[u8],
    addr: &TpAddressing,
) -> Result<(Scf, SyncRequest), AsduError> {
    let (scf, seq_bytes, body, mac) = split_asdu(asdu)?;
    if scf.service != SecureService::SyncReq {
        return Err(AsduError::UnexpectedService(asdu[0]));
    }
    if body.len() != SERIAL_LEN + CHALLENGE_LEN {
        return Err(AsduError::TooShort(asdu.len()));
    }
    let mut serial = [0u8; SERIAL_LEN];
    serial.copy_from_slice(&body[..SERIAL_LEN]);
    let mut ad = Vec::with_capacity(1 + SERIAL_LEN);
    ad.push(asdu[0]);
    ad.extend_from_slice(&serial);
    let sequence = Sequence::from_bytes(seq_bytes);
    let plain = open(
        key,
        sequence,
        addr,
        &ad,
        &body[SERIAL_LEN..],
        mac,
        scf.algorithm.encrypts(),
    )?;
    let mut challenge = [0u8; CHALLENGE_LEN];
    challenge.copy_from_slice(&plain);
    Ok((
        scf,
        SyncRequest {
            sequence,
            serial,
            challenge,
        },
    ))
}

/// XORs a 6-byte nonce sequence with a challenge (the S-A_Sync_Res masking).
fn mask(value: [u8; SEQ_LEN], challenge: &Challenge) -> [u8; SEQ_LEN] {
    let mut out = [0u8; SEQ_LEN];
    for (o, (v, c)) in out.iter_mut().zip(value.iter().zip(challenge.iter())) {
        *o = v ^ c;
    }
    out
}

/// Encodes an S-A_Sync_Res ASDU answering the request that carried `challenge`
/// (spec §6.3). `nonce` is the responder's choice of CCM nonce sequence (a
/// real device picks a fresh value per response); it travels masked with the
/// challenge. `scf.service` must be [`SecureService::SyncRes`].
///
/// # Errors
///
/// [`AsduError::UnexpectedService`] for a non-Sync_Res SCF, or a
/// [`CryptoError`] from the CCM primitives.
pub fn encode_sync_res(
    key: &Key16,
    scf: Scf,
    res: &SyncResponse,
    challenge: &Challenge,
    nonce: Sequence,
    addr: &TpAddressing,
) -> Result<SecureAsdu, AsduError> {
    let scf_byte = scf.to_byte();
    if scf.service != SecureService::SyncRes {
        return Err(AsduError::UnexpectedService(scf_byte));
    }
    let mut payload = Vec::with_capacity(2 * SEQ_LEN);
    payload.extend_from_slice(&res.responder_sequence.to_bytes());
    payload.extend_from_slice(&res.requester_sequence.to_bytes());
    let (secured, mac4) = seal(
        key,
        nonce,
        addr,
        &[scf_byte],
        &payload,
        scf.algorithm.encrypts(),
    )?;
    let mut out = Vec::with_capacity(1 + SEQ_LEN + secured.len() + TP_MAC_LEN);
    out.push(scf_byte);
    out.extend_from_slice(&mask(nonce.to_bytes(), challenge));
    out.extend_from_slice(&secured);
    out.extend_from_slice(&mac4);
    Ok(out)
}

/// Decodes and verifies an S-A_Sync_Res ASDU against the `challenge` of the
/// request it answers (spec §6.3).
///
/// # Errors
///
/// [`AsduError::UnexpectedService`] if the SCF is not a Sync_Res,
/// [`AsduError::TooShort`] on a wrong length, [`AsduError::MacMismatch`] on a
/// bad MAC (including a response to a different challenge).
pub fn decode_sync_res(
    key: &Key16,
    asdu: &[u8],
    addr: &TpAddressing,
    challenge: &Challenge,
) -> Result<SyncResponse, AsduError> {
    let (scf, masked, body, mac) = split_asdu(asdu)?;
    if scf.service != SecureService::SyncRes {
        return Err(AsduError::UnexpectedService(asdu[0]));
    }
    if body.len() != 2 * SEQ_LEN {
        return Err(AsduError::TooShort(asdu.len()));
    }
    let nonce = Sequence::from_bytes(mask(masked, challenge));
    let plain = open(
        key,
        nonce,
        addr,
        &[asdu[0]],
        body,
        mac,
        scf.algorithm.encrypts(),
    )?;
    let mut responder = [0u8; SEQ_LEN];
    responder.copy_from_slice(&plain[..SEQ_LEN]);
    let mut requester = [0u8; SEQ_LEN];
    requester.copy_from_slice(&plain[SEQ_LEN..]);
    Ok(SyncResponse {
        responder_sequence: Sequence::from_bytes(responder),
        requester_sequence: Sequence::from_bytes(requester),
    })
}

/// Serializes an inner management APDU to the byte string the CCM operates on.
///
/// The KNX application layer packs the 10-bit APCI as: octet 0 low 2 bits =
/// APCI bits 9-8, octet 1 = APCI bits 7-0. bussard's management APCIs are full
/// 10-bit values (e.g. `0x3D1`), and their parameter is carried in trailing data
/// octets (the crate never uses the 6-bit-packed short form for management), so
/// the packing is: `[(apci>>8) & 0x03, (apci & 0xFF)] || data`.
pub fn inner_apdu_bytes(apci: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(((apci >> 8) & 0x03) as u8);
    out.push((apci & 0xFF) as u8);
    out.extend_from_slice(data);
    out
}

/// Parses an inner APDU byte string back into `(apci, data)`.
fn parse_inner_apdu(apdu: &[u8]) -> Result<(u16, Vec<u8>), AsduError> {
    if apdu.len() < 2 {
        return Err(AsduError::InnerTooShort(apdu.len()));
    }
    let apci = ((u16::from(apdu[0]) & 0x03) << 8) | u16::from(apdu[1]);
    Ok((apci, apdu[2..].to_vec()))
}

/// Errors from the A_SecureData ASDU codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AsduError {
    /// The inner APDU payload exceeded the single-octet length field.
    #[error("secured payload too long for the length field: {0} bytes")]
    PayloadTooLong(usize),
    /// The ASDU was shorter than the minimum `SCF + seq + MAC`.
    #[error("A_SecureData ASDU too short: {0} bytes")]
    TooShort(usize),
    /// The recovered inner APDU was shorter than the two APCI octets.
    #[error("recovered inner APDU too short: {0} bytes")]
    InnerTooShort(usize),
    /// The recomputed MAC did not match the received MAC (a forgery, corruption,
    /// or wrong key).
    #[error("A_SecureData MAC verification failed")]
    MacMismatch,
    /// The received sequence was not strictly greater than the last accepted from
    /// this source (a replay, spec §5.9 receive-side).
    #[error("stale Data Secure sequence: got {got}, last accepted {last}")]
    StaleSequence {
        /// The sequence carried in the rejected frame.
        got: u64,
        /// The last sequence accepted from this source.
        last: u64,
    },
    /// The SCF byte carried an unrecognised algorithm or service.
    #[error("unrecognised Security Control Field byte: {0:#04x}")]
    UnknownScf(u8),
    /// The SCF named a secure service the caller did not expect here (e.g. a
    /// Sync frame handed to the S-A_Data decoder).
    #[error("unexpected secure service in SCF byte {0:#04x}")]
    UnexpectedService(u8),
    /// An S-A_Sync_Res arrived with no Sync_Req outstanding, so there is no
    /// challenge to verify it against.
    #[error("S-A_Sync_Res received without an outstanding S-A_Sync_Req")]
    UnsolicitedSyncResponse,
    /// The device did not answer the S-A_Sync_Req with an S-A_Sync_Res (spec
    /// §6.3). ETS always opens secured tool access with this exchange.
    #[error("the device did not answer the Data Secure sync request (S-A_Sync_Req)")]
    SyncUnanswered,
    /// A crypto primitive rejected its input.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scf_round_trip_data_frames() {
        // The three house-capture SCF bytes (spec §5.2).
        for byte in [0x90u8, 0x92, 0x93] {
            let scf = Scf::from_byte(byte).unwrap();
            assert_eq!(scf.to_byte(), byte);
        }
        // 0x90 = 1001_0000: tool-access data, auth+encrypt (algo bits 6-4 = 001).
        let scf = Scf::from_byte(0x90).unwrap();
        assert!(scf.tool_access);
        assert_eq!(scf.algorithm, SecurityAlgorithm::AuthenticationEncryption);
        assert_eq!(scf.service, SecureService::Data);
        // 0x92 = tool-access Sync_Req.
        assert_eq!(
            Scf::from_byte(0x92).unwrap().service,
            SecureService::SyncReq
        );
        // 0x93 = tool-access Sync_Res.
        assert_eq!(
            Scf::from_byte(0x93).unwrap().service,
            SecureService::SyncRes
        );
    }

    #[test]
    fn test_scf_tool_data_encrypt() {
        let scf = Scf::tool_data(SecurityAlgorithm::AuthenticationEncryption);
        // tool_access(1) | algo(001) | sysbcast(0) | service(000) = 1001_0000 = 0x90.
        assert_eq!(scf.to_byte(), 0x90);
        let scf = Scf::tool_data(SecurityAlgorithm::AuthenticationOnly);
        // algo 000 → 1000_0000 = 0x80.
        assert_eq!(scf.to_byte(), 0x80);
    }

    #[test]
    fn test_scf_rejects_unknown() {
        // Service selector 0b111 (7) is undefined.
        assert_eq!(Scf::from_byte(0x97), Err(AsduError::UnknownScf(0x97)));
    }

    fn addr() -> TpAddressing {
        TpAddressing {
            source: 0x1101,      // 1.1.1
            destination: 0x110A, // 1.1.10
            address_type_group: false,
            extended_frame_format: 0,
            tpci: 0x42, // some numbered-data TPCI octet
        }
    }

    #[test]
    fn test_tp_block_0_layout() {
        let seq = Sequence::new(0x0000_0000_002A);
        let b = tp_block_0(seq, &addr(), 5);
        assert_eq!(&b[0..6], &seq.to_bytes());
        assert_eq!(&b[6..10], &[0x11, 0x01, 0x11, 0x0A]);
        assert_eq!(b[10], 0x00);
        assert_eq!(b[11], 0x00); // individual, ext-format 0
        // The carrier's TPCI octet 0x42 keeps its 6-bit field in place and the
        // APCI high bits become 0x03 → 0x43 (spec §5.4's `(tpci_int<<2)+0x03`
        // with tpci_int = 0x10).
        assert_eq!(b[12], 0x43);
        assert_eq!(b[13], 0xF1);
        assert_eq!(b[14], 0x00);
        assert_eq!(b[15], 5);
    }

    #[test]
    fn test_tp_counter_0_layout() {
        let seq = Sequence::new(0x0000_0000_002A);
        let c = tp_counter_0(seq, &addr());
        assert_eq!(&c[0..6], &seq.to_bytes());
        assert_eq!(&c[6..10], &[0x11, 0x01, 0x11, 0x0A]);
        assert_eq!(&c[10..16], &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_inner_apdu_pack_unpack() {
        let bytes = inner_apdu_bytes(0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(bytes[0], 0x03);
        assert_eq!(bytes[1], 0xD1);
        let (apci, data) = parse_inner_apdu(&bytes).unwrap();
        assert_eq!(apci, 0x3D1);
        assert_eq!(data, vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    /// Spec §5.7 worked round-trip, encrypt mode: encode then decode returns the
    /// inner APDU, with an all-zero tool key and a fixed sequence.
    #[test]
    fn test_encode_decode_round_trip_encrypt() {
        let key = Key16::new([0u8; 16]);
        let scf = Scf::tool_data(SecurityAlgorithm::AuthenticationEncryption);
        let seq = Sequence::new(0x0102_0304_0506);
        let a = addr();
        let inner_apci = 0x280; // A_Memory_Write
        let inner_data = [0x00, 0x10, 0xAB, 0xCD];

        let asdu = encode(&key, scf, seq, &a, inner_apci, &inner_data).unwrap();
        // Layout: SCF(1) + seq(6) + secured_apdu(2+4) + MAC(4).
        assert_eq!(asdu[0], scf.to_byte());
        assert_eq!(&asdu[1..7], &seq.to_bytes());
        assert_eq!(asdu.len(), 1 + 6 + (2 + inner_data.len()) + TP_MAC_LEN);
        // Encrypted: the secured apdu must not equal the plaintext apdu.
        assert_ne!(
            &asdu[7..7 + 2 + inner_data.len()],
            &inner_apdu_bytes(inner_apci, &inner_data)[..]
        );

        let decoded = decode(&key, &asdu, &a).unwrap();
        assert_eq!(decoded.apci, inner_apci);
        assert_eq!(decoded.data, inner_data);
        assert_eq!(decoded.sequence, seq);
        assert_eq!(decoded.scf, scf);
    }

    /// Auth-only mode: the inner APDU travels in the clear, the MAC verifies.
    #[test]
    fn test_encode_decode_round_trip_auth_only() {
        let key = Key16::new([0x11; 16]);
        let scf = Scf::tool_data(SecurityAlgorithm::AuthenticationOnly);
        let seq = Sequence::new(42);
        let a = addr();
        let inner_apci = 0x3D1; // A_Authorize_Request
        let inner_data = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];

        let asdu = encode(&key, scf, seq, &a, inner_apci, &inner_data).unwrap();
        // Auth-only: the secured apdu is the plaintext apdu.
        let plain = inner_apdu_bytes(inner_apci, &inner_data);
        assert_eq!(&asdu[7..7 + plain.len()], &plain[..]);

        let decoded = decode(&key, &asdu, &a).unwrap();
        assert_eq!(decoded.apci, inner_apci);
        assert_eq!(decoded.data, inner_data);
    }

    /// SHARED KNOWN-ANSWER VECTOR (spec §12.1).
    ///
    /// The same inputs are encoded by the knx-sim's independent Data Secure
    /// implementation in `knx-sim/tests/secure_conformance.rs`
    /// (`test_shared_known_answer_vector`) and must yield these exact bytes. It is
    /// the cheap standing guard for the two byte-level divergences the #71
    /// conformance loop found — the `block_0` TPCI octet (§5.4) and the auth-only
    /// payload-length field — without needing the simulator running.
    ///
    /// Inputs: tool key `000102…0F` (synthetic), sequence 42, frame 1.1.1 → 1.1.2
    /// on a numbered data telegram (TPCI octet `0x42`, i.e. `tpci_int` `0x10`),
    /// inner APDU `A_Authorize_Request` (`0x3D1`) with the free-access key.
    const KAT_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const KAT_INNER_APCI: u16 = 0x3D1;
    const KAT_INNER_DATA: [u8; 5] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
    /// auth+encrypt (SCF 0x90): the inner APDU and the MAC are both encrypted.
    /// The payload keystream starts right after the 4 MAC bytes (the ETS layout,
    /// secure-1-1-12 capture 2026-09-23); the MAC bytes are unchanged from the
    /// earlier block-aligned vector, only the 7 payload bytes moved.
    const KAT_AUTH_ENC: [u8; 18] = [
        0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0xFB, 0xB8, 0x72, 0x5D, 0x14, 0x5F, 0xBE, 0x98,
        0xA5, 0x3D, 0xA2,
    ];
    /// auth-only (SCF 0x80): the inner APDU rides in the clear under the MAC.
    const KAT_AUTH_ONLY: [u8; 18] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x03, 0xD1, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xB5,
        0xA4, 0x6C, 0x9F,
    ];

    fn kat_addr() -> TpAddressing {
        TpAddressing {
            source: 0x1101,      // 1.1.1
            destination: 0x1102, // 1.1.2
            address_type_group: false,
            extended_frame_format: 0,
            tpci: 0x42, // numbered data, sequence 0
        }
    }

    #[test]
    fn test_known_answer_vector_matches_the_sim() {
        let key = Key16::new(KAT_KEY);
        let seq = Sequence::new(42);
        let a = kat_addr();
        for (alg, expected) in [
            (
                SecurityAlgorithm::AuthenticationEncryption,
                KAT_AUTH_ENC.as_slice(),
            ),
            (
                SecurityAlgorithm::AuthenticationOnly,
                KAT_AUTH_ONLY.as_slice(),
            ),
        ] {
            let asdu = encode(
                &key,
                Scf::tool_data(alg),
                seq,
                &a,
                KAT_INNER_APCI,
                &KAT_INNER_DATA,
            )
            .expect("the vector encodes");
            assert_eq!(
                asdu, expected,
                "{alg:?} A_SecureData bytes diverged from the shared vector"
            );
            // And the vector decodes back to the inner APDU.
            let decoded = decode(&key, expected, &a).expect("the vector verifies");
            assert_eq!(decoded.apci, KAT_INNER_APCI);
            assert_eq!(decoded.data, KAT_INNER_DATA);
            assert_eq!(decoded.sequence, seq);
        }
    }

    /// The `block_0` TPCI octet is the carrier's octet 6 with the APCI high bits
    /// forced to `0x03` — NOT the octet shifted again (the bug the sim caught).
    #[test]
    fn test_tp_block_0_tpci_octet_is_not_shifted_twice() {
        let seq = Sequence::new(1);
        for (octet, expected) in [
            (0x42u8, 0x43u8), // numbered data, sequence 0
            (0x46, 0x47),     // numbered data, sequence 1
            (0x00, 0x03),     // unnumbered data
        ] {
            let a = TpAddressing {
                tpci: octet,
                ..kat_addr()
            };
            assert_eq!(
                tp_block_0(seq, &a, 7)[12],
                expected,
                "TPCI octet {octet:#04x} must map to {expected:#04x}"
            );
        }
    }

    #[test]
    fn test_decode_rejects_wrong_mac() {
        let key = Key16::new([0u8; 16]);
        let scf = Scf::tool_data(SecurityAlgorithm::AuthenticationEncryption);
        let seq = Sequence::new(7);
        let a = addr();
        let mut asdu = encode(&key, scf, seq, &a, 0x280, &[0x00, 0x10, 0x01]).unwrap();
        // Corrupt the last MAC byte.
        let last = asdu.len() - 1;
        asdu[last] ^= 0xFF;
        assert_eq!(decode(&key, &asdu, &a), Err(AsduError::MacMismatch));
    }

    #[test]
    fn test_decode_rejects_wrong_key() {
        let key = Key16::new([0u8; 16]);
        let scf = Scf::tool_data(SecurityAlgorithm::AuthenticationEncryption);
        let seq = Sequence::new(7);
        let a = addr();
        let asdu = encode(&key, scf, seq, &a, 0x280, &[0x00, 0x10, 0x01]).unwrap();
        let wrong = Key16::new([0x99; 16]);
        assert_eq!(decode(&wrong, &asdu, &a), Err(AsduError::MacMismatch));
    }

    /// Sync_Req round trip: serial in the clear, challenge encrypted.
    #[test]
    fn test_sync_req_round_trip() -> Result<(), AsduError> {
        let key = Key16::new(KAT_KEY);
        let a = kat_addr();
        let req = SyncRequest {
            sequence: Sequence::new(0x0012_3456_789A),
            serial: [0x00, 0xFA, 0x12, 0x34, 0x56, 0x78],
            challenge: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        };
        let asdu = encode_sync_req(&key, Scf::tool_sync(SecureService::SyncReq), &req, &a)?;
        assert_eq!(asdu.len(), 1 + 6 + 6 + 6 + 4);
        assert_eq!(asdu[0], 0x92);
        assert_eq!(&asdu[1..7], &req.sequence.to_bytes());
        assert_eq!(&asdu[7..13], &req.serial, "the serial travels in the clear");
        assert_ne!(&asdu[13..19], &req.challenge, "the challenge is encrypted");
        let (scf, back) = decode_sync_req(&key, &asdu, &a)?;
        assert_eq!(scf.to_byte(), 0x92);
        assert_eq!(back, req);
        // The serial is authenticated: flipping it breaks the MAC.
        let mut forged = asdu.clone();
        forged[8] ^= 0x01;
        assert_eq!(
            decode_sync_req(&key, &forged, &a),
            Err(AsduError::MacMismatch)
        );
        Ok(())
    }

    /// Sync_Res round trip: the sequence slot carries the nonce masked with the
    /// challenge, and only the right challenge verifies.
    #[test]
    fn test_sync_res_round_trip() -> Result<(), AsduError> {
        let key = Key16::new(KAT_KEY);
        let a = kat_addr();
        let challenge = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let nonce = Sequence::new(0x0102_0304_0506);
        let res = SyncResponse {
            responder_sequence: Sequence::new(0x0012_3456_0001),
            requester_sequence: Sequence::new(0x0012_3456_789A),
        };
        let asdu = encode_sync_res(
            &key,
            Scf::tool_sync(SecureService::SyncRes),
            &res,
            &challenge,
            nonce,
            &a,
        )?;
        assert_eq!(asdu.len(), 1 + 6 + 12 + 4);
        assert_eq!(asdu[0], 0x93);
        assert_eq!(&asdu[1..7], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(decode_sync_res(&key, &asdu, &a, &challenge)?, res);
        assert_eq!(
            decode_sync_res(&key, &asdu, &a, &[0u8; 6]),
            Err(AsduError::MacMismatch)
        );
        Ok(())
    }

    /// The data decoder refuses a Sync frame instead of mis-verifying it.
    #[test]
    fn test_decode_rejects_sync_service() -> Result<(), AsduError> {
        let key = Key16::new(KAT_KEY);
        let req = SyncRequest {
            sequence: Sequence::new(1),
            serial: [0; 6],
            challenge: [0; 6],
        };
        let asdu = encode_sync_req(
            &key,
            Scf::tool_sync(SecureService::SyncReq),
            &req,
            &kat_addr(),
        )?;
        assert_eq!(
            decode(&key, &asdu, &kat_addr()),
            Err(AsduError::UnexpectedService(0x92))
        );
        Ok(())
    }

    #[test]
    fn test_decode_rejects_too_short() {
        let key = Key16::new([0u8; 16]);
        assert_eq!(
            decode(&key, &[0x90, 0x00], &addr()),
            Err(AsduError::TooShort(2))
        );
    }
}
