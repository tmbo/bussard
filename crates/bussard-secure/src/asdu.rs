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
/// (spec §5.3). `SEC-CAL:` confirm the gateway/device uses a 4-byte (not 16-byte)
/// MAC on the tunnel management path — capture needed (spec §6.2, §12.4 #2).
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
/// Values are read off the house-capture SCF bytes (`0x90`/`0x92`/`0x93`, spec
/// §5.2): data = 0, Sync_Req = 2, Sync_Res = 3. The enum names are `INFERRED`
/// from the tool-access flag + XKNX. `SEC-CAL:` confirm the SALService enum names
/// against a live capture.
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
    /// The TPCI value (the connection-control/sequence bits) of the carrying
    /// frame, as an integer.
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
    b[12] = (addr.tpci << 2) | APCI_SEC_HIGH;
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
/// APDU (spec §5.3), laid out `SCF(1) || seq(6) || secured_apdu(var) || MAC(4)`.
///
/// This is exactly what [`crate::session`] hands to the transport as the data
/// octets of the `A_SECURE_DATA` APCI.
pub type SecureAsdu = Vec<u8>;

/// Encodes an A_SecureData ASDU wrapping `inner_apci` + `inner_data` (spec §5.6).
///
/// `inner_apci` is the plain management APCI (e.g. `A_Memory_Write`); it is
/// serialized to its two APDU octets (10-bit APCI packed into the low 6 bits of
/// octet 0 and the high 2 bits... — see [`inner_apdu_bytes`]) plus its data, and
/// that byte string is the "apdu" the CCM authenticates/encrypts.
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
    let payload_len =
        u8::try_from(apdu.len()).map_err(|_| AsduError::PayloadTooLong(apdu.len()))?;
    let scf_byte = scf.to_byte();

    let block_0 = tp_block_0(seq, addr, payload_len);
    let counter_0 = tp_counter_0(seq, addr);

    let (secured_apdu, mac4) = if scf.algorithm.encrypts() {
        // CCM_ENCRYPTION: additional_data = SCF only; payload = apdu; encrypt
        // both apdu and MAC (spec §5.6).
        let mac_cbc = crypto::cbc_mac(key, &[scf_byte], &apdu, &block_0)?;
        let (enc_payload, enc_mac) = crypto::encrypt_ctr(key, &counter_0, &mac_cbc, &apdu)?;
        let mut mac4 = [0u8; TP_MAC_LEN];
        mac4.copy_from_slice(&enc_mac[..TP_MAC_LEN]);
        (enc_payload, mac4)
    } else {
        // CCM_AUTHENTICATION: additional_data = SCF || apdu; apdu in the clear;
        // encrypt only the MAC (spec §5.6).
        let mut ad = Vec::with_capacity(1 + apdu.len());
        ad.push(scf_byte);
        ad.extend_from_slice(&apdu);
        let mac_cbc = crypto::cbc_mac(key, &ad, &[], &block_0)?;
        let (_empty, enc_mac) = crypto::encrypt_ctr(key, &counter_0, &mac_cbc, &[])?;
        let mut mac4 = [0u8; TP_MAC_LEN];
        mac4.copy_from_slice(&enc_mac[..TP_MAC_LEN]);
        (apdu, mac4)
    };

    let mut out = Vec::with_capacity(1 + 6 + secured_apdu.len() + TP_MAC_LEN);
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

/// Decodes and verifies an A_SecureData ASDU, returning the inner APDU
/// (spec §5.6). The MAC is checked constant-time; a mismatch is rejected.
///
/// # Errors
///
/// - [`AsduError::TooShort`] if the ASDU is shorter than `SCF+seq+MAC`.
/// - [`AsduError::MacMismatch`] if the recomputed MAC does not match.
/// - [`AsduError::UnknownScf`] / [`CryptoError`] for malformed input.
pub fn decode(key: &Key16, asdu: &[u8], addr: &TpAddressing) -> Result<DecodedInner, AsduError> {
    // SCF(1) + seq(6) + at least the MAC(4).
    if asdu.len() < 1 + 6 + TP_MAC_LEN {
        return Err(AsduError::TooShort(asdu.len()));
    }
    let scf = Scf::from_byte(asdu[0])?;
    let scf_byte = asdu[0];
    let mut seq_bytes = [0u8; 6];
    seq_bytes.copy_from_slice(&asdu[1..7]);
    let seq = Sequence::from_bytes(seq_bytes);

    let secured_apdu = &asdu[7..asdu.len() - TP_MAC_LEN];
    let received_mac = &asdu[asdu.len() - TP_MAC_LEN..];

    let payload_len = u8::try_from(secured_apdu.len())
        .map_err(|_| AsduError::PayloadTooLong(secured_apdu.len()))?;
    let block_0 = tp_block_0(seq, addr, payload_len);
    let counter_0 = tp_counter_0(seq, addr);

    let apdu = if scf.algorithm.encrypts() {
        // Decrypt the MAC and the payload. We only have 4 MAC bytes on the wire;
        // recover the plaintext apdu, then recompute and compare the MAC.
        // First decrypt the payload with counter_0+1.. (the MAC uses block 0).
        // We reuse `decrypt_ctr` with a placeholder MAC to peel the payload, then
        // recompute the real MAC from the recovered apdu.
        let placeholder = [0u8; crypto::BLOCK];
        let (apdu, _discard) = crypto::decrypt_ctr(key, &counter_0, &placeholder, secured_apdu)?;
        // Recompute the expected MAC over the recovered apdu.
        let mac_cbc = crypto::cbc_mac(key, &[scf_byte], &apdu, &block_0)?;
        let (_e, enc_mac) = crypto::encrypt_ctr(key, &counter_0, &mac_cbc, &[])?;
        if !crypto::constant_time_eq(&enc_mac[..TP_MAC_LEN], received_mac) {
            return Err(AsduError::MacMismatch);
        }
        apdu
    } else {
        // AUTH-only: the apdu is in the clear; recompute the MAC over SCF||apdu.
        let apdu = secured_apdu.to_vec();
        let mut ad = Vec::with_capacity(1 + apdu.len());
        ad.push(scf_byte);
        ad.extend_from_slice(&apdu);
        let mac_cbc = crypto::cbc_mac(key, &ad, &[], &block_0)?;
        let (_e, enc_mac) = crypto::encrypt_ctr(key, &counter_0, &mac_cbc, &[])?;
        if !crypto::constant_time_eq(&enc_mac[..TP_MAC_LEN], received_mac) {
            return Err(AsduError::MacMismatch);
        }
        apdu
    };

    let (apci, data) = parse_inner_apdu(&apdu)?;
    Ok(DecodedInner {
        scf,
        sequence: seq,
        apci,
        data,
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
        assert_eq!(b[12], (0x42 << 2) | 0x03);
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

    #[test]
    fn test_decode_rejects_too_short() {
        let key = Key16::new([0u8; 16]);
        assert_eq!(
            decode(&key, &[0x90, 0x00], &addr()),
            Err(AsduError::TooShort(2))
        );
    }
}
