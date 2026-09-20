//! KNX Data Secure device model (spec §5, §6, §12.2).
//!
//! This is the simulator's model of a **security-activated** device's tool-access
//! path. It is deliberately strict, exactly as spec §12.2 requires:
//!
//! - a wrong MAC is refused,
//! - a replayed or stale sequence number is refused,
//! - a plain (unwrapped) management access to a protected function on an
//!   activated device is refused.
//!
//! The crypto primitives ([`crypto`]) are the decomposed AES-CCM (CBC-MAC + CTR)
//! of spec §3. This module adds the A_SecureData ASDU layout (§5), the SCF
//! (§5.2), the TP block_0 / counter_0 nonces (§5.4, §5.5), the MAC-only vs
//! MAC+encrypt split (§5.6) and the per-device [`DataSecureSession`] that a
//! [`crate::device::Device`] holds when it is activated.
//!
//! Synthetic keys only. No key material ever comes from a user file, and neither
//! keys nor decrypted key-bearing plaintext are ever logged (see
//! [`DataSecureSession::describe_frame`]).

pub mod crypto;

use crate::wire::CemiLData;

/// The A_SecureData APCI (spec §5.1): `_APCI_SEC_HIGH = 0x03`,
/// `_APCI_SEC_LOW = 0xF1`, i.e. the 10-bit APCI `0x3F1`.
pub const A_SECURE_DATA_APCI: u16 = 0x3F1;

/// The Data Secure MAC length on TP: 4 bytes, `mac[..4]` (spec §5.3). The full
/// CBC-MAC is 16 bytes; only the first four ride the wire.
///
/// SEC-CAL: confirm the device/gateway uses a 4-byte MAC (not 16) on the tunnel
/// management path, and whether every management APDU must be secured vs may stay
/// plain once inside a secure link (spec §6.2, §12.4). Best-evidence default: 4
/// bytes, all management APDUs secured. Settled by a live ETS activation capture.
pub const TP_MAC_LEN: usize = 4;

/// Length of the 6-byte sequence number field (ms since 2018-01-05, §5.8).
pub const SEQ_LEN: usize = 6;

/// The CCM algorithm identifier carried in SCF bits 6..4 (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecAlgorithm {
    /// `0b000` — CCM authentication only: the inner APDU rides in the clear, a
    /// 4-byte MAC authenticates `SCF || apdu` (spec §5.6).
    AuthOnly,
    /// `0b001` — CCM authentication + encryption: the inner APDU is encrypted and
    /// the MAC authenticates `SCF` (spec §5.6).
    AuthEnc,
}

impl SecAlgorithm {
    /// The 3-bit algorithm identifier for the SCF.
    pub fn to_bits(self) -> u8 {
        match self {
            SecAlgorithm::AuthOnly => 0b000,
            SecAlgorithm::AuthEnc => 0b001,
        }
    }

    /// Decode the 3-bit algorithm identifier from an SCF. Returns `None` for a
    /// value the sim does not model (a strict device refuses an unknown
    /// algorithm rather than guessing).
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b111 {
            0b000 => Some(SecAlgorithm::AuthOnly),
            0b001 => Some(SecAlgorithm::AuthEnc),
            _ => None,
        }
    }
}

/// The S-A_Data service selector carried in SCF bits 2..0 (spec §5.2).
///
/// The SCF byte for each service is decoded/encoded here (the wire form is
/// CONFIRMED from the capture SCF bytes), but the sim does not yet run the Sync
/// preamble exchange — it models the secure-DATA hot path (§12.2). The Sync seam
/// is left clean for a later addition.
///
/// SEC-CAL: Sync_Req/Sync_Res exact ASDU byte layout (serial placement, whether
/// the response carries the device seqnum) and whether Sync is mandatory once a
/// device is activated (spec §5.9, §6.3, §12.4). Settled by an ETS activation
/// capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecService {
    /// Secure data transfer (`0`). SCF `0x90` in the captures.
    Data,
    /// Sequence-number synchronisation request (`2`). SCF `0x92`.
    SyncReq,
    /// Sequence-number synchronisation response (`3`). SCF `0x93`.
    SyncRes,
}

impl SecService {
    /// The 3-bit service selector for the SCF.
    pub fn to_bits(self) -> u8 {
        match self {
            SecService::Data => 0,
            SecService::SyncReq => 2,
            SecService::SyncRes => 3,
        }
    }

    /// Decode the 3-bit service selector.
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b111 {
            0 => Some(SecService::Data),
            2 => Some(SecService::SyncReq),
            3 => Some(SecService::SyncRes),
            _ => None,
        }
    }
}

/// A decoded Security Control Field (spec §5.2), one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scf {
    /// Bit 7: tool/management access (uses the tool key).
    pub tool_access: bool,
    /// Bits 6..4: the CCM algorithm.
    pub algorithm: SecAlgorithm,
    /// Bit 3: system-broadcast flag.
    pub system_broadcast: bool,
    /// Bits 2..0: the S-A_Data service.
    pub service: SecService,
}

impl Scf {
    /// Serialize to the one SCF byte:
    /// `(tool_access<<7) | (algorithm<<4) | (system_broadcast<<3) | service`.
    pub fn to_byte(self) -> u8 {
        ((self.tool_access as u8) << 7)
            | (self.algorithm.to_bits() << 4)
            | ((self.system_broadcast as u8) << 3)
            | self.service.to_bits()
    }

    /// Decode an SCF byte. Returns `None` for an algorithm/service the simulator
    /// does not model.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(Scf {
            tool_access: b & 0x80 != 0,
            algorithm: SecAlgorithm::from_bits((b >> 4) & 0b111)?,
            system_broadcast: b & 0x08 != 0,
            service: SecService::from_bits(b & 0b111)?,
        })
    }
}

/// Reasons the secure layer refuses a frame (spec §12.2 strictness traps). A
/// real activated device drops such a frame; the sim surfaces the reason on the
/// event log (never the key or plaintext).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecureError {
    /// The ASDU was too short to hold SCF + 6-byte seq + 4-byte MAC.
    #[error("secure ASDU too short: {len} bytes")]
    TooShort {
        /// The ASDU length.
        len: usize,
    },
    /// The SCF carried an algorithm or service the sim does not model.
    #[error("unrecognised SCF byte 0x{scf:02x}")]
    BadScf {
        /// The offending SCF byte.
        scf: u8,
    },
    /// The recomputed MAC did not match the received MAC.
    #[error("MAC verification failed")]
    BadMac,
    /// The received sequence number was not strictly greater than the last seen
    /// for this source (replay / stale). Refused.
    #[error("stale/replayed sequence {got} (last seen {last})")]
    StaleSequence {
        /// The received sequence.
        got: u64,
        /// The last accepted sequence for this source.
        last: u64,
    },
    /// A plain (unwrapped) management access hit a protected function on an
    /// activated device (spec §6.4 / §12.2).
    #[error("plain access refused: device requires KNX Data Secure")]
    PlainAccessRefused,
}

/// The parts of a cEMI frame that the TP nonce protects (spec §5.4). Only the
/// address fields and a Ctrl2-derived octet are protected, plus the inner
/// TPCI/APCI. These are extracted from the carrier frame so the block_0 / nonce
/// can be reconstructed identically on both sides.
#[derive(Debug, Clone, Copy)]
struct FrameContext {
    /// Source IA (2 bytes, big-endian) followed by destination (2 bytes).
    address_fields: [u8; 4],
    /// The `A000EEEE` octet: address-type bit (bit 7) OR extended frame format
    /// (low nibble), derived from Ctrl2 (spec §5.4).
    addr_type_frame_format: u8,
    /// The TPCI value of the *carrier* A_SecureData telegram (its top bits),
    /// used to build the nonce's `(tpci_int << 2) + 0x03` octet (§5.4).
    tpci_int: u8,
}

impl FrameContext {
    /// Extract the protected context from the carrier cEMI frame.
    ///
    /// `tpci_int` is the transport-control value of the A_SecureData carrier: for
    /// a connected data telegram it is the sequence-bearing TPCI top bits, for an
    /// unnumbered telegram it is 0. The spec folds it into the block_0 octet as
    /// `(tpci_int << 2) + 0x03`.
    fn from_cemi(cemi: &CemiLData, tpci_int: u8) -> Self {
        let mut address_fields = [0u8; 4];
        address_fields[..2].copy_from_slice(&cemi.source.raw().to_be_bytes());
        address_fields[2..].copy_from_slice(&cemi.dest.to_be_bytes());
        // "Only Ctrl2 is protected, and only as A000EEEEb" (spec §5.4). Ctrl2
        // bit 7 is the address-type bit; its low nibble is the extended frame
        // format. Mask to that shape.
        let addr_type_frame_format = cemi.ctrl2 & 0b1000_1111;
        FrameContext {
            address_fields,
            addr_type_frame_format,
            tpci_int,
        }
    }

    /// The 16-byte CCM `block_0` for a TP frame (spec §5.4).
    fn block_0(&self, seq: &[u8; 6], payload_len: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..6].copy_from_slice(seq);
        b[6..10].copy_from_slice(&self.address_fields);
        b[10] = 0x00;
        b[11] = self.addr_type_frame_format;
        b[12] = (self.tpci_int << 2) + 0x03;
        b[13] = 0xF1;
        b[14] = 0x00;
        b[15] = payload_len;
        b
    }

    /// The 16-byte CCM `counter_0` for a TP frame (spec §5.5).
    fn counter_0(&self, seq: &[u8; 6]) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[..6].copy_from_slice(seq);
        c[6..10].copy_from_slice(&self.address_fields);
        c[10..].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
        c
    }
}

/// The KNX Data Secure epoch: 2018-01-05T00:00:00Z, in milliseconds since the
/// Unix epoch (spec §5.8). The sending sequence is `ms_since_unix - this`.
pub const KNX_SECURE_EPOCH_UNIX_MS: u64 = 1_515_110_400_000;

/// A synthetic 16-byte key. Deliberately NOT `Debug`/`Display`-derived: a
/// hand-written `Debug` redacts so a key can never be logged (spec §2.3). Never
/// serialized. Holds only synthetic key material in the simulator.
#[derive(Clone, PartialEq, Eq)]
pub struct Key16([u8; 16]);

impl Key16 {
    /// Wrap 16 raw bytes.
    pub fn new(bytes: [u8; 16]) -> Self {
        Key16(bytes)
    }

    /// Parse 32 hex characters into a key. Returns `None` on a bad length or a
    /// non-hex character. Used only for synthetic config keys.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Key16(out))
    }

    /// The raw key bytes. Internal to the crypto path; do not log the result.
    fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for Key16 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal key bytes (spec §2.3).
        f.write_str("Key16(<redacted>)")
    }
}

impl Drop for Key16 {
    fn drop(&mut self) {
        // Best-effort zeroization without an extra dependency (spec §2.3): a
        // plain safe loop over the buffer. `#[forbid(unsafe_code)]` is honoured.
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

/// One wrapped/unwrapped exchange result: the inner APDU bytes and the SCF that
/// framed them. `inner_tpdu` is a full TPDU (TPCI/APCI + data), ready to feed to
/// the device's normal APDU dispatch or to re-wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unwrapped {
    /// The recovered inner TPDU (TPCI byte + APCI byte + data).
    pub inner_tpdu: Vec<u8>,
    /// The SCF that framed the secure frame.
    pub scf: Scf,
    /// The 6-byte sequence number the frame carried.
    pub seq: [u8; 6],
}

/// A per-device Data Secure session (spec §6.1). The device holds this when it is
/// security-activated. It carries the tool key, the device's own send sequence
/// (for wrapping responses), and the per-source freshness table (for replay
/// protection on receive).
///
/// The sim models a real activated device: it wraps its responses with its OWN
/// monotonically-increasing sequence and refuses any inbound frame whose
/// sequence does not strictly exceed the last accepted for that source.
pub struct DataSecureSession {
    /// The device's tool key (synthetic).
    tool_key: Key16,
    /// The device's own next send sequence (48-bit), incremented per wrapped
    /// response. Seeded from config.
    tx_seq: u64,
    /// The last accepted receive sequence, per source IA (raw u16 → last seq).
    /// A received frame must be strictly greater than this to be accepted.
    rx_last: std::collections::HashMap<u16, u64>,
    /// The initial receive-freshness floor applied to a source not yet seen: a
    /// first frame from a new source must strictly exceed this (spec §5.9, so a
    /// device that persisted a starting sequence rejects a from-clock seed that
    /// is lower). Seeded from config.
    ///
    /// SEC-CAL: confirm whether a real device rejects a from-clock seed that is
    /// lower than its stored value (i.e. whether the Sync exchange (§6.3) is
    /// mandatory to learn the device's current seqnum) - capture needed (spec
    /// §5.9, §12.4). Best-evidence default: strict rejection below the floor.
    rx_floor: u64,
    /// Whether every management access to this device must be secured. When
    /// `true` a plain management APDU to a protected function is refused (spec
    /// §6.4). Activated devices set this.
    require_secure: bool,
}

impl DataSecureSession {
    /// Build an activated session with the given synthetic tool key and initial
    /// sequence numbers. `initial_tx_seq` seeds the device's own send counter;
    /// `initial_rx_seq` seeds the receive-freshness floor for all sources.
    pub fn new(tool_key: Key16, initial_tx_seq: u64, initial_rx_seq: u64) -> Self {
        DataSecureSession {
            tool_key,
            tx_seq: initial_tx_seq,
            rx_last: std::collections::HashMap::new(),
            rx_floor: initial_rx_seq,
            require_secure: true,
        }
    }

    /// Whether this device refuses plain access to protected functions.
    pub fn require_secure(&self) -> bool {
        self.require_secure
    }

    /// The device's current send sequence (for tests/observability). Never a key.
    pub fn tx_seq(&self) -> u64 {
        self.tx_seq
    }

    /// The last accepted receive sequence for a source IA (for tests).
    pub fn rx_last(&self, source: u16) -> Option<u64> {
        self.rx_last.get(&source).copied()
    }

    /// Encode a 48-bit sequence to the 6-byte big-endian wire field.
    fn seq_to_bytes(seq: u64) -> [u8; 6] {
        let b = seq.to_be_bytes();
        let mut out = [0u8; 6];
        out.copy_from_slice(&b[2..]);
        out
    }

    /// Decode a 6-byte big-endian wire field to a 48-bit sequence.
    fn seq_from_bytes(b: &[u8; 6]) -> u64 {
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(b);
        u64::from_be_bytes(buf)
    }

    /// Wrap an inner TPDU into an A_SecureData ASDU (spec §5.3, §5.6) using the
    /// given SCF, `seq`, and carrier `context`. Returns the ASDU bytes
    /// `SCF || seq(6) || secured_apdu || MAC(4)`.
    ///
    /// The inner TPDU is the full inner telegram body (TPCI/APCI + data). Per
    /// §5.4 the block_0's `payload_length` octet is the length of the plaintext
    /// that CCM protects: for auth-only that is 0 (the APDU is additional data),
    /// for auth+enc it is the inner APDU length.
    fn wrap_with_context(
        &self,
        scf: Scf,
        seq: &[u8; 6],
        inner_tpdu: &[u8],
        context: &FrameContext,
    ) -> Vec<u8> {
        let key = self.tool_key.bytes();
        let scf_byte = scf.to_byte();

        let (secured_apdu, mac4): (Vec<u8>, [u8; TP_MAC_LEN]) = match scf.algorithm {
            SecAlgorithm::AuthOnly => {
                // additional_data = SCF || apdu; payload empty; APDU in the clear.
                let block_0 = context.block_0(seq, 0);
                let mut ad = Vec::with_capacity(1 + inner_tpdu.len());
                ad.push(scf_byte);
                ad.extend_from_slice(inner_tpdu);
                let mac_cbc = crypto::cbc_mac(key, &ad, b"", &block_0);
                let counter_0 = context.counter_0(seq);
                let (_enc, enc_mac) = crypto::encrypt_data_ctr(key, &counter_0, &mac_cbc, b"");
                let mut mac4 = [0u8; TP_MAC_LEN];
                mac4.copy_from_slice(&enc_mac[..TP_MAC_LEN]);
                (inner_tpdu.to_vec(), mac4)
            }
            SecAlgorithm::AuthEnc => {
                // additional_data = SCF only; payload = apdu (encrypted).
                let block_0 = context.block_0(seq, inner_tpdu.len() as u8);
                let mac_cbc = crypto::cbc_mac(key, &[scf_byte], inner_tpdu, &block_0);
                let counter_0 = context.counter_0(seq);
                let (enc_payload, enc_mac) =
                    crypto::encrypt_data_ctr(key, &counter_0, &mac_cbc, inner_tpdu);
                let mut mac4 = [0u8; TP_MAC_LEN];
                mac4.copy_from_slice(&enc_mac[..TP_MAC_LEN]);
                (enc_payload, mac4)
            }
        };

        let mut asdu = Vec::with_capacity(1 + SEQ_LEN + secured_apdu.len() + TP_MAC_LEN);
        asdu.push(scf_byte);
        asdu.extend_from_slice(seq);
        asdu.extend_from_slice(&secured_apdu);
        asdu.extend_from_slice(&mac4);
        asdu
    }

    /// Unwrap and verify an inbound A_SecureData ASDU carried by `carrier`,
    /// returning the recovered inner TPDU. Enforces MAC verification and
    /// sequence freshness (spec §5.6, §5.9). Does NOT mutate the freshness table;
    /// the caller commits it via [`Self::commit_rx`] only after the inner APDU is
    /// accepted (spec: update only after a successful MAC verify).
    fn unwrap_with_context(
        &self,
        asdu: &[u8],
        carrier: &FrameContext,
        source: u16,
    ) -> Result<Unwrapped, SecureError> {
        // Minimum: SCF(1) + seq(6) + MAC(4).
        if asdu.len() < 1 + SEQ_LEN + TP_MAC_LEN {
            return Err(SecureError::TooShort { len: asdu.len() });
        }
        let scf_byte = asdu[0];
        let scf = Scf::from_byte(scf_byte).ok_or(SecureError::BadScf { scf: scf_byte })?;
        let mut seq = [0u8; 6];
        seq.copy_from_slice(&asdu[1..1 + SEQ_LEN]);
        let body = &asdu[1 + SEQ_LEN..asdu.len() - TP_MAC_LEN];
        let wire_mac = &asdu[asdu.len() - TP_MAC_LEN..];

        // Freshness check FIRST is tempting, but the spec updates the table only
        // after a successful MAC verify. We check both here and let the caller
        // commit; a stale sequence is refused regardless of MAC.
        let got = Self::seq_from_bytes(&seq);
        // A source not yet seen is checked against the configured floor (spec
        // §5.9): a first frame must strictly exceed the device's persisted
        // starting sequence, so a from-clock seed lower than the floor is stale.
        let last = self.rx_last.get(&source).copied().unwrap_or(self.rx_floor);
        if got <= last {
            return Err(SecureError::StaleSequence { got, last });
        }

        let key = self.tool_key.bytes();
        let (inner_tpdu, ok) = match scf.algorithm {
            SecAlgorithm::AuthOnly => {
                // APDU is in the clear; MAC over SCF || apdu.
                let block_0 = carrier.block_0(&seq, 0);
                let mut ad = Vec::with_capacity(1 + body.len());
                ad.push(scf_byte);
                ad.extend_from_slice(body);
                let mac_cbc = crypto::cbc_mac(key, &ad, b"", &block_0);
                let counter_0 = carrier.counter_0(&seq);
                let (_enc, enc_mac) = crypto::encrypt_data_ctr(key, &counter_0, &mac_cbc, b"");
                (
                    body.to_vec(),
                    crypto::ct_eq(&enc_mac[..TP_MAC_LEN], wire_mac),
                )
            }
            SecAlgorithm::AuthEnc => {
                // body is the encrypted APDU. Right-pad the 4-byte wire MAC into
                // a 16-byte block to run CTR-decrypt, recover the CBC-MAC, then
                // recompute and compare only the first 4 bytes.
                let counter_0 = carrier.counter_0(&seq);
                let mut enc_mac16 = [0u8; 16];
                enc_mac16[..TP_MAC_LEN].copy_from_slice(wire_mac);
                let (plain, _recovered_mac) =
                    crypto::decrypt_data_ctr(key, &counter_0, &enc_mac16, body);
                // Recompute the expected MAC over the recovered plaintext and
                // compare the encrypted first 4 bytes constant-time.
                let block_0 = carrier.block_0(&seq, plain.len() as u8);
                let mac_cbc = crypto::cbc_mac(key, &[scf_byte], &plain, &block_0);
                let (_enc_payload, enc_mac) =
                    crypto::encrypt_data_ctr(key, &counter_0, &mac_cbc, &plain);
                (plain, crypto::ct_eq(&enc_mac[..TP_MAC_LEN], wire_mac))
            }
        };

        if !ok {
            return Err(SecureError::BadMac);
        }
        Ok(Unwrapped {
            inner_tpdu,
            scf,
            seq,
        })
    }

    /// Commit an accepted receive sequence to the freshness table (spec §5.9):
    /// only call after the inner APDU has been verified and accepted.
    fn commit_rx(&mut self, source: u16, seq: &[u8; 6]) {
        let got = Self::seq_from_bytes(seq);
        let entry = self.rx_last.entry(source).or_insert(self.rx_floor);
        if got > *entry {
            *entry = got;
        }
    }

    /// Unwrap an inbound A_SecureData carried by `carrier` (its full inner TPDU
    /// starts at the SCF byte, i.e. `asdu` is the bytes after the two APCI
    /// bytes). Verifies MAC + freshness and, on success, commits the sequence.
    pub fn unwrap_incoming(
        &mut self,
        carrier: &CemiLData,
        tpci_int: u8,
        asdu: &[u8],
    ) -> Result<Unwrapped, SecureError> {
        let ctx = FrameContext::from_cemi(carrier, tpci_int);
        let source = carrier.source.raw();
        let unwrapped = self.unwrap_with_context(asdu, &ctx, source)?;
        self.commit_rx(source, &unwrapped.seq);
        Ok(unwrapped)
    }

    /// Wrap an outgoing inner TPDU (a device response) into an A_SecureData ASDU,
    /// using the device's own next send sequence. The `carrier` supplies the
    /// address/frame context; `algorithm` selects auth-only vs auth+enc. Advances
    /// the device send sequence. Returns `(asdu_bytes, seq_used)`.
    pub fn wrap_outgoing(
        &mut self,
        carrier: &CemiLData,
        tpci_int: u8,
        algorithm: SecAlgorithm,
        inner_tpdu: &[u8],
    ) -> (Vec<u8>, [u8; 6]) {
        let ctx = FrameContext::from_cemi(carrier, tpci_int);
        let seq = Self::seq_to_bytes(self.tx_seq);
        self.tx_seq = self.tx_seq.wrapping_add(1) & 0xFFFF_FFFF_FFFF;
        let scf = Scf {
            tool_access: true,
            algorithm,
            system_broadcast: false,
            service: SecService::Data,
        };
        let asdu = self.wrap_with_context(scf, &seq, inner_tpdu, &ctx);
        (asdu, seq)
    }

    /// A key-free, plaintext-free one-line description of a secure frame for the
    /// event log (spec §2.3, §12.2 observability): the SCF fields, direction hint
    /// and sequence, plus the inner APCI NAME — never the key, never the full
    /// decrypted payload. `inner_tpdu` is the recovered inner TPDU.
    pub fn describe_frame(direction: &str, scf: Scf, seq: &[u8; 6], inner_tpdu: &[u8]) -> String {
        let inner_apci = crate::wire::apdu::Apdu::parse(inner_tpdu)
            .map(|a| format!("{:?}", a.apci))
            .unwrap_or_else(|| "?".to_string());
        let seq_val = Self::seq_from_bytes(seq);
        let enc = match scf.algorithm {
            SecAlgorithm::AuthOnly => "auth",
            SecAlgorithm::AuthEnc => "auth+enc",
        };
        format!(
            "SECURE {direction} scf=0x{:02x}[{enc},tool={}] seq={seq_val} inner={inner_apci}",
            scf.to_byte(),
            scf.tool_access
        )
    }
}

impl std::fmt::Debug for DataSecureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the key; expose only non-sensitive counters.
        f.debug_struct("DataSecureSession")
            .field("tool_key", &self.tool_key)
            .field("tx_seq", &self.tx_seq)
            .field("require_secure", &self.require_secure)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{IndividualAddress, MessageCode};

    fn carrier(src: u16, dst: u16) -> CemiLData {
        CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress(src),
            dest: dst,
            tpdu: vec![],
        }
    }

    #[test]
    fn test_scf_roundtrip() {
        // The capture SCF bytes (spec §5.2): 0x90 data, 0x92 Sync_Req, 0x93 Sync_Res.
        for byte in [0x90u8, 0x92, 0x93] {
            let scf = Scf::from_byte(byte).expect("known scf");
            assert_eq!(scf.to_byte(), byte, "scf 0x{byte:02x} round-trips");
            assert!(scf.tool_access);
        }
        // 0x90 = tool-access, auth-enc? Bits 6..4 of 0x90 = 001 = AuthEnc.
        let s90 = Scf::from_byte(0x90).unwrap();
        assert_eq!(s90.algorithm, SecAlgorithm::AuthEnc);
        assert_eq!(s90.service, SecService::Data);
        let s92 = Scf::from_byte(0x92).unwrap();
        assert_eq!(s92.service, SecService::SyncReq);
    }

    #[test]
    fn test_wrap_unwrap_roundtrip_auth_enc() -> Result<(), SecureError> {
        let key = Key16::new([0u8; 16]); // synthetic all-zero tool key (spec §3.5)
        let mut dev = DataSecureSession::new(key, 100, 0);
        // Simulate a tool session with a fresh key so it can independently wrap.
        let tool_key = Key16::new([0u8; 16]);
        let mut tool = DataSecureSession::new(tool_key, 5000, 0);

        let c = carrier(0x0000, 0x1102); // tool -> device
        // Inner APDU: A_Authorize_Request 0x3D1 with free key.
        let inner = vec![0x43, 0xd1, 0x00, 0xff, 0xff, 0xff, 0xff];
        let (asdu, _seq) = tool.wrap_outgoing(&c, 0, SecAlgorithm::AuthEnc, &inner);
        // Device unwraps with the same key.
        let un = dev.unwrap_incoming(&c, 0, &asdu)?;
        assert_eq!(un.inner_tpdu, inner);
        assert_eq!(un.scf.algorithm, SecAlgorithm::AuthEnc);
        Ok(())
    }

    #[test]
    fn test_wrap_unwrap_roundtrip_auth_only() -> Result<(), SecureError> {
        let mut dev = DataSecureSession::new(Key16::new([7u8; 16]), 1, 0);
        let mut tool = DataSecureSession::new(Key16::new([7u8; 16]), 9000, 0);
        let c = carrier(0x0000, 0x1102);
        let inner = vec![0x43, 0x80]; // A_Restart bare
        let (asdu, _) = tool.wrap_outgoing(&c, 0, SecAlgorithm::AuthOnly, &inner);
        // Auth-only: the inner APDU rides in the clear inside the ASDU body.
        assert_eq!(&asdu[7..7 + inner.len()], inner.as_slice());
        let un = dev.unwrap_incoming(&c, 0, &asdu)?;
        assert_eq!(un.inner_tpdu, inner);
        Ok(())
    }

    #[test]
    fn test_wrong_mac_refused() {
        let mut dev = DataSecureSession::new(Key16::new([1u8; 16]), 1, 0);
        let mut tool = DataSecureSession::new(Key16::new([2u8; 16]), 9000, 0); // WRONG key
        let c = carrier(0x0000, 0x1102);
        let inner = vec![0x43, 0xd1, 0x00, 0xff, 0xff, 0xff, 0xff];
        let (asdu, _) = tool.wrap_outgoing(&c, 0, SecAlgorithm::AuthEnc, &inner);
        let err = dev.unwrap_incoming(&c, 0, &asdu).unwrap_err();
        assert_eq!(err, SecureError::BadMac);
    }

    #[test]
    fn test_replay_refused() -> Result<(), SecureError> {
        let mut dev = DataSecureSession::new(Key16::new([3u8; 16]), 1, 0);
        let mut tool = DataSecureSession::new(Key16::new([3u8; 16]), 9000, 0);
        let c = carrier(0x0000, 0x1102);
        let inner = vec![0x43, 0x80];
        let (asdu, _) = tool.wrap_outgoing(&c, 0, SecAlgorithm::AuthEnc, &inner);
        // First delivery accepted, commits the sequence.
        dev.unwrap_incoming(&c, 0, &asdu)?;
        // Replaying the SAME frame is refused as stale.
        let err = dev.unwrap_incoming(&c, 0, &asdu).unwrap_err();
        assert!(matches!(err, SecureError::StaleSequence { .. }));
        Ok(())
    }

    #[test]
    fn test_stale_lower_sequence_refused() -> Result<(), SecureError> {
        let mut dev = DataSecureSession::new(Key16::new([4u8; 16]), 1, 0);
        // A tool that starts high, then a second "tool" that replays a low seq.
        let mut tool_hi = DataSecureSession::new(Key16::new([4u8; 16]), 9000, 0);
        let mut tool_lo = DataSecureSession::new(Key16::new([4u8; 16]), 10, 0);
        let c = carrier(0x0000, 0x1102);
        let (hi, _) = tool_hi.wrap_outgoing(&c, 0, SecAlgorithm::AuthEnc, &[0x43, 0x80]);
        dev.unwrap_incoming(&c, 0, &hi)?;
        let (lo, _) = tool_lo.wrap_outgoing(&c, 0, SecAlgorithm::AuthEnc, &[0x43, 0x80]);
        let err = dev.unwrap_incoming(&c, 0, &lo).unwrap_err();
        assert!(matches!(err, SecureError::StaleSequence { .. }));
        Ok(())
    }

    #[test]
    fn test_key16_from_hex() {
        let k = Key16::from_hex("000102030405060708090a0b0c0d0e0f").expect("valid");
        assert_eq!(
            k.bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(Key16::from_hex("tooShort").is_none());
        assert!(Key16::from_hex("zz0102030405060708090a0b0c0d0e0f").is_none());
    }

    #[test]
    fn test_key16_debug_redacts() {
        let k = Key16::new([0xAB; 16]);
        assert_eq!(format!("{k:?}"), "Key16(<redacted>)");
        let s = DataSecureSession::new(Key16::new([0xAB; 16]), 42, 0);
        let d = format!("{s:?}");
        assert!(d.contains("<redacted>"), "session Debug redacts the key");
        assert!(!d.contains("171"), "no raw key byte leaks");
    }

    #[test]
    fn test_describe_frame_never_logs_key_or_plaintext() {
        let scf = Scf::from_byte(0x90).unwrap();
        let seq = [0, 0, 0, 0, 0, 42];
        // Inner: a property write carrying "secret" bytes.
        let inner = vec![0x43, 0xd7, 0x00, 0x0d, 0x50, 0xde, 0xad, 0xbe, 0xef];
        let d = DataSecureSession::describe_frame("recv", scf, &seq, &inner);
        assert!(d.contains("seq=42"));
        assert!(d.contains("PropertyValueWrite"));
        // The plaintext value bytes must NOT appear.
        assert!(!d.contains("deadbeef"));
        assert!(!d.contains("de ad be ef"));
    }
}
