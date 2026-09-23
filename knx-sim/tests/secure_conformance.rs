//! Conformance/calibration of the KNX Data Secure device model (spec §12.2).
//!
//! The knx-sim Secure device model is the executable spec for bussard's Phase A
//! Data Secure tool-access path (spec §12.2): this test *is* the secure tool. It
//! configures a security-ACTIVATED sim device with a SYNTHETIC tool key and a
//! starting sequence, then drives it over a raw-TPDU driver that wraps each
//! management APDU in A_SecureData exactly as spec §5 describes, and asserts:
//!
//! - a correct wrap reaches the inner management service and gets a valid
//!   wrapped response (both `algorithm` modes: auth-only and auth+enc);
//! - a wrong MAC is refused;
//! - a replayed/stale sequence is refused;
//! - a plain (unwrapped) access to a protected function is refused;
//! - a plain device is entirely unchanged (regression).
//!
//! No vendor fixture is needed: the device is built from the in-memory synthetic
//! MDT product, forced to the System B mask so the plain property/memory path is
//! exercised under the secure wrapper. All key material is synthetic; none comes
//! from a user file.

use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::device::{Device, LoadState, ProfileOverrides, SecureActivation};
use knx_sim::secure::{
    A_SECURE_DATA_APCI, DataSecureSession, Key16, Scf, SecAlgorithm, SecService, SecureError,
    Unwrapped,
};
use knx_sim::wire::{Apdu, CemiLData, IndividualAddress, MessageCode};

const DEV: u16 = 0x1102; // 1.1.2
const TOOL: u16 = 0x0000; // the tool's source IA (0.0.0, as ETS/bussard use)

/// The synthetic tool key both sides share. NOT derived from any user file.
const TOOL_KEY_HEX: &str = "0102030405060708090a0b0c0d0e0f10";

/// The device's initial send sequence and receive-freshness floor.
const DEV_TX_SEQ: u64 = 200;
const DEV_RX_FLOOR: u64 = 1000;

/// A secure tool driver: builds an activated device on a bus, holds its own
/// `DataSecureSession` (mirroring bussard's `DataSecureSession` on the tool
/// side) with the shared synthetic key, and wraps every management APDU in
/// A_SecureData before delivering it.
struct SecureTool {
    bus: Bus,
    sink: Arc<RecordingSink>,
    /// The tool's own secure session: wraps outgoing requests, unwraps responses.
    tool: DataSecureSession,
    /// The tool's L4 sequence, threaded through the connected NDTs.
    seq: u8,
    /// The default algorithm for wrapped APDUs (auth-only vs auth+enc).
    algorithm: SecAlgorithm,
}

impl SecureTool {
    fn new(algorithm: SecAlgorithm) -> Self {
        let sink = Arc::new(RecordingSink::new());
        let product = knx_sim::testfixtures::synthetic_mdt_sys7_product();
        let dev = Device::from_product_with_overrides(
            IndividualAddress(DEV),
            &product,
            LoadState::Loaded,
            ProfileOverrides {
                // Force System B so the plain property/memory path is under test,
                // wrapped by the secure layer.
                mask: Some("07B0".into()),
                secure: Some(SecureActivation {
                    tool_key: Key16::from_hex(TOOL_KEY_HEX).expect("valid hex key"),
                    initial_tx_seq: DEV_TX_SEQ,
                    initial_rx_seq: DEV_RX_FLOOR,
                }),
                ..Default::default()
            },
            sink.clone(),
        )
        .expect("activated System B device builds");
        let mut bus = Bus::new(sink.clone());
        bus.add_device(dev);
        // The tool starts its own send sequence above the device's rx floor so
        // its first frame is accepted (spec §5.9).
        let tool = DataSecureSession::new(
            Key16::from_hex(TOOL_KEY_HEX).expect("valid hex key"),
            DEV_RX_FLOOR + 1,
            0,
        );
        SecureTool {
            bus,
            sink,
            tool,
            seq: 0,
            algorithm,
        }
    }

    fn control(&mut self, byte: u8) {
        if byte == 0x80 {
            self.seq = 0;
        }
        self.bus.deliver_from_tool(&cemi_std(TOOL, DEV, vec![byte]));
    }

    /// Build the pure inner application PDU for a plain management APDU: the two
    /// APCI bytes (transport bits cleared) followed by the data. This is the
    /// exact byte form both sides authenticate.
    fn inner_tpdu(apci10: u16, data: &[u8]) -> Vec<u8> {
        let mut t = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
        t.extend_from_slice(data);
        t
    }

    /// Wrap `(apci10, data)` in A_SecureData and deliver it as a connected NDT,
    /// returning any unwrapped inner responses.
    fn secure_ndt(&mut self, apci10: u16, data: &[u8]) -> Vec<Unwrapped> {
        let inner = Self::inner_tpdu(apci10, data);
        // The carrier is the connected NDT toward the device. Derive tpci_int the
        // same way the device will (from the carrier's first TPDU byte) so both
        // sides build the identical CCM nonce.
        let carrier_tpdu = self.ndt_tpdu(A_SECURE_DATA_APCI, &[]);
        let carrier = cemi_std(TOOL, DEV, carrier_tpdu.clone());
        let tpci_int = tpci_int_of(&carrier_tpdu);
        let (asdu, _seq) = self
            .tool
            .wrap_outgoing(&carrier, tpci_int, self.algorithm, &inner);
        // Build the real carrier: connected NDT, APCI = A_SecureData, payload = ASDU.
        let tpdu = self.ndt_tpdu(A_SECURE_DATA_APCI, &asdu);
        let responses = self.bus.deliver_from_tool(&cemi_std(TOOL, DEV, tpdu));
        self.seq = (self.seq + 1) & 0x0F;
        self.unwrap_responses(responses)
    }

    /// Deliver a RAW (already-built) secure carrier without advancing the tool's
    /// sequence — used to inject a wrong-MAC or replayed frame.
    fn deliver_raw_secure(&mut self, asdu: &[u8]) -> Vec<CemiLData> {
        let tpdu = self.ndt_tpdu(A_SECURE_DATA_APCI, asdu);
        let responses = self.bus.deliver_from_tool(&cemi_std(TOOL, DEV, tpdu));
        self.seq = (self.seq + 1) & 0x0F;
        responses
    }

    /// Build a raw secure ASDU for `(apci10, data)` at the tool's current send
    /// sequence, returning `(asdu, carrier_tpci_int)` so a test can tamper with
    /// it before delivery.
    fn build_secure_asdu(&mut self, apci10: u16, data: &[u8]) -> Vec<u8> {
        let inner = Self::inner_tpdu(apci10, data);
        let carrier_tpdu = self.ndt_tpdu(A_SECURE_DATA_APCI, &[]);
        let carrier = cemi_std(TOOL, DEV, carrier_tpdu.clone());
        let tpci_int = tpci_int_of(&carrier_tpdu);
        let (asdu, _seq) = self
            .tool
            .wrap_outgoing(&carrier, tpci_int, self.algorithm, &inner);
        asdu
    }

    /// Deliver a PLAIN (unwrapped) management APDU — should be refused on an
    /// activated device.
    fn plain_ndt(&mut self, apci10: u16, data: &[u8]) -> Vec<CemiLData> {
        let tpdu = self.ndt_tpdu(apci10, data);
        let responses = self.bus.deliver_from_tool(&cemi_std(TOOL, DEV, tpdu));
        self.seq = (self.seq + 1) & 0x0F;
        responses
    }

    /// Build a connected NDT TPDU for `(apci10, payload)` at the current L4 seq.
    fn ndt_tpdu(&self, apci10: u16, payload: &[u8]) -> Vec<u8> {
        let mut tpdu = vec![
            0x40 | ((self.seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
            (apci10 & 0xFF) as u8,
        ];
        tpdu.extend_from_slice(payload);
        tpdu
    }

    /// Unwrap the device's secure responses back to their inner APDUs. A pure
    /// transport ACK (not A_SecureData) is skipped.
    fn unwrap_responses(&mut self, responses: Vec<CemiLData>) -> Vec<Unwrapped> {
        let mut out = Vec::new();
        for resp in responses {
            let Some(apdu) = Apdu::parse(&resp.tpdu) else {
                continue;
            };
            if apdu.apci_raw != A_SECURE_DATA_APCI {
                continue;
            }
            let tpci_int = tpci_int_of(&resp.tpdu);
            match self.tool.unwrap_incoming(&resp, tpci_int, &apdu.data) {
                Ok(un) => out.push(un),
                Err(e) => panic!("tool could not unwrap a device response: {e}"),
            }
        }
        out
    }

    fn rejections(&self) -> Vec<String> {
        self.sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Telegram { summary, .. } if summary.contains("REJECTED") => Some(summary),
                Event::SecureFrame { summary, .. } if summary.contains("refused") => Some(summary),
                _ => None,
            })
            .collect()
    }

    fn secure_events(&self) -> Vec<String> {
        self.sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::SecureFrame { summary, .. } => Some(summary),
                _ => None,
            })
            .collect()
    }
}

/// The CCM nonce `tpci_int` for a carrier TPDU, mirroring the device's
/// `carrier_tpci_int` (spec §5.4): connected data → top 6 bits, else 0.
fn tpci_int_of(tpdu: &[u8]) -> u8 {
    match tpdu.first() {
        Some(b) if b & 0xC0 == 0x40 => (b >> 2) & 0x3F,
        _ => 0,
    }
}

fn cemi_std(src: u16, dst: u16, tpdu: Vec<u8>) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress(src),
        dest: dst,
        tpdu,
    }
}

/// Extract the inner APCI raw value from an unwrapped response.
fn inner_apci_raw(un: &Unwrapped) -> u16 {
    Apdu::parse(&un.inner_tpdu).map(|a| a.apci_raw).unwrap_or(0)
}

/// A correct secure wrap of A_Authorize reaches the inner service and gets a
/// valid wrapped A_Authorize_Response, for auth+enc.
#[test]
fn test_secure_authorize_roundtrip_auth_enc() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80); // T_Connect (plain transport — not a protected function)
    // A_Authorize_Request (0x3D1) with the free key, wrapped in A_SecureData.
    let responses = t.secure_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(responses.len(), 1, "one wrapped response");
    // The inner response is an A_Authorize_Response (0x3D2) granting level 0.
    assert_eq!(inner_apci_raw(&responses[0]), 0x3D2);
    let data = &Apdu::parse(&responses[0].inner_tpdu).unwrap().data;
    assert_eq!(data, &[0x00], "granted access level 0");
    assert!(
        t.rejections().is_empty(),
        "no rejections: {:#?}",
        t.rejections()
    );
}

/// The same round-trip in auth-only mode: the inner APDU rides in the clear
/// inside the ASDU but is still MAC-authenticated.
#[test]
fn test_secure_authorize_roundtrip_auth_only() {
    let mut t = SecureTool::new(SecAlgorithm::AuthOnly);
    t.control(0x80);
    let responses = t.secure_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(responses.len(), 1);
    assert_eq!(inner_apci_raw(&responses[0]), 0x3D2);
    assert!(t.rejections().is_empty());
}

/// A full secured management exchange: authorize, then a property read and a
/// property write, each wrapped and each getting a valid wrapped response.
#[test]
fn test_secure_property_read_and_write() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    t.secure_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]); // authorize level 0

    // A_PropertyValue_Read obj0 pid 0x38 (max APDU) count=1 start=1.
    let reads = t.secure_ndt(0x3D5, &[0x00, 0x38, 0x10, 0x01]);
    assert_eq!(reads.len(), 1);
    assert_eq!(inner_apci_raw(&reads[0]), 0x3D6, "PropertyValue_Response");

    // A_PropertyValue_Write obj0 pid 0x0E (device control) count=1 start=1 = 0x00.
    let writes = t.secure_ndt(0x3D7, &[0x00, 0x0E, 0x10, 0x01, 0x00]);
    assert_eq!(writes.len(), 1);
    assert_eq!(inner_apci_raw(&writes[0]), 0x3D6, "write echo response");
    assert!(t.rejections().is_empty());
}

/// A wrong MAC is refused: tamper the last MAC byte of a correctly-built ASDU
/// and the device drops it (no response), surfacing a secure rejection.
#[test]
fn test_secure_wrong_mac_refused() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    let mut asdu = t.build_secure_asdu(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    let last = asdu.len() - 1;
    asdu[last] ^= 0xFF; // corrupt the MAC
    let responses = t.deliver_raw_secure(&asdu);
    assert!(responses.is_empty(), "a wrong-MAC frame draws no response");
    let rej = t.rejections();
    assert!(
        rej.iter().any(|r| r.contains("MAC")),
        "a wrong MAC is refused: {rej:#?}"
    );
}

/// A replayed frame is refused: deliver a correct frame, then deliver the exact
/// same ASDU again. The second (stale sequence) is dropped.
#[test]
fn test_secure_replay_refused() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    let asdu = t.build_secure_asdu(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    // First delivery accepted.
    let first = t.deliver_raw_secure(&asdu);
    assert_eq!(first.len(), 1, "first secure frame is accepted");
    // Replaying the identical ASDU is refused as stale.
    let second = t.deliver_raw_secure(&asdu);
    assert!(second.is_empty(), "a replayed frame draws no response");
    let rej = t.rejections();
    assert!(
        rej.iter()
            .any(|r| r.contains("stale") || r.contains("replayed")),
        "a replay is refused: {rej:#?}"
    );
}

/// A plain (unwrapped) access to a protected function is refused on an activated
/// device (spec §6.4, §12.2).
#[test]
fn test_secure_plain_access_refused() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    // A PLAIN A_Authorize_Request (not wrapped) — a protected function.
    let responses = t.plain_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    assert!(
        responses.is_empty(),
        "a plain protected access draws no response on an activated device"
    );
    let rej = t.rejections();
    assert!(
        rej.iter()
            .any(|r| r.contains("PLAIN") || r.contains("Secure")),
        "plain access to a protected function is refused: {rej:#?}"
    );
}

/// The secure event log names direction, SCF, sequence and the inner APCI, and
/// NEVER logs the key or the decrypted plaintext of a key-bearing payload.
#[test]
fn test_secure_event_log_redacts() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    t.secure_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    // Write a distinctive "secret" byte pattern via a property write.
    t.secure_ndt(0x3D7, &[0x00, 0x0E, 0x10, 0x01, 0xAB]);
    let events = t.secure_events();
    assert!(!events.is_empty(), "secure frames are observed");
    // The synthetic tool key bytes must never appear.
    for ev in &events {
        assert!(!ev.contains("0102030405"), "key material leaked: {ev}");
        // The written plaintext value (0xAB) must not be dumped.
        assert!(
            !ev.to_lowercase().contains(" ab "),
            "plaintext leaked: {ev}"
        );
    }
    // At least one frame decodes an inner APCI name.
    assert!(
        events.iter().any(|e| e.contains("Authorize")),
        "inner APCI name is logged: {events:#?}"
    );
}

/// Regression: a PLAIN device (no security block) is entirely unchanged — a
/// plain authorize succeeds exactly as before, with no secure interception.
#[test]
fn test_plain_device_unchanged() {
    let sink = Arc::new(RecordingSink::new());
    let product = knx_sim::testfixtures::synthetic_mdt_sys7_product();
    let dev = Device::from_product_with_overrides(
        IndividualAddress(DEV),
        &product,
        LoadState::Loaded,
        ProfileOverrides {
            mask: Some("07B0".into()),
            secure: None, // PLAIN
            ..Default::default()
        },
        sink.clone(),
    )
    .expect("plain device builds");
    let mut bus = Bus::new(sink.clone());
    bus.add_device(dev);

    // T_Connect then a PLAIN A_Authorize_Request — accepted, level 0.
    bus.deliver_from_tool(&cemi_std(TOOL, DEV, vec![0x80]));
    let auth = cemi_std(TOOL, DEV, vec![0x43, 0xd1, 0x00, 0xff, 0xff, 0xff, 0xff]);
    let responses = bus.deliver_from_tool(&auth);
    assert_eq!(responses.len(), 1, "plain authorize produces a response");
    let apdu = Apdu::parse(&responses[0].tpdu).expect("parses");
    assert_eq!(apdu.apci_raw, 0x3D2, "plain A_Authorize_Response");
    // No secure frames observed on a plain device.
    let secure_events: Vec<_> = sink
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::SecureFrame { .. }))
        .collect();
    assert!(
        secure_events.is_empty(),
        "a plain device emits no secure frames"
    );
}

/// The SCF byte the sim wraps a management response with is the capture's
/// tool-access data form (0x90 for auth+enc), asserting the exact wire byte.
#[test]
fn test_secure_response_scf_is_tool_access_data() {
    let scf = Scf {
        tool_access: true,
        algorithm: SecAlgorithm::AuthEnc,
        system_broadcast: false,
        service: SecService::Data,
    };
    // Spec §5.2: 0x90 = tool-access secure data (auth+enc).
    assert_eq!(scf.to_byte(), 0x90);
}

/// A SecureError surfaces as the expected variant when the device unwraps a bad
/// frame directly (a focused unit-level assertion complementing the bus tests).
#[test]
fn test_secure_error_variants() {
    // Too-short ASDU.
    let mut dev = DataSecureSession::new(Key16::from_hex(TOOL_KEY_HEX).unwrap(), 1, 0);
    let carrier = cemi_std(TOOL, DEV, vec![]);
    let err = dev.unwrap_incoming(&carrier, 0, &[0x90, 0x00]).unwrap_err();
    assert!(matches!(err, SecureError::TooShort { .. }));
}

/// SHARED KNOWN-ANSWER VECTOR (spec §12.1).
///
/// bussard's independent Data Secure implementation encodes the same inputs in
/// `crates/bussard-secure/src/asdu.rs` (`test_known_answer_vector_matches_the_sim`)
/// and must produce these exact bytes. Keeping the literal on both sides makes a
/// CCM/nonce divergence fail a plain `cargo test` on whichever side drifted,
/// without the other implementation being present — it is what the #71
/// conformance loop found the hard way (the `block_0` TPCI octet of §5.4, and
/// the auth-only payload-length field).
///
/// Inputs: synthetic tool key `000102…0F`, sequence 42, a numbered data telegram
/// 1.1.1 → 1.1.2 (TPCI octet `0x42`, i.e. `tpci_int` `0x10`), inner APDU
/// `A_Authorize_Request` (`0x3D1`) with the free-access key.
#[test]
fn test_shared_known_answer_vector() {
    const KAT_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const SRC: u16 = 0x1101; // 1.1.1
    const DST: u16 = 0x1102; // 1.1.2
    /// The inner APDU as it is authenticated: APCI high bits only in octet 0 (the
    /// carrier's transport-control bits are not part of the secured APDU).
    const KAT_INNER: [u8; 7] = [0x03, 0xD1, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
    /// auth+enc: the payload keystream starts right after the 4 MAC bytes (the
    /// ETS layout, secure-1-1-12 capture 2026-09-23).
    const KAT_AUTH_ENC: [u8; 18] = [
        0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0xFB, 0xB8, 0x72, 0x5D, 0x14, 0x5F, 0xBE, 0x98,
        0xA5, 0x3D, 0xA2,
    ];
    const KAT_AUTH_ONLY: [u8; 18] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x03, 0xD1, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xB5,
        0xA4, 0x6C, 0x9F,
    ];
    // The carrier's TPCI octet 0x42 (numbered data, sequence 0) is `tpci_int`
    // 0x10 in the nonce (spec §5.4's `(tpci_int << 2) + 0x03`).
    const TPCI_INT: u8 = 0x42 >> 2;

    let carrier = cemi_std(SRC, DST, vec![0x42, 0xF1]);
    for (alg, expected) in [
        (SecAlgorithm::AuthEnc, KAT_AUTH_ENC),
        (SecAlgorithm::AuthOnly, KAT_AUTH_ONLY),
    ] {
        // A session whose send sequence starts exactly at the vector's 42.
        let mut tool =
            DataSecureSession::new(Key16::from_hex(KAT_KEY_HEX).expect("synthetic key"), 42, 0);
        let (asdu, seq) = tool.wrap_outgoing(&carrier, TPCI_INT, alg, &KAT_INNER);
        assert_eq!(seq, [0, 0, 0, 0, 0, 42], "the vector's sequence");
        assert_eq!(
            asdu,
            expected.to_vec(),
            "{alg:?} A_SecureData bytes diverged from the shared vector"
        );
        // And the vector verifies and unwraps on the device side.
        let mut dev =
            DataSecureSession::new(Key16::from_hex(KAT_KEY_HEX).expect("synthetic key"), 1, 0);
        let un = dev
            .unwrap_incoming(&carrier, TPCI_INT, &expected)
            .expect("the vector verifies");
        assert_eq!(un.inner_tpdu, KAT_INNER.to_vec());
    }
}

/// The device answers a connection-oriented S-A_Sync_Req the way the real
/// device does in the secure-1-1-12 capture (2026-09-23), and the tool's first
/// S-A_Data may then carry the request's own sequence.
///
/// The request and response are built and checked here straight from the crypto
/// primitives, independent of the device model's Sync code:
/// Sync_Req = `0x92 || seq || serial(0) || enc(challenge) || MAC`, nonce = seq,
/// AD = `SCF || serial`; Sync_Res = `0x93 || nonce^challenge || enc(dev seq ||
/// tool seq) || MAC`, AD = `SCF`.
#[test]
fn test_secure_sync_handshake() -> Result<(), String> {
    use knx_sim::secure::crypto;
    let key_bytes: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);

    // The tool's clock seed is BELOW the device's freshness floor: the Sync must
    // hand back floor + 1.
    let req_seq: u64 = DEV_RX_FLOOR - 500;
    let seq6 = |v: u64| -> [u8; 6] {
        let b = v.to_be_bytes();
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    };
    let nonce_blocks = |seq: [u8; 6], src: u16, dst: u16, tpci: u8, len: u8| {
        let mut b0 = [0u8; 16];
        b0[..6].copy_from_slice(&seq);
        b0[6..8].copy_from_slice(&src.to_be_bytes());
        b0[8..10].copy_from_slice(&dst.to_be_bytes());
        b0[12] = (tpci & 0xFC) | 0x03;
        b0[13] = 0xF1;
        b0[15] = len;
        let mut c0 = [0u8; 16];
        c0[..10].copy_from_slice(&b0[..10]);
        c0[14] = 0x01;
        (b0, c0)
    };

    let challenge = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6];
    let tpci = 0x40 | (t.seq << 2) | 0x03;
    let (b0, c0) = nonce_blocks(seq6(req_seq), TOOL, DEV, tpci, 6);
    let mut ad = vec![0x92];
    ad.extend_from_slice(&[0u8; 6]);
    let mac = crypto::cbc_mac(&key_bytes, &ad, &challenge, &b0);
    let (enc_challenge, enc_mac) = crypto::encrypt_data_ctr(&key_bytes, &c0, &mac[..4], &challenge);
    let mut asdu = vec![0x92];
    asdu.extend_from_slice(&seq6(req_seq));
    asdu.extend_from_slice(&[0u8; 6]);
    asdu.extend_from_slice(&enc_challenge);
    asdu.extend_from_slice(&enc_mac);

    let responses = t.deliver_raw_secure(&asdu);
    assert_eq!(
        responses.len(),
        1,
        "one S-A_Sync_Res: {:#?}",
        t.secure_events()
    );
    let resp = &responses[0];
    let apdu = Apdu::parse(&resp.tpdu).ok_or("response parses")?;
    assert_eq!(apdu.apci_raw, A_SECURE_DATA_APCI);
    let res = &apdu.data;
    assert_eq!(res.len(), 1 + 6 + 12 + 4);
    assert_eq!(res[0], 0x93, "SCF of S-A_Sync_Res");
    let mut nonce = [0u8; 6];
    for i in 0..6 {
        nonce[i] = res[1 + i] ^ challenge[i];
    }
    let (rb0, rc0) = nonce_blocks(nonce, DEV, TOOL, resp.tpdu[0], 12);
    let (plain, _) = crypto::decrypt_data_ctr(&key_bytes, &rc0, &res[19..23], &res[7..19]);
    let rmac = crypto::cbc_mac(&key_bytes, &[0x93], &plain, &rb0);
    let (_, expected) = crypto::encrypt_data_ctr(&key_bytes, &rc0, &rmac[..4], &[]);
    assert_eq!(&expected[..], &res[19..23], "the Sync_Res MAC verifies");
    assert_eq!(
        &plain[..6],
        &seq6(DEV_TX_SEQ),
        "device reports its own next seq"
    );
    assert_eq!(
        &plain[6..],
        &seq6(DEV_RX_FLOOR + 1),
        "device tells the tool to jump past its freshness floor"
    );
    assert!(t.rejections().is_empty(), "{:#?}", t.rejections());

    // A Sync_Req under the wrong key is refused without an answer.
    let mut bad = asdu.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    assert!(t.deliver_raw_secure(&bad).is_empty());
    Ok(())
}

// --- Security interface object (IOT 17) over the extended property services ---

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Decode a hex string with optional spaces.
fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

/// The plain APDU of an unwrapped response: the two APCI octets (10-bit APCI,
/// transport bits cleared) followed by the data, the form the capture shows.
fn plain_apdu(un: &Unwrapped) -> Vec<u8> {
    let mut v = un.inner_tpdu.clone();
    if let Some(b) = v.first_mut() {
        *b &= 0x03;
    }
    v
}

impl SecureTool {
    /// Send a plain APDU given as capture hex (`APCI APCI data...`) wrapped in
    /// A_SecureData and return the single unwrapped response as a plain APDU.
    fn secure_hex(&mut self, apdu_hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let apdu = hex(apdu_hex)?;
        let apci10 = (u16::from(apdu[0] & 0x03) << 8) | u16::from(apdu[1]);
        let responses = self.secure_ndt(apci10, &apdu[2..]);
        let [one] = responses.as_slice() else {
            return Err(format!("expected one response, got {}", responses.len()).into());
        };
        Ok(plain_apdu(one))
    }

    /// Load a System B table object (`obj`, base `base`) with `image` through
    /// PID 5 plus A_MemoryExtended_Write, all wrapped in A_SecureData, and
    /// verify the image with A_MemoryExtended_Read.
    fn load_table_extended(&mut self, obj: u8, base: u32, image: &[u8]) -> TestResult {
        self.secure_ndt(0x3D7, &[obj, 0x05, 0x10, 0x01, 0x01]); // StartLoading
        self.secure_ndt(
            0x3D7,
            &[obj, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ); // allocate 256
        let [a2, a1, a0] = [(base >> 16) as u8, (base >> 8) as u8, base as u8];
        let mut write = vec![image.len() as u8, a2, a1, a0];
        write.extend_from_slice(image);
        let resp = self.secure_hex(&format!("01fb {}", to_hex(&write)))?;
        assert_eq!(resp, [vec![0x01, 0xfc, 0x00, a2, a1, a0]].concat());
        let read = self.secure_hex(&format!(
            "01fd {:02x} {a2:02x}{a1:02x}{a0:02x}",
            image.len()
        ))?;
        assert_eq!(
            read,
            [vec![0x01, 0xfe, 0x00, a2, a1, a0], image.to_vec()].concat()
        );
        self.secure_ndt(0x3D7, &[obj, 0x05, 0x10, 0x01, 0x02]); // LoadCompleted
        Ok(())
    }

    fn secobj_events(&self) -> Vec<String> {
        self.sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::SecurityObject { summary, .. } => Some(summary),
                _ => None,
            })
            .collect()
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The ETS-order security-object load, byte-exact against the decrypted capture,
/// driven end to end through A_SecureData on an activated device.
#[test]
fn test_security_object_ets_sequence_over_secure_data() -> TestResult {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    t.secure_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);

    let unload = "01d4 0011 001005 04000000000000000000";
    let start = "01d4 0011 001005 01000000000000000000";
    let complete = "01d4 0011 001005 02000000000000000000";
    assert_eq!(t.secure_hex(unload)?, hex("01d6 0011 001005 00 00")?);
    assert_eq!(t.secure_hex(start)?, hex("01d6 0011 001005 00 02")?);
    assert_eq!(
        t.secure_hex("01ce 0011 001036 01 0000 0000")?,
        hex("01cf 0011 001036 01 0000 00")?
    );
    let key_row = format!("01ce 0011 001035 01 0001 0001 {}", "a5".repeat(16));
    assert_eq!(t.secure_hex(&key_row)?, hex("01cf 0011 001035 01 0001 00")?);
    let first = format!("01ce 0011 00103d d3 0001 {}", "03".repeat(211));
    assert_eq!(t.secure_hex(&first)?, hex("01cf 0011 00103d d3 0001 00")?);
    assert_eq!(t.secure_hex(complete)?, hex("01d6 0011 001005 00 01")?);
    assert_eq!(
        t.secure_hex("01d4 0011 001033 000001")?,
        hex("01d6 0011 001033 00 00")?
    );
    assert!(t.rejections().is_empty(), "{:#?}", t.rejections());

    let events = t.secobj_events();
    assert!(
        events.contains(
            &"SECOBJ WriteCon iot=17/1 pid=61 start=1 count=211 rc=0x00 state=Loading".into()
        ),
        "{events:#?}"
    );
    assert!(
        events.contains(
            &"SECOBJ FunctionCommand iot=17/1 pid=5 event=LoadCompleted rc=0x00 state=Loaded"
                .into()
        ),
        "{events:#?}"
    );
    for e in &events {
        assert!(!e.contains("a5a5"), "key bytes leaked: {e}");
    }
    Ok(())
}

/// A plain (unwrapped) extended property service to an activated device is
/// refused like every other management service.
#[test]
fn test_security_object_plain_access_refused() {
    let mut t = SecureTool::new(SecAlgorithm::AuthEnc);
    t.control(0x80);
    let responses = t.plain_ndt(
        0x1D4,
        &[
            0x00, 0x11, 0x00, 0x10, 0x05, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    assert!(responses.is_empty());
    assert!(t.rejections().iter().any(|r| r.contains("PLAIN")));
    assert!(t.secobj_events().is_empty());
}

/// The device derives its limits from its own loaded tables: the address table
/// length bounds PID 53 indices and the group-object table count bounds PID 61.
/// The tables are written with A_MemoryExtended_Write inside A_SecureData.
#[test]
fn test_security_object_limits_follow_loaded_tables() -> TestResult {
    let mut t = SecureTool::new(SecAlgorithm::AuthOnly);
    t.control(0x80);
    t.secure_ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    // Address table (obj 1 at 0xA000): 3 group addresses.
    t.load_table_extended(1, 0xA000, &hex("0003 0801 0802 0803")?)?;
    // Group-object table (obj 3 at 0x8000): 2 descriptors.
    t.load_table_extended(3, 0x8000, &hex("0002 0000 0000")?)?;

    t.secure_hex("01d4 0011 001005 01000000000000000000")?;
    let row = |index: u16| format!("01ce 0011 001035 01 0001 {index:04x} {}", "a5".repeat(16));
    assert_eq!(t.secure_hex(&row(4))?, hex("01cf 0011 001035 01 0001 f7")?);
    assert_eq!(t.secure_hex(&row(3))?, hex("01cf 0011 001035 01 0001 00")?);
    assert_eq!(
        t.secure_hex("01ce 0011 00103d 03 0001 030303")?,
        hex("01cf 0011 00103d 03 0001 f7")?
    );
    assert_eq!(
        t.secure_hex("01ce 0011 00103d 02 0001 0300")?,
        hex("01cf 0011 00103d 02 0001 00")?
    );
    // The element count of PID 61 is the group-object count.
    assert_eq!(
        t.secure_hex("01cc 0011 00103d 01 0000")?,
        hex("01cd 0011 00103d 01 0000 0002")?
    );
    assert!(t.rejections().is_empty(), "{:#?}", t.rejections());
    Ok(())
}
