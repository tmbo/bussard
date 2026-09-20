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
