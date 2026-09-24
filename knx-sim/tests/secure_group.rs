//! KNX Data Secure GROUP communication on an activated sim device (issue #172).
//!
//! The test is both the flashing tool and the secured group peer. It builds a
//! security-activated System B device, loads its address / association /
//! group-object tables and its security interface object (a PID 53 group key
//! for 1/2/3 at address-table index 2, a PID 61 flag on object 1) through
//! A_SecureData tool access, exactly the way `bussard flash --keyring` does, and
//! then talks secured group traffic to it with frames built by the sim's own
//! `seal_group` / `open_group`:
//!
//! - a secured GroupValueWrite is accepted and updates the object,
//! - a secured GroupValueRead is answered with a secured GroupValueResponse,
//! - a wrong group key and a replayed sequence are refused with a log reason,
//! - a plain GroupValueRead to the secured object is ignored with a log reason,
//!   while the unsecured object on 1/2/1 still answers plain,
//! - a stimulus on the secured object sends a secured GroupValueWrite.
//!
//! All key material is synthetic. No vendor fixture is needed.

use std::sync::Arc;

use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::bus::{Bus, StimulusJob};
use knx_sim::device::{Device, LoadState, ProfileOverrides, SecureActivation, flag};
use knx_sim::secure::{
    A_SECURE_DATA_APCI, DataSecureSession, Key16, SecAlgorithm, Unwrapped, open_group, seal_group,
};
use knx_sim::wire::{Apdu, CemiLData, IndividualAddress, MessageCode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DEV: u16 = 0x110A; // 1.1.10
const TOOL: u16 = 0x0000; // the flashing tool
const PEER: u16 = 0x1101; // 1.1.1, the secured group peer
const GA_PLAIN: u16 = 0x0A01; // 1/2/1, object 2, unsecured
const GA_SECURE: u16 = 0x0A03; // 1/2/3, object 1, secured

/// The synthetic tool key of 1.1.10 in `examples/secure/synthetic.knxkeys`.
const TOOL_KEY: [u8; 16] = [0x42; 16];
/// A synthetic group key for 1/2/3 (NOT the keyring's; any key works here).
const GROUP_KEY: [u8; 16] = [
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
];
const DEV_RX_FLOOR: u64 = 1000;
/// The peer's sequence in the device's security individual address table.
const PEER_SEQ: u64 = 1500;
/// A sender the security individual address table does not list.
const STRANGER: u16 = 0x1102; // 1.1.2

/// The flashing tool plus the group peer around one activated device on a bus.
struct Rig {
    bus: Bus,
    sink: Arc<RecordingSink>,
    tool: DataSecureSession,
    seq: u8,
}

fn cemi(src: u16, dst: u16, group: bool, tpdu: Vec<u8>) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: if group { 0xe0 } else { 0x60 },
        source: IndividualAddress(src),
        dest: dst,
        tpdu,
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

impl Rig {
    /// Build the activated device and program it: tables plus security object.
    fn programmed() -> Result<Self, Box<dyn std::error::Error>> {
        let sink = Arc::new(RecordingSink::new());
        let product = knx_sim::testfixtures::synthetic_mdt_sys7_product();
        let dev = Device::from_product_with_overrides(
            IndividualAddress(DEV),
            &product,
            LoadState::Loaded,
            ProfileOverrides {
                mask: Some("07B0".into()),
                secure: Some(SecureActivation {
                    tool_key: Key16::new(TOOL_KEY),
                    initial_tx_seq: 300,
                    initial_rx_seq: DEV_RX_FLOOR,
                }),
                ..Default::default()
            },
            sink.clone(),
        )?;
        let mut bus = Bus::new(sink.clone());
        bus.add_device(dev);
        let mut rig = Rig {
            bus,
            sink,
            tool: DataSecureSession::new(Key16::new(TOOL_KEY), DEV_RX_FLOOR + 1, 0),
            seq: 0,
        };
        rig.bus
            .deliver_from_tool(&cemi(TOOL, DEV, false, vec![0x80]));
        rig.mgmt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff])?;

        // Address table: 1/2/1 (TSAP 1), 1/2/3 (TSAP 2).
        rig.load_table(1, 0xA000, &hex("0002 0a01 0a03")?)?;
        // Association table: TSAP 2 -> object 1, TSAP 1 -> object 2.
        rig.load_table(2, 0xC000, &hex("0002 0002 0001 0001 0002")?)?;
        // Group-object table: object 1 C+R+W+T (4-bit), object 2 C+R+W.
        let crwt = flag::COMMUNICATION | flag::READ | flag::WRITE | flag::TRANSMIT;
        let crw = flag::COMMUNICATION | flag::READ | flag::WRITE;
        let mut go = vec![0x00, 0x02];
        go.extend_from_slice(&(crwt | 0x03).to_be_bytes());
        go.extend_from_slice(&(crw | 0x07).to_be_bytes());
        rig.load_table(3, 0x8000, &go)?;

        // Security object: StartLoading, PID 54 clear and one row (the peer
        // 1.1.1, sequence 1500), PID 53 row (index 2 = 1/2/3, group key), PID 61
        // flags (object 1 secured), LoadCompleted.
        rig.secobj(
            "01d4 0011 001005 01000000000000000000",
            "01d6 0011 001005 00 02",
        )?;
        rig.secobj(
            "01ce 0011 001036 01 0000 0000",
            "01cf 0011 001036 01 0000 00",
        )?;
        rig.secobj(
            &format!("01ce 0011 001036 01 0001 {PEER:04x} {PEER_SEQ:012x}"),
            "01cf 0011 001036 01 0001 00",
        )?;
        rig.secobj(
            &format!("01ce 0011 001035 01 0001 0002 {}", to_hex(&GROUP_KEY)),
            "01cf 0011 001035 01 0001 00",
        )?;
        rig.secobj(
            "01ce 0011 00103d 02 0001 0300",
            "01cf 0011 00103d 02 0001 00",
        )?;
        rig.secobj(
            "01d4 0011 001005 02000000000000000000",
            "01d6 0011 001005 00 01",
        )?;
        rig.bus
            .deliver_from_tool(&cemi(TOOL, DEV, false, vec![0x81]));
        Ok(rig)
    }

    /// One secured management APDU; returns the unwrapped responses.
    fn mgmt(
        &mut self,
        apci10: u16,
        data: &[u8],
    ) -> Result<Vec<Unwrapped>, Box<dyn std::error::Error>> {
        let mut inner = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
        inner.extend_from_slice(data);
        let head = 0x40 | ((self.seq & 0x0F) << 2);
        let tpci_int = (head >> 2) & 0x3F;
        let carrier = cemi(TOOL, DEV, false, vec![head | 0x03, 0xF1]);
        let (asdu, _) = self
            .tool
            .wrap_outgoing(&carrier, tpci_int, SecAlgorithm::AuthEnc, &inner);
        let mut tpdu = carrier.tpdu.clone();
        tpdu.extend_from_slice(&asdu);
        let responses = self.bus.deliver_from_tool(&cemi(TOOL, DEV, false, tpdu));
        self.seq = (self.seq + 1) & 0x0F;
        let mut out = Vec::new();
        for resp in responses {
            let Some(apdu) = Apdu::parse(&resp.tpdu) else {
                continue;
            };
            if apdu.apci_raw != A_SECURE_DATA_APCI {
                continue;
            }
            let tpci_int = (resp.tpdu[0] >> 2) & 0x3F;
            out.push(self.tool.unwrap_incoming(&resp, tpci_int, &apdu.data)?);
        }
        Ok(out)
    }

    /// A security-object request given as hex, asserting the exact response.
    fn secobj(&mut self, req: &str, want: &str) -> TestResult {
        let apdu = hex(req)?;
        let apci10 = (u16::from(apdu[0] & 0x03) << 8) | u16::from(apdu[1]);
        let resp = self.mgmt(apci10, &apdu[2..])?;
        let [one] = resp.as_slice() else {
            return Err(format!("expected one response to {req}, got {}", resp.len()).into());
        };
        let mut got = one.inner_tpdu.clone();
        got[0] &= 0x03;
        assert_eq!(to_hex(&got), to_hex(&hex(want)?), "response to {req}");
        Ok(())
    }

    /// Load a table object through PID 5 + A_MemoryExtended_Write.
    fn load_table(&mut self, obj: u8, base: u32, image: &[u8]) -> TestResult {
        self.mgmt(0x3D7, &[obj, 0x05, 0x10, 0x01, 0x01])?;
        self.mgmt(
            0x3D7,
            &[obj, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        )?;
        let mut write = vec![
            image.len() as u8,
            (base >> 16) as u8,
            (base >> 8) as u8,
            base as u8,
        ];
        write.extend_from_slice(image);
        self.mgmt(0x1FB, &write)?;
        self.mgmt(0x3D7, &[obj, 0x05, 0x10, 0x01, 0x02])?;
        Ok(())
    }

    /// Put a group telegram on the bus from the peer; return the device's replies.
    fn group(&mut self, ga: u16, tpdu: Vec<u8>) -> Vec<CemiLData> {
        self.bus
            .deliver_from_tool(&cemi(PEER, ga, true, tpdu))
            .into_iter()
            .filter(|r| r.source == IndividualAddress(DEV))
            .collect()
    }

    /// A secured group telegram from the peer with `key` at `seq`.
    fn secure_group(
        &mut self,
        key: &Key16,
        alg: SecAlgorithm,
        seq: u64,
        inner: &[u8],
    ) -> Vec<CemiLData> {
        self.secure_group_from(PEER, key, alg, seq, inner)
    }

    /// A secured group telegram from `src` with `key` at `seq`.
    fn secure_group_from(
        &mut self,
        src: u16,
        key: &Key16,
        alg: SecAlgorithm,
        seq: u64,
        inner: &[u8],
    ) -> Vec<CemiLData> {
        let mut tpdu = vec![0x03, 0xF1];
        tpdu.extend_from_slice(&seal_group(key, alg, seq, src, GA_SECURE, inner));
        self.bus
            .deliver_from_tool(&cemi(src, GA_SECURE, true, tpdu))
            .into_iter()
            .filter(|r| r.source == IndividualAddress(DEV))
            .collect()
    }

    fn object_value(&self, object: u16) -> Option<Vec<u8>> {
        self.bus
            .device(IndividualAddress(DEV))?
            .group_comm()?
            .object(object)
            .map(|o| o.value.clone())
    }

    fn secure_lines(&self) -> Vec<String> {
        self.sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::SecureFrame { summary, .. } if summary.contains("group") => Some(summary),
                _ => None,
            })
            .collect()
    }

    fn has_line(&self, needle: &str) -> bool {
        self.secure_lines().iter().any(|l| l.contains(needle))
    }
}

/// Open a device-originated secured group telegram to 1/2/3.
fn open_reply(reply: &CemiLData) -> Result<Unwrapped, Box<dyn std::error::Error>> {
    assert_eq!(&reply.tpdu[..2], &[0x03, 0xF1], "reply is A_SecureData");
    assert_eq!(reply.dest, GA_SECURE);
    Ok(open_group(
        &Key16::new(GROUP_KEY),
        reply.source.raw(),
        reply.dest,
        &reply.tpdu[2..],
    )?)
}

#[test]
fn test_secure_group_write_then_read_answered_secured() -> TestResult {
    let mut rig = Rig::programmed()?;
    let key = Key16::new(GROUP_KEY);

    // Secured GroupValueWrite (small, value 9): accepted, no reply.
    let replies = rig.secure_group(&key, SecAlgorithm::AuthEnc, 2001, &[0x00, 0x89]);
    assert!(replies.is_empty());
    assert_eq!(rig.object_value(1), Some(vec![0x09]));
    assert!(
        rig.has_line(
            "SECURE group recv 1.1.1 -> 1/2/3 scf=0x10[auth+enc] seq=2001 inner=GroupValueWrite ok"
        ),
        "{:#?}",
        rig.secure_lines()
    );

    // Secured GroupValueRead: answered with a secured GroupValueResponse.
    let replies = rig.secure_group(&key, SecAlgorithm::AuthEnc, 2002, &[0x00, 0x00]);
    let [reply] = replies.as_slice() else {
        return Err(format!("expected one reply, got {replies:?}").into());
    };
    let un = open_reply(reply)?;
    assert_eq!(un.scf.to_byte(), 0x10);
    assert_eq!(un.inner_tpdu, vec![0x00, 0x49], "GroupValueResponse of 9");
    assert!(rig.has_line(
        "SECURE group recv 1.1.1 -> 1/2/3 scf=0x10[auth+enc] seq=2002 inner=GroupValueRead ok"
    ));
    assert!(rig.has_line("SECURE group send 1.1.10 -> 1/2/3 scf=0x10[auth+enc] seq="));
    assert!(rig.has_line("inner=GroupValueResponse"));

    // Auth-only is answered auth-only (SCF 0x00).
    let replies = rig.secure_group(&key, SecAlgorithm::AuthOnly, 2003, &[0x00, 0x00]);
    let [reply] = replies.as_slice() else {
        return Err(format!("expected one reply, got {replies:?}").into());
    };
    let un2 = open_reply(reply)?;
    assert_eq!(un2.scf.to_byte(), 0x00);
    assert!(
        u64::from_be_bytes([
            0, 0, un2.seq[0], un2.seq[1], un2.seq[2], un2.seq[3], un2.seq[4], un2.seq[5]
        ]) > u64::from_be_bytes([
            0, 0, un.seq[0], un.seq[1], un.seq[2], un.seq[3], un.seq[4], un.seq[5]
        ]),
        "the device's send sequence increases"
    );
    Ok(())
}

#[test]
fn test_secure_group_wrong_key_and_replay_refused() -> TestResult {
    let mut rig = Rig::programmed()?;
    let wrong = Key16::new([0xEE; 16]);
    let replies = rig.secure_group(&wrong, SecAlgorithm::AuthEnc, 3000, &[0x00, 0x81]);
    assert!(replies.is_empty());
    assert_eq!(
        rig.object_value(1),
        Some(vec![]),
        "a refused write changes nothing"
    );
    assert!(
        rig.has_line("REJECTED SECURE group recv 1.1.1 -> 1/2/3: MAC verification failed"),
        "{:#?}",
        rig.secure_lines()
    );

    let key = Key16::new(GROUP_KEY);
    assert!(
        rig.secure_group(&key, SecAlgorithm::AuthEnc, 3001, &[0x00, 0x00])
            .len()
            == 1
    );
    assert!(
        rig.secure_group(&key, SecAlgorithm::AuthEnc, 3001, &[0x00, 0x00])
            .is_empty()
    );
    assert!(rig.has_line(
        "REJECTED SECURE group recv 1.1.1 -> 1/2/3: stale/replayed sequence 3001 (last seen 3001)"
    ));
    // Below the receive floor for a fresh source is stale too.
    assert!(
        rig.secure_group(&key, SecAlgorithm::AuthEnc, 42, &[0x00, 0x00])
            .is_empty()
    );
    Ok(())
}

#[test]
fn test_secure_group_plain_read_to_secured_object_ignored() -> TestResult {
    let mut rig = Rig::programmed()?;
    // Plain GroupValueRead to the secured 1/2/3: ignored with a reason.
    assert!(rig.group(GA_SECURE, vec![0x00, 0x00]).is_empty());
    assert!(
        rig.has_line(
            "IGNORED PLAIN group GroupValueRead 1.1.1 -> 1/2/3: group object 1 requires KNX Data Secure"
        ),
        "{:#?}",
        rig.secure_lines()
    );
    // A plain write is ignored as well: the value stays unset.
    assert!(rig.group(GA_SECURE, vec![0x00, 0x81]).is_empty());
    assert_eq!(rig.object_value(1), Some(vec![]));
    // The unsecured object on 1/2/1 still answers plain.
    let replies = rig.group(GA_PLAIN, vec![0x00, 0x00]);
    let [reply] = replies.as_slice() else {
        return Err(format!("expected one plain reply, got {replies:?}").into());
    };
    assert_eq!(reply.tpdu, vec![0x00, 0x40], "plain GroupValueResponse");
    Ok(())
}

#[test]
fn test_secure_group_stimulus_sends_secured_write() -> TestResult {
    let mut rig = Rig::programmed()?;
    let key = Key16::new(GROUP_KEY);
    rig.secure_group(&key, SecAlgorithm::AuthEnc, 4000, &[0x00, 0x8C]);

    // No scripted values: the object's current value (12) is re-sent, secured.
    rig.bus.set_stimulus(vec![StimulusJob {
        device: IndividualAddress(DEV),
        object: 1,
        period_ms: 5000,
        values: vec![],
        next_due_ms: 0,
        cursor: 0,
    }]);
    let out = rig.bus.tick_stimulus(0);
    let [write] = out.as_slice() else {
        return Err(format!("expected one stimulus telegram, got {out:?}").into());
    };
    let un = open_reply(write)?;
    assert_eq!(un.scf.to_byte(), 0x10);
    assert_eq!(
        un.inner_tpdu,
        vec![0x00, 0x8C],
        "secured GroupValueWrite of 12"
    );
    assert!(rig.has_line("SECURE group send 1.1.10 -> 1/2/3 scf=0x10[auth+enc] seq="));
    assert!(rig.has_line("inner=GroupValueWrite"));
    // Not due again before the period.
    assert!(rig.bus.tick_stimulus(4999).is_empty());

    // A scripted value is sealed the same way and becomes the object's value.
    rig.bus.set_stimulus(vec![StimulusJob {
        device: IndividualAddress(DEV),
        object: 1,
        period_ms: 5000,
        values: vec![vec![0x05]],
        next_due_ms: 0,
        cursor: 0,
    }]);
    let out = rig.bus.tick_stimulus(0);
    let [write] = out.as_slice() else {
        return Err(format!("expected one stimulus telegram, got {out:?}").into());
    };
    assert_eq!(open_reply(write)?.inner_tpdu, vec![0x00, 0x85]);
    assert_eq!(rig.object_value(1), Some(vec![0x05]));
    Ok(())
}

/// The security individual address table (PID 54) gates secured group
/// telegrams (issue #181): an unlisted sender is dropped even with the right
/// group key, and a listed sender's sequence must exceed its table entry.
#[test]
fn test_secure_group_unlisted_sender_and_table_sequence_refused() -> TestResult {
    let mut rig = Rig::programmed()?;
    let key = Key16::new(GROUP_KEY);
    let replies = rig.secure_group_from(STRANGER, &key, SecAlgorithm::AuthEnc, 5000, &[0x00, 0x81]);
    assert!(replies.is_empty());
    assert_eq!(
        rig.object_value(1),
        Some(vec![]),
        "a dropped write changes nothing"
    );
    assert!(
        rig.has_line(
            "REJECTED SECURE group recv 1.1.2 -> 1/2/3: sender not in the security individual \
             address table (PID 54)"
        ),
        "{:#?}",
        rig.secure_lines()
    );
    // Above the receive floor (1000) but not above the peer's entry (1500).
    assert!(
        rig.secure_group(&key, SecAlgorithm::AuthEnc, 1200, &[0x00, 0x81])
            .is_empty()
    );
    assert!(rig.has_line(
        "REJECTED SECURE group recv 1.1.1 -> 1/2/3: sequence 1200 not above the PID 54 entry 1500"
    ));
    assert_eq!(rig.object_value(1), Some(vec![]));
    // Above it: accepted.
    rig.secure_group(&key, SecAlgorithm::AuthEnc, 1501, &[0x00, 0x81]);
    assert_eq!(rig.object_value(1), Some(vec![0x01]));
    Ok(())
}
