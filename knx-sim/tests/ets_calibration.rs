//! Calibration/validation against the real ETS→KNX-Virtual flash capture.
//!
//! The key result: the simulator, loaded with the DA.tp `.knxprod`
//! (`M-00FA_A-2500-10-51CB`, mask MV-07B0 = System B), must ACCEPT the exact
//! management sequence ETS sent to flash the real device (captured in
//! `dumpfile.pcap`, distilled to request TPDUs in
//! `tests/fixtures/ets_da_tp_flash_requests.txt`) and reach `Loaded` on all four
//! loadable objects — while REJECTING deliberate deviations.
//!
//! This is the independent cross-check: the simulator was built from the KNX
//! spec, the Wireshark dissector and the capture, not from the tool's code, so
//! agreement on the wire is meaningful.

use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::device::{Device, LoadState};
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

// The ETS request-TPDU stream is a committed text fixture. The DA.tp `.knxprod`
// is a vendor file that is NOT committed (git-ignores `*.knxprod`); it is loaded
// at runtime and the tests skip cleanly if it is absent.
const FIXTURE_FLASH: &str = include_str!("fixtures/ets_da_tp_flash_requests.txt");

/// Parse the request-TPDU fixture into `(src, dst, tpdu)` tuples.
fn parse_requests() -> Vec<(u16, u16, Vec<u8>)> {
    let mut out = Vec::new();
    for line in FIXTURE_FLASH.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let src = u16::from_str_radix(parts.next().unwrap(), 16).unwrap();
        let dst = u16::from_str_radix(parts.next().unwrap(), 16).unwrap();
        let tpdu = hex(parts.next().unwrap());
        out.push((src, dst, tpdu));
    }
    out
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn cemi(src: u16, dst: u16, tpdu: Vec<u8>) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress(src),
        dest: dst,
        tpdu,
    }
}

/// Build a bus with the DA.tp device at 1.1.2, starting `Loaded` (the real
/// device was already programmed before ETS re-flashed it). Returns `None` if
/// the (un-committed) `.knxprod` fixture is not present so the test can skip.
fn da_tp_bus(sink: Arc<RecordingSink>) -> Option<Bus> {
    let fixture = knx_sim::testfixtures::da_tp_knxprod()?;
    let pd =
        read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB")).expect("read DA.tp product");
    let dev = Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        sink.clone(),
    );
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    Some(bus)
}

/// Skip a test if the DA.tp fixture is absent, else yield the bus.
macro_rules! bus_or_skip {
    ($sink:expr) => {
        match da_tp_bus($sink) {
            Some(bus) => bus,
            None => {
                eprintln!("SKIP: DA.tp fixture not present; place it in tests/fixtures/");
                return;
            }
        }
    };
}

#[test]
fn test_sim_accepts_ets_flash_and_reaches_loaded() {
    let sink = Arc::new(RecordingSink::new());
    let mut bus = bus_or_skip!(sink.clone());
    let addr = IndividualAddress::new(1, 1, 2);

    // Replay every captured request TPDU in order.
    for (src, dst, tpdu) in parse_requests() {
        // Only telegrams addressed to the device (or its broadcast) matter; the
        // bus handles addressing.
        let _ = bus.deliver_from_tool(&cemi(src, dst, tpdu));
    }

    // Assert: no telegram in the whole ETS sequence was REJECTED by the device.
    let rejections: Vec<String> = sink
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Telegram { summary, .. } if summary.contains("REJECTED") => Some(summary),
            _ => None,
        })
        .collect();
    assert!(
        rejections.is_empty(),
        "simulator rejected part of ETS's real flash sequence: {rejections:#?}"
    );

    // Assert: all four loadable objects reached Loaded.
    let dev = bus.device(addr).expect("device present");
    for obj in [1u8, 2, 3, 4] {
        assert_eq!(
            dev.load_state(obj),
            Some(LoadState::Loaded),
            "object {obj} did not reach Loaded after the ETS flash"
        );
    }

    // Assert: the application segment carries ETS's exact bytes at 0x6000. The
    // first captured write to obj4 begins `05 05 ff ff ...`.
    let mem = dev.memory();
    assert_eq!(
        &mem.read(0x6000, 4),
        &[0x05, 0x05, 0xff, 0xff],
        "application image at 0x6000 does not match ETS's write"
    );
    // The com-object table at 0x8000 begins `00 49 17 00`.
    assert_eq!(&mem.read(0x8000, 4), &[0x00, 0x49, 0x17, 0x00]);
    // The association table at 0xC000 begins `00 05 00 01`.
    assert_eq!(&mem.read(0xC000, 4), &[0x00, 0x05, 0x00, 0x01]);
    // The address table at 0xA000 begins `00 05 00 01`.
    assert_eq!(&mem.read(0xA000, 4), &[0x00, 0x05, 0x00, 0x01]);
}

#[test]
fn test_sim_rejects_memory_write_to_wrong_object() {
    // Take the real flash prefix up to the point object 4 is allocated at
    // 0x6000, then inject a memory write to 0x8000 (a different object's base)
    // while only object 4's segment is open. A strict device must reject it.
    let sink = Arc::new(RecordingSink::new());
    let mut bus = bus_or_skip!(sink.clone());

    // Drive: connect, authorize, unload obj4, start-loading obj4, allocate 256.
    // (PID5 writes use the 10-octet load-event value, zero-padded, as ETS does.)
    let seq: Vec<Vec<u8>> = vec![
        hex("80"),                               // T_Connect
        hex("4bd100ffffffff"),                   // Authorize FF FF FF FF
        hex("4fd70405100104000000000000000000"), // PID5 obj4 = Unload
        hex("4fd70405100101000000000000000000"), // PID5 obj4 = StartLoading
        hex("4fd704051001030b0000010000000000"), // PID5 obj4 = RelSegment 256
    ];
    for tpdu in seq {
        bus.deliver_from_tool(&cemi(0x0000, 0x1102, tpdu));
    }

    // Now the deliberate deviation: A_MemoryWrite of 4 bytes at 0x8000. The
    // com-object table owns 0x8000 but is NOT open/Loading; only object 4's
    // segment at 0x6000 is open. A strict device must reject this.
    // TPDU: 0x42 = TPCI connected + APCI hi bits; 0x84 = A_MemoryWrite count 4;
    // 80 00 = address; then 4 data bytes.
    let mut t = vec![0x42u8, 0x84, 0x80, 0x00];
    t.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    bus.deliver_from_tool(&cemi(0x0000, 0x1102, t));

    let rejected = sink.events().into_iter().any(|e| match e {
        Event::Telegram { summary, .. } => summary.contains("REJECTED"),
        _ => false,
    });
    assert!(
        rejected,
        "simulator accepted a memory write to the wrong object's base"
    );
}

#[test]
fn test_sim_rejects_load_completed_without_start() {
    // A strict device must reject LoadCompleted issued from Unloaded (no
    // StartLoading first).
    let sink = Arc::new(RecordingSink::new());
    // Start Unloaded so the object is genuinely not in Loading.
    let Some(fixture) = knx_sim::testfixtures::da_tp_knxprod() else {
        eprintln!("SKIP: DA.tp fixture not present");
        return;
    };
    let pd = read_knxprod_bytes(&fixture, None).expect("prod");
    let dev = Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Unloaded,
        sink.clone(),
    );
    let mut bus = Bus::new(sink.clone());
    bus.add_device(dev);

    bus.deliver_from_tool(&cemi(0x0000, 0x1102, hex("80")));
    bus.deliver_from_tool(&cemi(0x0000, 0x1102, hex("4bd100ffffffff")));
    // PID5 obj4 = LoadCompleted (0x02) with no StartLoading.
    bus.deliver_from_tool(&cemi(
        0x0000,
        0x1102,
        hex("4fd70405100102000000000000000000"),
    ));

    let rejected = sink.events().into_iter().any(|e| match e {
        Event::Telegram { summary, .. } => summary.contains("REJECTED"),
        _ => false,
    });
    assert!(
        rejected,
        "simulator accepted LoadCompleted without StartLoading"
    );
    assert_ne!(
        bus.device(IndividualAddress::new(1, 1, 2))
            .and_then(|d| d.load_state(4)),
        Some(LoadState::Loaded)
    );
}
