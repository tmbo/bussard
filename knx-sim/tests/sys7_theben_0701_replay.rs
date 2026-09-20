//! Calibration/replay: the real ETS -> Theben Meteodata System 7 (mask 0701)
//! MEMORY-MAPPED flash.
//!
//! The knx-sim System 7 device is the executable spec (`docs/system7-spec.md`
//! §5/§9). This is the 0701-family, memory-mapped counterpart of
//! `sys7_jung_m2_replay.rs` (which replays the Jung 0705 *property* flash): it
//! replays the request-direction TPDU stream ETS sent to a real Theben Meteodata
//! 1409207 (mask 0701, app `M-0048_A-140C`) — captured in
//! `shared-with-windows/meteodata-140-s-download.pcapng` and distilled to
//! `tests/fixtures/sys7_theben_0701_flash_requests.txt` — against a sim device
//! driven by the **memory-mapped LSM** (the real 0701 verdict on the wire: 11-octet
//! records written to `0x0104`, status at `0xB6EA+`, zero PID-5 traffic).
//!
//! No vendor `.knxprod` is needed: the device is built from the in-memory
//! synthetic MDT-canonical product with a `0701` mask override and the
//! memory-mapped realisation, so the fixture exercises the exact 11-octet
//! record-decode path on a fresh device. (The Theben Meteodata `.knxprod` is not
//! in the corpus; the committed fixture carries only the load-control shape with
//! the real IA rewritten to 1.1.5.)

use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::device::{Device, LoadState, LsmAccess, ProfileOverrides};
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

/// The committed request-TPDU fixture (Theben 0701 capture, request direction).
const FIXTURE: &str = include_str!("fixtures/sys7_theben_0701_flash_requests.txt");

/// The device address the fixture targets (1.1.5; the real IA was rewritten out).
const DEV: u16 = 0x1105;

/// Parse the request-TPDU fixture into `(src, dst, tpdu)` tuples.
fn parse_requests() -> Vec<(u16, u16, Vec<u8>)> {
    let mut out = Vec::new();
    for line in FIXTURE.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let src = u16::from_str_radix(parts.next().expect("src field"), 16).expect("src hex");
        let dst = u16::from_str_radix(parts.next().expect("dst field"), 16).expect("dst hex");
        let tpdu = hex(parts.next().expect("tpdu field"));
        out.push((src, dst, tpdu));
    }
    out
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("tpdu hex digit"))
        .collect()
}

fn cemi(src: u16, dst: u16, tpdu: Vec<u8>) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc, // standard frame
        ctrl2: 0x60,
        source: IndividualAddress(src),
        dest: dst,
        tpdu,
    }
}

/// Build a bus with a memory-mapped System 7 (mask 0701) device at 1.1.5 starting
/// Unloaded. Uses the synthetic MDT-canonical product (three LSMs) with a `0701`
/// mask override — no vendor fixture required, so this test never skips.
fn theben_0701_bus(sink: Arc<RecordingSink>) -> Bus {
    let pd = knx_sim::testfixtures::synthetic_mdt_sys7_product();
    let dev = Device::from_product_with_overrides(
        IndividualAddress(DEV),
        &pd,
        LoadState::Unloaded,
        ProfileOverrides {
            mask: Some("0701".into()),
            lsm_access: LsmAccess::MemoryMapped,
            bcu_key: None,
            prog_mode: false,
        },
        sink.clone(),
    )
    .expect("Theben 0701 memory-mapped System 7 device builds");
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    bus
}

#[test]
fn test_sim_replays_theben_0701_memory_mapped_flash_to_loaded() {
    let sink = Arc::new(RecordingSink::new());
    let mut bus = theben_0701_bus(sink.clone());

    // Replay every captured request TPDU in order (the whole memory-mapped flash).
    for (src, dst, tpdu) in parse_requests() {
        let _ = bus.deliver_from_tool(&cemi(src, dst, tpdu));
    }

    // No telegram in ETS's real Theben 0701 sequence was rejected/dropped by the
    // memory-mapped device — the 11-octet records at 0x0104 are all accepted.
    let rejections: Vec<String> = sink
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Telegram { summary, .. }
                if summary.contains("REJECTED") || summary.contains("DROPPED") =>
            {
                Some(summary)
            }
            _ => None,
        })
        .collect();
    assert!(
        rejections.is_empty(),
        "sim rejected/dropped part of ETS's real Theben 0701 memory-mapped flash: {rejections:#?}"
    );

    // All three parallel LSMs reached Loaded via the memory-mapped (0x0104) path.
    let dev = bus.device(IndividualAddress(DEV)).expect("device present");
    for lsm in [1u8, 2, 3] {
        assert_eq!(
            dev.load_state(lsm),
            Some(LoadState::Loaded),
            "LSM {lsm} did not reach Loaded after the Theben 0701 memory-mapped flash"
        );
    }
}
