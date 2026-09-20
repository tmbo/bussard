//! M2 calibration/replay: the real ETS 6 -> Jung 3361-1M System 7 flash.
//!
//! The knx-sim System 7 device is the executable spec (`docs/system7-spec.md`
//! §9). This test replays the *exact* request-direction TPDU stream ETS 6 sent to
//! a real Jung 3361-1M (mask 0705, app `M-0004_A-A011`) — captured in the M2
//! session (issue #70) and distilled to `tests/fixtures/sys7_jung_flash_requests.txt`
//! — against a sim Jung device driven by the **property (PID-5) LSM** (the M2
//! verdict on the wire). It is the property-LSM analogue of `ets_calibration.rs`
//! (which replays the DA.tp System B capture).
//!
//! The Jung `.knxprod` is copyrighted vendor data and is NOT committed; it is read
//! at runtime from the product-corpus cache and the test skips cleanly when
//! absent. The request TPDU fixture IS committed (it carries no real individual
//! address — the device address is rewritten to 1.1.5).

use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::device::{Device, LoadState, LsmAccess, ProfileOverrides};
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

/// The committed request-TPDU fixture (M2 capture, request direction).
const FIXTURE: &str = include_str!("fixtures/sys7_jung_flash_requests.txt");

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

/// Build a bus with a Jung 3361-1M (mask 0705) device at 1.1.5 starting Unloaded,
/// driven by the property (PID-5) LSM. Returns `None` if the vendor product is
/// absent from the corpus cache so the test can skip.
fn jung_bus(sink: Arc<RecordingSink>) -> Option<Bus> {
    let bytes = knx_sim::testfixtures::jung_3361_knxprod()?;
    let pd = read_knxprod_bytes(&bytes, Some("M-0004_A-A011-13-60BC-O000A"))
        .expect("read Jung 3361-1M product");
    let dev = Device::from_product_with_overrides(
        IndividualAddress(DEV),
        &pd,
        LoadState::Unloaded,
        ProfileOverrides {
            mask: None, // MV-0705 from the product
            lsm_access: LsmAccess::Property,
            bcu_key: None,
            prog_mode: false,
        },
        sink.clone(),
    )
    .expect("Jung System 7 device builds");
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    Some(bus)
}

#[test]
fn test_sim_replays_jung_m2_property_flash_to_loaded() {
    let sink = Arc::new(RecordingSink::new());
    let Some(mut bus) = jung_bus(sink.clone()) else {
        eprintln!(
            "SKIP: Jung 3361-1M .knxprod not in the product-corpus cache at {}; \
             run tests-support/product-corpus/fetch.sh to enable this test",
            knx_sim::testfixtures::jung_3361_knxprod_path().display()
        );
        return;
    };

    // Replay every captured request TPDU in order (the whole M2 flash).
    for (src, dst, tpdu) in parse_requests() {
        let _ = bus.deliver_from_tool(&cemi(src, dst, tpdu));
    }

    // No telegram in the real ETS sequence was rejected by the property device.
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
        "sim rejected part of ETS's real Jung flash (property LSM): {rejections:#?}"
    );

    // All three parallel LSMs reached Loaded via the property (PID-5) path.
    let dev = bus.device(IndividualAddress(DEV)).expect("device present");
    for lsm in [1u8, 2, 3] {
        assert_eq!(
            dev.load_state(lsm),
            Some(LoadState::Loaded),
            "LSM {lsm} did not reach Loaded after the M2 Jung flash"
        );
    }

    // The M2 capture's first segment write was 0x4000 <- 01 (a single byte); the
    // application image begins there.
    assert_eq!(dev.memory().read(0x4000, 1), &[0x01]);
    // 0x41FF <- 00 (the LSM 2 table region's first byte).
    assert_eq!(dev.memory().read(0x41FF, 1), &[0x00]);
    // 0x43FF began the LSM 3 param image: c8 07 f9 07.
    assert_eq!(dev.memory().read(0x43FF, 4), &[0xc8, 0x07, 0xf9, 0x07]);
}
