//! Conformance/calibration of the System 7 (mask 0705) device model.
//!
//! The knx-sim System 7 device is the executable spec (per
//! `docs/system7-spec.md` §9): this test *is* the ETS side. It encodes the
//! canonical MDT `M-0083_A-000E` op sequence as raw TPDUs and drives the sim to
//! `Loaded` on all three parallel LSMs, for BOTH LsmAccess realisations
//! (memory-mapped and property-based) — mirroring how `ets_calibration.rs`
//! replays a capture for System B. A negative test proves a wrong-order
//! TaskSegment / a write before StartLoading does NOT reach Loaded.
//!
//! No vendor fixture is needed: the device is built from an in-memory synthetic
//! MDT-canonical product (`testfixtures::synthetic_mdt_sys7_product`).

use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Direction, Event, RecordingSink};
use knx_sim::device::{Device, LoadState, LsmAccess, ProfileOverrides};
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

const DEV: u16 = 0x1105; // 1.1.5

/// A tiny L4 sequence counter mirroring what a real tool threads through its
/// numbered data telegrams. Reset on every T_Connect.
struct Driver {
    bus: Bus,
    sink: Arc<RecordingSink>,
    seq: u8,
}

impl Driver {
    fn new(lsm_access: LsmAccess) -> Self {
        let sink = Arc::new(RecordingSink::new());
        let product = knx_sim::testfixtures::synthetic_mdt_sys7_product();
        let dev = Device::from_product_with_overrides(
            IndividualAddress(DEV),
            &product,
            LoadState::Unloaded,
            ProfileOverrides {
                mask: None, // mask comes from the product (MV-0705)
                lsm_access,
                bcu_key: None,
            },
            sink.clone(),
        )
        .expect("System 7 device builds");
        let mut bus = Bus::new(sink.clone());
        bus.add_device(dev);
        Driver { bus, sink, seq: 0 }
    }

    /// Send a bare control frame (T_Connect 0x80 / T_Disconnect 0x81).
    fn control(&mut self, byte: u8) {
        if byte == 0x80 {
            self.seq = 0;
        }
        self.bus
            .deliver_from_tool(&cemi_std(0x0000, DEV, vec![byte]));
    }

    /// Send a numbered data telegram with the given 10-bit APCI and payload,
    /// threading the current L4 sequence. Standard frame.
    fn ndt(&mut self, apci10: u16, payload: &[u8]) {
        let mut tpdu = vec![
            0x40 | ((self.seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
            (apci10 & 0xFF) as u8,
        ];
        tpdu.extend_from_slice(payload);
        self.bus.deliver_from_tool(&cemi_std(0x0000, DEV, tpdu));
        self.seq = (self.seq + 1) & 0x0F;
    }

    fn authorize_free(&mut self) {
        self.ndt(0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    }

    /// A_MemoryWrite of `payload` at `addr` (count = payload.len()).
    fn mem_write(&mut self, addr: u16, payload: &[u8]) {
        let apci10 = 0x280 | (payload.len() as u16 & 0x3F);
        let mut data = addr.to_be_bytes().to_vec();
        data.extend_from_slice(payload);
        self.ndt(apci10, &data);
    }

    fn device(&self) -> &Device {
        self.bus
            .device(IndividualAddress(DEV))
            .expect("device present")
    }

    fn rejections(&self) -> Vec<String> {
        self.sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Telegram { summary, .. } if summary.contains("REJECTED") => Some(summary),
                _ => None,
            })
            .collect()
    }
}

fn cemi_std(src: u16, dst: u16, tpdu: Vec<u8>) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc, // standard frame (bit 7 set)
        ctrl2: 0x60,
        source: IndividualAddress(src),
        dest: dst,
        tpdu,
    }
}

/// The 10-octet abstract load-event record for one op (spec §4).
mod event {
    /// StartLoading.
    pub fn start() -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0] = 0x01;
        r
    }
    /// LoadCompleted.
    pub fn completed() -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0] = 0x02;
        r
    }
    /// Unload.
    pub fn unload() -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0] = 0x04;
        r
    }
    /// AbsSegment allocate (Data subtype 0x00): [03][00][start:2][len:2][...].
    pub fn alloc_data(start: u16, len: u16) -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0] = 0x03;
        r[1] = 0x00;
        r[2..4].copy_from_slice(&start.to_be_bytes());
        r[4..6].copy_from_slice(&len.to_be_bytes());
        r
    }
    /// TaskSegment finalize, encoded as AllocAbsTaskSegment (subtype 0x02).
    pub fn task_segment(addr: u16, len: u16) -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0] = 0x03;
        r[1] = 0x02;
        r[2..4].copy_from_slice(&addr.to_be_bytes());
        r[4..6].copy_from_slice(&len.to_be_bytes());
        r
    }
}

/// The two LSM-access realisations differ only in how a load event reaches the
/// device: this trait lets the canonical sequence be written once and driven
/// against both.
trait LsmDriver {
    /// Send one load event to the given LSM index.
    fn send_event(driver: &mut Driver, lsm: u8, event: &[u8; 10]);
}

/// Memory-mapped: a 12-octet record `[lsm][00][event 10]` at the control addr.
struct MemMapped;
impl LsmDriver for MemMapped {
    fn send_event(driver: &mut Driver, lsm: u8, event: &[u8; 10]) {
        let mut rec = vec![lsm, 0x00];
        rec.extend_from_slice(event);
        driver.mem_write(0x0104, &rec);
    }
}

/// Property-based: a PID 5 write of the 10-octet event to the LSM object.
struct PropBased;
impl LsmDriver for PropBased {
    fn send_event(driver: &mut Driver, lsm: u8, event: &[u8; 10]) {
        // A_PropertyValue_Write obj=lsm pid=5 count=1 start=1, then the event.
        let mut data = vec![lsm, 0x05, 0x10, 0x01];
        data.extend_from_slice(event);
        driver.ndt(0x3D7, &data);
    }
}

/// Drive the canonical MDT `M-0083_A-000E` sequence to Loaded on LSM 1/2/3.
fn drive_canonical<L: LsmDriver>(driver: &mut Driver) {
    driver.control(0x80); // T_Connect
    driver.authorize_free();

    // Preflight: read object-0 PID 78 and (the tool would) compare. We just read.
    driver.ndt(0x3D5, &[0x00, 0x4E, 0x10, 0x01]);

    // Tear down all three LSMs.
    for lsm in [1u8, 2, 3] {
        L::send_event(driver, lsm, &event::unload());
    }

    // LSM 1: table region at 0x4000, size 513.
    L::send_event(driver, 1, &event::start());
    L::send_event(driver, 1, &event::alloc_data(0x4000, 513));
    stream_segment(driver, 0x4000, 513);
    L::send_event(driver, 1, &event::task_segment(0x4000, 513));
    L::send_event(driver, 1, &event::completed());

    // LSM 2: table region at 0x4201, size 511.
    L::send_event(driver, 2, &event::start());
    L::send_event(driver, 2, &event::alloc_data(0x4201, 511));
    stream_segment(driver, 0x4201, 511);
    L::send_event(driver, 2, &event::task_segment(0x4201, 511));
    L::send_event(driver, 2, &event::completed());

    // LSM 3: params. 0x0700 alloc-only (no data), 0x4400 param image.
    L::send_event(driver, 3, &event::start());
    L::send_event(driver, 3, &event::alloc_data(0x0700, 48)); // alloc-only
    L::send_event(driver, 3, &event::alloc_data(0x4400, 92));
    stream_segment(driver, 0x4400, 92);
    L::send_event(driver, 3, &event::task_segment(0x4400, 92));
    L::send_event(driver, 3, &event::completed());

    driver.control(0x81); // T_Disconnect
}

/// Stream `len` bytes to `addr` in <=12-octet chunks (spec section 6). The
/// payload is a deterministic ramp so the written image is checkable.
fn stream_segment(driver: &mut Driver, addr: u16, len: u16) {
    let mut off = 0u16;
    while off < len {
        let chunk = (len - off).min(12) as usize;
        let bytes: Vec<u8> = (0..chunk).map(|i| (off as usize + i) as u8).collect();
        driver.mem_write(addr + off, &bytes);
        off += chunk as u16;
    }
}

#[test]
fn test_sys7_memory_mapped_reaches_loaded() {
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    drive_canonical::<MemMapped>(&mut d);

    assert!(
        d.rejections().is_empty(),
        "memory-mapped canonical sequence was rejected: {:#?}",
        d.rejections()
    );
    for lsm in [1u8, 2, 3] {
        assert_eq!(
            d.device().load_state(lsm),
            Some(LoadState::Loaded),
            "LSM {lsm} did not reach Loaded (memory-mapped)"
        );
    }
    // The first bytes of the 0x4000 image are the ramp we streamed.
    assert_eq!(&d.device().memory().read(0x4000, 4), &[0, 1, 2, 3]);
    // The 0x0700 alloc-only region was allocated but never written.
    assert_eq!(d.device().memory().read(0x0700, 4), &[0, 0, 0, 0]);
}

#[test]
fn test_sys7_property_based_reaches_loaded() {
    let mut d = Driver::new(LsmAccess::Property);
    drive_canonical::<PropBased>(&mut d);

    assert!(
        d.rejections().is_empty(),
        "property-based canonical sequence was rejected: {:#?}",
        d.rejections()
    );
    for lsm in [1u8, 2, 3] {
        assert_eq!(
            d.device().load_state(lsm),
            Some(LoadState::Loaded),
            "LSM {lsm} did not reach Loaded (property-based)"
        );
    }
}

#[test]
fn test_sys7_dd0_reports_true_mask() {
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    d.control(0x80);
    // A_DeviceDescriptor_Read type 0.
    d.ndt(0x300, &[]);
    // The device's response (ToTool) carries the DD0 descriptor; its trailing
    // two bytes are the mask 0x0705.
    let resp = d
        .sink
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Telegram {
                cemi,
                direction: Direction::ToTool,
                ..
            } => Some(cemi),
            _ => None,
        })
        .next_back();
    let bytes = resp.expect("a response telegram");
    let dd0 = &bytes[bytes.len() - 2..];
    assert_eq!(dd0, &[0x07, 0x05], "DD0 must report the true System 7 mask");
}

#[test]
fn test_sys7_load_completed_without_start_does_not_reach_loaded() {
    // Negative: a write before StartLoading (LoadCompleted straight from
    // Unloaded) must be rejected and must NOT reach Loaded.
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    d.control(0x80);
    d.authorize_free();
    // LoadCompleted on LSM 1 with no StartLoading.
    MemMapped::send_event(&mut d, 1, &event::completed());
    assert!(
        !d.rejections().is_empty(),
        "LoadCompleted-before-Start must be rejected"
    );
    assert_ne!(d.device().load_state(1), Some(LoadState::Loaded));
}

#[test]
fn test_sys7_wrong_order_task_segment_does_not_reach_loaded() {
    // Negative: LoadCompleted with no committed TaskSegment must not reach
    // Loaded. Drive Start + an alloc (no task-segment), then LoadCompleted.
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    d.control(0x80);
    d.authorize_free();
    MemMapped::send_event(&mut d, 1, &event::start());
    MemMapped::send_event(&mut d, 1, &event::alloc_data(0x4000, 8));
    d.mem_write(0x4000, &[0, 0, 0, 0, 0, 0, 0, 0]);
    // LoadCompleted with no TaskSegment committed.
    MemMapped::send_event(&mut d, 1, &event::completed());
    assert!(
        !d.rejections().is_empty(),
        "LoadCompleted without a TaskSegment must be rejected"
    );
    assert_ne!(d.device().load_state(1), Some(LoadState::Loaded));
}

#[test]
fn test_sys7_extended_frame_memory_write_is_refused() {
    // Wire strictness: an A_Memory_Write on an EXTENDED frame to a System 7
    // device is refused (the trap for a 63-byte-chunk tool).
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    d.control(0x80);
    d.authorize_free();
    MemMapped::send_event(&mut d, 1, &event::start());
    MemMapped::send_event(&mut d, 1, &event::alloc_data(0x4000, 64));
    // Extended frame: ctrl1 bit 7 clear (0x3c). A_MemoryWrite count 12 (apci10
    // 0x28C): the TPCI byte carries the connected-data seq and the two APCI high
    // bits; the second byte is the APCI low byte.
    let apci10: u16 = 0x280 | 12;
    let mut tpdu = vec![
        0x40 | ((d.seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
        (apci10 & 0xFF) as u8,
        0x40,
        0x00,
    ];
    tpdu.extend_from_slice(&[0u8; 12]);
    let mut frame = cemi_std(0x0000, DEV, tpdu);
    frame.ctrl1 = 0x3c; // extended
    d.bus.deliver_from_tool(&frame);
    d.seq = (d.seq + 1) & 0x0F;
    assert!(
        d.rejections()
            .iter()
            .any(|r| r.contains("wire-strictness") || r.contains("extended")),
        "extended-frame memory write must be refused: {:#?}",
        d.rejections()
    );
}

#[test]
fn test_sys7_thirteen_octet_memory_write_is_refused() {
    // Wire strictness: a memory op carrying more than 12 data octets is refused.
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    d.control(0x80);
    d.authorize_free();
    MemMapped::send_event(&mut d, 1, &event::start());
    MemMapped::send_event(&mut d, 1, &event::alloc_data(0x4000, 64));
    // 13-octet write (count 13, standard frame).
    d.mem_write(0x4000, &[0u8; 13]);
    assert!(
        d.rejections().iter().any(|r| r.contains("wire-strictness")),
        "13-octet memory write must be refused: {:#?}",
        d.rejections()
    );
}

#[test]
fn test_sys7_participates_on_the_bus_after_loaded() {
    // After Loaded, the System 7 device self-parses its own written S7-format
    // tables and participates on the bus. Flash minimal but real tables: an
    // address table + group-object table in the LSM 1 region (0x4000) and an
    // association table in the LSM 2 region (0x4201), wiring one readable object
    // (asap 0) to GA 1/0/1, then read that GA and expect a response.
    let mut d = Driver::new(LsmAccess::MemoryMapped);
    d.control(0x80);
    d.authorize_free();

    // LSM 1: address table at 0x4000 then group-object table at 0x4100.
    MemMapped::send_event(&mut d, 1, &event::start());
    MemMapped::send_event(&mut d, 1, &event::alloc_data(0x4000, 513));
    // Address table: CNT=2 (own IA + 1 GA), own IA 1.1.5, GA1 = 1/0/1 (0x0801).
    let mut addr_tbl = vec![2u8];
    addr_tbl.extend_from_slice(&DEV.to_be_bytes());
    addr_tbl.extend_from_slice(&0x0801u16.to_be_bytes());
    write_chunked(&mut d, 0x4000, &addr_tbl);
    // Group-object table immediately after the address table (5 bytes → 0x4005):
    // CNT=1, RAM-flags ptr 0x0700, one descriptor asap0 = COMM|READ (CONFIG
    // C|R = 0x0C). The sim derives this base from the address-table length.
    let go_tbl = vec![1u8, 0x07, 0x00, 0x00, 0x00, 0x0C, 0x00];
    write_chunked(&mut d, 0x4000 + addr_tbl.len() as u16, &go_tbl);
    MemMapped::send_event(&mut d, 1, &event::task_segment(0x4000, 513));
    MemMapped::send_event(&mut d, 1, &event::completed());

    // LSM 2: association table at 0x4201: CNT=1, (TSAP1, ASAP0).
    MemMapped::send_event(&mut d, 2, &event::start());
    MemMapped::send_event(&mut d, 2, &event::alloc_data(0x4201, 511));
    write_chunked(&mut d, 0x4201, &[1u8, 1, 0]);
    MemMapped::send_event(&mut d, 2, &event::task_segment(0x4201, 511));
    MemMapped::send_event(&mut d, 2, &event::completed());

    assert!(
        d.rejections().is_empty(),
        "flashing real S7 tables was rejected: {:#?}",
        d.rejections()
    );
    // The device should now be linked: it has a reconstructed group_comm with the
    // readable object wired to 1/0/1.
    let gc = d
        .device()
        .group_comm()
        .expect("device is linked after Loaded");
    assert!(
        gc.object(0).expect("asap0").is_readable(),
        "asap0 must be readable from the parsed S7 tables"
    );
}

/// Write `bytes` to `addr` in <=12-octet chunks (like `stream_segment` but for a
/// caller-supplied image).
fn write_chunked(driver: &mut Driver, addr: u16, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + 12).min(bytes.len());
        driver.mem_write(addr + off as u16, &bytes[off..end]);
        off = end;
    }
}

#[test]
fn test_sys7_unauthorized_memory_write_is_refused() {
    // A memory write before A_Authorize on a keyed device is refused.
    let sink = Arc::new(RecordingSink::new());
    let product = knx_sim::testfixtures::synthetic_mdt_sys7_product();
    let dev = Device::from_product_with_overrides(
        IndividualAddress(DEV),
        &product,
        LoadState::Unloaded,
        ProfileOverrides {
            mask: None,
            lsm_access: LsmAccess::MemoryMapped,
            bcu_key: Some(0x1234_5678),
        },
        sink.clone(),
    )
    .expect("keyed System 7 device builds");
    let mut bus = Bus::new(sink.clone());
    bus.add_device(dev);
    let mut d = Driver { bus, sink, seq: 0 };

    d.control(0x80);
    // No authorize. Attempt a StartLoading LSM record (a memory write).
    MemMapped::send_event(&mut d, 1, &event::start());
    assert!(
        !d.rejections().is_empty(),
        "a memory write with no authorize must be refused on a keyed device"
    );

    // A wrong key grants the failed level; the write is still refused.
    d.ndt(0x3D1, &[0x00, 0x00, 0x00, 0x00, 0x01]); // wrong key
    MemMapped::send_event(&mut d, 1, &event::start());
    assert!(
        !d.rejections().is_empty(),
        "a memory write after a wrong-key authorize must be refused"
    );
    assert_ne!(d.device().load_state(1), Some(LoadState::Loading));
}
