//! System 7 device tests.

use super::*;
use crate::device::profile::LsmAccess;
use crate::wire::GroupAddress;

/// Build a System 7 device from the synthetic MDT-canonical product (no
/// fixture needed), at 1.1.5, starting Unloaded.
fn sys7_device(access: LsmAccess) -> Device {
    let product = crate::testfixtures::synthetic_mdt_sys7_product();
    Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 5),
        &product,
        LoadState::Unloaded,
        ProfileOverrides {
            mask: None,
            lsm_access: access,
            bcu_key: None,
            prog_mode: false,
            secure: None,
        },
        std::sync::Arc::new(RecordingSink::new()),
    )
    .expect("System 7 device builds")
}

#[test]
fn test_sys7_profile_selected_from_product_mask() {
    let dev = sys7_device(LsmAccess::MemoryMapped);
    assert!(dev.profile().is_system7());
    assert_eq!(dev.profile().mask(), 0x0705);
    // The three canonical LSMs exist and start Unloaded.
    for lsm in [1u8, 2, 3] {
        assert_eq!(dev.load_state(lsm), Some(LoadState::Unloaded));
    }
}

#[test]
fn test_unmodelled_mask_override_is_refused() {
    // A mask override to an unmodelled family is refused — a strict
    // simulator will not pretend to be a device generation it lacks.
    let product = crate::testfixtures::synthetic_mdt_sys7_product();
    let err = Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 5),
        &product,
        LoadState::Unloaded,
        ProfileOverrides {
            mask: Some("0012".into()),
            ..Default::default()
        },
        std::sync::Arc::new(RecordingSink::new()),
    );
    assert!(err.is_err(), "unmodelled mask must be refused");
}

#[test]
fn test_sys7_pid78_preflight_value_is_readable() -> Result<(), Box<dyn std::error::Error>> {
    // Object-0 PID 78 (PID_HARDWARE_TYPE) serves the 10-octet preflight
    // value the MDT CompareProp matches. App 14 seeds byte 5 = 0x0E.
    let mut dev = sys7_device(LsmAccess::MemoryMapped);
    connect(&mut dev)?;
    let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x00, 0x4E, 0x10, 0x01]))?;
    let value = prop_response_value(&r);
    assert_eq!(value.len(), 10, "PID 78 is a 10-octet value");
    assert_eq!(value[4], 0x03, "byte 4 is the run-state marker");
    Ok(())
}

#[test]
fn test_sys7_serves_mcb_table_after_load() -> Result<(), Box<dyn std::error::Error>> {
    // A System 7 device serves PID_MCB_TABLE (27) per loadable object,
    // computed over the written segment memory (Jung A-A011 uses
    // LoadImageProp on System 7). Drive LSM 1 to hold real bytes, then read
    // PID 27 and expect an 8-octet integrity block whose CRC matches.
    let mut dev = sys7_device(LsmAccess::MemoryMapped);
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    // StartLoading + alloc LSM 1 at 0x4000 via the 11-octet memory record
    // (LSM in the high nibble of octet 0, 3-octet start address).
    let start_rec = [0x11u8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &start_rec))?;
    let alloc_rec = [
        0x13u8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    ];
    dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &alloc_rec))?;
    // Write 8 bytes into the segment.
    dev.handle_cemi(&mem_write_frame(&dev, 0x4000, &[1, 2, 3, 4, 5, 6, 7, 8]))?;
    // Read PID_MCB_TABLE (27) on object 1.
    let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x10, 0x01]))?;
    let mcb = prop_response_value(&r);
    assert_eq!(mcb.len(), MCB_ENTRY_LEN, "MCB entry is 8 octets");
    // The size field is the 8 written bytes; the CRC matches an independent
    // computation over those bytes.
    assert_eq!(&mcb[0..4], &[0, 0, 0, 8]);
    let crc = crc16_aug_ccitt(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&mcb[6..8], &crc.to_be_bytes());
    Ok(())
}

#[test]
fn test_sys7_multi_element_mcb_read_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    // A real Jung 3361-1MWW (mask 0705, `M-0004_A-A011-13`) refused a
    // multi-element MCB read: `A_PropertyValue_Read obj=3 pid=27 count=6
    // start=1` came back count 0 with no data (issue #89 campaign,
    // 1.1.36). Six 8-octet entries never fit a standard-frame APDU and a
    // real device does not partially answer. ETS reads them one at a
    // time, so the sim serves count=1 and refuses anything wider.
    let mut dev = sys7_device(LsmAccess::MemoryMapped);
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    let start_rec = [0x11u8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &start_rec))?;
    let alloc_rec = [
        0x13u8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    ];
    dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &alloc_rec))?;
    dev.handle_cemi(&mem_write_frame(&dev, 0x4000, &[1, 2, 3, 4, 5, 6, 7, 8]))?;

    // count = 6, start = 1 — the shape the Jung refused.
    let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x60, 0x01]))?;
    let resp = &r.responses[0];
    assert_eq!(
        &resp.tpdu[2..],
        &[0x01, 27, 0x00, 0x01],
        "a multi-element MCB read is refused with nr_of_elem = 0 and no data"
    );

    // count = 1 at the same index still serves the entry.
    let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x10, 0x01]))?;
    assert_eq!(prop_response_value(&r).len(), MCB_ENTRY_LEN);
    Ok(())
}

/// Build a standard-frame A_MemoryWrite NDT at the device's expected seq.
fn mem_write_frame(dev: &Device, addr: u16, payload: &[u8]) -> CemiLData {
    let apci10 = 0x280 | (payload.len() as u16 & 0x3F);
    let mut d = addr.to_be_bytes().to_vec();
    d.extend_from_slice(payload);
    data(dev, apci10, &d)
}

// --- Table-only reload (spec §3/§4, §7) ------------------------------
//
// A tool that only changes group links rewrites the two *table* LSMs and
// leaves the parameter LSM (3) and the application image alone. From the
// device's side that is an ordinary load sequence restricted to LSM 1 and
// LSM 2, issued against a device that is already `Loaded`: Unload,
// StartLoading, allocate, stream, TaskSegment, LoadCompleted. The device
// must accept it in both LSM realisations and come back on the *new*
// tables it just parsed out of its own memory.

/// Send one 10-octet load event to `lsm` in the device's realisation:
/// `Property` writes PID 5 on the object, `MemoryMapped` writes the
/// 11-octet record to the control address (spec §5).
fn send_event(
    dev: &mut Device,
    access: LsmAccess,
    lsm: u8,
    event: [u8; 10],
) -> Result<(), DeviceError> {
    match access {
        LsmAccess::Property => {
            let mut payload = vec![lsm, PID_LOAD_STATE_CONTROL, 0x10, 0x01];
            payload.extend_from_slice(&event);
            dev.handle_cemi(&data(dev, 0x3D7, &payload))?;
        }
        LsmAccess::MemoryMapped => {
            let mut record = [0u8; 11];
            record[0] = (lsm << 4) | (event[0] & 0x0F);
            record[1] = event[1];
            record[3..11].copy_from_slice(&event[2..10]);
            let frame = mem_write_frame(dev, 0x0104, &record);
            dev.handle_cemi(&frame)?;
        }
    }
    Ok(())
}

/// A 10-octet event carrying only its opcode (spec §4.1).
fn simple(opcode: u8) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[0] = opcode;
    v
}

/// An `AdditionalLoadControls` absolute-Data-segment allocation record
/// (spec §4.2): `[03][00][start:2][length:2][…]`.
fn alloc(start: u16, length: u16) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[0] = 0x03;
    v[1] = 0x00;
    v[2..4].copy_from_slice(&start.to_be_bytes());
    v[4..6].copy_from_slice(&length.to_be_bytes());
    v[7] = 0x03; // EEPROM
    v
}

/// An `AdditionalLoadControls` task-segment finalize record (spec §4.3).
fn task(address: u16) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[0] = 0x03;
    v[1] = 0x02;
    v[2..4].copy_from_slice(&address.to_be_bytes());
    v
}

/// Write a whole table region in 12-octet chunks (the System 7
/// standard-frame cap, spec §6).
fn stream(dev: &mut Device, base: u16, image: &[u8]) -> Result<(), DeviceError> {
    for (i, piece) in image.chunks(12).enumerate() {
        let at = base + (i * 12) as u16;
        let frame = mem_write_frame(dev, at, piece);
        dev.handle_cemi(&frame)?;
    }
    Ok(())
}

/// Load the two table LSMs with the given region images, the way both a
/// full download and a table-only reload do it (spec §3): open both,
/// allocate, stream, finalize, complete.
fn load_tables(
    dev: &mut Device,
    access: LsmAccess,
    lsm1: &[u8],
    lsm2: &[u8],
) -> Result<(), DeviceError> {
    send_event(dev, access, 2, simple(0x04))?; // Unload LSM 2
    send_event(dev, access, 1, simple(0x04))?; // Unload LSM 1
    send_event(dev, access, 2, simple(0x01))?; // StartLoading LSM 2
    send_event(dev, access, 1, simple(0x01))?; // StartLoading LSM 1
    send_event(dev, access, 1, alloc(0x4000, lsm1.len() as u16))?;
    stream(dev, 0x4000, lsm1)?;
    send_event(dev, access, 2, alloc(0x4201, lsm2.len() as u16))?;
    stream(dev, 0x4201, lsm2)?;
    send_event(dev, access, 1, task(0x4000))?;
    send_event(dev, access, 1, simple(0x02))?; // LoadCompleted LSM 1
    send_event(dev, access, 2, task(0x4201))?;
    send_event(dev, access, 2, simple(0x02))?; // LoadCompleted LSM 2
    Ok(())
}

/// The LSM 1 region image: the address table (spec §7.1) followed by the
/// group-object descriptor table (spec §7.3, co-located in the 0x4000
/// region per §2.3).
fn lsm1_region(own_ia: u16, gas: &[u16]) -> Vec<u8> {
    let mut img = vec![(1 + gas.len()) as u8];
    img.extend_from_slice(&own_ia.to_be_bytes());
    for ga in gas {
        img.extend_from_slice(&ga.to_be_bytes());
    }
    // One com-object (ASAP 0): data-ptr 0x0700, CONFIG C|W, TYPE 1 bit.
    img.extend_from_slice(&[0x01, 0x07, 0x00]);
    img.extend_from_slice(&[0x07, 0x00, 0x94, 0x00]);
    img
}

/// The LSM 2 region image: the association table (spec §7.2), linking
/// every TSAP to com-object 0.
fn lsm2_region(count: u8) -> Vec<u8> {
    let mut img = vec![count];
    for tsap in 1..=count {
        img.push(tsap);
        img.push(0); // ASAP 0
    }
    img
}

fn table_only_reload(access: LsmAccess) -> Result<(), Box<dyn std::error::Error>> {
    let mut dev = sys7_device(access);
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;

    // First download: one GA, 1/0/1 (0x0801), on com-object 0.
    load_tables(
        &mut dev,
        access,
        &lsm1_region(0x1105, &[0x0801]),
        &lsm2_region(1),
    )?;
    assert_eq!(dev.load_state(1), Some(LoadState::Loaded));
    assert_eq!(dev.load_state(2), Some(LoadState::Loaded));
    let gc = dev.group_comm().expect("the device routes after the load");
    assert_eq!(
        gc.object(0).expect("com-object 0").gas,
        vec![GroupAddress(0x0801)]
    );
    assert!(gc.object(0).expect("com-object 0").is_writable());

    // The parameter LSM was never opened and must stay exactly as it was:
    // that is the whole point of a table-only reload.
    let lsm3_before = dev.load_state(3);

    // Table-only reload: two GAs now, 1/0/1 and 1/0/2. The address table
    // grows by two octets, so the group-object descriptor table moves with
    // it — the device must re-parse both from their new offsets.
    load_tables(
        &mut dev,
        access,
        &lsm1_region(0x1105, &[0x0801, 0x0802]),
        &lsm2_region(2),
    )?;
    assert_eq!(dev.load_state(1), Some(LoadState::Loaded));
    assert_eq!(dev.load_state(2), Some(LoadState::Loaded));
    assert_eq!(
        dev.load_state(3),
        lsm3_before,
        "a table-only reload must not touch the parameter LSM"
    );
    let gc = dev
        .group_comm()
        .expect("the device routes again after the reload");
    assert_eq!(
        gc.object(0).expect("com-object 0").gas,
        vec![GroupAddress(0x0801), GroupAddress(0x0802)],
        "the reloaded tables are re-parsed, not the old ones"
    );

    // And a shrink: back to a single GA. The descriptor table moves down
    // again and the dropped GA stops routing.
    load_tables(
        &mut dev,
        access,
        &lsm1_region(0x1105, &[0x0802]),
        &lsm2_region(1),
    )?;
    let gc = dev.group_comm().expect("still routing after the shrink");
    assert_eq!(
        gc.object(0).expect("com-object 0").gas,
        vec![GroupAddress(0x0802)]
    );
    assert!(
        gc.on_group_read(GroupAddress(0x0801)).is_none(),
        "the removed GA no longer routes"
    );
    Ok(())
}

#[test]
fn test_sys7_table_only_reload_property_lsm() -> Result<(), Box<dyn std::error::Error>> {
    table_only_reload(LsmAccess::Property)
}

#[test]
fn test_sys7_table_only_reload_memory_mapped_lsm() -> Result<(), Box<dyn std::error::Error>> {
    table_only_reload(LsmAccess::MemoryMapped)
}

#[test]
fn test_sys7_goes_silent_while_its_tables_are_being_rewritten()
-> Result<(), Box<dyn std::error::Error>> {
    // A table LSM that leaves `Loaded` takes the device off the group side
    // until the reload completes (spec §4.1: a table is active only in
    // `Loaded`). Without that, a device would keep routing on tables that
    // are mid-rewrite.
    let access = LsmAccess::Property;
    let mut dev = sys7_device(access);
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    load_tables(
        &mut dev,
        access,
        &lsm1_region(0x1105, &[0x0801]),
        &lsm2_region(1),
    )?;
    assert!(dev.group_comm().is_some());

    send_event(&mut dev, access, 1, simple(0x04))?; // Unload LSM 1
    assert!(
        dev.group_comm().is_none(),
        "an unloaded address table silences the device"
    );
    Ok(())
}
