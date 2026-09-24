//! Unit tests for [`Device`](super::Device): management, properties, load flow.

use super::*;
use crate::bus::event::RecordingSink;
use crate::prod::read_knxprod_bytes;

mod sys7;
mod transport;

/// Build a DA.tp device, or `Ok(None)` if the (un-committed) fixture is
/// absent so the caller can skip.
fn da_tp_device() -> Result<Option<Device>, Box<dyn std::error::Error>> {
    let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(None);
    };
    let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
    let sink = std::sync::Arc::new(RecordingSink::new());
    Ok(Some(Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        sink,
    )))
}

fn connect(dev: &mut Device) -> Result<(), DeviceError> {
    let cemi = CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: dev.address().raw(),
        tpdu: vec![0x80],
    };
    dev.handle_cemi(&cemi)?;
    Ok(())
}

/// Build a connected NDT at the device's **currently expected** receive
/// sequence, so a sequence of `handle_cemi(&data(&dev, ...))` calls carries a
/// correctly-incrementing L4 sequence (matching what a real tool sends). The
/// device advances `rx_seq` as it accepts each frame.
fn data(dev: &Device, apci10: u16, payload: &[u8]) -> CemiLData {
    data_seq(dev, dev.rx_seq, apci10, payload)
}

/// Build a connected NDT at an explicit sequence (for out-of-order tests).
fn data_seq(dev: &Device, seq: u8, apci10: u16, payload: &[u8]) -> CemiLData {
    let mut tpdu = vec![
        0x40 | ((seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
        (apci10 & 0xFF) as u8,
    ];
    tpdu.extend_from_slice(payload);
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: dev.address().raw(),
        tpdu,
    }
}

#[test]
fn test_master_reset_erase_code_7_clears_application_and_keeps_address()
-> Result<(), Box<dyn std::error::Error>> {
    let mut dev = system_b_device()?;
    dev.set_restart_process_time(8);
    // A previous image in the application object's segment (object 3).
    let base = dev.loadables.get(&3).ok_or("object 3")?.base;
    dev.memory.allocate(3, base, 6);
    dev.memory.write(3, base, &[0xAA; 6])?;

    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    // The ETS request from the issue #117 capture: A_Restart master reset,
    // erase code 7, channel 0.
    let reaction = dev.handle_cemi(&data(&dev, 0x381, &[0x07, 0x00]))?;
    assert!(reaction.did_master_reset);
    let resp = reaction
        .responses
        .iter()
        .find(|r| r.tpdu.len() == 5)
        .ok_or("an A_Restart_Response")?;
    // `.. a1 00 00 08`: APCI 0x3A1, error 0, process time 8 s.
    let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
    assert_eq!(apci10, 0x3A1);
    assert_eq!(&resp.tpdu[2..], &[0x00, 0x00, 0x08]);

    // Application erased, every object Unloaded, address kept, rebooted.
    for object in 1u8..=3 {
        assert_eq!(dev.load_state(object), Some(LoadState::Unloaded));
    }
    assert_eq!(dev.memory().read(base, 6), vec![0x00; 6]);
    assert!(dev.memory().segment_of(3).is_none());
    assert_eq!(dev.address(), IndividualAddress::new(1, 1, 2));
    assert!(!dev.connected);
    Ok(())
}

#[test]
fn test_master_reset_confirmed_restart_erases_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let mut dev = system_b_device()?;
    let base = dev.loadables.get(&3).ok_or("object 3")?.base;
    dev.memory.allocate(3, base, 2);
    dev.memory.write(3, base, &[0x12, 0x34])?;
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    let reaction = dev.handle_cemi(&data(&dev, 0x381, &[0x01, 0x00]))?;
    let resp = reaction
        .responses
        .iter()
        .find(|r| r.tpdu.len() == 5)
        .ok_or("an A_Restart_Response")?;
    assert_eq!(&resp.tpdu[2..], &[0x00, 0x00, 0x00]);
    assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
    assert_eq!(dev.memory().read(base, 2), vec![0x12, 0x34]);
    Ok(())
}

#[test]
fn test_memory_write_without_auth_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    // Start loading object 4 needs auth too; write should be rejected as
    // unauthorized before any load state work.
    let mw = data(&dev, 0x280 | 4, &[0x60, 0x00, 1, 2, 3, 4]);
    assert!(matches!(
        dev.handle_cemi(&mw),
        Err(DeviceError::Unauthorized { .. })
    ));
    Ok(())
}

/// Build a fixture-free System 7 device (from the synthetic MDT product) at
/// `1.1.2`, optionally starting in programming mode.
fn prog_device(prog_mode: bool) -> Result<Device, String> {
    let pd = crate::testfixtures::synthetic_mdt_sys7_product();
    let sink = std::sync::Arc::new(RecordingSink::new());
    Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        ProfileOverrides {
            prog_mode,
            ..Default::default()
        },
        sink,
    )
}

#[test]
fn test_individual_address_response_only_when_in_prog_mode()
-> Result<(), Box<dyn std::error::Error>> {
    // A device NOT in programming mode is silent to the broadcast read.
    let quiet = prog_device(false)?;
    assert!(quiet.individual_address_response().is_none());

    // A device in programming mode answers with an A_IndividualAddress_Response
    // whose source is its own address and dest is the broadcast group 0/0/0.
    let programming = prog_device(true)?;
    let resp = programming
        .individual_address_response()
        .ok_or("device in prog mode must answer")?;
    assert_eq!(resp.message_code, MessageCode::LDataInd);
    assert_eq!(resp.source, IndividualAddress::new(1, 1, 2));
    assert_eq!(resp.dest, 0x0000);
    assert!(resp.is_group(), "broadcast frames carry the group bit");
    let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
    assert_eq!(Apci::from_u10(apci10), Apci::IndividualAddressResponse);
    Ok(())
}

#[test]
fn test_pid_progmode_write_toggles_prog_mode() -> Result<(), Box<dyn std::error::Error>> {
    // Writing PID_PROGMODE over the wire (as ETS/`bussard assign` do) flips the
    // runtime bit: 1 enters programming mode, 0 leaves it.
    let mut dev = prog_device(false)?;
    connect(&mut dev)?;
    // Authorize (free access) so property writes are accepted.
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    assert!(!dev.prog_mode());

    // A_PropertyValue_Write obj0 PID_PROGMODE count=1 start=1 value=01.
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x00, PID_PROGMODE, 0x10, 0x01, 0x01]))?;
    assert!(dev.prog_mode(), "writing PID_PROGMODE=1 enters prog mode");
    assert!(
        dev.individual_address_response().is_some(),
        "now answers the broadcast read"
    );

    // Writing 0 leaves programming mode again (how `assign` clears it).
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x00, PID_PROGMODE, 0x10, 0x01, 0x00]))?;
    assert!(!dev.prog_mode(), "writing PID_PROGMODE=0 leaves prog mode");
    assert!(dev.individual_address_response().is_none());
    Ok(())
}

#[test]
fn test_set_prog_mode_syncs_property() -> Result<(), Box<dyn std::error::Error>> {
    // The programmatic toggle updates both the bit and the PID_PROGMODE
    // property value so a subsequent property read agrees.
    let mut dev = prog_device(false)?;
    dev.set_prog_mode(true);
    assert!(dev.prog_mode());
    let prop = dev
        .objects
        .get(&0)
        .and_then(|io| io.property(PID_PROGMODE))
        .ok_or("device object has PID_PROGMODE")?;
    assert_eq!(prop.value, vec![0x01]);
    Ok(())
}

/// Extract the value bytes from a single A_PropertyValue_Response reaction:
/// the payload after the 4-byte obj/pid/(count|start_hi)/start_lo header.
fn prop_response_value(reaction: &DeviceReaction) -> Vec<u8> {
    let resp = &reaction.responses[0];
    // TPDU: [tpci][apci_lo][obj][pid][count|start_hi][start_lo][value...].
    resp.tpdu[6..].to_vec()
}

#[test]
fn test_object_type_discovery_returns_iot_per_index() -> Result<(), Box<dyn std::error::Error>> {
    // A tool discovers the interface-object table by reading PID_OBJECT_TYPE
    // (PID 1) on each object index. The device must report each object's
    // IOT: [0:device, 1:address-table, 2:association-table,
    // 3:group-object-table, 4:application-program]. The object that owns the
    // application code segment (LSM index 4 at base 0x6000) is the
    // application-program object (type 3), and the com-object table (LSM index
    // 3 at 0x8000) is the group-object-table object (type 9) — so a tool's
    // MCB image-integrity read lands on the object that actually holds each
    // segment.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    let expected: [(u8, u16); 5] = [
        (0, iot::DEVICE),
        (1, iot::ADDRESS_TABLE),
        (2, iot::ASSOCIATION_TABLE),
        (3, iot::GROUP_OBJECT_TABLE),
        (4, iot::APPLICATION_PROGRAM),
    ];
    for (object, want) in expected {
        // A_PropertyValue_Read obj/pid=1/count=1/start=1.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[object, 0x01, 0x10, 0x01]))?;
        let value = prop_response_value(&r);
        assert_eq!(
            value,
            want.to_be_bytes(),
            "object {object} reported wrong interface-object type"
        );
    }
    Ok(())
}

#[test]
fn test_property_read_unknown_object_returns_error_signal() -> Result<(), Box<dyn std::error::Error>>
{
    // Reading PID_OBJECT_TYPE past the end of the object table must return
    // the spec error signal: an A_PropertyValue_Response echoing the header
    // with nr_of_elem = 0 and no value (not silence), so a probing tool can
    // detect the table end rather than time out.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    // Object 6 does not exist on the DA.tp device.
    let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x06, 0x01, 0x10, 0x01]))?;
    assert_eq!(r.responses.len(), 1, "must respond, not drop");
    let resp = &r.responses[0];
    // TPDU: [tpci][d6][obj=06][pid=01][count|start_hi][start_lo]; count = 0.
    let count = resp.tpdu[4] >> 4;
    assert_eq!(count, 0, "unknown property must report nr_of_elem = 0");
    assert_eq!(resp.tpdu.len(), 6, "error signal carries no value bytes");
    Ok(())
}

#[test]
fn test_property_description_read_by_index_and_terminates() -> Result<(), Box<dyn std::error::Error>>
{
    // A_PropertyDescription_Read on object 0 by index (PID 0): the device
    // answers each index with a 7-octet descriptor and reports the first
    // absent index with max_elements == 0 (the enumeration terminator).
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    // Object 0 exposes several device-object properties; index 1 is PID 1
    // (PID_OBJECT_TYPE) since the property map is PID-sorted.
    let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x00, 0x00, 0x01]))?;
    assert_eq!(r.responses.len(), 1, "must respond to a description read");
    let resp = &r.responses[0];
    // TPDU: [tpci][apci_lo][obj][pid][index][type][max_hi][max_lo][access].
    let payload = &resp.tpdu[2..];
    assert_eq!(payload[0], 0x00, "object index echoed");
    assert_eq!(payload[1], PID_OBJECT_TYPE, "index 1 is PID_OBJECT_TYPE");
    assert_eq!(payload[2], 0x01, "property index echoed");
    // PID_OBJECT_TYPE is read-only → write-enable bit clear, PDT generic.
    assert_eq!(payload[3] & 0x80, 0, "read-only property");
    assert_eq!(payload[3] & 0x3F, PDT_GENERIC_01);
    let max = u16::from_be_bytes([payload[4], payload[5]]);
    assert_eq!(max, 1, "one element");
    // read level 3 (high nibble), write level 15 (read-only, low nibble).
    assert_eq!(payload[6] >> 4, 3);
    assert_eq!(payload[6] & 0x0F, 15);

    // Walk indices until absence: the device reports max_elements == 0 once
    // the index runs past the object's property list.
    let mut last_present = 0u8;
    for index in 1u8..=32 {
        let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x00, 0x00, index]))?;
        let payload = &r.responses[0].tpdu[2..];
        let max = u16::from_be_bytes([payload[4], payload[5]]);
        if max == 0 {
            break;
        }
        last_present = index;
    }
    assert!(last_present >= 1, "object 0 has at least one property");
    Ok(())
}

#[test]
fn test_property_description_read_by_pid() -> Result<(), Box<dyn std::error::Error>> {
    // Addressing by PID (non-zero property_id) returns that PID's descriptor
    // and reports its 1-based property index. PID_PROGMODE is writable.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x00, PID_PROGMODE, 0x00]))?;
    let payload = &r.responses[0].tpdu[2..];
    assert_eq!(payload[1], PID_PROGMODE, "PID echoed");
    assert!(payload[2] >= 1, "a real 1-based property index reported");
    assert_eq!(payload[3] & 0x80, 0x80, "PID_PROGMODE is writable");
    assert_eq!(payload[6] & 0x0F, 0, "writable → write level 0");
    Ok(())
}

#[test]
fn test_property_description_read_unknown_reports_zero_max()
-> Result<(), Box<dyn std::error::Error>> {
    // A description read for an object that does not exist is answered with a
    // zero-max descriptor (not silence), matching the value-read error signal.
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x40, 0x00, 0x01]))?;
    assert_eq!(r.responses.len(), 1, "must respond, not drop");
    let payload = &r.responses[0].tpdu[2..];
    let max = u16::from_be_bytes([payload[4], payload[5]]);
    assert_eq!(max, 0, "unknown object → max_elements 0");
    Ok(())
}

/// Build a fixture-free **System B** device: the synthetic MDT product with
/// its mask forced to `07B0`, so the test needs no un-committed `.knxprod`.
fn system_b_device() -> Result<Device, String> {
    let pd = crate::testfixtures::synthetic_mdt_sys7_product();
    let sink = std::sync::Arc::new(RecordingSink::new());
    Device::from_product_with_overrides(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Loaded,
        ProfileOverrides {
            mask: Some("07B0".into()),
            ..Default::default()
        },
        sink,
    )
}

#[test]
fn test_pid_table_property_write_is_refused_with_zero_count()
-> Result<(), Box<dyn std::error::Error>> {
    // A real System B device does not take a loadable table through the
    // PID_TABLE property array. The Jung F50 52911ST answered this write with
    // a zero-count A_PropertyValue_Response (issue #89); the simulator models
    // that, so a tool that skips the allocate + memory-write realisation is
    // caught here rather than on a real bus.
    let mut dev = system_b_device()?;
    connect(&mut dev)?;
    // Authorize first, so the refusal is about PID 23 and not about access.
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    assert_eq!(dev.access_level, 0);

    // A_PropertyValue_Write(object 1, PID 23, count 1, start 1, [0x12, 0x34]).
    let write = data(&dev, 0x3D7, &[0x01, PID_TABLE, 0x10, 0x01, 0x12, 0x34]);
    let reaction = dev.handle_cemi(&write)?;

    // A refusal is still an answer, not silence: the tool must be able to
    // tell "refused" from "dropped telegram".
    let resp = reaction
        .responses
        .first()
        .ok_or("a refused PID_TABLE write must still be answered")?;
    let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
    assert_eq!(Apci::from_u10(apci10), Apci::PropertyValueResponse);
    assert_eq!(
        &resp.tpdu[2..],
        // object, pid, nr_of_elem = 0 in the high nibble | start_hi, start_lo
        &[0x01, PID_TABLE, 0x00, 0x01],
        "the header is echoed with nr_of_elem = 0 and no data"
    );

    // And nothing was stored: no PID 23 appeared on the object, and the write
    // left the device's memory untouched.
    assert!(
        dev.objects
            .get(&1)
            .map(|o| o.property(PID_TABLE).is_none())
            .unwrap_or(true),
        "a refused write must not create or fill PID_TABLE"
    );
    Ok(())
}

#[test]
fn test_authorize_unlocks() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    let auth = data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
    let r = dev.handle_cemi(&auth)?;
    assert_eq!(r.responses.len(), 1);
    assert_eq!(dev.access_level, 0);
    Ok(())
}

#[test]
fn test_load_flow_reaches_loaded() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    // StartLoading obj4
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?;
    assert_eq!(dev.load_state(4), Some(LoadState::Loading));
    // Allocate 256
    dev.handle_cemi(&data(
        &dev,
        0x3D7,
        &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
    ))?;
    assert_eq!(
        dev.memory().segment_of(4).map(|s| (s.base, s.len)),
        Some((0x6000, 256))
    );
    // Memory write at base 0x6000
    dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 5, 5, 0xff, 0xff]))?;
    // LoadCompleted
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x02]))?;
    assert_eq!(dev.load_state(4), Some(LoadState::Loaded));
    Ok(())
}

#[test]
fn test_load_state_read_reflects_live_lsm_state() -> Result<(), Box<dyn std::error::Error>> {
    // A wire read of PID_LOAD_STATE_CONTROL must return the LIVE load state
    // (1 octet), tracking the LSM as it transitions — not a value seeded at
    // construction. A tool verifies StartLoading/LoadCompleted by reading
    // PID 5 back, so a stale answer would stall it. Start Unloaded to make
    // the transitions observable.
    let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
        return Ok(());
    };
    let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB"))?;
    let mut dev = Device::from_product(
        IndividualAddress::new(1, 1, 2),
        &pd,
        LoadState::Unloaded,
        std::sync::Arc::new(RecordingSink::new()),
    );
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;

    // Reads the single load-state octet from a PID 5 read response.
    let read_state = |dev: &mut Device| -> Result<u8, Box<dyn std::error::Error>> {
        let r = dev.handle_cemi(&data(dev, 0x3D5, &[0x04, 0x05, 0x10, 0x01]))?;
        // TPDU: [tpci][d6][obj][pid][count|start_hi][start_lo][state].
        let state = *r.responses[0]
            .tpdu
            .last()
            .ok_or("empty load-state response")?;
        Ok(state)
    };

    assert_eq!(read_state(&mut dev)?, LoadState::Unloaded.to_byte());
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?; // StartLoading
    assert_eq!(read_state(&mut dev)?, LoadState::Loading.to_byte());
    dev.handle_cemi(&data(
        &dev,
        0x3D7,
        &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
    ))?; // Alloc 256
    assert_eq!(read_state(&mut dev)?, LoadState::Loading.to_byte());
    dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 5, 5, 0xff, 0xff]))?; // mem write
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x02]))?; // LoadCompleted
    assert_eq!(read_state(&mut dev)?, LoadState::Loaded.to_byte());
    Ok(())
}

#[test]
fn test_memory_write_to_wrong_base_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let Some(mut dev) = da_tp_device()? else {
        return Ok(());
    };
    connect(&mut dev)?;
    dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
    dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?;
    dev.handle_cemi(&data(
        &dev,
        0x3D7,
        &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
    ))?;
    // Write to 0x8000 (com-object base) while only obj4@0x6000 is open.
    let mw = data(&dev, 0x280 | 4, &[0x80, 0x00, 1, 2, 3, 4]);
    assert!(dev.handle_cemi(&mw).is_err());
    Ok(())
}
