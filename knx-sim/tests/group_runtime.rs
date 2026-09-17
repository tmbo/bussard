//! Integration tests for the runtime group-communication capability.
//!
//! These exercise the new behaviour end to end against the `Bus`:
//!
//! 1. **Table self-parsing after a download** — a device that is driven through a
//!    flash (allocate + write obj1/obj2/obj3 + LoadCompleted) reconstructs its
//!    runtime routing *from the tables it just stored in its own memory*, not
//!    from any external config.
//! 2. **`A_GroupValue_Read` → `A_GroupValue_Response`** — a device holding the
//!    Read flag on a group address answers a read with its current value; a
//!    device that only listens updates its value on an `A_GroupValue_Write`.
//! 3. **Stimulus emission** — a scripted stimulus makes a transmitting device
//!    put a value on the bus, which every other device on the bus receives.
//!
//! The tests build the tables the way `bussard flash` does (the mirror of
//! `bussard`'s `compute_tables`): a big-endian count word followed by the
//! entries. That is exactly what the device must be able to read back, so
//! building them here and driving them through the wire is the cross-check.

use std::sync::Arc;

use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::bus::{Bus, StimulusJob};
use knx_sim::device::{Device, LoadState, flag};
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::wire::{Apci, CemiLData, GroupAddress, IndividualAddress, MessageCode, Tpci};

/// Build a DA.tp device (or skip if the fixture is absent), starting Unloaded so
/// a flash can be driven and the tables written from scratch.
fn da_tp_unloaded(sink: Arc<RecordingSink>) -> Option<Device> {
    let fixture = knx_sim::testfixtures::da_tp_knxprod()?;
    let pd = read_knxprod_bytes(&fixture, Some("M-00FA_A-2500-10-51CB")).ok()?;
    Some(Device::from_product(
        IndividualAddress::new(1, 0, 1),
        &pd,
        LoadState::Unloaded,
        sink,
    ))
}

/// A bare T_Connect toward the device.
fn connect(dev: &Device) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: dev.address().raw(),
        tpdu: vec![0x80],
    }
}

/// Encode a table image the way the download engine does: a big-endian `u16`
/// count word followed by the raw element bytes.
fn table_image(count: u16, elements: &[u8]) -> Vec<u8> {
    let mut v = count.to_be_bytes().to_vec();
    v.extend_from_slice(elements);
    v
}

/// Drive one loadable object through a flash: StartLoading, allocate a segment of
/// `image.len()` bytes, write the image at the object's base, LoadCompleted. The
/// PID5 writes carry the 10-octet load-event value ETS uses. Sequence numbers are
/// threaded through the shared `seq` counter (mod 16).
fn flash_object(
    bus: &mut Bus,
    addr: IndividualAddress,
    obj: u8,
    seq: &mut u8,
    image: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // PID5 header: [obj, pid=5, (count<<4)|start_hi, start_lo, value(10)].
    let pid5 = |event: &[u8]| -> Vec<u8> {
        let mut v = vec![obj, 5, 0x10, 0x01];
        v.extend_from_slice(event);
        v.resize(4 + 10, 0x00);
        v
    };
    let size = image.len() as u32;
    // StartLoading (0x01).
    bus.deliver_from_tool(&mk(bus, addr, seq, 0x3D7, &pid5(&[0x01])));
    // Allocate RelSegment: [0x03, 0x0b, size:4 BE].
    let mut alloc = vec![0x03u8, 0x0b];
    alloc.extend_from_slice(&size.to_be_bytes());
    bus.deliver_from_tool(&mk(bus, addr, seq, 0x3D7, &pid5(&alloc)));
    // Read the object's base (PID_TABLE_REFERENCE, PID 7).
    let base = {
        let r = bus.deliver_from_tool(&mk(bus, addr, seq, 0x3D5, &[obj, 7, 0x10, 0x01]));
        // Response value is the last 4 octets: [00 00 base_hi base_lo].
        let tpdu = &r[0].tpdu;
        let n = tpdu.len();
        u16::from_be_bytes([tpdu[n - 2], tpdu[n - 1]])
    };
    // Write the image at the base in 12-byte chunks (A_MemoryWrite, count in APCI).
    let mut off = 0usize;
    while off < image.len() {
        let chunk = &image[off..(off + 12).min(image.len())];
        let addr16 = base.wrapping_add(off as u16);
        let mut payload = addr16.to_be_bytes().to_vec();
        payload.extend_from_slice(chunk);
        bus.deliver_from_tool(&mk(
            bus,
            addr,
            seq,
            0x280 | (chunk.len() as u16 & 0x3F),
            &payload,
        ));
        off += chunk.len();
    }
    // LoadCompleted (0x02).
    bus.deliver_from_tool(&mk(bus, addr, seq, 0x3D7, &pid5(&[0x02])));
    Ok(())
}

/// Build an NDT and advance the shared sequence counter.
fn mk(_bus: &Bus, addr: IndividualAddress, seq: &mut u8, apci10: u16, payload: &[u8]) -> CemiLData {
    let mut tpdu = vec![
        Tpci::data_connected_byte(*seq) | ((apci10 >> 8) as u8 & 0x03),
        (apci10 & 0xFF) as u8,
    ];
    tpdu.extend_from_slice(payload);
    *seq = (*seq + 1) & 0x0F;
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0x60,
        source: IndividualAddress::new(0, 0, 0),
        dest: addr.raw(),
        tpdu,
    }
}

/// Authorize + flash a device so it holds the three tables below and reaches
/// Loaded. The tables wire a readable status object (asap 3) to GA 1/0/2 and a
/// writable object (asap 1) to GA 1/0/1.
fn flash_two_object_device(
    bus: &mut Bus,
    addr: IndividualAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let dev = bus.device(addr).ok_or("device missing")?;
    let mut seq = 0u8;
    bus.deliver_from_tool(&connect(dev));
    // Authorize FF FF FF FF.
    bus.deliver_from_tool(&mk(
        bus,
        addr,
        &mut seq,
        0x3D1,
        &[0x00, 0xff, 0xff, 0xff, 0xff],
    ));

    // Address table (obj1): 2 GAs — 1/0/1 (0x0801) and 1/0/2 (0x0802).
    let addr_tbl = table_image(2, &[0x08, 0x01, 0x08, 0x02]);
    // Association table (obj2): TSAP1->ASAP1, TSAP2->ASAP3.
    let assoc_tbl = table_image(2, &[0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]);
    // Group-object table (obj3): 3 descriptor words. asap1 = COMM|WRITE,
    // asap2 unused, asap3 = COMM|READ|WRITE|TRANSMIT (a combi status object that
    // both accepts a value from the bus and answers reads / transmits it).
    let w1 = flag::COMMUNICATION | flag::WRITE;
    let w3 = flag::COMMUNICATION | flag::READ | flag::WRITE | flag::TRANSMIT;
    let go_tbl = table_image(
        3,
        &[
            (w1 >> 8) as u8,
            (w1 & 0xff) as u8,
            0x00,
            0x00,
            (w3 >> 8) as u8,
            (w3 & 0xff) as u8,
        ],
    );

    flash_object(bus, addr, 1, &mut seq, &addr_tbl)?;
    flash_object(bus, addr, 2, &mut seq, &assoc_tbl)?;
    flash_object(bus, addr, 3, &mut seq, &go_tbl)?;
    Ok(())
}

#[test]
fn test_device_self_parses_tables_after_download() -> Result<(), Box<dyn std::error::Error>> {
    let sink = Arc::new(RecordingSink::new());
    let Some(dev) = da_tp_unloaded(sink.clone()) else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let addr = dev.address();
    let mut bus = Bus::new(sink);
    bus.add_device(dev);

    // Before the flash the device is silent: no routing.
    assert!(bus.device(addr).and_then(|d| d.group_comm()).is_none());

    flash_two_object_device(&mut bus, addr)?;

    // After the flash the device reconstructed its routing FROM ITS OWN MEMORY.
    let dev = bus.device(addr).ok_or("device missing")?;
    let gc = dev
        .group_comm()
        .ok_or("routing not reconstructed after Loaded")?;
    // asap1 writable and bound to 1/0/1; asap3 readable+transmitter and bound to 1/0/2.
    let o1 = gc.object(1).ok_or("asap1 missing")?;
    assert!(o1.is_writable(), "asap1 should be writable");
    assert_eq!(o1.gas, vec![GroupAddress(0x0801)]);
    let o3 = gc.object(3).ok_or("asap3 missing")?;
    assert!(o3.is_readable(), "asap3 should be readable");
    assert!(o3.is_transmitter(), "asap3 should transmit");
    assert_eq!(o3.gas, vec![GroupAddress(0x0802)]);
    Ok(())
}

#[test]
fn test_group_value_read_is_answered_with_response() -> Result<(), Box<dyn std::error::Error>> {
    let sink = Arc::new(RecordingSink::new());
    let Some(dev) = da_tp_unloaded(sink.clone()) else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let addr = dev.address();
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    flash_two_object_device(&mut bus, addr)?;

    // Write a value on 1/0/2 (the readable object's GA) via a group write from
    // some other bus participant, then read it back.
    let write = group_telegram(Apci::GroupValueWrite, GroupAddress(0x0802), &[0x01]);
    bus.deliver_from_tool(&write);

    // A_GroupValue_Read on 1/0/2: the device answers with a GroupValueResponse
    // carrying the current value.
    let read = group_telegram(Apci::GroupValueRead, GroupAddress(0x0802), &[]);
    let responses = bus.deliver_from_tool(&read);
    assert_eq!(responses.len(), 1, "a readable object must answer a read");
    let resp = &responses[0];
    assert_eq!(resp.source, addr, "the response comes from the device");
    // Decode the response APDU: it must be a GroupValueResponse of value 1.
    let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
    assert_eq!(Apci::from_u10(apci10), Apci::GroupValueResponse);
    // The value 1 packs into the APCI low bits (small form).
    assert_eq!((apci10 & 0x3f) as u8, 0x01);
    Ok(())
}

#[test]
fn test_group_read_of_unlistened_ga_is_silent() -> Result<(), Box<dyn std::error::Error>> {
    let sink = Arc::new(RecordingSink::new());
    let Some(dev) = da_tp_unloaded(sink.clone()) else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let addr = dev.address();
    let mut bus = Bus::new(sink);
    bus.add_device(dev);
    flash_two_object_device(&mut bus, addr)?;

    // A read on a GA the device does not listen to draws no response, exactly as
    // a real device ignores group traffic it is not subscribed to.
    let read = group_telegram(Apci::GroupValueRead, GroupAddress(0x0999), &[]);
    assert!(bus.deliver_from_tool(&read).is_empty());
    Ok(())
}

#[test]
fn test_stimulus_emits_and_is_seen_on_the_bus() -> Result<(), Box<dyn std::error::Error>> {
    let sink = Arc::new(RecordingSink::new());
    let Some(dev) = da_tp_unloaded(sink.clone()) else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let addr = dev.address();
    let mut bus = Bus::new(sink.clone());
    bus.add_device(dev);
    flash_two_object_device(&mut bus, addr)?;

    // Script a stimulus: the transmitting object (asap 3) sends value 1 then 0
    // every 1000 ms. Its send GA is resolved from the flashed association table.
    bus.set_stimulus(vec![StimulusJob {
        device: addr,
        object: 3,
        period_ms: 1000,
        values: vec![vec![0x01], vec![0x00]],
        next_due_ms: 0,
        cursor: 0,
    }]);

    // Tick past the first due time: the device transmits, and the telegram is
    // returned for the tunnel client.
    let out = bus.tick_stimulus(0);
    assert_eq!(out.len(), 1, "the due stimulus produces one telegram");
    let t = &out[0];
    assert_eq!(t.source, addr, "stimulus originates from the device");
    assert_eq!(t.dest_group(), GroupAddress(0x0802), "sent on its GA");
    // It is a GroupValueWrite of value 1.
    let apci10 = ((t.tpdu[0] as u16 & 0x03) << 8) | t.tpdu[1] as u16;
    assert_eq!(Apci::from_u10(apci10), Apci::GroupValueWrite);
    assert_eq!((apci10 & 0x3f) as u8, 0x01);

    // The next tick before the period elapses produces nothing.
    assert!(bus.tick_stimulus(500).is_empty());
    // After the period, the next value (0) is transmitted.
    let out2 = bus.tick_stimulus(1000);
    assert_eq!(out2.len(), 1);
    let apci2 = ((out2[0].tpdu[0] as u16 & 0x03) << 8) | out2[0].tpdu[1] as u16;
    assert_eq!((apci2 & 0x3f) as u8, 0x00, "the second value is 0");
    Ok(())
}

#[test]
fn test_group_write_updates_listener_and_emits_event() -> Result<(), Box<dyn std::error::Error>> {
    let sink = Arc::new(RecordingSink::new());
    let Some(dev) = da_tp_unloaded(sink.clone()) else {
        eprintln!("SKIP: DA.tp fixture not present");
        return Ok(());
    };
    let addr = dev.address();
    let mut bus = Bus::new(sink.clone());
    bus.add_device(dev);
    flash_two_object_device(&mut bus, addr)?;

    // A group write to 1/0/1 updates the writable object (asap 1) and publishes a
    // GroupObjectUpdated event on the observable stream.
    let write = group_telegram(Apci::GroupValueWrite, GroupAddress(0x0801), &[0x01]);
    bus.deliver_from_tool(&write);
    let updated = sink.events().into_iter().any(|e| {
        matches!(
            e,
            Event::GroupObjectUpdated { device, object, ga }
                if device == addr && object == 1 && ga == 0x0801
        )
    });
    assert!(updated, "a group write should update the listening object");
    Ok(())
}

/// Build a group telegram (`L_Data.req`) to `ga` carrying `payload`, packing a
/// single small octet into the APCI as the wire does.
fn group_telegram(apci: Apci, ga: GroupAddress, payload: &[u8]) -> CemiLData {
    let apci10 = apci.to_u10();
    let packable = payload.len() == 1 && payload[0] <= 0x3f;
    let tpdu = if packable {
        vec![
            (apci10 >> 8) as u8 & 0x03,
            ((apci10 & 0xc0) as u8) | (payload[0] & 0x3f),
        ]
    } else {
        let mut t = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xff) as u8];
        t.extend_from_slice(payload);
        t
    };
    CemiLData {
        message_code: MessageCode::LDataReq,
        ctrl1: 0xbc,
        ctrl2: 0xe0, // group destination
        source: IndividualAddress::new(0, 0, 15),
        dest: ga.raw(),
        tpdu,
    }
}
