//! `PID_IO_LIST` object discovery (issue #209) against the testkit mock
//! device: the fast path and the `PID_OBJECT_TYPE` walk yield the same table,
//! and every way a device can decline the fast path falls back to the walk.

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::apci::{self, A_PROPERTY_VALUE_READ};
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_mgmt::{
    ConnectionSeed, Layer4Connection, ObjectTableSource, PID_IO_LIST, PID_OBJECT_TYPE, Timeouts,
    discover_object_table, probe_object_types,
};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x31;

/// The 11 interface objects of a 1.1.12-like Data Secure push-button module.
const TYPES: [u16; 11] = [
    OT_DEVICE,
    OT_ADDRESS_TABLE,
    OT_ASSOCIATION_TABLE,
    OT_APPLICATION_PROGRAM,
    4,
    6,
    OT_GROUP_OBJECT_TABLE,
    17,
    OT_APPLICATION_PROGRAM,
    8,
    19,
];

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.12".parse()?)
}

fn device() -> Result<MockDevice, BoxError> {
    Ok(MockDevice::new(target()?).with_object_types(&TYPES))
}

/// Runs `discover_object_table` against `device` (with `max_apdu` seeded),
/// returning the table, its source and the device's request log.
async fn discover(
    device: MockDevice,
    max_apdu: Option<u16>,
) -> Result<((Vec<(u8, u16)>, ObjectTableSource), Vec<(u16, Vec<u8>)>), BoxError> {
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .device(device)
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect_with(
        &mut bus,
        target()?,
        "0.0.255".parse()?,
        Timeouts::discovery(),
    )
    .await?;
    l4.set_max_apdu(max_apdu);
    let result = discover_object_table(&mut l4).await?;
    let _ = l4.disconnect().await;
    let requests = gw.with_device(target()?, |d| d.requests.clone())?;
    Ok((result, requests))
}

async fn walk(device: MockDevice) -> Result<Vec<(u8, u16)>, BoxError> {
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .device(device)
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect_with(
        &mut bus,
        target()?,
        "0.0.255".parse()?,
        Timeouts::discovery(),
    )
    .await?;
    let table = probe_object_types(&mut l4).await?;
    let _ = l4.disconnect().await;
    Ok(table)
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(addr)).await?)
}

/// The property reads in a request log, as `(object, pid, count, start)`.
fn property_reads(requests: &[(u16, Vec<u8>)]) -> Vec<(u8, u8, u8, u16)> {
    requests
        .iter()
        .filter(|(apci, _)| *apci == A_PROPERTY_VALUE_READ)
        .filter_map(|(_, data)| apci::decode_property_value_read(data))
        .map(|pv| (pv.object_index, pv.property_id, pv.count, pv.start))
        .collect()
}

fn expected() -> Vec<(u8, u16)> {
    TYPES
        .iter()
        .enumerate()
        .map(|(i, ot)| (i as u8, *ot))
        .collect()
}

#[tokio::test]
async fn test_discover_object_table_io_list_matches_walk() -> TestResult {
    let slow = walk(device()?).await?;
    // Secure-sized APDU: all 11 types in one multi-element read.
    let ((fast, source), requests) = discover(device()?, Some(233)).await?;
    assert_eq!(source, ObjectTableSource::IoList);
    assert_eq!(fast, slow);
    assert_eq!(fast, expected());
    let reads = property_reads(&requests);
    // Count, one 11-element read, then the check: last object, first
    // application object, the terminating index.
    assert_eq!(
        reads,
        vec![
            (0, PID_IO_LIST, 1, 0),
            (0, PID_IO_LIST, 11, 1),
            (10, PID_OBJECT_TYPE, 1, 1),
            (3, PID_OBJECT_TYPE, 1, 1),
            (11, PID_OBJECT_TYPE, 1, 1),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn test_discover_object_table_standard_frames_read_in_chunks() -> TestResult {
    // No max APDU: 8 value octets per read, 4 types each.
    let ((fast, source), requests) = discover(device()?, None).await?;
    assert_eq!(source, ObjectTableSource::IoList);
    assert_eq!(fast, expected());
    let io_reads: Vec<_> = property_reads(&requests)
        .into_iter()
        .filter(|r| r.1 == PID_IO_LIST)
        .collect();
    assert_eq!(
        io_reads,
        vec![
            (0, PID_IO_LIST, 1, 0),
            (0, PID_IO_LIST, 4, 1),
            (0, PID_IO_LIST, 4, 5),
            (0, PID_IO_LIST, 3, 9),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn test_discover_object_table_falls_back_when_io_list_refused() -> TestResult {
    let ((table, source), requests) = discover(device()?.without_io_list(), Some(233)).await?;
    assert_eq!(source, ObjectTableSource::Walk);
    assert_eq!(table, expected());
    let reads = property_reads(&requests);
    assert_eq!(reads[0], (0, PID_IO_LIST, 1, 0));
    // One refused count read, then the whole walk (11 objects + terminator).
    assert_eq!(reads.len(), 1 + 12);
    Ok(())
}

#[tokio::test]
async fn test_discover_object_table_falls_back_when_multi_element_refused() -> TestResult {
    let ((table, source), requests) =
        discover(device()?.with_single_element_reads(), Some(233)).await?;
    assert_eq!(source, ObjectTableSource::Walk);
    assert_eq!(table, expected());
    let reads = property_reads(&requests);
    assert_eq!(
        &reads[..2],
        &[(0, PID_IO_LIST, 1, 0), (0, PID_IO_LIST, 11, 1)]
    );
    assert_eq!(reads.len(), 2 + 12);
    Ok(())
}

#[tokio::test]
async fn test_discover_object_table_falls_back_when_io_list_unanswered() -> TestResult {
    // The device T_ACKs the PID_IO_LIST read and never answers it.
    let dev = device()?.with_hook(|_, apci, data| {
        let pv = apci::decode_property_value_read(data)?;
        (apci == A_PROPERTY_VALUE_READ && pv.property_id == PID_IO_LIST).then_some(Reaction::Ack)
    });
    let ((table, source), _) = discover(dev, Some(233)).await?;
    assert_eq!(source, ObjectTableSource::Walk);
    assert_eq!(table, expected());
    Ok(())
}

#[tokio::test]
async fn test_discover_object_table_falls_back_when_io_list_disagrees() -> TestResult {
    // The list names one object fewer than the device has: the terminator
    // check finds object 10 and the walk runs.
    let dev = device()?.with_hook(|_, apci, data| {
        let pv = apci::decode_property_value_read(data)?;
        if apci != A_PROPERTY_VALUE_READ || pv.property_id != PID_IO_LIST {
            return None;
        }
        let mut payload = vec![0, PID_IO_LIST];
        if pv.start == 0 {
            payload.extend_from_slice(&[0x10, 0x00, 0x00, 10]);
        } else {
            let n = pv.count.min(10);
            payload.extend_from_slice(&[n << 4, pv.start as u8]);
            for ot in TYPES
                .iter()
                .skip(usize::from(pv.start) - 1)
                .take(usize::from(n))
            {
                payload.extend_from_slice(&ot.to_be_bytes());
            }
        }
        Some(Reaction::Answer(apci::A_PROPERTY_VALUE_RESPONSE, payload))
    });
    let ((table, source), _) = discover(dev, Some(233)).await?;
    assert_eq!(source, ObjectTableSource::Walk);
    assert_eq!(table, expected());
    Ok(())
}

#[tokio::test]
async fn test_probe_object_types_uses_seeded_table() -> TestResult {
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .device(device()?)
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect_with(
        &mut bus,
        target()?,
        "0.0.255".parse()?,
        Timeouts::discovery(),
    )
    .await?;
    l4.seed(ConnectionSeed {
        mask: Some(0x07B0),
        object_table: expected(),
        max_apdu: Some(233),
        authorize_unanswered: false,
    });
    assert_eq!(probe_object_types(&mut l4).await?, expected());
    assert_eq!(l4.negotiate_max_apdu().await?, Some(233));
    let _ = l4.disconnect().await;
    let requests = gw.with_device(target()?, |d| d.requests.clone())?;
    assert!(
        requests.is_empty(),
        "a seeded walk sends nothing: {requests:?}"
    );
    Ok(())
}
