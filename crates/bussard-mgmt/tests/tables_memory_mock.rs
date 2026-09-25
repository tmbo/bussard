//! The memory path of the System B table read (issue #223) against the testkit
//! mock device: the tables read from memory at the negotiated chunk decode
//! exactly as the `PID_TABLE` property reads do, and every way a device can
//! decline the memory path (no reference, a refused or unanswered read, a count
//! word that disagrees) falls back to the property reads with the same result.
//!
//! The devices model 1.1.12 (a Data Secure push-button module, mask 07B0,
//! `PID_MAX_APDU_LENGTH = 233`, tables above `0xFFFF`, a group-object table of
//! 1,333 entries) and a large actuator with 400 group addresses and 1,333
//! associations.

use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bussard_mgmt::apci::{
    self, A_MEMORY_EXTENDED_READ, A_MEMORY_EXTENDED_READ_RESPONSE, A_MEMORY_READ,
    A_PROPERTY_VALUE_READ, A_PROPERTY_VALUE_RESPONSE,
};
use bussard_mgmt::tables::{
    self, DeviceTables, PID_TABLE, PID_TABLE_REFERENCE, TableSource, TablesError,
};
use bussard_mgmt::{Layer4Connection, MgmtError, SecureLayer, SilenceKind, Timeouts};
use bussard_model::IndividualAddress;
use bussard_secure::{DataSecureSession, Key16};
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, Step, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x23;

/// A synthetic tool key for the Data Secure mock (not a real key).
const TOOL_KEY: [u8; 16] = [0x5A; 16];

/// The max APDU 1.1.12 reports (`PID_MAX_APDU_LENGTH`, speed deep dive).
const MAX_APDU: u16 = 233;

/// Where the mock keeps the tables: above `0xFFFF`, like the 07B0 actuators'
/// `0xf000..0x1aad3` segments, so the memory path uses `A_MemoryExtended_Read`.
const ADDRESS_TABLE_BASE: u32 = 0x1_0000;
const ASSOCIATION_TABLE_BASE: u32 = 0x1_1000;
const GROUP_OBJECT_TABLE_BASE: u32 = 0x1_4000;

/// The group-object table size of 1.1.12 (the count word of its obj3 image).
const GO_ENTRIES: u16 = 1333;

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.12".parse()?)
}

/// A table image: the big-endian count word, then the entries.
fn image(entries: &[u8], elem_size: usize) -> Vec<u8> {
    let count = u16::try_from(entries.len() / elem_size).unwrap_or(u16::MAX);
    let mut out = count.to_be_bytes().to_vec();
    out.extend_from_slice(entries);
    out
}

/// Places a table image at `base` as the segment of `object_index`.
fn place(dev: &mut MockDevice, object_index: u8, base: u32, image: &[u8]) {
    let len = u32::try_from(image.len()).unwrap_or(u32::MAX);
    dev.segments.insert(object_index, (base, len));
    for (i, b) in image.iter().enumerate() {
        dev.memory.insert(base + i as u32, *b);
    }
}

/// A System B device with the given address table GAs (raw) and association
/// pairs, and a 1,333-entry group-object table.
fn device(gas: &[u16], associations: &[(u16, u16)]) -> Result<MockDevice, BoxError> {
    let mut dev = MockDevice::system_b(target()?).with_go_count(GO_ENTRIES);
    let addr: Vec<u8> = gas.iter().flat_map(|g| g.to_be_bytes()).collect();
    let assoc: Vec<u8> = associations
        .iter()
        .flat_map(|(t, a)| [t.to_be_bytes(), a.to_be_bytes()].concat())
        .collect();
    let go: Vec<u8> = (0..GO_ENTRIES)
        .flat_map(|i| (0x0040 | (i % 7)).to_be_bytes())
        .collect();
    place(&mut dev, 1, ADDRESS_TABLE_BASE, &image(&addr, 2));
    place(&mut dev, 2, ASSOCIATION_TABLE_BASE, &image(&assoc, 4));
    place(&mut dev, 3, GROUP_OBJECT_TABLE_BASE, &image(&go, 2));
    Ok(dev)
}

/// 1.1.12's tables: three group addresses, five associations.
fn small_device() -> Result<MockDevice, BoxError> {
    device(
        &[0x0005, 0x0006, 0x032F],
        &[(1, 65), (2, 66), (1, 69), (2, 70), (3, 1289)],
    )
}

/// A large actuator: 400 group addresses, 1,333 associations.
fn large_device() -> Result<MockDevice, BoxError> {
    let gas: Vec<u16> = (0..400u16).map(|i| 0x0800 + i).collect();
    let associations: Vec<(u16, u16)> = (0..GO_ENTRIES).map(|i| (i % 400 + 1, i + 1)).collect();
    device(&gas, &associations)
}

/// A scripted deviation from the mock's built-in behaviour, seeing the inner
/// (unwrapped) request.
type Fault = fn(u16, &[u8]) -> Option<Reaction>;

/// Answers `PID_TABLE_REFERENCE` with zero elements, as a device without it
/// does: the read takes the property path.
fn no_reference(apci: u16, data: &[u8]) -> Option<Reaction> {
    let pv = (apci == A_PROPERTY_VALUE_READ)
        .then(|| apci::decode_property_value_read(data))
        .flatten()?;
    (pv.property_id == PID_TABLE_REFERENCE).then(|| {
        Reaction::Answer(
            A_PROPERTY_VALUE_RESPONSE,
            bussard_testkit::device::prop_response(
                pv.object_index,
                PID_TABLE_REFERENCE,
                0,
                pv.start,
                &[],
            ),
        )
    })
}

/// How a run talks to the device.
#[derive(Clone, Copy)]
enum Link {
    /// Plain connection, max APDU seeded.
    Plain,
    /// KNX Data Secure, max APDU seeded (the 1.1.12 case).
    Secure,
}

/// One `read_tables` run: the result, the device's request log and the
/// wall-clock time of the read.
struct Run {
    result: Result<DeviceTables, TablesError>,
    requests: Vec<Request>,
    elapsed: Duration,
}

async fn run(device: MockDevice, link: Link, fault: Option<Fault>) -> Result<Run, BoxError> {
    // Log the inner requests: the device's own log holds the A_SecureData
    // wrappers on a secured link.
    let log: Arc<Mutex<Vec<Request>>> = Arc::default();
    let sink = Arc::clone(&log);
    let device = device.with_hook(move |_, apci, data| {
        if let Ok(mut log) = sink.lock() {
            log.push((apci, data.to_vec()));
        }
        fault.and_then(|f| f(apci, data))
    });
    let device = match link {
        Link::Plain => device,
        Link::Secure => device.with_data_secure(TOOL_KEY),
    };
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let secure = match link {
        Link::Plain => SecureLayer::plain(),
        Link::Secure => SecureLayer::activated(DataSecureSession::new(Key16::new(TOOL_KEY))),
    };
    let mut l4 = Layer4Connection::connect_with_secure(
        &mut bus,
        target()?,
        source,
        Timeouts::discovery(),
        secure,
    )
    .await?;
    l4.set_max_apdu(Some(MAX_APDU));
    let start = Instant::now();
    let result = tables::read_tables(&mut l4).await;
    let elapsed = start.elapsed();
    let _ = l4.disconnect().await;
    let requests = log.lock().map_err(|_| "request log poisoned")?.clone();
    Ok(Run {
        result,
        requests,
        elapsed,
    })
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(addr)).await?)
}

/// One request as the device saw it: `(apci, payload)`.
type Request = (u16, Vec<u8>);

/// The decoded content of a read: mask, GAs (raw), associations, resolved
/// links as `(object, raw GA)`, notes.
type Decoded = (u16, Vec<u16>, Vec<(u16, u16)>, Vec<(u16, u16)>, Vec<String>);

/// The decoded content of a read, without the per-table sources.
fn decoded(t: &DeviceTables) -> Decoded {
    (
        t.mask,
        t.addresses.iter().map(|g| g.raw()).collect(),
        t.associations.clone(),
        t.resolved.iter().map(|l| (l.object, l.ga.raw())).collect(),
        t.notes.clone(),
    )
}

fn sources(t: &DeviceTables) -> Vec<TableSource> {
    t.sources.iter().map(|(_, s)| *s).collect()
}

/// `(memory reads, PID_TABLE element reads)` in a request log.
fn read_counts(requests: &[Request]) -> (usize, usize) {
    let memory = requests
        .iter()
        .filter(|(a, _)| *a == A_MEMORY_EXTENDED_READ || (*a & 0x3C0) == A_MEMORY_READ)
        .count();
    let table = requests
        .iter()
        .filter(|(a, _)| *a == A_PROPERTY_VALUE_READ)
        .filter_map(|(_, d)| apci::decode_property_value_read(d))
        .filter(|pv| pv.property_id == PID_TABLE && pv.start > 0)
        .count();
    (memory, table)
}

#[tokio::test]
async fn test_read_tables_memory_path_matches_property_path_on_large_tables() -> TestResult {
    let fast = run(large_device()?, Link::Plain, None).await?;
    let slow = run(large_device()?, Link::Plain, Some(no_reference)).await?;
    let fast_tables = fast.result?;
    let slow_tables = slow.result?;
    assert_eq!(decoded(&fast_tables), decoded(&slow_tables));
    assert_eq!(fast_tables.addresses.len(), 400);
    assert_eq!(fast_tables.associations.len(), usize::from(GO_ENTRIES));
    assert_eq!(
        sources(&fast_tables),
        vec![TableSource::Memory, TableSource::Memory]
    );
    assert_eq!(
        sources(&slow_tables),
        vec![TableSource::Property, TableSource::Property]
    );
    let (fast_memory, fast_table) = read_counts(&fast.requests);
    assert_eq!(
        fast_table, 0,
        "no PID_TABLE element reads on the memory path"
    );
    // 802 and 5,334 octets at the 228-octet extended chunk of a 233-octet APDU.
    assert_eq!(fast_memory, 4 + 24);
    assert!(fast.requests.len() < slow.requests.len() / 3);
    Ok(())
}

#[tokio::test]
async fn test_read_tables_memory_path_matches_property_path_under_data_secure() -> TestResult {
    let fast = run(large_device()?, Link::Secure, None).await?;
    let slow = run(large_device()?, Link::Secure, Some(no_reference)).await?;
    let fast_tables = fast.result?;
    assert_eq!(decoded(&fast_tables), decoded(&slow.result?));
    assert_eq!(
        sources(&fast_tables),
        vec![TableSource::Memory, TableSource::Memory]
    );
    // The secured inner APDU leaves 215 octets per A_MemoryExtended_Read.
    let (fast_memory, _) = read_counts(&fast.requests);
    assert_eq!(fast_memory, 4 + 25);
    Ok(())
}

#[tokio::test]
async fn test_read_tables_small_tables_keep_the_property_path() -> TestResult {
    // 1.1.12's three addresses and five associations fit one PID_TABLE read
    // each, fewer requests than a reference read plus a memory read: the wire
    // stays exactly what it was.
    let read = run(small_device()?, Link::Secure, None).await?;
    let tables = read.result?;
    assert_eq!(
        sources(&tables),
        vec![TableSource::Property, TableSource::Property]
    );
    assert_eq!(tables.addresses.len(), 3);
    assert_eq!(tables.resolved.len(), 5);
    assert!(
        tables
            .notes
            .iter()
            .any(|n| n.starts_with("group object table: 1333 entries"))
    );
    let references = read
        .requests
        .iter()
        .filter(|(a, _)| *a == A_PROPERTY_VALUE_READ)
        .filter_map(|(_, d)| apci::decode_property_value_read(d))
        .filter(|pv| pv.property_id == PID_TABLE_REFERENCE)
        .count();
    assert_eq!(references, 0);
    assert_eq!(read_counts(&read.requests), (0, 2));
    Ok(())
}

#[tokio::test]
async fn test_read_tables_refused_extended_memory_read_falls_back() -> TestResult {
    fn refuse(apci: u16, data: &[u8]) -> Option<Reaction> {
        (apci == A_MEMORY_EXTENDED_READ && data.len() >= 4).then(|| {
            Reaction::Answer(
                A_MEMORY_EXTENDED_READ_RESPONSE,
                vec![0x01, data[1], data[2], data[3]],
            )
        })
    }
    let fallback = run(large_device()?, Link::Plain, Some(refuse)).await?;
    let slow = run(large_device()?, Link::Plain, Some(no_reference)).await?;
    let tables = fallback.result?;
    assert_eq!(decoded(&tables), decoded(&slow.result?));
    assert_eq!(
        sources(&tables),
        vec![TableSource::Property, TableSource::Property]
    );
    Ok(())
}

#[tokio::test]
async fn test_read_tables_unanswered_memory_read_falls_back() -> TestResult {
    fn ack_only(apci: u16, _: &[u8]) -> Option<Reaction> {
        (apci == A_MEMORY_EXTENDED_READ).then_some(Reaction::Ack)
    }
    let fallback = run(large_device()?, Link::Plain, Some(ack_only)).await?;
    let slow = run(large_device()?, Link::Plain, Some(no_reference)).await?;
    let tables = fallback.result?;
    assert_eq!(decoded(&tables), decoded(&slow.result?));
    assert_eq!(
        sources(&tables),
        vec![TableSource::Property, TableSource::Property]
    );
    Ok(())
}

#[tokio::test]
async fn test_read_tables_count_word_mismatch_falls_back() -> TestResult {
    // The device's PID_TABLE count says 399 addresses, its memory count word
    // 400: the property view wins, as it did before the memory path existed.
    fn short_count(apci: u16, data: &[u8]) -> Option<Reaction> {
        let pv = (apci == A_PROPERTY_VALUE_READ)
            .then(|| apci::decode_property_value_read(data))
            .flatten()?;
        (pv.object_index == 1 && pv.property_id == PID_TABLE && pv.start == 0).then(|| {
            Reaction::Answer(
                A_PROPERTY_VALUE_RESPONSE,
                bussard_testkit::device::prop_response(1, PID_TABLE, 1, 0, &399u16.to_be_bytes()),
            )
        })
    }
    let fallback = run(large_device()?, Link::Plain, Some(short_count)).await?;
    let tables = fallback.result?;
    assert_eq!(tables.addresses.len(), 399);
    assert_eq!(
        sources(&tables),
        vec![TableSource::Property, TableSource::Memory]
    );
    let slow = run(large_device()?, Link::Plain, Some(no_reference)).await?;
    let slow_tables = slow.result?;
    assert_eq!(tables.addresses[..], slow_tables.addresses[..399]);
    assert_eq!(tables.associations, slow_tables.associations);
    Ok(())
}

#[tokio::test]
async fn test_read_tables_disconnect_on_memory_read_is_an_error() -> TestResult {
    // A disconnect is not a refusal: the connection is gone, so the read
    // surfaces it instead of silently falling back on a dead link.
    fn hang_up(apci: u16, _: &[u8]) -> Option<Reaction> {
        (apci == A_MEMORY_EXTENDED_READ)
            .then(|| Reaction::Script(vec![Step::Ack, Step::Control(0x81)]))
    }
    let read = run(large_device()?, Link::Plain, Some(hang_up)).await?;
    assert!(
        matches!(
            read.result,
            Err(TablesError::Mgmt(
                MgmtError::Disconnected { .. }
                    | MgmtError::MidSessionSilence {
                        kind: SilenceKind::Disconnected,
                        ..
                    }
            ))
        ),
        "{:?}",
        read.result.map(|t| t.sources)
    );
    Ok(())
}

/// Request count and wall-clock of the table read with a 200 ms answer delay
/// (the Data Secure devices of the speed deep dive). Run by hand:
/// `cargo test -p bussard-mgmt --test tables_memory_mock -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "measurement, about a minute of 200 ms answer delays"]
async fn measure_read_tables_requests_and_wall_clock() -> TestResult {
    let delay = Duration::from_millis(200);
    for (name, dev) in [
        ("1.1.12-like (3 GAs, 5 assoc, 1333 GOs)", small_device()?),
        ("large (400 GAs, 1333 assoc, 1333 GOs)", large_device()?),
    ] {
        let read = run(dev.with_response_delay(delay), Link::Secure, None).await?;
        let tables = read.result?;
        let (memory, table) = read_counts(&read.requests);
        println!(
            "{name}: {} requests ({memory} memory reads, {table} PID_TABLE element reads), \
             {:.1} s, sources {:?}",
            read.requests.len(),
            read.elapsed.as_secs_f64(),
            sources(&tables)
        );
    }
    Ok(())
}
