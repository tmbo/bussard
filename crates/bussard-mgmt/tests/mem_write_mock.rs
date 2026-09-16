//! Integration tests for the phase-3 **write** primitives against an in-process
//! mock KNX device behind a mock KNXnet/IP gateway (the same UDP-loopback
//! pattern as `mock_device.rs` / `tables_mock.rs`).
//!
//! The mock device here is **de-mirrored**: it implements the KNX device
//! semantics independently of bussard's encoders, so a bug shared between the
//! encoder and a mirrored decoder cannot hide. It provides:
//!
//! - a **sparse, writable memory** (`HashMap<u16, u8>`) served by both
//!   `A_Memory_Read` and `A_Memory_Write`, with verify-on-read (a read returns
//!   exactly what was last written),
//! - the **10-octet AdditionalLoadControls** relative-segment allocation
//!   (`data[0]=3, data[1]=0x0B, data[2..6]=size, data[6]=fill, data[7]=byte`,
//!   decoded byte-by-byte here, not via bussard), answering a scripted allocated
//!   segment address through `PID_TABLE_REFERENCE`,
//! - the load-state machine (`PID_LOAD_STATE_CONTROL`) enough to drive
//!   `StartLoading` → allocate,
//! - failure scripts: a write that NAKs mid-chunk, a memory cell that reads back
//!   wrong (verify mismatch), and an allocation refusal (device goes to Error).
//!
//! Tests exercise: chunking boundaries (12-byte max, odd tails), verify failure
//! surfacing address + diff, allocation round-trip, and wrong-state allocation
//! refusal.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use bussard_mgmt::apci;
use bussard_mgmt::load::{self, LoadControl, LoadState};
use bussard_mgmt::{DeviceConnection, Layer4Connection, MgmtError, Timeouts, WriteError};
use bussard_model::IndividualAddress;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x17;

/// The load-state property (5) and the table-reference property (7); redeclared
/// here so the mock does not depend on bussard's constants for its *semantics*
/// (it may reference the numeric PID freely — these are wire facts).
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;

/// A de-mirrored mock System B device with writable memory and a loadable
/// object.
#[derive(Default)]
struct WriteDevice {
    /// Sparse, byte-addressable memory. A read returns 0 for unwritten cells.
    memory: HashMap<u16, u8>,
    /// Load state of object index 1 (the loadable table object under test).
    load_state: u8,
    /// The segment address the device hands back after a successful relative
    /// allocation (scripted).
    allocated_addr: u32,
    /// Whether the object has been allocated (drives PID_TABLE_REFERENCE: 0
    /// before allocation, `allocated_addr` after — mirrors thelsing).
    allocated: bool,
    // --- failure scripts ---
    /// If set, the Nth (0-based) `A_Memory_Write` telegram is NAKed instead of
    /// applied. Models a device that drops a write mid-chunk.
    nak_write_index: Option<usize>,
    /// Running count of `A_Memory_Write` telegrams seen.
    write_count: usize,
    /// If set, reads of this address return a fixed wrong byte regardless of
    /// what was written — models a cell that fails verify.
    corrupt_addr: Option<u16>,
    /// The byte a corrupt cell reads back as.
    corrupt_byte: u8,
    /// If true, a relative allocation is refused: the device goes to Error.
    refuse_allocation: bool,
}

type Shared = Arc<Mutex<WriteDevice>>;

// --- Mock gateway plumbing (same shape as tests/mock_device.rs) ---

async fn bind_mock() -> (SocketAddrV4, UdpSocket) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = match sock.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected v4"),
    };
    (addr, sock)
}

fn connect_response_body(channel: u8, gw: &UdpSocket) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(0x06);
    out.push(0x10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

async fn push_indication(
    gw: &UdpSocket,
    peer: std::net::SocketAddr,
    gw_seq: &mut u8,
    cemi: &CemiFrame,
) {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    let frame = knxnet::tunneling_request(hdr, cemi);
    gw.send_to(&frame, peer).await.unwrap();
    *gw_seq = gw_seq.wrapping_add(1);
}

/// Runs the mock gateway + de-mirrored device until the client disconnects.
async fn run_mock(gw: UdpSocket, address: IndividualAddress, dev: Shared) {
    let mut gw_seq: u8 = 0;
    let mut dev_send_seq: u8 = 0;

    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(5), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let parsed = match knxnet::parse(&buf[..n]) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, &gw),
                );
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::ConnectionstateRequest => {
                let resp = knxnet::connectionstate_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::DisconnectRequest => {
                let resp = knxnet::disconnect_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
                return;
            }
            ServiceType::TunnelingAck => {}
            ServiceType::TunnelingRequest => {
                let tr = match knxnet::parse_tunneling_request(parsed.body) {
                    Ok(tr) => tr,
                    Err(_) => continue,
                };
                let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                gw.send_to(&ack, from).await.unwrap();

                let cemi = &tr.cemi;
                let dest = match cemi.destination {
                    Destination::Individual(ia) => ia,
                    Destination::Group(_) => continue,
                };
                if dest != address {
                    continue; // absent address
                }
                let tool = cemi.source;
                match tpci::classify(cemi.tpci_octet()) {
                    TpciKind::Connect => dev_send_seq = 0,
                    TpciKind::NumberedData(client_seq) => {
                        // Decide whether to NAK (write-failure script) or ACK.
                        let nak = should_nak(&dev, cemi);
                        if nak {
                            let nak = CemiFrame::t_control(tool, address, tpci::t_nak(client_seq));
                            push_indication(&gw, from, &mut gw_seq, &nak).await;
                        } else {
                            let ack = CemiFrame::t_control(tool, address, tpci::t_ack(client_seq));
                            push_indication(&gw, from, &mut gw_seq, &ack).await;
                            if let Some((rapci, rdata)) = device_response(&dev, cemi) {
                                let resp = CemiFrame::t_data_connected(
                                    tool,
                                    address,
                                    tpci::ndt(dev_send_seq),
                                    rapci,
                                    &rdata,
                                );
                                push_indication(&gw, from, &mut gw_seq, &resp).await;
                                dev_send_seq = (dev_send_seq + 1) & 0x0f;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// The APCI selector mask for the low-6-bit services (memory read/write).
const APCI_SELECTOR: u16 = 0x3C0;
const A_MEMORY_READ: u16 = 0x200;
const A_MEMORY_WRITE: u16 = 0x280;

fn apci_and_data(cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    match (&cemi.tpci, &cemi.apdu) {
        (Tpci::Other(_), Apdu::Other { apci, data }) => Some((*apci, data.clone())),
        _ => None,
    }
}

/// Whether this telegram should be NAKed per the write-failure script. Applies
/// the write to memory as a side effect when it is *not* NAKed and is a write.
fn should_nak(dev: &Shared, cemi: &CemiFrame) -> bool {
    let Some((apci_val, data)) = apci_and_data(cemi) else {
        return false;
    };
    if apci_val & APCI_SELECTOR == A_MEMORY_WRITE {
        let mut d = dev.lock().unwrap();
        // Persistent NAK: once the scripted chunk index is reached, this write
        // (and every retransmission of it — style-1 repeats the same telegram)
        // is NAKed, so the client exhausts its retries and fails, as a real
        // device that rejects a chunk would. write_count only advances for
        // writes that are actually applied.
        if let Some(nak_at) = d.nak_write_index {
            if d.write_count >= nak_at {
                return true;
            }
        }
        d.write_count += 1;
        // Apply the write to sparse memory (de-mirrored: decode the wire here).
        if data.len() >= 2 {
            let addr = u16::from_be_bytes([data[0], data[1]]);
            let count = (apci_val & 0x3f) as usize;
            for (i, b) in data[2..].iter().take(count).enumerate() {
                d.memory.insert(addr.wrapping_add(i as u16), *b);
            }
        }
    }
    false
}

/// The de-mirrored device reaction that produces a *response* NDT (reads and the
/// allocation flow). Writes are applied in `should_nak` and produce no response.
fn device_response(dev: &Shared, cemi: &CemiFrame) -> Option<(u16, Vec<u8>)> {
    let (apci_val, data) = apci_and_data(cemi)?;

    // A_Memory_Read: answer from sparse memory (verify-on-read), honouring the
    // corrupt-cell script.
    if apci_val & APCI_SELECTOR == A_MEMORY_READ {
        if data.len() != 2 {
            return None; // strict: exactly the 2 address octets
        }
        let count = (apci_val & 0x3f) as u8;
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let d = dev.lock().unwrap();
        let bytes: Vec<u8> = (0..count)
            .map(|i| {
                let a = addr.wrapping_add(u16::from(i));
                if d.corrupt_addr == Some(a) {
                    d.corrupt_byte
                } else {
                    d.memory.get(&a).copied().unwrap_or(0)
                }
            })
            .collect();
        // Response: count in APCI low bits, payload = addr + data.
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&bytes);
        return Some((0x240 | u16::from(count), payload));
    }

    // Property services drive the load-state machine and allocation.
    if apci_val == apci::A_PROPERTY_VALUE_WRITE {
        return handle_property_write(dev, &data);
    }
    if apci_val == apci::A_PROPERTY_VALUE_READ {
        return handle_property_read(dev, &data);
    }
    None
}

/// Builds an `A_PropertyValue_Response` payload with an explicit element count.
fn property_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

fn handle_property_write(dev: &Shared, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    // 4-octet header (object, pid, count/start) then the value octets.
    if data.len() < 4 {
        return None;
    }
    let object_index = data[0];
    let pid = data[1];
    let start = (((data[2] & 0x0f) as u16) << 8) | data[3] as u16;
    let value = &data[4..];

    let mut d = dev.lock().unwrap();
    if pid == PID_LOAD_STATE_CONTROL {
        // De-mirrored decode of the load event (data[0] of the value).
        let event = value.first().copied().unwrap_or(0);
        match event {
            1 => d.load_state = 2, // StartLoading -> Loading
            2 => d.load_state = 1, // LoadCompleted -> Loaded
            4 => d.load_state = 0, // Unload -> Unloaded
            3 => {
                // AdditionalLoadControls: expect the 10-octet relative structure.
                // Decode byte-by-byte, independently of bussard's encoder.
                if value.len() >= 8 && value[1] == 0x0B {
                    if d.refuse_allocation {
                        d.load_state = 3; // Error
                    } else {
                        // size = value[2..6] big-endian; fill = value[6]; byte = value[7]
                        let size = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
                        let do_fill = value[6] == 0x01;
                        let fill_byte = value[7];
                        let base = d.allocated_addr;
                        if do_fill {
                            for i in 0..size {
                                d.memory
                                    .insert((base as u16).wrapping_add(i as u16), fill_byte);
                            }
                        }
                        d.allocated = true;
                        // stays Loading
                    }
                } else {
                    d.load_state = 3; // malformed structure -> Error
                }
            }
            _ => {}
        }
        // Echo the resulting state as the stored property octet.
        let resp = property_response(object_index, pid, 1, start, &[d.load_state]);
        return Some((apci::A_PROPERTY_VALUE_RESPONSE, resp));
    }
    // Unknown property write: echo empty (count 0) so bussard sees a non-match.
    let resp = property_response(object_index, pid, 0, start, &[]);
    Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
}

fn handle_property_read(dev: &Shared, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if data.len() < 4 {
        return None;
    }
    let object_index = data[0];
    let pid = data[1];
    let start = (((data[2] & 0x0f) as u16) << 8) | data[3] as u16;

    let d = dev.lock().unwrap();
    match pid {
        PID_LOAD_STATE_CONTROL => {
            let resp = property_response(object_index, pid, 1, start, &[d.load_state]);
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        PID_TABLE_REFERENCE => {
            // 0 before allocation, the scripted segment address after (u32 BE).
            let addr = if d.allocated { d.allocated_addr } else { 0 };
            let resp = property_response(object_index, pid, 1, start, &addr.to_be_bytes());
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        _ => {
            let resp = property_response(object_index, pid, 0, start, &[]);
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
    }
}

async fn open_bus(addr: SocketAddrV4) -> Transport {
    let config = ConnectionConfig::tunnel(addr);
    Transport::connect(&config).await.unwrap()
}

fn device() -> WriteDevice {
    WriteDevice {
        load_state: 0, // Unloaded
        allocated_addr: 0x4200,
        ..WriteDevice::default()
    }
}

fn fast() -> Timeouts {
    Timeouts {
        ack_timeout: Duration::from_millis(60),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(200),
    }
}

// --- Tests --------------------------------------------------------------

#[tokio::test]
async fn write_memory_chunks_and_verifies_round_trip() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw_task = tokio::spawn(run_mock(gw, target, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    // 27 bytes forces three chunks: 12 + 12 + an odd 3-byte tail.
    let payload: Vec<u8> = (0..27u8).map(|i| i.wrapping_mul(7)).collect();
    dev.write_memory(0x4000, &payload).await.unwrap();
    dev.disconnect().await.unwrap();

    // Every byte landed at its address in the device's independent memory map.
    {
        let d = shared.lock().unwrap();
        for (i, b) in payload.iter().enumerate() {
            assert_eq!(
                d.memory.get(&(0x4000 + i as u16)).copied(),
                Some(*b),
                "byte {i} mismatched in device memory"
            );
        }
        // Exactly three write telegrams (12/12/3).
        assert_eq!(
            d.write_count, 3,
            "27 bytes = three A_Memory_Write telegrams"
        );
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn write_memory_exact_single_chunk_boundary() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw_task = tokio::spawn(run_mock(gw, target, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    // Exactly 12 bytes: one full chunk, no tail.
    let payload: Vec<u8> = (0..12u8).collect();
    dev.write_memory(0x5000, &payload).await.unwrap();
    dev.disconnect().await.unwrap();

    {
        let d = shared.lock().unwrap();
        assert_eq!(d.write_count, 1, "12 bytes is a single A_Memory_Write");
        assert_eq!(d.memory.get(&0x5000).copied(), Some(0));
        assert_eq!(d.memory.get(&0x500B).copied(), Some(11));
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn write_memory_verify_mismatch_surfaces_address_and_diff() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let mut dev_state = device();
    // Address 0x4002 always reads back 0xFF regardless of what was written.
    dev_state.corrupt_addr = Some(0x4002);
    dev_state.corrupt_byte = 0xFF;
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw_task = tokio::spawn(run_mock(gw, target, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect(&mut bus, target, source)
        .await
        .unwrap();

    // Write 4 bytes covering the corrupt cell 0x4002.
    let err = dev
        .write_memory(0x4000, &[0x10, 0x11, 0x12, 0x13])
        .await
        .unwrap_err();
    assert!(err.device_present(), "a verify failure means present");
    match err {
        MgmtError::MemoryVerifyFailed {
            addr,
            expected,
            got,
            ..
        } => {
            assert_eq!(addr, 0x4000, "names the chunk start address");
            assert_eq!(expected, vec![0x10, 0x11, 0x12, 0x13]);
            // The corrupt cell (offset 2) reads 0xFF instead of 0x12.
            assert_eq!(got, vec![0x10, 0x11, 0xFF, 0x13]);
        }
        other => panic!("expected MemoryVerifyFailed, got {other:?}"),
    }
    dev.disconnect().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn write_memory_nak_mid_chunk_fails() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let mut dev_state = device();
    // NAK the second write telegram (0-based index 1).
    dev_state.nak_write_index = Some(1);
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw_task = tokio::spawn(run_mock(gw, target, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut dev = DeviceConnection::connect_with(&mut bus, target, source, fast())
        .await
        .unwrap();

    // 24 bytes = two 12-byte chunks; the second write NAKs.
    let payload: Vec<u8> = (0..24u8).collect();
    let err = dev.write_memory(0x4000, &payload).await.unwrap_err();
    assert!(
        matches!(err, MgmtError::Nak { .. }),
        "a NAK mid-chunk surfaces as Nak: {err:?}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn allocate_segment_round_trip_returns_device_address() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw_task = tokio::spawn(run_mock(gw, target, shared.clone()));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();

    // Object 1 must be Loading first (StartLoading).
    let state = load::write_load_control(&mut l4, 1, LoadControl::StartLoading)
        .await
        .unwrap();
    assert_eq!(state, LoadState::Loading);

    // Allocate a 320-octet segment, fill with 0x00.
    let seg = load::allocate_segment(&mut l4, 1, 320, Some(0x00), false)
        .await
        .unwrap();
    assert_eq!(seg.address, 0x4200, "the device-placed segment address");
    assert_eq!(seg.size, 320);

    let _ = l4.disconnect().await;

    // The fill wrote 0x00 across the segment; the object stayed Loading.
    {
        let d = shared.lock().unwrap();
        assert!(d.allocated);
        assert_eq!(d.load_state, 2, "object is still Loading after allocation");
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn allocate_segment_in_wrong_state_is_refused() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    // Object starts Unloaded (load_state 0); no StartLoading is issued.
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw_task = tokio::spawn(run_mock(gw, target, shared));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();

    // Allocating while Unloaded must be refused before any write.
    let err = load::allocate_segment(&mut l4, 1, 128, None, false)
        .await
        .unwrap_err();
    match err {
        WriteError::UnexpectedLoadState {
            expected, actual, ..
        } => {
            assert_eq!(expected, LoadState::Loading);
            assert_eq!(actual, LoadState::Unloaded);
        }
        other => panic!("expected UnexpectedLoadState, got {other:?}"),
    }
    let _ = l4.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}

#[tokio::test]
async fn allocate_segment_refusal_surfaces_load_error() {
    let (addr, gw) = bind_mock().await;
    let target: IndividualAddress = "1.1.4".parse().unwrap();
    let mut dev_state = device();
    dev_state.refuse_allocation = true; // device drops to Error on allocation
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw_task = tokio::spawn(run_mock(gw, target, shared));

    let mut bus = open_bus(addr).await;
    let source: IndividualAddress = "0.0.255".parse().unwrap();
    let mut l4 = Layer4Connection::connect(&mut bus, target, source)
        .await
        .unwrap();

    load::write_load_control(&mut l4, 1, LoadControl::StartLoading)
        .await
        .unwrap();

    let err = load::allocate_segment(&mut l4, 1, 0xFFFF_FFF0, None, false)
        .await
        .unwrap_err();
    match err {
        WriteError::LoadError { object_index, .. } => assert_eq!(object_index, 1),
        other => panic!("expected LoadError, got {other:?}"),
    }
    let _ = l4.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), gw_task).await;
}
