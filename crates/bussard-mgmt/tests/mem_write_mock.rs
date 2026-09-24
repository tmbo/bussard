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
//! Tests exercise: chunking boundaries (63-byte max, odd tails), verify failure
//! surfacing address + diff, allocation round-trip, and wrong-state allocation
//! refusal.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::load::{self, LoadControl, LoadState};
use bussard_mgmt::{
    DeviceConnection, Layer4Connection, MgmtError, SilenceKind, Timeouts, WriteError,
};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockError, MockGateway, Reaction, TestResult};
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
    /// before allocation, `allocated_addr` after).
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
    /// Running count of numbered data telegrams (NDTs) the tool has sent this
    /// session — every `T_Data_Connected`, be it a write, a read-back, or a
    /// property access. Lets a test compare the per-chunk vs batched
    /// numbered-message cost for the same payload (#50 discriminator).
    client_ndt_count: usize,
    /// If set, the mock goes silent (sends neither ACK nor response) once it has
    /// seen this many NDTs, modelling a device that wedges mid-session. The tool
    /// then hits its ACK timeout and surfaces a mid-session silence error.
    silent_after_ndt: Option<usize>,
    /// The octet count of every `A_Memory_Read` the tool sent, in order. Lets a
    /// test assert the reads were chunked to the device's negotiated APDU rather
    /// than a fixed 63 (issue #80).
    read_counts: Vec<u8>,
}

type Shared = Arc<Mutex<WriteDevice>>;

/// Locks the device state. A panicking holder only poisons the lock in a test
/// that has already failed, so the state is used as is.
fn lock(dev: &Shared) -> MutexGuard<'_, WriteDevice> {
    dev.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Starts a testkit gateway with the de-mirrored device at `address`.
///
/// The gateway stops when the client disconnects or when it is dropped.
async fn start_mock(address: IndividualAddress, dev: Shared) -> Result<MockGateway, MockError> {
    MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .device(
            MockDevice::new(address)
                .with_hook(move |_, apci_val, data| Some(react(&dev, apci_val, data))),
        )
        .start()
        .await
}

/// The device's reaction to one numbered data telegram.
fn react(dev: &Shared, apci_val: u16, data: &[u8]) -> Reaction {
    // Count this numbered telegram, and honour the mid-session silence script:
    // once the tool has sent `silent_after_ndt` NDTs, the device wedges (no ACK,
    // no response), so the tool's ACK timeout fires and surfaces a silence error.
    let go_silent = {
        let mut d = lock(dev);
        d.client_ndt_count += 1;
        matches!(d.silent_after_ndt, Some(n) if d.client_ndt_count > n)
    };
    if go_silent {
        return Reaction::Silent;
    }
    // Decide whether to NAK (write-failure script) or ACK.
    if should_nak(dev, apci_val, data) {
        return Reaction::Nak;
    }
    match device_response(dev, apci_val, data) {
        Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
        None => Reaction::Ack,
    }
}

/// The APCI selector mask for the low-6-bit services (memory read/write).
const APCI_SELECTOR: u16 = 0x3C0;
const A_MEMORY_READ: u16 = 0x200;
const A_MEMORY_WRITE: u16 = 0x280;

/// Whether this telegram should be NAKed per the write-failure script. Applies
/// the write to memory as a side effect when it is *not* NAKed and is a write.
fn should_nak(dev: &Shared, apci_val: u16, data: &[u8]) -> bool {
    if apci_val & APCI_SELECTOR == A_MEMORY_WRITE {
        let mut d = lock(dev);
        // Persistent NAK: once the scripted chunk index is reached, this write
        // (and every retransmission of it — style-1 repeats the same telegram)
        // is NAKed, so the client exhausts its retries and fails, as a real
        // device that rejects a chunk would. write_count only advances for
        // writes that are actually applied.
        if let Some(nak_at) = d.nak_write_index
            && d.write_count >= nak_at
        {
            return true;
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
fn device_response(dev: &Shared, apci_val: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    // A_Memory_Read: answer from sparse memory (verify-on-read), honouring the
    // corrupt-cell script.
    if apci_val & APCI_SELECTOR == A_MEMORY_READ {
        if data.len() != 2 {
            return None; // strict: exactly the 2 address octets
        }
        let count = (apci_val & 0x3f) as u8;
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mut d = lock(dev);
        d.read_counts.push(count);
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
        return handle_property_write(dev, data);
    }
    if apci_val == apci::A_PROPERTY_VALUE_READ {
        return handle_property_read(dev, data);
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

    let mut d = lock(dev);
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

    let d = lock(dev);
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

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    let config = ConnectionConfig::tunnel(addr);
    Ok(Transport::connect(&config).await?)
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
        absent_on_negative_confirmation: false,
    }
}

/// `compare_rel_mem` must chunk its read-back by the **negotiated** max-APDU: a
/// device advertising `PID_MAX_APDU_LENGTH = 15` takes 12-octet reads in standard
/// frames, and the fixed 63-octet chunk this used to send is an extended frame such
/// a device may reject (issue #80).
#[tokio::test]
async fn compare_rel_mem_chunks_by_the_negotiated_apdu() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let shared: Shared = Arc::new(Mutex::new(device()));
    // Seed 40 octets of segment content the compare will match.
    let expected: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(3)).collect();
    {
        let mut d = lock(&shared);
        for (i, b) in expected.iter().enumerate() {
            d.memory.insert(0x4200 + i as u16, *b);
        }
    }
    let gw = start_mock(target, shared.clone()).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;
    // A 15-octet APDU device: 15 - 3 octets of memory-read overhead = 12.
    l4.set_max_apdu(Some(15));

    load::compare_rel_mem(&mut l4, 1, 0x4200, 0, &expected, None, false)
        .await
        .map_err(|e| format!("the segment content matches, so the compare passes: {e}"))?;

    let counts = lock(&shared).read_counts.clone();
    assert_eq!(
        counts,
        vec![12, 12, 12, 4],
        "a 40-octet compare on a 15-octet-APDU device is four standard-frame reads"
    );

    drop(gw);
    Ok(())
}

// --- Tests --------------------------------------------------------------

#[tokio::test]
async fn write_memory_chunks_and_verifies_round_trip() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw = start_mock(target, shared.clone()).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    // 135 bytes forces three chunks at the 63-octet chunk size: 63 + 63 + an odd
    // 9-byte tail.
    let payload: Vec<u8> = (0..135u16).map(|i| (i as u8).wrapping_mul(7)).collect();
    dev.write_memory(0x4000, &payload).await?;
    dev.disconnect().await?;

    // Every byte landed at its address in the device's independent memory map.
    {
        let d = lock(&shared);
        for (i, b) in payload.iter().enumerate() {
            assert_eq!(
                d.memory.get(&(0x4000 + i as u16)).copied(),
                Some(*b),
                "byte {i} mismatched in device memory"
            );
        }
        // Exactly three write telegrams (63/63/9).
        assert_eq!(
            d.write_count, 3,
            "135 bytes = three A_Memory_Write telegrams at a 63-octet chunk size"
        );
    }
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn write_memory_exact_single_chunk_boundary() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw = start_mock(target, shared.clone()).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    // Exactly 63 bytes: one full chunk at the 63-octet chunk size, no tail.
    let payload: Vec<u8> = (0..63u8).collect();
    dev.write_memory(0x5000, &payload).await?;
    dev.disconnect().await?;

    {
        let d = lock(&shared);
        assert_eq!(d.write_count, 1, "63 bytes is a single A_Memory_Write");
        assert_eq!(d.memory.get(&0x5000).copied(), Some(0));
        assert_eq!(d.memory.get(&0x503E).copied(), Some(62));
    }
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn write_memory_verify_mismatch_surfaces_address_and_diff() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let mut dev_state = device();
    // Address 0x4002 always reads back 0xFF regardless of what was written.
    dev_state.corrupt_addr = Some(0x4002);
    dev_state.corrupt_byte = 0xFF;
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw = start_mock(target, shared.clone()).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;

    // Write 4 bytes covering the corrupt cell 0x4002.
    let err = dev
        .write_memory(0x4000, &[0x10, 0x11, 0x12, 0x13])
        .await
        .err()
        .ok_or("expected the call to fail, it succeeded")?;
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
    dev.disconnect().await?;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn write_memory_nak_mid_chunk_fails() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let mut dev_state = device();
    // NAK the second write telegram (0-based index 1).
    dev_state.nak_write_index = Some(1);
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw = start_mock(target, shared.clone()).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect_with(&mut bus, target, source, fast()).await?;

    // 126 bytes = two 63-byte chunks; the second write NAKs.
    let payload: Vec<u8> = (0..126u16).map(|i| i as u8).collect();
    let err = dev
        .write_memory(0x4000, &payload)
        .await
        .err()
        .ok_or("expected the call to fail, it succeeded")?;
    assert!(
        matches!(err, MgmtError::Nak { .. }),
        "a NAK mid-chunk surfaces as Nak: {err:?}"
    );
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn allocate_segment_round_trip_returns_device_address() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw = start_mock(target, shared.clone()).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;

    // Object 1 must be Loading first (StartLoading).
    let state = load::write_load_control(&mut l4, 1, LoadControl::StartLoading).await?;
    assert_eq!(state, LoadState::Loading);

    // Allocate a 320-octet segment, fill with 0x00.
    let seg = load::allocate_segment(&mut l4, 1, 320, Some(0x00)).await?;
    assert_eq!(seg.address, 0x4200, "the device-placed segment address");
    assert_eq!(seg.size, 320);

    let _ = l4.disconnect().await;

    // The fill wrote 0x00 across the segment; the object stayed Loading.
    {
        let d = lock(&shared);
        assert!(d.allocated);
        assert_eq!(d.load_state, 2, "object is still Loading after allocation");
    }
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn allocate_segment_in_wrong_state_is_refused() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    // Object starts Unloaded (load_state 0); no StartLoading is issued.
    let shared: Shared = Arc::new(Mutex::new(device()));
    let gw = start_mock(target, shared).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;

    // Allocating while Unloaded must be refused before any write.
    let err = load::allocate_segment(&mut l4, 1, 128, None)
        .await
        .err()
        .ok_or("expected the call to fail, it succeeded")?;
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
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn allocate_segment_refusal_surfaces_load_error() -> TestResult {
    let target: IndividualAddress = "1.1.4".parse()?;
    let mut dev_state = device();
    dev_state.refuse_allocation = true; // device drops to Error on allocation
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw = start_mock(target, shared).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, source).await?;

    load::write_load_control(&mut l4, 1, LoadControl::StartLoading).await?;

    let err = load::allocate_segment(&mut l4, 1, 0xFFFF_FFF0, None)
        .await
        .err()
        .ok_or("expected the call to fail, it succeeded")?;
    match err {
        WriteError::LoadError { object_index, .. } => assert_eq!(object_index, 1),
        other => panic!("expected LoadError, got {other:?}"),
    }
    let _ = l4.disconnect().await;
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn mid_session_silence_error_carries_exchange_counter() -> TestResult {
    // #50 item 3: when a device goes silent mid-session, the error folds in how
    // many numbered exchanges completed (and how many times the sequence wrapped),
    // so the next KV run measures the stall in protocol units, not just bytes.
    let target: IndividualAddress = "1.1.4".parse()?;
    let mut dev_state = device();
    // Answer the first 3 numbered telegrams, then wedge on the 4th.
    dev_state.silent_after_ndt = Some(3);
    let shared: Shared = Arc::new(Mutex::new(dev_state));
    let gw = start_mock(target, shared).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect_with(&mut bus, target, source, fast()).await?;

    // Three property reads succeed (3 acknowledged exchanges); the fourth draws
    // silence and surfaces the mid-session error with the counter.
    for _ in 0..3 {
        let _ = load::read_load_state(&mut l4, 1).await?;
    }
    let err = load::read_load_state(&mut l4, 1)
        .await
        .err()
        .ok_or("expected the call to fail, it succeeded")?;
    match err {
        WriteError::Mgmt(MgmtError::MidSessionSilence {
            kind,
            exchanges,
            wraps,
            ..
        }) => {
            assert_eq!(kind, SilenceKind::NoResponse, "a wedge is a no-response");
            assert_eq!(exchanges, 3, "three numbered exchanges completed first");
            assert_eq!(wraps, 0, "3 exchanges have not wrapped the 4-bit sequence");
        }
        other => panic!("expected MidSessionSilence, got {other:?}"),
    }
    let _ = l4.disconnect().await;
    drop(gw);
    Ok(())
}
