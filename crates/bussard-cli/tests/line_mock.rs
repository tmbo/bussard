//! End-to-end tests of `bussard plan --line` and `bussard apply --line` against
//! an in-process mock KNX gateway hosting a three-device line (issue #100).
//!
//! The line is deliberately mixed, because the whole point of a batch command is
//! what it does when one device misbehaves:
//!
//! * `1.1.4` — a System B device with writable, loadable tables (happy path);
//! * `1.1.5` — a System 1 (BCU1) device whose mask no table reader speaks, so it
//!   must be reported and **skipped** while the run continues;
//! * `1.1.6` — a System B device that persistently NAKs memory writes into its
//!   association-table segment, so its apply must **fail** while the run continues.
//!
//! The device model (load-state machine, `LdCtrlRelSegment` allocation,
//! `PID_TABLE_REFERENCE`, tables stored in memory segments) is written from the
//! KNX spec semantics, not from bussard's own encoder, exactly as
//! `bussard-download/tests/apply_mock.rs` does.
//! Every device counts the connected-mode telegrams and write services it sees,
//! which is how the resume test proves a finished device is never touched again.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE,
    PID_TABLE,
};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x55;

const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;
const APCI_SELECTOR: u16 = 0x3C0;

const LS_UNLOADED: u8 = 0;
const LS_LOADED: u8 = 1;
const LS_LOADING: u8 = 2;

const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_ADDITIONAL: u8 = 3;
const LE_UNLOAD: u8 = 4;
/// `AdditionalLoadControls` subtype `LdCtrlRelSegment`.
const SUB_REL_SEGMENT: u8 = 0x0B;

/// Where a table object's segment is placed: the address table at `0x4000`, the
/// association table `0x800` above it. A real device picks these itself and
/// reports them through `PID_TABLE_REFERENCE`; the mock is deterministic.
fn base_for(oi: u8) -> u32 {
    0x4000 + u32::from(oi.saturating_sub(1)) * 0x800
}

/// One scripted device on the line.
///
/// A System B table lives in an allocated memory segment, not in a writable
/// property array: `apply` allocates it with `LdCtrlRelSegment`, reads its base
/// from `PID_TABLE_REFERENCE`, streams the image with `A_Memory_Write`, and the
/// read side serves `PID_TABLE` straight out of that image.
#[derive(Clone)]
struct DeviceState {
    address: IndividualAddress,
    mask: u16,
    object_types: Vec<u16>,
    load_states: HashMap<u8, u8>,
    /// Per-object allocated segment: `(base, size)`.
    segments: HashMap<u8, (u32, u32)>,
    memory: HashMap<u32, u8>,
    /// The group-object table's element count (read side only).
    go_count: u16,
    /// Persistently NAK every memory write into the association segment.
    nak_assoc_writes: bool,
    /// Connected-mode requests this device answered, across all runs.
    telegrams: usize,
    /// Write services (property or memory) this device saw, across all runs.
    writes: usize,
}

impl DeviceState {
    fn elem_size(&self, oi: u8) -> usize {
        match self.object_types.get(usize::from(oi)) {
            Some(&OT_ASSOCIATION_TABLE) => 4,
            _ => 2,
        }
    }

    fn load_state(&self, oi: u8) -> u8 {
        self.load_states.get(&oi).copied().unwrap_or(LS_UNLOADED)
    }

    fn read_mem(&self, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                self.memory
                    .get(&addr.wrapping_add(i as u32))
                    .copied()
                    .unwrap_or(0)
            })
            .collect()
    }

    /// The segment `addr..addr+len` lies wholly inside, if any.
    fn segment_of(&self, addr: u32, len: usize) -> Option<u8> {
        let end = u64::from(addr) + len as u64;
        self.segments.iter().find_map(|(&oi, &(base, size))| {
            (u64::from(addr) >= u64::from(base) && end <= u64::from(base) + u64::from(size))
                .then_some(oi)
        })
    }

    /// Stores `value` at `addr`, or refuses it (outside every segment, or into
    /// the association segment while the write fault is armed).
    fn write_mem(&mut self, addr: u32, value: &[u8]) -> bool {
        let Some(oi) = self.segment_of(addr, value.len()) else {
            return false;
        };
        if self.nak_assoc_writes
            && self.object_types.get(usize::from(oi)) == Some(&OT_ASSOCIATION_TABLE)
        {
            return false;
        }
        for (i, b) in value.iter().enumerate() {
            self.memory.insert(addr.wrapping_add(i as u32), *b);
        }
        true
    }

    fn table_image(&self, oi: u8) -> Option<Vec<u8>> {
        let &(base, size) = self.segments.get(&oi)?;
        Some(self.read_mem(base, size as usize))
    }

    /// Places a table image (count word + elements) as if a download had run.
    fn preload(&mut self, oi: u8, image: &[u8]) {
        let base = base_for(oi);
        self.segments.insert(oi, (base, image.len() as u32));
        for (i, b) in image.iter().enumerate() {
            self.memory.insert(base + i as u32, *b);
        }
        self.load_states.insert(oi, LS_LOADED);
    }
}

type Shared = Arc<Mutex<Vec<DeviceState>>>;

/// The device's reaction to one management request.
enum Reaction {
    Answer(u16, Vec<u8>),
    Nak,
    Silent,
}

fn ga(s: &str) -> anyhow::Result<GroupAddress> {
    Ok(s.parse()?)
}

fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
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

fn connect_response_body(channel: u8, port: u16) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

async fn push(gw: &UdpSocket, peer: SocketAddr, gw_seq: &mut u8, cemi: &CemiFrame) -> bool {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    if gw
        .send_to(&knxnet::tunneling_request(hdr, cemi), peer)
        .await
        .is_err()
    {
        return false;
    }
    *gw_seq = gw_seq.wrapping_add(1);
    true
}

/// Builds a property-value response payload (4-octet header + data).
fn prop_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

/// Decodes a property-value read/write header from a request payload.
fn decode_prop_header(payload: &[u8]) -> Option<(u8, u8, u8, u16)> {
    if payload.len() < 4 {
        return None;
    }
    Some((
        payload[0],
        payload[1],
        (payload[2] >> 4) & 0x0f,
        (((payload[2] & 0x0f) as u16) << 8) | payload[3] as u16,
    ))
}

/// Answers one management request against one device's mutable state.
fn handle_request(dev: &mut DeviceState, req_apci: u16, data: &[u8]) -> Reaction {
    dev.telegrams += 1;

    if req_apci == apci::A_AUTHORIZE_REQUEST {
        return Reaction::Answer(apci::A_AUTHORIZE_RESPONSE, vec![0x00]);
    }
    if req_apci == apci::A_DEVICE_DESCRIPTOR_READ && data.is_empty() {
        return Reaction::Answer(
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        );
    }

    // --- Memory services ---
    if req_apci & APCI_SELECTOR == apci::A_MEMORY_READ {
        let count = usize::from(req_apci & 0x3f);
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&dev.read_mem(u32::from(addr), count));
        return Reaction::Answer(apci::A_MEMORY_RESPONSE | (count as u16 & 0x3f), payload);
    }
    if req_apci == apci::A_MEMORY_EXTENDED_READ {
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = usize::from(data[0]);
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut payload = vec![0x00, data[1], data[2], data[3]];
        payload.extend_from_slice(&dev.read_mem(addr, count));
        return Reaction::Answer(apci::A_MEMORY_EXTENDED_READ_RESPONSE, payload);
    }
    if req_apci == apci::A_MEMORY_EXTENDED_WRITE {
        dev.writes += 1;
        if data.len() < 4 {
            return Reaction::Nak;
        }
        let count = usize::from(data[0]);
        let addr = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        if data.len() < 4 + count || !dev.write_mem(addr, &data[4..4 + count]) {
            return Reaction::Nak;
        }
        return Reaction::Answer(
            apci::A_MEMORY_EXTENDED_WRITE_RESPONSE,
            vec![0x00, data[1], data[2], data[3]],
        );
    }
    if req_apci & APCI_SELECTOR == apci::A_MEMORY_WRITE {
        dev.writes += 1;
        if data.len() < 2 {
            return Reaction::Nak;
        }
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let value = data[2..].to_vec();
        if !dev.write_mem(u32::from(addr), &value) {
            return Reaction::Nak;
        }
        let mut payload = addr.to_be_bytes().to_vec();
        payload.extend_from_slice(&value);
        return Reaction::Answer(
            apci::A_MEMORY_RESPONSE | (value.len() as u16 & 0x3f),
            payload,
        );
    }

    // --- Property services ---
    if req_apci == apci::A_PROPERTY_VALUE_READ {
        let Some((oi, pid, count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let empty = || {
            Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 0, start, &[]),
            )
        };
        if pid == PID_OBJECT_TYPE {
            return match dev.object_types.get(usize::from(oi)) {
                Some(ot) => Reaction::Answer(
                    apci::A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &be16(*ot)),
                ),
                None => empty(),
            };
        }
        if pid == PID_LOAD_STATE_CONTROL {
            return Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[dev.load_state(oi)]),
            );
        }
        if pid == PID_TABLE_REFERENCE {
            let base = dev.segments.get(&oi).map(|&(b, _)| b).unwrap_or(0);
            return Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &base.to_be_bytes()),
            );
        }
        if pid == PID_TABLE {
            if dev.object_types.get(usize::from(oi)) == Some(&OT_GROUP_OBJECT_TABLE) {
                return if start == 0 {
                    Reaction::Answer(
                        apci::A_PROPERTY_VALUE_RESPONSE,
                        prop_response(oi, pid, 1, 0, &be16(dev.go_count)),
                    )
                } else {
                    empty()
                };
            }
            let elem_size = dev.elem_size(oi);
            let Some(image) = dev.table_image(oi) else {
                return empty();
            };
            if image.len() < 2 {
                return empty();
            }
            let stored = usize::from(u16::from_be_bytes([image[0], image[1]]));
            let total = stored.min((image.len() - 2) / elem_size);
            if start == 0 {
                return Reaction::Answer(
                    apci::A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, 0, &be16(total as u16)),
                );
            }
            let idx = usize::from(start);
            if idx > total {
                return empty();
            }
            let want = usize::from(count).clamp(1, total - idx + 1);
            let byte_start = 2 + (idx - 1) * elem_size;
            let chunk = image[byte_start..byte_start + want * elem_size].to_vec();
            return Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, want as u8, start, &chunk),
            );
        }
        return empty();
    }

    if req_apci == apci::A_PROPERTY_VALUE_WRITE {
        dev.writes += 1;
        let Some((oi, pid, _count, start)) = decode_prop_header(data) else {
            return Reaction::Nak;
        };
        let value = data[4..].to_vec();
        if pid == PID_LOAD_STATE_CONTROL {
            let event = value.first().copied().unwrap_or(0);
            // LdCtrlRelSegment: allocate a fresh segment of the requested size.
            if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
                if dev.load_state(oi) == LS_LOADING {
                    let size = if value.len() >= 6 {
                        u32::from_be_bytes([value[2], value[3], value[4], value[5]])
                    } else {
                        0
                    };
                    if let Some(&(old_base, old_size)) = dev.segments.get(&oi) {
                        for i in 0..old_size {
                            dev.memory.remove(&old_base.wrapping_add(i));
                        }
                    }
                    dev.segments.insert(oi, (base_for(oi), size));
                }
                return Reaction::Answer(
                    apci::A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &[dev.load_state(oi)]),
                );
            }
            let new_state = match event {
                LE_START_LOADING => LS_LOADING,
                LE_LOAD_COMPLETED => LS_LOADED,
                LE_UNLOAD => LS_UNLOADED,
                _ => dev.load_state(oi),
            };
            dev.load_states.insert(oi, new_state);
            return Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[new_state]),
            );
        }
        // Anything else (including a PID_TABLE write) is refused with a
        // zero-count response, as a real System B device does.
        return Reaction::Answer(
            apci::A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, 0, start, &[]),
        );
    }

    Reaction::Silent
}

/// Runs a mock gateway hosting the whole line. It deliberately keeps serving
/// after a `DisconnectRequest`, so a second `bussard` run (the resume test) still
/// finds the same devices with the same state.
async fn run_gateway(gw: UdpSocket, devices: Shared) {
    let Ok(local) = gw.local_addr() else {
        return;
    };
    let port = local.port();
    let mut gw_seq = 0u8;
    let mut dev_seq: HashMap<u16, u8> = HashMap::new();
    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(60), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, port),
                );
                if gw.send_to(&resp, from).await.is_err() {
                    return;
                }
            }
            ServiceType::ConnectionstateRequest => {
                if gw
                    .send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            ServiceType::DisconnectRequest => {
                if gw
                    .send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                if gw
                    .send_to(
                        &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                        from,
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                let cemi = &tr.cemi;
                let Destination::Individual(dest) = cemi.destination else {
                    continue;
                };
                {
                    let Ok(devs) = devices.lock() else { return };
                    if !devs.iter().any(|d| d.address == dest) {
                        continue;
                    }
                }
                let tool = cemi.source;
                match tpci::classify(cemi.tpci_octet()) {
                    TpciKind::Connect => {
                        dev_seq.insert(dest.raw(), 0);
                    }
                    TpciKind::Disconnect => {
                        dev_seq.remove(&dest.raw());
                    }
                    TpciKind::NumberedData(client_seq) => {
                        let (req_apci, payload) = match (&cemi.tpci, &cemi.apdu) {
                            (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
                            _ => continue,
                        };
                        let reaction = {
                            let Ok(mut devs) = devices.lock() else { return };
                            match devs.iter_mut().find(|d| d.address == dest) {
                                Some(dev) => handle_request(dev, req_apci, &payload),
                                None => continue,
                            }
                        };
                        match reaction {
                            Reaction::Silent => {}
                            Reaction::Nak => {
                                let nak = CemiFrame::t_control(tool, dest, tpci::t_nak(client_seq));
                                if !push(&gw, from, &mut gw_seq, &nak).await {
                                    return;
                                }
                            }
                            Reaction::Answer(rapci, rdata) => {
                                let ack = CemiFrame::t_control(tool, dest, tpci::t_ack(client_seq));
                                if !push(&gw, from, &mut gw_seq, &ack).await {
                                    return;
                                }
                                let seq = dev_seq.get(&dest.raw()).copied().unwrap_or(0);
                                let resp = CemiFrame::t_data_connected(
                                    tool,
                                    dest,
                                    tpci::ndt(seq),
                                    rapci,
                                    &rdata,
                                );
                                if !push(&gw, from, &mut gw_seq, &resp).await {
                                    return;
                                }
                                dev_seq.insert(dest.raw(), (seq + 1) & 0x0f);
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

/// A System B device carrying the tables the model will diff against: GAs
/// 1/2/0, 1/2/1 and 4/2/12, and associations (1,20), (2,21), (3,59). Object 59
/// → 4/2/12 is the ghost the model drops; object 22 → 1/2/2 is what it adds.
fn system_b_device(addr: &str, nak_assoc_writes: bool) -> anyhow::Result<DeviceState> {
    let mut addresses = be16(3);
    for g in ["1/2/0", "1/2/1", "4/2/12"] {
        addresses.extend_from_slice(&ga(g)?.raw().to_be_bytes());
    }
    let mut associations = be16(3);
    for (tsap, asap) in [(1u16, 20u16), (2, 21), (3, 59)] {
        associations.extend_from_slice(&tsap.to_be_bytes());
        associations.extend_from_slice(&asap.to_be_bytes());
    }
    let mut dev = DeviceState {
        address: addr.parse()?,
        mask: 0x07B0,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
        ],
        load_states: HashMap::new(),
        segments: HashMap::new(),
        memory: HashMap::new(),
        go_count: 60,
        nak_assoc_writes,
        telegrams: 0,
        writes: 0,
    };
    dev.preload(1, &addresses);
    dev.preload(2, &associations);
    Ok(dev)
}

/// A System 1 (BCU1) device: it answers the descriptor and nothing else, so the
/// table readers refuse its mask.
fn system_1_device(addr: &str) -> anyhow::Result<DeviceState> {
    Ok(DeviceState {
        address: addr.parse()?,
        mask: 0x0012,
        object_types: Vec::new(),
        load_states: HashMap::new(),
        segments: HashMap::new(),
        memory: HashMap::new(),
        go_count: 0,
        nak_assoc_writes: false,
        telegrams: 0,
        writes: 0,
    })
}

/// The scripted line: one good System B device, one unsupported mask, one
/// System B device that refuses association-table writes.
fn scripted_line() -> anyhow::Result<Vec<DeviceState>> {
    Ok(vec![
        system_b_device("1.1.4", false)?,
        system_1_device("1.1.5")?,
        system_b_device("1.1.6", true)?,
    ])
}

/// Writes the model: three devices on 1.1 and a link set that adds object 22 and
/// drops the ghost object 59 on both System B devices.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    for (addr, name) in [
        ("1.1.4", "Jalousie Wohnen"),
        ("1.1.5", "Alter Dimmer"),
        ("1.1.6", "Schaltaktor Kueche"),
    ] {
        std::fs::write(
            dir.join("devices").join(format!("{addr}.yaml")),
            format!("address: {addr}\nname: {name}\n"),
        )?;
    }
    let links = "links:\n".to_string()
        + &["1.1.4", "1.1.5", "1.1.6"]
            .iter()
            .map(|a| {
                format!(
                    "  {a}:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n  - object: 22\n    listen:\n    - 1/2/2\n"
                )
            })
            .collect::<String>();
    std::fs::write(dir.join("links.yaml"), links)?;
    Ok(())
}

/// A unique temporary directory for one test.
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bussard-line-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// Spawns the mock line, returning its port, the shared device state and the
/// gateway task handle.
fn spawn_line(
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<(u16, Shared, tokio::task::JoinHandle<()>)> {
    let (sock, port) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let port = sock.local_addr()?.port();
        anyhow::Ok((sock, port))
    })?;
    let shared: Shared = Arc::new(Mutex::new(scripted_line()?));
    let handle = rt.spawn(run_gateway(sock, Arc::clone(&shared)));
    Ok((port, shared, handle))
}

/// Runs the built `bussard` binary against the mock gateway.
fn run_bussard(port: u16, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let gw = format!("127.0.0.1:{port}");
    let mut all: Vec<&str> = args.to_vec();
    all.push("--gateway");
    all.push(&gw);
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&all)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

/// The per-device `(telegrams, writes)` counters.
fn counters(shared: &Shared, addr: &str) -> anyhow::Result<(usize, usize)> {
    let want: IndividualAddress = addr.parse()?;
    let devs = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("the mock device state was poisoned"))?;
    let dev = devs
        .iter()
        .find(|d| d.address == want)
        .ok_or_else(|| anyhow::anyhow!("no mock device at {addr}"))?;
    Ok((dev.telegrams, dev.writes))
}

/// Finds one device row in a `--json` summary.
fn row<'a>(json: &'a serde_json::Value, address: &str) -> anyhow::Result<&'a serde_json::Value> {
    json["devices"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no devices array in {json}"))?
        .iter()
        .find(|d| d["address"] == address)
        .ok_or_else(|| anyhow::anyhow!("no row for {address} in {json}"))
}

#[test]
fn test_plan_line_reports_every_device_and_skips_an_unsupported_mask() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (port, _shared, task) = spawn_line(&rt)?;

    let tmp = tmp_dir("plan");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?;
    let output = run_bussard(
        port,
        &["plan", "--line", "1.1", "--json", "--dir", model_arg],
    )?;
    task.abort();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "plan --line is read-only and must exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["line"], "1.1");
    assert_eq!(json["mode"], "plan");
    assert_eq!(json["total"], 3);

    // The good device has the one addition and the one removal.
    let good = row(&json, "1.1.4")?;
    assert_eq!(good["status"], "changes");
    assert_eq!(good["changes"], 2);
    assert_eq!(good["mask"], "07B0");

    // The unsupported mask is reported, skipped, and named.
    let old = row(&json, "1.1.5")?;
    assert_eq!(old["status"], "skipped");
    let detail = old["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("0012") && detail.contains("System 1"),
        "the skip must name the mask and family: {detail}"
    );

    // The run continued past it: the third device was planned too.
    assert_eq!(row(&json, "1.1.6")?["status"], "changes");
    assert_eq!(json["failed"], 0);
    Ok(())
}

#[test]
fn test_apply_line_continues_past_a_failure_and_resumes_without_rewriting() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (port, shared, task) = spawn_line(&rt)?;

    let tmp = tmp_dir("apply");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();
    let state_file = model_dir.join("captures").join("apply-line-1.1.json");

    // --- Run 1: 1.1.4 applies, 1.1.5 is skipped, 1.1.6 fails. ---
    let first = run_bussard(
        port,
        &[
            "apply", "--line", "1.1", "--yes", "--json", "--dir", &model_arg,
        ],
    )?;
    let first_out = String::from_utf8_lossy(&first.stdout).to_string();
    let first_err = String::from_utf8_lossy(&first.stderr).to_string();
    assert!(
        !first.status.success(),
        "a run with a failed device must exit non-zero; stdout:\n{first_out}\nstderr:\n{first_err}"
    );
    let json: serde_json::Value = serde_json::from_str(&first_out)?;
    assert_eq!(row(&json, "1.1.4")?["status"], "applied");
    assert_eq!(row(&json, "1.1.4")?["changes"], 2);
    assert_eq!(row(&json, "1.1.5")?["status"], "skipped");
    assert_eq!(row(&json, "1.1.6")?["status"], "failed");
    assert_eq!(json["failed"], 1);
    assert!(
        state_file.exists(),
        "an unfinished run must leave its state file at {}",
        state_file.display()
    );

    // The good device really was written.
    let (_, writes_before) = counters(&shared, "1.1.4")?;
    assert!(writes_before > 0, "1.1.4 must have been written");

    // --- Between the runs: the bad device is fixed and the counters reset. ---
    {
        let mut devs = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("the mock device state was poisoned"))?;
        for dev in devs.iter_mut() {
            dev.nak_assoc_writes = false;
            dev.telegrams = 0;
            dev.writes = 0;
        }
    }

    // --- Run 2: --resume must not touch the finished devices at all. ---
    let second = run_bussard(
        port,
        &[
            "apply", "--line", "1.1", "--yes", "--resume", "--json", "--dir", &model_arg,
        ],
    )?;
    task.abort();
    let second_out = String::from_utf8_lossy(&second.stdout).to_string();
    let second_err = String::from_utf8_lossy(&second.stderr).to_string();
    let second_ok = second.status.success();
    let counters_4 = counters(&shared, "1.1.4")?;
    let counters_6 = counters(&shared, "1.1.6")?;
    let state_left = state_file.exists();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        second_ok,
        "the resumed run must exit 0; stdout:\n{second_out}\nstderr:\n{second_err}"
    );
    let json: serde_json::Value = serde_json::from_str(&second_out)?;
    let done = row(&json, "1.1.4")?;
    assert_eq!(done["status"], "skipped");
    assert!(
        done["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("earlier run"),
        "the resume skip must say why: {done}"
    );
    assert_eq!(
        counters_4,
        (0, 0),
        "a finished device must see no telegrams and no writes on a --resume run"
    );

    // Only the previously-failed device was retried, and it succeeded.
    assert_eq!(row(&json, "1.1.6")?["status"], "applied");
    assert!(
        counters_6.1 > 0,
        "the retried device must be written on the resumed run"
    );
    assert!(
        !state_left,
        "a run that finishes cleanly must retire its state file"
    );
    Ok(())
}

#[test]
fn test_apply_line_refuses_without_a_tty_or_yes() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (port, _shared, task) = spawn_line(&rt)?;

    let tmp = tmp_dir("confirm");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();

    let output = run_bussard(port, &["apply", "--line", "1.1", "--dir", &model_arg])?;
    task.abort();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(!success, "a non-TTY run without --yes must fail");
    assert!(
        stderr.contains("without a terminal") && stderr.contains("127.0.0.1"),
        "the refusal must name the gateway: {stderr}"
    );
    Ok(())
}
