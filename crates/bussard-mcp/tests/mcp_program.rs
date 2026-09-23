//! Mock-gateway tests of the MCP programming tier (issue #118):
//! `knx_plan_device` and `knx_apply_device`.
//!
//! The mock is the writable System B device of `bussard-cli/tests/line_mock.rs`
//! (load-state machine, `LdCtrlRelSegment` allocation, `PID_TABLE_REFERENCE`,
//! tables in memory segments, written from the KNX spec semantics), hosted on a
//! loopback KNXnet/IP tunnel. The full MCP server runs in process over a duplex
//! transport against it.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`,
//! and the non-loopback case never opens a bus at all.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_OBJECT_TYPE,
    PID_TABLE,
};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::ConnectionConfig;
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};
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

/// Writes the model: device 1.1.4 with links that add object 22 → 1/2/2 and
/// drop the device's ghost object 59 → 4/2/12.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join("1.1.4.yaml"),
        "address: 1.1.4\nname: Jalousie Wohnen\n",
    )?;
    std::fs::write(
        dir.join("groups.yaml"),
        "groups:\n  1/2/0:\n    name: Blind move\n  1/2/1:\n    name: Blind stop\n  1/2/2:\n    name: Blind position\n",
    )?;
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.4:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n  - object: 22\n    listen:\n    - 1/2/2\n",
    )?;
    Ok(())
}

/// One running server plus its mock line.
struct Harness {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    server_task: tokio::task::JoinHandle<()>,
    gateway_task: tokio::task::JoinHandle<()>,
    devices: Shared,
    port: u16,
    dir: tempfile::TempDir,
}

impl Harness {
    /// Starts the mock device and a programming-tier server against it.
    async fn start(plan_ttl: Duration) -> anyhow::Result<Harness> {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let port = sock.local_addr()?.port();
        let devices: Shared = Arc::new(Mutex::new(vec![system_b_device("1.1.4", false)?]));
        let gateway_task = tokio::spawn(run_gateway(sock, Arc::clone(&devices)));

        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let connection = ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), port));
        let (client, server_task) = serve(dir.path(), connection.clone(), plan_ttl, true).await?;
        Ok(Harness {
            client,
            server_task,
            gateway_task,
            devices,
            port,
            dir,
        })
    }

    async fn call(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        call(&self.client, tool, args).await
    }

    /// The device's `(address table, association table)` as the mock holds them.
    fn tables(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let devs = self
            .devices
            .lock()
            .map_err(|_| anyhow::anyhow!("mock state poisoned"))?;
        let dev = devs.first().ok_or_else(|| anyhow::anyhow!("no device"))?;
        Ok((
            dev.table_image(1).unwrap_or_default(),
            dev.table_image(2).unwrap_or_default(),
        ))
    }

    fn writes(&self) -> anyhow::Result<usize> {
        let devs = self
            .devices
            .lock()
            .map_err(|_| anyhow::anyhow!("mock state poisoned"))?;
        Ok(devs.first().map(|d| d.writes).unwrap_or(0))
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.client.cancel().await?;
        self.server_task.abort();
        self.gateway_task.abort();
        Ok(())
    }
}

/// Builds the state from a model directory and serves it over a duplex
/// transport, spawning the bus actor only when `with_bus` is set.
async fn serve(
    dir: &Path,
    connection: ConnectionConfig,
    plan_ttl: Duration,
    with_bus: bool,
) -> anyhow::Result<(
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
)> {
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: connection.clone(),
        passive: false,
        allow_writes: false,
        no_model_edits: true,
        capture_db: None,
        allow_programming: true,
        allow_remote_gateway: false,
        plan_ttl,
    };
    let state = bussard_mcp::build_state(&config)?;
    if with_bus {
        let (handle, _task) = bussard_bus::Bus::connect(connection);
        if !handle.wait_connected(Duration::from_secs(5)).await {
            anyhow::bail!("the mock tunnel did not come up");
        }
        state.bus.wire(handle);
    }
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, server_task))
}

/// Calls one tool and returns its structured result.
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let Value::Object(map) = args else {
        anyhow::bail!("tool arguments must be an object");
    };
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        client.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
    )
    .await??;
    res.structured_content
        .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
}

fn digest_of(plan: &Value) -> anyhow::Result<String> {
    plan["plan_digest"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))
}

#[tokio::test]
async fn test_knx_apply_device_round_trip_plans_writes_and_verifies() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false);
    let text = plan["plan"].as_str().unwrap_or_default();
    assert!(
        text.contains("1 addition(s), 1 removal(s), 2 unchanged:"),
        "{text}"
    );
    assert!(text.contains("+ add:    object   22 → 1/2/2"), "{text}");
    assert!(text.contains("- remove: object   59 → 4/2/12"), "{text}");
    assert!(text.contains("load operations"), "{text}");
    let digest = digest_of(&plan)?;
    assert_eq!(digest.len(), 64);
    assert!(plan["planned_at"].is_string());
    assert_eq!(h.writes()?, 0, "planning must not write");

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true);
    let gateway = format!("127.0.0.1:{}", h.port);
    assert_eq!(applied["gateway"], gateway.as_str());
    let backup = applied["backup"].as_str().unwrap_or_default();
    assert!(Path::new(backup).is_file(), "backup {backup} must exist");

    // The device now holds the model's tables: 1/2/0, 1/2/1, 1/2/2 and the
    // associations (1,20), (2,21), (3,22).
    let (addresses, associations) = h.tables()?;
    let mut want_addresses = be16(3);
    for g in ["1/2/0", "1/2/1", "1/2/2"] {
        want_addresses.extend_from_slice(&ga(g)?.raw().to_be_bytes());
    }
    assert_eq!(addresses, want_addresses);
    let mut want_associations = be16(3);
    for (tsap, asap) in [(1u16, 20u16), (2, 21), (3, 22)] {
        want_associations.extend_from_slice(&tsap.to_be_bytes());
        want_associations.extend_from_slice(&asap.to_be_bytes());
    }
    assert_eq!(associations, want_associations);

    // The audit line: a history snapshot naming the device and the gateway.
    let latest = bussard_model::history::History::open(h.dir.path())
        .latest()?
        .ok_or_else(|| anyhow::anyhow!("no history snapshot recorded"))?;
    assert_eq!(latest.manifest.reason.command, "mcp knx_apply_device");
    assert_eq!(
        latest.manifest.reason.args.first().map(String::as_str),
        Some("1.1.4")
    );
    assert_eq!(latest.manifest.gateway.as_deref(), Some(gateway.as_str()));

    // A digest is single use.
    let again = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(
        again["refused"], true,
        "a spent digest must be refused: {again}"
    );

    // A fresh plan now has nothing to do.
    let replan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert!(replan["plan_digest"].is_null());

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_without_fresh_digest_is_refused() -> anyhow::Result<()> {
    // A zero lifetime: every plan is already stale when apply looks at it.
    let h = Harness::start(Duration::ZERO).await?;

    let unknown = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": "00".repeat(32)}),
        )
        .await?;
    assert_eq!(unknown["refused"], true, "{unknown}");
    assert!(
        unknown["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no fresh plan"),
        "{unknown}"
    );

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let stale = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(
        stale["refused"], true,
        "an expired plan must be refused: {stale}"
    );
    assert_eq!(h.writes()?, 0, "a refused apply must not write");

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_refuses_when_live_tables_changed() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;

    // Someone (ETS, another tool) rewrites the device's address table between
    // the plan and the apply.
    {
        let mut devs = h
            .devices
            .lock()
            .map_err(|_| anyhow::anyhow!("mock state poisoned"))?;
        let dev = devs
            .first_mut()
            .ok_or_else(|| anyhow::anyhow!("no device"))?;
        let mut addresses = be16(3);
        for g in ["1/2/0", "1/2/1", "5/0/0"] {
            addresses.extend_from_slice(&ga(g)?.raw().to_be_bytes());
        }
        dev.preload(1, &addresses);
    }

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["refused"], true, "{applied}");
    assert!(
        applied["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("live tables changed"),
        "{applied}"
    );
    assert_eq!(h.writes()?, 0, "a refused apply must not write");

    h.stop().await
}

#[tokio::test]
async fn test_knx_plan_device_refuses_non_loopback_gateway_without_gate() -> anyhow::Result<()> {
    // The environment opt-in would legitimately open the gate; this case is
    // about its absence, so it has nothing to prove when a developer set it.
    if bussard_transport::write_gate::real_gateway_env_opt_in() {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    // TEST-NET-1: never contacted, because no bus actor is spawned.
    let connection = ConnectionConfig::tunnel(SocketAddrV4::new([192, 0, 2, 10].into(), 3671));
    let (client, server_task) =
        serve(dir.path(), connection, Duration::from_secs(600), false).await?;

    for (tool, args) in [
        ("knx_plan_device", json!({"address": "1.1.4"})),
        (
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": "00".repeat(32)}),
        ),
    ] {
        let res = call(&client, tool, args).await?;
        assert_eq!(res["refused"], true, "{tool}: {res}");
        let reason = res["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("refusing to write to non-loopback gateway 192.0.2.10:3671"),
            "{tool}: {reason}"
        );
    }

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn test_programming_tools_registered_only_with_the_tier() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let connection = ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), 9));
    let (client, server_task) =
        serve(dir.path(), connection, Duration::from_secs(600), false).await?;
    let names: Vec<String> = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for tool in bussard_mcp::tools_program::PROGRAMMING_TOOLS {
        assert!(
            names.iter().any(|n| n == tool),
            "{tool} missing from {names:?}"
        );
    }
    let mut expected = bussard_mcp::tool_names_for(false, false, true, true);
    expected.sort_unstable();
    let mut got: Vec<&str> = names.iter().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, expected);
    assert!(
        !bussard_mcp::tool_names(false, true, false)
            .iter()
            .any(|n| n.starts_with("knx_plan_device") || n.starts_with("knx_apply_device"))
    );
    client.cancel().await?;
    server_task.abort();
    Ok(())
}
