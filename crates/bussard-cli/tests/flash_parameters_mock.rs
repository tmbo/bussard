//! End-to-end tests of `bussard flash --parameters-only` and the parameter
//! read-back of `bussard plan` / `bussard reconstruct` (issue #119), against an
//! in-process mock KNX gateway on loopback.
//!
//! The mock device is a System B device (mask 07B0) that already runs a small
//! synthetic application: a six-octet code segment and a two-octet parameter
//! segment (an 8-bit threshold, and a 1-bit switch that shows com-object 2).
//! It implements, from the KNX spec semantics, the interface-object walk, the
//! load-state machines, `PID_TABLE_REFERENCE` / `PID_PROGRAM_VERSION`, the two
//! link tables (`PID_TABLE`), and `A_Memory_Read` / `A_Memory_Write`. Every
//! load event and memory write is recorded, which is how the tests prove a
//! parameter-only download unloads nothing, allocates nothing, touches no table
//! and writes only the changed octet.
//!
//! The synthetic `.knxprod` is zipped with the `zip` CLI at test time; the
//! tests skip green when `zip` is unavailable, like `flash_dry_run.rs`. The
//! `bussard` binary always runs with an explicit loopback `--gateway`.

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, Tpci};
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::tpci::{self, TpciKind};
use tokio::net::UdpSocket;

type TestResult = Result<(), Box<dyn Error>>;

const CHANNEL: u8 = 0x5B;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;
const PID_PROGRAM_VERSION: u8 = 13;
const PID_TABLE: u8 = 23;

const LS_UNLOADED: u8 = 0;
const LS_LOADED: u8 = 1;
const LS_LOADING: u8 = 2;
const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_ADDITIONAL: u8 = 3;
const LE_UNLOAD: u8 = 4;

const APP_OBJECT: u8 = 3;
/// Where the code segment sits.
const CODE_BASE: u32 = 0x4000;
/// Where the parameter segment sits: the app object's last allocation.
const PARAM_BASE: u32 = 0x4006;

/// The synthetic application (bussard's own work, MIT; no vendor data).
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard parameter test app" LoadProcedureStyle="ProductDefault">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
              <RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
              <ParameterType Id="M-00FA_A-0002_PT-1" Name="onoff"><TypeRestriction Base="Value" SizeInBit="1">
                <Enumeration Text="Off" Value="0" /><Enumeration Text="On" Value="1" />
              </TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0002_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="obj2" Text="Object 2" ParameterType="M-00FA_A-0002_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
              <ComObject Id="M-00FA_A-0002_O-2" Number="2" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
              <ComObjectRef Id="M-00FA_A-0002_O-2_R-2" RefId="M-00FA_A-0002_O-2" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="par" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0002_O-1_R-1" />
                <choose ParamRefId="M-00FA_A-0002_P-1_R-2">
                  <when test="1"><ComObjectRefRef RefId="M-00FA_A-0002_O-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

/// The mock device.
#[derive(Clone)]
struct MockDevice {
    address: IndividualAddress,
    /// Load state per object index (1, 2 tables; 3 application).
    load_states: HashMap<u8, u8>,
    /// The two link tables' elements (object 1: GAs, object 2: associations).
    tables: HashMap<u8, Vec<u8>>,
    program_version: [u8; 5],
    memory: HashMap<u32, u8>,
    /// Every load-control write as `(object, event)`.
    load_events: Vec<(u8, u8)>,
    /// Every `A_Memory_Write` as `(address, length)`.
    memory_writes: Vec<(u32, usize)>,
    /// Every non-load-control property write as `(object, pid)`.
    property_writes: Vec<(u8, u8)>,
    restarts: usize,
}

impl MockDevice {
    /// A device running the synthetic app with the given parameter octets.
    fn running(params: [u8; 2]) -> MockDevice {
        let mut memory = HashMap::new();
        for (i, b) in [0u8, 1, 2, 3, 4, 5].iter().enumerate() {
            memory.insert(CODE_BASE + i as u32, *b);
        }
        memory.insert(PARAM_BASE, params[0]);
        memory.insert(PARAM_BASE + 1, params[1]);
        let ga = |s: &str| {
            s.parse::<GroupAddress>()
                .map(|g| g.raw().to_be_bytes())
                .unwrap_or([0, 0])
        };
        let mut addrs = Vec::new();
        addrs.extend_from_slice(&ga("1/2/0"));
        let mut assocs = Vec::new();
        assocs.extend_from_slice(&1u16.to_be_bytes());
        assocs.extend_from_slice(&1u16.to_be_bytes());
        MockDevice {
            address: IndividualAddress::from_raw(0x1104),
            load_states: HashMap::from([(1, LS_LOADED), (2, LS_LOADED), (3, LS_LOADED)]),
            tables: HashMap::from([(1, addrs), (2, assocs)]),
            // M-00FA, application 2, version 1: the synthetic app's id.
            program_version: [0x00, 0xFA, 0x00, 0x02, 0x01],
            memory,
            load_events: Vec::new(),
            memory_writes: Vec::new(),
            property_writes: Vec::new(),
            restarts: 0,
        }
    }
}

type Shared = Arc<Mutex<MockDevice>>;

fn lock(shared: &Shared) -> MutexGuard<'_, MockDevice> {
    match shared.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&[0x06, 0x10]);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn connect_response_body(port: u16) -> Vec<u8> {
    let mut body = vec![CHANNEL, 0x00, 0x08, 0x01, 127, 0, 0, 1];
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

fn prop_response(oi: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        oi,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

fn decode_prop_header(payload: &[u8]) -> Option<(u8, u8, u8, u16)> {
    if payload.len() < 4 {
        return None;
    }
    let count = (payload[2] >> 4) & 0x0f;
    let start = (((payload[2] & 0x0f) as u16) << 8) | payload[3] as u16;
    Some((payload[0], payload[1], count, start))
}

/// Answers one connected management request.
fn respond(dev: &mut MockDevice, req_apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if req_apci == apci::A_AUTHORIZE_REQUEST {
        return Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00]));
    }
    if req_apci == apci::A_DEVICE_DESCRIPTOR_READ && data.is_empty() {
        return Some((apci::A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]));
    }
    if req_apci & 0x3C0 == 0x380 {
        // A_Restart: the device reboots; the load survives.
        dev.restarts += 1;
        return None;
    }
    let selector = req_apci & 0x3C0;
    if selector == apci::A_MEMORY_READ && data.len() >= 2 {
        let count = usize::from(req_apci & 0x3f);
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let out: Vec<u8> = (0..count)
            .map(|i| {
                dev.memory
                    .get(&(u32::from(addr) + i as u32))
                    .copied()
                    .unwrap_or(0xFF)
            })
            .collect();
        return Some(apci::encode_memory_response(addr, &out));
    }
    if selector == apci::A_MEMORY_WRITE && data.len() >= 2 {
        let addr = u16::from_be_bytes([data[0], data[1]]);
        dev.memory_writes.push((u32::from(addr), data.len() - 2));
        for (i, b) in data[2..].iter().enumerate() {
            dev.memory.insert(u32::from(addr) + i as u32, *b);
        }
        return Some(apci::encode_memory_response(addr, &data[2..]));
    }
    if req_apci == apci::A_PROPERTY_VALUE_READ {
        let (oi, pid, count, start) = decode_prop_header(data)?;
        let empty = prop_response(oi, pid, 0, start, &[]);
        let answer = |d: &[u8]| prop_response(oi, pid, 1, start, d);
        let resp = match (oi, pid) {
            (_, PID_OBJECT_TYPE) => match [0u16, 1, 2, 3].get(usize::from(oi)) {
                Some(ot) => answer(&ot.to_be_bytes()),
                None => empty,
            },
            (1..=3, PID_LOAD_STATE_CONTROL) => {
                answer(&[dev.load_states.get(&oi).copied().unwrap_or(LS_UNLOADED)])
            }
            (APP_OBJECT, PID_TABLE_REFERENCE) => answer(&PARAM_BASE.to_be_bytes()),
            (APP_OBJECT, PID_PROGRAM_VERSION) => answer(&dev.program_version),
            (1 | 2, PID_TABLE) => {
                let size = if oi == 2 { 4 } else { 2 };
                let elements = dev.tables.get(&oi).cloned().unwrap_or_default();
                let n = elements.len() / size;
                if start == 0 {
                    answer(&(n as u16).to_be_bytes())
                } else if usize::from(start) > n {
                    empty
                } else {
                    let idx = usize::from(start);
                    let want = usize::from(count).clamp(1, n - idx + 1);
                    let bytes = elements[(idx - 1) * size..(idx - 1 + want) * size].to_vec();
                    prop_response(oi, pid, want as u8, start, &bytes)
                }
            }
            _ => empty,
        };
        return Some((apci::A_PROPERTY_VALUE_RESPONSE, resp));
    }
    if req_apci == apci::A_PROPERTY_VALUE_WRITE {
        let (oi, pid, count, start) = decode_prop_header(data)?;
        let value = data[4..].to_vec();
        if pid == PID_LOAD_STATE_CONTROL {
            let event = value.first().copied().unwrap_or(0);
            dev.load_events.push((oi, event));
            let state = dev.load_states.entry(oi).or_insert(LS_UNLOADED);
            *state = match event {
                LE_START_LOADING => LS_LOADING,
                LE_LOAD_COMPLETED => LS_LOADED,
                LE_UNLOAD => LS_UNLOADED,
                _ => *state,
            };
            let st = *state;
            return Some((
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &[st]),
            ));
        }
        dev.property_writes.push((oi, pid));
        return Some((
            apci::A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, count, start, &value),
        ));
    }
    None
}

async fn push(gw: &UdpSocket, peer: SocketAddr, gw_seq: &mut u8, cemi: &CemiFrame) {
    let hdr = ConnectionHeader {
        channel_id: CHANNEL,
        seq: *gw_seq,
    };
    let _ = gw
        .send_to(&knxnet::tunneling_request(hdr, cemi), peer)
        .await;
    *gw_seq = gw_seq.wrapping_add(1);
}

async fn handle_frame(
    gw: &UdpSocket,
    peer: SocketAddr,
    shared: &Shared,
    cemi: &CemiFrame,
    gw_seq: &mut u8,
    dev_seq: &mut u8,
) {
    let tool = cemi.source;
    let Destination::Individual(dest) = &cemi.destination else {
        return;
    };
    let dest = *dest;
    if lock(shared).address != dest {
        return;
    }
    match tpci::classify(cemi.tpci_octet()) {
        TpciKind::Connect => *dev_seq = 0,
        TpciKind::NumberedData(client_seq) => {
            let ack = CemiFrame::t_control(tool, dest, tpci::t_ack(client_seq));
            push(gw, peer, gw_seq, &ack).await;
            let (req_apci, data) = match (&cemi.tpci, &cemi.apdu) {
                (Tpci::Other(_), Apdu::Other { apci, data }) => (*apci, data.clone()),
                _ => return,
            };
            let reply = respond(&mut lock(shared), req_apci, &data);
            if let Some((rapci, rdata)) = reply {
                let resp =
                    CemiFrame::t_data_connected(tool, dest, tpci::ndt(*dev_seq), rapci, &rdata);
                push(gw, peer, gw_seq, &resp).await;
                *dev_seq = (*dev_seq + 1) & 0x0f;
            }
        }
        _ => {}
    }
}

async fn run_gateway(gw: UdpSocket, shared: Shared) {
    let port = gw.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut gw_seq = 0u8;
    let mut dev_seq = 0u8;
    loop {
        let mut buf = [0u8; 1024];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(120), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let Ok(parsed) = knxnet::parse(&buf[..n]) else {
            continue;
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                gw_seq = 0;
                dev_seq = 0;
                let resp = knxnet_frame(ServiceType::ConnectResponse, &connect_response_body(port));
                let _ = gw.send_to(&resp, from).await;
            }
            ServiceType::ConnectionstateRequest => {
                let _ = gw
                    .send_to(&knxnet::connectionstate_response(CHANNEL, 0), from)
                    .await;
            }
            ServiceType::DisconnectRequest => {
                let _ = gw
                    .send_to(&knxnet::disconnect_response(CHANNEL, 0), from)
                    .await;
            }
            ServiceType::TunnelingRequest => {
                let Ok(tr) = knxnet::parse_tunneling_request(parsed.body) else {
                    continue;
                };
                let _ = gw
                    .send_to(
                        &knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0),
                        from,
                    )
                    .await;
                handle_frame(&gw, from, &shared, &tr.cemi, &mut gw_seq, &mut dev_seq).await;
            }
            _ => {}
        }
    }
}

/// A running mock bus with a model directory and the synthetic product.
struct Bench {
    rt: tokio::runtime::Runtime,
    port: u16,
    shared: Shared,
    task: tokio::task::JoinHandle<()>,
    tmp: PathBuf,
    product: PathBuf,
}

impl Bench {
    /// Starts the bench, or `None` when the `zip` CLI is unavailable.
    fn start(
        tag: &str,
        device: MockDevice,
        model_params: &str,
    ) -> Result<Option<Bench>, Box<dyn Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        let sock = rt.block_on(UdpSocket::bind("127.0.0.1:0"))?;
        let port = sock.local_addr()?.port();
        let shared: Shared = Arc::new(Mutex::new(device));
        let task = rt.spawn(run_gateway(sock, Arc::clone(&shared)));
        let tmp =
            std::env::temp_dir().join(format!("bussard-{tag}-{}-{}", std::process::id(), port));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let Some(product) = build_knxprod(&tmp)? else {
            task.abort();
            return Ok(None);
        };
        write_model(&tmp.join("knx"), model_params)?;
        Ok(Some(Bench {
            rt,
            port,
            shared,
            task,
            tmp,
            product,
        }))
    }

    /// Runs `bussard <args> --dir <model> --gateway 127.0.0.1:<port>`.
    fn bussard(&self, args: &[&str]) -> Result<Output, Box<dyn Error>> {
        let model = self.tmp.join("knx");
        let gateway = format!("127.0.0.1:{}", self.port);
        let mut full: Vec<&str> = args.to_vec();
        full.extend_from_slice(&[
            "--dir",
            model.to_str().ok_or("non-UTF-8 temp path")?,
            "--gateway",
            &gateway,
        ]);
        Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(&full)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env("BUSSARD_FLASH_L4_TIMEOUT_MS", "300")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }

    fn product(&self) -> Result<&str, Box<dyn Error>> {
        Ok(self.product.to_str().ok_or("non-UTF-8 temp path")?)
    }

    fn device(&self) -> MockDevice {
        lock(&self.shared).clone()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        self.task.abort();
        self.rt.block_on(async { tokio::task::yield_now().await });
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// Zips the synthetic application into `<dir>/param-test.knxprod`.
fn build_knxprod(dir: &Path) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let src = dir.join("prod");
    std::fs::create_dir_all(src.join("M-00FA"))?;
    std::fs::write(src.join("M-00FA").join("M-00FA_A-0002.xml"), APP_XML)?;
    let archive = dir.join("param-test.knxprod");
    let Ok(status) = Command::new("zip")
        .current_dir(&src)
        .args(["-r", "-X", "-q"])
        .arg(&archive)
        .arg("M-00FA")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    else {
        eprintln!("skipping: the `zip` CLI is unavailable to build the synthetic .knxprod");
        return Ok(None);
    };
    Ok(status.success().then_some(archive))
}

/// The model: 1.1.4 runs the synthetic app with one link and `params` as its
/// `parameters:` block (YAML lines, indented by two).
fn write_model(dir: &Path, params: &str) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n",
    )?;
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.4:\n  - object: 1\n    listen:\n    - 1/2/0\n",
    )?;
    let block = if params.is_empty() {
        String::new()
    } else {
        format!("parameters:\n{params}")
    };
    std::fs::write(
        dir.join("devices").join("1.1.4-test.yaml"),
        format!(
            "address: 1.1.4\nname: Parameter test\nproduct:\n  application_ref: M-00FA_A-0002\n  mask: 07B0\n{block}"
        ),
    )?;
    Ok(())
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn test_flash_parameters_only_writes_only_the_changed_octet() -> TestResult {
    let Some(bench) = Bench::start(
        "params-only",
        MockDevice::running([7, 0]),
        "  thr@P-0_R-1: \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Threshold: 7 to 12"), "{stdout}");
    assert!(stdout.contains("1 of 2 octet(s) change"), "{stdout}");
    assert!(stdout.contains("parameters verified"), "{stdout}");

    let dev = bench.device();
    // One memory write: the threshold octet. Code and tables untouched.
    assert_eq!(dev.memory_writes, vec![(PARAM_BASE, 1)], "{stderr}");
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    assert_eq!(dev.memory.get(&(PARAM_BASE + 1)).copied(), Some(0));
    // StartLoading + LoadCompleted on the app object only: no Unload, no
    // segment allocation, no table object.
    assert_eq!(
        dev.load_events,
        vec![
            (APP_OBJECT, LE_START_LOADING),
            (APP_OBJECT, LE_LOAD_COMPLETED)
        ],
        "{stderr}"
    );
    assert!(!dev.load_events.iter().any(|(_, e)| *e == LE_ADDITIONAL));
    assert!(dev.property_writes.is_empty(), "{:?}", dev.property_writes);
    assert_eq!(dev.restarts, 1, "the device restarts");
    assert_eq!(dev.load_states.get(&APP_OBJECT).copied(), Some(LS_LOADED));

    // A backup of the parameter memory was written before the download.
    let dir = bench.tmp.join("knx/captures/backups/parameters");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let backup: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&files[0])?)?;
    assert_eq!(backup["regions"][0]["bytes"], "0700");
    assert_eq!(backup["regions"][0]["base"], PARAM_BASE);
    Ok(())
}

#[test]
fn test_flash_parameters_only_with_nothing_to_change_touches_nothing() -> TestResult {
    let Some(bench) = Bench::start(
        "params-noop",
        MockDevice::running([12, 0]),
        "  thr@P-0_R-1: \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("nothing to do"), "{stdout}");
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    Ok(())
}

#[test]
fn test_flash_parameters_only_refuses_another_application() -> TestResult {
    let mut device = MockDevice::running([7, 0]);
    device.program_version = [0x00, 0x83, 0x00, 0x42, 0x10];
    let Some(bench) = Bench::start("params-other-app", device, "  thr@P-0_R-1: \"12\"\n")? else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("runs application M-0083 A-0042 v16"),
        "{stderr}"
    );
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    Ok(())
}

#[test]
fn test_flash_parameters_only_refuses_an_unloaded_device() -> TestResult {
    let mut device = MockDevice::running([7, 0]);
    device.load_states.insert(APP_OBJECT, LS_UNLOADED);
    let Some(bench) = Bench::start("params-unloaded", device, "  thr@P-0_R-1: \"12\"\n")? else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("not Loaded"), "{stderr}");
    assert!(bench.device().load_events.is_empty());
    Ok(())
}

#[test]
fn test_flash_parameters_only_refuses_a_group_object_change() -> TestResult {
    let Some(bench) = Bench::start(
        "params-visibility",
        MockDevice::running([7, 0]),
        "  obj2@P-1_R-2: \"1\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("group-object table (shows object(s) 2)"),
        "{stderr}"
    );
    assert!(stderr.contains("full `bussard flash 1.1.4`"), "{stderr}");
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    Ok(())
}

#[test]
fn test_plan_and_reconstruct_read_back_the_parameters() -> TestResult {
    let Some(bench) = Bench::start(
        "params-readback",
        MockDevice::running([9, 0]),
        "  thr@P-0_R-1: \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["reconstruct", "1.1.4", "--product", bench.product()?])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("parameters (application M-00FA_A-0002)"),
        "{stdout}"
    );
    assert!(stdout.contains("Threshold: 9 (default 7)"), "{stdout}");
    assert!(stdout.contains("Threshold: device 9, model 12"), "{stdout}");

    let out = bench.bussard(&["plan", "1.1.4", "--product", bench.product()?, "--json"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    let diffs = json["parameters"]["differences"]
        .as_array()
        .ok_or("no parameter differences in the plan")?;
    assert_eq!(diffs.len(), 1, "{json}");
    assert_eq!(diffs[0]["device"], "9");
    assert_eq!(diffs[0]["model"], "12");
    // Both commands are read-only.
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    assert!(dev.property_writes.is_empty());
    Ok(())
}
