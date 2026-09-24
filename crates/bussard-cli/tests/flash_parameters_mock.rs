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
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::{MockGateway, Reaction};
use bussard_transport::tpci;

type TestResult = Result<(), Box<dyn Error>>;

const CHANNEL: u8 = 0x5B;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;
const PID_PROGRAM_VERSION: u8 = 13;
const PID_TABLE: u8 = 23;
const PID_MAX_APDU_LENGTH: u8 = 56;

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
    /// KNX Data Secure (issue #170): an activated device holds its tool key
    /// here, answers the plain descriptor read with mask FFFF (as 1.1.12 does),
    /// answers a plain authorize, and drops every other plain request.
    secure: Option<Arc<Mutex<bussard_secure::DataSecureSession>>>,
    /// The outer (wire) APCI of every numbered request, in order.
    wire_apcis: Vec<u16>,
    /// Requests that arrived inside a verified `A_SecureData`.
    secured_requests: usize,
    /// Plain requests an activated device dropped.
    plain_refused: usize,
    /// The inner (plain) APCI of every request the device served, in order.
    served_apcis: Vec<u16>,
    /// `PID_MAX_APDU_LENGTH` (device object), when the device exposes it.
    max_apdu: Option<u16>,
    /// Where the parameter segment sits (`PID_TABLE_REFERENCE` of the app
    /// object).
    param_base: u32,
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
            secure: None,
            wire_apcis: Vec::new(),
            secured_requests: 0,
            plain_refused: 0,
            served_apcis: Vec::new(),
            max_apdu: None,
            param_base: PARAM_BASE,
        }
    }

    /// A device running the large-segment app (see [`large_app_xml`]): a
    /// `size`-octet parameter segment at `base` holding `params` then zeros,
    /// advertising `PID_MAX_APDU_LENGTH = max_apdu`.
    fn running_large(params: [u8; 2], size: usize, base: u32, max_apdu: u16) -> MockDevice {
        let mut dev = MockDevice::running(params);
        dev.memory.remove(&PARAM_BASE);
        dev.memory.remove(&(PARAM_BASE + 1));
        for i in 0..size {
            let b = params.get(i).copied().unwrap_or(0);
            dev.memory.insert(base + i as u32, b);
        }
        dev.param_base = base;
        dev.max_apdu = Some(max_apdu);
        dev
    }

    /// The same device, KNX Data Secure-activated with [`TOOL_KEY`].
    fn activated(mut self) -> MockDevice {
        self.secure = Some(Arc::new(Mutex::new(
            bussard_secure::DataSecureSession::new(bussard_secure::Key16::new(TOOL_KEY)),
        )));
        self
    }
}

/// The synthetic tool key of the activated mock device (no real key material).
const TOOL_KEY: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
/// [`TOOL_KEY`] as `--tool-key` takes it.
const TOOL_KEY_HEX: &str = "0102030405060708090a0b0c0d0e0f10";
/// The Data Secure SCF octet of an S-A_Sync_Req.
const SCF_SYNC_REQ: u8 = 0x92;

/// The CCM addressing context of one frame (spec §5.4).
fn addressing(
    source: IndividualAddress,
    dest: IndividualAddress,
    tpci_octet: u8,
) -> bussard_secure::TpAddressing {
    bussard_secure::TpAddressing {
        source: source.raw(),
        destination: dest.raw(),
        address_type_group: false,
        extended_frame_format: 0,
        tpci: tpci_octet,
    }
}

/// Answers one numbered request through the device's security layer.
///
/// `None` drops the frame (no `T_ACK`, no answer), as an activated device does
/// with a plain request it refuses or a secured one that does not verify.
/// `Some(reply)` acknowledges it and sends `reply`, if any. A plain device
/// passes straight through to [`respond`].
fn secure_respond(
    dev: &mut MockDevice,
    tool: IndividualAddress,
    req_tpci: u8,
    resp_tpci: u8,
    wire_apci: u16,
    data: &[u8],
) -> Option<Option<(u16, Vec<u8>)>> {
    let Some(session) = dev.secure.clone() else {
        return Some(respond(dev, wire_apci, data));
    };
    let mut session = match session.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let req_addr = addressing(tool, dev.address, req_tpci);
    let resp_addr = addressing(dev.address, tool, resp_tpci);
    if wire_apci != bussard_secure::A_SECURE_DATA {
        if wire_apci == apci::A_DEVICE_DESCRIPTOR_READ && data.is_empty() {
            return Some(Some((apci::A_DEVICE_DESCRIPTOR_RESPONSE, vec![0xFF, 0xFF])));
        }
        if wire_apci == apci::A_AUTHORIZE_REQUEST {
            return Some(respond(dev, wire_apci, data));
        }
        dev.plain_refused += 1;
        return None;
    }
    if data.first() == Some(&SCF_SYNC_REQ) {
        return session
            .answer_sync_request(&req_addr, data, &resp_addr)
            .ok()
            .map(Some);
    }
    match session.unwrap(&req_addr, wire_apci, data) {
        Ok(bussard_secure::UnwrapOutcome::Secured { apci, data }) => {
            dev.secured_requests += 1;
            let reply = respond(dev, apci, &data);
            Some(reply.and_then(|(rapci, rdata)| session.wrap(&resp_addr, rapci, &rdata).ok()))
        }
        _ => None,
    }
}

type Shared = Arc<Mutex<MockDevice>>;

fn lock(shared: &Shared) -> MutexGuard<'_, MockDevice> {
    match shared.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
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
    dev.served_apcis.push(req_apci);
    if req_apci == apci::A_MEMORY_EXTENDED_READ {
        let req = apci::decode_memory_extended_request(data, false)?;
        let out: Vec<u8> = (0..u32::from(req.count))
            .map(|i| dev.memory.get(&(req.addr + i)).copied().unwrap_or(0xFF))
            .collect();
        return Some(apci::encode_memory_extended_read_response(
            0, req.addr, &out,
        ));
    }
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
            (APP_OBJECT, PID_TABLE_REFERENCE) => answer(&dev.param_base.to_be_bytes()),
            (0, PID_MAX_APDU_LENGTH) => match dev.max_apdu {
                Some(v) => answer(&v.to_be_bytes()),
                None => empty,
            },
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

/// Puts the device model on a testkit gateway line. The hook runs every
/// numbered request through the device's security layer: a dropped request
/// gets no `T_ACK`, an accepted one is `T_ACK`ed and answered if there is an
/// answer.
fn on_line(shared: &Shared) -> bussard_testkit::MockDevice {
    let address = lock(shared).address;
    let model = Arc::clone(shared);
    bussard_testkit::MockDevice::new(address).with_hook(move |line_dev, req_apci, data| {
        let tool = line_dev.tool;
        let req_tpci = tpci::ndt(line_dev.client_seq);
        let resp_tpci = tpci::ndt(line_dev.send_seq().unwrap_or(0));
        let mut dev = lock(&model);
        dev.wire_apcis.push(req_apci);
        Some(
            match secure_respond(&mut dev, tool, req_tpci, resp_tpci, req_apci, data) {
                None => Reaction::Silent,
                Some(None) => Reaction::Ack,
                Some(Some((rapci, rdata))) => Reaction::Answer(rapci, rdata),
            },
        )
    })
}

/// A running mock bus with a model directory and the synthetic product.
struct Bench {
    _gw: MockGateway,
    port: u16,
    shared: Shared,
    tmp: PathBuf,
    product: PathBuf,
    // Dropped last, after the gateway.
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    /// Starts the bench, or `None` when the `zip` CLI is unavailable.
    fn start(
        tag: &str,
        device: MockDevice,
        model_params: &str,
    ) -> Result<Option<Bench>, Box<dyn Error>> {
        Bench::start_with_app(tag, device, model_params, APP_XML)
    }

    /// [`Bench::start`] with another application XML.
    fn start_with_app(
        tag: &str,
        device: MockDevice,
        model_params: &str,
        app_xml: &str,
    ) -> Result<Option<Bench>, Box<dyn Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        let shared: Shared = Arc::new(Mutex::new(device));
        // Keep serving: a flash reconnects after the restart.
        let gw = rt.block_on(
            MockGateway::builder()
                .channel(CHANNEL)
                .keep_serving()
                .idle_timeout(Duration::from_secs(120))
                .device(on_line(&shared))
                .start(),
        )?;
        let port = gw.port();
        let tmp =
            std::env::temp_dir().join(format!("bussard-{tag}-{}-{}", std::process::id(), port));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let Some(product) = build_knxprod(&tmp, app_xml)? else {
            return Ok(None);
        };
        write_model(&tmp.join("knx"), model_params)?;
        Ok(Some(Bench {
            _gw: gw,
            port,
            shared,
            tmp,
            product,
            _rt: rt,
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
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// Zips the synthetic application into `<dir>/param-test.knxprod`.
fn build_knxprod(dir: &Path, app_xml: &str) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let src = dir.join("prod");
    std::fs::create_dir_all(src.join("M-00FA"))?;
    std::fs::write(src.join("M-00FA").join("M-00FA_A-0002.xml"), app_xml)?;
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
/// `[parameters]` table (TOML lines).
fn write_model(dir: &Path, params: &str) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        "version = 1\n\n[[device]]\naddress = \"1.1.4\"\napplication = \"M-00FA_A-0002\"\nmask = \"07B0\"\n",
    )?;
    let block = if params.is_empty() {
        String::new()
    } else {
        format!("\n[parameters]\n{params}")
    };
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        format!(
            "address = \"1.1.4\"\nname = \"Parameter test\"\n{block}\n[links]\n1.listen = [\"1/2/0\"]\n"
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
        "\"thr@P-0_R-1\" = \"12\"\n",
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

/// Issue #147: a piped run (stdout and stderr not a TTY) keeps today's plain,
/// line-oriented progress output byte for byte, with no cursor-control codes
/// beyond the `\r` the byte counter has always used.
#[test]
fn test_flash_parameters_only_piped_output_is_unchanged() -> TestResult {
    let Some(bench) = Bench::start(
        "params-piped",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
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
    // No escape sequence (cursor movement, colour, line erase) anywhere.
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
    assert!(!stderr.contains('\x1b'), "{stderr:?}");

    // stdout, with the temp-dir backup path normalised, is today's report.
    let backup_marker = "parameter backup written to ";
    let normalised: String = stdout
        .lines()
        .map(|line| match line.find(backup_marker) {
            Some(at) => format!("{}<backup>\n", &line[..at + backup_marker.len()]),
            None => format!("{line}\n"),
        })
        .collect();
    assert_eq!(
        normalised,
        "Parameter-only download for 1.1.4\n\
         \x20 application : M-00FA_A-0002 bussard parameter test app\n\
         \x20 parameters  : 1 change(s):\n\
         \x20     Threshold: 7 to 12\n\
         \x20 memory      :\n\
         \x20     M-00FA_A-0002_RS-2 at 0x004006: 1 of 2 octet(s) change\n\
         \x20 procedure   : open for loading (obj 4); write the differing parameter octets \
         (segment of 2 bytes) at 0x4006; complete load (obj 4); restart device (no unload, no \
         table write)\n\
         parameter backup written to <backup>\n\
         \n\
         parameters verified: 1 changed octet(s) read back from 1.1.4; the application is Loaded\n"
    );

    // stderr after the history line is the exact step / byte-counter trace.
    let (history, progress) = stderr.split_once('\n').ok_or("stderr has no lines")?;
    assert!(
        history.starts_with("recorded the current model"),
        "{stderr:?}"
    );
    assert_eq!(
        progress,
        "  [1/4] open for loading (obj 4)\n\
         \x20 [2/4] write the differing parameter octets (segment of 2 bytes) at 0x4006\n\
         \r      1/1 bytes\n\
         \x20 [3/4] complete load (obj 4)\n\
         \x20 [4/4] restart device\n"
    );
    Ok(())
}

#[test]
fn test_flash_parameters_only_with_nothing_to_change_touches_nothing() -> TestResult {
    let Some(bench) = Bench::start(
        "params-noop",
        MockDevice::running([12, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
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
    let Some(bench) = Bench::start("params-other-app", device, "\"thr@P-0_R-1\" = \"12\"\n")? else {
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
    let Some(bench) = Bench::start("params-unloaded", device, "\"thr@P-0_R-1\" = \"12\"\n")? else {
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
        "\"obj2@P-1_R-2\" = \"1\"\n",
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
        "\"thr@P-0_R-1\" = \"12\"\n",
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
    // The plain path carries no KNX Data Secure frame at all (issue #170).
    assert!(!dev.wire_apcis.contains(&bussard_secure::A_SECURE_DATA));
    Ok(())
}

#[test]
fn test_reconstruct_tool_key_reads_back_a_secure_device() -> TestResult {
    let Some(bench) = Bench::start(
        "params-secure",
        MockDevice::running([9, 0]).activated(),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "reconstruct",
        "1.1.4",
        "--product",
        bench.product()?,
        "--tool-key",
        TOOL_KEY_HEX,
        "--json",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    // The secured descriptor read returns the real mask, not FFFF.
    assert_eq!(json["mask"], "07B0", "{json}");
    assert_eq!(json["addresses"], serde_json::json!(["1/2/0"]), "{json}");
    assert_eq!(json["objects"]["1"], serde_json::json!(["1/2/0"]), "{json}");
    assert_eq!(json["parameters"]["application"], "M-00FA_A-0002", "{json}");
    let diffs = json["parameters"]["differences"]
        .as_array()
        .ok_or("no parameter differences in the reconstruct report")?;
    assert_eq!(diffs.len(), 1, "{json}");
    assert_eq!(diffs[0]["device"], "9");
    // Every numbered frame rode A_SecureData; nothing was refused or written.
    let dev = bench.device();
    assert!(dev.secured_requests > 0);
    assert_eq!(dev.plain_refused, 0);
    assert!(
        dev.wire_apcis
            .iter()
            .all(|&a| a == bussard_secure::A_SECURE_DATA),
        "a plain frame reached the secure device: {:03X?}",
        dev.wire_apcis
    );
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    assert!(dev.property_writes.is_empty());
    Ok(())
}

#[test]
fn test_plan_tool_key_reads_back_a_secure_device() -> TestResult {
    let Some(bench) = Bench::start(
        "plan-secure",
        MockDevice::running([9, 0]).activated(),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "plan",
        "1.1.4",
        "--product",
        bench.product()?,
        "--tool-key",
        TOOL_KEY_HEX,
        "--json",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["mask"], "07B0", "{json}");
    let diffs = json["parameters"]["differences"]
        .as_array()
        .ok_or("no parameter differences in the plan")?;
    assert_eq!(diffs.len(), 1, "{json}");
    assert_eq!(bench.device().plain_refused, 0);
    Ok(())
}

#[test]
fn test_reconstruct_without_key_on_a_secure_device_fails_with_hint() -> TestResult {
    let Some(bench) = Bench::start(
        "params-secure-nokey",
        MockDevice::running([9, 0]).activated(),
        "",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["reconstruct", "1.1.4", "--product", bench.product()?])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("mask FFFF") && stderr.contains("describe only"),
        "the unsupported-mask refusal: {stderr}"
    );
    assert!(
        stderr.contains("--keyring") && stderr.contains("--tool-key"),
        "the Data Secure hint: {stderr}"
    );
    let dev = bench.device();
    assert_eq!(dev.secured_requests, 0);
    assert!(!dev.wire_apcis.contains(&bussard_secure::A_SECURE_DATA));
    Ok(())
}

/// The synthetic application with a `size`-octet parameter segment (a multiple
/// of 3, so its zero `Data` is `AAAA` repeated). The two parameters stay at
/// offsets 0 and 1.
fn large_app_xml(size: usize) -> String {
    let data = "AAAA".repeat(size / 3);
    APP_XML
        .replace(
            r#"<RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data>"#,
            &format!(
                r#"<RelativeSegment Id="M-00FA_A-0002_RS-2" Size="{size}" LoadStateMachine="4" Offset="0"><Data>{data}</Data>"#
            ),
        )
        .replace(
            r#"<LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="par" />"#,
            &format!(r#"<LdCtrlRelSegment LsmIdx="4" Size="{size}" AppliesTo="par" />"#),
        )
        .replace(
            r#"<LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="par" />"#,
            &format!(r#"<LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="{size}" AppliesTo="par" />"#),
        )
}

/// The 1.1.5 shape of issue #194: a 19 155-octet parameter segment.
const LARGE_SEGMENT: usize = 19_155;
/// Above `0xFFFF`, where the 07B0 actuators keep their segments, so the read
/// goes out as `A_MemoryExtended_Read`.
const LARGE_BASE: u32 = 0x1_0000;

/// What a pre-flight run left: the device state, stdout and stderr.
type Preflight = (MockDevice, String, String);

/// Runs the flash pre-flight against the large-segment device without
/// `--yes` (so it stops at the confirmation) and returns the device and the
/// output.
fn large_preflight(tag: &str, extra: &[&str]) -> Result<Option<Preflight>, Box<dyn Error>> {
    let Some(bench) = Bench::start_with_app(
        tag,
        MockDevice::running_large([7, 0], LARGE_SEGMENT, LARGE_BASE, 233).activated(),
        "\"thr@P-0_R-1\" = \"12\"\n",
        &large_app_xml(LARGE_SEGMENT),
    )?
    else {
        return Ok(None);
    };
    let mut args = vec![
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--tool-key",
        TOOL_KEY_HEX,
    ];
    args.extend_from_slice(extra);
    let out = bench.bussard(&args)?;
    let (stdout, stderr) = text(&out);
    // No terminal to confirm on: the pre-flight runs, nothing is written.
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let dev = bench.device();
    assert!(dev.memory_writes.is_empty() && dev.load_events.is_empty());
    Ok(Some((dev, stdout, stderr)))
}

/// How many memory reads (plain `A_Memory_Read`, whose APCI carries the count,
/// or `A_MemoryExtended_Read`) the device served.
fn memory_reads(dev: &MockDevice) -> usize {
    dev.served_apcis
        .iter()
        .filter(|&&a| a & 0x3C0 == apci::A_MEMORY_READ || a == apci::A_MEMORY_EXTENDED_READ)
        .count()
}

/// How many numbered requests of `service` the device served.
fn served(dev: &MockDevice, service: u16) -> usize {
    dev.served_apcis.iter().filter(|&&a| a == service).count()
}

/// Issue #194: the System B pre-flight reads a 19 KB parameter segment of a
/// Data Secure device on the probe connection, in APDU-sized chunks
/// (`233 - 13` secure overhead `- 5` = 215 octets per
/// `A_MemoryExtended_Read`), not 12-octet chunks on a second connection.
#[test]
fn test_flash_preflight_reads_a_large_parameter_segment_in_apdu_sized_chunks() -> TestResult {
    let Some((dev, stdout, stderr)) = large_preflight("preflight-large", &[])? else {
        return Ok(());
    };
    let reads = memory_reads(&dev);
    eprintln!(
        "pre-flight: {} numbered request(s) on the wire, {reads} memory read(s)",
        dev.wire_apcis.len(),
    );
    assert!(stdout.contains("Threshold: 7 to 12"), "{stdout}\n{stderr}");
    assert_eq!(reads, LARGE_SEGMENT.div_ceil(215), "{stderr}");
    assert_eq!(served(&dev, apci::A_MEMORY_EXTENDED_READ), reads);
    // Everything rode one connection: the probe's Data Secure sync is the only one.
    assert_eq!(dev.plain_refused, 0);
    assert!(
        dev.wire_apcis.len() < 150,
        "{} requests",
        dev.wire_apcis.len()
    );
    Ok(())
}

/// Issue #194 item 2: with `--force` the current-parameter read is skipped;
/// the plan says so instead of showing a diff.
#[test]
fn test_flash_preflight_with_force_skips_the_parameter_read() -> TestResult {
    let Some((dev, stdout, stderr)) = large_preflight("preflight-force", &["--force"])? else {
        return Ok(());
    };
    assert_eq!(memory_reads(&dev), 0, "{stderr}");
    assert!(stdout.contains("current values not read back"), "{stdout}");
    Ok(())
}

/// Issue #194 item 6: `flash -v` ends with the wall-clock time per phase.
#[test]
fn test_flash_verbose_reports_phase_timings() -> TestResult {
    let Some(bench) = Bench::start(
        "flash-timing",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--yes",
        "-v",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(
        stderr.contains("timing: pre-flight "),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("restart + verification") || stderr.contains("did not reach"),
        "{stderr}"
    );
    if let Some(line) = stderr.lines().find(|l| l.starts_with("timing:")) {
        eprintln!("{line}");
    }
    Ok(())
}
