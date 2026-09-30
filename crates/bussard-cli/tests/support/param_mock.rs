// The System B parameter-test device, its synthetic application and the
// bench that runs `bussard` against it (issue #119). Shared by
// `flash_parameters_mock.rs` and `mcp_parameters_mock.rs` through `include!`,
// so both suites drive the same device model.

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

include!("param_app.rs");

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
        self.bussard_env(args, &[])
    }

    /// [`Bench::bussard`] with extra environment variables.
    fn bussard_env(&self, args: &[&str], env: &[(&str, &str)]) -> Result<Output, Box<dyn Error>> {
        let model = self.tmp.join("knx");
        let gateway = format!("127.0.0.1:{}", self.port);
        let mut full: Vec<&str> = args.to_vec();
        full.extend_from_slice(&[
            "--dir",
            model.to_str().ok_or("non-UTF-8 temp path")?,
            "--gateway",
            &gateway,
        ]);
        // `$BUSSARD_BIN` measures another build (before/after counts).
        let bin = std::env::var("BUSSARD_BIN")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_bussard").to_string());
        Ok(Command::new(bin)
            .args(&full)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env("BUSSARD_FLASH_L4_TIMEOUT_MS", "300")
            .envs(env.iter().copied())
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
        "version = 2\n\n[[device]]\naddress = \"1.1.4\"\napplication = \"M-00FA_A-0002\"\nmask = \"07B0\"\n",
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
