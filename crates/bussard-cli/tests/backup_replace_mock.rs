//! End-to-end tests of `bussard backup`, `bussard restore` and `bussard replace`
//! (issues #96 and #98) against an in-process mock KNX gateway.
//!
//! The mock gateway hosts a small population of System B devices. Each one
//! implements, from the KNX spec semantics:
//!
//! - interface-object discovery (`PID_OBJECT_TYPE`), the device-object identity
//!   properties (manufacturer, serial, order number);
//! - the loadable address and association tables (`PID_TABLE`) with their
//!   load-state machines (`PID_LOAD_STATE_CONTROL`), writable as `apply` writes
//!   them;
//! - an application-program object whose relative segment is readable through
//!   `PID_TABLE_REFERENCE` (base), `PID_MCB_TABLE` (size) and `A_Memory_Read`;
//! - programming mode: the `A_IndividualAddress_Read` / `_Write` broadcasts and
//!   `PID_PROGMODE`.
//!
//! Every write APDU a device receives is counted, which is how the backup test
//! proves `backup` never writes. The gateway survives the tool disconnecting and
//! reconnecting, because `replace` runs three bus sessions (swap, flash, apply)
//! in one process.
//!
//! The `bussard` binary always runs with an explicit loopback `--gateway`.

use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::{MockGateway, Reaction};

type TestResult = Result<(), Box<dyn Error>>;

const CHANNEL: u8 = 0x5A;

const PID_OBJECT_TYPE: u8 = 1;
const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;
const PID_PROGRAM_VERSION: u8 = 13;
const PID_TABLE: u8 = 23;
const PID_MCB_TABLE: u8 = 27;

const OT_DEVICE: u16 = 0;
const OT_ADDRESS_TABLE: u16 = 1;
const OT_ASSOCIATION_TABLE: u16 = 2;
const OT_APPLICATION_PROGRAM: u16 = 3;
const OT_GROUP_OBJECT_TABLE: u16 = 9;

const LS_UNLOADED: u8 = 0;
const LS_LOADED: u8 = 1;
const LS_LOADING: u8 = 2;
const LE_START_LOADING: u8 = 1;
const LE_LOAD_COMPLETED: u8 = 2;
const LE_UNLOAD: u8 = 4;
/// `AdditionalLoadControls`, whose sub-code 0x0B is `LdCtrlRelSegment`.
const LE_ADDITIONAL: u8 = 3;
const SUB_REL_SEGMENT: u8 = 0x0B;

/// The object index of the application-program object in every mock device.
const APP_OBJECT: u8 = 3;
/// Where the mock places the application segment.
const PARAM_BASE: u32 = 0x4800;

/// One loadable table object's state.
#[derive(Clone, Default)]
struct TableObject {
    load_state: u8,
    elements: Vec<u8>,
    elem_size: usize,
}

/// One mock device on the bus: the application model behind a testkit device
/// (see [`on_line`]).
#[derive(Clone)]
struct MockDevice {
    address: IndividualAddress,
    /// Answers the programming-mode broadcast and takes an address write.
    programming: bool,
    mask: u16,
    order: Vec<u8>,
    serial: [u8; 6],
    tables: HashMap<u8, TableObject>,
    program_version: [u8; 5],
    parameters: Vec<u8>,
    /// Per-table-object allocated segment base (`LdCtrlRelSegment`).
    segments: HashMap<u8, u32>,
    /// Device memory written with `A_Memory_Write`.
    memory: HashMap<u32, u8>,
    /// Every A_PropertyValue_Write / A_Memory_Write / A_MemoryExtended_Write.
    writes: usize,
    progmode_cleared: bool,
}

impl MockDevice {
    /// A System B device with the given tables and a 40-octet parameter image.
    fn system_b(addr: &str, order: &str, gas: &[&str], assocs: &[(u16, u16)]) -> MockDevice {
        let mut addr_elems = Vec::new();
        for g in gas {
            let raw = g.parse::<GroupAddress>().map(|g| g.raw()).unwrap_or(0);
            addr_elems.extend_from_slice(&raw.to_be_bytes());
        }
        let mut assoc_elems = Vec::new();
        for &(tsap, asap) in assocs {
            assoc_elems.extend_from_slice(&tsap.to_be_bytes());
            assoc_elems.extend_from_slice(&asap.to_be_bytes());
        }
        let mut tables = HashMap::new();
        tables.insert(
            1u8,
            TableObject {
                load_state: LS_LOADED,
                elements: addr_elems,
                elem_size: 2,
            },
        );
        tables.insert(
            2u8,
            TableObject {
                load_state: LS_LOADED,
                elements: assoc_elems,
                elem_size: 4,
            },
        );
        MockDevice {
            address: addr
                .parse()
                .unwrap_or_else(|_| IndividualAddress::from_raw(0xFFFF)),
            programming: false,
            mask: 0x07B0,
            order: order.as_bytes().to_vec(),
            serial: [0x00, 0x83, 0x10, 0x20, 0x30, 0x40],
            tables,
            program_version: [0x00, 0x83, 0x00, 0x42, 0x10],
            parameters: (0u8..40).collect(),
            segments: HashMap::new(),
            memory: HashMap::new(),
            writes: 0,
            progmode_cleared: false,
        }
    }

    fn object_types(&self) -> Vec<u16> {
        vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_APPLICATION_PROGRAM,
            OT_GROUP_OBJECT_TABLE,
        ]
    }

    /// The address and association table element octets.
    fn table_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        let get = |oi: u8| {
            self.tables
                .get(&oi)
                .map(|t| t.elements.clone())
                .unwrap_or_default()
        };
        (get(1), get(2))
    }
}

/// A device model shared between its testkit hook and the test.
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

/// Answers one connected management request, mutating the device on a write.
fn respond(dev: &mut MockDevice, req_apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if req_apci == apci::A_AUTHORIZE_REQUEST {
        return Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00]));
    }
    if req_apci == apci::A_DEVICE_DESCRIPTOR_READ && data.is_empty() {
        return Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        ));
    }
    let selector = req_apci & 0x3C0;
    if selector == apci::A_MEMORY_READ && data.len() >= 2 {
        let count = usize::from(req_apci & 0x3f);
        let addr = u16::from_be_bytes([data[0], data[1]]);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let at = u32::from(addr) + i as u32;
            let byte = dev.memory.get(&at).copied().unwrap_or_else(|| {
                at.checked_sub(PARAM_BASE)
                    .and_then(|off| dev.parameters.get(off as usize).copied())
                    .unwrap_or(0xFF)
            });
            out.push(byte);
        }
        return Some(apci::encode_memory_response(addr, &out));
    }
    if selector == apci::A_MEMORY_WRITE
        || req_apci == apci::A_MEMORY_EXTENDED_WRITE
        || req_apci == apci::A_PROPERTY_VALUE_WRITE
    {
        dev.writes += 1;
    }
    // A_Memory_Write lands in device memory and is echoed, as a verify-mode
    // device does (the table images `apply` streams into its segments).
    if selector == apci::A_MEMORY_WRITE && data.len() >= 2 {
        let addr = u16::from_be_bytes([data[0], data[1]]);
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
            (_, PID_OBJECT_TYPE) => match dev.object_types().get(usize::from(oi)) {
                Some(ot) => answer(&ot.to_be_bytes()),
                None => empty,
            },
            (0, apci::PID_MANUFACTURER_ID) => answer(&0x0083u16.to_be_bytes()),
            (0, apci::PID_SERIAL_NUMBER) => answer(&dev.serial),
            (0, apci::PID_ORDER_INFO) => answer(&dev.order),
            (APP_OBJECT, PID_LOAD_STATE_CONTROL) => answer(&[LS_LOADED]),
            (APP_OBJECT, PID_TABLE_REFERENCE) => answer(&PARAM_BASE.to_be_bytes()),
            (APP_OBJECT, PID_PROGRAM_VERSION) => answer(&dev.program_version),
            (APP_OBJECT, PID_MCB_TABLE) => {
                let mut mcb = (dev.parameters.len() as u32).to_be_bytes().to_vec();
                mcb.extend_from_slice(&[0x00, 0xFF, 0x00, 0x00]);
                answer(&mcb)
            }
            (4, PID_TABLE) if start == 0 => answer(&4u16.to_be_bytes()),
            (1 | 2, PID_TABLE_REFERENCE) => {
                answer(&dev.segments.get(&oi).copied().unwrap_or(0).to_be_bytes())
            }
            (_, PID_LOAD_STATE_CONTROL) => {
                let st = dev
                    .tables
                    .get(&oi)
                    .map(|t| t.load_state)
                    .unwrap_or(LS_UNLOADED);
                answer(&[st])
            }
            (1 | 2, PID_TABLE) => {
                let t = dev.tables.get(&oi).cloned().unwrap_or_default();
                let size = t.elem_size.max(1);
                let n = t.elements.len() / size;
                if start == 0 {
                    answer(&(n as u16).to_be_bytes())
                } else if usize::from(start) > n {
                    empty
                } else {
                    let idx = usize::from(start);
                    let want = usize::from(count).clamp(1, n - idx + 1);
                    let bytes = t.elements[(idx - 1) * size..(idx - 1 + want) * size].to_vec();
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
        match (oi, pid) {
            (0, apci::PID_PROGMODE) => {
                if value.first() == Some(&0x00) {
                    dev.programming = false;
                    dev.progmode_cleared = true;
                }
            }
            (1 | 2, PID_LOAD_STATE_CONTROL) => {
                let event = value.first().copied().unwrap_or(0);
                if event == LE_ADDITIONAL && value.get(1) == Some(&SUB_REL_SEGMENT) {
                    // The device places the segment itself; deterministic here.
                    let base = if oi == 1 { 0x1000 } else { 0x1800 };
                    dev.segments.insert(oi, base);
                } else if event == LE_LOAD_COMPLETED {
                    // Activate what was streamed into the segment: count word,
                    // then the elements.
                    if let Some(&base) = dev.segments.get(&oi) {
                        let size = if oi == 2 { 4 } else { 2 };
                        let byte = |i: u32| dev.memory.get(&(base + i)).copied().unwrap_or(0);
                        let n = u32::from(u16::from_be_bytes([byte(0), byte(1)]));
                        let elements: Vec<u8> = (0..n * size).map(|i| byte(2 + i)).collect();
                        let t = dev.tables.entry(oi).or_default();
                        t.elements = elements;
                        t.elem_size = size as usize;
                    }
                }
                let t = dev.tables.entry(oi).or_default();
                t.load_state = match event {
                    LE_START_LOADING => LS_LOADING,
                    LE_LOAD_COMPLETED => LS_LOADED,
                    LE_UNLOAD => LS_UNLOADED,
                    _ => t.load_state,
                };
                let st = t.load_state;
                return Some((
                    apci::A_PROPERTY_VALUE_RESPONSE,
                    prop_response(oi, pid, 1, start, &[st]),
                ));
            }
            (1 | 2, PID_TABLE) => {
                let size = if oi == 2 { 4 } else { 2 };
                let t = dev.tables.entry(oi).or_default();
                t.elem_size = size;
                if start == 0 {
                    let n = if value.len() >= 2 {
                        usize::from(u16::from_be_bytes([value[0], value[1]]))
                    } else {
                        0
                    };
                    t.elements = vec![0u8; n * size];
                } else {
                    let from = (usize::from(start) - 1) * size;
                    let to = from + value.len();
                    if to > t.elements.len() {
                        t.elements.resize(to, 0);
                    }
                    t.elements[from..to].copy_from_slice(&value);
                }
            }
            _ => {}
        }
        return Some((
            apci::A_PROPERTY_VALUE_RESPONSE,
            prop_response(oi, pid, count, start, &value),
        ));
    }
    None
}

/// Puts a device model on a testkit gateway line. The testkit device holds the
/// address and programming mode (it answers the programming-mode broadcast and
/// takes an address write without leaving programming mode, as this bench's
/// devices always did); the hook `T_ACK`s every numbered request and answers
/// it from the model.
fn on_line(model: MockDevice) -> (bussard_testkit::MockDevice, Shared) {
    let mut dev = bussard_testkit::MockDevice::new(model.address).with_mask(model.mask);
    dev.programming = model.programming;
    dev.stuck_programming = true;
    let shared: Shared = Arc::new(Mutex::new(model));
    let hook_model = Arc::clone(&shared);
    let dev = dev.with_hook(move |dev, req_apci, data| {
        let mut model = lock(&hook_model);
        model.address = dev.address;
        model.programming = dev.programming;
        let reply = respond(&mut model, req_apci, data);
        dev.programming = model.programming;
        Some(match reply {
            Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
            None => Reaction::Ack,
        })
    });
    (dev, shared)
}

/// A running mock bus: the gateway, the device models in line order, and the
/// runtime the gateway runs on.
struct Bench {
    gw: MockGateway,
    port: u16,
    models: Mutex<Vec<Shared>>,
    tmp: PathBuf,
    // Dropped last, after the gateway.
    _rt: tokio::runtime::Runtime,
}

impl Bench {
    fn start(tag: &str, devices: Vec<MockDevice>) -> Result<Bench, Box<dyn Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        let (line, models): (Vec<_>, Vec<_>) = devices.into_iter().map(on_line).unzip();
        // Keep serving after a tunnel disconnect, so several bussard sessions
        // can run against it (`replace` runs three).
        let gw = rt.block_on(
            MockGateway::builder()
                .channel(CHANNEL)
                .keep_serving()
                .idle_timeout(Duration::from_secs(120))
                .devices(line)
                .start(),
        )?;
        let port = gw.port();
        let tmp =
            std::env::temp_dir().join(format!("bussard-{tag}-{}-{}", std::process::id(), port));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        Ok(Bench {
            gw,
            port,
            models: Mutex::new(models),
            tmp,
            _rt: rt,
        })
    }

    /// Replaces every device on the bus with `devices`.
    fn swap_line(&self, devices: Vec<MockDevice>) -> Result<(), Box<dyn Error>> {
        let (line, models): (Vec<_>, Vec<_>) = devices.into_iter().map(on_line).unzip();
        self.gw.with_line(|l| *l = line)?;
        *self
            .models
            .lock()
            .map_err(|_| "the model list is poisoned")? = models;
        Ok(())
    }

    fn model(&self) -> PathBuf {
        self.tmp.join("knx")
    }

    /// Runs `bussard <args> --dir <model> --gateway 127.0.0.1:<port>`.
    fn bussard(&self, args: &[&str]) -> Result<Output, Box<dyn Error>> {
        let model = self.model();
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
            .env("BUSSARD_ASSIGN_WAIT_MS", "300")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }

    /// The model of the device now at `addr`, with its current address and
    /// programming mode.
    fn device(&self, addr: &str) -> Option<MockDevice> {
        let addr: IndividualAddress = addr.parse().ok()?;
        let line = self.gw.devices().ok()?;
        let index = line.iter().position(|d| d.address == addr)?;
        let models = self.models.lock().ok()?;
        let mut model = lock(models.get(index)?).clone();
        model.address = line[index].address;
        model.programming = line[index].programming;
        Some(model)
    }

    fn total_writes(&self) -> usize {
        self.models
            .lock()
            .map(|models| models.iter().map(|m| lock(m).writes).sum())
            .unwrap_or(0)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The model: 1.1.4 is an MDT blind actuator with two links; `extra` adds more
/// device files (address, order number).
fn write_model(dir: &Path, extra: &[(&str, &str)]) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Rollladen Wohnzimmer\"\nproduct = \"MDT-JAL0410\"\n\n\
         [links]\n20.send = \"1/2/0\"\n21.listen = [\"1/2/1\"]\n",
    )?;
    let mut lock = String::from(
        "version = 2\n\n[[device]]\naddress = \"1.1.4\"\nproduct = \"MDT-JAL0410\"\nmask = \"07B0\"\n",
    );
    for (addr, order) in extra {
        std::fs::write(
            dir.join("devices").join(format!("{addr}.toml")),
            format!("address = \"{addr}\"\nname = \"Device {addr}\"\nproduct = \"{order}\"\n"),
        )?;
        lock.push_str(&format!(
            "\n[[device]]\naddress = \"{addr}\"\nproduct = \"{order}\"\n"
        ));
    }
    std::fs::write(dir.join("bussard.lock"), lock)?;
    Ok(())
}

/// The tables the model computes for 1.1.4.
fn model_tables_device(addr: &str) -> MockDevice {
    MockDevice::system_b(
        addr,
        "MDT-JAL0410",
        &["1/2/0", "1/2/1"],
        &[(1, 20), (2, 21)],
    )
}

fn manifest_in(dir: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        dir.join("manifest.json"),
    )?)?)
}

/// The only run directory under `<model>/captures/backups/`.
fn only_run_dir(model: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let root = model.join("captures").join("backups");
    let dirs: Vec<PathBuf> = std::fs::read_dir(&root)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("manifest.json").is_file())
        .collect();
    match dirs.as_slice() {
        [one] => Ok(one.clone()),
        other => Err(format!(
            "expected one backup run in {}, found {other:?}",
            root.display()
        )
        .into()),
    }
}

/// The address/association element octets recorded in a device backup file.
fn backup_table_bytes(file: &Path) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
    let mut addrs = Vec::new();
    for g in json["addresses"].as_array().ok_or("no addresses")? {
        let ga: GroupAddress = g.as_str().ok_or("ga not a string")?.parse()?;
        addrs.extend_from_slice(&ga.raw().to_be_bytes());
    }
    let mut assocs = Vec::new();
    for a in json["associations"].as_array().ok_or("no associations")? {
        let tsap = a["tsap"].as_u64().ok_or("tsap")? as u16;
        let asap = a["asap"].as_u64().ok_or("asap")? as u16;
        assocs.extend_from_slice(&tsap.to_be_bytes());
        assocs.extend_from_slice(&asap.to_be_bytes());
    }
    Ok((addrs, assocs))
}

#[test]
fn test_backup_reads_every_model_device_and_never_writes() -> TestResult {
    let mut system1 = MockDevice::system_b("1.1.5", "OLD-BCU1", &[], &[]);
    system1.mask = 0x0012;
    let bench = Bench::start(
        "backup",
        vec![
            MockDevice::system_b(
                "1.1.4",
                "MDT-JAL0410",
                &["1/2/0", "4/2/12"],
                &[(1, 20), (2, 59)],
            ),
            system1,
        ],
    )?;
    // 1.1.6 is in the model but not on the bus.
    write_model(
        &bench.model(),
        &[("1.1.5", "OLD-BCU1"), ("1.1.6", "GONE-1")],
    )?;
    let out_dir = bench.tmp.join("snap");

    let out = bench.bussard(&["backup", "--json", "--out", out_dir.to_str().ok_or("path")?])?;
    let (stdout, stderr) = text(&out);
    assert!(
        out.status.success(),
        "an unreachable device is listed, not a failure; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        bench.total_writes(),
        0,
        "backup must never write; stderr:\n{stderr}"
    );

    let manifest = manifest_in(&out_dir)?;
    let devices = manifest["devices"].as_array().ok_or("devices")?;
    let status = |ia: &str| {
        devices
            .iter()
            .find(|d| d["address"] == ia)
            .map(|d| d["status"].as_str().unwrap_or("").to_string())
    };
    assert_eq!(status("1.1.4").as_deref(), Some("backed_up"), "{manifest}");
    assert_eq!(status("1.1.5").as_deref(), Some("skipped"), "{manifest}");
    assert_eq!(
        status("1.1.6").as_deref(),
        Some("unreachable"),
        "{manifest}"
    );

    let dev = devices
        .iter()
        .find(|d| d["address"] == "1.1.4")
        .ok_or("1.1.4 row")?;
    assert_eq!(dev["mask"], "07B0");
    assert_eq!(dev["order_number"], "MDT-JAL0410");
    assert!(dev["application"].is_string(), "{dev}");
    assert_eq!(dev["parameters"]["captured"], true, "{dev}");
    assert_eq!(dev["parameters"]["length"], 40, "{dev}");
    let skipped = devices
        .iter()
        .find(|d| d["address"] == "1.1.5")
        .ok_or("1.1.5 row")?;
    assert!(
        skipped["detail"]
            .as_str()
            .unwrap_or("")
            .contains("unsupported mask 0012"),
        "{skipped}"
    );

    // The device file carries the tables and the parameter image.
    let file = out_dir.join(dev["file"].as_str().ok_or("file")?);
    let backup: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file)?)?;
    assert_eq!(backup["addresses"], serde_json::json!(["1/2/0", "4/2/12"]));
    let expected_hex: String = (0u8..40).map(|b| format!("{b:02X}")).collect();
    assert_eq!(backup["parameters"]["bytes"], expected_hex);
    assert_eq!(backup["parameters"]["base"], PARAM_BASE);
    Ok(())
}

#[test]
fn test_restore_of_a_fresh_backup_is_an_empty_plan() -> TestResult {
    let bench = Bench::start("restore-noop", vec![model_tables_device("1.1.4")])?;
    write_model(&bench.model(), &[])?;

    let out = bench.bussard(&["backup", "1.1.4"])?;
    let (_, stderr) = text(&out);
    assert!(out.status.success(), "backup failed:\n{stderr}");
    let run = only_run_dir(&bench.model())?;

    let out = bench.bussard(&["restore", run.to_str().ok_or("path")?, "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("nothing to do"),
        "a fresh backup must plan empty; stdout:\n{stdout}"
    );
    assert_eq!(bench.total_writes(), 0, "an empty plan writes nothing");
    Ok(())
}

#[test]
fn test_restore_after_apply_returns_byte_identical_tables() -> TestResult {
    // The device carries a ghost link the model does not have, so `apply`
    // changes it; `restore` from the pre-apply backup must put it back exactly.
    let original = MockDevice::system_b(
        "1.1.4",
        "MDT-JAL0410",
        &["1/2/0", "1/2/1", "4/2/12"],
        &[(1, 20), (2, 21), (3, 59)],
    );
    let before = original.table_bytes();
    let bench = Bench::start("restore-apply", vec![original])?;
    write_model(&bench.model(), &[])?;

    let out = bench.bussard(&["backup"])?;
    assert!(out.status.success(), "backup failed:\n{}", text(&out).1);
    let run = only_run_dir(&bench.model())?;

    let out = bench.bussard(&["apply", "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "apply failed:\n{stdout}\n{stderr}");
    assert!(
        !stderr.contains("No installation-wide backup yet"),
        "a backup run exists, so apply must not nag; stderr:\n{stderr}"
    );
    let applied = bench.device("1.1.4").ok_or("device")?.table_bytes();
    assert_ne!(applied, before, "apply should have changed the tables");

    let out = bench.bussard(&["restore", run.to_str().ok_or("path")?, "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "restore failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("restore verified"), "stdout:\n{stdout}");
    let restored = bench.device("1.1.4").ok_or("device")?.table_bytes();
    assert_eq!(
        restored, before,
        "restore must return byte-identical tables"
    );
    Ok(())
}

#[test]
fn test_replace_refuses_a_different_order_number() -> TestResult {
    // 1.1.4 is dead; the spare in programming mode is the wrong product.
    let mut spare = MockDevice::system_b("15.15.255", "MDT-AKS0416", &[], &[]);
    spare.programming = true;
    let bench = Bench::start("replace-refuse", vec![spare])?;
    write_model(&bench.model(), &[])?;

    let out = bench.bussard(&[
        "replace",
        "1.1.4",
        "--product",
        "unused.knxprod",
        "--no-flash",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(!out.status.success(), "must refuse; stdout:\n{stdout}");
    assert!(
        stderr.contains("refusing to replace 1.1.4") && stderr.contains("MDT-AKS0416"),
        "stderr:\n{stderr}"
    );
    assert!(
        bench.device("15.15.255").is_some(),
        "the spare must keep its address"
    );
    assert_eq!(bench.total_writes(), 0, "a refused replace writes nothing");
    Ok(())
}

#[test]
fn test_replace_no_flash_restores_the_pre_failure_tables() -> TestResult {
    let bench = Bench::start("replace-happy", vec![model_tables_device("1.1.4")])?;
    write_model(&bench.model(), &[])?;

    // Day one: the owner backs up.
    let out = bench.bussard(&["backup"])?;
    assert!(out.status.success(), "backup failed:\n{}", text(&out).1);
    let run = only_run_dir(&bench.model())?;
    let pre_failure = backup_table_bytes(
        &run.join(
            manifest_in(&run)?["devices"][0]["file"]
                .as_str()
                .ok_or("file")?,
        ),
    )?;

    // The actuator dies; a factory-fresh spare of the same product goes in.
    let mut spare = MockDevice::system_b("15.15.255", "MDT-JAL0410", &[], &[]);
    spare.programming = true;
    bench.swap_line(vec![spare])?;

    let out = bench.bussard(&[
        "replace",
        "1.1.4",
        "--product",
        "unused.knxprod",
        "--no-flash",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");

    let dev = bench
        .device("1.1.4")
        .ok_or("the spare must now answer at 1.1.4")?;
    assert!(dev.progmode_cleared, "programming mode must be cleared");
    assert_eq!(
        dev.table_bytes(),
        pre_failure,
        "the replacement's tables must equal the pre-failure backup"
    );

    // The summary.
    assert!(
        stdout.contains("assigned 15.15.255 → 1.1.4"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("replaced 1.1.4 via 127.0.0.1:"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("order number: MDT-JAL0410"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("left alone (--no-flash)"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("link tables: applied and verified"),
        "stdout:\n{stdout}"
    );

    // The record.
    let body = std::fs::read_to_string(bench.model().join("devices").join("1.1.4.toml"))?;
    assert!(
        body.lines().any(|l| l.starts_with("replaced = \"20")),
        "device file:\n{body}"
    );
    assert!(
        body.contains("product = \"MDT-JAL0410\"") && body.contains("21.listen = [\"1/2/1\"]"),
        "rest of the file kept:\n{body}"
    );
    Ok(())
}

/// `apply` declares a group address the device file uses but `groups.toml`
/// does not define (named after the device and the object), and a device whose
/// tables already match the model is not written at all.
#[test]
fn test_apply_declares_used_groups_and_writes_nothing_when_the_device_matches() -> TestResult {
    let bench = Bench::start("apply-declare", vec![model_tables_device("1.1.4")])?;
    write_model(&bench.model(), &[])?;

    let out = bench.bussard(&["apply", "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "apply failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains(
            "added 1/2/0 \"Rollladen Wohnzimmer object 20\" to groups.toml, first used by \
             1.1.4 object 20"
        ),
        "stdout:\n{stdout}"
    );
    let groups = std::fs::read_to_string(bench.model().join("groups.toml"))?;
    assert!(groups.contains("\"1/2/1\""), "{groups}");
    assert_eq!(bench.total_writes(), 0, "a matching device is not written");
    Ok(())
}

/// Validation is part of `apply`: a model with an error is refused before the
/// bus is touched, with the diagnostic.
#[test]
fn test_apply_refuses_a_model_with_validation_errors() -> TestResult {
    let bench = Bench::start(
        "apply-invalid",
        vec![MockDevice::system_b("1.1.4", "MDT-JAL0410", &[], &[])],
    )?;
    write_model(&bench.model(), &[])?;
    std::fs::write(
        bench.model().join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"A\" },\n  { address = \"1/2/0\", name = \"B\" },\n  \
         { address = \"1/2/1\", name = \"C\" },\n]\n",
    )?;
    let out = bench.bussard(&["apply", "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(!out.status.success(), "must refuse:\n{stdout}\n{stderr}");
    assert!(
        stderr.contains("refusing to apply: the model has"),
        "{stderr}"
    );
    assert!(stderr.contains("E020"), "{stderr}");
    assert_eq!(bench.total_writes(), 0, "nothing is written");
    Ok(())
}
