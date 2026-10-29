//! `bussard mcp` with a KNX Data Secure keyring against a mock gateway
//! (issue #205), driven over real stdio JSON-RPC:
//!
//! - `knx_plan_device` / `knx_apply_device` on a device the keyring lists:
//!   the tables are read and written over `A_SecureData`, and the security
//!   object is reprogrammed next to them (group key table PID 53, security
//!   individual address table PID 54, group-object flags PID 61, between the
//!   security load-state transitions), as `bussard apply --keyring` does. The
//!   device also runs the synthetic parameter-test application, and the model
//!   changes one parameter: the plan lists it and the apply writes the
//!   differing octet over `A_SecureData` after the tables (issue #274).
//! - `knx_wait_for_telegram` / `knx_infer_group` see a secured group telegram
//!   decrypted, through the ring feeder's `from_frame_secured` path.
//!
//! The keyring is the committed SYNTHETIC `knx-sim/examples/secure/synthetic.knxkeys`
//! (made-up password; a tool key for 1.1.10, a group key for 1/2/3). The test
//! decrypts it itself to build the mock device and the secured sender, and
//! never prints a key. The mock binds 127.0.0.1 and every run passes an
//! explicit loopback `--gateway`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mgmt::property_ext::{
    A_FUNCTION_PROPERTY_EXT_COMMAND, A_FUNCTION_PROPERTY_EXT_STATE_READ,
    A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE, A_PROPERTY_EXT_DESCRIPTION_READ,
    A_PROPERTY_EXT_DESCRIPTION_RESPONSE, A_PROPERTY_EXT_VALUE_READ, A_PROPERTY_EXT_VALUE_RESPONSE,
    A_PROPERTY_EXT_VALUE_WRITE_CON, A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE, OT_SECURITY,
    PID_GO_SECURITY_FLAGS, PID_GRP_KEY_TABLE, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE,
    PID_SECURITY_LOAD_STATE_CONTROL,
};
use bussard_model::GroupAddress;
use bussard_secure::{Key16, SecurityAlgorithm, Sequence, encode_group};
use bussard_testkit::consts::{
    A_MEMORY_RESPONSE, A_MEMORY_WRITE, APCI_SELECTOR, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM,
    OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE, PID_PROGRAM_VERSION,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ga, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, GroupData, MessageCode};
use serde_json::{Value, json};

/// The synthetic keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// The group-object count the mock's security object reports.
const GO_COUNT: u16 = 60;

/// The interface object of the application program on the mock.
const APP_OBJECT: u8 = 4;

include!("support/param_app.rs");

/// Zips the application XML `xml` into `<dir>/products/param-test.knxprod`
/// and returns its SHA-256, for the lock to pin.
fn store_product_xml(dir: &Path, xml: &str) -> TestResult<String> {
    use sha2::Digest as _;
    let store = dir.join("products");
    std::fs::create_dir_all(&store)?;
    let path = store.join("param-test.knxprod");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path)?);
    zip.start_file(
        "M-00FA/M-00FA_A-0002.xml",
        zip::write::SimpleFileOptions::default(),
    )?;
    zip.write_all(xml.as_bytes())?;
    zip.finish()?;
    Ok(sha2::Sha256::digest(std::fs::read(&path)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn keyring_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knx-sim/examples/secure/synthetic.knxkeys")
}

fn keyring() -> TestResult<bussard_project::Keyring> {
    let xml = std::fs::read_to_string(keyring_path())?;
    Ok(bussard_project::parse_keyring(&xml, PASSWORD)?)
}

/// The tool key the synthetic keyring holds for 1.1.10.
fn tool_key() -> TestResult<[u8; 16]> {
    let keyring = keyring()?;
    let key = keyring
        .tool_key(ia("1.1.10")?)
        .ok_or("the synthetic keyring lists no tool key for 1.1.10")?;
    Ok(*key.bytes())
}

/// The group key of 1/2/3 in the synthetic keyring.
fn group_key() -> TestResult<Key16> {
    Ok(keyring()?
        .group_keys
        .get(&ga("1/2/3")?)
        .ok_or("the synthetic keyring has no key for 1/2/3")?
        .clone())
}

/// A fresh model directory: device 1.1.10 (security activated) sending 1/2/0
/// from object 20 and listening on the secured 1/2/3 with object 22.
fn model_dir(tag: &str) -> TestResult<PathBuf> {
    model_dir_with(tag, APP_XML)
}

/// [`model_dir`] whose product holds the application XML `xml`.
fn model_dir_with(tag: &str, xml: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-mcp-secure-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    // A documentation address as the configured gateway: every run overrides
    // it with the mock's loopback endpoint.
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Status\", dpt = \"1.001\" },\n  \
         { address = \"1/2/3\", name = \"Secured level\", dpt = \"5.001\", secure = true },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.10.toml"),
        "address = \"1.1.10\"\nname = \"Secure actuator\"\n\n[security]\nactivated = true\n\n\
         [parameters]\n\"thr@P-0_R-1\" = \"12\"\n\n\
         [links]\n20.send = \"1/2/0\"\n22.listen = [\"1/2/3\"]\n",
    )?;
    // The device runs the synthetic application; the lock pins its archive.
    let sha = store_product_xml(&dir, xml)?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \
             \"products/param-test.knxprod\"\norigin = {{ kind = \"file\", path = \
             \"param-test.knxprod\" }}\napplications = [\"M-00FA_A-0002\"]\n\n[[device]]\n\
             address = \"1.1.10\"\napplication = \"M-00FA_A-0002\"\nproduct_sha256 = \
             \"{sha}\"\nmask = \"07B0\"\n"
        ),
    )?;
    Ok(dir)
}

/// What the mock's security object saw.
#[derive(Debug, Default)]
struct SecurityLog {
    /// Load-control events, as their first octet (`04` unload, `01` start,
    /// `02` complete).
    controls: Vec<u8>,
    /// `A_PropertyExtValue_WriteCon` writes as `(pid, count, start, octets)`.
    writes: Vec<(u16, u8, u16, Vec<u8>)>,
    /// The security individual address table (PID 54) the device holds,
    /// 8 octets per entry, as the writes leave it (issue #297).
    pid54: Vec<u8>,
    /// How many times PID 54 was read.
    pid54_reads: usize,
    /// The group-object security flags (PID 61) the device holds, one octet
    /// per group object, as the writes leave it (issue #331).
    pid61: Vec<u8>,
    /// How many times PID 61 was read (its element count, the first read of
    /// every table read; issue #336).
    pid61_reads: usize,
    /// The group key table's (PID 53) element count, as the writes leave it
    /// (the keys themselves are write-only, issue #349).
    pid53: u16,
    /// What the device acknowledges and then drops (issue #349).
    dropped: Option<Dropped>,
    /// The security object's load state (PID 5) as the device reports it
    /// to a state read (issue #534); `None` until the first transition
    /// (the object then reads `Loaded`).
    load_state: Option<u8>,
    /// The state the device answers `LoadCompleted` with, and keeps, in
    /// place of `Loaded` (issue #534).
    completes_to: Option<u8>,
    /// The state the device falls back to after it answered
    /// `LoadCompleted` (a device that does not persist the object, #534).
    reverts_to: Option<u8>,
    /// The `max_nr_of_elem` the property description of PID 54 reports
    /// (issue #537); `None` answers the default description (0 elements).
    pid54_capacity: Option<u16>,
}

/// A write the mock device acknowledges as written and does not store, so
/// only a read-back can tell (issue #349).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropped {
    /// Every `A_PropertyExtValue_WriteCon` to this security-object property.
    Pid(u16),
    /// The memory writes into the association table's segment.
    Associations,
    /// The memory writes into the parameter segment.
    Parameters,
}

impl Dropped {
    /// The object whose segment this drops memory writes into.
    fn segment(self) -> Option<u8> {
        match self {
            Dropped::Pid(_) => None,
            Dropped::Associations => Some(2),
            Dropped::Parameters => Some(APP_OBJECT),
        }
    }
}

/// The security object header fields of an `A_PropertyExt*` payload:
/// `(object type, property id)`.
fn ext_header(data: &[u8]) -> Option<(u16, u16)> {
    let h = data.get(..5)?;
    let object_type = u16::from_be_bytes([h[0], h[1]]);
    let pid = (u16::from(h[3] & 0x0F) << 8) | u16::from(h[4]);
    Some((object_type, pid))
}

/// A System B device with Data Secure activated and a security object that
/// follows the load-state machine and accepts the property writes of a
/// secured download, recording them in `log`.
fn secure_device(log: Arc<Mutex<SecurityLog>>) -> TestResult<MockDevice> {
    // The synthetic application, Loaded, with its parameter segment holding
    // threshold 7 (the model asks for 12) and the switch off.
    secure_device_with(log, &["1/2/0"], &[(1, 20)], &[7, 0], &[])
}

/// [`secure_device`] holding the address table `addresses`, the
/// associations `associations`, the parameter octets `params` and the
/// group objects `secured` flagged `0x03` in PID 61.
fn secure_device_with(
    log: Arc<Mutex<SecurityLog>>,
    addresses: &[&str],
    associations: &[(u16, u16)],
    params: &[u8],
    secured: &[u16],
) -> TestResult<MockDevice> {
    {
        let mut flags = vec![0u8; usize::from(GO_COUNT)];
        for object in secured {
            if let Some(flag) = usize::from(*object)
                .checked_sub(1)
                .and_then(|i| flags.get_mut(i))
            {
                *flag = 0x03;
            }
        }
        log.lock().map_err(|_| "log poisoned")?.pid61 = flags;
    }
    let mut address_table = u16::try_from(addresses.len())?.to_be_bytes().to_vec();
    for address in addresses {
        address_table.extend_from_slice(&ga(address)?.raw().to_be_bytes());
    }
    let mut association_table = u16::try_from(associations.len())?.to_be_bytes().to_vec();
    for (tsap, asap) in associations {
        association_table.extend_from_slice(&tsap.to_be_bytes());
        association_table.extend_from_slice(&asap.to_be_bytes());
    }
    Ok(MockDevice::system_b(ia("1.1.10")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_table(1, &address_table)
        .with_table(2, &association_table)
        .with_table(APP_OBJECT, params)
        .with_property(
            APP_OBJECT,
            PID_PROGRAM_VERSION,
            5,
            &[0x00, 0xFA, 0x00, 0x02, 0x01],
        )
        .with_go_count(GO_COUNT)
        .with_data_secure(tool_key()?)
        .with_hook(move |_, apci, data| {
            // A memory write into a dropped segment: echoed as written,
            // never stored.
            if apci & APCI_SELECTOR == A_MEMORY_WRITE
                && let Some(object) = log.lock().ok()?.dropped.and_then(Dropped::segment)
            {
                let address = u32::from(u16::from_be_bytes([*data.first()?, *data.get(1)?]));
                let base = bussard_testkit::device::segment_base_for(object);
                if (base..base + 0x800).contains(&address) {
                    let value = data.get(2..)?;
                    let mut out = data.get(..2)?.to_vec();
                    out.extend_from_slice(value);
                    return Some(Reaction::Answer(
                        A_MEMORY_RESPONSE | (u16::try_from(value.len()).ok()? & 0x3F),
                        out,
                    ));
                }
            }
            let (object_type, pid) = ext_header(data)?;
            if object_type != OT_SECURITY {
                return None;
            }
            let header = data.get(..5)?.to_vec();
            match apci {
                A_FUNCTION_PROPERTY_EXT_STATE_READ if pid == PID_SECURITY_LOAD_STATE_CONTROL => {
                    let state = log.lock().ok()?.load_state.unwrap_or(0x01);
                    let mut out = header;
                    out.extend_from_slice(&[0x00, state]);
                    Some(Reaction::Answer(
                        A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE,
                        out,
                    ))
                }
                A_FUNCTION_PROPERTY_EXT_COMMAND if pid == PID_SECURITY_LOAD_STATE_CONTROL => {
                    let event = *data.get(5)?;
                    let completes_to = log.lock().ok()?.completes_to;
                    let state = match event {
                        0x04 => 0x00,                      // Unload -> Unloaded
                        0x01 => 0x02,                      // StartLoading -> Loading
                        _ => completes_to.unwrap_or(0x01), // LoadCompleted -> Loaded
                    };
                    if let Ok(mut log) = log.lock() {
                        log.load_state = Some(if event == 0x02 {
                            log.reverts_to.unwrap_or(state)
                        } else {
                            state
                        });
                        log.controls.push(event);
                        // Unload empties the group key table.
                        if event == 0x04 && log.dropped != Some(Dropped::Pid(PID_GRP_KEY_TABLE)) {
                            log.pid53 = 0;
                        }
                    }
                    let mut out = header;
                    out.extend_from_slice(&[0x00, state]);
                    Some(Reaction::Answer(
                        A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE,
                        out,
                    ))
                }
                A_PROPERTY_EXT_DESCRIPTION_READ if pid == PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                    let max = log.lock().ok()?.pid54_capacity?;
                    let desc = bussard_mgmt::property_ext::PropertyExtDescription {
                        addr: bussard_mgmt::property_ext::PropertyExtAddress::decode(data)?,
                        description_type: 0,
                        property_index: 5,
                        dpt_main: 0,
                        dpt_sub: 0,
                        write_enable: true,
                        pdt: 0x18,
                        max_elements: max,
                        read_level: 3,
                        write_level: 0,
                    };
                    Some(Reaction::Answer(
                        A_PROPERTY_EXT_DESCRIPTION_RESPONSE,
                        bussard_mgmt::property_ext::encode_property_ext_description_response(&desc),
                    ))
                }
                A_PROPERTY_EXT_VALUE_READ if pid == PID_GO_SECURITY_FLAGS => {
                    // The element count (start 0), or the flags the device
                    // holds (issue #331).
                    let count = *data.get(5)?;
                    let start = u16::from_be_bytes([*data.get(6)?, *data.get(7)?]);
                    let mut log = log.lock().ok()?;
                    let mut out = header;
                    if start == 0 {
                        log.pid61_reads += 1;
                        out.extend_from_slice(&[1, 0, 0]);
                        out.extend_from_slice(&GO_COUNT.to_be_bytes());
                    } else {
                        let from = usize::from(start) - 1;
                        let to = (from + usize::from(count)).min(log.pid61.len());
                        let elements = log.pid61.get(from..to)?.to_vec();
                        out.push(u8::try_from(elements.len()).ok()?);
                        out.extend_from_slice(&start.to_be_bytes());
                        out.extend_from_slice(&elements);
                    }
                    Some(Reaction::Answer(A_PROPERTY_EXT_VALUE_RESPONSE, out))
                }
                A_PROPERTY_EXT_VALUE_READ if pid == PID_GRP_KEY_TABLE => {
                    // Only the element count (start 0): the keys are
                    // write-only.
                    let start = u16::from_be_bytes([*data.get(6)?, *data.get(7)?]);
                    let log = log.lock().ok()?;
                    let mut out = header;
                    if start == 0 {
                        out.extend_from_slice(&[1, 0, 0]);
                        out.extend_from_slice(&log.pid53.to_be_bytes());
                    } else {
                        out.extend_from_slice(&[0, 0, 0]);
                    }
                    Some(Reaction::Answer(A_PROPERTY_EXT_VALUE_RESPONSE, out))
                }
                A_PROPERTY_EXT_VALUE_READ if pid == PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE => {
                    let count = *data.get(5)?;
                    let start = u16::from_be_bytes([*data.get(6)?, *data.get(7)?]);
                    let mut log = log.lock().ok()?;
                    log.pid54_reads += 1;
                    let mut out = header;
                    if start == 0 {
                        let entries = u16::try_from(log.pid54.len() / 8).ok()?;
                        out.extend_from_slice(&[1, 0, 0]);
                        out.extend_from_slice(&entries.to_be_bytes());
                    } else {
                        let from = (usize::from(start) - 1) * 8;
                        let to = (from + usize::from(count) * 8).min(log.pid54.len());
                        let elements = log.pid54.get(from..to)?.to_vec();
                        out.push(u8::try_from(elements.len() / 8).ok()?);
                        out.extend_from_slice(&start.to_be_bytes());
                        out.extend_from_slice(&elements);
                    }
                    Some(Reaction::Answer(A_PROPERTY_EXT_VALUE_RESPONSE, out))
                }
                A_PROPERTY_EXT_VALUE_WRITE_CON => {
                    let count = *data.get(5)?;
                    let start = u16::from_be_bytes([*data.get(6)?, *data.get(7)?]);
                    if let Ok(mut log) = log.lock()
                        && log.dropped != Some(Dropped::Pid(pid))
                    {
                        let octets = data.get(8..).unwrap_or(&[]).to_vec();
                        if pid == PID_GRP_KEY_TABLE && start > 0 {
                            let last = start.saturating_add(u16::from(count)).saturating_sub(1);
                            log.pid53 = log.pid53.max(last);
                        }
                        if pid == PID_GO_SECURITY_FLAGS && start > 0 {
                            let from = usize::from(start) - 1;
                            for (i, flag) in octets.iter().enumerate() {
                                if let Some(slot) = log.pid61.get_mut(from + i) {
                                    *slot = *flag;
                                }
                            }
                        }
                        if pid == PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE {
                            if start == 0 {
                                // The count-0 clear.
                                log.pid54.clear();
                            } else {
                                let from = (usize::from(start) - 1) * 8;
                                log.pid54.truncate(from);
                                log.pid54.extend_from_slice(&octets);
                            }
                        }
                        log.writes.push((pid, count, start, octets));
                    }
                    let mut out = header;
                    out.push(count);
                    out.extend_from_slice(&start.to_be_bytes());
                    out.push(0x00);
                    Some(Reaction::Answer(
                        A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE,
                        out,
                    ))
                }
                _ => None,
            }
        }))
}

/// A `bussard mcp` child process spoken to over stdio JSON-RPC.
struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl Server {
    /// Starts `bussard mcp` on `dir` against the loopback mock at `port`,
    /// with the synthetic keyring and its password, and completes the
    /// handshake.
    fn start(dir: &Path, port: u16, extra: &[&str]) -> TestResult<Server> {
        Server::start_with(dir, port, extra, &keyring_path())
    }

    /// [`Server::start`] with another keyring (or key store) file.
    fn start_with(dir: &Path, port: u16, extra: &[&str], keyring: &Path) -> TestResult<Server> {
        let mut args = vec!["--no-model-edits"];
        args.extend_from_slice(extra);
        Server::spawn(dir, port, &args, keyring)
    }

    /// Starts the server with the model-edit tools and `extra` flags.
    fn spawn(dir: &Path, port: u16, extra: &[&str], keyring: &Path) -> TestResult<Server> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .arg("mcp")
            .arg("--dir")
            .arg(dir)
            .arg("--gateway")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--keyring")
            .arg(keyring)
            .args(extra)
            .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env_remove("BUSSARD_KEYRING")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or("no stdin pipe")?;
        let stdout = child.stdout.take().ok_or("no stdout pipe")?;
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Server {
            child,
            stdin,
            lines,
            next_id: 1,
        };
        server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-secure-mock", "version": "0"}
            }),
        )?;
        server.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        Ok(server)
    }

    fn send(&mut self, message: &Value) -> TestResult {
        writeln!(self.stdin, "{message}")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Sends a request and returns its `result`, skipping notifications.
    fn request(&mut self, method: &str, params: Value) -> TestResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let line = self.lines.recv_timeout(Duration::from_secs(90))?;
            let message: Value = serde_json::from_str(&line)?;
            if message["id"] == id {
                if let Some(error) = message.get("error") {
                    return Err(format!("{method} failed: {error}").into());
                }
                return Ok(message["result"].clone());
            }
        }
    }

    /// Calls a tool and returns its structured result.
    fn call(&mut self, tool: &str, args: Value) -> TestResult<Value> {
        let result = self.request("tools/call", json!({"name": tool, "arguments": args}))?;
        Ok(result["structuredContent"].clone())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_mcp_apply_on_a_keyring_listed_device_reprograms_the_security_object() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let log = Arc::new(Mutex::new(SecurityLog::default()));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x55)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device(Arc::clone(&log))?)
            .start(),
    )?;
    let dir = model_dir("apply")?;
    let mut server = Server::start(&dir, gw.port(), &["--allow-programming"])?;

    // The server connects its tunnel in the background: retry a plan refused
    // only because the bus is not up yet.
    let mut plan = Value::Null;
    for _ in 0..50 {
        plan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
        let waiting = plan["reason"]
            .as_str()
            .is_some_and(|r| r.contains("is not connected"));
        if !waiting {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["secured"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    let security = &plan["security_object"];
    assert_eq!(security["keyed_groups"], json!(["1/2/3"]), "plan: {plan}");
    assert_eq!(security["secured_objects"], json!([22]), "plan: {plan}");
    let summary = security["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("security object is reprogrammed"),
        "{summary}"
    );
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(sentences.contains("Data Secure"), "{sentences}");
    // The parameter half, read over A_SecureData (issue #274).
    assert!(
        sentences.contains("  ~ thr@P-0_R-1 = 12, was 7\n"),
        "{sentences}"
    );
    assert_eq!(plan["writes"]["parameter_octets"], 1, "plan: {plan}");
    let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;
    assert!(
        log.lock().map_err(|_| "log poisoned")?.controls.is_empty(),
        "planning must not touch the security object"
    );

    let applied = server.call(
        "knx_apply_device",
        json!({"address": "1.1.10", "plan_digest": digest}),
    )?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    assert_eq!(applied["secured"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["written"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["octets"], 1, "apply: {applied}");
    // Issue #349: verified means read back and compared, with the counts.
    let readback = &applied["readback"];
    assert_eq!(readback["verified"], true, "apply: {applied}");
    assert_eq!(readback["leftovers"], json!([]), "apply: {applied}");
    assert_eq!(readback["compared"]["addresses"], 2, "apply: {applied}");
    assert_eq!(readback["compared"]["associations"], 2, "apply: {applied}");
    assert_eq!(readback["compared"]["group_keys"], 1, "apply: {applied}");
    assert_eq!(
        readback["compared"]["secured_objects"], 1,
        "apply: {applied}"
    );
    assert!(
        readback["compared"]["parameters"].as_u64() >= Some(1),
        "apply: {applied}"
    );
    let (params, app_state, plain_refused) = gw.with_device(ia("1.1.10")?, |dev| {
        (
            dev.table_image(APP_OBJECT).unwrap_or_default(),
            dev.load_state(APP_OBJECT),
            dev.plain_refused,
        )
    })?;
    assert_eq!(params, vec![12, 0], "the differing octet is written");
    assert_eq!(app_state, 1, "the application is Loaded again");
    assert_eq!(plain_refused, 0, "every request rode A_SecureData");

    // The tables: 1/2/0 and 1/2/3, with (1,20) and (2,22).
    let (addresses, associations) = gw.with_device(ia("1.1.10")?, |dev| {
        (
            dev.table_image(1).unwrap_or_default(),
            dev.table_image(2).unwrap_or_default(),
        )
    })?;
    let mut expected = 2u16.to_be_bytes().to_vec();
    expected.extend_from_slice(&ga("1/2/0")?.raw().to_be_bytes());
    expected.extend_from_slice(&ga("1/2/3")?.raw().to_be_bytes());
    assert_eq!(addresses, expected);
    assert_eq!(associations, vec![0, 2, 0, 1, 0, 20, 0, 2, 0, 22]);

    // The security object: unload, start, the three tables, complete.
    let log = log.lock().map_err(|_| "log poisoned")?;
    assert_eq!(log.controls, vec![0x04, 0x01, 0x02], "{log:?}");
    let pids: Vec<u16> = log.writes.iter().map(|w| w.0).collect();
    assert_eq!(
        pids.first(),
        Some(&PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE),
        "the IA table is cleared first: {pids:?}"
    );
    let key_table: Vec<_> = log
        .writes
        .iter()
        .filter(|w| w.0 == PID_GRP_KEY_TABLE)
        .collect();
    assert_eq!(key_table.len(), 1, "{pids:?}");
    // One 18-octet element: the address-table index of 1/2/3 (2), then its key.
    assert_eq!(key_table[0].1, 1);
    assert_eq!(key_table[0].3.get(..2), Some(&[0u8, 2][..]));
    assert_eq!(
        key_table[0].3.get(2..),
        Some(group_key()?.bytes().as_slice())
    );
    let flags: Vec<u8> = log
        .writes
        .iter()
        .filter(|w| w.0 == PID_GO_SECURITY_FLAGS)
        .flat_map(|w| w.3.clone())
        .collect();
    assert_eq!(flags.len(), usize::from(GO_COUNT), "{pids:?}");
    let secured: Vec<usize> = flags
        .iter()
        .enumerate()
        .filter(|(_, f)| **f != 0)
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(secured, vec![22], "only object 22 is flagged secure");
    drop(log);

    // A fresh plan has nothing to do.
    let replan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert!(replan["security_object"].is_null(), "replan: {replan}");
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Plans `address`, retrying while the server's tunnel is still coming up.
fn plan_when_connected(server: &mut Server, address: &str) -> TestResult<Value> {
    let mut plan = Value::Null;
    for _ in 0..50 {
        plan = server.call("knx_plan_device", json!({"address": address}))?;
        let waiting = plan["reason"]
            .as_str()
            .is_some_and(|r| r.contains("is not connected"));
        if !waiting {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(plan)
}

/// `[connection] admit_tunnel_senders = true` (issue #297): a device whose
/// tables and parameters already match the model gets a plan of one change,
/// the keyring's tunnelling address 1.1.200 joining its PID 54, and the apply
/// writes it there (sequence 0). Off, the same device plans as a no-op and
/// PID 54 is not even read.
#[test]
fn test_mcp_apply_with_admit_tunnel_senders_writes_the_tunnel_address_into_pid54() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let log = Arc::new(Mutex::new(SecurityLog::default()));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x56)
            // The keyring's tunnelling user 2 (1.1.200), as the real
            // interface assigns it.
            .tunnel_address(0x11C8)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device_with(
                Arc::clone(&log),
                &["1/2/0", "1/2/3"],
                &[(1, 20), (2, 22)],
                &[12, 0],
                &[22],
            )?)
            .start(),
    )?;
    let dir = model_dir("admit")?;
    let mut server = Server::start(&dir, gw.port(), &["--allow-programming", "--allow-writes"])?;

    // Off (the default): nothing to write, PID 54 is not read.
    let plan = plan_when_connected(&mut server, "1.1.10")?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], true, "plan: {plan}");
    assert_eq!(
        log.lock().map_err(|_| "log poisoned")?.pid54_reads,
        0,
        "PID 54 is read only with admit_tunnel_senders"
    );

    // On: PID 54 (empty, as ETS left it) is missing the tunnel address.
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n\
         admit_tunnel_senders = true\n",
    )?;
    let plan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    assert_eq!(plan["writes"]["security_object"], true, "plan: {plan}");
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.contains(
            "+ the security individual address table (PID 54) admits the tunnelling address \
             1.1.200 as secure sender (sequence 0, admit_tunnel_senders)"
        ),
        "{sentences}"
    );
    let security = &plan["security_object"];
    assert_eq!(
        security["secure_senders"],
        json!([{"address": "1.1.200", "sequence": 0}]),
        "plan: {plan}"
    );
    let summary = security["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("tunnel addresses admitted: 1.1.200"),
        "{summary}"
    );
    assert!(log.lock().map_err(|_| "log poisoned")?.pid54_reads > 0);
    let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;

    let applied = server.call(
        "knx_apply_device",
        json!({"address": "1.1.10", "plan_digest": digest}),
    )?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    {
        let log = log.lock().map_err(|_| "log poisoned")?;
        assert_eq!(log.controls, vec![0x04, 0x01, 0x02], "{log:?}");
        // After: 1.1.200 (0x11C8) with sequence 0.
        assert_eq!(log.pid54, vec![0x11, 0xC8, 0, 0, 0, 0, 0, 0], "{log:?}");
    }
    // The verified write is recorded in the lock, as `adopt` records a read.
    assert_eq!(applied["secure_senders_recorded"], true, "apply: {applied}");
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    assert!(
        lock.contains("secure_senders = [\n  { address = \"1.1.200\", sequence = 0 },\n]"),
        "{lock}"
    );
    // So a secured write from the tunnel is admitted without an adopt.
    let mut write = Value::Null;
    for _ in 0..50 {
        write = server.call("knx_write_group", json!({"ga": "1/2/3", "value": "50%"}))?;
        if write["admission"] == "admitted" {
            break;
        }
        // The server's model handle picks the lock change up on its next poll.
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(write["ok"], true, "write: {write}");
    assert_eq!(write["secured"], true, "write: {write}");
    assert_eq!(write["admission"], "admitted", "write: {write}");

    // The device now admits the tunnel: nothing left to do.
    let replan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Issue #297: with `admit_tunnel_senders` off and a key store whose
/// tunnelling address has no group assigned, `knx_plan_device` notes that
/// only tunnel clients can write the secured 1/2/3 and 1.1.10 does not admit
/// them.
#[test]
fn test_mcp_plan_notes_a_secured_ga_only_unadmitted_tunnel_clients_can_write() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let log = Arc::new(Mutex::new(SecurityLog::default()));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x57)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device_with(
                Arc::clone(&log),
                &["1/2/0", "1/2/3"],
                &[(1, 20), (2, 22)],
                &[12, 0],
                &[22],
            )?)
            .start(),
    )?;
    let dir = model_dir("gap")?;
    let mut store = bussard_project::KeyStore::new("Synthetic");
    store.merge_keyring(&keyring()?);
    for interface in &mut store.interfaces {
        interface.gas.clear();
    }
    let stripped = dir.join("stripped.keys");
    std::fs::write(&stripped, store.to_xml(PASSWORD)?)?;
    let mut server = Server::start_with(&dir, gw.port(), &["--allow-programming"], &stripped)?;
    let plan = plan_when_connected(&mut server, "1.1.10")?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let notes = plan["notes"].to_string();
    assert!(
        notes.contains(
            "secured 1/2/3 has no device sender; only tunnel clients can write it, and 1.1.10 \
             does not admit the tunnelling addresses (set `admit_tunnel_senders = true` under \
             [connection] and apply 1.1.10, or assign 1/2/3 to a tunnelling connection in ETS)"
        ),
        "plan: {plan}"
    );
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A secured `GroupValueWrite` of `value` from 1.1.10 to `dest`, as an
/// `L_Data.ind`.
fn secured_write(key: &Key16, dest: GroupAddress, seq: u64, value: u8) -> TestResult<CemiFrame> {
    let source = ia("1.1.10")?;
    let apdu = Apdu::GroupValueWrite(GroupData::Large(vec![value]));
    let asdu = encode_group(
        key,
        SecurityAlgorithm::AuthenticationEncryption,
        Sequence::new(seq),
        source.raw(),
        dest.raw(),
        &apdu.group_tpdu_bytes(),
    )?;
    let mut frame = CemiFrame::group_secure(dest, source, asdu);
    frame.message_code = MessageCode::LDataInd;
    Ok(frame)
}

/// Pushes `frames` to the connected client over and over from the first
/// CONNECT on, with a fresh sequence number each round. Ends when the gateway
/// has stopped.
async fn push_loop(gw: Arc<MockGateway>, key: Key16) {
    if !gw
        .wait_until(Duration::from_secs(60), |s| s.connects > 0)
        .await
    {
        return;
    }
    let Ok(dest) = ga("1/2/3") else {
        return;
    };
    for seq in 20_000u64.. {
        let Ok(frame) = secured_write(&key, dest, seq, 0x80) else {
            return;
        };
        if gw.push(frame).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[test]
fn test_mcp_wait_and_infer_see_a_secured_telegram_decrypted() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = Arc::new(
        rt.block_on(
            MockGateway::builder()
                .idle_timeout(Duration::from_secs(120))
                .start(),
        )?,
    );
    let pusher = rt.spawn(push_loop(Arc::clone(&gw), group_key()?));
    let dir = model_dir("wait")?;
    let mut server = Server::start(&dir, gw.port(), &[])?;

    let waited = server.call(
        "knx_wait_for_telegram",
        json!({"ga": "1/2/3", "timeout_seconds": 30}),
    )?;
    assert_eq!(waited["matched"], true, "wait: {waited}");
    let telegram = &waited["telegram"];
    assert_eq!(telegram["secured"], true, "{telegram}");
    assert_eq!(telegram["secure_status"], "ok", "{telegram}");
    assert_eq!(telegram["apci"], "write", "{telegram}");
    assert_eq!(
        telegram["payload"], "80",
        "the decrypted payload: {telegram}"
    );

    let inferred = server.call("knx_infer_group", json!({"ga": "1/2/3"}))?;
    assert_eq!(inferred["secured"], true, "infer: {inferred}");
    assert_eq!(inferred["undecrypted_secured"], 0, "infer: {inferred}");
    let payloads = inferred["payloads_hex"]
        .as_array()
        .ok_or("no payloads_hex")?;
    assert!(!payloads.is_empty(), "infer: {inferred}");
    assert!(
        payloads.iter().all(|p| p == "80"),
        "only decrypted payloads: {inferred}"
    );
    assert_eq!(gw.stats().requests, 0, "the server transmitted");
    pusher.abort();
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The model of the unsecure test (issue #331): 1.1.10 sends 1/2/0 from
/// object 20 and listens on the secured 1/2/3 (object 22) and 1/2/4 (object
/// 23), with the key store `bussard.keys` holding the synthetic keyring and a
/// second, made-up group key for 1/2/4.
fn unsecure_model_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = model_dir(tag)?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Status\", dpt = \"1.001\" },\n  \
         { address = \"1/2/3\", name = \"Secured level\", dpt = \"5.001\", secure = true },\n  \
         { address = \"1/2/4\", name = \"Secured scene\", dpt = \"17.001\", secure = true },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.10.toml"),
        "address = \"1.1.10\"\nname = \"Secure actuator\"\n\n[security]\nactivated = true\n\n\
         [parameters]\n\"thr@P-0_R-1\" = \"12\"\n\n\
         [links]\n20.send = \"1/2/0\"\n22.listen = [\"1/2/3\"]\n23.listen = [\"1/2/4\"]\n",
    )?;
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "{lock}objects = [\n  {{ number = 20, flags = \"CT\" }},\n  \
             {{ number = 22, flags = \"CW\", secure = true }},\n  \
             {{ number = 23, flags = \"CW\", secure = true }},\n]\n"
        ),
    )?;
    let mut store = bussard_project::KeyStore::new("Synthetic");
    store.merge_keyring(&keyring()?);
    store
        .group_keys
        .insert(ga("1/2/4")?, Key16::new([0x33; 16]));
    store.save(&dir, PASSWORD)?;
    Ok(dir)
}

/// Issue #331, end to end on a Secure mock device: `knx_set_group` with
/// `secure: false` takes 1/2/3's key out of the key store and clears the
/// group's and object 22's flags; the plan of 1.1.10 is the one
/// security-object change, the apply rewrites the group key table without
/// the entry and clears object 22's flag, and a re-plan has nothing to do.
/// The group write then goes out plain, `bussard keys export` leaves the key
/// out, and `knx_undo` brings the flags and the very key back.
#[test]
fn test_mcp_unsecure_a_group_address_end_to_end() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let log = Arc::new(Mutex::new(SecurityLog::default()));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x58)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device_with(
                Arc::clone(&log),
                &["1/2/0", "1/2/3", "1/2/4"],
                &[(1, 20), (2, 22), (3, 23)],
                &[12, 0],
                &[22, 23],
            )?)
            .start(),
    )?;
    let dir = unsecure_model_dir("unsecure")?;
    let store_path = bussard_project::KeyStore::path(&dir);
    let mut server = Server::spawn(
        &dir,
        gw.port(),
        &["--allow-programming", "--allow-writes"],
        &store_path,
    )?;

    let pid61_reads =
        || -> TestResult<usize> { Ok(log.lock().map_err(|_| "log poisoned")?.pid61_reads) };

    // The device already runs the model: both GAs secured.
    let plan = plan_when_connected(&mut server, "1.1.10")?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], true, "plan: {plan}");
    assert_eq!(pid61_reads()?, 1, "the first plan reads PID 61");
    // The read budget (issue #336): no security change pending, so a second
    // plan takes the cached read and does not read PID 61 again.
    let again = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(again["noop"], true, "plan: {again}");
    assert_eq!(again["state_hash"], plan["state_hash"], "plan: {again}");
    assert_eq!(
        pid61_reads()?,
        1,
        "a plan without a pending change reads no PID 61"
    );

    // Security off for 1/2/3: one model change, the key out of the store.
    let set = server.call("knx_set_group", json!({"ga": "1/2/3", "secure": false}))?;
    assert_eq!(set["ok"], true, "set: {set}");
    assert_eq!(set["key_store"]["group_key"], "removed", "set: {set}");
    assert_eq!(
        set["key_store"]["snapshot_keeps_key_store"], true,
        "set: {set}"
    );
    let sentences = set["changes"].to_string();
    assert!(
        sentences.contains("Secured level (1/2/3) now runs plain (KNX Data Secure off)."),
        "set: {set}"
    );
    assert!(
        sentences.contains("Secure actuator (1.1.10): object 22 now runs plain"),
        "set: {set}"
    );
    assert_eq!(
        set["security"]["devices"],
        json!([{"address": "1.1.10", "objects": [22]}]),
        "set: {set}"
    );
    let note = set["note"].as_str().unwrap_or_default();
    assert!(note.contains("Home Assistant"), "{note}");
    assert!(note.contains("bussard keys export"), "{note}");
    let store = bussard_project::KeyStore::load(&dir, PASSWORD)?.ok_or("no key store")?;
    assert!(store.group_key(ga("1/2/3")?).is_none());
    assert!(store.group_key(ga("1/2/4")?).is_some());
    let groups = std::fs::read_to_string(dir.join("groups.toml"))?;
    assert!(
        !groups.contains("\"Secured level\", dpt = \"5.001\", secure"),
        "{groups}"
    );

    // `bussard keys export` leaves the key out (the keyring Home Assistant loads).
    let export = dir.join("ha.knxkeys");
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["--dir"])
        .arg(&dir)
        .args(["keys", "export"])
        .arg(&export)
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let exported = bussard_project::parse_keyring(&std::fs::read_to_string(&export)?, PASSWORD)?;
    assert!(!exported.group_keys.contains_key(&ga("1/2/3")?));
    assert!(exported.group_keys.contains_key(&ga("1/2/4")?));

    // The plan: exactly one change, the security object. The change is
    // pending, so the device is read again.
    let plan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(pid61_reads()?, 2, "a pending security change reads PID 61");
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    let changes = plan["changes"].as_array().ok_or("no changes")?;
    assert_eq!(changes.len(), 1, "plan: {plan}");
    assert_eq!(changes[0]["subject"], "security", "plan: {plan}");
    assert_eq!(changes[0]["mark"], "-", "plan: {plan}");
    assert_eq!(
        changes[0]["sentence"],
        "security object: Data Secure off for 1/2/3 (Secured level): its group key leaves the \
         group key table (PID 53) and object 22 loses its security flag (PID 61 0x03 to 0x00)",
        "plan: {plan}"
    );
    assert_eq!(plan["writes"]["security_object"], true, "plan: {plan}");
    assert!(
        log.lock().map_err(|_| "log poisoned")?.controls.is_empty(),
        "planning must not touch the security object"
    );
    let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;

    let applied = server.call(
        "knx_apply_device",
        json!({"address": "1.1.10", "plan_digest": digest}),
    )?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    {
        let log = log.lock().map_err(|_| "log poisoned")?;
        // A full security-object program, as an ETS download writes it.
        assert_eq!(log.controls, vec![0x04, 0x01, 0x02], "{log:?}");
        let key_table: Vec<_> = log
            .writes
            .iter()
            .filter(|w| w.0 == PID_GRP_KEY_TABLE)
            .collect();
        // The group key table rewritten from element 1 without 1/2/3: one
        // element, address-table index 3 (1/2/4), then its key.
        assert_eq!(key_table.len(), 1, "{log:?}");
        assert_eq!((key_table[0].1, key_table[0].2), (1, 1));
        assert_eq!(key_table[0].3.get(..2), Some(&[0u8, 3][..]));
        assert_eq!(key_table[0].3.get(2..), Some(&[0x33u8; 16][..]));
        // Object 22 is plain now, 23 still secured: the device takes a plain
        // telegram on 1/2/3 from a non-Secure sender.
        let secured: Vec<usize> = log
            .pid61
            .iter()
            .enumerate()
            .filter(|(_, f)| **f != 0)
            .map(|(i, _)| i + 1)
            .collect();
        assert_eq!(secured, vec![23], "{log:?}");
    }

    // Nothing left to do. The apply dropped the cache, so this plan reads
    // the device once; the next one does not.
    let reads = pid61_reads()?;
    let replan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert_eq!(
        pid61_reads()?,
        reads + 1,
        "the plan after an apply reads PID 61"
    );
    let replan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert_eq!(pid61_reads()?, reads + 1, "and caches it");

    // A group write on 1/2/3 now goes out plain.
    let write = server.call("knx_write_group", json!({"ga": "1/2/3", "value": "50%"}))?;
    assert_eq!(write["ok"], true, "write: {write}");
    assert_eq!(write["secured"], false, "write: {write}");

    // One undo restores all three signals, the very key included.
    let undo = server.call("knx_undo", json!({}))?;
    assert_eq!(undo["ok"], true, "undo: {undo}");
    assert_eq!(undo["key_store"]["ok"], true, "undo: {undo}");
    let store = bussard_project::KeyStore::load(&dir, PASSWORD)?.ok_or("no key store")?;
    assert_eq!(store.group_key(ga("1/2/3")?), Some(&group_key()?));
    let groups = std::fs::read_to_string(dir.join("groups.toml"))?;
    assert!(
        groups.contains("dpt = \"5.001\", secure = true"),
        "{groups}"
    );
    // And the device needs the key and the flag back.
    let plan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.contains("+ security object: Data Secure on for 1/2/3 (Secured level)"),
        "plan: {plan}"
    );
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Issue #349: a gateway serving the secured 1.1.10 whose device drops
/// `dropped` (acknowledged, never stored), and the model directory to apply
/// to. `admit` turns `admit_tunnel_senders` on, so PID 54 receives the
/// tunnelling address 1.1.200.
fn dropping_bench(
    rt: &tokio::runtime::Runtime,
    tag: &str,
    dropped: Option<Dropped>,
    admit: bool,
) -> TestResult<(MockGateway, Arc<Mutex<SecurityLog>>, PathBuf)> {
    faulty_bench(
        rt,
        tag,
        SecurityLog {
            dropped,
            ..SecurityLog::default()
        },
        admit,
    )
}

/// [`dropping_bench`] with the device's security object starting from
/// `log` (its faults, issue #534).
fn faulty_bench(
    rt: &tokio::runtime::Runtime,
    tag: &str,
    log: SecurityLog,
    admit: bool,
) -> TestResult<(MockGateway, Arc<Mutex<SecurityLog>>, PathBuf)> {
    let log = Arc::new(Mutex::new(log));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x59)
            .tunnel_address(0x11C8)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device(Arc::clone(&log))?)
            .start(),
    )?;
    let dir = model_dir(tag)?;
    if admit {
        std::fs::write(
            dir.join("bussard.toml"),
            "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n\
             admit_tunnel_senders = true\n",
        )?;
    }
    Ok((gw, log, dir))
}

/// Plans and applies 1.1.10 over `bussard mcp` against a device that drops
/// `dropped`, and returns the apply's result.
fn apply_over_mcp(tag: &str, dropped: Option<Dropped>, admit: bool) -> TestResult<Value> {
    let rt = tokio::runtime::Runtime::new()?;
    let (gw, _log, dir) = dropping_bench(&rt, tag, dropped, admit)?;
    let mut server = Server::start(&dir, gw.port(), &["--allow-programming"])?;
    let plan = plan_when_connected(&mut server, "1.1.10")?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;
    let applied = server.call(
        "knx_apply_device",
        json!({"address": "1.1.10", "plan_digest": digest}),
    )?;
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(applied)
}

/// Runs `bussard apply 1.1.10 --yes --keyring` against a device that drops
/// `dropped`: whether it succeeded, its stdout and its stderr.
fn apply_over_cli(
    tag: &str,
    dropped: Option<Dropped>,
    admit: bool,
) -> TestResult<(bool, String, String)> {
    let rt = tokio::runtime::Runtime::new()?;
    let (gw, _log, dir) = dropping_bench(&rt, tag, dropped, admit)?;
    let run = run_cli_apply(&gw, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    run
}

/// `bussard apply 1.1.10 --yes --keyring` on `dir` against `gw`: whether it
/// succeeded, its stdout and its stderr.
fn run_cli_apply(gw: &MockGateway, dir: &Path) -> TestResult<(bool, String, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .arg("apply")
        .arg("1.1.10")
        .arg("--yes")
        .arg("--dir")
        .arg(dir)
        .arg("--gateway")
        .arg(format!("127.0.0.1:{}", gw.port()))
        .arg("--keyring")
        .arg(keyring_path())
        .stdin(Stdio::null())
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Asserts that an MCP apply did not verify and names `item` among its
/// read-back leftovers.
fn assert_mcp_names(applied: &Value, kind: &str, item: &str) {
    assert_eq!(applied["ok"], false, "apply: {applied}");
    assert_eq!(applied["verified"], false, "apply: {applied}");
    assert_eq!(applied["readback"]["verified"], false, "apply: {applied}");
    let named = applied["readback"]["leftovers"]
        .as_array()
        .is_some_and(|l| {
            l.iter()
                .any(|x| x["kind"] == kind && x["item"].as_str().is_some_and(|i| i.contains(item)))
        });
    assert!(named, "{kind} {item} not named: {applied}");
    let reason = applied["reason"].as_str().unwrap_or_default();
    assert!(reason.contains(item), "the reason names {item}: {applied}");
}

/// Asserts that a CLI apply failed and named `item` on stderr.
fn assert_cli_names(run: &(bool, String, String), item: &str) {
    let (success, stdout, stderr) = run;
    assert!(!success, "the apply must fail: {stdout}\n{stderr}");
    assert!(
        stderr.contains("not verified") && stderr.contains(item),
        "{item} not named: {stdout}\n{stderr}"
    );
}

#[test]
fn test_mcp_apply_readback_names_a_dropped_security_flag() -> TestResult {
    let applied = apply_over_mcp(
        "drop-pid61",
        Some(Dropped::Pid(PID_GO_SECURITY_FLAGS)),
        false,
    )?;
    assert_mcp_names(
        &applied,
        "security_flag",
        "group object 22 security flag (PID 61)",
    );
    Ok(())
}

#[test]
fn test_mcp_apply_readback_names_a_dropped_group_key_table() -> TestResult {
    let applied = apply_over_mcp("drop-pid53", Some(Dropped::Pid(PID_GRP_KEY_TABLE)), false)?;
    assert_mcp_names(&applied, "group_key_table", "group key table (PID 53)");
    Ok(())
}

#[test]
fn test_mcp_apply_readback_names_a_dropped_secure_sender() -> TestResult {
    let applied = apply_over_mcp(
        "drop-pid54",
        Some(Dropped::Pid(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)),
        true,
    )?;
    assert_mcp_names(&applied, "secure_sender", "secure sender 1.1.200 (PID 54)");
    Ok(())
}

#[test]
fn test_mcp_apply_readback_names_a_dropped_link() -> TestResult {
    let applied = apply_over_mcp("drop-link", Some(Dropped::Associations), false)?;
    assert_mcp_names(&applied, "link", "object 22 -> 1/2/3");
    Ok(())
}

#[test]
fn test_mcp_apply_readback_names_a_dropped_parameter() -> TestResult {
    let applied = apply_over_mcp("drop-param", Some(Dropped::Parameters), false)?;
    assert_mcp_names(&applied, "parameter", "thr");
    Ok(())
}

#[test]
fn test_cli_apply_readback_reports_the_counts_when_healthy() -> TestResult {
    let (success, stdout, stderr) = apply_over_cli("cli-healthy", None, true)?;
    assert!(success, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(
            "read back from 1.1.10 and compared with the model: 2 group address(es), 2 \
             association(s)"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "1 group key(s) (PID 53), 1 secure sender(s) (PID 54), 1 secured object(s) (PID 61), \
             security object Loaded (PID 5)"
        ),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_cli_apply_readback_names_a_dropped_security_flag() -> TestResult {
    let run = apply_over_cli(
        "cli-drop-pid61",
        Some(Dropped::Pid(PID_GO_SECURITY_FLAGS)),
        false,
    )?;
    assert_cli_names(&run, "group object 22 security flag (PID 61)");
    Ok(())
}

#[test]
fn test_cli_apply_readback_names_a_dropped_group_key_table() -> TestResult {
    let run = apply_over_cli(
        "cli-drop-pid53",
        Some(Dropped::Pid(PID_GRP_KEY_TABLE)),
        false,
    )?;
    assert_cli_names(&run, "group key table (PID 53)");
    Ok(())
}

#[test]
fn test_cli_apply_readback_names_a_dropped_secure_sender() -> TestResult {
    let run = apply_over_cli(
        "cli-drop-pid54",
        Some(Dropped::Pid(PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE)),
        true,
    )?;
    assert_cli_names(&run, "secure sender 1.1.200 (PID 54)");
    Ok(())
}

#[test]
fn test_cli_apply_readback_names_a_dropped_link() -> TestResult {
    let run = apply_over_cli("cli-drop-link", Some(Dropped::Associations), false)?;
    assert_cli_names(&run, "object 22 -> 1/2/3");
    Ok(())
}

#[test]
fn test_cli_apply_readback_names_a_dropped_parameter() -> TestResult {
    let run = apply_over_cli("cli-drop-param", Some(Dropped::Parameters), false)?;
    assert_cli_names(&run, "thr");
    Ok(())
}

/// `bussard apply 1.1.10 --secure-sender 1.1.30` with tunnel admission on:
/// two PID 54 entries, the tunnel address and 1.1.30.
fn run_cli_apply_two_senders(gw: &MockGateway, dir: &Path) -> TestResult<(bool, String, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .arg("apply")
        .arg("1.1.10")
        .arg("--yes")
        .arg("--secure-sender")
        .arg("1.1.30")
        .arg("--dir")
        .arg(dir)
        .arg("--gateway")
        .arg(format!("127.0.0.1:{}", gw.port()))
        .arg("--keyring")
        .arg(keyring_path())
        .stdin(Stdio::null())
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Issue #537: the device's PID 54 holds one entry (its property
/// description says so) and the apply needs two: refused with the counts
/// before the security object, or any table, is opened.
#[test]
fn test_cli_apply_refuses_a_sender_table_over_the_described_capacity() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let (gw, log, dir) = faulty_bench(
        &rt,
        "cli-capacity-desc",
        SecurityLog {
            pid54_capacity: Some(1),
            ..SecurityLog::default()
        },
        true,
    )?;
    let run = run_cli_apply_two_senders(&gw, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let (success, stdout, stderr) = run?;
    assert!(!success, "the apply must refuse: {stdout}\n{stderr}");
    assert!(
        stderr.contains(
            "the security individual address table (PID 54) needs 2 entries but the device \
             holds at most 1 (property description)"
        ),
        "{stderr}"
    );
    let log = log.lock().map_err(|_| "log poisoned")?;
    assert!(
        log.controls.is_empty(),
        "nothing unloaded: {:?}",
        log.controls
    );
    assert!(log.writes.is_empty(), "nothing written");
    // The address table was never opened (2 = Loading).
    let address_state = gw.with_device(ia("1.1.10")?, |dev| dev.load_state(1))?;
    assert_ne!(address_state, 2);
    Ok(())
}

/// Issue #537: the product declares one PID 54 entry: the apply refuses at
/// plan time, before it contacts the gateway.
#[test]
fn test_cli_apply_refuses_a_sender_table_over_the_product_capacity() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let log = Arc::new(Mutex::new(SecurityLog::default()));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x5A)
            .tunnel_address(0x11C8)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device(Arc::clone(&log))?)
            .start(),
    )?;
    let xml = APP_XML.replacen(
        "<ApplicationProgram ",
        "<ApplicationProgram IsSecureEnabled=\"true\" MaxSecurityIndividualAddressEntries=\"1\" ",
        1,
    );
    let dir = model_dir_with("cli-capacity-product", &xml)?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n\
         admit_tunnel_senders = true\n",
    )?;
    let run = run_cli_apply_two_senders(&gw, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let (success, stdout, stderr) = run?;
    assert!(!success, "the apply must refuse: {stdout}\n{stderr}");
    assert!(
        stderr.contains(
            "the security individual address table (PID 54) needs 2 entries but the device \
             holds at most 1 (product data)"
        ),
        "{stderr}"
    );
    let log = log.lock().map_err(|_| "log poisoned")?;
    assert!(log.controls.is_empty() && log.writes.is_empty());
    Ok(())
}

/// Issue #534: a security object that answers `LoadCompleted` with state
/// Error stops the apply between `Unload` and `LoadCompleted`. The error
/// names the consequence and the remedy, and the lock records no PID 54.
#[test]
fn test_cli_apply_load_completed_error_names_the_dead_secured_addresses() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let (gw, _log, dir) = faulty_bench(
        &rt,
        "cli-complete-error",
        SecurityLog {
            completes_to: Some(0x03),
            ..SecurityLog::default()
        },
        true,
    )?;
    let (success, stdout, stderr) = run_cli_apply(&gw, &dir)?;
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!success, "the apply must fail: {stdout}\n{stderr}");
    assert!(
        stderr.contains("did not reach Loaded after LoadCompleted (device reports Error)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("drops every secured group telegram")
            && stderr.contains("Run `bussard apply 1.1.10` again"),
        "{stderr}"
    );
    assert!(!lock.contains("secure_senders"), "{lock}");
    Ok(())
}

/// Issue #534: a device that confirms `LoadCompleted` but reads back
/// another load state is not verified; the read-back names PID 5.
#[test]
fn test_cli_apply_readback_names_a_security_object_left_unloaded() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let (gw, _log, dir) = faulty_bench(
        &rt,
        "cli-reverts",
        SecurityLog {
            reverts_to: Some(0x00),
            ..SecurityLog::default()
        },
        false,
    )?;
    let run = run_cli_apply(&gw, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let run = run?;
    assert_cli_names(&run, "security object load state (PID 5)");
    assert!(run.2.contains("the device holds Unloaded"), "{}", run.2);
    Ok(())
}

/// Issue #534 over MCP: the same not-Loaded object is a read-back leftover.
#[test]
fn test_mcp_apply_readback_names_a_security_object_left_unloaded() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let (gw, _log, dir) = faulty_bench(
        &rt,
        "mcp-reverts",
        SecurityLog {
            reverts_to: Some(0x03),
            ..SecurityLog::default()
        },
        false,
    )?;
    let mut server = Server::start(&dir, gw.port(), &["--allow-programming"])?;
    let plan = plan_when_connected(&mut server, "1.1.10")?;
    let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;
    let applied = server.call(
        "knx_apply_device",
        json!({"address": "1.1.10", "plan_digest": digest}),
    )?;
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    assert_mcp_names(
        &applied,
        "security_load_state",
        "security object load state (PID 5)",
    );
    Ok(())
}

/// Issue #316: a secured write whose admission the lock and the key store
/// cannot tell reads the receiver's PID 54 first. Listing only an ETS
/// sender, it refuses with the remedy and records the table in the lock;
/// after the apply that admits the tunnel addresses the write is admitted.
#[test]
fn test_mcp_write_reads_pid54_on_an_unknown_admission_then_refuses() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let log = Arc::new(Mutex::new(SecurityLog::default()));
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x58)
            .tunnel_address(0x11C8)
            .keep_serving()
            .idle_timeout(Duration::from_secs(120))
            .device(secure_device_with(
                Arc::clone(&log),
                &["1/2/0", "1/2/3"],
                &[(1, 20), (2, 22)],
                &[12, 0],
                &[22],
            )?)
            .start(),
    )?;
    // PID 54 as ETS left it: one device sender, 1.1.16, not the tunnel.
    log.lock().map_err(|_| "log poisoned")?.pid54 = vec![0x11, 0x10, 0, 0, 0, 0, 0, 0];
    let dir = model_dir("pid54-on-unknown")?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n\
         admit_tunnel_senders = true\n",
    )?;
    // A key store without the ETS group assignment of the tunnelling user, so
    // nothing but the device can tell.
    let mut store = bussard_project::KeyStore::new("Synthetic");
    store.merge_keyring(&keyring()?);
    for interface in &mut store.interfaces {
        interface.gas.clear();
    }
    let stripped = dir.join("stripped.keys");
    std::fs::write(&stripped, store.to_xml(PASSWORD)?)?;
    let mut server = Server::start_with(
        &dir,
        gw.port(),
        &["--allow-programming", "--allow-writes"],
        &stripped,
    )?;
    let plan = plan_when_connected(&mut server, "1.1.10")?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let reads_before = log.lock().map_err(|_| "log poisoned")?.pid54_reads;

    let refused = server.call("knx_write_group", json!({"ga": "1/2/3", "value": "50%"}))?;
    assert_eq!(refused["ok"], false, "write: {refused}");
    assert_eq!(refused["refused"], true, "write: {refused}");
    assert_eq!(refused["admission"], "refused", "write: {refused}");
    let reason = refused["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("1.1.10 does not list the tunnel address 1.1.200"),
        "{refused}"
    );
    let hint = refused["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("admit_tunnel_senders = true"), "{refused}");
    assert!(
        log.lock().map_err(|_| "log poisoned")?.pid54_reads > reads_before,
        "PID 54 is read before the refusal"
    );
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    assert!(
        lock.contains("secure_senders = [\n  { address = \"1.1.16\", sequence = 0 },\n]"),
        "{lock}"
    );

    // Apply the admission change, then the write is admitted.
    let plan = server.call("knx_plan_device", json!({"address": "1.1.10"}))?;
    let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;
    let applied = server.call(
        "knx_apply_device",
        json!({"address": "1.1.10", "plan_digest": digest}),
    )?;
    assert_eq!(applied["verified"], true, "apply: {applied}");
    let mut write = Value::Null;
    for _ in 0..50 {
        write = server.call("knx_write_group", json!({"ga": "1/2/3", "value": "50%"}))?;
        if write["admission"] == "admitted" {
            break;
        }
        // The server's model handle picks the lock change up on its next poll.
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(write["ok"], true, "write: {write}");
    assert_eq!(write["admission"], "admitted", "write: {write}");
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
