//! `bussard mcp` with a KNX Data Secure keyring against a mock gateway
//! (issue #205), driven over real stdio JSON-RPC:
//!
//! - `knx_plan_device` / `knx_apply_device` on a device the keyring lists:
//!   the tables are read and written over `A_SecureData`, and the security
//!   object is reprogrammed next to them (group key table PID 53, security
//!   individual address table PID 54, group-object flags PID 61, between the
//!   security load-state transitions), as `bussard apply --keyring` does.
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
    A_FUNCTION_PROPERTY_EXT_COMMAND, A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE,
    A_PROPERTY_EXT_VALUE_READ, A_PROPERTY_EXT_VALUE_RESPONSE, A_PROPERTY_EXT_VALUE_WRITE_CON,
    A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE, OT_SECURITY, PID_GO_SECURITY_FLAGS, PID_GRP_KEY_TABLE,
    PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, PID_SECURITY_LOAD_STATE_CONTROL,
};
use bussard_model::GroupAddress;
use bussard_secure::{Key16, SecurityAlgorithm, Sequence, encode_group};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ga, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, GroupData, MessageCode};
use serde_json::{Value, json};

/// The synthetic keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// The group-object count the mock's security object reports.
const GO_COUNT: u16 = 60;

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
         [links]\n20.send = \"1/2/0\"\n22.listen = [\"1/2/3\"]\n",
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
    let mut address_table = 1u16.to_be_bytes().to_vec();
    address_table.extend_from_slice(&ga("1/2/0")?.raw().to_be_bytes());
    let mut association_table = 1u16.to_be_bytes().to_vec();
    association_table.extend_from_slice(&[0, 1, 0, 20]);
    Ok(MockDevice::system_b(ia("1.1.10")?)
        .with_table(1, &address_table)
        .with_table(2, &association_table)
        .with_go_count(GO_COUNT)
        .with_data_secure(tool_key()?)
        .with_hook(move |_, apci, data| {
            let (object_type, pid) = ext_header(data)?;
            if object_type != OT_SECURITY {
                return None;
            }
            let header = data.get(..5)?.to_vec();
            match apci {
                A_FUNCTION_PROPERTY_EXT_COMMAND if pid == PID_SECURITY_LOAD_STATE_CONTROL => {
                    let event = *data.get(5)?;
                    let state = match event {
                        0x04 => 0x00, // Unload -> Unloaded
                        0x01 => 0x02, // StartLoading -> Loading
                        _ => 0x01,    // LoadCompleted -> Loaded
                    };
                    if let Ok(mut log) = log.lock() {
                        log.controls.push(event);
                    }
                    let mut out = header;
                    out.extend_from_slice(&[0x00, state]);
                    Some(Reaction::Answer(
                        A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE,
                        out,
                    ))
                }
                A_PROPERTY_EXT_VALUE_READ if pid == PID_GO_SECURITY_FLAGS => {
                    // Only the element count (start 0) is asked for.
                    let mut out = header;
                    out.extend_from_slice(&[1, 0, 0]);
                    out.extend_from_slice(&GO_COUNT.to_be_bytes());
                    Some(Reaction::Answer(A_PROPERTY_EXT_VALUE_RESPONSE, out))
                }
                A_PROPERTY_EXT_VALUE_WRITE_CON => {
                    let count = *data.get(5)?;
                    let start = u16::from_be_bytes([*data.get(6)?, *data.get(7)?]);
                    if let Ok(mut log) = log.lock() {
                        log.writes
                            .push((pid, count, start, data.get(8..).unwrap_or(&[]).to_vec()));
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
            .arg("mcp")
            .arg("--dir")
            .arg(dir)
            .arg("--gateway")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--keyring")
            .arg(keyring_path())
            .arg("--no-model-edits")
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
