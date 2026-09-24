//! End-to-end test of `bussard assign` against an in-process mock KNX gateway.
//!
//! A `bussard-testkit` mock KNXnet/IP gateway answers the broadcast + connected management
//! protocol for a single device that starts in programming mode at the factory
//! address 15.15.255. The built `bussard` binary is run as a subprocess with an
//! **explicit** target address (so its non-TTY confirmation gate passes), and
//! the test asserts it exits 0, prints the old → new line, and writes a stub
//! device file into the model directory.

use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};

const CHANNEL: u8 = 0x22;

/// What the factory device reports about itself.
#[derive(Clone)]
struct Identity {
    mask: u16,
    manufacturer: u16,
    serial: [u8; 6],
    order: Vec<u8>,
}

/// A factory device in programming mode at 15.15.255. The testkit device
/// answers the broadcast individual-address read while in programming mode and
/// takes the address on a write. With `stay_in_programming` it keeps answering
/// the programming-mode broadcast even after it takes its new address,
/// modelling a KNX Virtual device (which does not clear programming mode) or a
/// stuck programming button.
fn factory_device(stay_in_programming: bool) -> TestResult<MockDevice> {
    let identity = Identity {
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: b"MDT-JAL0410".to_vec(),
    };
    let mut dev = MockDevice::new(ia("15.15.255")?).with_programming(true);
    if stay_in_programming {
        dev = dev.with_stuck_programming();
    }
    Ok(dev.with_hook(move |dev, apci, data| {
        // A property-value WRITE mutates device state (e.g. clearing
        // programming mode via PID_PROGMODE = 0) and is echoed back as a
        // confirming A_PropertyValue_Response.
        let answer = handle_property_write(dev, apci, data)
            .or_else(|| device_response(&identity, apci, data));
        Some(match answer {
            Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
            None => Reaction::Ack,
        })
    }))
}

fn device_response(dev: &Identity, apci_val: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    match apci_val {
        // Authorize (issue #52 finding #1): grant full access (level 0).
        apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
        apci::A_DEVICE_DESCRIPTOR_READ => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            dev.mask.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(data)?;
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => dev.manufacturer.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => dev.serial.to_vec(),
                apci::PID_ORDER_INFO => dev.order.clone(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0u8 } else { 1 };
            let mut resp = vec![
                pv.object_index,
                pv.property_id,
                (count << 4) | ((pv.start >> 8) as u8 & 0x0f),
                (pv.start & 0xff) as u8,
            ];
            resp.extend_from_slice(&value);
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        _ => None,
    }
}

/// Whether a request is the `PID_PROGMODE = 0` write on the device object that
/// clears programming mode, as ETS sends it.
fn is_progmode_clear(apci_val: u16, data: &[u8]) -> bool {
    apci_val == apci::A_PROPERTY_VALUE_WRITE
        && data.len() >= 4
        && data[0] == apci::DEVICE_OBJECT_INDEX
        && data[1] == apci::PID_PROGMODE
        && data.get(4) == Some(&0x00)
}

/// Handles an `A_PropertyValue_Write` against the device state, echoing the
/// stored value back in an `A_PropertyValue_Response` (the KNX confirm form).
/// Returns `None` for any non-write telegram so the caller falls through to the
/// read-only responder. The device leaves programming mode on a
/// `PID_PROGMODE = 0` write (unless it models a stuck one); the test finds the
/// write in the device's request log.
fn handle_property_write(
    dev: &mut MockDevice,
    apci_val: u16,
    data: &[u8],
) -> Option<(u16, Vec<u8>)> {
    if apci_val != apci::A_PROPERTY_VALUE_WRITE || data.len() < 4 {
        return None;
    }
    // De-mirrored A_PropertyValue_Write header: [obj_index, pid, (count<<4)|start_hi, start_lo, value…].
    let object_index = data[0];
    let property_id = data[1];
    let count = (data[2] >> 4) & 0x0f;
    let start = (((data[2] & 0x0f) as u16) << 8) | data[3] as u16;
    let value = data[4..].to_vec();

    if is_progmode_clear(apci_val, data) && !dev.stuck_programming {
        // The device clears programming mode when told to (unless it is
        // modelling a stuck one that ignores the write).
        dev.programming = false;
    }
    // Echo the stored value back as the confirming response.
    let mut resp = vec![
        object_index,
        property_id,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(&value);
    Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
}

/// Starts the mock gateway on `rt` with `device` on its line.
fn start_gateway(rt: &tokio::runtime::Runtime, device: MockDevice) -> TestResult<MockGateway> {
    Ok(rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .device(device)
            .start(),
    )?)
}

fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    // One existing device on line 1.1 so the model has a dominant line and the
    // explicit 1.1.7 sits on a known line.
    std::fs::write(
        dir.join("devices").join("1.1.4-jal.yaml"),
        "address: 1.1.4\nname: Rollladen Wohnzimmer\n",
    )?;
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n",
    )
}

#[test]
fn assign_writes_address_and_stub_file() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;

    // A factory device in programming mode at 15.15.255.
    let gw = start_gateway(&rt, factory_device(false)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-assign-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--yes",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        // Shrink both the poll budgets and the per-poll collection window: the
        // programming-mode device answers instantly, so a 200ms window is ample
        // and avoids the default 1500ms wait.
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null()) // non-TTY: explicit address must be accepted
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    // Read the stub file before cleanup.
    let stub = model_dir
        .join("devices")
        .join("1.1.7-new-device-assign.yaml");
    let stub_body = std::fs::read_to_string(&stub).ok();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "assign should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("assigned 15.15.255 → 1.1.7"),
        "expected old→new line; stdout:\n{stdout}"
    );
    // The device cleared programming mode, so no persistence warning.
    assert!(
        !stderr.contains("still in programming mode"),
        "a device that cleared programming mode must NOT warn; stderr:\n{stderr}"
    );

    let body = stub_body.ok_or("stub device file should exist")?;
    assert!(body.contains("address: 1.1.7"), "stub body:\n{body}");
    assert!(body.contains("New device (assign)"), "stub body:\n{body}");
    // The product block reflects the verified read-back (MDT / order / mask).
    assert!(body.contains("MDT"), "stub body:\n{body}");
    assert!(body.contains("MDT-JAL0410"), "stub body:\n{body}");
    Ok(())
}

#[test]
fn assign_clears_programming_mode_like_ets() -> TestResult {
    // After the address write + verify, bussard must explicitly clear programming
    // mode by writing PID_PROGMODE = 0 on the device object (index 0), exactly as
    // ETS does — not merely rely on the device auto-clearing. This asserts the
    // write reached the device AND that assign reports it.
    let rt = tokio::runtime::Runtime::new()?;

    let gw = start_gateway(&rt, factory_device(false)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-assign-clearprog-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--yes",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let progmode_write_seen = gw
        .devices()?
        .first()
        .ok_or("the device is on the line")?
        .requests
        .iter()
        .any(|(apci_val, data)| is_progmode_clear(*apci_val, data));
    drop(gw);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "assign should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The explicit PID_PROGMODE = 0 write must have reached the device.
    assert!(
        progmode_write_seen,
        "assign must write PID_PROGMODE = 0 to clear programming mode (ETS behaviour); \
         stderr:\n{stderr}"
    );
    // assign reports that it cleared programming mode.
    assert!(
        stderr.contains("cleared programming mode on 1.1.7"),
        "assign should report clearing programming mode; stderr:\n{stderr}"
    );
    // A conformant device that took the explicit clear does NOT trigger the
    // persistence warning.
    assert!(
        !stderr.contains("still in programming mode"),
        "a device that cleared must not warn; stderr:\n{stderr}"
    );
    Ok(())
}

#[test]
fn assign_refuses_implicit_address_without_tty() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = start_gateway(&rt, factory_device(false)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-assign-tty-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    // No explicit address → implicit allocation. Piped stdin (non-TTY) must be
    // refused for safety.
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        // The device is in programming mode and answers instantly; a short
        // collection window keeps the safety-refusal path fast.
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !output.status.success(),
        "implicit allocation without a TTY must fail; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("refusing to assign") || stderr.contains("without a terminal"),
        "expected a safety refusal; stderr:\n{stderr}"
    );
    Ok(())
}

#[test]
fn assign_warns_when_device_stays_in_programming_mode() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;

    // A KNX-Virtual-style device: it takes the new address but keeps answering
    // the programming-mode broadcast (never clears programming mode).
    let gw = start_gateway(&rt, factory_device(true)?)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-assign-progmode-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "assign",
            "1.1.7",
            "--yes",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    // The assignment still succeeds — the warning is advisory, not fatal.
    assert!(
        success,
        "assign should still exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("assigned 15.15.255 → 1.1.7"),
        "expected old→new line; stdout:\n{stdout}"
    );
    // The persistence warning must fire, naming the address and the KNX Virtual
    // guidance.
    assert!(
        stderr.contains("1.1.7 is still in programming mode"),
        "expected a programming-mode persistence warning; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("KNX Virtual"),
        "warning should point at the KNX Virtual GUI toggle; stderr:\n{stderr}"
    );
    Ok(())
}

// --- KNX Data Secure verification (issue #203) ---

/// The synthetic keyring's made-up password.
const KEYRING_PASSWORD: &str = "synthetic-keyring-pw";

/// The committed SYNTHETIC keyring; it lists one device, 1.1.10.
fn keyring_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../knx-sim/examples/secure/synthetic.knxkeys")
}

/// The tool key the synthetic keyring holds for 1.1.10 (never printed).
fn keyring_tool_key() -> TestResult<[u8; 16]> {
    let xml = std::fs::read_to_string(keyring_path())?;
    let keyring = bussard_project::parse_keyring(&xml, KEYRING_PASSWORD)?;
    let key = keyring
        .tool_key(ia("1.1.10")?)
        .ok_or("the synthetic keyring lists no tool key for 1.1.10")?;
    Ok(*key.bytes())
}

/// A Data Secure-activated device in programming mode at `addr`: a plain
/// descriptor read gets mask FFFF.
fn secure_factory_device(addr: &str, key: [u8; 16]) -> TestResult<MockDevice> {
    Ok(MockDevice::new(ia(addr)?)
        .with_programming(true)
        .with_mask(0x07B0)
        .with_manufacturer(0x0083)
        .with_order_info(b"MDT-SECURE")
        .with_data_secure(key))
}

/// What one secure assign run produced.
struct SecureRun {
    success: bool,
    stdout: String,
    stderr: String,
    stub: Option<String>,
    secured_requests: usize,
}

/// Runs `bussard assign <target> <extra…>` against `device`.
fn secure_assign(
    tag: &str,
    device: MockDevice,
    target: &str,
    extra: &[&str],
) -> TestResult<SecureRun> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = start_gateway(&rt, device)?;
    let tmp = std::env::temp_dir().join(format!("bussard-assign-{tag}-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let mut args = vec![
        "assign".to_string(),
        target.to_string(),
        "--yes".to_string(),
        "--dir".to_string(),
        model_dir
            .to_str()
            .ok_or("temp path is not UTF-8")?
            .to_string(),
        "--gateway".to_string(),
        format!("127.0.0.1:{}", gw.port()),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_KEYRING_PASSWORD", KEYRING_PASSWORD)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let secured_requests = gw
        .devices()?
        .first()
        .map(|d| d.secured_requests)
        .unwrap_or(0);
    drop(gw);
    let stub = std::fs::read_to_string(
        model_dir
            .join("devices")
            .join(format!("{target}-new-device-assign.yaml")),
    )
    .ok();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(SecureRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        stub,
        secured_requests,
    })
}

/// The keyring lists the NEW address: the verification rides A_SecureData and
/// reports the real mask.
#[test]
fn test_assign_verifies_secured_with_the_keyring_entry_of_the_new_address() -> TestResult {
    let key = keyring_tool_key()?;
    let keyring = keyring_path();
    let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;
    let run = secure_assign(
        "secure-new",
        secure_factory_device("15.15.255", key)?,
        "1.1.10",
        &["--keyring", keyring],
    )?;
    assert!(
        run.success,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("verified (secured): mask 0x07b0"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(!run.stdout.contains("0xffff"), "stdout:\n{}", run.stdout);
    assert!(run.secured_requests > 0, "the verify rode A_SecureData");
    assert!(!run.stderr.contains("re-export"), "stderr:\n{}", run.stderr);
    let stub = run.stub.ok_or("stub device file")?;
    assert!(stub.contains("MDT-SECURE"), "stub:\n{stub}");
    Ok(())
}

/// The keyring lists only the OLD address: its key verifies, and the operator
/// is told to re-export the keyring.
#[test]
fn test_assign_uses_the_old_address_key_and_asks_for_a_keyring_reexport() -> TestResult {
    let key = keyring_tool_key()?;
    let keyring = keyring_path();
    let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;
    let run = secure_assign(
        "secure-old",
        secure_factory_device("1.1.10", key)?,
        "1.1.11",
        &["--keyring", keyring],
    )?;
    assert!(
        run.success,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("verified (secured): mask 0x07b0"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(
        run.stderr.contains("old address 1.1.10") && run.stderr.contains("Re-export the keyring"),
        "stderr:\n{}",
        run.stderr
    );
    Ok(())
}

/// `--tool-key` verifies an address the keyring does not know yet.
#[test]
fn test_assign_tool_key_verifies_secured() -> TestResult {
    let key = keyring_tool_key()?;
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let run = secure_assign(
        "secure-raw",
        secure_factory_device("15.15.255", key)?,
        "1.1.7",
        &["--tool-key", &hex],
    )?;
    assert!(
        run.success,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("verified (secured): mask 0x07b0"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(run.secured_requests > 0);
    Ok(())
}

/// Without a tool key the device answers mask FFFF: the address is verified,
/// the row is labelled, and the stub records no bogus mask.
#[test]
fn test_assign_without_key_labels_a_secure_device() -> TestResult {
    let run = secure_assign(
        "secure-nokey",
        secure_factory_device("15.15.255", [0x24; 16])?,
        "1.1.7",
        &[],
    )?;
    assert!(
        run.success,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout
            .contains("Data Secure activated (mask hidden), no tool key in the keyring"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(
        !run.stdout.contains("mask 0xffff"),
        "stdout:\n{}",
        run.stdout
    );
    let stub = run.stub.ok_or("stub device file")?;
    assert!(!stub.to_ascii_uppercase().contains("FFFF"), "stub:\n{stub}");
    Ok(())
}

/// A keyring entry for a device that is not activated: the secured read is not
/// answered, the plain one is, and the assignment is verified with a warning.
#[test]
fn test_assign_listed_but_plain_device_falls_back_to_a_plain_verify() -> TestResult {
    let keyring = keyring_path();
    let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;
    let run = secure_assign(
        "secure-stale",
        MockDevice::new(ia("15.15.255")?)
            .with_programming(true)
            .with_mask(0x07B0),
        "1.1.10",
        &["--keyring", keyring],
    )?;
    assert!(
        run.success,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("verified: mask 0x07b0"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(
        run.stderr.contains("answers in the clear"),
        "stderr:\n{}",
        run.stderr
    );
    Ok(())
}
