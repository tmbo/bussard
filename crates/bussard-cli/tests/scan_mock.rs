//! End-to-end test of `bussard scan` against an in-process mock KNX line.
//!
//! A mock KNXnet/IP gateway (`bussard-testkit`) answers the management protocol
//! for three present devices among otherwise-absent addresses on line `1.1`. The
//! built `bussard` binary is run as a subprocess with `--gateway
//! 127.0.0.1:PORT --json`, and its JSON output is asserted for device content
//! and the model cross-reference (one device present on the bus but missing
//! from the model, one model device that did not respond).

use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};

const CHANNEL: u8 = 0x21;

#[derive(Clone)]
struct Device {
    mask: u16,
    manufacturer: u16,
    serial: Vec<u8>,
    order: Vec<u8>,
}

/// A device on the mock line: it `T_ACK`s every numbered request and answers
/// the management reads a scan issues.
fn device(addr: &str, mask: u16, manufacturer: u16, order: &[u8]) -> TestResult<MockDevice> {
    let dev = Device {
        mask,
        manufacturer,
        serial: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        order: order.to_vec(),
    };
    Ok(MockDevice::new(ia(addr)?).with_hook(move |_, apci, data| {
        Some(match device_response(&dev, apci, data) {
            Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
            None => Reaction::Ack,
        })
    }))
}

fn device_response(dev: &Device, apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    match apci {
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
                apci::PID_SERIAL_NUMBER => dev.serial.clone(),
                apci::PID_ORDER_INFO => dev.order.clone(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0 } else { 1 };
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

/// Starts the mock gateway on `rt` with `devices` on its line.
fn start_gateway(
    rt: &tokio::runtime::Runtime,
    devices: Vec<MockDevice>,
) -> TestResult<MockGateway> {
    Ok(rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .devices(devices)
            .start(),
    )?)
}

fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    // Model knows 1.1.4 and 1.1.6; 1.1.6 will NOT respond (missing from bus),
    // and 1.1.7 responds but is NOT in the model. Kept in a tight device-number
    // cluster so the test can restrict the sweep to `--from 1 --to 8`.
    std::fs::write(
        dir.join("devices").join("1.1.4-jal.yaml"),
        "address: 1.1.4\nname: Rollladen Wohnzimmer\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.6-dimmer.yaml"),
        "address: 1.1.6\nname: Dimmer Flur\n",
    )
}

#[test]
fn scan_reports_devices_and_model_delta() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    // Three present devices among absent addresses, all inside 1..=8 so the
    // sweep can be restricted to a handful of addresses.
    let devices = vec![
        device("1.1.4", 0x07B0, 0x0083, b"MDT-JAL0410")?, // MDT, System B, known
        device("1.1.7", 0x0705, 0x0004, b"2118REGHE")?,   // Jung, System 7, not in model
        device("1.1.8", 0x0012, 0x0002, b"6197/15")?,     // ABB, System 1, not in model
    ];
    let gw = start_gateway(&rt, devices)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-scan-test-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "scan",
            "1.1",
            "--from",
            "1",
            "--to",
            "8",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
            "--json",
        ])
        // Keep the few absent-address probes fast; combined with the 1..=8 range
        // restriction the whole mock sweep finishes in well under a second.
        .env("BUSSARD_SCAN_DISCOVERY_MS", "40")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        output.status.success(),
        "scan should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("scan --json must emit valid JSON: {e}\n{stdout}"))?;

    let found = json["found"].as_array().ok_or("found array")?;
    assert_eq!(found.len(), 3, "three devices should respond: {stdout}");

    // Find 1.1.4 and check its decoded fields.
    let d4 = found
        .iter()
        .find(|d| d["address"] == "1.1.4")
        .ok_or("1.1.4 present")?;
    assert_eq!(d4["mask"], "07B0");
    assert_eq!(d4["system_type"], "System B");
    assert_eq!(d4["manufacturer"], "MDT");
    assert_eq!(d4["order"], "MDT-JAL0410");
    assert_eq!(d4["model_status"], "known");

    // 1.1.7 responds but is not in the model.
    let d7 = found
        .iter()
        .find(|d| d["address"] == "1.1.7")
        .ok_or("1.1.7 present")?;
    assert_eq!(d7["manufacturer"], "Jung");
    assert_eq!(d7["system_type"], "System 7");
    assert_eq!(d7["model_status"], "not_in_model");

    // 1.1.8 → ABB, System 1.
    let d8 = found
        .iter()
        .find(|d| d["address"] == "1.1.8")
        .ok_or("1.1.8 present")?;
    assert_eq!(d8["manufacturer"], "ABB");
    assert_eq!(d8["system_type"], "System 1");

    // Cross-reference deltas.
    let not_in_model: Vec<&str> = json["not_in_model"]
        .as_array()
        .ok_or("not_in_model array")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(not_in_model.contains(&"1.1.7"));
    assert!(not_in_model.contains(&"1.1.8"));

    let missing: Vec<&str> = json["missing_from_bus"]
        .as_array()
        .ok_or("missing_from_bus array")?
        .iter()
        .map(|v| v["address"].as_str().ok_or("address string"))
        .collect::<Result<_, _>>()?;
    assert_eq!(missing, vec!["1.1.6"], "1.1.6 is in the model but silent");
    Ok(())
}

/// The pre-flight source-address check: the mock hands out tunnel address
/// `1.1.255` in its CONNECT_RESPONSE *and* answers management traffic there, so
/// a real device sits exactly where bussard would speak from. Sharing a source
/// address with a live device interleaves two management sessions inside one
/// layer-4 connection at the device, so the command must refuse.
#[test]
fn scan_refuses_when_a_device_answers_at_our_source_address() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    // 1.1.255 is the tunnel address the testkit gateway assigns in its
    // CONNECT_RESPONSE: here it is also a live device.
    let devices = vec![
        device("1.1.4", 0x07B0, 0x0083, b"MDT-JAL0410")?,
        device("1.1.255", 0x07B0, 0x0083, b"MDT-JAL0410")?,
    ];
    let gw = start_gateway(&rt, devices)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-scan-dup-ia-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "scan",
            "1.1",
            "--from",
            "1",
            "--to",
            "8",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
            "--json",
        ])
        .env("BUSSARD_SCAN_DISCOVERY_MS", "40")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "scan must refuse to run; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("already answers at 1.1.255"),
        "the refusal must name the shared address; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--skip-address-check"),
        "the refusal must name the escape hatch; stderr:\n{stderr}"
    );
    Ok(())
}

/// `--skip-address-check` is the escape hatch for a gateway that misbehaves on
/// the probe: the same colliding bus still scans.
#[test]
fn scan_with_skip_address_check_runs_despite_a_shared_source_address() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let devices = vec![
        device("1.1.4", 0x07B0, 0x0083, b"MDT-JAL0410")?,
        device("1.1.255", 0x07B0, 0x0083, b"MDT-JAL0410")?,
    ];
    let gw = start_gateway(&rt, devices)?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-scan-skip-ia-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "scan",
            "1.1",
            "--from",
            "1",
            "--to",
            "8",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
            "--skip-address-check",
            "--json",
        ])
        .env("BUSSARD_SCAN_DISCOVERY_MS", "40")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "--skip-address-check must let the scan run; stderr:\n{stderr}"
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("scan --json must emit valid JSON: {e}\n{stdout}"))?;
    let found = json["found"].as_array().ok_or("found array")?;
    assert!(
        found.iter().any(|d| d["address"] == "1.1.4"),
        "the sweep still reports the devices it saw: {stdout}"
    );
    Ok(())
}

// --- KNX Data Secure identity reads (issue #203) ---

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

/// A Data Secure-activated device: plain descriptor reads get mask FFFF.
fn secure_device(addr: &str, key: [u8; 16]) -> TestResult<MockDevice> {
    Ok(MockDevice::new(ia(addr)?)
        .with_mask(0x07B0)
        .with_manufacturer(0x0083)
        .with_order_info(b"MDT-SECURE")
        .with_data_secure(key))
}

/// Runs a scan of 1.1.1–12 against `port`, with `extra` arguments.
fn run_scan(
    port: u16,
    model_dir: &std::path::Path,
    extra: &[&str],
) -> TestResult<std::process::Output> {
    let mut args = vec![
        "scan".to_string(),
        "1.1".to_string(),
        "--from".to_string(),
        "1".to_string(),
        "--to".to_string(),
        "12".to_string(),
        "--dir".to_string(),
        model_dir
            .to_str()
            .ok_or("temp path is not UTF-8")?
            .to_string(),
        "--gateway".to_string(),
        format!("127.0.0.1:{port}"),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        .env("BUSSARD_SCAN_DISCOVERY_MS", "60")
        .env("BUSSARD_KEYRING_PASSWORD", KEYRING_PASSWORD)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

/// The requests the plain device 1.1.4 saw.
fn plain_requests(gw: &MockGateway) -> TestResult<Vec<(u16, Vec<u8>)>> {
    Ok(gw
        .devices()?
        .into_iter()
        .find(|d| d.address.to_string() == "1.1.4")
        .map(|d| d.requests)
        .ok_or("1.1.4 is on the line")?)
}

/// A keyring-listed activated device is read over A_SecureData and shows its
/// real mask; an activated device the keyring does not list is labelled; a
/// plain device sees exactly the frames it saw before (issue #203).
#[test]
fn test_scan_secure_devices_are_read_secured_or_labelled() -> TestResult {
    let rt = tokio::runtime::Runtime::new()?;
    let key = keyring_tool_key()?;
    // 1.1.12's key is not in the keyring (a synthetic stand-in).
    let other_key = [0x24u8; 16];
    let lines = || -> TestResult<Vec<MockDevice>> {
        Ok(vec![
            device("1.1.4", 0x07B0, 0x0083, b"MDT-JAL0410")?,
            secure_device("1.1.10", key)?,
            secure_device("1.1.12", other_key)?,
        ])
    };
    let tmp = std::env::temp_dir().join(format!("bussard-scan-secure-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let keyring = keyring_path();
    let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;

    // With the keyring, JSON.
    let gw = start_gateway(&rt, lines()?)?;
    let output = run_scan(gw.port(), &model_dir, &["--keyring", keyring, "--json"])?;
    let with_keyring = plain_requests(&gw)?;
    let secure_devices = gw.devices()?;
    drop(gw);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "scan should exit 0; stderr:\n{stderr}"
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("scan --json must emit valid JSON: {e}\n{stdout}"))?;
    let found = json["found"].as_array().ok_or("found array")?;
    let row = |addr: &str| {
        found
            .iter()
            .find(|d| d["address"] == addr)
            .ok_or(format!("{addr} present: {stdout}"))
    };
    let d10 = row("1.1.10")?;
    assert_eq!(
        d10["mask"], "07B0",
        "the secured read shows the real mask: {stdout}"
    );
    assert_eq!(d10["secure"], "activated");
    assert_eq!(d10["manufacturer"], "MDT");
    assert_eq!(d10["order"], "MDT-SECURE");
    let d12 = row("1.1.12")?;
    assert_eq!(d12["mask"], "FFFF");
    assert_eq!(d12["secure"], "activated_no_key");
    let d4 = row("1.1.4")?;
    assert!(
        d4.get("secure").is_none(),
        "a plain row is unchanged: {stdout}"
    );
    assert_eq!(d4["mask"], "07B0");
    let dev10 = secure_devices
        .iter()
        .find(|d| d.address.to_string() == "1.1.10")
        .ok_or("1.1.10 on the line")?;
    assert!(
        dev10.secured_requests > 0,
        "1.1.10 was read over A_SecureData"
    );
    assert_eq!(
        dev10.plain_refused, 0,
        "no plain read reached the listed device"
    );
    let dev12 = secure_devices
        .iter()
        .find(|d| d.address.to_string() == "1.1.12")
        .ok_or("1.1.12 on the line")?;
    assert_eq!(
        dev12.plain_refused, 0,
        "after the FFFF descriptor the probe sends no refused plain reads"
    );

    // Without the keyring, text: the plain device's frames are identical and
    // both activated devices are labelled.
    let gw = start_gateway(&rt, lines()?)?;
    let output = run_scan(gw.port(), &model_dir, &[])?;
    let without_keyring = plain_requests(&gw)?;
    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert_eq!(
        with_keyring, without_keyring,
        "the plain device sees byte-identical requests with and without a keyring"
    );
    let labelled = text
        .lines()
        .filter(|l| l.contains("Data Secure activated (mask hidden), no tool key in the keyring"))
        .count();
    assert_eq!(labelled, 2, "both activated devices are labelled:\n{text}");
    Ok(())
}
