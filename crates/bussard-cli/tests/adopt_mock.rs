//! End-to-end tests of `bussard adopt` against an in-process mock KNX gateway.
//!
//! `adopt` is a wizard, so its non-interactive shape is gated: it runs only when
//! BOTH a `--product` file and the documented `BUSSARD_ADOPT_ADDRESS` env hook
//! are supplied (the env var stands in for the address the wizard would prompt
//! for). These tests assemble a tiny fabricated `.knxprod` in a temp dir — the
//! same technique `bussard-prod`'s own tests use — and drive the built binary as
//! a subprocess against a `bussard-testkit` mock gateway hosting one device in programming mode.
//!
//! Cases:
//!   * happy path — device adopted, rich device file with a com-object table;
//!   * order-number mismatch — device reports an order the product doesn't list,
//!     so a loud warning prints but the run still succeeds;
//!   * no-device timeout — nothing in programming mode → clean failure;
//!   * product-less stub path — no `--product` and a non-TTY → refused (the
//!     wizard needs inputs), documenting the gate.

use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};

const CHANNEL: u8 = 0x22;

// ---------------------------------------------------------------------------
// A tiny fabricated .knxprod (fixture XML — no vendor data committed).
// ---------------------------------------------------------------------------

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-0083">
    <Hardware>
      <Products><Product OrderNumber="MDT-BE-04001.02" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-0083_A-1234-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

// Two com-objects: one transmit-capable (a button, #0) and one write-only
// (#1). `adopt` should list the transmit-capable one first. The Dynamic
// section puts both and an enum parameter in one channel, which `adopt` turns
// into the lock's channel handle and keys.
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-0083"><ApplicationPrograms>
  <ApplicationProgram Id="M-0083_A-1234-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Taster BE 04001" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ParameterTypes>
     <ParameterType Id="M-0083_A-1234-11-ABCD-O000A_PT-Mode" Name="Mode">
      <TypeRestriction Base="Value" SizeInBit="8">
       <Enumeration Text="Schalten" Value="0" Id="M-0083_A-1234-11-ABCD-O000A_PT-Mode_EN-0" />
       <Enumeration Text="Dimmen" Value="1" Id="M-0083_A-1234-11-ABCD-O000A_PT-Mode_EN-1" />
      </TypeRestriction>
     </ParameterType>
    </ParameterTypes>
    <Parameters>
     <Parameter Id="M-0083_A-1234-11-ABCD-O000A_P-1" Name="Mode1" Text="Funktion" ParameterType="M-0083_A-1234-11-ABCD-O000A_PT-Mode" Value="0" />
    </Parameters>
    <ParameterRefs>
     <ParameterRef Id="M-0083_A-1234-11-ABCD-O000A_P-1_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_P-1" />
    </ParameterRefs>
    <ComObjectTable>
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-0" Number="0" Text="Taste 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" ReadFlag="Disabled" WriteFlag="Disabled" />
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-1" Number="1" Text="LED 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-1_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-1" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
   <Dynamic>
    <Channel Id="M-0083_A-1234-11-ABCD-O000A_CH-1" Name="Taste" Number="1" Text="Taste 1">
     <ParameterBlock Id="M-0083_A-1234-11-ABCD-O000A_PB-1" Name="General" Text="Allgemein">
      <ParameterRefRef RefId="M-0083_A-1234-11-ABCD-O000A_P-1_R-1" />
      <ComObjectRefRef RefId="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" />
      <ComObjectRefRef RefId="M-0083_A-1234-11-ABCD-O000A_O-1_R-1" />
     </ParameterBlock>
    </Channel>
   </Dynamic>
   <LoadProcedures>
    <LoadProcedure MergeId="1"><LdCtrlConnect /><LdCtrlRestart /></LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn build_knxprod(path: &std::path::Path) -> std::io::Result<()> {
    // A `.knxprod` is a plain ZIP. To keep this test free of a `zip` dev-dep
    // (file-set discipline — only adopt_*.rs is ours to add), we emit a
    // store-mode (uncompressed, method 0) ZIP by hand. Store mode needs only a
    // CRC-32 per entry, so the writer below is a few dozen lines.
    let entries: &[(&str, &[u8])] = &[
        ("knx_master.xml", b"<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML.as_bytes()),
        ("M-0083/M-0083_A-1234-11-ABCD-O000A.xml", APP_XML.as_bytes()),
    ];
    let bytes = zip_store(entries);
    std::fs::write(path, bytes)
}

/// Emits a minimal store-mode (method 0) ZIP archive for the given entries.
fn zip_store(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        offsets.push(offset);
        let crc = crc32(data);
        let name_bytes = name.as_bytes();

        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // signature
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: store
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);
    }

    // Central directory.
    let cd_start = out.len() as u32;
    for ((name, data), offset) in entries.iter().zip(&offsets) {
        let crc = crc32(data);
        let name_bytes = name.as_bytes();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // signature
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: store
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // compressed
        central.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncompressed
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory record.
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // signature
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries on disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // total entries
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// A standard CRC-32 (IEEE 802.3, reflected) over `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Mock device on the `bussard-testkit` gateway.
// ---------------------------------------------------------------------------

/// What the factory device reports about itself.
#[derive(Clone)]
struct Identity {
    mask: u16,
    manufacturer: u16,
    serial: [u8; 6],
    order: Vec<u8>,
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

// ---------------------------------------------------------------------------
// Test harness helpers.
// ---------------------------------------------------------------------------

fn write_model(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    // One existing device on line 1.1 so the explicit 1.1.7 sits on a known line.
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Rollladen Wohnzimmer\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )
}

/// Starts a runtime and the mock gateway on it, with `devices` on the line.
fn start_gateway(devices: Vec<MockDevice>) -> TestResult<(tokio::runtime::Runtime, MockGateway)> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .devices(devices)
            .start(),
    )?;
    Ok((rt, gw))
}

/// A factory device in programming mode at 15.15.255 reporting `order`. It
/// `T_ACK`s every numbered request and answers the reads `adopt` issues; the
/// testkit device answers the programming-mode broadcast and takes the new
/// address (leaving programming mode).
fn factory_device(order: &[u8]) -> TestResult<MockDevice> {
    let identity = Identity {
        mask: 0x07B0,
        manufacturer: 0x0083,
        serial: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        order: order.to_vec(),
    };
    Ok(MockDevice::new(ia("15.15.255")?)
        .with_programming(true)
        .with_hook(move |_, apci, data| {
            Some(match device_response(&identity, apci, data) {
                Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
                None => Reaction::Ack,
            })
        }))
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn adopt_happy_path_writes_rich_device_file() -> TestResult {
    let (_rt, gw) = start_gateway(vec![factory_device(b"MDT-BE-04001.02")?])?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-happy-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--yes",
            "--product",
            knxprod.to_str().ok_or("temp path is not UTF-8")?,
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    let device_file = model_dir.join("devices").join("1.1.7.toml");
    let body = std::fs::read_to_string(&device_file).ok();
    let lock = std::fs::read_to_string(model_dir.join("bussard.lock")).ok();
    let vendor_cached = knxprod_cached(&model_dir);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "adopt should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("adopted 15.15.255 → 1.1.7"),
        "expected the adopted line; stdout:\n{stdout}"
    );
    // No order-number mismatch warning on the happy path.
    assert!(
        !stderr.contains("WARNING:"),
        "no mismatch warning expected; stderr:\n{stderr}"
    );
    // Ready-to-paste snippets are printed: a groups.toml row and a device-file
    // object line (the model itself gains no links).
    assert!(
        stdout.contains("# ---8<--- groups.toml (inside `groups = [ … ]`)")
            && stdout.contains("{ address = \"0/0/1\", name = "),
        "expected a groups.toml snippet; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("# ---8<--- devices/1.1.7.toml") && stdout.contains(".send = \"0/0/1\""),
        "expected a device-file snippet; stdout:\n{stdout}"
    );
    // Flash pointer surfaces for a product-backed adoption.
    assert!(
        stdout.contains("bussard flash 1.1.7"),
        "expected a flash pointer; stdout:\n{stdout}"
    );

    // The device file: address, name and order number; the lock entry: the
    // product identity and the com-object table.
    let body = body.ok_or("device file should exist")?;
    assert!(body.contains("address = \"1.1.7\""), "device body:\n{body}");
    assert!(body.contains("Taster BE 04001"), "device body:\n{body}");
    assert!(
        body.contains("product = \"MDT-BE-04001.02\""),
        "device body:\n{body}"
    );
    assert!(!body.contains("[links]"), "no links wired yet:\n{body}");
    let lock = lock.ok_or("bussard.lock should exist")?;
    assert!(
        lock.contains("application = \"M-0083_A-1234-11-ABCD-O000A\""),
        "expected the pinned application; lock:\n{lock}"
    );
    assert!(lock.contains("objects = ["), "lock:\n{lock}");
    // The two com-objects with their DPTs.
    assert!(
        lock.contains("dpt = \"1.001\""),
        "expected a DPT; lock:\n{lock}"
    );
    // Channel handle and object keys derived from the vendor defaults; the
    // lock lists no parameter, since a fresh device stores no value.
    for line in [
        r#"  { key = "taste-1", id = "CH-1", number = 1, text = "Taste 1" },"#,
        r#"  { number = 0, key = "taste-1", channel = "taste-1", text = "Taste 1", dpt = "1.001""#,
        r#"  { number = 1, key = "led-1", channel = "taste-1", text = "LED 1", dpt = "1.001""#,
    ] {
        assert!(lock.contains(line), "lock lacks {line}; lock:\n{lock}");
    }
    // A fresh device stores no parameter values.
    assert!(!body.contains("[channel."), "device body:\n{body}");
    // The snippet names the object by its key in its channel.
    assert!(
        stdout.contains("[channel.taste-1]") && stdout.contains("taste-1.send = \"0/0/1\""),
        "expected a keyed snippet; stdout:\n{stdout}"
    );
    // The vendor .knxprod is cached under vendor/.
    assert!(
        vendor_cached,
        "expected the vendor file cached under vendor/"
    );
    Ok(())
}

#[test]
fn adopt_warns_on_order_number_mismatch() -> TestResult {
    // The device reports a totally different order number than the product lists.
    let (_rt, gw) = start_gateway(vec![factory_device(b"JUNG-4093TSM")?])?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-mismatch-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--yes",
            "--product",
            knxprod.to_str().ok_or("temp path is not UTF-8")?,
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    // A mismatch is a loud warning, not a failure.
    assert!(
        success,
        "mismatch must not fail the run; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("WARNING") && stderr.contains("JUNG-4093TSM"),
        "expected a loud order-number mismatch warning; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("adopted 15.15.255 → 1.1.7"),
        "still adopts; stdout:\n{stdout}"
    );
    Ok(())
}

#[test]
fn adopt_times_out_with_no_device() -> TestResult {
    // No device in programming mode → clean failure after the (shortened) budget.
    let (_rt, gw) = start_gateway(vec![])?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-timeout-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--yes",
            "--product",
            knxprod.to_str().ok_or("temp path is not UTF-8")?,
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "300")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    drop(gw);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let device_written = model_dir.join("devices").join("1.1.7.toml").exists();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !success,
        "no device in programming mode must fail; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("no device entered programming mode"),
        "expected the timeout guidance; stderr:\n{stderr}"
    );
    assert!(
        !device_written,
        "no device file should be written on timeout"
    );
    Ok(())
}

#[test]
fn adopt_refuses_product_less_non_tty() -> TestResult {
    // No --product and a non-TTY: the wizard needs inputs, so it must refuse.
    let tmp = std::env::temp_dir().join(format!("bussard-adopt-refuse-{}", std::process::id()));
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            "127.0.0.1:1", // never contacted — the gate fails first
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !success,
        "product-less non-TTY adopt must be refused; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("interactive wizard") && stderr.contains("BUSSARD_ADOPT_ADDRESS"),
        "expected the wizard-needs-inputs refusal; stderr:\n{stderr}"
    );
    Ok(())
}

/// Whether the vendor `.knxprod` was cached under `<dir>/vendor/`.
fn knxprod_cached(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir.join("vendor"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().ends_with(".knxprod"))
}

/// Writes a one-entry pointer index serving `order` from `knxprod` over a
/// `file://` URL (size and SHA-256 of the real file), for the download step.
fn stub_index(path: &std::path::Path, order: &str, knxprod: &std::path::Path) -> TestResult {
    use sha2::Digest as _;
    let bytes = std::fs::read(knxprod)?;
    let sha: String = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let index = serde_json::json!({"entries": [{
        "manufacturer": "MDT",
        "manufacturer_id": "M-0083",
        "order_numbers": [order],
        "name": "Taster BE (test fixture)",
        "url": format!("file://{}", knxprod.display()),
        "sha256": sha,
        "size": bytes.len(),
        "filename": "fixture.knxprod",
        "redistributable": false,
    }]});
    std::fs::write(path, serde_json::to_vec_pretty(&index)?)?;
    Ok(())
}

/// Without `--product`, adopt looks the order number the device reports up in
/// the pointer index, downloads the archive (consented by `--yes`), imports it
/// and adopts with it.
#[test]
fn adopt_fetches_the_product_data_for_the_reported_order_number() -> TestResult {
    let (_rt, gw) = start_gateway(vec![factory_device(b"MDT-BE-04001.02")?])?;
    let port = gw.port();

    let tmp = std::env::temp_dir().join(format!("bussard-adopt-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let knxprod = tmp.join("download.knxprod");
    build_knxprod(&knxprod)?;
    let index = tmp.join("index.json");
    stub_index(&index, "MDT-BE-04001.02", &knxprod)?;

    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--yes",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_ADOPT_ADDRESS", "1.1.7")
        .env("BUSSARD_PRODUCT_INDEX", &index)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    drop(gw);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lock = std::fs::read_to_string(model_dir.join("bussard.lock")).unwrap_or_default();
    let cached = model_dir.join("vendor").join("fixture.knxprod").is_file();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("no product data cached for MDT-BE-04001.02; looking it up"),
        "{stdout}"
    );
    assert!(
        stdout.contains("using application M-0083_A-1234-11-ABCD-O000A"),
        "{stdout}"
    );
    assert!(cached, "the download is cached under vendor/");
    assert!(
        lock.contains("application = \"M-0083_A-1234-11-ABCD-O000A\""),
        "lock:\n{lock}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// KNX Data Secure-activated devices (issue #201, tier 1).
// ---------------------------------------------------------------------------

/// The synthetic keyring's made-up password.
const KEYRING_PASSWORD: &str = "synthetic-keyring-pw";

/// The committed SYNTHETIC keyring: tool key for 1.1.10 (sequence 42), group
/// key for 1/2/3.
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

/// A table image: a count word plus 16-bit (or 2 × 16-bit) elements.
fn table_image(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut image = (elements.len() as u16).to_be_bytes().to_vec();
    for e in elements {
        image.extend_from_slice(e);
    }
    image
}

/// A commissioned Data Secure device at `addr` in programming mode, keyed with
/// `key`: object 1 (LED) listens on the keyed 1/2/3, object 0 (button) sends on
/// the plain 1/2/4; its security object flags object 1 (PID 61) and admits the
/// secured sender 1.1.20 at sequence 7 (PID 54).
fn secure_commissioned_device(addr: &str, key: [u8; 16]) -> TestResult<MockDevice> {
    let addresses = table_image(&[
        ga_raw("1/2/3")?.to_be_bytes().to_vec(),
        ga_raw("1/2/4")?.to_be_bytes().to_vec(),
    ]);
    let associations = table_image(&[vec![0, 1, 0, 1], vec![0, 2, 0, 0]]);
    let mut senders = ia("1.1.20")?.raw().to_be_bytes().to_vec();
    senders.extend_from_slice(&[0, 0, 0, 0, 0, 7]);
    Ok(MockDevice::system_b(ia(addr)?)
        .with_programming(true)
        .with_manufacturer(0x0083)
        .with_order_info(b"MDT-BE-04001.02")
        .with_serial([0, 1, 2, 3, 4, 5])
        .with_table(1, &addresses)
        .with_table(2, &associations)
        .with_go_count(2)
        .with_property_ext(17, 61, 1, &[0x03, 0x00])
        .with_property_ext(17, 54, 8, &senders)
        .with_data_secure(key))
}

fn ga_raw(s: &str) -> TestResult<u16> {
    Ok(s.parse::<bussard_model::GroupAddress>()?.raw())
}

/// What one secure adopt run produced.
struct SecureAdopt {
    /// `bussard plan <address>` right after the adopt: exit code and output.
    plan: String,
    /// `bussard validate` on the written model: exit code and output.
    validate: String,
    success: bool,
    stdout: String,
    stderr: String,
    device_file: Option<String>,
    groups: String,
    lock: String,
    secured_requests: usize,
    writes: usize,
    device_address: Option<String>,
}

/// Runs `bussard adopt --yes --product <fixture>` against `device`, with the
/// synthetic keyring as `connection.keyring` and `address` as the scripted
/// target.
fn secure_adopt(tag: &str, device: MockDevice, address: &str) -> TestResult<SecureAdopt> {
    // The gateway keeps serving after adopt disconnects, for the `plan` below.
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .keep_serving()
            .devices(vec![device])
            .start(),
    )?;
    let port = gw.port();
    let tmp = std::env::temp_dir().join(format!("bussard-adopt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let model_dir = tmp.join("knx");
    std::fs::create_dir_all(&model_dir)?;
    let keyring = keyring_path();
    std::fs::write(
        model_dir.join("bussard.toml"),
        format!(
            "[connection]\ntransport = \"tunnel\"\nkeyring = \"{}\"\n",
            keyring.to_str().ok_or("keyring path is not UTF-8")?
        ),
    )?;
    let knxprod = tmp.join("fixture.knxprod");
    build_knxprod(&knxprod)?;
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "adopt",
            "--yes",
            "--product",
            knxprod.to_str().ok_or("temp path is not UTF-8")?,
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_ASSIGN_WAIT_MS", "200")
        .env("BUSSARD_ADOPT_ADDRESS", address)
        .env("BUSSARD_KEYRING_PASSWORD", KEYRING_PASSWORD)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    // `plan` against the same device right after: the model now holds what the
    // device holds.
    let plan = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "plan",
            address,
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
            "--gateway",
            &format!("127.0.0.1:{port}"),
        ])
        .env("BUSSARD_KEYRING_PASSWORD", KEYRING_PASSWORD)
        .stdin(Stdio::null())
        .output()?;
    let plan = format!(
        "exit {:?}\n{}{}",
        plan.status.code(),
        String::from_utf8_lossy(&plan.stdout),
        String::from_utf8_lossy(&plan.stderr)
    );
    let devices = gw.devices()?;
    let dev = devices.first();
    let secured_requests = dev.map(|d| d.secured_requests).unwrap_or(0);
    let writes = dev.map(|d| d.writes).unwrap_or(0);
    let device_address = dev.map(|d| d.address.to_string());
    drop(gw);
    let device_file =
        std::fs::read_to_string(model_dir.join("devices").join(format!("{address}.toml"))).ok();
    let groups = std::fs::read_to_string(model_dir.join("groups.toml")).unwrap_or_default();
    let lock = std::fs::read_to_string(model_dir.join("bussard.lock")).unwrap_or_default();
    // The written model must validate (links against the recorded objects).
    let validate = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args([
            "validate",
            "--dir",
            model_dir.to_str().ok_or("temp path is not UTF-8")?,
        ])
        .stdin(Stdio::null())
        .output()?;
    let validate = format!(
        "exit {:?}\n{}{}",
        validate.status.code(),
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr)
    );
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(SecureAdopt {
        plan,
        validate,
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        device_file,
        groups,
        lock,
        secured_requests,
        writes,
        device_address,
    })
}

/// The keyring lists the device: adopt reads it over A_SecureData, records its
/// links, the Data Secure intent, the secured object and group, and the PID 54
/// sender table, and writes nothing to the device.
#[test]
fn test_adopt_secure_device_reads_everything_over_secure_data() -> TestResult {
    let key = keyring_tool_key()?;
    let run = secure_adopt(
        "secure",
        secure_commissioned_device("1.1.10", key)?,
        "1.1.10",
    )?;
    let out = format!("stdout:\n{}\nstderr:\n{}", run.stdout, run.stderr);
    assert!(run.success, "{out}");
    assert!(
        run.stderr.contains("1.1.10 already has the address 1.1.10; no address write"),
        "{out}"
    );
    assert!(
        run.stdout.contains("verified (secured): mask 0x07b0"),
        "{out}"
    );
    assert!(run.secured_requests > 0, "the reads rode A_SecureData");
    assert_eq!(run.writes, 0, "nothing written to the device");
    assert!(
        run.stdout.contains("secure objects (the device's GO security flags (PID 61)): 1"),
        "{out}"
    );
    assert!(
        run.stdout.contains("secure groups (keyed in the keyring): 1/2/3"),
        "{out}"
    );
    assert!(
        run.stdout.contains("secured senders (PID 54, kept in the lock): 1.1.20 (sequence 7)"),
        "{out}"
    );
    assert!(run.stdout.contains("recorded the 2 link(s)"), "{out}");
    assert!(run.stdout.contains("should report no change"), "{out}");
    assert!(!run.stdout.contains("bussard apply 1.1.10"), "{out}");
    assert!(!run.stdout.contains("bussard flash 1.1.10"), "{out}");

    let body = run.device_file.ok_or("device file")?;
    assert!(body.contains("[security]"), "{body}");
    assert!(body.contains("activated = true"), "{body}");
    assert!(body.contains("secure_commissioning = true"), "{body}");
    assert!(body.contains("\"1/2/3\""), "{body}");
    assert!(body.contains("\"1/2/4\""), "{body}");
    for generated in ["secure_capable", "secure_senders", "sequence_number"] {
        assert!(!body.contains(generated), "{generated} belongs in the lock:\n{body}");
    }
    assert!(
        run.validate.starts_with("exit Some(0)"),
        "the adopted model validates: {}",
        run.validate
    );
    assert!(
        run.plan.starts_with("exit Some(0)")
            && run.plan.contains("1.1.10 matches the model; nothing to write"),
        "plan after adopt: {}",
        run.plan
    );
    let lock = run.lock;
    assert!(lock.contains("secure_capable = true"), "{lock}");
    assert!(lock.contains("sequence_number = 42"), "{lock}");
    assert!(
        lock.contains("secure_senders = [\n  { address = \"1.1.20\", sequence = 7 },\n]"),
        "{lock}"
    );
    assert!(lock.contains("secure = true"), "object 1 secure:\n{lock}");
    let groups = run.groups;
    assert!(
        groups.contains("address = \"1/2/3\"") && groups.contains("secure = true"),
        "{groups}"
    );
    Ok(())
}

/// An activated device the keyring does not list (the house's 1.1.13 case):
/// the unsecured read sees mask FFFF, adopt fails with the "no tool key"
/// message and a re-export hint, and writes no device file.
#[test]
fn test_adopt_activated_device_without_keyring_entry_fails_cleanly() -> TestResult {
    let run = secure_adopt(
        "secure-nokey",
        secure_commissioned_device("1.1.13", [0x24; 16])?,
        "1.1.13",
    )?;
    let out = format!("stdout:\n{}\nstderr:\n{}", run.stdout, run.stderr);
    assert!(!run.success, "{out}");
    assert!(run.stderr.contains("has no tool key for 1.1.13"), "{out}");
    assert!(run.stderr.contains("Re-export the keyring from ETS"), "{out}");
    assert!(run.stderr.contains("No device file was written"), "{out}");
    assert!(run.device_file.is_none(), "no device file");
    assert_eq!(run.writes, 0, "nothing written to the device");
    assert_eq!(run.secured_requests, 0);
    Ok(())
}

/// A keyring-listed device and another target address: refused before any
/// write, the device keeps its address.
#[test]
fn test_adopt_secure_device_refuses_a_new_address() -> TestResult {
    let key = keyring_tool_key()?;
    let run = secure_adopt(
        "secure-move",
        secure_commissioned_device("1.1.10", key)?,
        "1.1.11",
    )?;
    let out = format!("stdout:\n{}\nstderr:\n{}", run.stdout, run.stderr);
    assert!(!run.success, "{out}");
    assert!(run.stderr.contains("never re-addresses it"), "{out}");
    assert!(run.stderr.contains("Nothing was written"), "{out}");
    assert_eq!(run.device_address.as_deref(), Some("1.1.10"));
    assert!(run.device_file.is_none());
    Ok(())
}
