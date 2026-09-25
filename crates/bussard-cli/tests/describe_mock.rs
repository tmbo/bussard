//! End-to-end tests of `bussard describe` against an in-process mock KNX device
//! (same mock-gateway pattern as `reconstruct_mock.rs`).
//!
//! The headline case is issue #155: a KNX Data Secure-activated device answers
//! the plain `A_DeviceDescriptor_Read`, `A_Authorize` and the PID 56 max-APDU
//! read, then refuses the interface-object walk. `describe` must treat that
//! empty walk as a failure (non-zero exit, the `--keyring` hint on stderr, and
//! `"unsecured_management": "refused"` in `--json`), not as a device with no
//! objects.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE, PID_OBJECT_TYPE,
};
use bussard_model::IndividualAddress;
use bussard_testkit::{MockGateway, Reaction};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHANNEL: u8 = 0x22;

/// A scripted System B device.
#[derive(Clone)]
struct MockDevice {
    address: IndividualAddress,
    /// The interface-object types served on `PID_OBJECT_TYPE`. Empty models a
    /// security-activated device that refuses the plain walk: it answers every
    /// `PID_OBJECT_TYPE` read with a zero-element response.
    object_types: Vec<u16>,
    /// The application id the application-program object reports in
    /// `PID_PROGRAM_VERSION`, when it has one.
    program_version: Option<[u8; 5]>,
}

fn property_response(object_index: u8, pid: u8, count: u8, start: u16, data: &[u8]) -> Vec<u8> {
    let mut resp = vec![
        object_index,
        pid,
        (count << 4) | ((start >> 8) as u8 & 0x0f),
        (start & 0xff) as u8,
    ];
    resp.extend_from_slice(data);
    resp
}

fn device_response(dev: &MockDevice, req_apci: u16, data: &[u8]) -> Option<(u16, Vec<u8>)> {
    match req_apci {
        apci::A_AUTHORIZE_REQUEST => Some((apci::A_AUTHORIZE_RESPONSE, vec![0x00])),
        apci::A_DEVICE_DESCRIPTOR_READ if data.is_empty() => Some((
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            0x07B0u16.to_be_bytes().to_vec(),
        )),
        apci::A_PROPERTY_VALUE_READ => {
            let pv = apci::decode_property_value_read(data)?;
            let empty = property_response(pv.object_index, pv.property_id, 0, pv.start, &[]);
            let resp = if pv.object_index == 0 && pv.property_id == apci::PID_MAX_APDU_LENGTH {
                // Answered even by an activated device (the ETS capture in #155).
                property_response(0, pv.property_id, 1, pv.start, &55u16.to_be_bytes())
            } else if pv.property_id == 13
                && dev.object_types.get(usize::from(pv.object_index))
                    == Some(&OT_APPLICATION_PROGRAM)
                && let Some(id) = dev.program_version
            {
                property_response(pv.object_index, pv.property_id, 1, pv.start, &id)
            } else if pv.property_id == PID_OBJECT_TYPE {
                match dev.object_types.get(usize::from(pv.object_index)) {
                    Some(ot) => property_response(
                        pv.object_index,
                        pv.property_id,
                        1,
                        pv.start,
                        &ot.to_be_bytes(),
                    ),
                    None => empty,
                }
            } else {
                empty
            };
            Some((apci::A_PROPERTY_VALUE_RESPONSE, resp))
        }
        apci::A_PROPERTY_DESCRIPTION_READ if !dev.object_types.is_empty() => {
            // Report no property at any index: the walk ends at once.
            let object_index = data.first().copied().unwrap_or(0);
            let index = data.get(2).copied().unwrap_or(0);
            Some((
                apci::A_PROPERTY_DESCRIPTION_RESPONSE,
                vec![object_index, 0, index, 0, 0, 0, 0],
            ))
        }
        _ => None,
    }
}

/// Puts `device` on a testkit gateway line: every numbered request is
/// `T_ACK`ed, then answered when [`device_response`] has an answer.
fn gateway_device(device: MockDevice) -> bussard_testkit::MockDevice {
    bussard_testkit::MockDevice::new(device.address).with_hook(move |_, apci, data| {
        Some(match device_response(&device, apci, data) {
            Some((rapci, rdata)) => Reaction::Answer(rapci, rdata),
            None => Reaction::Ack,
        })
    })
}

/// A scratch model directory, removed on drop.
struct TempModel(PathBuf);

impl TempModel {
    /// Creates `<tmp>/<name>-<pid>/knx` and, when `security` is given (TOML
    /// `key = value` lines), a device 1.1.12 carrying it: `activated` and
    /// `secure_commissioning` in its file's `[security]`, the device facts
    /// (`secure_capable`, `has_fdsk_certificate`, `sequence_number`) in its
    /// `bussard.lock` entry.
    fn new(name: &str, security: Option<&str>) -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let dir = root.join("knx");
        std::fs::create_dir_all(&dir)?;
        if let Some(security) = security {
            let (intent, facts): (Vec<&str>, Vec<&str>) = security
                .lines()
                .filter(|l| !l.trim().is_empty())
                .partition(|l| l.starts_with("activated") || l.starts_with("secure_commissioning"));
            let mut file = "address = \"1.1.12\"\nname = \"Secure module\"\n".to_string();
            if !intent.is_empty() {
                file.push_str(&format!("\n[security]\n{}\n", intent.join("\n")));
            }
            std::fs::create_dir_all(dir.join("devices"))?;
            std::fs::write(dir.join("devices").join("1.1.12.toml"), file)?;
            if !facts.is_empty() {
                std::fs::write(
                    dir.join("bussard.lock"),
                    format!(
                        "version = 2\n\n[[device]]\naddress = \"1.1.12\"\n{}\n",
                        facts.join("\n")
                    ),
                )?;
            }
        }
        Ok(TempModel(root))
    }

    fn dir(&self) -> PathBuf {
        self.0.join("knx")
    }
}

impl Drop for TempModel {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Starts the mock gateway for `device` and runs `bussard describe 1.1.12`.
fn describe_against(device: MockDevice, model_dir: &Path, extra: &[&str]) -> TestResult<Output> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .device(gateway_device(device))
            .start(),
    )?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let dir = model_dir.to_str().ok_or("non-UTF-8 temp dir")?;
    let mut args = vec!["describe", "1.1.12", "--dir", dir, "--gateway", &gateway];
    args.extend_from_slice(extra);
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    drop(gw);
    Ok(output)
}

fn target() -> TestResult<IndividualAddress> {
    Ok("1.1.12".parse()?)
}

#[test]
fn test_describe_refused_plain_walk_fails_with_hint_and_json_field() -> TestResult {
    let model = TempModel::new(
        "bussard-describe-refused",
        Some("secure_capable = true\nhas_fdsk_certificate = true\nsequence_number = 42\n"),
    )?;
    let device = MockDevice {
        address: target()?,
        object_types: Vec::new(),
        program_version: None,
    };
    let output = describe_against(device, &model.dir(), &["--json"])?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a refused walk must exit non-zero; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("refused the interface-object walk") && stderr.contains("--keyring"),
        "stderr must carry the no-key secure hint: {stderr}"
    );

    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["address"], "1.1.12");
    assert_eq!(json["mask"], "07B0");
    assert_eq!(json["unsecured_management"], "refused");
    assert!(
        json.get("objects").is_none(),
        "a refused walk must not report an empty object list: {stdout}"
    );
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|e| e.contains("--keyring"))
    );
    assert_eq!(
        json["secure"],
        serde_json::json!({
            "model": {
                "secure_capable": true,
                "activated": false,
                "has_fdsk_certificate": true,
            },
            "device": {
                "plain_management": "refused",
                "secured_management": "not_attempted",
            },
        }),
        "the secure block splits model from device and drops sequence_number: {stdout}"
    );
    Ok(())
}

#[test]
fn test_describe_refused_plain_walk_without_model_security_still_fails() -> TestResult {
    let model = TempModel::new("bussard-describe-refused-nomodel", None)?;
    let device = MockDevice {
        address: target()?,
        object_types: Vec::new(),
        program_version: None,
    };
    let output = describe_against(device, &model.dir(), &[])?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("--keyring"), "stderr: {stderr}");
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains("plain management refused"),
        "text output names the refusal: {stdout}"
    );
    assert!(
        !stdout.contains("no interface objects discoverable"),
        "a refusal is not an empty device: {stdout}"
    );
    Ok(())
}

#[test]
fn test_describe_answering_device_succeeds_without_secure_block() -> TestResult {
    let model = TempModel::new("bussard-describe-plain", None)?;
    let device = MockDevice {
        address: target()?,
        object_types: vec![OT_DEVICE, OT_ADDRESS_TABLE],
        program_version: None,
    };
    let output = describe_against(device, &model.dir(), &["--json"])?;
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    let objects = json["objects"]
        .as_array()
        .ok_or("objects must be an array")?;
    assert_eq!(objects.len(), 2, "{stdout}");
    assert!(json.get("secure").is_none(), "{stdout}");
    assert!(json.get("unsecured_management").is_none(), "{stdout}");
    assert!(json.get("error").is_none(), "{stdout}");
    Ok(())
}

#[test]
fn test_describe_answering_secure_capable_device_reports_answered() -> TestResult {
    let model = TempModel::new("bussard-describe-capable", Some("secure_capable = true\n"))?;
    let device = MockDevice {
        address: target()?,
        object_types: vec![OT_DEVICE],
        program_version: None,
    };
    let output = describe_against(device, &model.dir(), &["--json"])?;
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(
        json["secure"]["device"],
        serde_json::json!({
            "plain_management": "answered",
            "secured_management": "not_attempted",
        }),
        "{stdout}"
    );
    assert_eq!(json["secure"]["model"]["secure_capable"], true);
    assert!(json["secure"].get("sequence_number").is_none());
    Ok(())
}

/// A model whose lock pins application `M-0004_A-D141-22-151B` (id
/// `0004D14122`) and mask `07B0` for 1.1.12 (lock v2, issue #228).
fn pinned_model(name: &str) -> std::io::Result<TempModel> {
    let model = TempModel::new(name, None)?;
    let dir = model.dir();
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices/1.1.12.toml"),
        "address = \"1.1.12\"\nname = \"Aktor\"\nproduct = \"X-1\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        "version = 2\n\n[[device]]\naddress = \"1.1.12\"\nproduct = \"X-1\"\n\
         application = \"M-0004_A-D141-22-151B\"\nmask = \"07B0\"\n",
    )?;
    Ok(model)
}

fn application_device(program_version: [u8; 5]) -> TestResult<MockDevice> {
    Ok(MockDevice {
        address: target()?,
        object_types: vec![
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_APPLICATION_PROGRAM,
        ],
        program_version: Some(program_version),
    })
}

#[test]
fn test_describe_identity_matches_the_lock() -> TestResult {
    let model = pinned_model("bussard-describe-identity-match")?;
    let device = application_device([0x00, 0x04, 0xD1, 0x41, 0x22])?;
    let output = describe_against(device, &model.dir(), &["--json"])?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json["identity"]["verdict"], "match", "{json}");
    assert_eq!(json["identity"]["device"]["application_id"], "0004D14122");
    assert_eq!(json["identity"]["lock"]["application_id"], "0004D14122");
    Ok(())
}

#[test]
fn test_describe_identity_reports_drift_without_refusing() -> TestResult {
    let model = pinned_model("bussard-describe-identity-drift")?;
    let device = application_device([0x00, 0x04, 0xD1, 0x41, 0x23])?;
    let output = describe_against(device, &model.dir(), &[])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "describe is read-only: {stdout}");
    assert!(
        stdout.contains("identity of 1.1.12: drift from bussard.lock")
            && stdout.contains("0004D14123")
            && stdout.contains("0004D14122"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn test_describe_identity_unmodelled_device() -> TestResult {
    let model = TempModel::new("bussard-describe-identity-none", None)?;
    let device = application_device([0x00, 0x04, 0xD1, 0x41, 0x22])?;
    let output = describe_against(device, &model.dir(), &["--json"])?;
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json["identity"]["verdict"], "unmodelled", "{json}");
    Ok(())
}
