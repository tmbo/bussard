//! `bussard status <ADDRESS>` and the KNXnet/IP section of `describe` against
//! a mock KNX IP interface (issue #391): the device's KNXnet/IP parameter
//! object is read, printed, stored with the device facts and compared with
//! the device file's `[knxnet]` table. Read-only.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway, MockKnxnet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHANNEL: u8 = 0x23;

/// A scratch model directory with the interface's device file, removed on
/// drop.
struct TempModel(PathBuf);

impl TempModel {
    fn new(name: &str, device_file: &str) -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("knx");
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::write(dir.join("devices").join("1.1.200.toml"), device_file)?;
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

fn interface() -> TestResult<MockDevice> {
    let knxnet = MockKnxnet {
        tunnels: (22..=29)
            .map(|n| format!("1.1.{n}").parse())
            .collect::<Result<Vec<IndividualAddress>, _>>()?,
        friendly_name: "Demohouse Alpha".to_string(),
        ..MockKnxnet::default()
    };
    Ok(MockDevice::new("1.1.200".parse()?)
        .with_mask(0x0021)
        .with_knxnet(&knxnet))
}

/// Runs `bussard <args> --dir <dir> --gateway <mock>` against `device`.
fn run_against(device: MockDevice, dir: &Path, args: &[&str]) -> TestResult<(Output, usize)> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .idle_timeout(Duration::from_secs(30))
            .device(device)
            .start(),
    )?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let dir_s = dir.to_str().ok_or("non-UTF-8 temp dir")?;
    let mut all = args.to_vec();
    all.extend_from_slice(&["--dir", dir_s, "--gateway", &gateway]);
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .env_remove("BUSSARD_KEYRING")
        .args(&all)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let writes = gw.devices()?.first().map(|d| d.writes).unwrap_or_default();
    drop(gw);
    Ok((output, writes))
}

/// `s` with every whitespace run collapsed to one space, so the checks do not
/// depend on the column widths.
fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const DEVICE_FILE: &str = r#"address = "1.1.200"
name = "KNX IP Interface"

[knxnet]
assignment = "dhcp"
friendly_name = "Demohouse Alpha"
tunnels = ["1.1.22", "1.1.23", "1.1.24", "1.1.25", "1.1.26", "1.1.27", "1.1.28", "1.1.30"]
"#;

#[test]
fn test_status_address_prints_the_knxnet_state_and_the_drift() -> TestResult {
    let model = TempModel::new("bussard-status-knxnet", DEVICE_FILE)?;
    let (output, writes) = run_against(interface()?, &model.dir(), &["status", "1.1.200"])?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(writes, 0, "status writes nothing");
    for needle in [
        "Device 1.1.200",
        "mask 0021",
        "KNX IP Interface",
        "IP address     192.0.2.74 (dhcp)",
        "MAC            00:00:5E:00:53:01",
        "friendly name  Demohouse Alpha",
        "tunnels        1.1.22, 1.1.23, 1.1.24, 1.1.25, 1.1.26, 1.1.27, 1.1.28, 1.1.29",
        "state          ok",
        "[knxnet] in devices/1.1.200.toml differs from the device:",
        "tunnels: 1.1.22, 1.1.23, 1.1.24, 1.1.25, 1.1.26, 1.1.27, 1.1.28, 1.1.30 in your project",
        // The supported-device verdict (issue #1093); a loopback gateway
        // never needs the override.
        "not on the supported list (no product data pinned, application unknown)",
    ] {
        assert!(
            squash(&stdout).contains(&squash(needle)),
            "missing {needle:?} in:\n{stdout}"
        );
    }
    let facts = std::fs::read_to_string(model.dir().join(".bussard/facts/1.1.200.toml"))?;
    assert!(facts.contains("[device_facts.knxnet]"), "{facts}");
    assert!(
        facts.contains("current_address = \"192.0.2.74\""),
        "{facts}"
    );
    assert!(facts.contains("mac = \"00:00:5E:00:53:01\""), "{facts}");
    let device_file = std::fs::read_to_string(model.dir().join("devices/1.1.200.toml"))?;
    assert_eq!(device_file, DEVICE_FILE, "status never edits the model");
    Ok(())
}

#[test]
fn test_status_address_json_carries_facts_model_and_drift() -> TestResult {
    let model = TempModel::new("bussard-status-knxnet-json", DEVICE_FILE)?;
    let (output, _) = run_against(interface()?, &model.dir(), &["status", "1.1.200", "--json"])?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["schema"], 2);
    assert_eq!(json["address"], "1.1.200");
    assert_eq!(json["knxnet"]["current_address"], "192.0.2.74");
    assert_eq!(json["knxnet"]["assignment_mode"], "dhcp");
    assert_eq!(json["knxnet"]["tunnels"][7], "1.1.29");
    assert_eq!(json["model_knxnet"]["tunnels"][7], "1.1.30");
    assert_eq!(json["knxnet_drift"].as_array().map(Vec::len), Some(1));
    assert_eq!(json["support"]["status"], "unsupported", "{json}");
    assert_eq!(
        json["support"]["reason"], "no product data pinned, application unknown",
        "{json}"
    );
    assert!(json["support"]["override_needed"].is_null(), "{json}");
    Ok(())
}

#[test]
fn test_status_address_on_a_plain_device_says_it_has_no_knxnet_object() -> TestResult {
    let model = TempModel::new("bussard-status-plain", DEVICE_FILE)?;
    let device = MockDevice::new("1.1.200".parse()?);
    let (output, _) = run_against(device, &model.dir(), &["status", "1.1.200"])?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("no KNXnet/IP parameter object"), "{stdout}");
    Ok(())
}

#[test]
fn test_describe_prints_the_knxnet_section() -> TestResult {
    let model = TempModel::new("bussard-describe-knxnet", DEVICE_FILE)?;
    let (output, writes) = run_against(interface()?, &model.dir(), &["describe", "1.1.200"])?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert_eq!(writes, 0);
    assert!(stdout.contains("KNXnet/IP (object 1, read "), "{stdout}");
    assert!(
        squash(&stdout).contains("IP address 192.0.2.74 (dhcp)"),
        "{stdout}"
    );
    Ok(())
}

/// The live shape of 1.1.200 (issue #391): mask 0021, the object-index walk
/// shows a device object and an address table only, and the KNXnet/IP
/// parameter object answers by object type 11 and instance 1. `status` finds
/// it with the extended-service probe and reads it by type and instance.
#[test]
fn test_status_address_finds_an_object_the_walk_does_not_list() -> TestResult {
    let model = TempModel::new("bussard-status-knxnet-unlisted", DEVICE_FILE)?;
    let knxnet = MockKnxnet {
        tunnels: (22..=29)
            .map(|n| format!("1.1.{n}").parse())
            .collect::<Result<Vec<IndividualAddress>, _>>()?,
        ..MockKnxnet::default()
    };
    let device = MockDevice::new("1.1.200".parse()?)
        .with_mask(0x0021)
        .with_object_types(&[0, 1])
        .with_knxnet_unlisted(&knxnet);
    let (output, writes) = run_against(device, &model.dir(), &["status", "1.1.200"])?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert_eq!(writes, 0);
    for needle in [
        "KNXnet/IP (object type 11, read",
        "IP address 192.0.2.74 (dhcp)",
        "tunnels 1.1.22, 1.1.23, 1.1.24, 1.1.25, 1.1.26, 1.1.27, 1.1.28, 1.1.29",
    ] {
        assert!(
            squash(&stdout).contains(&squash(needle)),
            "missing {needle:?} in:\n{stdout}"
        );
    }
    Ok(())
}

/// A device that `T_ACK`s the extended read and never answers: `status`
/// says it has no KNXnet/IP object and still exits 0.
#[test]
fn test_status_address_on_a_device_silent_to_extended_reads() -> TestResult {
    let model = TempModel::new("bussard-status-silent-ext", DEVICE_FILE)?;
    let device = MockDevice::new("1.1.200".parse()?)
        .with_hook(|_, apci, _| (apci == 0x1CC).then_some(bussard_testkit::Reaction::Ack));
    let (output, _) = run_against(device, &model.dir(), &["status", "1.1.200"])?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("no KNXnet/IP parameter object"), "{stdout}");
    // The absence is a device fact: the next command reusing the facts does
    // not probe again.
    let facts = std::fs::read_to_string(model.dir().join(".bussard/facts/1.1.200.toml"))?;
    assert!(facts.contains("no_knxnet = true"), "{facts}");
    Ok(())
}
