//! `bussard plan` and `bussard apply` of a KNX IP interface against a mock
//! interface that takes writes (issue #391, sub-task b): the device file's
//! `[knxnet]` table becomes property writes on the KNXnet/IP parameter
//! object, read back after the write, and a plan after the apply is a no-op.
//! A change to the interface the command tunnels through is refused unless
//! `--allow-self-reconfigure`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway, MockKnxnet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHANNEL: u8 = 0x24;

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

/// The mock interface: DHCP, eight tunnels, "Demohouse Alpha", at `ip`.
fn interface(ip: [u8; 4]) -> TestResult<MockDevice> {
    let knxnet = MockKnxnet {
        tunnels: (22..=29)
            .map(|n| format!("1.1.{n}").parse())
            .collect::<Result<Vec<IndividualAddress>, _>>()?,
        friendly_name: "Demohouse Alpha".to_string(),
        current: [ip, [255, 255, 255, 0], [192, 168, 1, 1]],
        ..MockKnxnet::default()
    };
    Ok(MockDevice::new("1.1.200".parse()?)
        .with_mask(0x0021)
        .with_knxnet_writable(&knxnet, 8))
}

/// One mock gateway for several commands.
struct Bench {
    rt: tokio::runtime::Runtime,
    gw: Option<MockGateway>,
    gateway: String,
}

impl Bench {
    fn start(device: MockDevice) -> TestResult<Bench> {
        Bench::start_with(device, |builder| builder)
    }

    /// [`start`](Self::start) with the gateway builder adjusted by `adjust`.
    fn start_with(
        device: MockDevice,
        adjust: impl FnOnce(bussard_testkit::GatewayBuilder) -> bussard_testkit::GatewayBuilder,
    ) -> TestResult<Bench> {
        let rt = tokio::runtime::Runtime::new()?;
        let gw = rt.block_on(
            adjust(
                MockGateway::builder()
                    .channel(CHANNEL)
                    .keep_serving()
                    .idle_timeout(Duration::from_secs(30))
                    .device(device),
            )
            .start(),
        )?;
        let gateway = format!("127.0.0.1:{}", gw.port());
        Ok(Bench {
            rt,
            gw: Some(gw),
            gateway,
        })
    }

    /// Runs `bussard <args> --dir <dir> --gateway <mock>`.
    fn run(&self, dir: &Path, args: &[&str]) -> TestResult<Output> {
        let dir_s = dir.to_str().ok_or("non-UTF-8 temp dir")?;
        let mut all = args.to_vec();
        all.extend_from_slice(&["--dir", dir_s, "--gateway", &self.gateway]);
        Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .env("BUSSARD_NO_DOTENV", "1")
            .env_remove("BUSSARD_KEYRING")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .args(&all)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?)
    }

    fn stats(&self) -> TestResult<bussard_testkit::GatewayStats> {
        Ok(self.gw.as_ref().ok_or("gateway stopped")?.stats())
    }

    fn device(&self) -> TestResult<MockDevice> {
        let gw = self.gw.as_ref().ok_or("gateway stopped")?;
        Ok(gw.devices()?.into_iter().next().ok_or("no device")?)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let gw = self.gw.take();
        let _guard = self.rt.enter();
        drop(gw);
    }
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const CHANGED: &str = r#"address = "1.1.200"
name = "KNX IP Interface"

[knxnet]
assignment = "dhcp"
friendly_name = "Demohouse Beta"
tunnels = ["1.1.22", "1.1.23", "1.1.24", "1.1.25", "1.1.26", "1.1.27", "1.1.28", "1.1.30"]
"#;

#[test]
fn test_interface_plan_apply_then_plan_is_a_noop() -> TestResult {
    let model = TempModel::new("bussard-interface-apply", CHANGED)?;
    let bench = Bench::start(interface([192, 0, 2, 74])?)?;

    let plan = bench.run(&model.dir(), &["plan", "1.1.200", "-v"])?;
    let (stdout, stderr) = text(&plan);
    assert!(plan.status.success(), "{stdout}\n{stderr}");
    for needle in [
        "~ friendly name = \"Demohouse Beta\", was \"Demohouse Alpha\"",
        "+ tunnel address 1.1.30 added",
        "- tunnel address 1.1.29 removed",
        "writes: KNXnet/IP parameter object (PID 76, PID 53)",
        "write: object type 11 instance 1 PID 53 start 1 count 8:",
        "> bussard apply 1.1.200",
    ] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
    assert_eq!(bench.device()?.writes, 0, "plan writes nothing");

    let apply = bench.run(&model.dir(), &["apply", "1.1.200", "--yes"])?;
    let (stdout, stderr) = text(&apply);
    assert!(apply.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("apply verified: 2 properties written"),
        "{stdout}"
    );
    assert!(stdout.contains("backup written to"), "{stdout}");
    let device = bench.device()?;
    let name = device.knxnet_property(76).ok_or("PID 76")?;
    assert_eq!(&name[..14], b"Demohouse Beta");
    assert_eq!(
        device.knxnet_property(53).and_then(|t| t.get(14..16)),
        Some(&[0x11, 0x1E][..])
    );
    let backups: Vec<_> = std::fs::read_dir(model.dir().join("captures/backups"))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        backups.iter().any(|b| b.starts_with("1.1.200-knxnet-")),
        "{backups:?}"
    );

    let again = bench.run(&model.dir(), &["plan", "1.1.200", "--json"])?;
    let (stdout, stderr) = text(&again);
    assert!(again.status.success(), "{stdout}\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["noop"], true, "{stdout}");
    assert_eq!(json["changes"].as_array().map(Vec::len), Some(0));
    Ok(())
}

#[test]
fn test_interface_apply_refuses_a_stale_plan_hash() -> TestResult {
    let model = TempModel::new("bussard-interface-hash", CHANGED)?;
    let bench = Bench::start(interface([192, 0, 2, 74])?)?;
    let apply = bench.run(
        &model.dir(),
        &["apply", "1.1.200", "--yes", "--plan", "0000000000000000"],
    )?;
    let (stdout, stderr) = text(&apply);
    assert!(!apply.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("no longer matches the plan"), "{stderr}");
    assert_eq!(bench.device()?.writes, 0);
    Ok(())
}

/// An apply of the KNXnet/IP parameter object is a device write like any
/// other (issue #1093): on a non-loopback gateway an interface whose
/// application is not on the supported list is refused before any socket
/// opens (the gateway is TEST-NET-1, `192.0.2.1`, which is never contacted).
#[test]
fn test_interface_apply_refuses_an_unsupported_interface_on_a_real_gateway() -> TestResult {
    let model = TempModel::new("bussard-interface-unsupported", CHANGED)?;
    let dir = model.dir();
    let dir_s = dir.to_str().ok_or("non-UTF-8 temp dir")?;
    let apply = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_NO_DOTENV", "1")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .args([
            "apply",
            "1.1.200",
            "--yes",
            "--allow-remote-gateway",
            "--dir",
            dir_s,
            "--gateway",
            "192.0.2.1:3671",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let (stdout, stderr) = text(&apply);
    assert!(!apply.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("refusing to write: 1.1.200 runs")
            && stderr.contains("not on bussard's list of supported devices. Nothing was written."),
        "{stderr}"
    );
    assert!(stderr.contains("--allow-unsupported"), "{stderr}");
    Ok(())
}

const STATIC: &str = r#"address = "1.1.200"
name = "KNX IP Interface"

[knxnet]
assignment = "static"
address = "192.168.1.80"
netmask = "255.255.255.0"
tunnels = ["1.1.22", "1.1.23", "1.1.24", "1.1.25", "1.1.26", "1.1.27", "1.1.28", "1.1.29"]
"#;

#[test]
fn test_interface_apply_refuses_to_reconfigure_its_own_tunnel() -> TestResult {
    let model = TempModel::new("bussard-interface-self", STATIC)?;
    // The interface is the gateway the command tunnels through.
    let bench = Bench::start(interface([127, 0, 0, 1])?)?;
    let apply = bench.run(&model.dir(), &["apply", "1.1.200", "--yes"])?;
    let (stdout, stderr) = text(&apply);
    assert!(!apply.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("the tunnel drops"), "{stderr}");
    assert!(stderr.contains("--allow-self-reconfigure"), "{stderr}");
    assert_eq!(bench.device()?.writes, 0, "refused before any write");

    let apply = bench.run(
        &model.dir(),
        &["apply", "1.1.200", "--yes", "--allow-self-reconfigure"],
    )?;
    let (stdout, stderr) = text(&apply);
    assert!(apply.status.success(), "{stdout}\n{stderr}");
    let device = bench.device()?;
    assert_eq!(device.knxnet_property(60), Some(&[192, 168, 1, 80][..]));
    assert_eq!(device.knxnet_property(55), Some(&[0x01][..]));
    Ok(())
}

/// The gateway is the interface 1.1.200 itself: its description names it,
/// and it serves device management connections (issue #523).
fn interface_gateway(builder: bussard_testkit::GatewayBuilder) -> bussard_testkit::GatewayBuilder {
    let mut description = bussard_testkit::wire::description_response_body("IPS 300", 4, 0);
    description[4..6].copy_from_slice(&0x11C8u16.to_be_bytes());
    builder
        .interface_device(IndividualAddress::from_raw(0x11C8))
        .description(description)
}

/// The cEMI message codes the interface received on device management
/// connections.
fn device_configuration_codes(bench: &Bench) -> TestResult<Vec<u8>> {
    Ok(bench
        .stats()?
        .device_configuration
        .iter()
        .filter_map(|c| c.first().copied())
        .collect())
}

#[test]
fn test_interface_plan_apply_over_device_management() -> TestResult {
    let model = TempModel::new("bussard-interface-devmgmt", CHANGED)?;
    let bench = Bench::start_with(interface([192, 0, 2, 74])?, interface_gateway)?;

    let plan = bench.run(&model.dir(), &["plan", "1.1.200", "--device-management"])?;
    let (stdout, stderr) = text(&plan);
    assert!(plan.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("~ friendly name = \"Demohouse Beta\", was \"Demohouse Alpha\""),
        "{stdout}"
    );

    let apply = bench.run(
        &model.dir(),
        &["apply", "1.1.200", "--yes", "--device-management"],
    )?;
    let (stdout, stderr) = text(&apply);
    assert!(apply.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("apply verified: 2 properties written"),
        "{stdout}"
    );
    let device = bench.device()?;
    let name = device.knxnet_property(76).ok_or("PID 76")?;
    assert_eq!(&name[..14], b"Demohouse Beta");
    // The property writes went as local device management, no tunnel was
    // opened.
    let codes = device_configuration_codes(&bench)?;
    assert!(codes.contains(&0xF6), "{codes:02X?}");
    assert!(
        !bench
            .stats()?
            .services
            .contains(&bussard_transport::knxnet::ServiceType::TunnelingRequest)
    );

    let again = bench.run(
        &model.dir(),
        &["plan", "1.1.200", "--json", "--device-management"],
    )?;
    let (stdout, stderr) = text(&again);
    assert!(again.status.success(), "{stdout}\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["noop"], true, "{stdout}");
    Ok(())
}

#[test]
fn test_interface_plan_falls_back_to_device_management_without_a_free_tunnel() -> TestResult {
    let model = TempModel::new("bussard-interface-devmgmt-full", CHANGED)?;
    let bench = Bench::start_with(interface([192, 0, 2, 74])?, |b| {
        interface_gateway(b).refuse_connect(0x24)
    })?;
    let plan = bench.run(&model.dir(), &["plan", "1.1.200"])?;
    let (stdout, stderr) = text(&plan);
    assert!(plan.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("note: the interface has no free tunnelling connection"),
        "{stderr}"
    );
    assert!(stdout.contains("+ tunnel address 1.1.30 added"), "{stdout}");
    assert!(!device_configuration_codes(&bench)?.is_empty());
    Ok(())
}

#[test]
fn test_interface_device_management_refuses_another_gateway() -> TestResult {
    let model = TempModel::new("bussard-interface-devmgmt-other", CHANGED)?;
    // The gateway describes itself as 1.0.0, not the interface 1.1.200.
    let bench = Bench::start_with(interface([192, 0, 2, 74])?, |b| {
        b.interface_device(IndividualAddress::from_raw(0x11C8))
            .description(bussard_testkit::wire::description_response_body(
                "IPS 300", 4, 0,
            ))
    })?;
    let plan = bench.run(&model.dir(), &["plan", "1.1.200", "--device-management"])?;
    let (stdout, stderr) = text(&plan);
    assert!(!plan.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("is the KNXnet/IP server 1.0.0"), "{stderr}");
    assert!(device_configuration_codes(&bench)?.is_empty());
    Ok(())
}

#[test]
fn test_interface_plan_falls_back_to_device_management_on_a_duplicated_tunnel_address() -> TestResult
{
    let model = TempModel::new("bussard-interface-devmgmt-dup", CHANGED)?;
    // A device on the line answers at the tunnel's address.
    let tunnel = IndividualAddress::from_raw(bussard_testkit::consts::TUNNEL_IA_RAW);
    let bench = Bench::start_with(interface([192, 0, 2, 74])?, |b| {
        interface_gateway(b).device(MockDevice::new(tunnel))
    })?;
    let plan = bench.run(&model.dir(), &["plan", "1.1.200"])?;
    let (stdout, stderr) = text(&plan);
    assert!(plan.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains(&format!("answers at the tunnel address {tunnel}")),
        "{stderr}"
    );
    assert!(stdout.contains("+ tunnel address 1.1.30 added"), "{stdout}");
    Ok(())
}

#[test]
fn test_describe_reads_the_interface_over_device_management() -> TestResult {
    let model = TempModel::new("bussard-interface-devmgmt-describe", CHANGED)?;
    let bench = Bench::start_with(interface([192, 0, 2, 74])?, interface_gateway)?;
    let describe = bench.run(
        &model.dir(),
        &["describe", "1.1.200", "--device-management"],
    )?;
    let (stdout, stderr) = text(&describe);
    assert!(describe.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("0021"), "{stdout}");
    assert!(!device_configuration_codes(&bench)?.is_empty());
    Ok(())
}

#[test]
fn test_device_management_flag_is_refused_for_other_commands() -> TestResult {
    let model = TempModel::new("bussard-interface-devmgmt-flag", CHANGED)?;
    let bench = Bench::start(interface([192, 0, 2, 74])?)?;
    let read = bench.run(&model.dir(), &["read", "1/0/1", "--device-management"])?;
    let (stdout, stderr) = text(&read);
    assert!(!read.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("only `plan`, `apply`"), "{stderr}");
    Ok(())
}
