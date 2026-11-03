//! The KNX IP interface loop against knx-sim (issue #391, sub-task b): a
//! simulated interface with a KNXnet/IP parameter object (reached by object
//! type only, as the Jung IPS 300 SREG), a device file whose `[knxnet]` table
//! differs from it, `bussard apply --yes`, then `bussard plan --json` must be
//! a no-op. Not part of the product-catalog loop: it needs no product file.
//!
//! knx-sim runs as its own process (`BUSSARD_KNX_SIM_BIN`, the `serve`
//! binary) on a loopback port and is reached over KNXnet/IP only, so no
//! bussard crate links it. Without the variable the test skips green; build
//! the binary with `cargo build --manifest-path knx-sim/Cargo.toml --bin
//! serve` and point the variable at `knx-sim/target/debug/serve`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A running knx-sim, killed on drop.
struct Sim {
    child: Child,
    port: u16,
}

impl Sim {
    fn start(bin: &Path, root: &Path, listed: bool) -> Result<Sim, Box<dyn std::error::Error>> {
        Sim::start_as(bin, root, listed, "")
    }

    /// [`start`](Self::start) with `gateway_extra` appended to the `gateway`
    /// block of the configuration.
    fn start_as(
        bin: &Path,
        root: &Path,
        listed: bool,
        gateway_extra: &str,
    ) -> Result<Sim, Box<dyn std::error::Error>> {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let yaml = format!(
            "gateway:\n  host: \"127.0.0.1\"\n  port: {port}\n{gateway_extra}\ndevices:\n  - address: \"1.1.200\"\n    \
             initial_state: loaded\n    knxnet:\n      friendly_name: \"Bocklisch Alpha\"\n      \
             tunnels: [\"1.1.22\", \"1.1.23\", \"1.1.24\", \"1.1.25\"]\n      tunnel_slots: 8\n      \
             listed: {listed}\n"
        );
        let config = root.join("sim.yaml");
        std::fs::write(&config, yaml)?;
        let log = root.join("sim.log");
        let child = Command::new(bin)
            .arg(&config)
            .env("RUST_LOG", "knx_sim::run=info,warn")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log)?)
            .stderr(std::fs::File::create(root.join("sim.err"))?)
            .spawn()?;
        let mut sim = Sim { child, port };
        let started = Instant::now();
        loop {
            if std::fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("listening")
            {
                return Ok(sim);
            }
            if let Some(status) = sim.child.try_wait()? {
                let err = std::fs::read_to_string(root.join("sim.err")).unwrap_or_default();
                return Err(format!("knx-sim did not start ({status}): {err}").into());
            }
            if started.elapsed() > Duration::from_secs(30) {
                return Err("knx-sim did not listen within 30 s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bussard(
    model: &Path,
    gateway: &str,
    args: &[&str],
) -> Result<Output, Box<dyn std::error::Error>> {
    let model = model.to_str().ok_or("non-UTF-8 path")?;
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .args(["--dir", model, "--gateway", gateway])
        .env("BUSSARD_NO_DOTENV", "1")
        .env("NO_COLOR", "1")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

fn run_loop(listed: bool) -> TestResult {
    run_loop_via(listed, false)
}

/// The loop, over a tunnel or (`device_management`) over a KNXnet/IP device
/// management connection to the simulated interface itself (issue #523).
fn run_loop_via(listed: bool, device_management: bool) -> TestResult {
    let Some(bin) = std::env::var_os("BUSSARD_KNX_SIM_BIN").map(PathBuf::from) else {
        eprintln!("BUSSARD_KNX_SIM_BIN unset; skipping the knx-sim interface loop.");
        return Ok(());
    };
    let root = std::env::temp_dir().join(format!(
        "bussard-sim-interface-{}-{listed}-{device_management}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let scratch = Scratch(root.clone());
    let model = scratch.0.join("knx");
    std::fs::create_dir_all(model.join("devices"))?;
    std::fs::write(
        model.join("devices").join("1.1.200.toml"),
        "address = \"1.1.200\"\nname = \"Simulated IP interface\"\n\n[knxnet]\n\
         assignment = \"dhcp\"\nfriendly_name = \"Bocklisch Beta\"\n\
         tunnels = [\"1.1.22\", \"1.1.23\", \"1.1.24\", \"1.1.25\", \"1.1.26\", \"1.1.27\"]\n",
    )?;
    let sim = if device_management {
        Sim::start_as(&bin, &root, listed, "  interface_device: \"1.1.200\"\n")?
    } else {
        Sim::start(&bin, &root, listed)?
    };
    let gateway = format!("127.0.0.1:{}", sim.port);
    let bussard = |model: &Path, gateway: &str, args: &[&str]| {
        let mut args = args.to_vec();
        if device_management {
            args.push("--device-management");
        }
        bussard(model, gateway, &args)
    };

    let plan = bussard(&model, &gateway, &["plan", "1.1.200"])?;
    let out = String::from_utf8_lossy(&plan.stdout);
    let err = String::from_utf8_lossy(&plan.stderr);
    assert!(plan.status.success(), "plan: {out}\n{err}");
    assert!(
        out.contains("~ friendly name = \"Bocklisch Beta\", was \"Bocklisch Alpha\""),
        "{out}"
    );
    assert!(out.contains("+ tunnel address 1.1.27 added"), "{out}");

    let apply = bussard(&model, &gateway, &["apply", "1.1.200", "--yes"])?;
    let out = String::from_utf8_lossy(&apply.stdout);
    let err = String::from_utf8_lossy(&apply.stderr);
    assert!(apply.status.success(), "apply: {out}\n{err}");
    assert!(out.contains("apply verified"), "{out}");

    let again = bussard(&model, &gateway, &["plan", "1.1.200", "--json"])?;
    let out = String::from_utf8_lossy(&again.stdout);
    assert!(again.status.success(), "plan again: {out}");
    let json: serde_json::Value = serde_json::from_str(&out)?;
    assert_eq!(json["noop"], true, "{out}");
    drop(sim);
    Ok(())
}

#[test]
fn test_sim_interface_apply_then_plan_is_a_noop_by_type() -> TestResult {
    run_loop(false)
}

#[test]
fn test_sim_interface_apply_then_plan_is_a_noop_by_index() -> TestResult {
    run_loop(true)
}

#[test]
fn test_sim_interface_apply_then_plan_is_a_noop_over_device_management() -> TestResult {
    run_loop_via(false, true)
}
