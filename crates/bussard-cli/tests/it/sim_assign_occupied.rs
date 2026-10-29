//! `bussard assign` against knx-sim with two devices on the line (issue
//! #530): one already holds the target address, the other waits in
//! programming mode. NM_IndividualAddress_Write step 1 (Management Procedures
//! 03_05_02 §2.3) must find the first and refuse before anything is
//! broadcast; a free address then goes to the second.
//!
//! knx-sim runs as its own process (`BUSSARD_KNX_SIM_BIN`, the `serve`
//! binary) on a loopback port, so no bussard crate links it. Without the
//! variable the test skips green; build the binary with `cargo build
//! --manifest-path knx-sim/Cargo.toml --bin serve` and point the variable at
//! `knx-sim/target/debug/serve`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A running knx-sim and its scratch directory, both cleaned up on drop.
struct Sim {
    child: Child,
    port: u16,
    root: PathBuf,
}

impl Sim {
    fn start(bin: &Path, root: PathBuf) -> Result<Sim, Box<dyn std::error::Error>> {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let yaml = format!(
            "gateway:\n  host: \"127.0.0.1\"\n  port: {port}\n\ndevices:\n  \
             - address: \"1.1.7\"\n    initial_state: loaded\n  \
             - address: \"15.15.255\"\n    prog_mode: true\n"
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
        let mut sim = Sim { child, port, root };
        let started = Instant::now();
        loop {
            if std::fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("listening")
            {
                return Ok(sim);
            }
            if let Some(status) = sim.child.try_wait()? {
                let err = std::fs::read_to_string(sim.root.join("sim.err")).unwrap_or_default();
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
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assign(model: &Path, port: u16, address: &str) -> Result<Output, Box<dyn std::error::Error>> {
    let model = model.to_str().ok_or("non-UTF-8 path")?;
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["assign", address, "--yes", "--dir", model])
        .args(["--gateway", &format!("127.0.0.1:{port}")])
        .env("BUSSARD_NO_DOTENV", "1")
        .env("NO_COLOR", "1")
        .env("BUSSARD_ASSIGN_WAIT_MS", "500")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

#[test]
fn test_sim_assign_refuses_an_occupied_address_before_any_broadcast() -> TestResult {
    let Some(bin) = std::env::var_os("BUSSARD_KNX_SIM_BIN").map(PathBuf::from) else {
        eprintln!("BUSSARD_KNX_SIM_BIN unset; skipping the knx-sim assign test.");
        return Ok(());
    };
    let root = std::env::temp_dir().join(format!("bussard-sim-assign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    let sim = Sim::start(&bin, root.clone())?;
    let model = root.join("knx");
    std::fs::create_dir_all(model.join("devices"))?;
    std::fs::write(
        model.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Existing\"\n",
    )?;

    // 1.1.7 is not in the model, but a device answers there.
    let refused = assign(&model, sim.port, "1.1.7")?;
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{err}");
    assert!(err.contains("1.1.7 is already in use"), "{err}");
    assert!(
        !err.contains("device in programming mode:"),
        "refused before the programming-mode broadcast: {err}"
    );

    // The device in programming mode was left alone: it still sits at
    // 15.15.255 and takes a free address.
    let taken = assign(&model, sim.port, "1.1.8")?;
    let out = String::from_utf8_lossy(&taken.stdout);
    let err = String::from_utf8_lossy(&taken.stderr);
    assert!(taken.status.success(), "{out}\n{err}");
    assert!(out.contains("assigned 15.15.255 → 1.1.8"), "{out}\n{err}");
    drop(sim);
    Ok(())
}
