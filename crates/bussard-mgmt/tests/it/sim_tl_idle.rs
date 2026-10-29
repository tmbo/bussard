//! Issue #575 against the knx-sim Style 3 transport server (#511): a
//! management connection idle past the device's 6 s connection timeout
//! (03_03_04 §5, E16) reconnects at the next request instead of meeting the
//! closed connection's `T_Disconnect` (A10).
//!
//! knx-sim runs as its own process (`BUSSARD_KNX_SIM_BIN`, the `serve`
//! binary) on a loopback port, so no bussard crate links it. Without the
//! variable the test skips green; build the binary with `cargo build
//! --manifest-path knx-sim/Cargo.toml --bin serve` and point the variable at
//! `knx-sim/target/debug/serve`. It waits out the real 6 s timeout.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bussard_mgmt::{CONNECTION_TIMEOUT, Layer4Connection, read_device_descriptor};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

/// A running knx-sim and its scratch directory, both cleaned up on drop.
struct Sim {
    child: Child,
    port: u16,
    root: PathBuf,
}

impl Sim {
    fn start(bin: &Path, root: PathBuf) -> Result<Sim, BoxError> {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let yaml = format!(
            "gateway:\n  host: \"127.0.0.1\"\n  port: {port}\n\ndevices:\n  \
             - address: \"1.1.7\"\n    initial_state: loaded\n"
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

#[tokio::test]
async fn test_idle_connection_reconnects_against_the_style3_sim() -> TestResult {
    let Some(bin) = std::env::var_os("BUSSARD_KNX_SIM_BIN").map(PathBuf::from) else {
        eprintln!("skipping: BUSSARD_KNX_SIM_BIN is not set");
        return Ok(());
    };
    let root = std::env::temp_dir().join(format!("bussard-sim-tl-idle-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let sim = Sim::start(&bin, root)?;
    let gateway = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, sim.port);
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gateway)).await?;
    let target: IndividualAddress = "1.1.7".parse()?;
    let mut l4 = Layer4Connection::connect(&mut bus, target, "0.0.255".parse()?).await?;
    let mask = read_device_descriptor(&mut l4).await?;

    // Past the sim's connection timeout: it has closed the connection and
    // sent its T_Disconnect (E16, A6).
    tokio::time::sleep(CONNECTION_TIMEOUT + Duration::from_millis(700)).await;
    assert!(l4.idle_beyond_connection_timeout());
    assert_eq!(read_device_descriptor(&mut l4).await?, mask);
    assert_eq!(l4.idle_reconnects(), 1);
    // And the new connection carries on.
    assert_eq!(read_device_descriptor(&mut l4).await?, mask);
    l4.disconnect().await?;
    drop(sim);
    Ok(())
}
