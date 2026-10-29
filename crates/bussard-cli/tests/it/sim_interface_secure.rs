//! `bussard interface secure on|off` (issue #398): the dry-run plan and its
//! `--dump-images` (always), and the whole switch against knx-sim (when
//! `BUSSARD_KNX_SIM_BIN` names the `serve` binary): a simulated KNX IP
//! interface in factory state (Data Secure tool access under its FDSK,
//! plain tunnelling) whose gateway is its own KNXnet/IP server, switched on
//! (the gateway then serves secure-only tunnelling with the credentials
//! bussard generated into the key store) and off again.
//!
//! Synthetic keys and passwords only; the key store is written with a
//! synthetic password in a scratch directory.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use bussard_project::KeyStore;
use bussard_project::keystore::StoreDevice;
use bussard_secure::Key16;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STORE_PASSWORD: &str = "synthetic-store-password";
/// The synthetic factory key, as the sim config and the key store hold it.
const FDSK_HEX: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0";

fn fdsk() -> Result<Key16, Box<dyn std::error::Error>> {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&FDSK_HEX[2 * i..2 * i + 2], 16)?;
    }
    Ok(Key16::new(out))
}

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Result<Scratch, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("bussard-ipsecure-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("knx").join("devices"))?;
    Ok(Scratch(root))
}

/// A model with the interface 1.1.200 (two tunnelling addresses) and a key
/// store that knows only its factory key.
fn model(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let model = root.join("knx");
    std::fs::write(
        model.join("devices").join("1.1.200.toml"),
        "address = \"1.1.200\"\nname = \"Simulated IP interface\"\n\n[knxnet]\n\
         assignment = \"dhcp\"\ntunnels = [\"1.1.22\", \"1.1.23\"]\n",
    )?;
    let mut store = KeyStore::new("Synthetic");
    store.devices.insert(
        "1.1.200".parse()?,
        StoreDevice {
            fdsk: Some(fdsk()?),
            ..StoreDevice::default()
        },
    );
    store.save(&model, STORE_PASSWORD)?;
    Ok(model)
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
        .env("BUSSARD_KEYRING_PASSWORD", STORE_PASSWORD)
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

#[test]
fn test_interface_secure_dry_run_dumps_the_plan_without_key_material() -> TestResult {
    let root = scratch("dry")?;
    let model = model(&root.0)?;
    let store_before = std::fs::read(model.join("bussard.keys"))?;
    let dump = root.0.join("dump");
    let dump_arg = dump.to_str().ok_or("non-UTF-8 path")?;
    // A closed loopback port: a dry run must not connect.
    let out = bussard(
        &model,
        "127.0.0.1:9",
        &[
            "interface",
            "secure",
            "on",
            "1.1.200",
            "--dry-run",
            "--dump-images",
            dump_arg,
        ],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("security mode on (type 17 PID 51), under the FDSK"),
        "{stdout}"
    );
    assert!(
        stdout.contains("tunnelling users 2->1 3->2 (type 11 PID 97)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("dry run: nothing sent, the key store unchanged"),
        "{stdout}"
    );
    assert_eq!(std::fs::read(model.join("bussard.keys"))?, store_before);
    let plan: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dump.join("plan.json"))?)?;
    assert_eq!(plan["system"], "ip-secure");
    let records: Vec<serde_json::Value> = plan["steps"]
        .as_array()
        .ok_or("no steps")?
        .iter()
        .flat_map(|s| s["properties"].as_array().cloned().unwrap_or_default())
        .collect();
    let keys: Vec<(u64, u64)> = records
        .iter()
        .map(|r| {
            (
                r["object_type"].as_u64().unwrap_or(0),
                r["pid"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            (17, 51),
            (17, 56),
            (17, 59),
            (11, 94),
            (11, 92),
            (11, 93),
            (11, 93),
            (11, 94),
            (11, 97),
            (11, 97),
            (11, 94),
        ]
    );
    for r in &records {
        let secret = matches!(r["pid"].as_u64(), Some(56 | 92 | 93));
        assert_eq!(r.get("data").is_none(), secret || r["pid"] == 59, "{r}");
    }
    let text = std::fs::read_to_string(dump.join("plan.json"))?;
    assert!(!text.contains(FDSK_HEX), "the FDSK leaked into plan.json");
    Ok(())
}

/// A running knx-sim, killed on drop.
struct Sim {
    child: Child,
    port: u16,
}

impl Sim {
    fn start(bin: &Path, root: &Path) -> Result<Sim, Box<dyn std::error::Error>> {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let yaml = format!(
            "gateway:\n  host: \"127.0.0.1\"\n  port: {port}\n  interface_device: \"1.1.200\"\n\n\
             devices:\n  - address: \"1.1.200\"\n    initial_state: loaded\n    security:\n      \
             status: factory\n      tool_key: \"{FDSK_HEX}\"\n      initial_tx_seq: 1000\n    \
             knxnet:\n      \
             tunnels: [\"1.1.22\", \"1.1.23\"]\n      tunnel_slots: 8\n      listed: false\n      \
             tunnelling_addresses: [0, 1, 2]\n"
        );
        let config = root.join("sim.yaml");
        std::fs::write(&config, yaml)?;
        let log = root.join("sim.log");
        let child = Command::new(bin)
            .arg(&config)
            .env("RUST_LOG", "knx_sim=info,warn")
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

#[test]
fn test_interface_secure_on_then_off_against_knx_sim() -> TestResult {
    let Some(bin) = std::env::var_os("BUSSARD_KNX_SIM_BIN").map(PathBuf::from) else {
        eprintln!("BUSSARD_KNX_SIM_BIN unset; skipping the knx-sim IP Secure loop.");
        return Ok(());
    };
    let root = scratch("sim")?;
    let model = model(&root.0)?;
    let sim = Sim::start(&bin, &root.0)?;
    let gateway = format!("127.0.0.1:{}", sim.port);

    let on = bussard(
        &model,
        &gateway,
        &["interface", "secure", "on", "1.1.200", "--yes"],
    )?;
    let out = String::from_utf8_lossy(&on.stdout);
    let err = String::from_utf8_lossy(&on.stderr);
    let log = std::fs::read_to_string(root.0.join("sim.log")).unwrap_or_default();
    assert!(on.status.success(), "on: {out}\n{err}\nsim: {log}");
    assert!(
        out.contains("KNXnet/IP Secure switched on for 1.1.200: verified"),
        "{out}"
    );
    assert!(
        out.contains("secure tunnel with the key store's credentials"),
        "{out}"
    );
    assert!(
        log.contains("KNXnet/IP Secure on, secure-only tunnelling"),
        "{log}"
    );
    // PID 79 is [0, 1, 2] (the own address first): PID 97 must name table
    // entries 2 and 3, or user 2 would land on 1.1.200 itself (issue #520).
    assert!(
        out.contains("PID_TUNNELLING_ADDRESSES (79) reads [0, 1, 2]"),
        "{out}"
    );
    assert!(log.contains("tunnelling user 2 on 1.1.22"), "{log}");
    assert!(log.contains("tunnelling user 3 on 1.1.23"), "{log}");

    // The key store now holds the tool key and every credential; the device
    // file holds none.
    let store = KeyStore::load(&model, STORE_PASSWORD)?.ok_or("no key store")?;
    let device = &store.devices[&"1.1.200".parse()?];
    assert!(device.tool_key.is_some() && device.authentication.is_some());
    assert!(device.management_password.is_some());
    assert_eq!(
        store
            .interfaces
            .iter()
            .map(|i| (i.ia.to_string(), i.user_id))
            .collect::<Vec<_>>(),
        vec![("1.1.22".to_string(), 2), ("1.1.23".to_string(), 3)]
    );
    let file = std::fs::read_to_string(model.join("devices").join("1.1.200.toml"))?;
    assert!(!file.to_ascii_lowercase().contains("password"), "{file}");

    // A second `on` is refused: the interface already runs IP Secure.
    let again = bussard(
        &model,
        &gateway,
        &["interface", "secure", "on", "1.1.200", "--yes"],
    )?;
    assert!(!again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("already runs KNXnet/IP Secure"),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );

    // `off` over the secure session with the interface itself needs the flag.
    let refused = bussard(
        &model,
        &gateway,
        &["interface", "secure", "off", "1.1.200", "--yes"],
    )?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--allow-self-reconfigure"));
    let off = bussard(
        &model,
        &gateway,
        &[
            "interface",
            "secure",
            "off",
            "1.1.200",
            "--yes",
            "--allow-self-reconfigure",
        ],
    )?;
    let out = String::from_utf8_lossy(&off.stdout);
    let err = String::from_utf8_lossy(&off.stderr);
    let log = std::fs::read_to_string(root.0.join("sim.log")).unwrap_or_default();
    assert!(off.status.success(), "off: {out}\n{err}\nsim: {log}");
    assert!(
        out.contains("KNXnet/IP Secure switched off for 1.1.200: verified"),
        "{out}"
    );
    assert!(
        log.contains("KNXnet/IP Secure off, plain tunnelling"),
        "{log}"
    );
    let store = KeyStore::load(&model, STORE_PASSWORD)?.ok_or("no key store")?;
    let device = &store.devices[&"1.1.200".parse()?];
    assert!(device.tool_key.is_none() && device.fdsk.is_some());
    drop(sim);
    Ok(())
}
