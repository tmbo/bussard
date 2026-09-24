//! Interop test ladder against thelsing/knx's `knx-linux-ip` demo, run as an
//! EXTERNAL process over KNXnet/IP routing multicast.
//!
//! This is the first time bussard's management stack is driven against an
//! independent, foreign device implementation instead of our own in-process
//! mocks. The device is thelsing/knx (GPL), built by
//! `tests-support/virtual-device/build.sh` into a standalone `knx-linux-ip`
//! binary and spawned here as a separate peer — we never link or vendor that
//! code (see the build script's licence note).
//!
//! # How it is gated (never runs in the normal suite)
//!
//! The whole module is `#[ignore]` AND requires two env vars, so it is inert
//! unless deliberately switched on:
//!
//! - `BUSSARD_VIRTUAL_DEVICE=1`     — opt in to the harness at all;
//! - `BUSSARD_VIRTUAL_DEVICE_BIN=…` — absolute path to the built `knx-linux-ip`.
//!
//! Run it (Linux only — the demo does not build on macOS):
//!
//! ```text
//! BIN=$(tests-support/virtual-device/build.sh)
//! BUSSARD_VIRTUAL_DEVICE=1 BUSSARD_VIRTUAL_DEVICE_BIN=$BIN \
//!   cargo test -p bussard-cli --test virtual_device -- --ignored --nocapture
//! ```
//!
//! It also self-skips unless `BUSSARD_TEST_MULTICAST=1` is set, reusing the same
//! gate the transport crate's `routing_loopback` test uses, because multicast on
//! a loopback-only host is unreliable.
//!
//! # The ladder
//!
//! The demo binary that speaks KNXnet/IP routing is `knx-linux-ip`, which is a
//! System B **device** stack (`BauSystemBDevice`) reachable over multicast — but
//! compiled with `MASK_VERSION=0x57B0` (KNXnet/IP), NOT `0x07B0` (TP). The mask
//! and the medium are coupled at compile time in thelsing's tree: the only binary
//! that reports `07B0` (`knx-linux-tp`) talks to a serial TP-UART, not multicast.
//! So over routing we necessarily face a `57B0` device.
//!
//! Consequences, rung by rung:
//!   (a) programming-mode discovery — WORKS. A fresh device (no flash.bin) boots
//!       unconfigured at 15.15.255 and does NOT enter prog mode by itself, so
//!       the harness presses its programming button first (a raw
//!       `PID_PROG_MODE = 1` write to 15.15.255, see
//!       `VirtualDevice::press_programming_button`); `assign`'s broadcast read
//!       then finds it.
//!   (b) assign — WORKS. `A_IndividualAddress_Write` lands, and the post-write
//!       descriptor read verifies (the device answers `57B0`).
//!   (c) scan — WORKS. It reports the device with mask `57B0`, classified
//!       "System B (IP)" by bussard's mask profile.
//!   (d) reconstruct — WORKS. The mask profile treats 57B0 as System B, so the
//!       tables are read (empty on a fresh device, which has no application).
//!   (e) apply — not attempted: the fresh device carries no application program.
//!
//! The value of this test is proving (a)-(d) against a foreign stack.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// A self-cleaning temporary directory, so this test file needs no `tempfile`
/// dev-dependency (the crate's manifest is out of scope for this change). Uses a
/// process-unique, monotonically-incrementing name and removes the tree on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("bussard-vdev-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(TmpDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Skip helper: returns the built device binary path if the harness is enabled,
/// else `None` after printing why (so `--nocapture` explains the skip).
fn device_bin() -> Option<PathBuf> {
    if std::env::var("BUSSARD_VIRTUAL_DEVICE").ok().as_deref() != Some("1") {
        eprintln!("skipping: set BUSSARD_VIRTUAL_DEVICE=1 to enable the virtual-device harness");
        return None;
    }
    if std::env::var("BUSSARD_TEST_MULTICAST").ok().as_deref() != Some("1") {
        eprintln!("skipping: set BUSSARD_TEST_MULTICAST=1 (loopback multicast gate)");
        return None;
    }
    match std::env::var("BUSSARD_VIRTUAL_DEVICE_BIN") {
        Ok(p) if PathBuf::from(&p).is_file() => Some(PathBuf::from(p)),
        Ok(p) => {
            eprintln!(
                "skipping: BUSSARD_VIRTUAL_DEVICE_BIN={p} is not a file (run build.sh first)"
            );
            None
        }
        Err(_) => {
            eprintln!(
                "skipping: set BUSSARD_VIRTUAL_DEVICE_BIN to the knx-linux-ip binary (run \
                 tests-support/virtual-device/build.sh)"
            );
            None
        }
    }
}

/// A spawned virtual device that kills the child on drop, running factory-fresh
/// (no flash.bin in its private working directory) so it enters programming mode.
struct VirtualDevice {
    child: Child,
    _workdir: TmpDir,
}

impl VirtualDevice {
    /// Spawns the demo in a fresh temp working directory (so `flash.bin` is
    /// absent and the device boots unconfigured → programming mode).
    ///
    /// The device command can be wrapped by setting `BUSSARD_VIRTUAL_DEVICE_WRAP`
    /// to a space-separated command prefix (e.g. `sudo ip netns exec knxdev`).
    /// This is how CI puts the device in its own network namespace so its
    /// multicast frames physically cross a veth pair to bussard — sidestepping
    /// thelsing's `IP_MULTICAST_LOOP=0`, which otherwise stops same-host loopback
    /// delivery of its responses (see `tests-support/virtual-device/README.md`).
    ///
    /// stdout+stderr are streamed to `dev.log` inside `workdir` so a CI run can
    /// upload the device's output as an artifact and callers can wait for its
    /// startup banner instead of sleeping blindly.
    fn spawn_fresh(bin: &Path) -> std::io::Result<Self> {
        let workdir = TmpDir::new("dev")?;

        // Optional wrapper: split on whitespace, first token is the program.
        let wrap: Vec<String> = std::env::var("BUSSARD_VIRTUAL_DEVICE_WRAP")
            .ok()
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();

        let bin_abs = std::fs::canonicalize(bin)?;
        let mut cmd = if let Some((prog, rest)) = wrap.split_first() {
            let mut c = Command::new(prog);
            c.args(rest);
            c.arg(&bin_abs);
            c
        } else {
            Command::new(&bin_abs)
        };

        // The demo writes flash.bin into its CWD; an empty CWD means prog mode.
        // (A wrapper like `ip netns exec` preserves CWD, so this still controls
        // where flash.bin lands.)
        let log = std::fs::File::create(workdir.path().join("dev.log"))?;
        let log_err = log.try_clone()?;
        let child = cmd
            .current_dir(workdir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()?;
        Ok(VirtualDevice {
            child,
            _workdir: workdir,
        })
    }

    /// Waits until the device is actually ready to answer on the bus, or
    /// `timeout` elapses. Returns whether readiness was observed (a `false` is
    /// non-fatal: the ladder still runs and surfaces a clearer failure, with the
    /// log uploaded as an artifact).
    ///
    /// The startup banner (`main() start.`) prints at the very top of thelsing's
    /// `main()`, BEFORE `knx.start()` joins the multicast group and begins
    /// receiving. Keying readiness on the banner alone races the group join: a
    /// single broadcast read fired right after the banner can arrive before the
    /// device has joined and is then simply missed (there is no retransmit). So
    /// when `BUSSARD_VIRTUAL_DEVICE_READY_CMD` is set (CI sets it to a command
    /// that checks the device's multicast membership, e.g. the group appears in
    /// `ip netns exec knxdev ip maddr show`), we wait for THAT to succeed. Absent
    /// the env var we fall back to the banner (fine for a fast local box).
    fn wait_ready(&self, timeout: Duration) -> bool {
        let log_path = self._workdir.path().join("dev.log");
        let ready_cmd = std::env::var("BUSSARD_VIRTUAL_DEVICE_READY_CMD").ok();
        let start = Instant::now();
        while start.elapsed() < timeout {
            // Strongest signal: the readiness command reports the device has
            // joined the group and is listening.
            if let Some(cmd) = &ready_cmd {
                let ok = Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok {
                    return true;
                }
            } else if let Ok(f) = std::fs::File::open(&log_path) {
                // Fallback: the startup banner (no group-join guarantee).
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    if line.contains("main() start.") || line.contains("FDSK:") {
                        return true;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Prints the captured device log to stderr (so `--nocapture` and the CI
    /// artifact both carry it) — called on assertion paths for diagnosis.
    fn dump_log(&self) {
        let log_path = self._workdir.path().join("dev.log");
        if let Ok(contents) = std::fs::read_to_string(&log_path) {
            eprintln!(
                "--- virtual device log ({}) ---\n{contents}",
                log_path.display()
            );
        }
    }
}

/// KNXnet/IP routing multicast group and port the device listens on.
const ROUTING_GROUP: (&str, u16) = ("224.0.23.12", 3671);

/// Wraps a cEMI body in a KNXnet/IP `ROUTING_INDICATION` (0x0530).
fn routing_indication(cemi: &[u8]) -> Vec<u8> {
    let total = u16::try_from(6 + cemi.len()).unwrap_or(u16::MAX);
    let mut f = vec![0x06, 0x10, 0x05, 0x30];
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(cemi);
    f
}

/// A point-to-point `L_Data.req` from 0.0.255 to 15.15.255 (the factory
/// address of the fresh device) carrying `tpdu` (TPCI byte first).
fn to_factory_address(tpdu: &[u8]) -> Vec<u8> {
    let npdu_len = u8::try_from(tpdu.len().saturating_sub(1)).unwrap_or(u8::MAX);
    let mut cemi = vec![0x11, 0x00, 0xBC, 0x60, 0x00, 0xFF, 0xFF, 0xFF, npdu_len];
    cemi.extend_from_slice(tpdu);
    routing_indication(&cemi)
}

impl VirtualDevice {
    /// Presses the device's programming button, then waits until the device
    /// logs `progmode on`. Returns whether that was observed.
    ///
    /// A real installer presses a physical button before `bussard assign`.
    /// thelsing's demo boots at 15.15.255 (its `DeviceObject` default), so its
    /// `if (individualAddress() == 0) progMode(true)` guard never fires and a
    /// fresh device is NOT in programming mode. The harness stands in for the
    /// installer: it opens a transport connection to 15.15.255 over routing and
    /// writes `PID_PROG_MODE` (device object 0, property 54) = 1, which is what
    /// the button does. This is raw KNX on a plain UDP socket, deliberately
    /// independent of bussard's own stack, so rung (a) still tests bussard's
    /// discovery and not the harness.
    fn press_programming_button(&self) -> bool {
        let log_path = self._workdir.path().join("dev.log");
        let progmode_on = || {
            std::fs::read_to_string(&log_path)
                .map(|s| s.contains("progmode on"))
                .unwrap_or(false)
        };
        let Ok(tx) = std::net::UdpSocket::bind("0.0.0.0:0") else {
            return false;
        };
        let _ = tx.set_multicast_ttl_v4(2);
        // A_PropertyValue_Write, sequence 0: object 0, PID 54, count 1 /
        // start 1, value 1. APCI 0x3D7 split across the TPCI and APCI octets.
        let apci: u16 = 0x3D7;
        let write = [
            0x40 | ((apci >> 8) as u8 & 0x03),
            (apci & 0xFF) as u8,
            0x00,
            54,
            0x10,
            0x01,
            0x01,
        ];
        for _attempt in 0..3 {
            let frames: [&[u8]; 4] = [&[0x80], &write, &[0xC2], &[0x81]];
            // T_Connect, the write, T_ACK for the device's response (seq 0),
            // T_Disconnect. Small gaps let the single-threaded device loop
            // service each frame in order.
            for tpdu in frames {
                let _ = tx.send_to(&to_factory_address(tpdu), ROUTING_GROUP);
                std::thread::sleep(Duration::from_millis(200));
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(2) {
                if progmode_on() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        progmode_on()
    }
}

impl Drop for VirtualDevice {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs the built `bussard` binary with `--routing` and the given args, returning
/// (success, stdout, stderr). A short assign/scan window keeps the run brisk.
fn bussard(args: &[&str]) -> (bool, String, String) {
    // Keep the assign/scan windows generous on slow CI runners; overridable via
    // env so a fast local box can shorten them. The netns hop adds latency, so
    // the default here is deliberately roomy (5s assign, 800ms scan discovery).
    let assign_wait = std::env::var("BUSSARD_ASSIGN_WAIT_MS").unwrap_or_else(|_| "5000".into());
    let scan_disc = std::env::var("BUSSARD_SCAN_DISCOVERY_MS").unwrap_or_else(|_| "800".into());
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .arg("--routing")
        // Routing counts as non-loopback for the write gate (issue #74): a
        // multicast write does reach a real bus. Here it reaches only the veth
        // namespace holding the interop device, so the harness opts in
        // explicitly; without it every write refuses before it starts.
        .env("BUSSARD_ALLOW_REAL_GATEWAY", "1")
        .env("BUSSARD_ASSIGN_WAIT_MS", assign_wait)
        .env("BUSSARD_SCAN_DISCOVERY_MS", scan_disc)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run bussard");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The full ladder in one test (the rungs share one booted device, and later
/// rungs depend on the assign from earlier ones, so they must run in order).
#[test]
#[ignore = "external virtual device; enable with BUSSARD_VIRTUAL_DEVICE=1 (Linux+multicast)"]
fn ladder_against_thelsing_knx_linux_ip() {
    let Some(bin) = device_bin() else {
        return;
    };

    // The address we assign the fresh device. `scan` and `reconstruct` target it.
    let assigned = "1.1.47";

    let device = VirtualDevice::spawn_fresh(&bin).expect("spawn virtual device");
    // Wait for the device to print its startup banner rather than sleeping
    // blindly; then a short settle for the multicast join to take effect.
    if !device.wait_ready(Duration::from_secs(20)) {
        eprintln!(
            "warning: virtual device did not report ready within 20s; continuing \
             (the ladder will surface a clearer failure and the log is dumped below)"
        );
        device.dump_log();
    }
    // A short settle after the group join so the device's receive loop is
    // servicing the socket before the first broadcast read.
    std::thread::sleep(Duration::from_millis(1500));

    // The fresh device boots at 15.15.255 and is not in programming mode;
    // press its button the way an installer would before running assign.
    if !device.press_programming_button() {
        eprintln!(
            "warning: the virtual device did not log `progmode on` after the \
             PID_PROG_MODE write; continuing (assign will fail with the log below)"
        );
        device.dump_log();
    }

    // --- Rung (a)+(b): assign finds the fresh device and writes its address ---
    // It internally does the programming-mode broadcast read (rung a) and then
    // the A_IndividualAddress_Write + descriptor-read verify (rung b).
    //
    // `--yes` is required: an explicit address stopped being consent in issue
    // #74, so a non-TTY assign without it refuses before touching the bus.
    let tmp = TmpDir::new("model").expect("model dir");
    let dir = tmp.path().join("knx");
    let (ok, out, err) = bussard(&["assign", assigned, "--yes", "--dir", dir.to_str().unwrap()]);
    eprintln!("--- assign stdout ---\n{out}\n--- assign stderr ---\n{err}");
    if !ok {
        device.dump_log();
    }
    assert!(
        ok,
        "rung (a)+(b): assign should find the fresh device in programming mode \
         and write {assigned}; stderr:\n{err}"
    );
    // The verify read-back reports the device's mask. thelsing knx-linux-ip is a
    // 57B0 (KNXnet/IP System B) device — this is the key interop fact.
    assert!(
        out.to_uppercase().contains("57B0") || err.to_uppercase().contains("57B0"),
        "rung (b): expected the verified mask to be 57B0 (knx-linux-ip); \
         stdout:\n{out}\nstderr:\n{err}"
    );

    // --- Rung (c): scan finds the now-addressed device with its mask ---
    let (ok, out, err) = bussard(&[
        "scan",
        "1.1",
        "--from",
        "47",
        "--to",
        "47",
        "--dir",
        dir.to_str().unwrap(),
        "--json",
    ]);
    eprintln!("--- scan stdout ---\n{out}\n--- scan stderr ---\n{err}");
    assert!(ok, "rung (c): scan should exit 0; stderr:\n{err}");
    let json: serde_json::Value =
        serde_json::from_str(&out).expect("scan --json must emit valid JSON");
    let found = json["found"].as_array().expect("found array");
    let dev = found
        .iter()
        .find(|d| d["address"] == assigned)
        .unwrap_or_else(|| panic!("rung (c): scan did not find {assigned}: {out}"));
    assert_eq!(
        dev["mask"], "57B0",
        "rung (c): the foreign device reports mask 57B0"
    );
    // bussard classifies 57B0 as System B on the IP medium (the mask family
    // profile). Asserting this pins the classification against a real 57B0 device.
    assert_eq!(
        dev["system_type"], "System B (IP)",
        "rung (c): 57B0 is classified 'System B (IP)' by bussard"
    );

    // --- Rung (d): reconstruct reads the 57B0 device's tables ---
    // The mask profile made reconstruct medium-agnostic: 57B0 (System B, IP)
    // is read like 07B0. The fresh device has no application loaded, so the
    // tables are empty, but the read must succeed against the foreign stack.
    let (ok, out, err) = bussard(&["reconstruct", assigned, "--dir", dir.to_str().unwrap()]);
    eprintln!("--- reconstruct stdout ---\n{out}\n--- reconstruct stderr ---\n{err}");
    if !ok {
        device.dump_log();
    }
    assert!(
        ok,
        "rung (d): reconstruct should read the 57B0 (System B, IP) device; stderr:\n{err}"
    );

    eprintln!(
        "ladder complete: (a) prog-mode discovery, (b) assign+verify (mask 57B0), \
         (c) scan classified 57B0 as 'System B (IP)', (d) reconstruct read it."
    );
}
