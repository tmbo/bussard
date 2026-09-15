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
//! # The ladder (and where it is expected to stop)
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
//!       unconfigured and auto-enters prog mode; `assign`'s broadcast read finds
//!       it.
//!   (b) assign — WORKS. `A_IndividualAddress_Write` lands, and the post-write
//!       descriptor read verifies (the device answers `57B0`).
//!   (c) scan — WORKS. It reports the device with mask `57B0`, classified
//!       "System ?" by bussard (an honest interop signal, not a bug).
//!   (d) reconstruct — STOPS. `bussard reconstruct` gates on `07B0` and refuses a
//!       `57B0` mask. This is the documented boundary, asserted here so the
//!       divergence is pinned by a test rather than described in prose.
//!   (e) apply — not attempted over routing for the same reason (07B0 gate).
//!
//! The value of this test is proving (a)-(c) against a foreign stack and pinning
//! (d) as a concrete, reproducible interop finding.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

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
    fn spawn_fresh(bin: &PathBuf) -> std::io::Result<Self> {
        let workdir = TmpDir::new("dev")?;
        // The demo writes flash.bin into its CWD; an empty CWD means prog mode.
        let child = Command::new(bin)
            .current_dir(workdir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(VirtualDevice {
            child,
            _workdir: workdir,
        })
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
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .arg("--routing")
        // Shorten the programming-mode/scan windows for a responsive local device.
        .env("BUSSARD_ASSIGN_WAIT_MS", "2000")
        .env("BUSSARD_SCAN_DISCOVERY_MS", "300")
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

    let _device = VirtualDevice::spawn_fresh(&bin).expect("spawn virtual device");
    // Give the device a moment to join the multicast group and settle.
    std::thread::sleep(Duration::from_millis(1500));

    // --- Rung (a)+(b): assign finds the fresh device and writes its address ---
    // `assign <addr> --routing` is non-interactive-safe with an explicit address
    // (no TTY confirmation needed), so it drives cleanly from the test harness.
    // It internally does the programming-mode broadcast read (rung a) and then the
    // A_IndividualAddress_Write + descriptor-read verify (rung b).
    let tmp = TmpDir::new("model").expect("model dir");
    let dir = tmp.path().join("knx");
    let (ok, out, err) = bussard(&["assign", assigned, "--dir", dir.to_str().unwrap()]);
    eprintln!("--- assign stdout ---\n{out}\n--- assign stderr ---\n{err}");
    assert!(
        ok,
        "rung (a)+(b): assign should find the fresh device in programming mode \
         and write {assigned}; stderr:\n{err}"
    );
    // The verify read-back reports the device's mask. thelsing knx-linux-ip is a
    // 57B0 (KNXnet/IP System B) device — this is the key interop fact.
    assert!(
        out.contains("57B0") || out.contains("0x57B0") || err.contains("57B0"),
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
    // bussard classifies 57B0 as an unknown system (it only tables the TP masks).
    // Asserting this pins the classification behaviour against a real 57B0 device.
    assert_eq!(
        dev["system_type"], "System ?",
        "rung (c): 57B0 is classified 'System ?' by bussard (interop signal)"
    );

    // --- Rung (d): reconstruct STOPS at the 07B0 gate ---
    // This is the documented divergence: reconstruct/apply support System B
    // (07B0) only, and the routing-reachable demo is 57B0. We assert the clean
    // refusal (non-zero exit, explanatory message) rather than a crash.
    let (ok, out, err) = bussard(&["reconstruct", assigned, "--dir", dir.to_str().unwrap()]);
    eprintln!("--- reconstruct stdout ---\n{out}\n--- reconstruct stderr ---\n{err}");
    assert!(
        !ok,
        "rung (d): reconstruct must refuse a 57B0 device (07B0-only gate); \
         it unexpectedly succeeded:\n{out}"
    );
    assert!(
        err.contains("57B0") && err.to_lowercase().contains("system b"),
        "rung (d): the refusal should name the 57B0 mask and the System B (07B0) \
         limitation; stderr:\n{err}"
    );

    eprintln!(
        "ladder complete: (a) prog-mode discovery, (b) assign+verify (mask 57B0), \
         (c) scan classified 57B0 as 'System ?', (d) reconstruct correctly refused \
         the 57B0 device at the 07B0 gate. Rung (e) apply is not reachable over \
         routing for the same reason."
    );
}
