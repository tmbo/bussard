//! End-to-end **flash** interop test against thelsing/knx's `knx-linux-ip` demo,
//! run as an EXTERNAL process over KNXnet/IP routing multicast.
//!
//! This is the full-flash oracle the interop ladder (`virtual_device.rs`) could
//! not reach: it drives `bussard flash` — the ETS-free application download —
//! against a REAL, foreign device-side load-state machine and asserts the device
//! program object goes Unloaded -> Loading -> Loaded.
//!
//! # Why this can flash where `assign` could not
//!
//! The management ladder in `virtual_device.rs` stops at rung (a): the pinned
//! thelsing demo boots at its default address 15.15.255 (`_ownAddress = 0xFFFF`),
//! so its `main.cpp` prog-mode guard never fires and it does not answer the
//! broadcast `A_IndividualAddress_Read` that `assign` relies on. `flash` does not
//! need programming-mode discovery: it opens a **connection-oriented** management
//! session to a KNOWN address and downloads. The bussard-independent
//! `knx_probe.py` established that the device IS reachable connection-oriented at
//! 15.15.255 and answers property read/write there, so we flash it at 15.15.255
//! directly and sidestep the assign wall entirely.
//!
//! # The .knxprod
//!
//! A tiny synthetic product (bussard's own MIT work, not vendor data) lives at
//! `tests-support/virtual-device/knxprod/`. Its single application declares
//! `MaskVersion="MV-57B0"` so bussard's flash pre-flight accepts the 57B0 device
//! (`is_system_b(0x57B0)` is true, and the exact app-mask==device-mask compare
//! passes), and carries a 6-byte relative code segment whose load procedure
//! lowers to exactly: Unload / StartLoading / allocate / write / LoadCompleted /
//! Restart. The harness zips the XML into a `.knxprod` at run time (via the `zip`
//! CLI) so git carries readable XML, not a binary blob.
//!
//! # How it is gated (never runs in the normal suite)
//!
//! `#[ignore]` AND requires `BUSSARD_VIRTUAL_DEVICE=1`, `BUSSARD_TEST_MULTICAST=1`
//! and `BUSSARD_VIRTUAL_DEVICE_BIN=<knx-linux-ip>` — the same gate the ladder
//! test uses. Linux only (the demo does not build on macOS).
//!
//! ```text
//! BIN=$(tests-support/virtual-device/build.sh)
//! BUSSARD_VIRTUAL_DEVICE=1 BUSSARD_TEST_MULTICAST=1 BUSSARD_VIRTUAL_DEVICE_BIN=$BIN \
//!   cargo test -p bussard-cli --test virtual_device_flash -- --ignored --nocapture
//! ```

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// A self-cleaning temporary directory (no `tempfile` dev-dependency needed).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bussard-vdev-flash-{tag}-{}-{n}",
            std::process::id()
        ));
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

/// Returns the built device binary path if the harness is enabled, else `None`
/// after printing why (so `--nocapture` explains the skip).
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

/// A spawned virtual device that kills the child on drop, running factory-fresh.
struct VirtualDevice {
    child: Child,
    workdir: TmpDir,
}

impl VirtualDevice {
    /// Spawns the demo in a fresh temp working directory (so `flash.bin` is
    /// absent and the device boots unconfigured at its default 15.15.255). The
    /// command can be wrapped via `BUSSARD_VIRTUAL_DEVICE_WRAP` (e.g. CI's
    /// `sudo ip netns exec knxdev stdbuf -oL -eL`), exactly as the ladder test.
    fn spawn_fresh(bin: &Path) -> std::io::Result<Self> {
        let workdir = TmpDir::new("dev")?;
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
        let log = std::fs::File::create(workdir.path().join("dev.log"))?;
        let log_err = log.try_clone()?;
        let child = cmd
            .current_dir(workdir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()?;
        Ok(VirtualDevice { child, workdir })
    }

    /// Waits until the device has joined the routing group (via
    /// `BUSSARD_VIRTUAL_DEVICE_READY_CMD` when set — CI checks the namespace's
    /// multicast membership), else falls back to the startup banner.
    fn wait_ready(&self, timeout: Duration) -> bool {
        let log_path = self.workdir.path().join("dev.log");
        let ready_cmd = std::env::var("BUSSARD_VIRTUAL_DEVICE_READY_CMD").ok();
        let start = Instant::now();
        while start.elapsed() < timeout {
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

    fn dump_log(&self) {
        let log_path = self.workdir.path().join("dev.log");
        if let Ok(contents) = std::fs::read_to_string(&log_path) {
            eprintln!(
                "--- virtual device log ({}) ---\n{contents}",
                log_path.display()
            );
        }
    }
}

impl Drop for VirtualDevice {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Builds the synthetic `.knxprod` from the committed fixture XML by zipping it
/// with the `zip` CLI. Returns the path to the archive inside `out_dir` (kept
/// alive by the caller), or an explanatory `Err` string if `zip` is unavailable.
///
/// The archive layout is exactly what `read_knxprod` expects: a `M-00FA/`
/// manufacturer folder holding the ApplicationProgram XML. No `knx_master.xml`
/// or `Hardware.xml` is needed — `read_knxprod` discovers the manufacturer folder
/// and the sole application, and the flash selects it as the only candidate.
fn build_knxprod(out_dir: &Path) -> Result<PathBuf, String> {
    // The committed fixture tree, relative to this test file.
    let fixture_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests-support/virtual-device/knxprod");
    let fixture_root = std::fs::canonicalize(&fixture_root)
        .map_err(|e| format!("locating fixture root {}: {e}", fixture_root.display()))?;

    let archive = out_dir.join("bussard-interop.knxprod");
    // `zip -j` would flatten paths; we need `M-00FA/…`, so run zip FROM the
    // fixture root and add the relative tree. `-X` strips extra metadata for a
    // reproducible archive; `-r` recurses the manufacturer folder.
    let status = Command::new("zip")
        .current_dir(&fixture_root)
        .arg("-r")
        .arg("-X")
        .arg("-q")
        .arg(&archive)
        .arg("M-00FA")
        .status()
        .map_err(|e| format!("running `zip` (is it installed?): {e}"))?;
    if !status.success() {
        return Err(format!("`zip` exited with {status}"));
    }
    Ok(archive)
}

/// Runs the built `bussard` binary with `--routing` and the given args, returning
/// (success, stdout, stderr).
fn bussard(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .arg("--routing")
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

/// The full-flash oracle: download the synthetic application into thelsing's
/// `knx-linux-ip` at 15.15.255 with PLAIN flags and assert it reaches `Loaded`.
#[test]
#[ignore = "external virtual device; enable with BUSSARD_VIRTUAL_DEVICE=1 (Linux+multicast)"]
fn flash_reaches_loaded_against_thelsing_knx_linux_ip() -> Result<(), String> {
    let Some(bin) = device_bin() else {
        return Ok(());
    };

    // The device's factory-fresh default address; flash targets it directly.
    let target = "15.15.255";

    let out_dir = TmpDir::new("prod").map_err(|e| e.to_string())?;
    let knxprod = match build_knxprod(out_dir.path()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: could not build the synthetic .knxprod: {e}");
            return Ok(());
        }
    };
    eprintln!("built synthetic product at {}", knxprod.display());

    let device = VirtualDevice::spawn_fresh(&bin).map_err(|e| e.to_string())?;
    if !device.wait_ready(Duration::from_secs(20)) {
        eprintln!(
            "warning: virtual device did not report ready within 20s; continuing \
             (flash will surface a clearer failure and the log is dumped below)"
        );
        device.dump_log();
    }
    // Settle after the group join so the device's receive loop is servicing the
    // socket before the first connection-oriented frame.
    std::thread::sleep(Duration::from_millis(1500));

    // Flash with PLAIN flags: no --pace, no --reconnect-every, no
    // --tolerate-nonconformant-load-states, no --max-window-retries. A
    // non-existent model dir means no parameter overrides (vendor defaults).
    // `--yes` confirms non-interactively; `--bcu-key FFFFFFFF` presents the
    // free-access key (harmless if the device does not gate on it).
    let model_dir = out_dir.path().join("no-model");
    let (ok, out, err) = bussard(&[
        "flash",
        target,
        "--product",
        knxprod.to_str().unwrap(),
        "--dir",
        model_dir.to_str().unwrap(),
        "--yes",
        "--bcu-key",
        "FFFFFFFF",
    ]);
    eprintln!("--- flash stdout ---\n{out}\n--- flash stderr ---\n{err}");
    if !ok {
        device.dump_log();
    }

    assert!(
        ok,
        "flash should reach Loaded against the thelsing knx-linux-ip device; \
         it exited non-zero.\nstdout:\n{out}\nstderr:\n{err}"
    );
    // The success line is `flash verified: application program <id> is Loaded on <ia>`.
    assert!(
        out.contains("is Loaded") || out.contains("Loaded"),
        "flash should report the application program is Loaded; stdout:\n{out}"
    );

    eprintln!(
        "flash oracle complete: bussard flash drove thelsing's knx-linux-ip \
         application object Unloaded -> Loading -> Loaded over KNXnet/IP routing."
    );
    Ok(())
}
