//! `bussard flash --dry-run --dump-images` (the offline conformance oracle,
//! issue #89): the plan and the exact images a flash would stream are written to
//! disk without any bus access. No gateway is configured in any of these tests,
//! so a dry run that tried to resolve or reach one would fail them.
//!
//! The synthetic test zips the committed interop application
//! (`tests-support/virtual-device/knxprod/`) with the `zip` CLI and skips green
//! when `zip` is unavailable. The corpus test needs `BUSSARD_PRODUCT_CORPUS`
//! pointing at the product-corpus cache and skips green without it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use sha2::{Digest, Sha256};

/// A self-cleaning temporary directory (no `tempfile` dev-dependency needed).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bussard-flash-dry-run-{tag}-{}-{n}",
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

/// Zips the committed interop application into a `.knxprod`, or `None` when
/// the `zip` CLI is unavailable.
fn build_knxprod(out_dir: &Path) -> Option<PathBuf> {
    let root = std::fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests-support/virtual-device/knxprod"),
    )
    .ok()?;
    let archive = out_dir.join("interop.knxprod");
    let status = Command::new("zip")
        .current_dir(&root)
        .args(["-r", "-X", "-q"])
        .arg(&archive)
        .arg("M-00FA")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    status.success().then_some(archive)
}

/// Runs `bussard` with no gateway in the environment; returns (success,
/// stdout, stderr).
fn bussard(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_GATEWAY")
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(err) => (false, String::new(), err.to_string()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Checks every image record in `plan.json` against the file it names.
fn assert_images_match(dump: &Path, plan: &serde_json::Value) -> Result<usize, String> {
    let steps = plan["steps"]
        .as_array()
        .ok_or("plan.json has no steps array")?;
    let mut images = 0;
    for step in steps {
        let Some(image) = step.get("image") else {
            continue;
        };
        let file = image["file"]
            .as_str()
            .ok_or("image record without a file")?;
        let bytes = std::fs::read(dump.join(file)).map_err(|e| format!("reading {file}: {e}"))?;
        if image["length"].as_u64() != Some(bytes.len() as u64) {
            return Err(format!("{file}: length does not match plan.json"));
        }
        if image["sha256"].as_str() != Some(sha256_hex(&bytes).as_str()) {
            return Err(format!("{file}: sha256 does not match plan.json"));
        }
        images += 1;
    }
    Ok(images)
}

#[test]
fn test_flash_dry_run_dump_images_writes_plan_and_images_without_a_gateway() -> Result<(), String> {
    let tmp = TmpDir::new("synthetic").map_err(|e| e.to_string())?;
    let Some(knxprod) = build_knxprod(tmp.path()) else {
        eprintln!("skipping: the `zip` CLI is unavailable to build the synthetic .knxprod");
        return Ok(());
    };
    // An empty model directory: no bussard.toml, so no gateway anywhere.
    let model = tmp.path().join("knx");
    std::fs::create_dir_all(&model).map_err(|e| e.to_string())?;
    let dump = tmp.path().join("dump");

    let (ok, stdout, stderr) = bussard(&[
        "flash",
        "1.0.10",
        "--product",
        knxprod.to_str().ok_or("non-UTF-8 temp path")?,
        "--dir",
        model.to_str().ok_or("non-UTF-8 temp path")?,
        "--dry-run",
        "--dump-images",
        dump.to_str().ok_or("non-UTF-8 temp path")?,
    ]);
    if !ok {
        return Err(format!(
            "dry run failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        ));
    }
    if !stderr.contains("no connection opened") {
        return Err(format!("missing the dry-run notice: {stderr}"));
    }
    if !stdout.contains("Flash plan for 1.0.10") {
        return Err(format!("missing the pre-flight plan: {stdout}"));
    }

    let raw = std::fs::read_to_string(dump.join("plan.json")).map_err(|e| e.to_string())?;
    let plan: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if plan["device"] != "1.0.10" || plan["system"] != "B" {
        return Err(format!("unexpected plan header: {raw}"));
    }
    let images = assert_images_match(&dump, &plan)?;
    if images == 0 {
        return Err(format!("no streamed image recorded: {raw}"));
    }
    // The relative segment is keyed by object and segment id, never an address.
    let rel = plan["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.get("image"))
        .find(|i| i["address"].is_null())
        .ok_or("no relative-segment image")?;
    if !rel["file"].as_str().unwrap_or_default().starts_with("obj") {
        return Err(format!("relative image not keyed by object: {rel}"));
    }
    if plan["allocations"].as_array().is_none_or(|a| a.is_empty()) {
        return Err(format!("no allocation recorded: {raw}"));
    }
    Ok(())
}

#[test]
fn test_flash_dump_images_requires_dry_run() -> Result<(), String> {
    let (ok, _, stderr) = bussard(&[
        "flash",
        "1.0.10",
        "--product",
        "/nonexistent.knxprod",
        "--dump-images",
        "/nonexistent-dump",
    ]);
    if ok || !stderr.contains("--dry-run") {
        return Err(format!(
            "--dump-images without --dry-run must be refused: {stderr}"
        ));
    }
    Ok(())
}

/// Finds `name` at most three directory levels under `dir`.
fn find_file(dir: &Path, name: &str, depth: u32) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.is_file() {
        return Some(direct);
    }
    if depth == 0 {
        return None;
    }
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .find_map(|p| find_file(&p, name, depth - 1))
}

/// A real System 7 product (Jung 3361-1 M presence detector, mask 0705): the
/// absolute segments are keyed by address, the group-address table carries its
/// mask, and the LSM tables are dumped.
#[test]
fn test_flash_dry_run_dump_images_system7_corpus_product() -> Result<(), String> {
    let Some(corpus) = std::env::var_os("BUSSARD_PRODUCT_CORPUS").map(PathBuf::from) else {
        eprintln!("skipping: BUSSARD_PRODUCT_CORPUS is unset");
        return Ok(());
    };
    let Some(knxprod) = find_file(&corpus, "de_3361-1m_V1.3_2020-05.knxprod", 3) else {
        eprintln!("skipping: the Jung 3361-1 M product is not in the corpus");
        return Ok(());
    };
    let tmp = TmpDir::new("sys7").map_err(|e| e.to_string())?;
    let model = tmp.path().join("knx");
    std::fs::create_dir_all(&model).map_err(|e| e.to_string())?;
    let dump = tmp.path().join("dump");
    let (ok, stdout, stderr) = bussard(&[
        "flash",
        "1.0.10",
        "--product",
        knxprod.to_str().ok_or("non-UTF-8 path")?,
        "--dir",
        model.to_str().ok_or("non-UTF-8 path")?,
        "--dry-run",
        "--json",
        "--dump-images",
        dump.to_str().ok_or("non-UTF-8 path")?,
    ]);
    if !ok {
        return Err(format!(
            "dry run failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        ));
    }
    let raw = std::fs::read_to_string(dump.join("plan.json")).map_err(|e| e.to_string())?;
    let plan: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if plan["system"] != "7" || plan["device_mask"] != "0705" {
        return Err(format!("unexpected plan header: {raw}"));
    }
    assert_images_match(&dump, &plan)?;
    for file in [
        "0x004000.bin",
        "0x004000.mask.bin",
        "table-lsm1.bin",
        "table-lsm1.mask.bin",
        "table-lsm2.bin",
    ] {
        if !dump.join(file).is_file() {
            return Err(format!("{file} was not written"));
        }
    }
    let tables = plan["tables"].as_array().ok_or("no tables array")?;
    if !tables
        .iter()
        .any(|t| t["name"] == "lsm1" && t["address"] == 0x4000)
    {
        return Err(format!("the LSM 1 table is not at 0x4000: {raw}"));
    }
    Ok(())
}
