//! `bussard import` end to end on the small xknxproject JSON fixture: the
//! group addresses a device uses are declared, the model is validated after
//! the write, and the summary names the devices written without product data.
//! No bus and no network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The fixture shared with `bussard-project`'s import tests.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-project/tests/fixtures/tiny.xknxproject.json")
}

fn tmp(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-import-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn bussard(args: &[&str], envs: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.args(args)
        .env_remove("BUSSARD_PRODUCT_INDEX")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
}

/// The fixture with the switch object also listening on `1/0/9`, which the
/// project does not define.
fn fixture_with_undefined_ga(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(fixture())?;
    let text = text.replace(
        "\"group_address_links\": [\"1/0/1\"]",
        "\"group_address_links\": [\"1/0/1\", \"1/0/9\"]",
    );
    let path = dir.join("project.json");
    std::fs::write(&path, text)?;
    Ok(path)
}

#[test]
fn test_import_declares_a_group_address_the_project_uses_but_does_not_define() -> TestResult {
    let tmp = tmp("declare")?;
    let project = fixture_with_undefined_ga(&tmp)?;
    let dir = tmp.join("knx");
    let out = bussard(
        &[
            "import",
            "--from-json",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("added 1/0/9 \"Test Switch Actuator object 0\""),
        "{stdout}"
    );
    let groups = std::fs::read_to_string(dir.join("groups.toml"))?;
    assert!(groups.contains("\"1/0/9\""), "{groups}");
    // Validation runs after the write and prints its summary.
    assert!(stdout.contains("validation: 0 error(s)"), "{stdout}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Writes a pointer index with the given entries.
fn index(dir: &Path, entries: serde_json::Value) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("index.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({ "entries": entries }))?,
    )?;
    Ok(path)
}

#[test]
fn test_import_names_the_order_numbers_it_found_no_product_data_for() -> TestResult {
    let tmp = tmp("missing")?;
    let dir = tmp.join("knx");
    let empty = index(&tmp, serde_json::json!([]))?;
    let out = bussard(
        &[
            "import",
            "--from-json",
            fixture().to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
        ],
        &[("BUSSARD_PRODUCT_INDEX", empty.to_str().ok_or("path")?)],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    // The device still gets its file.
    assert!(dir.join("devices/1.1.1.toml").is_file());
    assert!(
        stdout.contains("1 device(s) written without product data"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "TST-1: not in bussard's product index. Download the product data (.knxprod) from \
             the manufacturer's website"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("bussard import-product <file>"), "{stdout}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

#[test]
fn test_import_no_download_lists_what_the_index_could_fetch() -> TestResult {
    let tmp = tmp("no-download")?;
    let dir = tmp.join("knx");
    let known = index(
        &tmp,
        serde_json::json!([{
            "manufacturer": "Test Manufacturer",
            "manufacturer_id": "M-9999",
            "order_numbers": ["TST-1"],
            "name": "Test Switch Actuator",
            "url": "file:///nonexistent/never-read.knxprod",
            "sha256": "00",
            "size": 1,
            "filename": "never-read.knxprod",
        }]),
    )?;
    let out = bussard(
        &[
            "import",
            "--from-json",
            fixture().to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--no-download",
        ],
        &[("BUSSARD_PRODUCT_INDEX", known.to_str().ok_or("path")?)],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains(
            "TST-1: in bussard's product index but --no-download; run `bussard import-product \
             --order-number TST-1"
        ),
        "{stdout}"
    );
    assert!(!dir.join("vendor").exists(), "nothing downloaded");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// The first run is one command: `init <project>` writes `bussard.toml`, then
/// imports the project into the fresh directory (not a re-import).
#[test]
fn test_init_with_a_project_file_imports_it() -> TestResult {
    let tmp = tmp("init")?;
    let dir = tmp.join("knx");
    let out = bussard(
        &[
            "init",
            fixture().to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--routing",
            "--no-download",
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Importing"), "{stdout}");
    assert!(stdout.contains("imported 2 group addresses, 1 devices"), "{stdout}");
    assert!(!stdout.contains("re-import"), "a fresh import, not a merge: {stdout}");
    assert!(stdout.contains("validation: 0 error(s)"), "{stdout}");
    assert!(stdout.contains("bussard device <address>"), "{stdout}");
    let config = std::fs::read_to_string(dir.join("bussard.toml"))?;
    assert!(config.contains("transport = \"routing\""), "{config}");
    assert!(dir.join("devices/1.1.1.toml").is_file());
    assert!(dir.join("groups.toml").is_file());
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}
