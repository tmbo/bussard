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
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
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
    assert!(!dir.join("products").exists(), "nothing downloaded");
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
    assert!(
        stdout.contains("imported 2 group addresses, 1 devices"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("re-import"),
        "a fresh import, not a merge: {stdout}"
    );
    assert!(stdout.contains("validation: 0 error(s)"), "{stdout}");
    assert!(stdout.contains("bussard device <address>"), "{stdout}");
    let config = std::fs::read_to_string(dir.join("bussard.toml"))?;
    assert!(config.contains("transport = \"routing\""), "{config}");
    assert!(dir.join("devices/1.1.1.toml").is_file());
    assert!(dir.join("groups.toml").is_file());
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// A tiny fabricated `.knxprod` whose catalogue maps `TST-1` to the fixture
/// device's application (no vendor data committed).
fn tst_knxprod(path: &Path) -> TestResult {
    use std::io::Write as _;
    const APP: &str = "M-9999_A-0001-1-0000";
    let hardware = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-9999"><Hardware>
<Products><Product OrderNumber="TST-1" /></Products>
<Hardware2Programs><Hardware2Program><ApplicationProgramRef RefId="{APP}" /></Hardware2Program></Hardware2Programs>
</Hardware></Manufacturer></ManufacturerData></KNX>"#
    );
    let app = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-9999"><ApplicationPrograms>
<ApplicationProgram Id="{APP}" ApplicationNumber="1" ApplicationVersion="1" MaskVersion="MV-07B0" Name="Test" LoadProcedureStyle="MergedProcedure"><Static /></ApplicationProgram>
</ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#
    );
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>".to_string()),
        ("M-9999/Hardware.xml", hardware),
        (&format!("M-9999/{APP}.xml") as &str, app),
    ] {
        zip.start_file(name, zip::write::SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}

#[test]
fn test_import_pins_the_downloaded_product_data_in_the_lock() -> TestResult {
    use sha2::Digest as _;
    let tmp = tmp("pin")?;
    let dir = tmp.join("knx");
    let knxprod = tmp.join("tst.knxprod");
    tst_knxprod(&knxprod)?;
    let bytes = std::fs::read(&knxprod)?;
    let sha: String = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let known = index(
        &tmp,
        serde_json::json!([{
            "manufacturer": "Test Manufacturer",
            "manufacturer_id": "M-9999",
            "order_numbers": ["TST-1"],
            "name": "Test Switch Actuator",
            "url": format!("file://{}", knxprod.display()),
            "sha256": sha,
            "size": bytes.len(),
            "filename": "tst.knxprod",
        }]),
    )?;
    let out = bussard(
        &[
            "import",
            "--from-json",
            fixture().to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--yes-download",
        ],
        &[("BUSSARD_PRODUCT_INDEX", known.to_str().ok_or("path")?)],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    assert!(lock.contains("version = 2\n"), "{lock}");
    assert!(lock.contains("[[product]]"), "{lock}");
    assert!(lock.contains(&format!("sha256 = \"{sha}\"")), "{lock}");
    assert!(lock.contains("file = \"products/tst.knxprod\""), "{lock}");
    assert!(
        lock.contains("origin = { kind = \"index\", order_number = \"TST-1\""),
        "{lock}"
    );
    assert!(
        lock.contains(&format!("product_sha256 = \"{sha}\"")),
        "{lock}"
    );

    // A re-import keeps the device linked to the archive.
    let again = bussard(
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
    assert!(again.status.success());
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    assert!(
        lock.contains(&format!("product_sha256 = \"{sha}\"")),
        "{lock}"
    );
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Issue #205: a `.knxkeys` exported next to the project is recorded as
/// `connection.keyring` (relative to the model directory), `init` prints the
/// password reminder, and `validate` resolves the recorded path. The keyring
/// is the committed synthetic one; nothing decrypts it here.
#[test]
fn test_init_records_the_keyring_next_to_the_project() -> TestResult {
    let tmp = tmp("init-keyring")?;
    let project = tmp.join("project.json");
    std::fs::copy(fixture(), &project)?;
    let synthetic = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../knx-sim/examples/secure/synthetic.knxkeys");
    std::fs::copy(&synthetic, tmp.join("Site.knxkeys"))?;
    let dir = tmp.join("knx");
    let out = bussard(
        &[
            "init",
            project.to_str().ok_or("path")?,
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
    assert!(stdout.contains("Found the ETS keyring"), "{stdout}");
    assert!(stdout.contains("BUSSARD_KEYRING_PASSWORD"), "{stdout}");
    assert!(stdout.contains("bussard keys import"), "{stdout}");
    // Without the password no store can be written.
    assert!(!dir.join("bussard.keys").exists());
    // The recorded path resolves to the keyring (compared as paths, not
    // strings, so the check holds on Windows too).
    let config = bussard_model::load_config(&dir)?;
    let recorded = config
        .connection
        .keyring_path(&dir)
        .ok_or("init recorded no connection.keyring")?;
    assert_eq!(
        std::fs::canonicalize(&recorded)?,
        std::fs::canonicalize(tmp.join("Site.knxkeys"))?,
        "recorded {}",
        recorded.display()
    );
    let text = std::fs::read_to_string(dir.join("bussard.toml"))?;
    assert!(!text.contains('\\'), "forward slashes only: {text}");

    // `validate` resolves it: present, and without the password one info line.
    let out = bussard(
        &[
            "validate",
            "--dir",
            dir.to_str().ok_or("path")?,
            "--format",
            "json",
        ],
        &[],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("E027"), "{stdout}");

    // A keyring that went away is an error naming the file.
    std::fs::remove_file(tmp.join("Site.knxkeys"))?;
    let out = bussard(&["validate", "--dir", dir.to_str().ok_or("path")?], &[])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "{stdout}");
    assert!(stdout.contains("error[E027]"), "{stdout}");
    assert!(stdout.contains("Site.knxkeys"), "{stdout}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Issue #241 item 2: with the password set, `init` (through its import)
/// merges the `.knxkeys` next to the project into `bussard.keys` and records
/// no `connection.keyring`; a re-import with a newer export merges again.
#[test]
fn test_init_and_import_create_the_key_store_from_a_neighbouring_keyring() -> TestResult {
    let tmp = tmp("init-keystore")?;
    let project = tmp.join("project.json");
    std::fs::copy(fixture(), &project)?;
    let synthetic = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../knx-sim/examples/secure/synthetic.knxkeys");
    std::fs::copy(&synthetic, tmp.join("Site.knxkeys"))?;
    let dir = tmp.join("knx");
    let password = [("BUSSARD_KEYRING_PASSWORD", "synthetic-keyring-pw")];
    let out = bussard(
        &[
            "init",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--routing",
            "--no-download",
        ],
        &password,
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Imported the ETS keyring"), "{stdout}");
    assert!(stdout.contains("created"), "{stdout}");
    assert_eq!(
        stdout.matches("BUSSARD_KEYRING_PASSWORD").count(),
        1,
        "one password reminder: {stdout}"
    );
    assert!(dir.join("bussard.keys").exists());
    let config = bussard_model::load_config(&dir)?;
    assert!(
        config.connection.keyring_path(&dir).is_none(),
        "no connection.keyring with a store"
    );
    let gitignore = std::fs::read_to_string(dir.join(".gitignore"))?;
    assert!(gitignore.contains("*.knxkeys"), "{gitignore}");

    // A plain re-import finds the same export: nothing changes.
    let out = bussard(
        &[
            "import",
            "--from-json",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--no-download",
        ],
        &password,
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("already up to date"), "{stdout}");
    assert!(!dir.join("bussard.keys.bak").exists());

    // A wrong password warns and leaves the import (and the store) alone.
    let out = bussard(
        &[
            "import",
            "--from-json",
            project.to_str().ok_or("path")?,
            "--dir",
            dir.to_str().ok_or("path")?,
            "--no-download",
        ],
        &[("BUSSARD_KEYRING_PASSWORD", "wrong")],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("was not imported"), "{stderr}");
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}
