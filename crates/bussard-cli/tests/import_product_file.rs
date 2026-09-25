//! CLI tests for `import-product <FILE>`: a vendor `.knxprod` is cached
//! byte-identical under `<dir>/vendor/`, while an ETS project export
//! (`.knxproj`, detected by extension or by its `P-XXXX` project folder) is read
//! in place and never copied there. Both write the generated model.
//!
//! The fixtures are tiny fabricated archives (no vendor data committed).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_ID: &str = "M-0083_A-1234-11-ABCD-O000A";

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-0083">
    <Hardware>
      <Products><Product OrderNumber="MDT-BE-04001.02" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-0083_A-1234-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-0083"><ApplicationPrograms>
  <ApplicationProgram Id="M-0083_A-1234-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Taster BE 04001" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-0" Number="0" Text="Taste 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

/// A minimal unencrypted project folder, as in an ETS export.
const PROJECT_XML: &str =
    r#"<KNX xmlns="http://knx.org/xml/project/23"><Project Id="P-048B" /></KNX>"#;

/// Writes a ZIP archive with the given entries to `path`.
fn write_zip(path: &Path, entries: &[(&str, &str)]) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    for (name, body) in entries {
        zip.start_file(*name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}

/// The product entries shared by both fixtures.
fn product_entries() -> Vec<(&'static str, &'static str)> {
    vec![
        ("knx_master.xml", "<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML),
        ("M-0083/M-0083_A-1234-11-ABCD-O000A.xml", APP_XML),
    ]
}

/// A synthetic project export: the product entries plus a `P-XXXX` folder.
fn project_entries() -> Vec<(&'static str, &'static str)> {
    let mut entries = product_entries();
    entries.push(("P-048B/project.xml", PROJECT_XML));
    entries.push(("P-048B/0.xml", PROJECT_XML));
    entries
}

/// A fresh scratch directory for one test.
fn scratch(name: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-import-product-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Runs `bussard import-product <file> --dir <dir>` in `cwd`.
fn import(cwd: &Path, file: &Path, dir: &Path) -> std::io::Result<(bool, String, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("import-product")
        .arg(file)
        .arg("--dir")
        .arg(dir)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Imports a project export and checks the model is written and nothing
/// lands under `vendor/`.
fn assert_project_export_not_cached(name: &str, file_name: &str) -> TestResult {
    let tmp = scratch(name)?;
    let file = tmp.join(file_name);
    write_zip(&file, &project_entries())?;
    let dir = tmp.join("knx");

    let (ok, stdout, stderr) = import(&tmp, &file, &dir)?;
    assert!(
        ok,
        "import should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Read the ETS project export in place"),
        "expected the in-place note; stdout:\n{stdout}"
    );
    assert!(
        dir.join("models").join(format!("{APP_ID}.yaml")).is_file(),
        "expected the generated model; stdout:\n{stdout}"
    );
    assert!(
        !dir.join("vendor").exists(),
        "a project export must not be cached under vendor/"
    );
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

#[test]
fn test_import_product_knxproj_is_not_cached() -> TestResult {
    assert_project_export_not_cached("knxproj", "home.knxproj")
}

#[test]
fn test_import_product_project_export_detected_by_container() -> TestResult {
    // A renamed export still carries its P-XXXX project folder.
    assert_project_export_not_cached("renamed", "home-export.zip")
}

#[test]
fn test_import_product_knxprod_is_cached_byte_identical() -> TestResult {
    let tmp = scratch("knxprod")?;
    let file = tmp.join("taster.knxprod");
    write_zip(&file, &product_entries())?;
    let dir = tmp.join("knx");

    let (ok, stdout, stderr) = import(&tmp, &file, &dir)?;
    assert!(
        ok,
        "import should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Cached vendor file:"),
        "expected the cache note; stdout:\n{stdout}"
    );
    let cached = std::fs::read(dir.join("vendor").join("taster.knxprod"))?;
    assert_eq!(
        cached,
        std::fs::read(&file)?,
        "cache must be byte-identical"
    );
    assert!(dir.join("vendor").join(".gitignore").is_file());
    assert!(dir.join("models").join(format!("{APP_ID}.yaml")).is_file());
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// The `[[product]]` block of `<dir>/bussard.lock`.
fn lock_text(dir: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(dir.join("bussard.lock"))
}

/// The SHA-256 of a file, lowercase hex.
fn sha256_hex(path: &Path) -> std::io::Result<String> {
    use sha2::Digest as _;
    let bytes = std::fs::read(path)?;
    Ok(sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[test]
fn test_import_product_pins_the_archive_and_links_the_device() -> TestResult {
    let tmp = scratch("pin")?;
    let file = tmp.join("taster.knxprod");
    write_zip(&file, &product_entries())?;
    let dir = tmp.join("knx");
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices/1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Taster\"\nproduct = \"MDT-BE-04001.02\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 1\n\n[[device]]\naddress = \"1.1.4\"\nproduct = \"MDT-BE-04001.02\"\n\
             application = \"{APP_ID}\"\n"
        ),
    )?;

    let (ok, stdout, stderr) = import(&tmp, &file, &dir)?;
    assert!(ok, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("pinned the product data of 1 device(s)"),
        "{stdout}"
    );
    let sha = sha256_hex(&file)?;
    let lock = lock_text(&dir)?;
    assert!(lock.contains("version = 2\n"), "{lock}");
    assert!(lock.contains(&format!("sha256 = \"{sha}\"")), "{lock}");
    assert!(lock.contains("file = \"vendor/taster.knxprod\""), "{lock}");
    assert!(lock.contains("origin = { kind = \"file\""), "{lock}");
    assert!(
        lock.contains("order_numbers = [\"MDT-BE-04001.02\"]"),
        "{lock}"
    );
    assert!(
        lock.contains(&format!("product_sha256 = \"{sha}\"")),
        "{lock}"
    );
    // The model still loads and validates with the pinned archive.
    let model = bussard_model::Model::load(&dir)?;
    let codes: Vec<&str> = bussard_model::validate_in_dir(&model, &dir)
        .iter()
        .map(|d| d.code)
        .collect();
    assert!(
        !codes.iter().any(|c| *c == "E032" || *c == "E033"),
        "{codes:?}"
    );
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

#[test]
fn test_import_product_project_export_is_pinned_by_its_hash() -> TestResult {
    let tmp = scratch("pin-knxproj")?;
    let file = tmp.join("home.knxproj");
    write_zip(&file, &project_entries())?;
    let dir = tmp.join("knx");
    let (ok, stdout, stderr) = import(&tmp, &file, &dir)?;
    assert!(ok, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let sha = sha256_hex(&file)?;
    let lock = lock_text(&dir)?;
    assert!(lock.contains("origin = { kind = \"knxproj\""), "{lock}");
    assert!(
        lock.contains(&format!("project_hash = \"{sha}\"")),
        "{lock}"
    );
    assert!(
        !lock.contains("file = "),
        "an export is not held in the model: {lock}"
    );
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}
