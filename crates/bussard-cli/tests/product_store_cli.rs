//! The retained product store `<dir>/products/` (issue #228, item 3): the
//! one-shot move of an earlier `vendor/`, the regeneration of
//! `.bussard/models/` when it is absent, and the refusals when an archive the
//! lock pins is missing or changed. No bus: every refusal happens before a
//! connection is opened (the configured gateway is a closed loopback port).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn write_knxprod(path: &Path) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML),
        (&format!("M-0083/{APP_ID}.xml") as &str, APP_XML),
    ] {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}

fn sha256_hex(path: &Path) -> std::io::Result<String> {
    use sha2::Digest as _;
    Ok(sha2::Sha256::digest(std::fs::read(path)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// A model with device 1.1.4 (one link, so `apply` has a plan) and a v2
/// lock; `lock_extra` is appended (a `[[product]]` entry and the device's
/// link, when a test pins one).
fn model(
    tag: &str,
    product_block: &str,
    device_link: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir()
        .join(format!("bussard-store-{tag}-{}", std::process::id()))
        .join("knx");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/0\", name = \"Licht\", dpt = \"1.001\" },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices/1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Taster\"\nproduct = \"MDT-BE-04001.02\"\n\n[links]\n0.send = \"1/0/0\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 2\n{product_block}\n[[device]]\naddress = \"1.1.4\"\nproduct = \"MDT-BE-04001.02\"\n\
             application = \"{APP_ID}\"\n{device_link}mask = \"07B0\"\n"
        ),
    )?;
    Ok(dir)
}

fn product_block(sha: &str) -> String {
    format!(
        "\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/taster.knxprod\"\n\
         filename = \"taster.knxprod\"\norigin = {{ kind = \"index\", order_number = \
         \"MDT-BE-04001.02\" }}\napplications = [\"{APP_ID}\"]\norder_numbers = \
         [\"MDT-BE-04001.02\"]\n"
    )
}

fn bussard(dir: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .arg("--dir")
        .arg(dir)
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env("BUSSARD_PRODUCT_INDEX", "/nonexistent/index.json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn cleanup(dir: &Path) {
    if let Some(root) = dir.parent() {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn test_vendor_directory_moves_into_products_and_is_pinned() -> TestResult {
    let dir = model("migrate", "", "")?;
    std::fs::create_dir_all(dir.join("vendor"))?;
    write_knxprod(&dir.join("vendor/taster.knxprod"))?;
    std::fs::write(dir.join("vendor/.gitignore"), "*\n")?;
    let sha = sha256_hex(&dir.join("vendor/taster.knxprod"))?;

    let out = bussard(&dir, &["validate"])?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("moved"), "{}", text(&out));
    assert!(!dir.join("vendor").exists(), "the empty vendor/ is removed");
    assert_eq!(sha256_hex(&dir.join("products/taster.knxprod"))?, sha);
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    assert!(
        lock.contains("file = \"products/taster.knxprod\""),
        "{lock}"
    );
    assert!(
        lock.contains(&format!("product_sha256 = \"{sha}\"")),
        "{lock}"
    );
    assert!(dir.join(format!(".bussard/models/{APP_ID}.yaml")).is_file());

    // Idempotent: the second run has nothing to move.
    let out = bussard(&dir, &["validate"])?;
    assert!(!text(&out).contains("moved"), "{}", text(&out));
    cleanup(&dir);
    Ok(())
}

#[test]
fn test_absent_dot_bussard_regenerates_the_product_models() -> TestResult {
    let dir = model("regen", "", "")?;
    let src = dir.parent().ok_or("root")?.join("taster.knxprod");
    write_knxprod(&src)?;
    let out = bussard(&dir, &["import-product", src.to_str().ok_or("path")?])?;
    assert!(out.status.success(), "{}", text(&out));
    let model_file = dir.join(format!(".bussard/models/{APP_ID}.yaml"));
    assert!(model_file.is_file());

    std::fs::remove_dir_all(dir.join(".bussard"))?;
    for args in [&["validate"][..], &["status"], &["device", "1.1.4"]] {
        let out = bussard(&dir, args)?;
        assert!(out.status.success(), "{args:?}: {}", text(&out));
        assert!(model_file.is_file(), "{args:?} regenerates the models");
        std::fs::remove_dir_all(dir.join(".bussard"))?;
    }
    cleanup(&dir);
    Ok(())
}

/// The model pins `products/taster.knxprod`; `state` prepares the store.
fn pinned_model(
    tag: &str,
    changed: bool,
    present: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let scratch =
        std::env::temp_dir().join(format!("bussard-store-src-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&scratch)?;
    let src = scratch.join("taster.knxprod");
    write_knxprod(&src)?;
    let sha = sha256_hex(&src)?;
    let dir = model(
        tag,
        &product_block(&sha),
        &format!("product_sha256 = \"{sha}\"\n"),
    )?;
    if present {
        std::fs::create_dir_all(dir.join("products"))?;
        if changed {
            std::fs::write(
                dir.join("products/taster.knxprod"),
                b"not the pinned archive",
            )?;
        } else {
            std::fs::copy(&src, dir.join("products/taster.knxprod"))?;
        }
    }
    std::fs::remove_dir_all(&scratch)?;
    Ok(dir)
}

fn assert_refused(out: &Output, needle: &str) {
    let said = text(out);
    assert!(!out.status.success(), "must refuse: {said}");
    assert!(said.contains(needle), "expected {needle:?} in: {said}");
}

#[test]
fn test_flash_refuses_a_missing_or_changed_archive() -> TestResult {
    let missing = pinned_model("flash-missing", false, false)?;
    let out = bussard(&missing, &["flash", "1.1.4", "--dry-run"])?;
    assert_refused(
        &out,
        "product data for 1.1.4 (MDT-BE-04001.02, products/taster.knxprod",
    );
    assert_refused(
        &out,
        "bussard import-product --order-number MDT-BE-04001.02",
    );
    cleanup(&missing);

    let changed = pinned_model("flash-changed", true, true)?;
    let out = bussard(&changed, &["flash", "1.1.4", "--dry-run"])?;
    assert_refused(&out, "but bussard.lock pins");
    cleanup(&changed);

    // The intact archive plans.
    let good = pinned_model("flash-good", false, true)?;
    let out = bussard(&good, &["flash", "1.1.4", "--dry-run"])?;
    assert!(!text(&out).contains("is missing"), "{}", text(&out));
    cleanup(&good);
    Ok(())
}

#[test]
fn test_apply_refuses_a_missing_archive_before_the_bus() -> TestResult {
    let dir = pinned_model("apply-missing", false, false)?;
    let out = bussard(&dir, &["apply", "1.1.4", "--yes"])?;
    assert_refused(&out, "product data for 1.1.4");
    assert!(!text(&out).contains("connect"), "{}", text(&out));
    cleanup(&dir);
    Ok(())
}

#[test]
fn test_plan_warns_and_reads_links_only_without_the_archive() -> TestResult {
    let dir = pinned_model("plan-missing", false, false)?;
    // plan reaches for the bus after the warning; the closed port fails it,
    // but the warning comes first.
    let out = bussard(&dir, &["plan", "1.1.4"])?;
    assert!(
        text(&out).contains("warning: product data for 1.1.4"),
        "{}",
        text(&out)
    );
    cleanup(&dir);
    Ok(())
}

#[test]
fn test_commission_flash_refuses_a_missing_archive_before_the_bus() -> TestResult {
    let dir = pinned_model("commission-missing", false, false)?;
    let out = bussard(&dir, &["commission", "--line", "1.1", "--flash", "--yes"])?;
    assert_refused(
        &out,
        "refusing to commission with --flash: product data is missing",
    );
    assert_refused(&out, "product data for 1.1.4");
    cleanup(&dir);
    Ok(())
}
