//! The retained product store `<dir>/products/` (issue #228, item 3): the
//! one-shot move of an earlier `vendor/`, the regeneration of
//! `.bussard/models/` when it is absent, empty or incomplete (#267), and the
//! refusals when an archive the
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

/// Issue #267: an existing but empty `.bussard/models/` is filled by the
/// next command, and E026 does not tell the user to fetch anything.
#[test]
fn test_empty_models_directory_is_filled_by_the_next_command() -> TestResult {
    let dir = pinned_model("regen-empty", false, true)?;
    std::fs::write(
        dir.join("devices/1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Taster\"\nproduct = \"MDT-BE-04001.02\"\n\n\
         [parameters]\n\"x@P-1\" = \"1\"\n\n[links]\n0.send = \"1/0/0\"\n",
    )?;
    let models = dir.join(".bussard/models");
    std::fs::create_dir_all(&models)?;
    let out = bussard(&dir, &["validate"])?;
    let said = text(&out);
    assert!(
        models.join(format!("{APP_ID}.yaml")).is_file(),
        "validate fills the empty directory: {said}"
    );
    assert!(!said.contains("E026"), "{said}");
    cleanup(&dir);
    Ok(())
}

/// Issue #267: a single deleted model file is restored while the directory
/// keeps its other content.
#[test]
fn test_deleted_model_file_is_restored() -> TestResult {
    let dir = pinned_model("regen-one", false, true)?;
    let model_file = dir.join(format!(".bussard/models/{APP_ID}.yaml"));
    let out = bussard(&dir, &["validate"])?;
    assert!(model_file.is_file(), "{}", text(&out));
    let other = dir.join(".bussard/models/M-0001_A-0000-10-0000.yaml");
    std::fs::write(&other, "# another application\n")?;
    std::fs::remove_file(&model_file)?;
    let out = bussard(&dir, &["status"])?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(model_file.is_file(), "status restores it: {}", text(&out));
    assert!(other.is_file());
    cleanup(&dir);
    Ok(())
}

/// Issue #267: E026 names `bussard import-product` only when no stored
/// archive carries the application.
#[test]
fn test_e026_names_import_product_only_without_an_archive() -> TestResult {
    let dir = pinned_model("regen-e026", false, false)?;
    std::fs::write(
        dir.join("devices/1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Taster\"\nproduct = \"MDT-BE-04001.02\"\n\n\
         [parameters]\n\"x@P-1\" = \"1\"\n\n[links]\n0.send = \"1/0/0\"\n",
    )?;
    let said = text(&bussard(&dir, &["validate"])?);
    assert!(said.contains("E026"), "{said}");
    assert!(
        said.contains("no stored archive carries it; run `bussard import-product`"),
        "{said}"
    );
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

/// Another archive for the same product: same catalogue, different bytes.
fn write_other_knxprod(path: &Path) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML),
        (&format!("M-0083/{APP_ID}.xml") as &str, APP_XML),
        ("M-0083/Catalog.xml", "<KNX/>"),
    ] {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}

#[test]
fn test_override_that_contradicts_the_lock_is_refused_unless_force() -> TestResult {
    let dir = pinned_model("override", false, true)?;
    let other = dir.parent().ok_or("root")?.join("other.knxprod");
    write_other_knxprod(&other)?;
    let other_str = other.to_str().ok_or("path")?;

    // flash and apply refuse, before any bus access.
    let out = bussard(&dir, &["flash", "1.1.4", "--product", other_str, "--yes"])?;
    assert_refused(&out, "refusing to flash 1.1.4: --product");
    assert_refused(&out, "but bussard.lock pins");
    let out = bussard(&dir, &["apply", "1.1.4", "--product", other_str, "--yes"])?;
    assert_refused(&out, "refusing to apply to 1.1.4: --product");
    let out = bussard(
        &dir,
        &[
            "apply",
            "1.1.4",
            "--application",
            "M-0083_A-9999-10-0000",
            "--yes",
        ],
    )?;
    assert_refused(&out, "is not the application bussard.lock pins for 1.1.4");

    // A dry run only warns.
    let out = bussard(
        &dir,
        &["flash", "1.1.4", "--product", other_str, "--dry-run"],
    )?;
    assert!(
        text(&out).contains("a dry run writes nothing"),
        "{}",
        text(&out)
    );

    // --force uses it and pins it (the closed loopback port then fails the
    // connection, after the lock changed).
    let _ = bussard(
        &dir,
        &["flash", "1.1.4", "--product", other_str, "--force", "--yes"],
    )?;
    let sha = sha256_hex(&other)?;
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    assert!(
        lock.contains(&format!("product_sha256 = \"{sha}\"")),
        "{lock}"
    );
    assert!(lock.contains("file = \"products/other.knxprod\""), "{lock}");
    cleanup(&dir);
    Ok(())
}

#[test]
fn test_flash_from_an_export_needs_no_application_when_the_lock_pins_it() -> TestResult {
    let dir = pinned_model("export-app", false, true)?;
    let export = dir.parent().ok_or("root")?.join("home.knxproj");
    let second = APP_XML.replace("A-1234-11-ABCD", "A-5678-11-ABCD");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&export)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML),
        (&format!("M-0083/{APP_ID}.xml") as &str, APP_XML),
        ("M-0083/M-0083_A-5678-11-ABCD-O000A.xml", second.as_str()),
        ("P-048B/project.xml", "<KNX/>"),
    ] {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    let out = bussard(
        &dir,
        &[
            "flash",
            "1.1.4",
            "--product",
            export.to_str().ok_or("path")?,
            "--dry-run",
        ],
    )?;
    let said = text(&out);
    assert!(
        !said.contains("cannot select an application program"),
        "{said}"
    );
    assert!(
        !said.contains("but bussard.lock pins"),
        "an export is compared by application: {said}"
    );
    cleanup(&dir);
    Ok(())
}

/// A synthetic program (bussard's own work, MIT; no vendor data) whose enum
/// labels differ between its default language (en-US) and its de-DE layer:
/// `Cooling` is `Kühlen` in German. The same program as `flash_dry_run.rs`
/// uses for issue #231, here as manufacturer `M-9999`, application
/// `M-9999_A-0001-1-0000` and order number `TST-1`, the identity the small
/// xknxproject fixture's device carries.
const BILINGUAL_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-9999">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-9999_A-0001-1-0000" ApplicationNumber="3" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard label test app" LoadProcedureStyle="ProductDefault"
            DefaultLanguage="en-US">
          <Static>
            <Options DownloadInvisibleParameters="None" />
            <Code>
              <RelativeSegment Id="M-9999_A-0001-1-0000_RS-1" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-9999_A-0001-1-0000_PT-1" Name="mode"><TypeRestriction Base="Value" SizeInBit="8">
                <Enumeration Text="Heating" Value="0" Id="M-9999_A-0001-1-0000_PT-1_EN-0" />
                <Enumeration Text="Cooling" Value="1" Id="M-9999_A-0001-1-0000_PT-1_EN-1" />
                <Enumeration Text="Both" Value="2" Id="M-9999_A-0001-1-0000_PT-1_EN-2" />
                <Enumeration Text="Heating and cooling" Value="3" Id="M-9999_A-0001-1-0000_PT-1_EN-3" />
              </TypeRestriction></ParameterType>
              <ParameterType Id="M-9999_A-0001-1-0000_PT-2" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-9999_A-0001-1-0000_P-1" Name="mode" Text="Mode" ParameterType="M-9999_A-0001-1-0000_PT-1" Value="0"><Memory CodeSegment="M-9999_A-0001-1-0000_RS-1" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-9999_A-0001-1-0000_P-2" Name="extra" Text="Extra" ParameterType="M-9999_A-0001-1-0000_PT-2" Value="5"><Memory CodeSegment="M-9999_A-0001-1-0000_RS-1" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-9999_A-0001-1-0000_P-1_R-1" RefId="M-9999_A-0001-1-0000_P-1" />
              <ParameterRef Id="M-9999_A-0001-1-0000_P-2_R-2" RefId="M-9999_A-0001-1-0000_P-2" />
            </ParameterRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="full" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="full" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-9999_A-0001-1-0000_PB-1" Name="main">
                <ParameterRefRef RefId="M-9999_A-0001-1-0000_P-1_R-1" />
                <choose ParamRefId="M-9999_A-0001-1-0000_P-1_R-1">
                  <when test="3"><ParameterRefRef RefId="M-9999_A-0001-1-0000_P-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
          <Languages>
            <Language Identifier="de-DE">
              <TranslationUnit RefId="M-9999_A-0001-1-0000">
                <TranslationElement RefId="M-9999_A-0001-1-0000_PT-1_EN-0"><Translation AttributeName="Text" Text="Heizen" /></TranslationElement>
                <TranslationElement RefId="M-9999_A-0001-1-0000_PT-1_EN-1"><Translation AttributeName="Text" Text="K&#252;hlen" /></TranslationElement>
                <TranslationElement RefId="M-9999_A-0001-1-0000_PT-1_EN-2"><Translation AttributeName="Text" Text="Beides" /></TranslationElement>
                <TranslationElement RefId="M-9999_A-0001-1-0000_PT-1_EN-3"><Translation AttributeName="Text" Text="Both" /></TranslationElement>
              </TranslationUnit>
            </Language>
          </Languages>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

/// The bilingual program's application id.
const BILINGUAL_APP: &str = "M-9999_A-0001-1-0000";

/// Writes the bilingual program as a `.knxprod` whose catalogue lists it for
/// order number `TST-1`.
fn write_bilingual_knxprod(path: &Path) -> TestResult {
    let hardware = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-9999"><Hardware>
<Products><Product OrderNumber="TST-1" /></Products>
<Hardware2Programs><Hardware2Program><ApplicationProgramRef RefId="{BILINGUAL_APP}" /></Hardware2Program></Hardware2Programs>
</Hardware></Manufacturer></ManufacturerData></KNX>"#
    );
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>".to_string()),
        ("M-9999/Hardware.xml", hardware),
        (
            &format!("M-9999/{BILINGUAL_APP}.xml") as &str,
            BILINGUAL_APP_XML.to_string(),
        ),
    ] {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}

/// The E017 diagnostics of a `validate --json` run.
fn e017(out: &Output) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("{e}: {}", text(out)))?;
    let list = report
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("no diagnostics in {report}"))?;
    Ok(list
        .iter()
        .filter(|d| d.get("code").and_then(serde_json::Value::as_str) == Some("E017"))
        .cloned()
        .collect())
}

/// Issue #255: the product models a command regenerates at start are parsed
/// in the lock's language, so a German enum label in a device file resolves
/// (before the fix they were English and `Kühlen` read as E017).
#[test]
fn test_regenerated_models_follow_the_lock_language() -> TestResult {
    let dir = std::env::temp_dir()
        .join(format!("bussard-store-regen-de-{}", std::process::id()))
        .join("knx");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join("products"))?;
    let archive = dir.join("products/labels.knxprod");
    write_bilingual_knxprod(&archive)?;
    let sha = sha256_hex(&archive)?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 2\nlanguage = \"de-DE\"\n\n[[product]]\nsha256 = \"{sha}\"\n\
             file = \"products/labels.knxprod\"\nfilename = \"labels.knxprod\"\n\
             origin = {{ kind = \"file\", path = \"labels.knxprod\" }}\n\
             applications = [\"{BILINGUAL_APP}\"]\norder_numbers = [\"TST-1\"]\n\n\
             [[device]]\naddress = \"1.0.10\"\nproduct = \"TST-1\"\n\
             application = \"{BILINGUAL_APP}\"\nproduct_sha256 = \"{sha}\"\nmask = \"07B0\"\n"
        ),
    )?;
    std::fs::write(
        dir.join("devices/1.0.10.toml"),
        "address = \"1.0.10\"\nname = \"Label test\"\nproduct = \"TST-1\"\n\n\
         [parameters]\n\"mode@P-1_R-1\" = \"K\u{fc}hlen\"\n",
    )?;

    let out = bussard(&dir, &["validate", "--json"])?;
    let model = std::fs::read_to_string(dir.join(format!(".bussard/models/{BILINGUAL_APP}.yaml")))?;
    assert!(model.contains("K\u{fc}hlen"), "{model}");
    assert!(!model.contains("Cooling"), "{model}");
    let errors = e017(&out)?;
    assert!(errors.is_empty(), "{errors:?}");
    cleanup(&dir);
    Ok(())
}

/// Issue #255: a fresh import into a model whose `[import] language` is
/// de-DE leaves `.bussard/models/` written in German, and the next
/// `validate` reports no E017.
#[test]
fn test_fresh_import_writes_the_models_in_the_lock_language() -> TestResult {
    let root = std::env::temp_dir().join(format!("bussard-store-import-de-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("knx");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n\n\
         [import]\nlanguage = \"de-DE\"\n",
    )?;
    let archive = root.join("labels.knxprod");
    write_bilingual_knxprod(&archive)?;
    let bytes = std::fs::read(&archive)?;
    let index = root.join("index.json");
    std::fs::write(
        &index,
        serde_json::to_string(&serde_json::json!({ "entries": [{
            "manufacturer": "Test Manufacturer",
            "manufacturer_id": "M-9999",
            "order_numbers": ["TST-1"],
            "name": "Label test",
            "url": format!("file://{}", archive.display()),
            "sha256": sha256_hex(&archive)?,
            "size": bytes.len(),
            "filename": "labels.knxprod",
        }] }))?,
    )?;
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-project/tests/fixtures/tiny.xknxproject.json");
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["import", "--from-json"])
        .arg(&fixture)
        .arg("--dir")
        .arg(&dir)
        .arg("--yes-download")
        .env("BUSSARD_PRODUCT_INDEX", &index)
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    assert!(out.status.success(), "{}", text(&out));
    // An xknxproject dump records no lock language; the model's language is
    // then `[import] language` (`product_cache::model_language`).
    let model = std::fs::read_to_string(dir.join(format!(".bussard/models/{BILINGUAL_APP}.yaml")))?;
    assert!(model.contains("K\u{fc}hlen"), "{model}");

    let out = bussard(&dir, &["validate", "--json"])?;
    let errors = e017(&out)?;
    assert!(errors.is_empty(), "{errors:?}");
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
