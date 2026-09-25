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

/// A synthetic program (bussard's own work, MIT; no vendor data) whose enum
/// labels differ between its default language (en-US) and its de-DE layer,
/// as the Jung heating actuator's `_RE_Betriebsart_RSM` of issue #231.
/// `Both` is the English label of member 2 and the German label of member 3.
/// Member 3 shows `P-2` (value 5), which is written only in that branch
/// (the program does not download invisible parameters).
const BILINGUAL_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0003" ApplicationNumber="3" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard label test app" LoadProcedureStyle="ProductDefault"
            DefaultLanguage="en-US">
          <Static>
            <Options DownloadInvisibleParameters="None" />
            <Code>
              <RelativeSegment Id="M-00FA_A-0003_RS-1" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0003_PT-1" Name="mode"><TypeRestriction Base="Value" SizeInBit="8">
                <Enumeration Text="Heating" Value="0" Id="M-00FA_A-0003_PT-1_EN-0" />
                <Enumeration Text="Cooling" Value="1" Id="M-00FA_A-0003_PT-1_EN-1" />
                <Enumeration Text="Both" Value="2" Id="M-00FA_A-0003_PT-1_EN-2" />
                <Enumeration Text="Heating and cooling" Value="3" Id="M-00FA_A-0003_PT-1_EN-3" />
              </TypeRestriction></ParameterType>
              <ParameterType Id="M-00FA_A-0003_PT-2" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0003_P-1" Name="mode" Text="Mode" ParameterType="M-00FA_A-0003_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0003_RS-1" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0003_P-2" Name="extra" Text="Extra" ParameterType="M-00FA_A-0003_PT-2" Value="5"><Memory CodeSegment="M-00FA_A-0003_RS-1" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0003_P-1_R-1" RefId="M-00FA_A-0003_P-1" />
              <ParameterRef Id="M-00FA_A-0003_P-2_R-2" RefId="M-00FA_A-0003_P-2" />
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
              <ParameterBlock Id="M-00FA_A-0003_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0003_P-1_R-1" />
                <choose ParamRefId="M-00FA_A-0003_P-1_R-1">
                  <when test="3"><ParameterRefRef RefId="M-00FA_A-0003_P-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
          <Languages>
            <Language Identifier="de-DE">
              <TranslationUnit RefId="M-00FA_A-0003">
                <TranslationElement RefId="M-00FA_A-0003_PT-1_EN-0"><Translation AttributeName="Text" Text="Heizen" /></TranslationElement>
                <TranslationElement RefId="M-00FA_A-0003_PT-1_EN-1"><Translation AttributeName="Text" Text="K&#252;hlen" /></TranslationElement>
                <TranslationElement RefId="M-00FA_A-0003_PT-1_EN-2"><Translation AttributeName="Text" Text="Beides" /></TranslationElement>
                <TranslationElement RefId="M-00FA_A-0003_PT-1_EN-3"><Translation AttributeName="Text" Text="Both" /></TranslationElement>
              </TranslationUnit>
            </Language>
          </Languages>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

/// Writes the bilingual program as `<dir>/labels.knxprod`.
fn build_bilingual_knxprod(dir: &Path) -> Result<PathBuf, String> {
    let archive = dir.join("labels.knxprod");
    let file = std::fs::File::create(&archive).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "M-00FA/M-00FA_A-0003.xml",
        zip::write::SimpleFileOptions::default(),
    )
    .map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut zip, BILINGUAL_APP_XML.as_bytes()).map_err(|e| e.to_string())?;
    zip.finish().map_err(|e| e.to_string())?;
    Ok(archive)
}

/// Dry-runs a flash of 1.0.10 from a model whose lock records `language`
/// (none when `None`) and whose device file sets `mode` to `label`; returns
/// the parameter segment image, or the failing run's stderr.
fn bilingual_image(tag: &str, language: Option<&str>, label: &str) -> Result<Vec<u8>, String> {
    let tmp = TmpDir::new(tag).map_err(|e| e.to_string())?;
    let knxprod = build_bilingual_knxprod(tmp.path())?;
    let model = tmp.path().join("knx");
    std::fs::create_dir_all(model.join("devices")).map_err(|e| e.to_string())?;
    let language = language
        .map(|l| format!("language = \"{l}\"\n"))
        .unwrap_or_default();
    std::fs::write(
        model.join("bussard.lock"),
        format!(
            "version = 1\n{language}\n[[device]]\naddress = \"1.0.10\"\n\
             application = \"M-00FA_A-0003\"\nmask = \"07B0\"\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        model.join("devices").join("1.0.10.toml"),
        format!(
            "address = \"1.0.10\"\nname = \"Label test\"\n\n[parameters]\n\"mode@P-1_R-1\" = \"{label}\"\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    let dump = tmp.path().join("dump");
    let path = |p: &Path| p.to_str().map(str::to_string).ok_or("non-UTF-8 temp path");
    let (ok, stdout, stderr) = bussard(&[
        "flash",
        "1.0.10",
        "--product",
        &path(&knxprod)?,
        "--dir",
        &path(&model)?,
        "--dry-run",
        "--dump-images",
        &path(&dump)?,
    ]);
    if !ok {
        return Err(format!("stdout:\n{stdout}\nstderr:\n{stderr}"));
    }
    let raw = std::fs::read_to_string(dump.join("plan.json")).map_err(|e| e.to_string())?;
    let plan: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let file = plan["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["image"]["file"].as_str())
        .find(|f| f.contains("RS-1"))
        .ok_or(format!("no parameter image in {raw}"))?;
    std::fs::read(dump.join(file)).map_err(|e| e.to_string())
}

#[test]
fn test_flash_dry_run_enum_label_in_lock_language_resolves() -> Result<(), String> {
    // Issue #231: the lock says de-DE and the device file carries the German
    // label, as `import` writes it. The byte is the member's value, and the
    // branch the member selects is taken (P-2 written with its default 5).
    assert_eq!(
        bilingual_image("de-label", Some("de-DE"), "Kühlen")?,
        [1, 0]
    );
    // `Both` is member 3 in German, member 2 in English: the lock's language
    // decides.
    assert_eq!(bilingual_image("de-both", Some("de-DE"), "Both")?, [3, 5]);
    assert_eq!(bilingual_image("en-both", None, "Both")?, [2, 0]);
    // The English (default-language) label still resolves under a de-DE lock.
    assert_eq!(
        bilingual_image("de-english", Some("de-DE"), "Heating and cooling")?,
        [3, 5]
    );
    Ok(())
}

#[test]
fn test_flash_dry_run_unknown_enum_label_lists_lock_language_labels() -> Result<(), String> {
    let err = match bilingual_image("de-unknown", Some("de-DE"), "Lüften") {
        Ok(image) => return Err(format!("an unknown label was accepted: {image:?}")),
        Err(err) => err,
    };
    if !err.contains("Heizen | Kühlen | Beides | Both") {
        return Err(format!(
            "the refusal does not list the German labels: {err}"
        ));
    }
    Ok(())
}
