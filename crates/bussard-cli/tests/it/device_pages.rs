//! `bussard device` on a System 7 application without channels of its own
//! (issue #298), end to end: an ETS project running the fabricated program
//! of `crates/bussard-product/tests/fixtures/blocks_app.xml` (universal
//! channels A, B and C as parameter pages behind "enable" parameters) is
//! imported, and the device view lists the pages in ETS order, marks B and C
//! inactive with the parameter that enables each, and counts them.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_ID: &str = "M-00FA_A-0298-10-0000";
const APP_XML: &[u8] = include_bytes!("../../../bussard-product/tests/fixtures/blocks_app.xml");

/// One device on 1.1.30: channel A enabled with the temperature function.
const PROJECT_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21">
 <Project Id="P-9997">
  <Installations><Installation>
   <Topology><Area Address="1"><Line Address="1">
    <DeviceInstance Id="P-9997-0_DI-1" Address="30" Name="Weather station" Hardware2ProgramRefId="M-00FA_H-1_HP-0298-10-0000">
     <ParameterInstanceRefs>
      <ParameterInstanceRef RefId="M-00FA_A-0298-10-0000_P-1_R-1" Value="1" />
      <ParameterInstanceRef RefId="M-00FA_A-0298-10-0000_P-11_R-11" Value="2" />
     </ParameterInstanceRefs>
    </DeviceInstance>
   </Line></Area></Topology>
  </Installation></Installations>
 </Project>
</KNX>"#;

fn bussard(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

/// Imports the project into a fresh model directory.
fn imported(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!(
        "bussard-device-pages-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let knxproj = dir.join("pages.knxproj");
    let mut zw = zip::ZipWriter::new(std::fs::File::create(&knxproj)?);
    let opts = zip::write::SimpleFileOptions::default();
    zw.start_file("knx_master.xml", opts)?;
    zw.write_all(br#"<KNX xmlns="http://knx.org/xml/project/21"/>"#)?;
    zw.start_file("P-9997/0.xml", opts)?;
    zw.write_all(PROJECT_XML.as_bytes())?;
    zw.start_file(format!("M-00FA/{APP_ID}.xml"), opts)?;
    zw.write_all(APP_XML)?;
    zw.finish()?;
    let model = dir.join("knx");
    let out = bussard(&[
        "import",
        knxproj.to_str().ok_or("path")?,
        "--no-download",
        "--dir",
        model.to_str().ok_or("path")?,
    ])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(model)
}

#[test]
fn test_device_lists_pages_and_marks_the_inactive_ones() -> TestResult {
    let dir = imported("table")?;
    let d = dir.to_str().ok_or("path")?;
    let out = bussard(&["device", "1.1.30", "--dir", d])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("pages (ETS parameter blocks, in ETS order):"),
        "{stdout}"
    );
    let state = |handle: &str| -> Option<String> {
        stdout
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{handle} ")))
            .map(str::to_string)
    };
    let a = state("universal-channel-a-function").ok_or(stdout.to_string())?;
    assert!(a.ends_with("active"), "{a}");
    let b = state("universal-channel-b-function").ok_or(stdout.to_string())?;
    assert!(
        b.contains(
            "inactive: set universal-channel-b-enable = \"yes\" (default \"no\"); shows 1 \
             object(s); shows com-objects, so the push is a flash (a parameter push does not \
             change the object table): `bussard flash 1.1.30`"
        ),
        "{b}"
    );
    let c = state("universal-channel-c-function").ok_or(stdout.to_string())?;
    assert!(
        c.contains("then \"Universal channel C enable\" = \"yes\""),
        "{c}"
    );
    assert!(
        stdout.contains(
            "summary: 2 of 4 pages inactive: 2 Universal channel B: function .. Universal \
             channel C: function"
        ),
        "{stdout}"
    );

    // The JSON carries the same, and a page handle details one page.
    let out = bussard(&["device", "1.1.30", "--json", "--dir", d])?;
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let blocks = json["data"]["blocks"]
        .as_array()
        .or_else(|| json["blocks"].as_array())
        .ok_or("blocks")?;
    assert_eq!(blocks.len(), 4, "{json}");
    let out = bussard(&[
        "device",
        "1.1.30",
        "universal-channel-b-function",
        "--dir",
        d,
    ])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("page universal-channel-b-function (Universal channel B: function)"),
        "{stdout}"
    );
    assert!(stdout.contains("channel-function"), "{stdout}");
    assert!(stdout.contains("B Universal channel: Switch"), "{stdout}");
    std::fs::remove_dir_all(dir.parent().ok_or("parent")?)?;
    Ok(())
}
