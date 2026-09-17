//! End-to-end import tests for older ETS namespace versions (issue #9, ETS 4/5).
//!
//! These build **synthetic** `.knxproj` archives in memory — hand-written XML,
//! no real project data and nothing vendored from any third-party project — and
//! run them through the public [`bussard_project::import`] entry point. They
//! exercise:
//!
//! * schema-version detection from `knx_master.xml` (ETS 4 = 11, ETS 5 = 14,
//!   ETS 6 = 21),
//! * the `Project.xml` (capital P, ETS 4) vs `project.xml` (ETS 5/6) filename,
//! * the group-address plan parsing across versions, and
//! * the ETS 6 WinZip-AES + PBKDF2 password path end-to-end (a protected
//!   archive built with the same derived password the importer computes).
//!
//! The ETS 4/5 ZipCrypto *password* derivation (raw UTF-8, no KDF) is covered by
//! unit tests in `password.rs`; the `zip` crate does not expose a public API to
//! *write* a ZipCrypto entry, so the encrypted end-to-end case here uses the
//! ETS 6 AES path.

use std::io::{Cursor, Write};

use zip::write::{FileOptions, SimpleFileOptions};
use zip::{AesMode, ZipWriter};

/// A minimal `knx_master.xml` declaring a given schema-version namespace.
fn knx_master(version: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/{version}">
  <MasterData>
    <Manufacturers>
      <Manufacturer Id="M-0001" Name="Test Manufacturer"/>
    </Manufacturers>
  </MasterData>
</KNX>"#
    )
}

/// A minimal project `0.xml` with a two-level group-address plan and one GA.
fn project_0_xml(version: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/{version}">
  <Project Id="P-0001">
    <Installations><Installation>
      <GroupAddresses><GroupRanges>
        <GroupRange Id="P-0001_GR-1" Name="Ground floor" RangeStart="2048">
          <GroupRange Id="P-0001_GR-2" Name="Lighting" RangeStart="2048">
            <GroupAddress Id="P-0001_GA-10" Address="2049" Name="Living room light" DatapointType="DPST-1-1"/>
          </GroupRange>
        </GroupRange>
      </GroupRanges></GroupAddresses>
    </Installation></Installations>
  </Project>
</KNX>"#
    )
}

/// A minimal `project.xml`/`Project.xml` naming the project (ThreeLevel style).
fn project_info_xml(version: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/{version}">
  <Project Id="P-0001">
    <ProjectInformation Name="Synthetic {version} Home" GroupAddressStyle="ThreeLevel"/>
  </Project>
</KNX>"#
    )
}

/// Builds an **unprotected** `.knxproj` in memory: `knx_master.xml` plus the
/// project files stored directly under `P-0001/` (no inner archive).
///
/// `info_filename` is `Project.xml` for ETS 4, `project.xml` otherwise.
fn build_unprotected(version: u32, info_filename: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default();
        let mut add = |name: &str, body: &str| {
            zip.start_file(name, opts).expect("start_file");
            zip.write_all(body.as_bytes()).expect("write");
        };
        add("knx_master.xml", &knx_master(version));
        add("P-0001/0.xml", &project_0_xml(version));
        add(
            &format!("P-0001/{info_filename}"),
            &project_info_xml(version),
        );
        zip.finish().expect("finish");
    }
    buf
}

/// Builds an ETS 6 **AES-protected** `.knxproj` in memory: the project files are
/// packed into an inner `P-0001.zip` encrypted with `zip_password` (the derived
/// archive password), which the outer archive stores. This mirrors the real ETS
/// 6 on-disk layout.
fn build_ets6_protected(zip_password: &str) -> Vec<u8> {
    // Inner archive, AES-encrypted with the derived password.
    let mut inner = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut inner));
        let opts: FileOptions<'_, ()> =
            FileOptions::default().with_aes_encryption(AesMode::Aes256, zip_password);
        zip.start_file("0.xml", opts).expect("inner 0.xml");
        zip.write_all(project_0_xml(21).as_bytes()).expect("write");
        let opts2: FileOptions<'_, ()> =
            FileOptions::default().with_aes_encryption(AesMode::Aes256, zip_password);
        zip.start_file("project.xml", opts2)
            .expect("inner project.xml");
        zip.write_all(project_info_xml(21).as_bytes())
            .expect("write");
        zip.finish().expect("inner finish");
    }

    // Outer archive: knx_master + the encrypted inner archive.
    let mut outer = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut outer));
        let opts = SimpleFileOptions::default();
        zip.start_file("knx_master.xml", opts).expect("master");
        zip.write_all(knx_master(21).as_bytes()).expect("write");
        zip.start_file("P-0001.zip", opts).expect("inner entry");
        zip.write_all(&inner).expect("write inner");
        zip.finish().expect("outer finish");
    }
    outer
}

/// Writes `bytes` to a temp `.knxproj` and returns the temp file (kept alive by
/// the caller so the path stays valid).
fn temp_knxproj(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(".knxproj")
        .tempfile()
        .expect("tempfile");
    f.write_all(bytes).expect("write knxproj");
    f.flush().expect("flush");
    f
}

#[test]
fn test_import_ets4_unprotected_project() -> anyhow::Result<()> {
    // ETS 4: schema 11, project info in `Project.xml` (capital P).
    let bytes = build_unprotected(11, "Project.xml");
    let f = temp_knxproj(&bytes);
    let model = bussard_project::import(f.path(), None)?;

    // Project name from Project.xml, and the GA plan parsed.
    assert_eq!(model.groups.project.as_deref(), Some("Synthetic 11 Home"));
    let ga: bussard_model::GroupAddress = "1/0/1".parse()?;
    let g = model.groups.groups.get(&ga).expect("GA 1/0/1 present");
    assert_eq!(g.name, "Living room light");
    assert_eq!(g.dpt.map(|d| d.to_string()).as_deref(), Some("1.001"));
    // Range names flattened from the two-level tree.
    assert_eq!(
        model.groups.ranges.get("1").map(|r| r.name.as_str()),
        Some("Ground floor")
    );
    Ok(())
}

#[test]
fn test_import_ets5_unprotected_project() -> anyhow::Result<()> {
    // ETS 5: schema 14, project info in lowercase `project.xml`.
    let bytes = build_unprotected(14, "project.xml");
    let f = temp_knxproj(&bytes);
    let model = bussard_project::import(f.path(), None)?;
    assert_eq!(model.groups.project.as_deref(), Some("Synthetic 14 Home"));
    let ga: bussard_model::GroupAddress = "1/0/1".parse()?;
    assert!(model.groups.groups.contains_key(&ga));
    Ok(())
}

#[test]
fn test_import_ets6_aes_protected_project() -> anyhow::Result<()> {
    // The importer derives this same archive password from the user password
    // "test" via the ETS 6 PBKDF2 scheme; build the fixture with it so the
    // encrypted end-to-end path is exercised.
    let derived = bussard_project::derive_zip_password("test");
    let bytes = build_ets6_protected(&derived);
    let f = temp_knxproj(&bytes);

    // Wrong / missing password is rejected.
    let missing = bussard_project::import(f.path(), None);
    assert!(matches!(
        missing,
        Err(bussard_project::ImportError::PasswordRequired)
    ));

    // Correct user password decrypts and imports.
    let model = bussard_project::import(f.path(), Some("test"))?;
    assert_eq!(model.groups.project.as_deref(), Some("Synthetic 21 Home"));
    let ga: bussard_model::GroupAddress = "1/0/1".parse()?;
    assert!(model.groups.groups.contains_key(&ga));
    Ok(())
}

#[test]
fn test_import_rejects_unknown_schema_version() {
    // A namespace below the earliest known version (11) is refused with a clear
    // diagnostic rather than silently mis-parsed.
    let bytes = build_unprotected(9, "project.xml");
    let f = temp_knxproj(&bytes);
    let err = bussard_project::import(f.path(), None).expect_err("should reject schema 9");
    assert!(matches!(
        err,
        bussard_project::ImportError::UnsupportedSchemaVersion { .. }
    ));
}
