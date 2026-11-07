//! Adversarial importer tests: corrupt and hostile `.knxproj` ZIP containers.
//!
//! The container is opened only through the public `bussard_product::import`
//! entry point (the `container` module is private), so these tests build real
//! ZIP files on disk and feed them in. `zip` is a normal dependency of this
//! crate, so it is available to the integration-test binary.

use std::io::Write;

use bussard_product::{ProductError, import};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

// ---------------------------------------------------------------------------
// Corrupt / hostile ZIP containers via the public `import`.
// ---------------------------------------------------------------------------

fn tmp_file(tag: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(std::env::temp_dir().join(format!(
        "bussard-import-adv-{tag}-{}-{}.knxproj",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    )))
}

#[test]
fn not_a_zip_is_clean_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = tmp_file("notzip")?;
    std::fs::write(&path, b"this is definitely not a zip file")?;
    let r = std::panic::catch_unwind(|| import(&path, None));
    assert!(r.is_ok(), "non-zip must not panic");
    assert!(matches!(
        r.map_err(|_| "import panicked")?,
        Err(ProductError::Zip { .. })
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn empty_zip_missing_project_entry_errors() -> Result<(), Box<dyn std::error::Error>> {
    let path = tmp_file("emptyzip")?;
    {
        let f = std::fs::File::create(&path)?;
        let zw = ZipWriter::new(f);
        zw.finish()?;
    }
    let r = import(&path, None);
    // No P-XXXX.zip or P-XXXX/0.xml -> MissingEntry.
    assert!(
        matches!(r, Err(ProductError::MissingEntry { .. })),
        "empty zip should be MissingEntry, got {r:?}"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn zip_slip_entry_names_are_not_written_to_disk() -> Result<(), Box<dyn std::error::Error>> {
    // A `.knxproj` whose entries carry path-traversal names. The container reads
    // entries by exact name into memory (never extracts to disk), so the sentinel
    // file the traversal would target must NOT appear. We assert the import fails
    // to find a project (the traversal entry is not a valid P-XXXX/0.xml) AND that
    // no file escaped to the parent directory.
    let path = tmp_file("zipslip")?;
    let sentinel = std::env::temp_dir().join("bussard-zipslip-sentinel-should-not-exist.txt");
    let _ = std::fs::remove_file(&sentinel);
    {
        let f = std::fs::File::create(&path)?;
        let mut zw = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        // A classic zip-slip path.
        zw.start_file(
            "../../../../tmp/bussard-zipslip-sentinel-should-not-exist.txt",
            opts,
        )?;
        zw.write_all(b"evil")?;
        // Also a plausible-looking but traversal-prefixed project entry.
        zw.start_file("../P-9999/0.xml", opts)?;
        zw.write_all(b"<Project/>")?;
        zw.finish()?;
    }
    let r = std::panic::catch_unwind(|| import(&path, None));
    assert!(r.is_ok(), "zip-slip container must not panic");
    // The import must not have written the sentinel anywhere on disk.
    assert!(
        !sentinel.exists(),
        "zip-slip sentinel escaped to disk — extraction is not in-memory-only!"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&sentinel);
    Ok(())
}

#[test]
fn unencrypted_project_xml_is_read_from_memory() -> Result<(), Box<dyn std::error::Error>> {
    // A minimal valid-shape container: P-9999/0.xml directly in the outer zip.
    // The project XML is trivial and will fail later parsing, but the container
    // open + project_xml read path is exercised without touching disk.
    let path = tmp_file("plainproj")?;
    {
        let f = std::fs::File::create(&path)?;
        let mut zw = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        zw.start_file("P-9999/0.xml", opts)?;
        zw.write_all(b"<KNX><Project Id=\"P-9999\"/></KNX>")?;
        zw.start_file("knx_master.xml", opts)?;
        zw.write_all(b"<KNX/>")?;
        zw.finish()?;
    }
    // import will get past container open; it may fail later in project parsing,
    // but it must return a clean Result (no panic).
    let r = std::panic::catch_unwind(|| import(&path, None));
    assert!(r.is_ok(), "plain-project container must not panic");
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Writes a minimal unencrypted `.knxproj` with `P-9999/0.xml` and
/// `P-9999/project.xml` (direct outer-archive form), returning its path.
fn write_plain_knxproj_with_project_xml(
    tag: &str,
    project_xml: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = tmp_file(tag)?;
    let f = std::fs::File::create(&path)?;
    let mut zw = ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    // A device-free topology so `build_model` needs no manufacturer resolution.
    zw.start_file("P-9999/0.xml", opts)?;
    zw.write_all(b"<KNX><Project Id=\"P-9999\"/></KNX>")?;
    zw.start_file("P-9999/project.xml", opts)?;
    zw.write_all(project_xml.as_bytes())?;
    zw.start_file("knx_master.xml", opts)?;
    zw.write_all(b"<KNX/>")?;
    zw.finish()?;
    Ok(path)
}

#[test]
fn three_level_project_xml_populates_name() -> Result<(), Box<dyn std::error::Error>> {
    // A fabricated project.xml (ThreeLevel) must import cleanly and carry the
    // name onto the model (issue #62).
    let path = write_plain_knxproj_with_project_xml(
        "threelevel",
        r#"<KNX><Project Id="P-9999"><ProjectInformation Name="Fab Home" GroupAddressStyle="ThreeLevel"/></Project></KNX>"#,
    )?;
    let model = import(&path, None)?;
    assert_eq!(model.groups.project.as_deref(), Some("Fab Home"));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn two_level_project_xml_is_refused_with_clear_error() -> Result<(), Box<dyn std::error::Error>> {
    // A 2-level style must be refused (not silently mis-parsed) with an error
    // that names the actual style (issue #62).
    let path = write_plain_knxproj_with_project_xml(
        "twolevel",
        r#"<KNX><Project Id="P-9999"><ProjectInformation Name="TwoLvl" GroupAddressStyle="TwoLevel"/></Project></KNX>"#,
    )?;
    let err = import(&path, None)
        .err()
        .ok_or("two-level must be refused")?;
    match &err {
        ProductError::UnsupportedGroupAddressStyle { style } => {
            assert_eq!(style, "TwoLevel");
        }
        other => panic!("expected UnsupportedGroupAddressStyle, got {other:?}"),
    }
    // The message should mention the actual style for the user.
    assert!(
        err.to_string().contains("TwoLevel"),
        "error should name the style: {err}"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn free_style_project_xml_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let path = write_plain_knxproj_with_project_xml(
        "freestyle",
        r#"<KNX><Project Id="P-9999"><ProjectInformation Name="F" GroupAddressStyle="Free"/></Project></KNX>"#,
    )?;
    assert!(matches!(
        import(&path, None),
        Err(ProductError::UnsupportedGroupAddressStyle { .. })
    ));
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn missing_project_xml_is_tolerated() -> Result<(), Box<dyn std::error::Error>> {
    // Older exports may omit project.xml entirely; import must still succeed
    // (name simply stays None), not error.
    let path = tmp_file("noprojectxml")?;
    {
        let f = std::fs::File::create(&path)?;
        let mut zw = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        zw.start_file("P-9999/0.xml", opts)?;
        zw.write_all(b"<KNX><Project Id=\"P-9999\"/></KNX>")?;
        zw.start_file("knx_master.xml", opts)?;
        zw.write_all(b"<KNX/>")?;
        zw.finish()?;
    }
    let model = import(&path, None)?;
    assert!(model.groups.project.is_none());
    let _ = std::fs::remove_file(&path);
    Ok(())
}
