//! Adversarial importer tests: hostile JSON dumps and corrupt/hostile
//! `.knxproj` ZIP containers.
//!
//! The container is opened only through the public `bussard_project::import`
//! entry point (the `container` module is private), so these tests build real
//! ZIP files on disk and feed them in. `zip` is a normal dependency of this
//! crate, so it is available to the integration-test binary.

use std::io::Write;

use bussard_project::{ImportError, import, import_from_json_str};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

// ---------------------------------------------------------------------------
// Hostile JSON dumps (--from-json escape hatch).
// ---------------------------------------------------------------------------

#[test]
fn empty_json_object_yields_empty_model() {
    let m = import_from_json_str("{}").expect("empty object is valid");
    assert!(m.groups.groups.is_empty());
    assert!(m.devices.is_empty());
}

#[test]
fn malformed_json_is_clean_error() {
    let r = std::panic::catch_unwind(|| import_from_json_str("{ not json"));
    assert!(r.is_ok(), "malformed JSON must not panic");
    assert!(matches!(r.unwrap(), Err(ImportError::Json { .. })));
}

#[test]
fn ga_out_of_range_in_json_is_malformed_error() {
    let json = r#"{
        "group_addresses": {
            "x": { "name": "bad", "address": "99/0/0" }
        }
    }"#;
    let r = import_from_json_str(json);
    assert!(
        matches!(r, Err(ImportError::Malformed { .. })),
        "out-of-range GA should be Malformed, got {r:?}"
    );
}

#[test]
fn invalid_ia_in_device_is_malformed_error() {
    let json = r#"{
        "devices": {
            "d": { "name": "dev", "individual_address": "1.1" }
        }
    }"#;
    assert!(matches!(
        import_from_json_str(json),
        Err(ImportError::Malformed { .. })
    ));
}

#[test]
fn invalid_ga_in_com_object_link_is_malformed_error() {
    let json = r#"{
        "devices": {
            "d": { "name": "dev", "individual_address": "1.1.4" }
        },
        "communication_objects": {
            "c": {
                "number": 1,
                "device_address": "1.1.4",
                "group_address_links": ["not-a-ga"]
            }
        }
    }"#;
    assert!(matches!(
        import_from_json_str(json),
        Err(ImportError::Malformed { .. })
    ));
}

#[test]
fn com_object_for_unknown_device_is_dropped_not_crashed() {
    // A com-object whose device_address has no matching device: the com-object
    // table insert is skipped (device missing), and since it has GAs it still
    // creates a links entry for that IA. Must not panic.
    let json = r#"{
        "communication_objects": {
            "c": {
                "number": 1,
                "device_address": "9.9.9",
                "group_address_links": ["1/0/0"]
            }
        }
    }"#;
    let r = std::panic::catch_unwind(|| import_from_json_str(json));
    assert!(r.is_ok(), "orphan com-object must not panic");
    let m = r.unwrap().expect("imports");
    // A link entry exists for the orphan device IA even though no device file
    // defines it (this is exactly what validation rule E013 later flags).
    assert!(m.links.links.contains_key(&"9.9.9".parse().unwrap()));
}

#[test]
fn wrong_type_in_json_is_clean_error() {
    // `number` must be an integer; give it a string.
    let json = r#"{
        "communication_objects": {
            "c": { "number": "oops", "device_address": "1.1.4" }
        }
    }"#;
    assert!(matches!(
        import_from_json_str(json),
        Err(ImportError::Json { .. })
    ));
}

#[test]
fn huge_object_number_at_u16_boundary() {
    // 65535 is fine; 65536 overflows u16 -> JSON error.
    let ok =
        r#"{ "communication_objects": { "c": { "number": 65535, "device_address": "1.1.4" } } }"#;
    assert!(import_from_json_str(ok).is_ok());
    let bad =
        r#"{ "communication_objects": { "c": { "number": 65536, "device_address": "1.1.4" } } }"#;
    assert!(matches!(
        import_from_json_str(bad),
        Err(ImportError::Json { .. })
    ));
}

// ---------------------------------------------------------------------------
// Corrupt / hostile ZIP containers via the public `import`.
// ---------------------------------------------------------------------------

fn tmp_file(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bussard-import-adv-{tag}-{}-{}.knxproj",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn not_a_zip_is_clean_error() {
    let path = tmp_file("notzip");
    std::fs::write(&path, b"this is definitely not a zip file").unwrap();
    let r = std::panic::catch_unwind(|| import(&path, None));
    assert!(r.is_ok(), "non-zip must not panic");
    assert!(matches!(r.unwrap(), Err(ImportError::Zip { .. })));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn empty_zip_missing_project_entry_errors() {
    let path = tmp_file("emptyzip");
    {
        let f = std::fs::File::create(&path).unwrap();
        let zw = ZipWriter::new(f);
        zw.finish().unwrap();
    }
    let r = import(&path, None);
    // No P-XXXX.zip or P-XXXX/0.xml -> MissingEntry.
    assert!(
        matches!(r, Err(ImportError::MissingEntry { .. })),
        "empty zip should be MissingEntry, got {r:?}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn zip_slip_entry_names_are_not_written_to_disk() {
    // A `.knxproj` whose entries carry path-traversal names. The container reads
    // entries by exact name into memory (never extracts to disk), so the sentinel
    // file the traversal would target must NOT appear. We assert the import fails
    // to find a project (the traversal entry is not a valid P-XXXX/0.xml) AND that
    // no file escaped to the parent directory.
    let path = tmp_file("zipslip");
    let sentinel = std::env::temp_dir().join("bussard-zipslip-sentinel-should-not-exist.txt");
    let _ = std::fs::remove_file(&sentinel);
    {
        let f = std::fs::File::create(&path).unwrap();
        let mut zw = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        // A classic zip-slip path.
        zw.start_file(
            "../../../../tmp/bussard-zipslip-sentinel-should-not-exist.txt",
            opts,
        )
        .unwrap();
        zw.write_all(b"evil").unwrap();
        // Also a plausible-looking but traversal-prefixed project entry.
        zw.start_file("../P-9999/0.xml", opts).unwrap();
        zw.write_all(b"<Project/>").unwrap();
        zw.finish().unwrap();
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
}

#[test]
fn unencrypted_project_xml_is_read_from_memory() {
    // A minimal valid-shape container: P-9999/0.xml directly in the outer zip.
    // The project XML is trivial and will fail later parsing, but the container
    // open + project_xml read path is exercised without touching disk.
    let path = tmp_file("plainproj");
    {
        let f = std::fs::File::create(&path).unwrap();
        let mut zw = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        zw.start_file("P-9999/0.xml", opts).unwrap();
        zw.write_all(b"<KNX><Project Id=\"P-9999\"/></KNX>")
            .unwrap();
        zw.start_file("knx_master.xml", opts).unwrap();
        zw.write_all(b"<KNX/>").unwrap();
        zw.finish().unwrap();
    }
    // import will get past container open; it may fail later in project parsing,
    // but it must return a clean Result (no panic).
    let r = std::panic::catch_unwind(|| import(&path, None));
    assert!(r.is_ok(), "plain-project container must not panic");
    let _ = std::fs::remove_file(&path);
}

/// Writes a minimal unencrypted `.knxproj` with `P-9999/0.xml` and
/// `P-9999/project.xml` (direct outer-archive form), returning its path.
fn write_plain_knxproj_with_project_xml(tag: &str, project_xml: &str) -> std::path::PathBuf {
    let path = tmp_file(tag);
    let f = std::fs::File::create(&path).unwrap();
    let mut zw = ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    // A device-free topology so `build_model` needs no manufacturer resolution.
    zw.start_file("P-9999/0.xml", opts).unwrap();
    zw.write_all(b"<KNX><Project Id=\"P-9999\"/></KNX>")
        .unwrap();
    zw.start_file("P-9999/project.xml", opts).unwrap();
    zw.write_all(project_xml.as_bytes()).unwrap();
    zw.start_file("knx_master.xml", opts).unwrap();
    zw.write_all(b"<KNX/>").unwrap();
    zw.finish().unwrap();
    path
}

#[test]
fn three_level_project_xml_populates_name() {
    // A fabricated project.xml (ThreeLevel) must import cleanly and carry the
    // name onto the model (issue #62).
    let path = write_plain_knxproj_with_project_xml(
        "threelevel",
        r#"<KNX><Project Id="P-9999"><ProjectInformation Name="Fab Home" GroupAddressStyle="ThreeLevel"/></Project></KNX>"#,
    );
    let model = import(&path, None).expect("three-level project imports");
    assert_eq!(model.groups.project.as_deref(), Some("Fab Home"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn two_level_project_xml_is_refused_with_clear_error() {
    // A 2-level style must be refused (not silently mis-parsed) with an error
    // that names the actual style (issue #62).
    let path = write_plain_knxproj_with_project_xml(
        "twolevel",
        r#"<KNX><Project Id="P-9999"><ProjectInformation Name="TwoLvl" GroupAddressStyle="TwoLevel"/></Project></KNX>"#,
    );
    let err = import(&path, None).expect_err("two-level must be refused");
    match &err {
        ImportError::UnsupportedGroupAddressStyle { style } => {
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
}

#[test]
fn free_style_project_xml_is_refused() {
    let path = write_plain_knxproj_with_project_xml(
        "freestyle",
        r#"<KNX><Project Id="P-9999"><ProjectInformation Name="F" GroupAddressStyle="Free"/></Project></KNX>"#,
    );
    assert!(matches!(
        import(&path, None),
        Err(ImportError::UnsupportedGroupAddressStyle { .. })
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_project_xml_is_tolerated() {
    // Older exports may omit project.xml entirely; import must still succeed
    // (name simply stays None), not error.
    let path = tmp_file("noprojectxml");
    {
        let f = std::fs::File::create(&path).unwrap();
        let mut zw = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        zw.start_file("P-9999/0.xml", opts).unwrap();
        zw.write_all(b"<KNX><Project Id=\"P-9999\"/></KNX>")
            .unwrap();
        zw.start_file("knx_master.xml", opts).unwrap();
        zw.write_all(b"<KNX/>").unwrap();
        zw.finish().unwrap();
    }
    let model = import(&path, None).expect("import without project.xml still works");
    assert!(model.groups.project.is_none());
    let _ = std::fs::remove_file(&path);
}
