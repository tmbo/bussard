//! Adversarial YAML-loader and validation tests (bussard-model).
//!
//! Exercises the on-disk loader with hostile files (duplicate keys, wrong types,
//! CRLF/BOM, non-UTF8, alias bombs, duplicate device addresses) and a validation
//! performance smoke test at scale.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use bussard_model::{Model, has_errors, validate};

/// A fresh unique temp dir.
fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bussard-loader-adv-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, contents: &[u8]) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

// ---------------------------------------------------------------------------
// Duplicate keys at every level are rejected.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_ga_key_rejected() {
    let dir = tmp("dupga");
    write(
        &dir,
        "groups.yaml",
        b"groups:\n  \"1/0/0\":\n    name: a\n  \"1/0/0\":\n    name: b\n",
    );
    let err = Model::load(&dir).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("groups.yaml"), "path in error: {msg}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_nested_field_rejected() {
    let dir = tmp("dupnested");
    // Duplicate `name:` inside one group.
    write(
        &dir,
        "groups.yaml",
        b"groups:\n  \"1/0/0\":\n    name: a\n    name: b\n",
    );
    assert!(Model::load(&dir).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_top_level_key_rejected() {
    let dir = tmp("duptop");
    write(&dir, "groups.yaml", b"groups: {}\ngroups: {}\n");
    assert!(Model::load(&dir).is_err());
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Wrong types & unknown fields.
// ---------------------------------------------------------------------------

#[test]
fn unknown_field_rejected() {
    let dir = tmp("unknown");
    write(&dir, "groups.yaml", b"groups: {}\nbogus: 1\n");
    assert!(Model::load(&dir).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wrong_type_for_dpt_rejected_with_path() {
    let dir = tmp("wrongtype");
    write(
        &dir,
        "groups.yaml",
        b"groups:\n  \"1/0/0\":\n    name: a\n    dpt: {nested: 1}\n",
    );
    let err = Model::load(&dir).unwrap_err();
    assert!(err.to_string().contains("1/0/0"), "path in error: {err}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn out_of_range_ga_key_rejected() {
    let dir = tmp("oorga");
    write(
        &dir,
        "groups.yaml",
        b"groups:\n  \"99/0/0\":\n    name: a\n",
    );
    assert!(Model::load(&dir).is_err());
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// BOM and CRLF.
// ---------------------------------------------------------------------------

#[test]
fn utf8_bom_prefixed_file_handling() {
    let dir = tmp("bom");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"groups:\n  \"1/0/0\":\n    name: a\n");
    write(&dir, "groups.yaml", &bytes);
    // Whatever serde_norway decides (accept or reject), it must not panic and
    // must return a clean Result.
    let r = Model::load(&dir);
    // Document behaviour: a BOM is either tolerated or a clean Yaml error.
    if let Ok(m) = &r {
        assert!(m.groups.groups.contains_key(&"1/0/0".parse().unwrap()));
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crlf_line_endings_load_fine() {
    let dir = tmp("crlf");
    write(
        &dir,
        "groups.yaml",
        b"groups:\r\n  \"1/0/0\":\r\n    name: a\r\n",
    );
    let m = Model::load(&dir).expect("CRLF should load");
    assert_eq!(m.groups.groups.len(), 1);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Non-UTF8 bytes: must be a clean error (Io/Yaml), never a panic.
// ---------------------------------------------------------------------------

#[test]
fn non_utf8_file_is_clean_error() {
    let dir = tmp("nonutf8");
    // Invalid UTF-8 sequence.
    write(&dir, "groups.yaml", &[0xff, 0xfe, 0x00, 0x01, 0x80, 0x81]);
    let r = std::panic::catch_unwind(|| Model::load(&dir));
    assert!(r.is_ok(), "non-UTF8 file must not panic");
    assert!(r.unwrap().is_err(), "non-UTF8 file must error");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Alias bomb (billion-laughs shape): must terminate quickly, not hang/OOM.
// ---------------------------------------------------------------------------

#[test]
fn modest_alias_bomb_terminates_quickly() {
    let dir = tmp("bomb");
    // A modest billion-laughs: each level references the previous a few times.
    // We keep it small enough that a bounded parser finishes instantly, and rely
    // on the overall <30s suite budget + this timing assertion to catch runaway
    // expansion.
    let bomb = r#"
groups:
  "1/0/0":
    name: &a "aaaaaaaa"
    description: &b [*a, *a, *a, *a, *a]
"#;
    write(&dir, "groups.yaml", bomb.as_bytes());
    let start = Instant::now();
    let r = std::panic::catch_unwind(|| Model::load(&dir));
    let elapsed = start.elapsed();
    assert!(r.is_ok(), "alias handling must not panic");
    // Either loads or errors on the type mismatch (description is a seq); the key
    // property is it returns fast.
    assert!(
        elapsed.as_secs() < 5,
        "alias parse took too long: {elapsed:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Duplicate device addresses across files: a hard load error naming both files
// (issue #39). Previously the loader silently collapsed to last-wins in the map,
// dropping a device and misattributing its links; that is now rejected.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_device_address_across_files_is_a_load_error() {
    use bussard_model::loader::LoadError;

    let dir = tmp("dupdev");
    write(&dir, "groups.yaml", b"groups: {}\n");
    write(
        &dir,
        "devices/1.1.4-aaa.yaml",
        b"address: 1.1.4\nname: First\n",
    );
    write(
        &dir,
        "devices/1.1.4-bbb.yaml",
        b"address: 1.1.4\nname: Second\n",
    );
    let err = Model::load(&dir).expect_err("duplicate device address must be rejected");
    match err {
        LoadError::DuplicateDeviceAddress {
            address,
            first,
            second,
        } => {
            assert_eq!(address, "1.1.4".parse().unwrap());
            // Sorted order: the "aaa" file is first, the "bbb" file second.
            assert!(first.ends_with("1.1.4-aaa.yaml"), "first: {first:?}");
            assert!(second.ends_with("1.1.4-bbb.yaml"), "second: {second:?}");
        }
        other => panic!("expected DuplicateDeviceAddress, got {other:?}"),
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn device_filename_address_mismatch_flags_e002() {
    let dir = tmp("mismatch");
    write(&dir, "groups.yaml", b"groups: {}\n");
    // filename does not start with the address.
    write(&dir, "devices/wrongname.yaml", b"address: 1.1.4\nname: X\n");
    let m = Model::load(&dir).expect("load");
    let diags = validate(&m);
    assert!(
        diags.iter().any(|d| d.code == "E002"),
        "expected E002 for filename mismatch, got {diags:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Missing files: groups/links are optional, absent devices dir is fine.
// ---------------------------------------------------------------------------

#[test]
fn empty_directory_loads_empty_model() {
    let dir = tmp("empty");
    let m = Model::load(&dir).expect("empty dir loads");
    assert!(m.groups.groups.is_empty());
    assert!(m.devices.is_empty());
    assert!(m.links.links.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Validation performance smoke test: 1000+ synthetic GAs under 1s.
// ---------------------------------------------------------------------------

#[test]
fn validate_1000_plus_gas_is_fast() {
    let dir = tmp("perf");
    // Build a groups.yaml with ~1500 GAs, and links referencing many of them.
    let mut groups = String::from("groups:\n");
    let mut n = 0;
    'outer: for main in 1..=31u32 {
        for middle in 0..=7u32 {
            for sub in 0..=255u32 {
                if n >= 1500 {
                    break 'outer;
                }
                groups.push_str(&format!(
                    "  \"{main}/{middle}/{sub}\":\n    name: G{n}\n    dpt: \"1.001\"\n"
                ));
                n += 1;
            }
        }
    }
    write(&dir, "groups.yaml", groups.as_bytes());

    // A device with many com-objects and links.
    let mut dev = String::from("address: 1.1.4\nname: Big\ncom_objects:\n");
    let mut links = String::from("links:\n  \"1.1.4\":\n");
    for obj in 0..500u16 {
        dev.push_str(&format!("  {obj}:\n    dpt: \"1.001\"\n    flags: CW\n"));
        // Link each object to a distinct GA (main derived to stay in range).
        let main = 1 + (obj as u32 % 31);
        let middle = (obj as u32 / 31) % 8;
        let sub = (obj as u32) % 256;
        links.push_str(&format!(
            "    - object: {obj}\n      listen: [\"{main}/{middle}/{sub}\"]\n"
        ));
    }
    write(&dir, "devices/1.1.4-big.yaml", dev.as_bytes());
    write(&dir, "links.yaml", links.as_bytes());

    let m = Model::load(&dir).expect("load big model");
    assert!(m.groups.groups.len() >= 1000);

    let start = Instant::now();
    let diags = validate(&m);
    let elapsed = start.elapsed();
    // has_errors is exercised too.
    let _ = has_errors(&diags);
    assert!(
        elapsed.as_secs_f64() < 1.0,
        "validate of {} GAs took {elapsed:?} (>1s)",
        m.groups.groups.len()
    );
    let _ = fs::remove_dir_all(&dir);
}
