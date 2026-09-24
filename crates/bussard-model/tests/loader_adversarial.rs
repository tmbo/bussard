//! Adversarial TOML-loader and validation tests (bussard-model).
//!
//! Exercises the on-disk loader with hostile files (duplicate keys, wrong types,
//! CRLF/BOM, non-UTF8, deep nesting, duplicate device addresses) and a validation
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
    // Two entries for one GA parse (they are array elements); validation
    // reports both lines as E020.
    let dir = tmp("dupga");
    write(
        &dir,
        "groups.toml",
        b"groups = [\n  { address = \"1/0/0\", name = \"a\" },\n  { address = \"1/0/0\", name = \"b\" },\n]\n",
    );
    let m = Model::load(&dir).unwrap();
    let diags = bussard_model::validate_in_dir(&m, &dir);
    let e020: Vec<_> = diags.iter().filter(|d| d.code == "E020").collect();
    assert_eq!(e020.len(), 2, "one E020 per line: {diags:?}");
    assert!(e020[0].location.starts_with("groups.toml:2:"), "{e020:?}");
    assert!(e020[1].location.starts_with("groups.toml:3:"), "{e020:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_nested_field_rejected() {
    let dir = tmp("dupnested");
    // Duplicate `name` inside one group entry.
    write(
        &dir,
        "groups.toml",
        b"groups = [{ address = \"1/0/0\", name = \"a\", name = \"b\" }]\n",
    );
    let err = Model::load(&dir).unwrap_err();
    assert!(err.to_string().contains("duplicate key"), "{err}");
    assert!(
        err.to_string().contains("groups.toml"),
        "path in error: {err}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_top_level_key_rejected() {
    let dir = tmp("duptop");
    write(&dir, "groups.toml", b"project = \"a\"\nproject = \"b\"\n");
    let err = Model::load(&dir).unwrap_err();
    assert!(err.to_string().contains("first defined here"), "{err}");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Wrong types & unknown fields.
// ---------------------------------------------------------------------------

#[test]
fn unknown_field_rejected() {
    let dir = tmp("unknown");
    write(&dir, "groups.toml", b"groups = []\nbogus = 1\n");
    assert!(Model::load(&dir).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wrong_type_for_dpt_rejected_with_path() {
    let dir = tmp("wrongtype");
    write(
        &dir,
        "groups.toml",
        b"groups = [\n  { address = \"1/0/0\", name = \"a\", dpt = { nested = 1 } },\n]\n",
    );
    let err = Model::load(&dir).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("groups.toml"), "path in error: {msg}");
    assert!(msg.contains("line 2"), "line in error: {msg}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn out_of_range_ga_key_rejected() {
    let dir = tmp("oorga");
    write(
        &dir,
        "groups.toml",
        b"groups = [{ address = \"99/0/0\", name = \"a\" }]\n",
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
    bytes.extend_from_slice(b"groups = [{ address = \"1/0/0\", name = \"a\" }]\n");
    write(&dir, "groups.toml", &bytes);
    // Whatever the parser decides (accept or reject), it must not panic and
    // must return a clean Result.
    let r = Model::load(&dir);
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
        "groups.toml",
        b"groups = [\r\n  { address = \"1/0/0\", name = \"a\" },\r\n]\r\n",
    );
    let m = Model::load(&dir).expect("CRLF should load");
    assert_eq!(m.groups.groups.len(), 1);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Non-UTF8 bytes: must be a clean error (Io/Parse), never a panic.
// ---------------------------------------------------------------------------

#[test]
fn non_utf8_file_is_clean_error() {
    let dir = tmp("nonutf8");
    // Invalid UTF-8 sequence.
    write(&dir, "groups.toml", &[0xff, 0xfe, 0x00, 0x01, 0x80, 0x81]);
    let r = std::panic::catch_unwind(|| Model::load(&dir));
    assert!(r.is_ok(), "non-UTF8 file must not panic");
    assert!(r.unwrap().is_err(), "non-UTF8 file must error");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Deep nesting (TOML's stand-in for YAML's alias bomb): must terminate
// quickly, not hang or overflow the stack.
// ---------------------------------------------------------------------------

#[test]
fn deeply_nested_values_terminate_quickly() {
    let dir = tmp("deep");
    let depth = 5000;
    let text = format!(
        "project = \"x\"\ngroups = [{{ address = \"1/0/0\", name = \"a\", description = {}{} }}]\n",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    write(&dir, "groups.toml", text.as_bytes());
    let start = Instant::now();
    let r = std::panic::catch_unwind(|| Model::load(&dir));
    let elapsed = start.elapsed();
    assert!(r.is_ok(), "deep nesting must not panic");
    assert!(r.unwrap().is_err(), "description is a string, not an array");
    assert!(elapsed.as_secs() < 5, "parse took too long: {elapsed:?}");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Duplicate device addresses across files: a hard load error naming both files
// (issue #39).
// ---------------------------------------------------------------------------

#[test]
fn duplicate_device_address_across_files_is_a_load_error() {
    use bussard_model::loader::LoadError;

    let dir = tmp("dupdev");
    write(&dir, "groups.toml", b"groups = []\n");
    write(
        &dir,
        "devices/1.1.4.toml",
        b"address = \"1.1.4\"\nname = \"First\"\n",
    );
    write(
        &dir,
        "devices/1.1.40.toml",
        b"address = \"1.1.4\"\nname = \"Second\"\n",
    );
    let err = Model::load(&dir).expect_err("duplicate device address must be rejected");
    match err {
        LoadError::DuplicateDeviceAddress {
            address,
            first,
            second,
        } => {
            assert_eq!(address, "1.1.4".parse().unwrap());
            // Sorted order: `1.1.4.toml` is first, `1.1.40.toml` second.
            assert!(first.ends_with("1.1.4.toml"), "first: {first:?}");
            assert!(second.ends_with("1.1.40.toml"), "second: {second:?}");
        }
        other => panic!("expected DuplicateDeviceAddress, got {other:?}"),
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn device_filename_address_mismatch_flags_e002() {
    let dir = tmp("mismatch");
    write(&dir, "groups.toml", b"groups = []\n");
    // The file name is not the address.
    write(
        &dir,
        "devices/wrongname.toml",
        b"address = \"1.1.4\"\nname = \"X\"\n",
    );
    let m = Model::load(&dir).expect("load");
    let diags = validate(&m);
    assert!(
        diags.iter().any(|d| d.code == "E002"),
        "expected E002 for filename mismatch, got {diags:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Missing files: every file is optional, an absent devices dir is fine.
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

#[test]
fn a_yaml_only_directory_is_refused() {
    let dir = tmp("yaml");
    write(&dir, "groups.yaml", b"groups: {}\n");
    let err = Model::load(&dir).expect_err("the YAML model is not read any more");
    assert!(err.to_string().contains("YAML model"), "{err}");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Validation performance smoke test: 1000+ synthetic GAs under 1s.
// ---------------------------------------------------------------------------

#[test]
fn validate_1000_plus_gas_is_fast() {
    let dir = tmp("perf");
    // Build a groups.toml with ~1500 GAs, and links referencing many of them.
    let mut groups = String::from("groups = [\n");
    let mut n = 0;
    'outer: for main in 1..=31u32 {
        for middle in 0..=7u32 {
            for sub in 0..=255u32 {
                if n >= 1500 {
                    break 'outer;
                }
                groups.push_str(&format!(
                    "  {{ address = \"{main}/{middle}/{sub}\", name = \"G{n}\", dpt = \"1.001\" }},\n"
                ));
                n += 1;
            }
        }
    }
    groups.push_str("]\n");
    write(&dir, "groups.toml", groups.as_bytes());

    // A device with many com-objects (in the lock) and links (in its file).
    let mut dev = String::from("address = \"1.1.4\"\nname = \"Big\"\n\n[links]\n");
    let mut lock = String::from("version = 1\n\n[[device]]\naddress = \"1.1.4\"\nobjects = [\n");
    for obj in 0..500u16 {
        lock.push_str(&format!(
            "  {{ number = {obj}, dpt = \"1.001\", flags = \"CW\" }},\n"
        ));
        // Link each object to a distinct GA (main derived to stay in range).
        let main = 1 + (obj as u32 % 31);
        let middle = (obj as u32 / 31) % 8;
        let sub = (obj as u32) % 256;
        dev.push_str(&format!("{obj}.listen = [\"{main}/{middle}/{sub}\"]\n"));
    }
    lock.push_str("]\n");
    write(&dir, "devices/1.1.4.toml", dev.as_bytes());
    write(&dir, "bussard.lock", lock.as_bytes());

    let m = Model::load(&dir).expect("load big model");
    assert!(m.groups.groups.len() >= 1000);
    assert_eq!(m.links.links[&"1.1.4".parse().unwrap()].len(), 500);

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
