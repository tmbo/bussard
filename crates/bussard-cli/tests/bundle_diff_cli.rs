//! End-to-end tests of `bussard export`, `import <file.bussard>` and `diff`
//! (issues #111, #99).
//!
//! Every test works on copies in a temporary directory; nothing touches a bus
//! or the committed fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The repository root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The committed example model.
fn fixture() -> PathBuf {
    repo_root().join("knx-sim/examples/small-installation/knx")
}

/// A fresh temporary directory.
fn temp_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-bundle-cli-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Copies a model directory's files (one level of `devices/`).
fn copy_model(from: &Path, to: &Path) -> TestResult {
    std::fs::create_dir_all(to.join("devices"))?;
    for entry in std::fs::read_dir(from)? {
        let path = entry?.path();
        if path.is_file() {
            std::fs::copy(&path, to.join(path.file_name().ok_or("name")?))?;
        }
    }
    for entry in std::fs::read_dir(from.join("devices"))? {
        let path = entry?.path();
        std::fs::copy(
            &path,
            to.join("devices").join(path.file_name().ok_or("name")?),
        )?;
    }
    Ok(())
}

/// Runs the bussard binary.
fn bussard(args: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .env_remove("BUSSARD_PROJECT_PASSWORD")
        .output()?)
}

/// Runs bussard, asserting the exit code, and returns stdout.
fn run(args: &[&str], code: i32) -> Result<String, Box<dyn std::error::Error>> {
    let out = bussard(args)?;
    assert_eq!(
        out.status.code(),
        Some(code),
        "`bussard {}`: {}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?)
}

/// One model file: its relative path and bytes.
type ModelFile = (String, Vec<u8>);

/// The model files of a directory as (relative path, bytes), sorted.
fn model_bytes(dir: &Path) -> Result<Vec<ModelFile>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for name in ["bussard.toml", "groups.toml", "links.yaml"] {
        if dir.join(name).is_file() {
            out.push((name.to_string(), std::fs::read(dir.join(name))?));
        }
    }
    let mut devices: Vec<_> = std::fs::read_dir(dir.join("devices"))?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    devices.sort();
    for path in devices {
        let name = path.file_name().and_then(|n| n.to_str()).ok_or("name")?;
        out.push((format!("devices/{name}"), std::fs::read(&path)?));
    }
    Ok(out)
}

/// Path as &str for arguments.
fn s(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| "non-UTF-8 path".into())
}

#[test]
fn test_export_import_round_trip_is_byte_identical() -> TestResult {
    let root = temp_dir("round-trip")?;
    let source = root.join("knx");
    copy_model(&fixture(), &source)?;
    let bundle = root.join("house.bussard");

    let out = run(&["export", s(&bundle)?, "--dir", s(&source)?], 0)?;
    assert!(out.contains("4 device(s)"), "{out}");
    assert!(out.contains("never included"), "{out}");
    assert!(source.join(".bussard/last_export.json").is_file());

    let target = root.join("copy");
    run(&["import", s(&bundle)?, "--dir", s(&target)?], 0)?;
    assert_eq!(model_bytes(&target)?, model_bytes(&fixture())?);

    // Re-importing the same bundle changes nothing and reports no conflict.
    let out = run(&["import", s(&bundle)?, "--dir", s(&target)?], 0)?;
    assert!(out.contains("The import changes nothing"), "{out}");
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_import_bundle_conflicts_mine_and_theirs() -> TestResult {
    let root = temp_dir("conflicts")?;
    let integrator = root.join("integrator");
    copy_model(&fixture(), &integrator)?;
    let groups = std::fs::read_to_string(integrator.join("groups.toml"))?;
    std::fs::write(
        integrator.join("groups.toml"),
        groups.replace("name: Light Kitchen\n", "name: Kitchen ceiling\n"),
    )?;
    let bundle = root.join("new.bussard");
    run(&["export", s(&bundle)?, "--dir", s(&integrator)?], 0)?;

    let owner = root.join("owner");
    copy_model(&fixture(), &owner)?;
    let args = ["import", s(&bundle)?, "--dir", s(&owner)?];

    // Default: the local name is kept and the run exits 3.
    let out = run(&args, 3)?;
    assert!(
        out.contains(
            "Group address Light Kitchen (1/0/1): the name is \"Light Kitchen\" here and \
             \"Kitchen ceiling\" in the bundle. Kept this model's value."
        ),
        "{out}"
    );
    // --mine settles the same conflict and exits 0.
    run(&[&args[..], &["--mine"]].concat(), 0)?;
    assert!(std::fs::read_to_string(owner.join("groups.toml"))?.contains("Light Kitchen"));

    // --theirs takes the bundle's name.
    let out = run(&[&args[..], &["--theirs"]].concat(), 0)?;
    assert!(out.contains("Took the bundle's value."), "{out}");
    assert!(
        out.contains("Group address 1/0/1 is now called \"Kitchen ceiling\""),
        "{out}"
    );
    assert!(std::fs::read_to_string(owner.join("groups.toml"))?.contains("Kitchen ceiling"));

    // The import snapshotted first, so it can be undone.
    let out = run(&["history", "--dir", s(&owner)?], 0)?;
    assert!(out.contains("import"), "{out}");
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_diff_rename_is_one_change_and_same_project_is_empty() -> TestResult {
    let root = temp_dir("diff")?;
    let a = root.join("a");
    let b = root.join("b");
    copy_model(&fixture(), &a)?;
    copy_model(&fixture(), &b)?;
    let groups = std::fs::read_to_string(b.join("groups.toml"))?;
    std::fs::write(
        b.join("groups.toml"),
        groups.replace("name: Light Kitchen\n", "name: Kitchen ceiling\n"),
    )?;
    let bundle_b = root.join("b.bussard");
    run(&["export", s(&bundle_b)?, "--dir", s(&b)?], 0)?;

    let out = run(&["diff", s(&a)?, s(&bundle_b)?, "--json"], 0)?;
    let value: serde_json::Value = serde_json::from_str(&out)?;
    let changes = value["changes"].as_array().ok_or("changes")?;
    assert_eq!(changes.len(), 1, "{out}");
    assert_eq!(changes[0]["kind"], "group_renamed");
    assert_eq!(changes[0]["group"], "1/0/1");

    let out = run(&["diff", s(&a)?, s(&bundle_b)?, "--raw"], 0)?;
    assert!(
        out.contains("+  1/0/1:") || out.contains("+    name: Kitchen ceiling"),
        "{out}"
    );

    // Two imports of the same project: no differences.
    let json = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../bussard-project/tests/fixtures/tiny.xknxproject.json");
    let copy = root.join("tiny-again.json");
    std::fs::copy(&json, &copy)?;
    let out = run(&["diff", s(&json)?, s(&copy)?], 0)?;
    assert!(out.contains("No differences"), "{out}");
    std::fs::remove_dir_all(&root)?;
    Ok(())
}
