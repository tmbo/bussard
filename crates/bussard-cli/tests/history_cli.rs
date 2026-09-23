//! End-to-end test of `bussard status`, `history`, `show` and `undo`
//! (issues #110, #112).
//!
//! Runs the built binary against a temporary model directory. Nothing here
//! touches a bus: the four commands read and write `<dir>/.bussard/history` and
//! the model files, and nothing else.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use bussard_model::history::{History, SnapshotReason};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The `groups.yaml` the baseline snapshot holds.
const BASE_GROUPS: &str = "groups:\n  \"0/0/4\":\n    name: Porch light\n    dpt: \"1.001\"\n";

/// The `groups.yaml` after the edit under test.
const EDITED_GROUPS: &str = "groups:\n  \"0/0/4\":\n    name: Front light\n    dpt: \"1.001\"\n";

/// A fresh temporary model directory.
fn model_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-history-cli-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(dir.join("groups.yaml"), BASE_GROUPS)?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    Ok(dir)
}

/// Runs the bussard binary and returns its stdout, asserting it exited 0.
fn run(dir: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(args)
        .arg("--dir")
        .arg(dir)
        .output()?;
    assert!(
        output.status.success(),
        "`bussard {}` exited {:?}: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn test_status_without_history_says_so_and_exits_zero() -> TestResult {
    let dir = model_dir("empty")?;
    let out = run(&dir, &["status"])?;
    assert!(out.contains("No history yet"), "{out}");
    let out = run(&dir, &["history"])?;
    assert!(out.contains("No history yet"), "{out}");
    let out = run(&dir, &["undo"])?;
    assert!(out.contains("nothing to undo"), "{out}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_status_history_show_and_undo_round_trip() -> TestResult {
    let dir = model_dir("round-trip")?;
    let history = History::open(&dir);
    history.snapshot(SnapshotReason::new("import").with_args(["home.knxproj"]))?;

    // An edit nobody has pushed anywhere yet.
    std::fs::write(dir.join("groups.yaml"), EDITED_GROUPS)?;

    let out = run(&dir, &["status"])?;
    assert!(
        out.contains("Group address 0/0/4 is now called \"Front light\" (was \"Porch light\")."),
        "{out}"
    );
    assert!(out.contains("1 pending change(s)"), "{out}");

    // The JSON shape carries the same change, structured.
    let out = run(&dir, &["status", "--json"])?;
    let json: serde_json::Value = serde_json::from_str(&out)?;
    assert_eq!(json["changes"][0]["kind"], "group_renamed");
    assert_eq!(json["changes"][0]["group"], "0/0/4");
    assert!(json["base"].is_string());

    // `--raw` is the file-level view for the people who do read YAML.
    let out = run(&dir, &["status", "--raw"])?;
    assert!(out.contains("--- snapshot/groups.yaml"), "{out}");
    assert!(out.contains("+    name: Front light"), "{out}");

    // A second snapshot, so there is something to undo back to.
    history.snapshot(SnapshotReason::new("apply").with_args(["1.1.5"]))?;

    let out = run(&dir, &["history"])?;
    assert!(out.contains("import home.knxproj"), "{out}");
    assert!(out.contains("apply 1.1.5"), "{out}");
    assert!(
        out.contains("Group address 0/0/4 is now called \"Front light\""),
        "the summary line is the first sentence: {out}"
    );

    let out = run(&dir, &["show", "2"])?;
    assert!(
        out.contains("Group address 0/0/4 is now called \"Front light\""),
        "{out}"
    );

    // Undo goes back to snapshot 1 and says what that reverts.
    let out = run(&dir, &["undo"])?;
    assert!(
        out.contains("Group address 0/0/4 is now called \"Porch light\" (was \"Front light\")."),
        "{out}"
    );
    assert!(
        out.contains("to push this to devices"),
        "undo must point at plan/apply: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("groups.yaml"))?,
        BASE_GROUPS
    );

    // The undo is itself a snapshot, so a second undo reverts it.
    assert_eq!(history.list()?.len(), 3);
    let out = run(&dir, &["undo"])?;
    assert!(out.contains("now called \"Front light\""), "{out}");
    assert_eq!(
        std::fs::read_to_string(dir.join("groups.yaml"))?,
        EDITED_GROUPS
    );

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_history_snapshots_never_hold_product_data_or_captures() -> TestResult {
    let dir = model_dir("private")?;
    std::fs::create_dir_all(dir.join("vendor"))?;
    std::fs::write(dir.join("vendor").join("product.knxprod"), "binary")?;
    std::fs::create_dir_all(dir.join("captures"))?;
    std::fs::write(dir.join("captures").join("bus.db"), "sqlite")?;
    std::fs::write(dir.join("keyring.knxkeys"), "secret")?;

    let history = History::open(&dir);
    let id = history.snapshot(SnapshotReason::new("import"))?;
    let snapshot = history.snapshot_dir(&id);

    let mut names: Vec<String> = std::fs::read_dir(&snapshot)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "devices".to_string(),
            "groups.yaml".to_string(),
            "links.yaml".to_string(),
            "manifest.json".to_string(),
        ],
        "a snapshot holds the model files and nothing else"
    );

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
