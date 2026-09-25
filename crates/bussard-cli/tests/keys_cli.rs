//! `bussard keys import|export|show` end to end against the committed
//! SYNTHETIC keyring (issue #241). Never a real export.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The synthetic keyring the secure tests share.
const SYNTHETIC: &str = include_str!("../../../knx-sim/examples/secure/synthetic.knxkeys");

/// Its made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// A fresh temp directory holding a model directory and the keyring.
fn setup(tag: &str) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "bussard-keys-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let model = root.join("knx");
    std::fs::create_dir_all(&model)?;
    let keyring = root.join("synthetic.knxkeys");
    std::fs::write(&keyring, SYNTHETIC)?;
    Ok((model, keyring))
}

/// Runs `bussard --dir <model> keys <args>` with the synthetic password.
fn keys(model: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("--dir")
        .arg(model)
        .arg("keys")
        .args(args)
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_KEYRING")
        .output()
}

/// Asserts success and returns stdout.
fn ok(out: &Output) -> Result<String, Box<dyn std::error::Error>> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout.clone())?)
}

/// No output may carry key bytes or passwords of the fixture.
fn assert_no_secrets(text: &str) {
    for leak in ["tunnel-user-pw", "device-auth-pw", "QkJC", "d3d3", "ERER"] {
        assert!(!text.contains(leak), "leaked {leak}: {text}");
    }
}

#[test]
fn test_keys_import_show_export_round_trip() -> TestResult {
    let (model, keyring) = setup("round")?;
    let path = keyring.to_string_lossy().to_string();

    let first = ok(&keys(&model, &["import", &path])?)?;
    assert!(first.contains("1 added (1.1.10)"), "{first}");
    assert!(first.contains("created the key store"), "{first}");
    assert_no_secrets(&first);
    assert!(model.join("bussard.keys").exists());

    // A second import is a no-op and touches nothing.
    let again = keys(&model, &["--json", "import", &path])?;
    let v: serde_json::Value = serde_json::from_str(&ok(&again)?)?;
    assert_eq!(v["changed"], false);
    assert_eq!(v["written"], false);
    assert_eq!(v["report"]["devices_unchanged"], 1);
    assert!(!model.join("bussard.keys.bak").exists());

    let show = ok(&keys(&model, &["--json", "show"])?)?;
    assert_no_secrets(&show);
    let v: serde_json::Value = serde_json::from_str(&show)?;
    assert_eq!(v["project"], "Synthetic");
    assert_eq!(v["group_keys"], serde_json::json!(["1/2/3"]));
    assert_eq!(v["devices"][0]["address"], "1.1.10");
    assert_eq!(v["devices"][0]["has_tool_key"], true);
    assert_eq!(v["interfaces"][0]["user_id"], 2);

    let text = ok(&keys(&model, &["show"])?)?;
    assert!(text.contains("1.1.10: tool key"), "{text}");
    assert_no_secrets(&text);

    // Export, then read the export back with `bussard keyring` (signature
    // verified by the reader).
    let out = model.parent().ok_or("no parent")?.join("export.knxkeys");
    let out_s = out.to_string_lossy().to_string();
    let exported = ok(&keys(&model, &["export", &out_s])?)?;
    assert!(
        exported.contains("1 device(s), 1 group key(s), 1 interface(s)"),
        "{exported}"
    );
    let read = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["--json", "keyring"])
        .arg(&out)
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .output()?;
    let v: serde_json::Value = serde_json::from_str(&ok(&read)?)?;
    assert_eq!(v["devices"], serde_json::json!(["1.1.10"]));
    assert_eq!(v["group_key_count"], 1);
    assert_eq!(v["has_backbone_key"], true);

    // Refuses to overwrite without --force.
    assert!(!keys(&model, &["export", &out_s])?.status.success());
    ok(&keys(&model, &["export", "--force", &out_s])?)?;
    Ok(())
}

#[test]
fn test_keys_wrong_password_is_refused() -> TestResult {
    let (model, keyring) = setup("wrong")?;
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("--dir")
        .arg(&model)
        .args(["keys", "import"])
        .arg(&keyring)
        .env("BUSSARD_KEYRING_PASSWORD", "not-the-password")
        .output()?;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("wrong keyring password"), "{stderr}");
    assert!(!model.join("bussard.keys").exists());
    Ok(())
}

#[test]
fn test_keys_show_without_a_store_hints_at_import() -> TestResult {
    let (model, _) = setup("empty")?;
    let out = keys(&model, &["show"])?;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bussard keys import"), "{stderr}");
    Ok(())
}
