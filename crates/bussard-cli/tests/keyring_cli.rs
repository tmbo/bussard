//! `bussard keyring` end to end against a SYNTHETIC `.knxkeys` (issue #84).
//!
//! The fixture was generated with a made-up password by an independent
//! implementation of the documented algorithm; it is never a real export.

use std::path::PathBuf;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An empty synthetic keyring signed with [`PASSWORD`].
const EMPTY: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-01-02T03:04:05" Signature="w3ZTlYHQfH8/GYKciFYCkA==" xmlns="http://knx.org/xml/keyring/1" />"#;

/// The synthetic keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// Writes `content` to a fresh temp file and returns its path.
fn write_keyring(tag: &str, content: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("bussard-keyring-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("synthetic.knxkeys");
    std::fs::write(&path, content)?;
    Ok(path)
}

/// Runs `bussard keyring <file> [extra]` with the given password in the env.
fn run(file: &PathBuf, password: &str, extra: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("keyring")
        .arg(file)
        .args(extra)
        .env("BUSSARD_KEYRING_PASSWORD", password)
        .output()
}

#[test]
fn test_keyring_cli_empty_json() -> TestResult {
    let file = write_keyring("json", EMPTY)?;
    let out = run(&file, PASSWORD, &["--json"])?;
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(v["project"], "Synthetic");
    assert_eq!(v["created"], "2026-01-02T03:04:05");
    assert_eq!(v["has_backbone_key"], false);
    assert_eq!(v["devices"], serde_json::json!([]));
    assert_eq!(v["interfaces"], serde_json::json!([]));
    assert_eq!(v["group_key_count"], 0);
    Ok(())
}

#[test]
fn test_keyring_cli_empty_text() -> TestResult {
    let file = write_keyring("text", EMPTY)?;
    let out = run(&file, PASSWORD, &[])?;
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout)?;
    assert!(text.contains("\"Synthetic\""), "{text}");
    assert!(text.contains("group keys: 0"), "{text}");
    Ok(())
}

#[test]
fn test_keyring_cli_wrong_password_vs_parse_error() -> TestResult {
    let file = write_keyring("wrong", EMPTY)?;
    let out = run(&file, "not-the-password", &[])?;
    assert!(!out.status.success());
    let err = String::from_utf8(out.stderr)?;
    assert!(err.contains("wrong keyring password"), "{err}");

    let broken = write_keyring("broken", "<Keyring Created=\"x\"")?;
    let out = run(&broken, PASSWORD, &[])?;
    assert!(!out.status.success());
    let err = String::from_utf8(out.stderr)?;
    assert!(!err.contains("wrong keyring password"), "{err}");
    assert!(err.contains(".knxkeys"), "{err}");
    Ok(())
}
