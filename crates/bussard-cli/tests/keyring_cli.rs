//! `bussard keyring` end to end against a SYNTHETIC `.knxkeys` (issue #84).
//!
//! The fixture was generated with a made-up password by an independent
//! implementation of the documented algorithm; it is never a real export.

use std::path::PathBuf;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An empty synthetic keyring signed with [`PASSWORD`].
const EMPTY: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-01-02T03:04:05" Signature="w3ZTlYHQfH8/GYKciFYCkA==" xmlns="http://knx.org/xml/keyring/1" />"#;

/// A synthetic keyring with a backbone, one KNXnet/IP Secure tunnelling user
/// (user 2 on interface 1.1.0, tunnel 1.1.200, password `tunnel-user-pw`), one
/// group key and one device (copied from the `bussard-project` keyring tests).
const FULL: &str = r#"<Keyring Project="Synthetic" CreatedBy="bussard-test" Created="2026-02-03T04:05:06" Signature="BwFnB3x3sq9qwzQsIIYDHQ==" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.12" Latency="1000" Key="XXLSoIYX1PClHpjLLr06xw==" />
  <Interface Type="Tunneling" Host="1.1.0" IndividualAddress="1.1.200" UserID="2" Password="CEuTO5HdZ/da1DOMrSJhAQZ94w6kq3rM2I2EFv/3fWw=" Authentication="fj0EBnFwaOJuRN85Aovn5Z8UU1ndm0p0F5tkraeg72Y=">
    <Group Address="2563" Senders="1.1.10" />
  </Interface>
  <GroupAddresses>
    <Group Address="2563" Key="9gsADI4+cx1p65cAhr5GDA==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="1.1.10" ToolKey="4KejWFAOVLtfuK2uo4tiyA==" ManagementPassword="v66sERBaqXzGcl6zuAsdsA==" Authentication="Qoy1wZsb3MhAe+PdJd6p4uHl3mt02IukjeAPcy2BWrE=" SequenceNumber="42" />
  </Devices>
</Keyring>"#;

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
    assert_eq!(v["tunnelling_users"], serde_json::json!([]));
    assert_eq!(v["ip_secure_devices"], serde_json::json!([]));
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

#[test]
fn test_keyring_cli_lists_tunnelling_users_without_secrets() -> TestResult {
    let file = write_keyring("tunnel", FULL)?;
    let out = run(&file, PASSWORD, &["--json"])?;
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let users = v["tunnelling_users"].as_array().ok_or("tunnelling_users")?;
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["user_id"], 2);
    assert_eq!(users[0]["tunnel_address"], "1.1.200");
    assert_eq!(users[0]["host"], "1.1.0");
    assert_eq!(users[0]["has_password"], true);
    assert_eq!(users[0]["has_device_authentication"], true);
    assert_eq!(v["ip_secure_devices"], serde_json::json!(["1.1.10"]));

    let text_out = run(&file, PASSWORD, &[])?;
    let text = String::from_utf8(text_out.stdout)?;
    assert!(
        text.contains("user 2 -> tunnel 1.1.200 on interface 1.1.0"),
        "{text}"
    );
    for secret in ["tunnel-user-pw", "device-auth-pw"] {
        assert!(!text.contains(secret), "leaked a password: {text}");
    }
    Ok(())
}
