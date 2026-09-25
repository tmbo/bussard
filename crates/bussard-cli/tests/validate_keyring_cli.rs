//! `bussard validate` against the configured keyring (issue #205): W028 for a
//! security-activated device the keyring has no tool key for, W029 for a
//! group whose `secure` flag disagrees with the keyring's group keys, E027 for
//! a `connection.keyring` that points at a missing file, and one I031 line
//! instead of the key checks when `BUSSARD_KEYRING_PASSWORD` is not set.
//!
//! The keyring is the committed SYNTHETIC `knx-sim/examples/secure/synthetic.knxkeys`
//! (made-up password; a tool key for 1.1.10 and a group key for 1/2/3). No
//! bus, no network, no key is printed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The synthetic keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

fn keyring_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knx-sim/examples/secure/synthetic.knxkeys")
}

/// A model: activated 1.1.10 (in the keyring) and 1.1.13 (not in it), GA
/// 1/2/3 secure (keyed) and GA 1/2/4 secure (not keyed), with
/// `connection.keyring` set to `keyring`.
fn model(tag: &str, keyring: &Path) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-validate-keyring-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;
    std::fs::write(
        dir.join("bussard.toml"),
        format!("[connection]\ntransport = \"routing\"\nkeyring = {keyring:?}\n"),
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/3\", name = \"Keyed\", secure = true },\n  \
         { address = \"1/2/4\", name = \"Not keyed\", secure = true },\n]\n",
    )?;
    for ia in ["1.1.10", "1.1.13"] {
        std::fs::write(
            dir.join("devices").join(format!("{ia}.toml")),
            format!("address = \"{ia}\"\nname = \"Secure {ia}\"\n\n[security]\nactivated = true\n"),
        )?;
    }
    Ok(dir)
}

fn validate(dir: &Path, password: Option<&str>) -> TestResult<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.args(["validate", "--format", "json", "--dir"])
        .arg(dir)
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(password) = password {
        cmd.env("BUSSARD_KEYRING_PASSWORD", password);
    }
    Ok(cmd.output()?)
}

/// `(code, location)` of every diagnostic of a `--format json` run.
fn diagnostics(out: &Output) -> TestResult<Vec<(String, String, String)>> {
    let items: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(items
        .as_array()
        .ok_or("validate --format json prints an array")?
        .iter()
        .map(|d| {
            (
                d["code"].as_str().unwrap_or_default().to_string(),
                d["location"].as_str().unwrap_or_default().to_string(),
                d["message"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect())
}

#[test]
fn test_validate_keyring_names_the_missing_tool_key_and_the_flag_mismatch() -> TestResult {
    let dir = model("loaded", &keyring_path())?;
    let out = validate(&dir, Some(PASSWORD))?;
    let diags = diagnostics(&out)?;
    assert!(out.status.success(), "warnings only: {diags:?}");
    let w028: Vec<_> = diags.iter().filter(|d| d.0 == "W028").collect();
    assert_eq!(w028.len(), 1, "{diags:?}");
    assert!(w028[0].1.contains("1.1.13"), "{diags:?}");
    assert!(w028[0].2.contains("re-export"), "{diags:?}");
    let w029: Vec<_> = diags.iter().filter(|d| d.0 == "W029").collect();
    assert_eq!(w029.len(), 1, "{diags:?}");
    assert_eq!(w029[0].1, "groups.toml 1/2/4");
    assert!(
        !diags.iter().any(|d| d.0 == "I031" || d.0 == "E027"),
        "{diags:?}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_validate_keyring_without_password_skips_the_key_checks() -> TestResult {
    let dir = model("locked", &keyring_path())?;
    let out = validate(&dir, None)?;
    let diags = diagnostics(&out)?;
    assert!(out.status.success(), "{diags:?}");
    let keyring: Vec<_> = diags
        .iter()
        .filter(|d| ["W028", "W029", "W030", "I031", "E027"].contains(&d.0.as_str()))
        .collect();
    assert_eq!(keyring.len(), 1, "{diags:?}");
    assert_eq!(keyring[0].0, "I031");
    assert!(
        keyring[0].2.contains("BUSSARD_KEYRING_PASSWORD"),
        "{diags:?}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_validate_keyring_wrong_password_warns_without_a_key() -> TestResult {
    let dir = model("wrong", &keyring_path())?;
    let out = validate(&dir, Some("not-the-password"))?;
    let diags = diagnostics(&out)?;
    assert!(out.status.success(), "{diags:?}");
    assert!(diags.iter().any(|d| d.0 == "W030"), "{diags:?}");
    assert!(!diags.iter().any(|d| d.0 == "W028"), "{diags:?}");
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn test_validate_keyring_missing_file_is_an_error() -> TestResult {
    let dir = model("missing", Path::new("/nonexistent/bussard/site.knxkeys"))?;
    let out = validate(&dir, Some(PASSWORD))?;
    let diags = diagnostics(&out)?;
    assert!(!out.status.success(), "E027 fails validate: {diags:?}");
    assert!(
        diags
            .iter()
            .any(|d| d.0 == "E027" && d.2.contains("site.knxkeys")),
        "{diags:?}"
    );
    assert_eq!(
        diags.iter().filter(|d| d.0 == "W028").count(),
        2,
        "{diags:?}"
    );
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
