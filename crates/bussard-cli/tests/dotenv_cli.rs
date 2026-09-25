//! `BUSSARD_*` variables from a `.env` file (issue #251), end to end.
//!
//! Every case builds its own tree under a unique temp directory: `<root>/.env`
//! next to the model directory `<root>/knx`, so no `.env` ever lands in the
//! shared temp directory. The keyring is the committed SYNTHETIC
//! `knx-sim/examples/secure/synthetic.knxkeys` (made-up password). The write
//! gate case uses TEST-NET-1 (`192.0.2.1`, RFC 5737), which the gate refuses
//! before any socket opens. No bus, no network, no real secret.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The synthetic keyring's made-up password.
const PASSWORD: &str = "synthetic-keyring-pw";

/// Every variable these tests control; removed from the child's environment
/// so the developer's shell cannot leak in.
const CONTROLLED: &[&str] = &[
    "BUSSARD_DIR",
    "BUSSARD_GATEWAY",
    "BUSSARD_KEYRING",
    "BUSSARD_KEYRING_PASSWORD",
    "BUSSARD_ALLOW_REAL_GATEWAY",
    "RUST_LOG",
];

fn keyring_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../knx-sim/examples/secure/synthetic.knxkeys")
}

/// A unique, empty root directory (canonical, so paths compare on macOS).
fn root(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-dotenv-cli-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(std::fs::canonicalize(&dir)?)
}

/// `<root>/knx`: activated 1.1.10 (in the keyring) and 1.1.13 (not in it),
/// with `connection.keyring` pointing at the synthetic keyring.
fn model(root: &Path) -> TestResult<PathBuf> {
    let dir = root.join("knx");
    std::fs::create_dir_all(dir.join("devices"))?;
    let keyring = keyring_path();
    let keyring = keyring.to_str().ok_or("keyring path is not UTF-8")?;
    std::fs::write(
        dir.join("bussard.toml"),
        format!("[connection]\ntransport = \"routing\"\nkeyring = {keyring:?}\n"),
    )?;
    std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
    for ia in ["1.1.10", "1.1.13"] {
        std::fs::write(
            dir.join("devices").join(format!("{ia}.toml")),
            format!("address = \"{ia}\"\nname = \"Secure {ia}\"\n\n[security]\nactivated = true\n"),
        )?;
    }
    Ok(dir)
}

/// A `bussard` command run in `cwd` with the controlled variables removed.
fn bussard(cwd: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in CONTROLLED {
        cmd.env_remove(key);
    }
    cmd
}

/// The diagnostic codes of a `validate --json` run.
fn codes(out: &Output) -> TestResult<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(doc["diagnostics"]
        .as_array()
        .ok_or("validate --json prints {\"diagnostics\": [...]}")?
        .iter()
        .map(|d| d["code"].as_str().unwrap_or_default().to_string())
        .collect())
}

#[test]
fn test_validate_reads_keyring_password_from_parent_dotenv() -> TestResult {
    let root = root("parent")?;
    let dir = model(&root)?;
    std::fs::write(
        root.join(".env"),
        format!("# local secrets\nOTHER_SECRET=x\nexport BUSSARD_KEYRING_PASSWORD='{PASSWORD}'\n"),
    )?;

    let out = bussard(&root)
        .args(["validate", "--json", "--dir"])
        .arg(&dir)
        .output()?;
    let found = codes(&out)?;
    assert!(out.status.success(), "{found:?}");
    assert!(
        found.iter().any(|c| c == "W028"),
        "key checks ran: {found:?}"
    );
    assert!(!found.iter().any(|c| c == "I031"), "{found:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(PASSWORD), "never print a value: {stderr}");

    // An exported empty value wins over the file: the keyring does not open.
    let out = bussard(&root)
        .args(["validate", "--json", "--dir"])
        .arg(&dir)
        .env("BUSSARD_KEYRING_PASSWORD", "")
        .output()?;
    let found = codes(&out)?;
    assert!(!found.iter().any(|c| c == "W028"), "{found:?}");
    assert!(found.iter().any(|c| c == "W030"), "{found:?}");

    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_validate_model_dir_dotenv_beats_parent_without_merging() -> TestResult {
    let root = root("first-wins")?;
    let dir = model(&root)?;
    // The model directory's file is first and has no password; the parent's
    // password must not be merged in.
    std::fs::write(dir.join(".env"), "BUSSARD_GATEWAY=127.0.0.1:9\n")?;
    std::fs::write(
        root.join(".env"),
        format!("BUSSARD_KEYRING_PASSWORD={PASSWORD}\n"),
    )?;
    let out = bussard(&root)
        .args(["validate", "--json", "--dir"])
        .arg(&dir)
        .output()?;
    let found = codes(&out)?;
    assert!(found.iter().any(|c| c == "I031"), "{found:?}");
    assert!(!found.iter().any(|c| c == "W028"), "{found:?}");
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_bussard_dir_from_cwd_dotenv_then_lookup_from_model() -> TestResult {
    let root = root("cwd-dir")?;
    let project = root.join("project");
    std::fs::create_dir_all(&project)?;
    model(&project)?;
    let work = root.join("work");
    std::fs::create_dir_all(&work)?;
    // cwd's `.env` names the model; its password is NOT applied, because the
    // lookup from the model then finds `<project>/.env` first.
    std::fs::write(
        work.join(".env"),
        "BUSSARD_DIR=../project/knx\nBUSSARD_KEYRING_PASSWORD=wrong\n",
    )?;
    std::fs::write(
        project.join(".env"),
        format!("BUSSARD_KEYRING_PASSWORD=\"{PASSWORD}\"\r\n"),
    )?;
    let out = bussard(&work)
        .args(["validate", "--json", "--timing"])
        .output()?;
    let found = codes(&out)?;
    assert!(found.iter().any(|c| c == "W028"), "{found:?}");
    assert!(!found.iter().any(|c| c == "W030"), "{found:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // `BUSSARD_DIR` is relative, so the file is named `../project/.env`
    // (`../project\.env` on Windows: compare with one separator).
    let normalized = stderr.replace('\\', "/");
    assert!(
        normalized.contains("dotenv") && normalized.contains("project/.env"),
        "--timing names the file: {stderr}"
    );
    assert!(!stderr.contains(PASSWORD), "never print a value: {stderr}");
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_allow_real_gateway_in_dotenv_does_not_open_the_write_gate() -> TestResult {
    let root = root("gate")?;
    std::fs::write(
        root.join(".env"),
        "BUSSARD_GATEWAY=192.0.2.1:3671\nBUSSARD_ALLOW_REAL_GATEWAY=1\n",
    )?;
    let out = bussard(&root)
        .args(["write", "3/0/4", "on", "--dpt", "1.001", "--yes", "--dir"])
        .arg(root.join("knx"))
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must refuse: {stderr}");
    assert!(
        stderr.contains("refusing to write to non-loopback gateway 192.0.2.1:3671"),
        "the gateway comes from the .env, the opt-in does not: {stderr}"
    );
    assert!(
        stderr.contains("BUSSARD_ALLOW_REAL_GATEWAY in") && stderr.contains("is ignored"),
        "the ignored key is named: {stderr}"
    );
    std::fs::remove_dir_all(&root)?;
    Ok(())
}
