//! The confirmation and output rules every command shares (issue #228, item
//! 6): one non-TTY refusal text, `--yes` separate from the download consent
//! `--yes-download`, `validate --json`, `"schema"` on every JSON document, and
//! one wording per error condition.
//!
//! Every bus row binds a `bussard-testkit` mock on `127.0.0.1:0` or names the
//! unused loopback port `127.0.0.1:1`, which a refused command never contacts.
//! The real-gateway rows name `192.0.2.1` (TEST-NET-1) and are refused by the
//! gate before any socket opens.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use bussard_testkit::{MockGateway, TestResult, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination};

/// The tail every non-TTY refusal ends with (`confirm::refusal`).
const REFUSAL_TAIL: &str = "without a terminal to confirm on; pass --yes to confirm \
                            non-interactively";

/// A fresh temp directory for one test.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bussard-confirm-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Writes a small model (one group address, one acceptance test) to `dir`.
fn write_model(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n\
         \x20 { address = \"1/0/10\", name = \"Kitchen light\", dpt = \"1.001\" },\n\
         ]\n",
    )?;
    std::fs::write(
        dir.join("tests.toml"),
        "[[tests]]\n\
         name = \"Kitchen light\"\n\
         write = { ga = \"1/0/10\", value = \"on\" }\n",
    )?;
    Ok(())
}

/// Runs the binary with stdin detached (never a terminal) and without the
/// real-gateway opt-in in the environment.
fn bussard(args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.args(args)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output()
}

/// `path` as `&str`.
fn s(path: &Path) -> Result<&str, &'static str> {
    path.to_str().ok_or("temp path is not UTF-8")
}

#[test]
fn test_confirm_refusal_is_one_text_for_every_write_command() -> TestResult {
    let tmp = temp_dir("refusal");
    let dir = tmp.join("knx");
    write_model(&dir)?;
    let product = tmp.join("unused.knxprod");
    let d = s(&dir)?;
    let p = s(&product)?;

    // (arguments, the action the refusal names). `flash`, `apply` and
    // `restore` read the device before they ask; their rows live with their
    // mock devices (device_facts_mock, line_mock, backup_replace_mock) and
    // assert the same REFUSAL_TAIL.
    let rows: &[(&[&str], &str)] = &[
        (&["assign", "1.1.47"], "refusing to assign 1.1.47 "),
        (&["assign"], "refusing to assign the next free address "),
        (
            &["adopt", "1.1.7"],
            "refusing to adopt the device in programming mode as 1.1.7 ",
        ),
        (
            &["adopt"],
            "refusing to adopt the device in programming mode ",
        ),
        (
            &["replace", "1.1.4", "--product", p],
            "refusing to replace 1.1.4 ",
        ),
        (
            &["commission", "--line", "1.1"],
            "refusing to commission line 1.1 ",
        ),
        (
            &["learn", "--ga", "1/0/10"],
            "refusing to learn group addresses ",
        ),
        (
            &["write", "1/0/10", "on"],
            "refusing to write 1/0/10 Kitchen light",
        ),
        (
            &["test"],
            "refusing to run 1 acceptance test(s) via 127.0.0.1:1 ",
        ),
    ];
    for (args, action) in rows {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--dir", d, "--gateway", "127.0.0.1:1"]);
        let out = bussard(&full, &[])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} must be refused: {stderr}");
        assert!(
            stderr.contains(action) && stderr.contains(REFUSAL_TAIL),
            "{args:?}: expected `{action}... {REFUSAL_TAIL}`, got: {stderr}"
        );
        assert_eq!(
            stderr.matches("refusing to").count(),
            1,
            "{args:?}: one refusal, nothing else: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn test_yes_is_not_download_consent() -> TestResult {
    // On `init` and `import`, `--yes` only skips the non-empty-directory
    // prompt; the download has its own flag next to it.
    for command in ["init", "import"] {
        let out = bussard(&[command, "--help"], &[])?;
        let help = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = help.lines().collect();
        let at = lines
            .iter()
            .position(|line| {
                let line = line.trim();
                line == "--yes" || line.starts_with("--yes ")
            })
            .ok_or("no --yes entry")?;
        let yes = lines[at..(at + 3).min(lines.len())].join(" ");
        assert!(
            yes.contains("confirmation prompt") && !yes.contains("download"),
            "{command} --yes: {yes}"
        );
    }
    // The download consent has one name on every command that downloads.
    for command in ["init", "import", "import-product", "adopt"] {
        let out = bussard(&[command, "--help"], &[])?;
        let help = String::from_utf8_lossy(&out.stdout);
        assert!(help.contains("--yes-download"), "{command} --help: {help}");
    }
    // adopt keeps --yes for its prompt, next to --yes-download.
    let out = bussard(&["adopt", "--help"], &[])?;
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.lines().any(|line| line.trim() == "--yes"),
        "adopt --help: {help}"
    );

    // --yes does not answer the download question: import-product without a
    // terminal and without --yes-download is refused before any download.
    let out = bussard(&["import-product", "--order-number", "AKK-0216.03"], &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "refusing to download this file without a terminal to confirm on; pass \
             --yes-download to consent non-interactively"
        ),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn test_validate_json_shape() -> TestResult {
    let tmp = temp_dir("validate");
    let dir = tmp.join("knx");
    write_model(&dir)?;
    // A group address without a DPT raises at least one diagnostic (W011).
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/10\", name = \"Kitchen light\" },\n]\n",
    )?;
    let out = bussard(&["validate", "--json", "--dir", s(&dir)?], &[])?;
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(doc["schema"], 1, "{doc}");
    let diagnostics = doc["diagnostics"]
        .as_array()
        .ok_or("validate --json: no diagnostics array")?;
    assert!(!diagnostics.is_empty(), "{doc}");
    for item in diagnostics {
        for key in ["code", "severity", "message", "location"] {
            assert!(item.get(key).is_some(), "missing {key}: {item}");
        }
    }
    // `--format` is gone (pre-release, no alias).
    let out = bussard(&["validate", "--format", "json", "--dir", s(&dir)?], &[])?;
    assert!(!out.status.success());
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// A mock gateway that answers a `GroupValueRead` on `1/0/10` with `on`.
fn start_gateway(rt: &tokio::runtime::Runtime) -> TestResult<MockGateway> {
    let source = ia("1.1.30")?;
    Ok(rt.block_on(
        MockGateway::builder()
            .channel(0x31)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .respond(move |cemi| {
                let Destination::Group(ga) = cemi.destination else {
                    return vec![];
                };
                if !matches!(cemi.apdu, Apdu::GroupValueRead) {
                    return vec![];
                }
                vec![CemiFrame::group_response_packed(ga, source, &[0x01])]
            })
            .start(),
    )?)
}

#[test]
fn test_every_json_output_carries_schema() -> TestResult {
    let tmp = temp_dir("schema");
    let dir = tmp.join("knx");
    write_model(&dir)?;
    let other = tmp.join("other");
    write_model(&other)?;
    let bundle = tmp.join("out.bussard");
    let rt = tokio::runtime::Runtime::new()?;
    let gw = start_gateway(&rt)?;
    let gateway = format!("127.0.0.1:{}", gw.port());
    let d = s(&dir)?;

    let rows: &[&[&str]] = &[
        &["validate"],
        &["status"],
        &["history"],
        &["show", "1"],
        &["undo"],
        &["doc"],
        &["groups", "reserve", "EG Küche", "light"],
        &["export", s(&bundle)?],
        &["diff", d, s(&other)?],
        &["read", "1/0/10", "--gateway", &gateway],
        &["write", "1/0/10", "on", "--yes", "--gateway", &gateway],
    ];
    for args in rows {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--json", "--dir", d]);
        let out = bussard(&full, &[])?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let doc: serde_json::Value = serde_json::from_str(&stdout).map_err(|e| {
            format!(
                "{args:?} --json is not one JSON document ({e}): {stdout}\nstderr: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        })?;
        assert!(
            doc["schema"].as_u64().is_some_and(|n| n >= 1),
            "{args:?} --json lacks a top-level schema: {doc}"
        );
    }
    drop(gw);
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn test_real_gateway_refusal_is_one_text() -> TestResult {
    let tmp = temp_dir("gate");
    let dir = tmp.join("knx");
    write_model(&dir)?;
    let d = s(&dir)?;
    let expected = bussard_transport::write_gate::WriteGateRefused {
        gateway: "192.0.2.1:3671".to_string(),
    }
    .to_string();
    let rows: &[&[&str]] = &[
        &["write", "1/0/10", "on", "--yes"],
        &["assign", "1.1.47", "--yes"],
        &["test", "--yes"],
    ];
    for args in rows {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--dir", d, "--gateway", "192.0.2.1:3671"]);
        let out = bussard(&full, &[])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?}: {stderr}");
        assert!(stderr.contains(&expected), "{args:?}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn test_missing_keyring_password_is_one_text() -> TestResult {
    let tmp = temp_dir("password");
    let dir = tmp.join("knx");
    write_model(&dir)?;
    let keyring = tmp.join("some.knxkeys");
    std::fs::write(&keyring, "<Keyring/>")?;
    let k = s(&keyring)?;
    let expected = bussard_service::secure::SecureKeyError::MissingPassword.to_string();
    let rows: &[&[&str]] = &[
        &["keys", "show"],
        &["read", "1/0/10", "--keyring", k, "--gateway", "127.0.0.1:1"],
    ];
    for args in rows {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--dir", s(&dir)?]);
        let out = bussard(&full, &[])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?}: {stderr}");
        assert!(stderr.contains(&expected), "{args:?}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn test_missing_keyring_is_one_text() -> TestResult {
    let tmp = temp_dir("keyring");
    let dir = tmp.join("knx");
    write_model(&dir)?;
    let out = bussard(
        &[
            "test",
            "--secure-idle",
            "1",
            "--dir",
            s(&dir)?,
            "--gateway",
            "127.0.0.1:1",
        ],
        &[],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&bussard_service::guidance::tunnel_credentials_hint()),
        "{stderr}"
    );
    let out = bussard(
        &["test", "--secure-transport", "tcp", "--dir", s(&dir)?],
        &[],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&bussard_service::guidance::tunnel_credentials_hint()),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}
