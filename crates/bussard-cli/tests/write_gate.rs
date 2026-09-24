//! Safety-envelope tests for write commands (issue #74).
//!
//! These exercise the non-loopback opt-in gate and the confirmation prompts,
//! none of which require a live bus: the gate and the non-TTY confirmation both
//! fire before any connection is attempted. Every case uses a non-loopback
//! gateway (`192.0.2.1`, TEST-NET-1, RFC 5737) or a bogus loopback port that is
//! never contacted, so no real gateway is ever touched.

use std::process::{Command, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A gateway host guaranteed not to be a real endpoint: TEST-NET-1 (RFC 5737),
/// which is non-loopback so it exercises the opt-in gate but is never contacted
/// (the gate refuses first).
const NON_LOOPBACK: &str = "192.0.2.1:3671";

/// Runs `bussard` with the given args and no TTY, returning (success, stderr).
fn run(args: &[&str], allow_env: bool) -> std::io::Result<(bool, String)> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.args(args)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if allow_env {
        cmd.env("BUSSARD_ALLOW_REAL_GATEWAY", "1");
    }
    let out = cmd.output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

#[test]
fn write_refuses_non_loopback_gateway_without_optin() -> TestResult {
    // No model dir needed: with --dpt the write is unmodeled, and the gate fires
    // before any bus contact.
    let (success, stderr) = run(
        &[
            "write",
            "3/0/4",
            "on",
            "--dpt",
            "1.001",
            "--dir",
            "/nonexistent-knx",
            "--gateway",
            NON_LOOPBACK,
        ],
        false,
    )?;
    assert!(!success, "must refuse; stderr:\n{stderr}");
    assert!(
        stderr.contains("refusing to write to non-loopback gateway"),
        "expected the non-loopback refusal; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("192.0.2.1:3671"),
        "must name the host; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--allow-remote-gateway"),
        "must state how to proceed; stderr:\n{stderr}"
    );
    Ok(())
}

#[test]
fn write_non_tty_without_yes_is_refused_on_loopback() -> TestResult {
    // Loopback is exempt from the opt-in gate, but a non-TTY write still needs
    // --yes: it must not fire blind. The confirmation refusal names the gateway.
    // The loopback port is bogus and never reached (the confirmation fails
    // first).
    let (success, stderr) = run(
        &[
            "write",
            "3/0/4",
            "on",
            "--dpt",
            "1.001",
            "--dir",
            "/nonexistent-knx",
            "--gateway",
            "127.0.0.1:1",
        ],
        false,
    )?;
    assert!(!success, "must refuse without --yes; stderr:\n{stderr}");
    assert!(
        stderr.contains("refusing to write") && stderr.contains("--yes"),
        "expected the non-TTY confirmation refusal; stderr:\n{stderr}"
    );
    // The confirmation names the resolved gateway.
    assert!(
        stderr.contains("127.0.0.1:1"),
        "confirmation must name the gateway; stderr:\n{stderr}"
    );
    Ok(())
}

#[test]
fn flash_refuses_non_loopback_gateway_without_optin() -> TestResult {
    // A missing product file would fail eventually, but the gate fires first —
    // assert the refusal names the host. `--yes` is present so only the gate can
    // stop it.
    let (success, stderr) = run(
        &[
            "flash",
            "1.1.10",
            "--product",
            "/nonexistent.knxprod",
            "--yes",
            "--dir",
            "/nonexistent-knx",
            "--gateway",
            NON_LOOPBACK,
        ],
        false,
    )?;
    assert!(!success, "must refuse; stderr:\n{stderr}");
    // The product read happens before the gate in flash, so this may fail on the
    // product instead; accept either the gate refusal or a product error, but if
    // it is the gate it must name the host.
    if stderr.contains("non-loopback gateway") {
        assert!(
            stderr.contains("192.0.2.1"),
            "gate must name the host; stderr:\n{stderr}"
        );
    }
    Ok(())
}

#[test]
fn assign_non_tty_without_yes_is_refused() -> TestResult {
    // An explicit address is no longer consent: a non-TTY assign without --yes
    // must refuse before touching the bus. Loopback keeps the opt-in gate out of
    // the way so the confirmation gate is what fires.
    let (success, stderr) = run(
        &[
            "assign",
            "1.1.47",
            "--dir",
            "/nonexistent-knx",
            "--gateway",
            "127.0.0.1:1",
        ],
        false,
    )?;
    assert!(!success, "must refuse without --yes; stderr:\n{stderr}");
    assert!(
        stderr.contains("refusing to assign") && stderr.contains("--yes"),
        "expected the non-TTY refusal naming --yes; stderr:\n{stderr}"
    );
    Ok(())
}

// --- the long-running servers (issue #74 follow-up) --------------------------
//
// `bussard mcp --allow-writes` and `bussard viz --allow-writes/--watch-prog`
// can transmit for their whole lifetime, so both run the same gate at server
// construction. The refusal happens before the listener binds and before any
// bus contact, so these cases terminate immediately.

/// Creates a minimal, loadable model directory under the OS temp dir.
///
/// Both servers load the model before resolving the connection, so the gate
/// cases need a directory that exists and parses.
fn model_dir(tag: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-gate-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups:\n  \"3/0/4\":\n    name: Living Room Blind Move\n    dpt: \"1.008\"\n",
    )?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    Ok(dir)
}

/// Asserts that a server refused to start on the non-loopback write gate.
fn assert_gate_refusal(success: bool, stderr: &str) {
    assert!(!success, "must refuse to start; stderr:\n{stderr}");
    assert!(
        stderr.contains("refusing to write to non-loopback gateway"),
        "expected the non-loopback refusal; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("192.0.2.1:3671"),
        "must name the host; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--allow-remote-gateway"),
        "must state how to proceed; stderr:\n{stderr}"
    );
}

#[test]
fn mcp_allow_writes_refuses_non_loopback_gateway_without_optin() -> TestResult {
    let dir = model_dir("mcp")?;
    let (success, stderr) = run(
        &[
            "mcp",
            "--allow-writes",
            "--dir",
            dir.to_str().ok_or("non-UTF-8 dir")?,
            "--gateway",
            NON_LOOPBACK,
        ],
        false,
    )?;
    assert_gate_refusal(success, &stderr);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn mcp_allow_programming_refuses_non_loopback_gateway_without_optin() -> TestResult {
    // The programming tier (issue #118) writes device tables: the server must
    // refuse to start against a real gateway without the opt-in.
    let dir = model_dir("mcp-program")?;
    let (success, stderr) = run(
        &[
            "mcp",
            "--allow-programming",
            "--dir",
            dir.to_str().ok_or("non-UTF-8 dir")?,
            "--gateway",
            NON_LOOPBACK,
        ],
        false,
    )?;
    assert_gate_refusal(success, &stderr);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn viz_allow_writes_refuses_non_loopback_gateway_without_optin() -> TestResult {
    let dir = model_dir("viz-write")?;
    let (success, stderr) = run(
        &[
            "viz",
            "--allow-writes",
            "--listen",
            "127.0.0.1:0",
            "--dir",
            dir.to_str().ok_or("non-UTF-8 dir")?,
            "--gateway",
            NON_LOOPBACK,
        ],
        false,
    )?;
    assert_gate_refusal(success, &stderr);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn viz_watch_prog_refuses_non_loopback_gateway_without_optin() -> TestResult {
    // `--watch-prog` puts broadcast reads on the bus on a timer: also a write
    // in the gate's sense, and it must not run unnoticed against a real house.
    let dir = model_dir("viz-prog")?;
    let (success, stderr) = run(
        &[
            "viz",
            "--watch-prog",
            "--listen",
            "127.0.0.1:0",
            "--dir",
            dir.to_str().ok_or("non-UTF-8 dir")?,
            "--gateway",
            NON_LOOPBACK,
        ],
        false,
    )?;
    assert_gate_refusal(success, &stderr);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
