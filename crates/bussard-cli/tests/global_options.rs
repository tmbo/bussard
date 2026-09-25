//! The global option group (issue #228): model directory discovery, the
//! `BUSSARD_DIR` / `BUSSARD_GATEWAY` / `BUSSARD_KEYRING` environment
//! variables, and their precedence (flag > env > `bussard.toml` > discovery).
//!
//! Nothing here reaches a bus: the directory checks use `groups reserve` and
//! `status` (files only), and the gateway checks use gateway spellings that
//! fail to parse before any socket is opened.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh scratch directory, symlinks resolved (macOS `/var` is a link).
fn scratch(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-globals-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(std::fs::canonicalize(&dir)?)
}

/// Writes a model marker (`bussard.toml`) into `dir`, creating it.
fn model(dir: &Path, gateway: &str) -> TestResult {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("bussard.toml"),
        format!("[connection]\ntransport = \"tunnel\"\ngateway = \"{gateway}\"\n"),
    )?;
    Ok(())
}

/// Runs bussard in `cwd` with the three global variables cleared, then `env`
/// set.
fn bussard(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bussard"));
    cmd.current_dir(cwd)
        .args(args)
        .env_remove("BUSSARD_DIR")
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Reserves a light block for `room` from `cwd` and asserts success.
fn reserve(cwd: &Path, room: &str, extra: &[&str], env: &[(&str, &str)]) -> TestResult {
    let mut args = vec!["groups", "reserve", room, "light"];
    args.extend_from_slice(extra);
    let out = bussard(cwd, &args, env)?;
    assert!(out.status.success(), "{}", text(&out));
    Ok(())
}

fn groups_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("groups.toml")).unwrap_or_default()
}

#[test]
fn test_discovery_root_model_and_subdirectory_resolve_the_same_dir() -> TestResult {
    let root = scratch("discover")?;
    let knx = root.join("knx");
    model(&knx, "127.0.0.1:3671")?;
    let sub = knx.join("devices");
    std::fs::create_dir_all(&sub)?;

    // The repository root (holds knx/), the model itself, a subdirectory.
    reserve(&root, "EG Küche", &[], &[])?;
    reserve(&knx, "EG Bad", &[], &[])?;
    reserve(&sub, "EG Flur", &[], &[])?;

    let groups = groups_of(&knx);
    for room in ["EG Küche", "EG Bad", "EG Flur"] {
        assert!(groups.contains(room), "{room} missing from {groups}");
    }
    assert!(!sub.join("groups.toml").exists());
    assert!(!root.join("groups.toml").exists());
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_discovery_no_model_anywhere_falls_back_to_knx() -> TestResult {
    let root = scratch("nomodel")?;
    let out = bussard(&root, &["status"], &[])?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("No history yet for knx"),
        "{}",
        text(&out)
    );
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_dir_flag_wins_over_discovery_and_env() -> TestResult {
    let root = scratch("dirwins")?;
    let a = root.join("a");
    let b = root.join("b");
    let c = root.join("c");
    for dir in [&a, &b, &c] {
        model(dir, "127.0.0.1:3671")?;
    }
    let b_str = b.to_str().ok_or("path")?;
    let c_str = c.to_str().ok_or("path")?;

    // Inside model a, --dir b wins over discovery (after the subcommand...).
    reserve(&a, "EG Küche", &["--dir", b_str], &[])?;
    // ...and before it.
    let out = bussard(
        &a,
        &["--dir", b_str, "groups", "reserve", "EG Bad", "light"],
        &[],
    )?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(groups_of(&b).contains("EG Küche") && groups_of(&b).contains("EG Bad"));
    assert!(!a.join("groups.toml").exists());

    // BUSSARD_DIR beats discovery; --dir beats BUSSARD_DIR.
    reserve(&a, "OG Büro", &[], &[("BUSSARD_DIR", b_str)])?;
    assert!(groups_of(&b).contains("OG Büro"));
    reserve(&a, "OG Bad", &["--dir", c_str], &[("BUSSARD_DIR", b_str)])?;
    assert!(groups_of(&c).contains("OG Bad"));
    assert!(!groups_of(&b).contains("OG Bad"));
    assert!(!a.join("groups.toml").exists());
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_gateway_precedence_flag_env_bussard_toml() -> TestResult {
    let root = scratch("gateway")?;
    // Unparseable ports: each run fails while resolving, before any socket.
    model(&root, "tomlgw:notaport")?;

    let out = bussard(&root, &["read", "1/1/1"], &[])?;
    assert!(!out.status.success());
    assert!(text(&out).contains("tomlgw"), "{}", text(&out));

    let env = [("BUSSARD_GATEWAY", "envgw:notaport")];
    let out = bussard(&root, &["read", "1/1/1"], &env)?;
    assert!(!out.status.success());
    assert!(text(&out).contains("envgw"), "{}", text(&out));

    let out = bussard(
        &root,
        &["read", "1/1/1", "--gateway", "flaggw:notaport"],
        &env,
    )?;
    assert!(!out.status.success());
    assert!(text(&out).contains("flaggw"), "{}", text(&out));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_keyring_env_serves_bus_commands_only() -> TestResult {
    let root = scratch("keyring")?;
    model(&root, "tomlgw:notaport")?;
    let missing = root.join("absent.knxkeys");
    let env = [("BUSSARD_KEYRING", missing.to_str().ok_or("path")?)];

    // A bus command resolves the keyring (and needs its password).
    let out = bussard(&root, &["read", "1/1/1"], &env)?;
    assert!(!out.status.success());
    let said = text(&out);
    assert!(said.contains("absent.knxkeys"), "{said}");
    assert!(said.contains("BUSSARD_KEYRING"), "{said}");

    // A files-only command never touches it.
    let out = bussard(&root, &["status"], &env)?;
    assert!(out.status.success(), "{}", text(&out));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_json_refused_by_a_command_without_json_output() -> TestResult {
    let root = scratch("json")?;
    model(&root, "127.0.0.1:3671")?;
    let out = bussard(&root, &["ha-config", "--json"], &[])?;
    assert!(!out.status.success());
    assert!(text(&out).contains("has no JSON output"), "{}", text(&out));
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn test_init_never_discovers_upward() -> TestResult {
    let root = scratch("init")?;
    model(&root, "127.0.0.1:3671")?;
    let sub = root.join("site");
    std::fs::create_dir_all(&sub)?;
    // Inside an existing model's subdirectory, init still creates ./knx.
    // Without a project, and without a terminal to offer the scan on, it only
    // writes the skeleton; nothing is sent to the (loopback) gateway.
    let out = bussard(
        &sub,
        &["init", "--gateway", "127.0.0.1:9", "--no-download"],
        &[],
    )?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(sub.join("knx").join("bussard.toml").exists());
    std::fs::remove_dir_all(&root)?;
    Ok(())
}
