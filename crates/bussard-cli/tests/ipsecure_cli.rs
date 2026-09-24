//! The CLI against a loopback secure-only KNXnet/IP interface
//! ([`MockSecureGateway`]; issue #71 Phase B, #182).
//!
//! - no credentials: `scan` fails at once with the "requires KNXnet/IP
//!   Secure" refusal, no reconnect loop, no fallback-source warning;
//! - `--secure-user` / `--secure-password-env`: `write` goes through a secure
//!   session;
//! - `init` reports the interface as secure-only.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use bussard_secure::{Password, salt};
use bussard_testkit::{MockSecureGateway, TestResult, group_dest};

const USER_PASSWORD: &str = "synthetic-tunnel-user-3";
const PASSWORD_ENV: &str = "BUSSARD_TEST_TUNNEL_PW";

async fn gateway() -> TestResult<MockSecureGateway> {
    Ok(MockSecureGateway::builder()
        .user(
            3,
            Password::new(USER_PASSWORD).derive(salt::USER_PASSWORD),
            0x1117,
        )
        .start()
        .await?)
}

fn model_dir(tag: &str, port: u16) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!("bussard-ipsecure-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        format!("connection:\n  transport: tunnel\n  gateway: 127.0.0.1:{port}\n"),
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "project: ipsecure\ngroups:\n  1/2/3:\n    name: Light\n    dpt: '1.001'\n",
    )?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    Ok(dir)
}

async fn bussard(args: Vec<String>) -> TestResult<Output> {
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_bussard"))
            .args(&args)
            .env(PASSWORD_ENV, USER_PASSWORD)
            .env("BUSSARD_TUNNEL_RECONNECT_SECS", "0")
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .stdin(Stdio::null())
            .output()
    })
    .await??;
    Ok(out)
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_scan_secure_only_interface_without_credentials_refuses_cleanly() -> TestResult {
    let gw = gateway().await?;
    let dir = model_dir("scan", gw.addr().port())?;
    let gateway = gw.addr().to_string();
    let started = Instant::now();
    let out = bussard(args(&[
        "scan",
        "1.1",
        "--from",
        "1",
        "--to",
        "2",
        "--dir",
        &dir.to_string_lossy(),
        "--gateway",
        &gateway,
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("interface {gateway} requires KNXnet/IP Secure")),
        "{stderr}"
    );
    assert!(!stderr.contains("retrying"), "no reconnect loop: {stderr}");
    assert!(
        !stderr.contains("fallback source"),
        "no fallback-source warning: {stderr}"
    );
    assert!(started.elapsed() < Duration::from_secs(8), "fails fast");
    assert_eq!(gw.stats()?.plain_refusals, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_write_with_explicit_secure_user_goes_through_a_secure_session() -> TestResult {
    let gw = gateway().await?;
    let dir = model_dir("write", gw.addr().port())?;
    let out = bussard(args(&[
        "write",
        "1/2/3",
        "on",
        "--yes",
        "--dir",
        &dir.to_string_lossy(),
        "--gateway",
        &gw.addr().to_string(),
        "--secure-user",
        "3",
        "--secure-password-env",
        PASSWORD_ENV,
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let stats = gw.stats()?;
    assert_eq!(stats.users, vec![3]);
    assert_eq!(stats.plain_refusals, 0);
    let write = stats.requests.first().ok_or("no frame reached the mock")?;
    assert_eq!(group_dest(write)?, "1/2/3");
    // The password never reaches the output.
    assert!(!stderr.contains(USER_PASSWORD));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(USER_PASSWORD));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_secure_user_without_password_env_is_refused() -> TestResult {
    let gw = gateway().await?;
    let dir = model_dir("half", gw.addr().port())?;
    let out = bussard(args(&[
        "write",
        "1/2/3",
        "on",
        "--yes",
        "--dir",
        &dir.to_string_lossy(),
        "--secure-user",
        "3",
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("--secure-password-env"), "{stderr}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_init_reports_a_secure_only_interface() -> TestResult {
    let gw = gateway().await?;
    let dir = std::env::temp_dir().join(format!("bussard-ipsecure-init-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let out = bussard(vec![
        "init".into(),
        "--gateway".into(),
        gw.addr().to_string(),
        "--dir".into(),
        dir.to_string_lossy().into_owned(),
    ])
    .await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("KNXnet/IP Secure: tunnelling is secure-only"),
        "{stdout}"
    );
    assert!(stdout.contains("--secure-user"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_monitor_secure_only_interface_without_credentials_exits() -> TestResult {
    let gw = gateway().await?;
    let dir = model_dir("monitor", gw.addr().port())?;
    let started = Instant::now();
    let out = bussard(args(&[
        "monitor",
        "--dir",
        &dir.to_string_lossy(),
        "--gateway",
        &gw.addr().to_string(),
    ]))
    .await?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("requires KNXnet/IP Secure"), "{stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "monitor does not hang"
    );
    Ok(())
}
