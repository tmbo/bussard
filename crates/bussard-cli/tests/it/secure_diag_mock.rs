//! Issue #533: `bussard secure diag <ia>` reads a Data Secure device's
//! security failures log (PID 55), report (PID 57) and report control
//! (PID 58) with its tool key, and `--clear` clears the log, resets the
//! report and reads both back. `status <ia>` shows the same lines.
//!
//! All keys are SYNTHETIC. The mock binds 127.0.0.1 and every run passes an
//! explicit loopback `--gateway`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bussard_mgmt::property_ext::{
    A_FUNCTION_PROPERTY_EXT_COMMAND, A_FUNCTION_PROPERTY_EXT_STATE_READ,
    A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE, A_PROPERTY_EXT_VALUE_READ,
    A_PROPERTY_EXT_VALUE_RESPONSE, A_PROPERTY_EXT_VALUE_WRITE_CON,
    A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE, OT_SECURITY, PID_SECURITY_FAILURES_LOG,
    PID_SECURITY_REPORT, PID_SECURITY_REPORT_CONTROL,
};
use bussard_project::KeyStore;
use bussard_project::keystore::StoreDevice;
use bussard_secure::Key16;
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};

/// The key store's made-up password.
const PASSWORD: &str = "synthetic-store-password";
/// The synthetic tool key of 1.1.10.
const TOOL_KEY: [u8; 16] = [0x11; 16];

/// The device's failures log: counters (seq, crypto, access), the latest
/// failure's sender, and the report.
#[derive(Debug, Default)]
struct Log {
    counters: [u16; 3],
    latest: Option<u16>,
    report: u8,
}

/// The header fields of an `A_PropertyExt*` / `A_FunctionPropertyExt*`
/// payload: `(object type, property id)`.
fn ext_header(data: &[u8]) -> Option<(u16, u16)> {
    let h = data.get(..5)?;
    Some((
        u16::from_be_bytes([h[0], h[1]]),
        (u16::from(h[3] & 0x0F) << 8) | u16::from(h[4]),
    ))
}

/// A secured 1.1.10 whose security object serves PID 55, 57 and 58 from `log`.
fn device(log: Arc<Mutex<Log>>) -> TestResult<MockDevice> {
    Ok(MockDevice::system_b(ia("1.1.10")?)
        .with_data_secure(TOOL_KEY)
        .with_hook(move |_, apci, data| {
            let (object_type, pid) = ext_header(data)?;
            if object_type != OT_SECURITY {
                return None;
            }
            let mut log = log.lock().ok()?;
            let mut out = data.get(..5)?.to_vec();
            match (apci, pid) {
                (A_FUNCTION_PROPERTY_EXT_STATE_READ, PID_SECURITY_FAILURES_LOG) => {
                    match data.get(5..8)? {
                        [0, 0, 0] => {
                            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
                            for c in log.counters {
                                out.extend_from_slice(&c.to_be_bytes());
                            }
                        }
                        [0, 1, 0] => match log.latest {
                            Some(sender) => {
                                out.extend_from_slice(&[0x00, 0x01, 0x00]);
                                out.extend_from_slice(&sender.to_be_bytes());
                                out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x2A, 0x04]);
                            }
                            None => out.extend_from_slice(&[0xF8, 0x01]),
                        },
                        _ => out.extend_from_slice(&[0xF2, 0x00]),
                    }
                    Some(Reaction::Answer(
                        A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE,
                        out,
                    ))
                }
                (A_FUNCTION_PROPERTY_EXT_COMMAND, PID_SECURITY_FAILURES_LOG) => {
                    log.counters = [0; 3];
                    log.latest = None;
                    out.extend_from_slice(&[0x00, 0x00]);
                    Some(Reaction::Answer(
                        A_FUNCTION_PROPERTY_EXT_STATE_RESPONSE,
                        out,
                    ))
                }
                (A_PROPERTY_EXT_VALUE_READ, PID_SECURITY_REPORT | PID_SECURITY_REPORT_CONTROL) => {
                    let value = if pid == PID_SECURITY_REPORT {
                        log.report
                    } else {
                        0
                    };
                    out.extend_from_slice(&[0x01, 0x00, 0x01, value]);
                    Some(Reaction::Answer(A_PROPERTY_EXT_VALUE_RESPONSE, out))
                }
                (A_PROPERTY_EXT_VALUE_WRITE_CON, PID_SECURITY_REPORT) => {
                    log.report = *data.get(8)?;
                    out.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]);
                    Some(Reaction::Answer(
                        A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE,
                        out,
                    ))
                }
                _ => None,
            }
        }))
}

/// A model directory with 1.1.10 activated and a key store holding its tool
/// key.
fn model_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-diag-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.10.toml"),
        "address = \"1.1.10\"\nname = \"Secure actuator\"\n\n[security]\nactivated = true\n",
    )?;
    let mut store = KeyStore::new("Synthetic");
    store.devices.insert(
        ia("1.1.10")?,
        StoreDevice {
            tool_key: Some(Key16::new(TOOL_KEY)),
            ..StoreDevice::default()
        },
    );
    store.save(&dir, PASSWORD)?;
    Ok(dir)
}

/// Runs `bussard <args>` on `dir` against a mock serving `log`.
fn run(dir: &Path, log: Arc<Mutex<Log>>, args: &[&str]) -> TestResult<Output> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x5B)
            .idle_timeout(Duration::from_secs(60))
            .keep_serving()
            .device(device(log)?)
            .start(),
    )?;
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
        .env("BUSSARD_ADDRESS_PROBE_MS", "200")
        .env("BUSSARD_KEYRING_PASSWORD", PASSWORD)
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .args(args)
        .arg("--dir")
        .arg(dir)
        .arg("--gateway")
        .arg(format!("127.0.0.1:{}", gw.port()))
        .arg("--keyring")
        .arg(KeyStore::path(dir))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    drop(gw);
    Ok(out)
}

#[test]
fn test_secure_diag_reads_the_counters_and_the_latest_failure() -> TestResult {
    let dir = model_dir("read")?;
    let log = Arc::new(Mutex::new(Log {
        counters: [0, 0, 1],
        latest: Some(0x1118),
        report: 0x01,
    }));
    let out = run(&dir, Arc::clone(&log), &["secure", "diag", "1.1.10"]);
    let _ = std::fs::remove_dir_all(&dir);
    let out = out?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("security failures (PID 55): 0 sequence, 0 cryptographic, 1 access"),
        "{stdout}"
    );
    assert!(
        stdout.contains("latest failure: from 1.1.24: access error"),
        "{stdout}"
    );
    assert!(stdout.contains("a security failure is flagged"), "{stdout}");
    assert!(stdout.contains("(PID 58): disabled"), "{stdout}");
    // Read-only: nothing cleared.
    assert_eq!(log.lock().map_err(|_| "poisoned")?.counters, [0, 0, 1]);
    Ok(())
}

#[test]
fn test_secure_diag_clear_resets_and_reads_back() -> TestResult {
    let dir = model_dir("clear")?;
    let log = Arc::new(Mutex::new(Log {
        counters: [2, 3, 0],
        latest: Some(0x1118),
        report: 0x01,
    }));
    let out = run(
        &dir,
        Arc::clone(&log),
        &["secure", "diag", "1.1.10", "--clear", "--yes", "--json"],
    );
    let _ = std::fs::remove_dir_all(&dir);
    let out = out?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["cleared"], true, "{json}");
    assert_eq!(
        json["diagnostics"]["counters"]["cryptographic"], 0,
        "{json}"
    );
    assert_eq!(json["diagnostics"]["report_failure"], false, "{json}");
    let log = log.lock().map_err(|_| "poisoned")?;
    assert_eq!((log.counters, log.report), ([0; 3], 0));
    Ok(())
}

/// Issue #571: `knx_clear_security_log` clears the log over MCP behind the
/// CLI's confirmation: the first call reads (nothing cleared) and asks the
/// `secure diag --clear` question with a digest, a wrong digest is refused,
/// and the digest clears, resets the report and reads back.
#[test]
fn test_mcp_clear_security_log_asks_then_clears() -> TestResult {
    let dir = model_dir("mcp-clear")?;
    let log = Arc::new(Mutex::new(Log {
        counters: [2, 3, 0],
        latest: Some(0x1118),
        report: 0x01,
    }));
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(0x5D)
            .idle_timeout(Duration::from_secs(60))
            .keep_serving()
            .device(device(Arc::clone(&log))?)
            .start(),
    )?;
    let calls = (|| {
        let mut server = crate::mcp_stdio_client::McpServer::start(
            &dir,
            gw.port(),
            &KeyStore::path(&dir),
            PASSWORD,
            &["--no-model-edits", "--allow-programming"],
        )?;
        let args = serde_json::json!({"address": "1.1.10"});
        let plan = server.call_when_connected("knx_clear_security_log", args, 50)?;
        let counters_after_plan = log.lock().map_err(|_| "poisoned")?.counters;
        let wrong = server.call(
            "knx_clear_security_log",
            serde_json::json!({"address": "1.1.10", "plan_digest": "0000000000000000"}),
        )?;
        let digest = plan["plan_digest"].as_str().unwrap_or_default().to_string();
        let cleared = server.call(
            "knx_clear_security_log",
            serde_json::json!({"address": "1.1.10", "plan_digest": digest}),
        )?;
        TestResult::Ok((plan, counters_after_plan, wrong, cleared))
    })();
    drop(gw);
    let _ = std::fs::remove_dir_all(&dir);
    let (plan, counters_after_plan, wrong, cleared) = calls?;
    assert_eq!(plan["ok"], true, "{plan}");
    assert_eq!(
        plan["question"],
        "Clear the security failures log and reset the security report of 1.1.10?",
        "{plan}"
    );
    assert_eq!(
        plan["diagnostics"]["counters"]["cryptographic"], 3,
        "{plan}"
    );
    assert_eq!(counters_after_plan, [2, 3, 0], "the first call only reads");
    assert_ne!(wrong["ok"], true, "{wrong}");
    assert_eq!(cleared["cleared"], true, "{cleared}");
    assert_eq!(
        cleared["diagnostics"]["counters"]["cryptographic"], 0,
        "{cleared}"
    );
    let log = log.lock().map_err(|_| "poisoned")?;
    assert_eq!((log.counters, log.report), ([0; 3], 0));
    Ok(())
}
