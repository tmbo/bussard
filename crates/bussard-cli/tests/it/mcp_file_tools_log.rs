//! Issue #743: a password given to `knx_import_file` and `knx_export` and the
//! key material of the keyring they move never reach the log, even at
//! `RUST_LOG=trace`, nor the JSON-RPC answers. Spawns the real `bussard mcp`
//! (passive, against a loopback address nobody answers on) with stderr
//! captured to a file.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use bussard_project::KeyStore;
use bussard_secure::Key16;
use bussard_testkit::TestResult;
use serde_json::{Value, json};

/// The keyring's made-up password.
const PASSWORD: &str = "synthetic-log-password-5d1e";
/// The SYNTHETIC group key of 1/0/4.
const GROUP_KEY: [u8; 16] = [0x5a; 16];

#[test]
fn test_mcp_file_tools_never_log_the_password_or_key_material() -> TestResult {
    let tmp = std::env::temp_dir().join(format!("bussard-mcp-keys-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let dir = tmp.join("knx");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("bussard.toml"), "")?;
    std::fs::write(
        dir.join("groups.toml"),
        "project = \"Demo\"\ngroups = [\n  { address = \"1/0/4\", name = \"Hall\", dpt = \
         \"1.001\", secure = true },\n]\n",
    )?;
    let mut store = KeyStore::new("Demo");
    store
        .group_keys
        .insert("1/0/4".parse()?, Key16::new(GROUP_KEY));
    let keyring = tmp.join("export.knxkeys");
    std::fs::write(&keyring, store.export_knxkeys(PASSWORD)?.xml)?;
    let stderr_path = tmp.join("stderr.log");
    let stderr = std::fs::File::create(&stderr_path)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .env("BUSSARD_NO_DOTENV", "1")
        .env("RUST_LOG", "trace")
        .env_remove("BUSSARD_KEYRING_PASSWORD")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .args(["mcp", "--passive", "--dir"])
        .arg(&dir)
        .args(["--gateway", "127.0.0.1:9"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let mut reader = BufReader::new(stdout);
    let send = |stdin: &mut std::process::ChildStdin, v: Value| -> TestResult {
        writeln!(stdin, "{v}")?;
        stdin.flush()?;
        Ok(())
    };
    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "log-test", "version": "0"}
            }
        }),
    )?;
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )?;
    let out = tmp.join("handover.knxkeys");
    let calls = [
        json!({"name": "knx_import_file", "arguments": {"path": keyring, "password": PASSWORD}}),
        json!({"name": "knx_export",
               "arguments": {"what": "keyring", "out": out, "password": PASSWORD}}),
    ];
    // One call at a time: the export needs the store the import writes.
    let mut answers = Vec::new();
    let mut wire = String::new();
    for (id, params) in (2..).zip(calls) {
        send(
            &mut stdin,
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}),
        )?;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            wire.push_str(&line);
            let v: Value = serde_json::from_str(line.trim_end())?;
            if v["id"] == id {
                answers.push(v);
                break;
            }
        }
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let log = std::fs::read_to_string(&stderr_path)?;

    assert_eq!(answers.len(), 2, "both calls answered: {wire}");
    for answer in &answers {
        let result = &answer["result"]["structuredContent"];
        assert_eq!(result["ok"], true, "{answer}");
    }
    assert!(
        log.contains("tools/call"),
        "the trace log saw the calls: {log}"
    );
    let hex: String = GROUP_KEY.iter().map(|b| format!("{b:02x}")).collect();
    // Base64 of sixteen 0x5a bytes; the byte list a Debug print shows.
    let base64 = "WlpaWlpaWlpaWlpaWlpaWg";
    let bytes = "90, 90, 90, 90";
    for secret in [PASSWORD, hex.as_str(), &hex.to_uppercase(), base64, bytes] {
        assert!(!log.contains(secret), "the log leaks {secret:?}");
        assert!(!wire.contains(secret), "an answer leaks {secret:?}: {wire}");
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}
