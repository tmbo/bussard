//! End-to-end subprocess test of `bussard mcp` over real stdio.
//!
//! Spawns the built binary, speaks a JSON-RPC `initialize` + `tools/list`
//! handshake on its stdin/stdout, and asserts:
//!
//! - stdout carries **only** valid JSON-RPC (nothing else may print there), and
//! - `tools/list` returns exactly the expected tool set (8 in `--passive`).
//!
//! This is the stdout-purity guard the design brief calls for.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Writes a minimal model directory and returns its path.
fn write_model(dir: &std::path::Path) {
    std::fs::create_dir_all(dir.join("devices")).unwrap();
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n  gateway: \"192.0.2.1:3671\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("groups.yaml"),
        "project: Demo\ngroups:\n  \"3/2/0\":\n    name: Windalarm\n    dpt: \"1.005\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("links.yaml"), "links: {}\n").unwrap();
}

#[test]
fn mcp_stdio_handshake_is_pure_json_and_lists_seven_passive_tools() {
    let tmp = std::env::temp_dir().join(format!("bussard-mcp-stdio-{}", std::process::id()));
    let knx = tmp.join("knx");
    write_model(&knx);

    let bin = env!("CARGO_BIN_EXE_bussard");
    let mut child = Command::new(bin)
        .args(["mcp", "--dir"])
        .arg(&knx)
        .arg("--passive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bussard mcp");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // initialize.
    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"}
        }
    });
    writeln!(stdin, "{init}").unwrap();
    stdin.flush().unwrap();

    // Read the initialize response line.
    let init_line = read_line(&mut reader);
    let init_resp: serde_json::Value =
        serde_json::from_str(&init_line).expect("initialize response is valid JSON");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "bussard");

    // initialized notification, then tools/list.
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    )
    .unwrap();
    stdin.flush().unwrap();

    // Read lines until we get the tools/list response (id == 2). Every line we
    // read from stdout must be valid JSON — that is the purity guarantee.
    let mut tools: Option<Vec<String>> = None;
    for _ in 0..10 {
        let line = read_line(&mut reader);
        if line.is_empty() {
            break;
        }
        let v: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("non-JSON on stdout: {line:?} ({e})"));
        if v["id"] == 2 {
            let names = v["result"]["tools"]
                .as_array()
                .expect("tools array")
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            tools = Some(names);
            break;
        }
    }

    // Close stdin so the server exits on EOF, then reap. The assertion above
    // already has the tools/list response, so this is only a graceful-exit grace
    // window: a short poll (the server exits near-instantly on EOF) followed by
    // an unconditional kill, rather than a fixed 3s wait.
    drop(stdin);
    let _ = child.wait_timeout(Duration::from_millis(500));
    let _ = child.kill();

    let mut tools = tools.expect("received a tools/list response");
    tools.sort();
    let mut expected = vec![
        "knx_get_device",
        "knx_get_group",
        "knx_infer_group",
        "knx_model_lookup",
        "knx_project_summary",
        "knx_recent_telegrams",
        "knx_validate",
        "knx_wait_for_telegram",
    ];
    expected.sort_unstable();
    assert_eq!(tools, expected, "passive mode exposes exactly 8 tools");

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Reads one line, returning it trimmed (empty string on EOF).
fn read_line(reader: &mut impl BufRead) -> String {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => String::new(),
        Ok(_) => line.trim_end().to_string(),
        Err(_) => String::new(),
    }
}

/// A tiny `wait_timeout` shim so we don't pull in the `wait-timeout` crate: it
/// polls `try_wait` for up to `dur`.
trait WaitTimeout {
    fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
        let deadline = std::time::Instant::now() + dur;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
