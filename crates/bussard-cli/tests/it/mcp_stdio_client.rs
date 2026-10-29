//! A minimal JSON-RPC client for `bussard mcp` over stdio, shared by the
//! integration tests that drive the real binary against a loopback mock.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use bussard_testkit::TestResult;
use serde_json::{Value, json};

/// A running `bussard mcp`, killed on drop.
pub(crate) struct McpServer {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl McpServer {
    /// Starts `bussard mcp --dir <dir> --gateway 127.0.0.1:<port> --keyring
    /// <keyring> <extra…>` with the keyring password `password` and the short
    /// mock timeouts, and completes the handshake.
    pub(crate) fn start(
        dir: &Path,
        port: u16,
        keyring: &Path,
        password: &str,
        extra: &[&str],
    ) -> TestResult<McpServer> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
            .env("BUSSARD_MGMT_TIMEOUT_MS", "300")
            .env("BUSSARD_ADDRESS_PROBE_MS", "200")
            .env("BUSSARD_KEYRING_PASSWORD", password)
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env_remove("BUSSARD_KEYRING")
            .arg("mcp")
            .arg("--dir")
            .arg(dir)
            .arg("--gateway")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--keyring")
            .arg(keyring)
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or("no stdin pipe")?;
        let stdout = child.stdout.take().ok_or("no stdout pipe")?;
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = McpServer {
            child,
            stdin,
            lines,
            next_id: 1,
        };
        server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-stdio-test", "version": "0"}
            }),
        )?;
        server.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        Ok(server)
    }

    fn send(&mut self, message: &Value) -> TestResult {
        writeln!(self.stdin, "{message}")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Sends a request and returns its `result`, skipping notifications.
    pub(crate) fn request(&mut self, method: &str, params: Value) -> TestResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let line = self.lines.recv_timeout(Duration::from_secs(90))?;
            let message: Value = serde_json::from_str(&line)?;
            if message["id"] == id {
                if let Some(error) = message.get("error") {
                    return Err(format!("{method} failed: {error}").into());
                }
                return Ok(message["result"].clone());
            }
        }
    }

    /// Calls a tool and returns its structured result.
    pub(crate) fn call(&mut self, tool: &str, args: Value) -> TestResult<Value> {
        let result = self.request("tools/call", json!({"name": tool, "arguments": args}))?;
        Ok(result["structuredContent"].clone())
    }

    /// Calls `tool` until the bus is connected (the server connects in the
    /// background), at most `tries` times, and returns the last result.
    pub(crate) fn call_when_connected(
        &mut self,
        tool: &str,
        args: Value,
        tries: usize,
    ) -> TestResult<Value> {
        let mut last = Value::Null;
        for _ in 0..tries {
            last = self.call(tool, args.clone())?;
            let reason = last["reason"].as_str().unwrap_or_default();
            if !(reason.contains("not wired")
                || reason.contains("not connected")
                || reason.contains("connecting"))
            {
                return Ok(last);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(last)
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
