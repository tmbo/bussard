//! `bussard mcp --allow-home-assistant` as a subprocess (issue #280): the
//! token stays out of stdout and stderr through status, plan and apply and
//! an automation plan and apply, at the most verbose log level.
//!
//! Home Assistant is the mock from `bussard-testkit` on 127.0.0.1; the bus
//! connection is a loopback port and the server is passive.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_testkit::{MockHaConfig, MockHomeAssistant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TOKEN: &str = "llat-stdio-91be44f0c3-secret";

#[test]
fn test_mcp_home_assistant_tier_never_prints_the_token() -> TestResult {
    let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
    let tmp = tempfile_dir()?;
    let knx = tmp.join("knx");
    std::fs::create_dir_all(knx.join("devices"))?;
    std::fs::create_dir_all(knx.join("ha"))?;
    std::fs::write(
        knx.join("bussard.toml"),
        format!(
            "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n\n\
             [home_assistant]\nurl = \"{}\"\nconfig_path = \"ha/knx.yaml\"\n",
            mock.url()
        ),
    )?;
    std::fs::write(
        knx.join("groups.toml"),
        "groups = [\n  { address = \"1/0/1\", name = \"Licht\", dpt = \"1.001\" },\n  \
         { address = \"4/3/2\", name = \"Zu Hause\", dpt = \"1.001\" },\n  \
         { address = \"4/3/10\", name = \"Gastmodus\", dpt = \"1.001\" },\n]\n",
    )?;
    std::fs::write(knx.join("ha/knx.yaml"), "knx:\n")?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["-vv", "mcp", "--dir"])
        .arg(&knx)
        .args([
            "--gateway",
            "127.0.0.1:9",
            "--passive",
            "--allow-home-assistant",
        ])
        .env("BUSSARD_NO_DOTENV", "1")
        .env("BUSSARD_HA_TOKEN", TOKEN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let mut stdout_seen = String::new();

    send(
        &mut stdin,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"probe","version":"0"}}}),
    )?;
    let init = response(&mut reader, 1, &mut stdout_seen)?;
    assert!(
        init["result"]["instructions"]
            .as_str()
            .is_some_and(|i| i.contains("knx_ha_plan")),
        "{init}"
    );
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )?;

    let status = tool(
        &mut stdin,
        &mut reader,
        2,
        "knx_ha_status",
        serde_json::json!({}),
        &mut stdout_seen,
    )?;
    assert_eq!(status["authorized"], true, "{status}");
    let plan = tool(
        &mut stdin,
        &mut reader,
        3,
        "knx_ha_plan",
        serde_json::json!({}),
        &mut stdout_seen,
    )?;
    let digest = plan["plan_digest"].as_str().ok_or("no digest")?.to_string();
    let applied = tool(
        &mut stdin,
        &mut reader,
        4,
        "knx_ha_apply",
        serde_json::json!({"plan_digest": digest}),
        &mut stdout_seen,
    )?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(mock.reloads(), 1);
    let rule = serde_json::json!({
        "id": "bussard_guest_mode_end",
        "when": {"ga": "4/3/2", "value": "1"},
        "then": [{"send": {"ga": "4/3/10", "value": "0"}}],
    });
    let auto_plan = tool(
        &mut stdin,
        &mut reader,
        5,
        "knx_ha_automation_plan",
        rule,
        &mut stdout_seen,
    )?;
    let auto_digest = auto_plan["plan_digest"]
        .as_str()
        .ok_or("no automation digest")?
        .to_string();
    let auto_applied = tool(
        &mut stdin,
        &mut reader,
        6,
        "knx_ha_automation_apply",
        serde_json::json!({"plan_digest": auto_digest}),
        &mut stdout_seen,
    )?;
    assert_eq!(auto_applied["ok"], true, "{auto_applied}");
    assert_eq!(mock.automation_reloads(), 1);

    drop(stdin);
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while child.try_wait()?.is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(stderr.contains("audit: knx_ha_apply"), "{stderr}");
    assert!(
        stderr.contains("audit: knx_ha_automation_apply"),
        "{stderr}"
    );
    assert!(!stderr.contains(TOKEN), "the token is on stderr");
    assert!(!stdout_seen.contains(TOKEN), "the token is on stdout");
    Ok(())
}

/// A fresh scratch directory under the system temp dir.
fn tempfile_dir() -> TestResult<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("bussard-mcp-ha-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn send(stdin: &mut impl Write, message: serde_json::Value) -> TestResult {
    writeln!(stdin, "{message}")?;
    stdin.flush()?;
    Ok(())
}

/// Reads stdout lines until the response with `id`, keeping every line.
fn response(
    reader: &mut impl BufRead,
    id: u64,
    seen: &mut String,
) -> TestResult<serde_json::Value> {
    for _ in 0..20 {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        seen.push_str(&line);
        let value: serde_json::Value = serde_json::from_str(line.trim_end())?;
        if value["id"] == id {
            return Ok(value);
        }
    }
    Err(format!("no response with id {id}").into())
}

/// Calls a tool and returns its structured content.
fn tool(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    id: u64,
    name: &str,
    arguments: serde_json::Value,
    seen: &mut String,
) -> TestResult<serde_json::Value> {
    send(
        stdin,
        serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":name,"arguments":arguments}}),
    )?;
    let value = response(reader, id, seen)?;
    Ok(value["result"]["structuredContent"].clone())
}
