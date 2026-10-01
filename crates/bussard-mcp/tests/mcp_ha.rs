//! The Home Assistant tier over MCP (issue #280), against the mock Home
//! Assistant from `bussard-testkit` on 127.0.0.1.
//!
//! - the gate: the three tools exist only with the `[home_assistant]` table
//!   AND `--allow-home-assistant`;
//! - `knx_ha_status` against the mock;
//! - `knx_ha_plan` on a fixture model: per-entity sentences and a digest;
//! - `knx_ha_apply`: refuses an unknown and a stale digest, refuses a file
//!   that is not YAML-managed, and otherwise backs up, writes and reloads;
//! - the token appears in no result.
//!
//! No bus is opened: the connection points at a loopback port nothing listens
//! on, and the bus is never wired.

use std::net::SocketAddrV4;
use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_testkit::{MockHaConfig, MockHomeAssistant};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type TestResult = anyhow::Result<()>;

/// The token variable these tests use, installed as a `.env` value so no
/// test has to mutate the process environment.
const TOKEN_ENV: &str = "BUSSARD_HA_TOKEN_MCP_TEST";

/// The token the mock accepts. It must never appear in a tool result.
const TOKEN: &str = "llat-7c2e9b41d0a5-secret";

const LOCK: &str = r#"version = 3

[[device]]
address = "1.1.10"
objects = [
  { number = 0, key = "schalten", channel = "a-1", text = "Kanal A", function = "Schalten", dpt = "1.001", flags = "CWU" },
  { number = 1, key = "status", channel = "a-1", text = "Kanal A", function = "Status", dpt = "1.001", flags = "CRT" },
]
"#;

const DEVICE: &str = r#"address = "1.1.10"
name = "Schaltaktor Küche"

[links]
schalten.listen = ["1/0/1"]
status.send = "1/0/2"
"#;

/// Writes the fixture model; `ha` is the `[home_assistant]` table, if any.
fn write_model(dir: &Path, ha: Option<&str>) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    let mut config =
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n".to_string();
    if let Some(table) = ha {
        config.push_str(table);
    }
    std::fs::write(dir.join("bussard.toml"), config)?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/1\", name = \"Licht Küche\", dpt = \"1.001\" },\n  \
         { address = \"1/0/2\", name = \"Licht Küche Status\", dpt = \"1.001\" },\n  \
         { address = \"5/0/0\", name = \"Unbenutzt\", dpt = \"1.001\" },\n]\n",
    )?;
    std::fs::write(dir.join("devices").join("1.1.10.toml"), DEVICE)?;
    std::fs::write(dir.join("bussard.lock"), LOCK)?;
    Ok(())
}

/// The `[home_assistant]` table for `url`, with the file at `ha/knx.yaml`.
fn ha_table(url: &str) -> String {
    format!(
        "\n[home_assistant]\nurl = \"{url}\"\ntoken_env = \"{TOKEN_ENV}\"\nconfig_path = \"ha/knx.yaml\"\n"
    )
}

type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// Serves the model at `dir` over a duplex transport.
async fn serve(
    dir: &Path,
    allow_home_assistant: bool,
) -> anyhow::Result<(Client, tokio::task::JoinHandle<()>)> {
    bussard_model::dotenv::install(vec![(TOKEN_ENV.to_string(), TOKEN.to_string())]);
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), 9)),
        passive: true,
        allow_writes: false,
        no_model_edits: false,
        capture_db: None,
        allow_programming: false,
        allow_remote_gateway: false,
        plan_ttl: Duration::from_secs(600),
        keyring: None,
        allow_home_assistant,
    };
    let state = bussard_mcp::build_state(&config)?;
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, task))
}

/// Calls one tool and returns its structured content; asserts the token is
/// not in it.
async fn call(client: &Client, name: &'static str, args: Value) -> anyhow::Result<Value> {
    let mut params = CallToolRequestParams::new(name);
    if let Some(map) = args.as_object() {
        params = params.with_arguments(map.clone());
    }
    let value = client
        .call_tool(params)
        .await?
        .structured_content
        .ok_or_else(|| anyhow::anyhow!("{name} returned no structured content"))?;
    assert!(
        !value.to_string().contains(TOKEN),
        "{name} leaked the token: {value}"
    );
    Ok(value)
}

/// The registered tool names.
async fn tool_names(client: &Client) -> anyhow::Result<Vec<String>> {
    Ok(client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect())
}

fn ha_tools(names: &[String]) -> Vec<&String> {
    names.iter().filter(|n| n.starts_with("knx_ha_")).collect()
}

#[tokio::test]
async fn test_gate_needs_the_table_and_the_flag() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let with_table = tmp.path().join("with");
    let without = tmp.path().join("without");
    write_model(&with_table, Some(&ha_table("http://127.0.0.1:9")))?;
    write_model(&without, None)?;
    for (dir, flag, expected) in [
        (&with_table, false, 0),
        (&without, true, 0),
        (&without, false, 0),
        (&with_table, true, 3),
    ] {
        let (client, task) = serve(dir, flag).await?;
        let names = tool_names(&client).await?;
        assert_eq!(
            ha_tools(&names).len(),
            expected,
            "flag {flag}, table {}: {names:?}",
            dir == &with_table
        );
        let mut expected_names: Vec<String> =
            bussard_mcp::tool_names_with_ha(true, false, false, false, expected == 3)
                .into_iter()
                .map(str::to_string)
                .collect();
        let mut sorted = names.clone();
        sorted.sort();
        expected_names.sort();
        assert_eq!(sorted, expected_names);
        let instructions = client
            .peer_info()
            .and_then(|i| i.instructions.clone())
            .unwrap_or_default();
        assert_eq!(instructions.contains("knx_ha_plan"), expected == 3);
        let summary = call(&client, "knx_project_summary", json!({})).await?;
        assert_eq!(summary["server"]["home_assistant"], expected == 3);
        client.cancel().await?;
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_status_reads_the_mock() -> TestResult {
    let mock = MockHomeAssistant::start(
        MockHaConfig::new(TOKEN).with_entities(&[("switch.licht_kueche", "Licht Küche")]),
    )?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, Some(&ha_table(&mock.url())))?;
    std::fs::create_dir_all(dir.join("ha"))?;
    std::fs::write(dir.join("ha/knx.yaml"), "knx:\n")?;
    let (client, task) = serve(&dir, true).await?;
    let status = call(&client, "knx_ha_status", json!({})).await?;
    assert_eq!(status["ok"], true, "{status}");
    assert_eq!(status["reachable"], true);
    assert_eq!(status["authorized"], true);
    assert_eq!(status["version"], "2026.9.2");
    assert_eq!(status["knx_loaded"], true);
    assert_eq!(status["entity_counts"]["switch"], 1);
    assert_eq!(status["managed"], "yaml");
    assert_eq!(status["file"]["layout"], "package");
    assert_eq!(status["generated_entities"], 1);
    assert_eq!(status["running"]["generated_running"], 1, "{status}");
    assert!(mock.requests().iter().all(|r| r.method == "GET"));
    assert_eq!(mock.reloads(), 0);
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_plan_and_apply_write_back_up_and_reload() -> TestResult {
    let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, Some(&ha_table(&mock.url())))?;
    std::fs::create_dir_all(dir.join("ha"))?;
    let file = dir.join("ha/knx.yaml");
    let old = "knx:\n  sensor:\n  - name: Alt\n    state_address: 7/7/7\n    type: temperature\n";
    std::fs::write(&file, old)?;
    let (client, task) = serve(&dir, true).await?;

    let plan = call(&client, "knx_ha_plan", json!({})).await?;
    assert_eq!(plan["ok"], true, "{plan}");
    let sentences: Vec<&str> = plan["sentences"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("sentences"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        sentences,
        [
            "- sensor \"Alt\"",
            "+ switch \"Licht Küche\" (address 1/0/1, state_address 1/0/2)",
        ],
        "{plan}"
    );
    assert_eq!(plan["counts"]["added"], 1);
    assert_eq!(plan["counts"]["removed"], 1);
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no digest: {plan}"))?
        .to_string();
    assert!(
        plan["question"]
            .as_str()
            .is_some_and(|q| q.contains("reload"))
    );
    assert_eq!(
        std::fs::read_to_string(&file)?,
        old,
        "a plan writes nothing"
    );

    // A digest this session did not produce.
    let refused = call(
        &client,
        "knx_ha_apply",
        json!({"plan_digest": "0".repeat(64)}),
    )
    .await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert_eq!(mock.reloads(), 0);

    let applied = call(&client, "knx_ha_apply", json!({"plan_digest": digest})).await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["reload"]["ok"], true);
    assert_eq!(mock.reloads(), 1);
    let written = std::fs::read_to_string(&file)?;
    assert!(
        written.starts_with("# generated by bussard ha-config"),
        "{written}"
    );
    assert!(written.contains("name: Licht Küche"), "{written}");
    let backup = applied["backup"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no backup: {applied}"))?;
    assert!(
        Path::new(backup).starts_with(bussard_ha::apply::backup_dir(&dir)),
        "{backup}"
    );
    assert_eq!(std::fs::read_to_string(backup)?, old);
    assert_eq!(applied["status_after"]["reachable"], true);

    // Single use: the same digest again is refused, and nothing reloads.
    let again = call(&client, "knx_ha_apply", json!({"plan_digest": digest})).await?;
    assert_eq!(again["refused"], true, "{again}");
    assert_eq!(mock.reloads(), 1);

    // Reload only after a write: the order on the wire.
    let requests = mock.requests();
    let reload_at = requests
        .iter()
        .position(|r| r.method == "POST")
        .ok_or_else(|| anyhow::anyhow!("no POST"))?;
    assert_eq!(requests[reload_at].path, "/api/services/knx/reload");

    // Nothing to do now: no digest.
    let noop = call(&client, "knx_ha_plan", json!({})).await?;
    assert_eq!(noop["noop"], true, "{noop}");
    assert!(noop["plan_digest"].is_null());
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_apply_refuses_a_stale_digest() -> TestResult {
    let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, Some(&ha_table(&mock.url())))?;
    std::fs::create_dir_all(dir.join("ha"))?;
    let file = dir.join("ha/knx.yaml");
    std::fs::write(&file, "knx:\n")?;
    let (client, task) = serve(&dir, true).await?;
    let plan = call(&client, "knx_ha_plan", json!({})).await?;
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no digest: {plan}"))?
        .to_string();
    // Someone edits the file after the plan.
    std::fs::write(&file, "knx:\n  light: []\n")?;
    let refused = call(&client, "knx_ha_apply", json!({"plan_digest": digest})).await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .is_some_and(|r| r.contains("stale")),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(&file)?, "knx:\n  light: []\n");
    assert_eq!(mock.reloads(), 0);
    assert!(!dir.join("captures/backups/ha").exists());
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_plan_gives_no_digest_for_a_file_that_is_not_yaml_managed() -> TestResult {
    let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, Some(&ha_table(&mock.url())))?;
    std::fs::create_dir_all(dir.join("ha"))?;
    let file = dir.join("ha/knx.yaml");
    std::fs::write(&file, "homeassistant:\n  name: Haus\nknx:\n")?;
    let (client, task) = serve(&dir, true).await?;
    let plan = call(&client, "knx_ha_plan", json!({})).await?;
    assert_eq!(plan["file"]["state"], "not_yaml", "{plan}");
    assert!(plan["plan_digest"].is_null(), "{plan}");
    let status = call(&client, "knx_ha_status", json!({})).await?;
    assert_eq!(status["managed"], "not_yaml");
    // A missing file is not YAML-managed either.
    std::fs::remove_file(&file)?;
    let missing = call(&client, "knx_ha_plan", json!({})).await?;
    assert!(missing["plan_digest"].is_null(), "{missing}");
    assert!(!file.exists());
    assert_eq!(mock.reloads(), 0);
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_next_step_mentions_knx_ha_plan_for_an_exposed_group() -> TestResult {
    let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, Some(&ha_table(&mock.url())))?;
    let (client, task) = serve(&dir, true).await?;
    let exposed = call(
        &client,
        "knx_set_group",
        json!({"ga": "1/0/1", "name": "Licht Küche Decke"}),
    )
    .await?;
    let step = exposed["next_step"].as_str().unwrap_or_default();
    assert!(
        step.contains("knx_ha_plan") && step.contains("1/0/1"),
        "{exposed}"
    );
    let unexposed = call(
        &client,
        "knx_set_group",
        json!({"ga": "5/0/0", "name": "Weiterhin unbenutzt"}),
    )
    .await?;
    let step = unexposed["next_step"].as_str().unwrap_or_default();
    assert!(!step.contains("knx_ha_plan"), "{unexposed}");
    client.cancel().await?;
    task.abort();
    Ok(())
}
