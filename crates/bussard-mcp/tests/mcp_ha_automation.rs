//! bussard-managed Home Assistant automations over MCP (issue #280 step 2),
//! against the mock Home Assistant from `bussard-testkit` on 127.0.0.1.
//!
//! Plan, apply, update and remove; the refusals (unknown GA, DPT mismatch,
//! non-bussard id, an automation without the marker, stale and unknown
//! digests); the exact rendered guest-mode automation; the token in no
//! result. No bus is opened.

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

const TOKEN_ENV: &str = "BUSSARD_HA_TOKEN_AUTOMATION_TEST";
const TOKEN: &str = "llat-automation-5d1f0e-secret";

/// Writes a model with the guest-mode group addresses.
fn write_model(dir: &Path, url: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        format!(
            "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n\n\
             [home_assistant]\nurl = \"{url}\"\ntoken_env = \"{TOKEN_ENV}\"\n\
             config_path = \"ha/knx.yaml\"\n"
        ),
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"4/3/2\", name = \"Zu Hause\", dpt = \"1.001\" },\n  \
         { address = \"4/3/10\", name = \"Gastmodus\", dpt = \"1.001\" },\n  \
         { address = \"4/3/11\", name = \"Gastmodus Licht\", dpt = \"5.001\" },\n]\n",
    )?;
    Ok(())
}

type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

async fn serve(dir: &Path) -> anyhow::Result<(Client, tokio::task::JoinHandle<()>)> {
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
        allow_home_assistant: true,
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

fn guest_rule() -> Value {
    json!({
        "id": "bussard_guest_mode_end",
        "description": "Zu Hause ends guest mode",
        "when": {"ga": "4/3/2", "value": "1", "dpt": "1.001"},
        "then": [{"send": {"ga": "4/3/10", "value": "0", "dpt": "1.001"}}],
    })
}

fn digest(plan: &Value) -> anyhow::Result<String> {
    plan["plan_digest"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no digest: {plan}"))
}

/// The guest-mode automation exactly as bussard writes it.
fn guest_automation(model_name: &str) -> Value {
    json!({
        "id": "bussard_guest_mode_end",
        "alias": "when 4/3/2 receives 1, send 0 to 4/3/10",
        "description": format!("Zu Hause ends guest mode\n\nmanaged by bussard (model {model_name})"),
        "mode": "single",
        "triggers": [{
            "trigger": "knx.telegram",
            "destination": ["4/3/2"],
            "group_value_write": true,
            "group_value_response": false,
            "group_value_read": false,
            "incoming": true,
            "outgoing": false,
        }],
        "conditions": [{
            "condition": "template",
            "value_template": "{{ trigger.payload == 1 }}",
        }],
        "actions": [{
            "action": "knx.send",
            "data": {"address": "4/3/10", "payload": 0},
        }],
    })
}

#[tokio::test]
async fn test_guest_mode_plan_apply_update_remove() -> TestResult {
    let mock = MockHomeAssistant::start(MockHaConfig::new(TOKEN))?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, &mock.url())?;
    let (client, task) = serve(&dir).await?;

    // Plan: create, the sentence, the exact payload, nothing written.
    let plan = call(&client, "knx_ha_automation_plan", guest_rule()).await?;
    assert_eq!(plan["ok"], true, "{plan}");
    assert_eq!(plan["op"], "create");
    assert_eq!(plan["sentence"], "when 4/3/2 receives 1, send 0 to 4/3/10");
    assert_eq!(plan["automation"], guest_automation("knx"), "{plan}");
    assert!(
        plan["yaml"]
            .as_str()
            .is_some_and(|y| y.contains("knx.send"))
    );
    assert!(mock.automation("bussard_guest_mode_end").is_none());

    // Unknown digest refused.
    let refused = call(
        &client,
        "knx_ha_automation_apply",
        json!({"plan_digest": "f".repeat(64)}),
    )
    .await?;
    assert_eq!(refused["refused"], true, "{refused}");

    // Apply: stored exactly, automations reloaded, no backup for a new one.
    let applied = call(
        &client,
        "knx_ha_automation_apply",
        json!({"plan_digest": digest(&plan)?}),
    )
    .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["op"], "create");
    assert!(applied["backup"].is_null());
    let stored: Value = serde_json::from_str(
        &mock
            .automation("bussard_guest_mode_end")
            .ok_or_else(|| anyhow::anyhow!("not stored"))?,
    )?;
    assert_eq!(stored, guest_automation("knx"));
    assert_eq!(mock.automation_reloads(), 1);
    assert_eq!(mock.reloads(), 0, "the KNX integration is not reloaded");

    // The same rule again: unchanged, no digest.
    let again = call(&client, "knx_ha_automation_plan", guest_rule()).await?;
    assert_eq!(again["op"], "unchanged", "{again}");
    assert!(again["plan_digest"].is_null());

    // knx_ha_plan lists it as bussard-managed.
    std::fs::create_dir_all(dir.join("ha"))?;
    std::fs::write(dir.join("ha/knx.yaml"), "knx:\n")?;
    let ha_plan = call(&client, "knx_ha_plan", json!({})).await?;
    assert_eq!(
        ha_plan["automations"][0]["id"], "bussard_guest_mode_end",
        "{ha_plan}"
    );
    assert_eq!(ha_plan["automations"][0]["managed"], true);

    // Update: a backup of the previous JSON, the new config stored.
    let mut changed = guest_rule();
    changed["alias"] = json!("Zu Hause beendet Gastmodus");
    let update = call(&client, "knx_ha_automation_plan", changed).await?;
    assert_eq!(update["op"], "update", "{update}");
    assert!(
        update["sentences"][0]
            .as_str()
            .is_some_and(|s| s.contains("changes alias")),
        "{update}"
    );
    let updated = call(
        &client,
        "knx_ha_automation_apply",
        json!({"plan_digest": digest(&update)?}),
    )
    .await?;
    assert_eq!(updated["ok"], true, "{updated}");
    let backup = updated["backup"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no backup: {updated}"))?;
    let backup_path = std::path::Path::new(backup);
    assert!(
        backup_path.starts_with(bussard_ha::apply::backup_dir(&dir)),
        "{backup}"
    );
    assert!(
        backup_path.file_name().is_some_and(|n| n
            .to_string_lossy()
            .starts_with("automation-bussard_guest_mode_end-")),
        "{backup}"
    );
    let backed_up: Value = serde_json::from_str(&std::fs::read_to_string(backup)?)?;
    assert_eq!(backed_up, guest_automation("knx"));
    assert!(
        mock.automation("bussard_guest_mode_end")
            .is_some_and(|c| c.contains("Zu Hause beendet Gastmodus"))
    );

    // Stale on the Home Assistant side: someone edits the automation after
    // the removal plan.
    let stale_plan = call(
        &client,
        "knx_ha_automation_remove",
        json!({"id": "bussard_guest_mode_end"}),
    )
    .await?;
    let mut edited: Value = serde_json::from_str(
        &mock
            .automation("bussard_guest_mode_end")
            .ok_or_else(|| anyhow::anyhow!("not stored"))?,
    )?;
    edited["mode"] = json!("restart");
    bussard_ha::api::HaClient::new(&mock.url(), TOKEN.to_string(), TOKEN_ENV)?
        .save_automation("bussard_guest_mode_end", &edited)?;
    let stale = call(
        &client,
        "knx_ha_automation_remove",
        json!({"id": "bussard_guest_mode_end", "plan_digest": digest(&stale_plan)?}),
    )
    .await?;
    assert!(
        stale["reason"]
            .as_str()
            .is_some_and(|r| r.contains("stale")),
        "{stale}"
    );
    assert!(mock.automation("bussard_guest_mode_end").is_some());

    // Remove: plan first (nothing deleted), then with the digest.
    let remove_plan = call(
        &client,
        "knx_ha_automation_remove",
        json!({"id": "bussard_guest_mode_end"}),
    )
    .await?;
    assert_eq!(remove_plan["op"], "remove", "{remove_plan}");
    assert!(mock.automation("bussard_guest_mode_end").is_some());
    // A removal digest is not accepted by the apply tool.
    let wrong = call(
        &client,
        "knx_ha_automation_apply",
        json!({"plan_digest": digest(&remove_plan)?}),
    )
    .await?;
    assert_eq!(wrong["refused"], true, "{wrong}");
    let removed = call(
        &client,
        "knx_ha_automation_remove",
        json!({"id": "bussard_guest_mode_end", "plan_digest": digest(&remove_plan)?}),
    )
    .await?;
    assert_eq!(removed["ok"], true, "{removed}");
    assert!(mock.automation("bussard_guest_mode_end").is_none());
    assert!(removed["backup"].as_str().is_some());
    assert_eq!(mock.automation_reloads(), 3);
    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_automation_refusals() -> TestResult {
    let mock = MockHomeAssistant::start(
        MockHaConfig::new(TOKEN)
            .with_automation(
                "bussard_hand_made",
                r#"{"id":"bussard_hand_made","alias":"x","description":"mine"}"#,
            )
            .with_automation(
                "kitchen_lights",
                r#"{"id":"kitchen_lights","alias":"Kitchen","description":"mine"}"#,
            ),
    )?;
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("knx");
    write_model(&dir, &mock.url())?;
    let (client, task) = serve(&dir).await?;
    let reason = |v: &Value| v["reason"].as_str().unwrap_or_default().to_string();

    let mut unknown = guest_rule();
    unknown["then"][0]["send"]["ga"] = json!("4/3/99");
    let r = call(&client, "knx_ha_automation_plan", unknown).await?;
    assert!(reason(&r).contains("not in groups.toml"), "{r}");

    let mut mismatch = guest_rule();
    mismatch["then"][0]["send"]["ga"] = json!("4/3/11");
    let r = call(&client, "knx_ha_automation_plan", mismatch).await?;
    assert!(reason(&r).contains("contradicts"), "{r}");

    let mut foreign = guest_rule();
    foreign["id"] = json!("kitchen_lights");
    let r = call(&client, "knx_ha_automation_plan", foreign).await?;
    assert!(reason(&r).contains("not a bussard id"), "{r}");
    let r = call(
        &client,
        "knx_ha_automation_remove",
        json!({"id": "kitchen_lights"}),
    )
    .await?;
    assert!(reason(&r).contains("not a bussard id"), "{r}");

    let mut unmarked = guest_rule();
    unmarked["id"] = json!("bussard_hand_made");
    let r = call(&client, "knx_ha_automation_plan", unmarked).await?;
    assert!(reason(&r).contains("did not write"), "{r}");
    let r = call(
        &client,
        "knx_ha_automation_remove",
        json!({"id": "bussard_hand_made"}),
    )
    .await?;
    assert!(reason(&r).contains("did not write"), "{r}");

    // Stale: groups.toml retypes the send address after the plan.
    let plan = call(&client, "knx_ha_automation_plan", guest_rule()).await?;
    let digest = digest(&plan)?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"4/3/2\", name = \"Zu Hause\", dpt = \"1.001\" },\n  \
         { address = \"4/3/10\", name = \"Gastmodus\", dpt = \"5.001\" },\n]\n",
    )?;
    let r = call(
        &client,
        "knx_ha_automation_apply",
        json!({"plan_digest": digest}),
    )
    .await?;
    assert_eq!(r["refused"], true, "{r}");
    assert!(mock.automation("bussard_guest_mode_end").is_none());
    assert_eq!(mock.automation_reloads(), 0);
    // The hand-made automations are untouched.
    assert!(mock.automation("kitchen_lights").is_some());
    assert!(mock.automation("bussard_hand_made").is_some());
    assert!(
        mock.requests().iter().all(|r| r.method == "GET"),
        "{:?}",
        mock.requests()
    );
    client.cancel().await?;
    task.abort();
    Ok(())
}
