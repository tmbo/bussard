//! Integration test for the MCP model-edit and history tools (issues #110, #112).
//!
//! Drives the server through the rmcp client over an in-process duplex
//! transport against a real temporary model directory, so the whole ladder runs:
//! snapshot, edit, save, validate, sentences. No bus is involved — these tools
//! touch files only.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bussard_mcp::SharedState;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_transport::TransportKind;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh temporary model directory holding one device and two GAs, one of
/// which is protected.
fn model_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-mcp-edit-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"3/0/1\", name = \"Central down\", dpt = \"1.008\" },\n  \
         { address = \"3/2/0\", name = \"Wind alarm\",   dpt = \"1.005\", protected = true },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\n\
         name = \"Living room blind actuator\"\n\n\
         [channel.CH-2]\n\
         name = \"B\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        "version = 1\n\n[[device]]\naddress = \"1.1.4\"\n\
         channels = [\n  { id = \"CH-2\" },\n]\n\
         objects = [\n  { number = 12, channel = \"CH-2\", flags = \"CRT\" },\n]\n",
    )?;
    Ok(dir)
}

/// Builds a server over a real model directory with the edit tools registered.
fn server_over(dir: &Path) -> Result<BussardMcp, Box<dyn std::error::Error>> {
    let model = Model::load(dir)?;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: true,
        allow_writes: false,
        no_model_edits: false,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
        programming: None,
        keyring: None,
    });
    Ok(BussardMcp::new(state))
}

async fn connect(
    server: BussardMcp,
) -> Result<
    (
        rmcp::service::RunningService<rmcp::RoleClient, ()>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    let (server_io, client_io) = tokio::io::duplex(8 * 1024);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, task))
}

/// Calls one tool and returns its structured content.
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    args: Value,
) -> Value {
    let params = match args.as_object() {
        Some(map) => CallToolRequestParams::new(name).with_arguments(map.clone()),
        None => CallToolRequestParams::new(name),
    };
    client
        .call_tool(params)
        .await
        .unwrap_or_else(|e| panic!("{name} call failed: {e}"))
        .structured_content
        .unwrap_or_else(|| panic!("{name} returned no structured content"))
}

#[tokio::test]
async fn test_model_edit_tools_snapshot_edit_and_describe() -> TestResult {
    let dir = model_dir("edit")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    // The edit tools are registered in passive mode: they never touch the bus.
    let names: Vec<String> = client
        .list_all_tools()
        .await?
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(names.contains(&"knx_set_group".to_string()));
    assert!(!names.contains(&"knx_read_group".to_string()));

    // Create a group address.
    let res = call(
        &client,
        "knx_set_group",
        json!({"ga": "0/0/4", "name": "Porch light", "dpt": "1.001"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(res["snapshot"].is_string(), "{res}");
    assert_eq!(
        res["changes"][0], "New group address Porch light (0/0/4), type 1.001.",
        "{res}"
    );
    assert_eq!(res["validation"]["ok"], true, "{res}");

    // Link it to the blind actuator's channel B.
    let res = call(
        &client,
        "knx_add_link",
        json!({"device": "1.1.4", "com_object": 12, "ga": "0/0/4", "role": "listen"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(
        res["changes"][0],
        "Living room blind actuator, channel B, now listens to Porch light (0/0/4).",
        "{res}"
    );

    // The files on disk carry it.
    let saved = Model::load(&dir)?;
    let ga: bussard_model::GroupAddress = "0/0/4".parse()?;
    assert_eq!(saved.groups.groups[&ga].name, "Porch light");

    // `knx_describe_change` with no arguments describes the pending change: the
    // working model against the snapshot taken before the link edit.
    let res = call(&client, "knx_describe_change", json!({})).await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["count"], 1, "{res}");
    assert!(
        res["sentences"][0]
            .as_str()
            .is_some_and(|s| s.contains("now listens to Porch light")),
        "{res}"
    );

    // `knx_history` lists both snapshots with a summary each.
    let res = call(&client, "knx_history", json!({})).await;
    assert_eq!(res["count"], 2, "{res}");
    assert_eq!(res["snapshots"][0]["command"], "mcp knx_set_group", "{res}");
    assert_eq!(res["snapshots"][1]["command"], "mcp knx_add_link", "{res}");

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[tokio::test]
async fn test_protected_group_addresses_are_refused() -> TestResult {
    let dir = model_dir("protected")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    let res = call(
        &client,
        "knx_add_link",
        json!({"device": "1.1.4", "com_object": 12, "ga": "3/2/0", "role": "listen"}),
    )
    .await;
    assert_eq!(res["ok"], false, "{res}");
    assert_eq!(res["refused"], true, "{res}");
    assert!(
        res["reason"]
            .as_str()
            .is_some_and(|r| r.contains("protected")),
        "{res}"
    );

    let res = call(
        &client,
        "knx_set_group",
        json!({"ga": "3/2/0", "name": "Wind alarm north"}),
    )
    .await;
    assert_eq!(res["ok"], false, "{res}");
    assert!(
        res["reason"]
            .as_str()
            .is_some_and(|r| r.contains("protected")),
        "{res}"
    );

    // Nothing was written, and no snapshot was taken for a refused edit.
    let model = Model::load(&dir)?;
    let ga: bussard_model::GroupAddress = "3/2/0".parse()?;
    assert_eq!(model.groups.groups[&ga].name, "Wind alarm");
    assert!(model.links.links.is_empty());
    assert!(
        !dir.join(".bussard").exists(),
        "a refusal must leave no snapshot"
    );

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[tokio::test]
async fn test_undo_puts_the_model_back_without_touching_devices() -> TestResult {
    let dir = model_dir("undo")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    call(
        &client,
        "knx_set_device",
        json!({"address": "1.1.4", "room": "Wohnzimmer", "floor": "EG"}),
    )
    .await;
    let res = call(
        &client,
        "knx_set_group",
        json!({"ga": "0/0/4", "name": "Porch light", "dpt": "1.001"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");

    let res = call(&client, "knx_undo", json!({})).await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(
        res["changes"][0]
            .as_str()
            .is_some_and(|s| s.contains("Porch light")),
        "{res}"
    );
    assert!(
        res["next_step"]
            .as_str()
            .is_some_and(|s| s.contains("plan")),
        "the caller must be told a human still has to push this: {res}"
    );

    // The group address is gone again; the earlier device edit survives.
    let model = Model::load(&dir)?;
    let ga: bussard_model::GroupAddress = "0/0/4".parse()?;
    assert!(!model.groups.groups.contains_key(&ga));
    let ia: bussard_model::IndividualAddress = "1.1.4".parse()?;
    let location = model.devices[&ia]
        .device
        .location
        .as_ref()
        .ok_or("the device lost its location")?;
    assert_eq!(location.room.as_deref(), Some("Wohnzimmer"));

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[tokio::test]
async fn test_set_parameter_refuses_without_a_product_model() -> TestResult {
    let dir = model_dir("parameter")?;
    std::fs::write(
        dir.join("devices").join("1.1.7.toml"),
        "address = \"1.1.7\"\n\
         name = \"Bathroom thermostat\"\n\n\
         [parameters]\n\"nachtabsenkung@P-1312_R-2140\" = \"18\"\n",
    )?;
    let (client, task) = connect(server_over(&dir)?).await?;

    let res = call(
        &client,
        "knx_set_parameter",
        json!({"address": "1.1.7", "parameter": "nachtabsenkung@P-1312_R-2140", "value": "17"}),
    )
    .await;
    assert_eq!(res["ok"], false, "{res}");
    assert!(
        res["reason"]
            .as_str()
            .is_some_and(|r| r.contains("application_ref")),
        "the refusal says why the value could not be checked: {res}"
    );

    // A parameter neither the file nor the lock knows is refused too, with
    // the tool that lists the keys.
    let res = call(
        &client,
        "knx_set_parameter",
        json!({"address": "1.1.4", "parameter": "x@P-1_R-1", "value": "1"}),
    )
    .await;
    assert_eq!(res["ok"], false, "{res}");
    assert!(
        res["reason"]
            .as_str()
            .is_some_and(|r| r.contains("has no parameter") && r.contains("knx_show_device")),
        "{res}"
    );

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A GA that `groups.toml` does not define is declared there by the edit that
/// first links it, named after the channel and the object, and reported.
#[tokio::test]
async fn test_add_link_declares_an_undefined_group_address() -> TestResult {
    let dir = model_dir("declare")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    let res = call(
        &client,
        "knx_add_link",
        json!({"device": "1.1.4", "com_object": 12, "ga": "0/0/9", "role": "send"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(
        res["groups_declared"][0],
        "added 0/0/9 \"B object 12\" to groups.toml, first used by 1.1.4 object 12",
        "{res}"
    );
    let saved = Model::load(&dir)?;
    let ga: bussard_model::GroupAddress = "0/0/9".parse()?;
    assert_eq!(saved.groups.groups[&ga].name, "B object 12");
    // The declared address is part of the change the human is shown.
    assert!(
        res["changes"].as_array().is_some_and(|c| c
            .iter()
            .any(|s| s.as_str().is_some_and(|s| s.contains("0/0/9")))),
        "{res}"
    );

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// `knx_show_device` lists a channel's objects in the device file's words and
/// hands back the paste-ready TOML; without product data it says so.
#[tokio::test]
async fn test_show_device_lists_a_channel_and_its_toml() -> TestResult {
    let dir = model_dir("show")?;
    let (client, task) = connect(server_over(&dir)?).await?;
    let res = call(
        &client,
        "knx_show_device",
        json!({"address": "1.1.4", "channel": "CH-2", "toml": true}),
    )
    .await;
    assert_eq!(res["channels"][0]["handle"], "CH-2", "{res}");
    assert_eq!(res["scope"]["objects"][0]["number"], 12, "{res}");
    assert_eq!(res["scope"]["objects"][0]["flags"], "CRT", "{res}");
    assert!(
        res["notes"][0]
            .as_str()
            .is_some_and(|n| n.contains("no product data")),
        "{res}"
    );
    let toml = res["toml"].as_str().unwrap_or_default();
    assert!(toml.contains("[channel.CH-2]"), "{toml}");
    assert!(toml.contains("# 12.send = \"\""), "{toml}");
    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// The fixture of a keyed device with its product model (see
/// `bussard-model/tests/device_view.rs`).
const KEYED_LOCK: &str = r#"version = 1

[[device]]
address = "1.1.47"
product = "230021SU"
application = "M-0004_A-20DE-22-C7D8-O000A"
mask = "07B0"
channels = [
  { key = "a-1", id = "MD-3_M-18_MI-1_CH-25", number = 1, text = "Jalousie 1", base = 2915 },
]
objects = [
  { number = 138, key = "in-betrieb", text = "Allgemein", function = "In Betrieb", dpt = "1.002", flags = "CRT" },
  { number = 144, key = "langzeitbetrieb", channel = "a-1", text = "Jalousie 1", function = "Langzeitbetrieb", dpt = "1.008", flags = "CWU" },
  { number = 162, key = "status-position", channel = "a-1", dpt = "5.001", flags = "CRT" },
]
parameters = [
  { key = "regenalarm", ref = "P-19_R-38", param = "P-19" },
  { key = "betriebsart", channel = "a-1", ref = "MD-3_M-18_MI-1_P-14_R-14", param = "MD-3_P-14" },
  { key = "fahrzeit", channel = "a-1", ref = "MD-3_M-18_MI-1_P-15_R-15", param = "MD-3_P-15" },
]
"#;

const KEYED_DEVICE: &str = r#"address = "1.1.47"
name = "Jalousieaktor Kind 2"
product = "230021SU"

[links]
in-betrieb.send = "4/1/2"

[channel.a-1]
name = "Fenster Süd"
betriebsart = "2"
langzeitbetrieb.listen = ["0/1/3"]
"#;

const KEYED_PRODUCT: &str = r#"identity:
  id: M-0004_A-20DE-22-C7D8-O000A
parameters:
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-14
    text: Betriebsart
    type: !enum
      values:
        - { value: 1, text: Rollladen }
        - { value: 2, text: Jalousie }
    default: "1"
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-15
    text: Fahrzeit
    type: !int
      min: 1
      max: 600
    default: "60"
  - id: M-0004_A-20DE-22-C7D8-O000A_P-19
    text: Regenalarm
    type: !enum
      values:
        - { value: 0, text: Nein }
        - { value: 1, text: Ja }
    default: "0"
"#;

/// `knx_set_parameter` takes the key the device file uses and an enum label,
/// and stores the code.
#[tokio::test]
async fn test_set_parameter_takes_the_file_key_and_a_label() -> TestResult {
    let dir = model_dir("keyed")?;
    let app = "M-0004_A-20DE-22-C7D8-O000A";
    std::fs::create_dir_all(dir.join("models"))?;
    std::fs::write(
        dir.join("models").join(format!("{app}.yaml")),
        KEYED_PRODUCT,
    )?;
    std::fs::write(dir.join("bussard.lock"), KEYED_LOCK)?;
    std::fs::remove_file(dir.join("devices").join("1.1.4.toml"))?;
    std::fs::write(dir.join("devices").join("1.1.47.toml"), KEYED_DEVICE)?;
    let (client, task) = connect(server_over(&dir)?).await?;
    let res = call(
        &client,
        "knx_set_parameter",
        json!({"address": "1.1.47", "parameter": "fahrzeit", "channel": "a-1", "value": "90"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    let res = call(
        &client,
        "knx_set_parameter",
        json!({"address": "1.1.47", "parameter": "betriebsart", "value": "Rollladen"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    let saved = Model::load(&dir)?;
    let device = &saved.devices[&"1.1.47".parse()?].device;
    assert_eq!(device.parameters["fahrzeit@MD-3_M-18_MI-1_P-15_R-15"], "90");
    assert_eq!(
        device.parameters["betriebsart@MD-3_M-18_MI-1_P-14_R-14"],
        "1"
    );
    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
