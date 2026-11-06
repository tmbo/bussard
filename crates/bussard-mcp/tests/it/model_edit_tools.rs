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
        "version = 3\n\n[[device]]\naddress = \"1.1.4\"\n\
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
        home_assistant: None,
        jobs: Default::default(),
        viz: Default::default(),
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
        res["changes"][0], "New group address Porch light, type 1.001.",
        "{res}"
    );
    assert_eq!(res["validation"]["ok"], true, "{res}");

    // Link it to the blind actuator's channel B.
    let res = call(
        &client,
        "knx_add_link",
        json!({"address": "1.1.4", "com_object": 12, "ga": "0/0/4", "role": "listen"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(
        res["changes"][0], "Living room blind actuator, channel B, now listens to Porch light.",
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
        json!({"address": "1.1.4", "com_object": 12, "ga": "3/2/0", "role": "listen"}),
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
        "the caller must be told how the change reaches a device: {res}"
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
        json!({"address": "1.1.4", "com_object": 12, "ga": "0/0/9", "role": "send"}),
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
    // The declared address is part of the change the human is shown, by
    // its name; the structured detail keeps the address (issue #306).
    assert!(
        res["changes"].as_array().is_some_and(|c| c
            .iter()
            .any(|s| s.as_str().is_some_and(|s| s.contains("B object 12")))),
        "{res}"
    );
    assert!(
        res["detail"]
            .as_array()
            .is_some_and(|d| d.iter().any(|c| c["group"] == "0/0/9")),
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
    // The flags are the integrator's (issue #306): `technical` returns them.
    assert!(res["scope"]["objects"][0].get("flags").is_none(), "{res}");
    let technical = call(
        &client,
        "knx_show_device",
        json!({"address": "1.1.4", "channel": "CH-2", "toml": true, "technical": true}),
    )
    .await;
    assert_eq!(
        technical["scope"]["objects"][0]["flags"], "CRT",
        "{technical}"
    );
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
/// `bussard-model/tests/it/device_view.rs`).
const KEYED_LOCK: &str = r#"version = 3

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

const KEYED_PRODUCT: &str = r#"{
  "parameters": {
    "MD-3_P-14": {
      "kind": {"Enum": {"values": [1, 2]}},
      "default": "1",
      "text": "Betriebsart",
      "labels": [[1, "Rollladen"], [2, "Jalousie"]],
      "enum_values": [
        {"value": 1, "text": "Rollladen", "default_text": "Rollladen"},
        {"value": 2, "text": "Jalousie", "default_text": "Jalousie"}
      ]
    },
    "MD-3_P-15": {
      "kind": {"Int": {"min": 1, "max": 600, "signed": false}},
      "default": "60",
      "text": "Fahrzeit"
    },
    "P-19": {
      "kind": {"Enum": {"values": [0, 1]}},
      "default": "0",
      "text": "Regenalarm",
      "labels": [[0, "Nein"], [1, "Ja"]],
      "enum_values": [
        {"value": 0, "text": "Nein", "default_text": "Nein"},
        {"value": 1, "text": "Ja", "default_text": "Ja"}
      ]
    }
  },
  "program_id": "M-0004_A-20DE-22-C7D8-O000A"
}
"#;

/// `knx_set_parameter` takes the key the device file uses and an enum label,
/// and stores the code.
#[tokio::test]
async fn test_set_parameter_takes_the_file_key_and_a_label() -> TestResult {
    let dir = model_dir("keyed")?;
    bussard_model::param_model::write_product_model(&dir, serde_json::from_str(KEYED_PRODUCT)?)?;
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

/// Calls one tool that is expected to fail with a tool result that has
/// `isError` set, and returns the result's text.
async fn call_err(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    params: CallToolRequestParams,
) -> Result<String, Box<dyn std::error::Error>> {
    let res = client.call_tool(params).await?;
    if res.is_error != Some(true) {
        return Err(format!("the call succeeded: {res:?}").into());
    }
    let text = res
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone())
        .ok_or("the error result carries no text")?;
    Ok(text)
}

/// Issue #269: a client that drops the arguments gets told so, with the
/// fields to send, instead of serde's "missing field `address`"; a mistyped
/// field keeps serde's text and names the field; a valid call still works.
#[tokio::test]
async fn test_add_link_argument_errors_explain_what_arrived() -> TestResult {
    let dir = model_dir("args")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    let msg = call_err(&client, CallToolRequestParams::new("knx_add_link")).await?;
    assert_eq!(
        msg,
        "the call reached bussard without any arguments (the client sent none); \
         expected fields: address, com_object, ga, role; \
         retry with the arguments as a JSON object"
    );

    let empty = json!({});
    let empty = empty.as_object().ok_or("not an object")?.clone();
    let msg = call_err(
        &client,
        CallToolRequestParams::new("knx_add_link").with_arguments(empty),
    )
    .await?;
    assert!(
        msg.starts_with("the call reached bussard with an empty object"),
        "{msg}"
    );

    let wrong = json!({"address": "1.1.4", "com_object": "seven", "ga": "3/0/1", "role": "listen"});
    let wrong = wrong.as_object().ok_or("not an object")?.clone();
    let msg = call_err(
        &client,
        CallToolRequestParams::new("knx_add_link").with_arguments(wrong),
    )
    .await?;
    assert!(
        msg.contains("com_object: invalid type: string \"seven\", expected u16"),
        "{msg}"
    );
    assert!(
        msg.contains("expected fields: address, com_object, ga, role"),
        "{msg}"
    );

    let res = call(
        &client,
        "knx_add_link",
        json!({"address": "1.1.4", "com_object": 12, "ga": "3/0/1", "role": "listen"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");

    // A tool whose fields are all optional still runs without arguments.
    let res = call(&client, "knx_describe_change", Value::Null).await;
    assert!(res.is_object(), "{res}");

    client.cancel().await?;
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The link tools advertise `address` as the required field name. The Claude
/// remote-devices bridge strips a `device` key from forwarded calls, so that
/// name appears nowhere in the schema.
#[tokio::test]
async fn test_link_tools_schema_advertises_address() -> TestResult {
    let dir = model_dir("schema")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    let tools = client.list_all_tools().await?;
    for name in ["knx_add_link", "knx_remove_link"] {
        let tool = tools
            .iter()
            .find(|t| t.name == name)
            .ok_or_else(|| format!("{name} is not registered"))?;
        let schema = Value::Object(tool.input_schema.as_ref().clone());
        let properties = schema["properties"]
            .as_object()
            .ok_or_else(|| format!("{name} schema has no properties: {schema}"))?;
        assert!(properties.contains_key("address"), "{name}: {schema}");
        assert!(!properties.contains_key("device"), "{name}: {schema}");
        let required: Vec<&str> = schema["required"]
            .as_array()
            .ok_or_else(|| format!("{name} schema has no required list: {schema}"))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(required.contains(&"address"), "{name}: {schema}");
        assert!(!required.contains(&"device"), "{name}: {schema}");
    }

    client.cancel().await?;
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The link tools take `address` only: a call that names the device
/// `device` is refused with the fields the tool expects (issue #285).
#[tokio::test]
async fn test_add_link_refuses_device_field() -> TestResult {
    let dir = model_dir("device-field")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    for name in ["knx_add_link", "knx_remove_link"] {
        let args = json!({"device": "1.1.4", "com_object": 12, "ga": "3/0/1", "role": "listen"});
        let args = args.as_object().ok_or("not an object")?.clone();
        let msg = call_err(
            &client,
            CallToolRequestParams::new(name).with_arguments(args),
        )
        .await?;
        assert!(msg.contains("missing field `address`"), "{name}: {msg}");
        assert!(
            msg.contains("expected fields: address, com_object, ga, role"),
            "{name}: {msg}"
        );
    }

    client.cancel().await?;
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The link tools' descriptions say where the device's address goes: an
/// assistant still tries `device` first (issue #285).
#[tokio::test]
async fn test_link_tools_describe_the_address_field() -> TestResult {
    let dir = model_dir("link-descriptions")?;
    let (client, task) = connect(server_over(&dir)?).await?;

    let tools = client.list_all_tools().await?;
    for name in ["knx_add_link", "knx_remove_link"] {
        let tool = tools
            .iter()
            .find(|t| t.name == name)
            .ok_or_else(|| format!("{name} is not registered"))?;
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("The device's address goes in `address`"),
            "{name}: {description}"
        );
        assert!(!description.contains("`device`"), "{name}: {description}");
    }

    client.cancel().await?;
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The keyed fixture with the device file writing `betriebsart` by its label
/// (as `bussard import` does) and groups.toml defining the linked addresses.
fn labelled_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = model_dir(tag)?;
    bussard_model::param_model::write_product_model(&dir, serde_json::from_str(KEYED_PRODUCT)?)?;
    std::fs::write(dir.join("bussard.lock"), KEYED_LOCK)?;
    std::fs::remove_file(dir.join("devices").join("1.1.4.toml"))?;
    std::fs::write(
        dir.join("devices").join("1.1.47.toml"),
        KEYED_DEVICE.replace("betriebsart = \"2\"", "betriebsart = \"Jalousie\""),
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"0/1/3\", name = \"Langzeit\", dpt = \"1.008\" },\n  \
         { address = \"4/1/2\", name = \"In Betrieb\", dpt = \"1.002\" },\n  \
         { address = \"4/1/9\", name = \"Untyped\" },\n]\n",
    )?;
    Ok(dir)
}

/// Issue #279: every edit tool reports exactly its own change (no label/code
/// noise from the labelled device file), enum values as labels, and only the
/// warnings it introduced; the full list stays in knx_validate.
#[tokio::test]
async fn test_edit_tools_report_only_their_change_and_new_warnings() -> TestResult {
    // (tool, arguments, the change sentences, the new warning codes)
    let cases: Vec<(&'static str, Value, Vec<&str>, Vec<&str>)> = vec![
        (
            "knx_set_parameter",
            json!({"address": "1.1.47", "parameter": "betriebsart", "value": "Rollladen"}),
            vec!["Betriebsart on Jalousieaktor Kind 2: Jalousie (2) to Rollladen (1)."],
            vec![],
        ),
        (
            "knx_set_parameter",
            json!({"address": "1.1.47", "parameter": "regenalarm", "value": "1"}),
            vec!["Regenalarm on Jalousieaktor Kind 2 is set to Ja (1)."],
            vec![],
        ),
        (
            "knx_set_group",
            json!({"ga": "0/1/3", "dpt": "1.009"}),
            vec!["Langzeit changes type from 1.008 to 1.009."],
            // Two subtypes of one main type agree (W005 follows ETS, #348).
            vec![],
        ),
        (
            "knx_set_group",
            json!({"ga": "0/1/3", "dpt": "1"}),
            vec!["Langzeit changes type from 1.008 to 1."],
            vec![],
        ),
        (
            "knx_add_link",
            json!({"address": "1.1.47", "com_object": 162, "ga": "4/1/9", "role": "listen"}),
            vec![],
            vec![],
        ),
    ];
    for (tool, args, want_changes, want_new) in cases {
        let dir = labelled_dir("noise")?;
        let (client, task) = connect(server_over(&dir)?).await?;
        // A fresh model: nothing pending against its own snapshot.
        let fresh = call(&client, "knx_describe_change", json!({})).await;
        assert!(
            fresh["sentences"].as_array().is_none_or(Vec::is_empty),
            "{fresh}"
        );

        let res = call(&client, tool, args.clone()).await;
        assert_eq!(res["ok"], true, "{tool} {args}: {res}");
        let changes: Vec<&str> = res["changes"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !want_changes.is_empty() {
            assert_eq!(changes, want_changes, "{tool} {args}: {res}");
        } else {
            assert_eq!(changes.len(), 1, "{tool} {args}: {res}");
        }
        let validation = &res["validation"];
        assert!(validation.get("warnings").is_none(), "{validation}");
        assert!(
            validation["warning_count"].as_u64().is_some(),
            "{validation}"
        );
        let new: Vec<&str> = validation["new_warnings"]
            .as_array()
            .map(|a| a.iter().filter_map(|w| w["code"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(new, want_new, "{tool} {args}: {validation}");

        // The undo reverts exactly that edit, with no warning of its own
        // beyond what the edit removed.
        let undo = call(&client, "knx_undo", json!({})).await;
        assert_eq!(undo["ok"], true, "{undo}");
        assert_eq!(
            undo["changes"].as_array().map(Vec::len),
            Some(changes.len()),
            "{undo}"
        );
        assert!(undo["validation"].get("warnings").is_none(), "{undo}");

        // knx_validate keeps the full list (the untyped 4/1/9 is W011).
        let full = call(&client, "knx_validate", json!({})).await;
        assert!(full.to_string().contains("W011"), "{full}");

        client.cancel().await?;
        task.abort();
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

/// `knx_remove_group` refuses while a link uses the address (naming the link
/// and knx_remove_link), refuses a protected one, succeeds after the link is
/// gone, and `knx_undo` puts it back (issue #305).
#[tokio::test]
async fn test_remove_group_refuses_while_linked_and_succeeds_after_remove_link() -> TestResult {
    let dir = model_dir("remove-group")?;
    let (client, task) = connect(server_over(&dir)?).await?;
    let link = json!({"address": "1.1.4", "com_object": 12, "ga": "3/0/1", "role": "listen"});
    let ga: bussard_model::GroupAddress = "3/0/1".parse()?;

    let res = call(&client, "knx_add_link", link.clone()).await;
    assert_eq!(res["ok"], true, "{res}");

    let res = call(&client, "knx_remove_group", json!({"ga": "3/0/1"})).await;
    assert_eq!(res["refused"], true, "{res}");
    let reason = res["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("1.1.4 object 12 listens"), "{reason}");
    assert!(reason.contains("knx_remove_link"), "{reason}");
    assert!(Model::load(&dir)?.groups.groups.contains_key(&ga));

    let res = call(&client, "knx_remove_group", json!({"ga": "3/2/0"})).await;
    assert_eq!(res["refused"], true, "{res}");
    assert!(
        res["reason"]
            .as_str()
            .is_some_and(|r| r.contains("protected")),
        "{res}"
    );

    let res = call(&client, "knx_remove_link", link).await;
    assert_eq!(res["ok"], true, "{res}");
    let res = call(&client, "knx_remove_group", json!({"ga": "3/0/1"})).await;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(
        res["changes"],
        json!(["Group address Central down removed."]),
        "{res}"
    );
    assert_eq!(res["detail"][0]["kind"], "group_removed", "{res}");
    assert!(res["snapshot"].is_string(), "{res}");
    assert!(!Model::load(&dir)?.groups.groups.contains_key(&ga));

    let res = call(&client, "knx_undo", json!({})).await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(Model::load(&dir)?.groups.groups.contains_key(&ga));

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// `knx_discard_edits` with `group` drops a group address created in the
/// session, but refuses while a link uses it; a device discard leaves such a
/// group in place and says so (issue #305).
#[tokio::test]
async fn test_discard_edits_group_created_in_session() -> TestResult {
    let dir = model_dir("discard-group")?;
    let (client, task) = connect(server_over(&dir)?).await?;
    let ga: bussard_model::GroupAddress = "1/0/22".parse()?;

    let res = call(
        &client,
        "knx_set_group",
        json!({"ga": "1/0/22", "name": "Kitchen door light", "dpt": "1.001"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    let res = call(
        &client,
        "knx_add_link",
        json!({"address": "1.1.4", "com_object": 12, "ga": "1/0/22", "role": "listen"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");

    // Linked: the group cannot be discarded.
    let res = call(&client, "knx_discard_edits", json!({"group": "1/0/22"})).await;
    assert_eq!(res["refused"], true, "{res}");
    assert!(
        res["reason"]
            .as_str()
            .is_some_and(|r| r.contains("1.1.4 object 12 listens")),
        "{res}"
    );

    // Discarding the device drops the link and keeps the group, saying so.
    let res = call(&client, "knx_discard_edits", json!({"address": "1.1.4"})).await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(
        res["note"].as_str().is_some_and(|n| n.contains("1/0/22")),
        "{res}"
    );
    let model = Model::load(&dir)?;
    assert!(model.groups.groups.contains_key(&ga));
    let ia: bussard_model::IndividualAddress = "1.1.4".parse()?;
    assert!(
        model
            .links
            .links
            .get(&ia)
            .is_none_or(|links| links.iter().all(|l| !l.listen.contains(&ga))),
        "the link is gone"
    );

    // Now the group goes too; neither call needs an argument it cannot use.
    let res = call(&client, "knx_discard_edits", json!({"group": "1/0/22"})).await;
    assert_eq!(res["ok"], true, "{res}");
    assert!(!Model::load(&dir)?.groups.groups.contains_key(&ga));
    let res = call(&client, "knx_discard_edits", json!({})).await;
    assert_eq!(res["refused"], true, "{res}");

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// A model with the secured GA 1/0/4 and the plain GA 1/0/5, the Secure
/// actuator 1.1.5 listening to both, and the weather station 1.1.202 without
/// KNX Data Secure (issue #330).
fn secure_model_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-mcp-secure-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/4\", name = \"Licht Kueche aussen\", dpt = \"1.001\", secure = true },\n  \
         { address = \"1/0/5\", name = \"Licht Kueche Logik\", dpt = \"1.001\" },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Switch actuator\"\n\n[links]\n\
         schalten.listen = [\"1/0/4\"]\nlogik.listen = [\"1/0/5\"]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.202.toml"),
        "address = \"1.1.202\"\nname = \"Weather station\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        "version = 3\n\n[[device]]\naddress = \"1.1.5\"\nsecure_capable = true\n\
         objects = [\n  { number = 3, key = \"schalten\", dpt = \"1.001\", flags = \"CWU\", secure = true },\n  \
         { number = 4, key = \"logik\", dpt = \"1.001\", flags = \"CWU\" },\n]\n\n\
         [[device]]\naddress = \"1.1.202\"\n\
         objects = [\n  { number = 18, key = \"c18\", dpt = \"1.001\", flags = \"CRT\" },\n]\n",
    )?;
    Ok(dir)
}

/// Linking a device without Data Secure as sender on a GA a Secure receiver
/// takes secured is refused with E035 and the ways out; the same link onto
/// a plain GA is accepted (issue #330).
#[tokio::test]
async fn test_add_link_refuses_plain_sender_on_secured_ga() -> TestResult {
    let dir = secure_model_dir("plain-sender")?;
    let before = Model::load(&dir)?;
    assert!(
        bussard_model::secure_link_conflicts(&before).is_empty(),
        "the fixture starts clean"
    );
    let (client, task) = connect(server_over(&dir)?).await?;

    let res = call(
        &client,
        "knx_add_link",
        json!({"address": "1.1.202", "com_object": 18, "ga": "1/0/4", "role": "send"}),
    )
    .await;
    assert_ne!(res["ok"], true, "{res}");
    let text = res.to_string();
    for needle in [
        "E035",
        "1.1.202 object 18",
        "1/0/4",
        "1.1.5 object 3",
        "logic input",
    ] {
        assert!(text.contains(needle), "{needle}: {res}");
    }
    // Nothing was written.
    let ia: bussard_model::IndividualAddress = "1.1.202".parse()?;
    assert!(
        Model::load(&dir)?
            .links
            .links
            .get(&ia)
            .is_none_or(|l| l.is_empty())
    );

    let res = call(
        &client,
        "knx_add_link",
        json!({"address": "1.1.202", "com_object": 18, "ga": "1/0/5", "role": "send"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    let saved = Model::load(&dir)?;
    let ga: bussard_model::GroupAddress = "1/0/5".parse()?;
    assert!(
        saved.links.links[&ia]
            .iter()
            .any(|l| l.object == 18 && l.send == Some(ga))
    );

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// Packs the synthetic catalogue product `name`
/// (`tests-support/synthetic-products/<name>/xml`) into a `.knxprod` at `out`.
fn pack_synthetic_product(name: &str, out: &Path) -> TestResult {
    use std::io::Write;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products")
        .join(name)
        .join("xml");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(out)?);
    let opts = zip::write::SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(&root)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                zip.start_file(rel, opts)?;
                zip.write_all(&std::fs::read(&path)?)?;
            }
        }
    }
    zip.finish()?;
    Ok(())
}

/// A model directory with device 1.1.1 on `syn-param-calculation` (the
/// `calc-input` capture's shape) at its defaults, the product model imported
/// from the catalogue XML, and the application the plan builds its image
/// from.
fn param_calculation_dir()
-> Result<(PathBuf, bussard_prod::ApplicationProgram), Box<dyn std::error::Error>> {
    let dir = model_dir("calc")?;
    let knxprod = dir.join("syn-param-calculation.knxprod");
    pack_synthetic_product("syn-param-calculation", &knxprod)?;
    let data = bussard_prod::read_knxprod(&knxprod)?;
    std::fs::remove_file(&knxprod)?;
    let app = data.applications.first().ok_or("no application")?.clone();
    bussard_prod::product_model::write_product_models(&data, &dir)?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 3\n\n[[device]]\naddress = \"1.1.1\"\nproduct = \"NEST-CALC\"\n\
             application = \"{}\"\nmask = \"07B0\"\nparameters = [\n  \
             {{ key = \"operating-mode\", ref = \"P-1_R-1\", param = \"P-1\" }},\n  \
             {{ key = \"delay-s\", ref = \"P-2_R-2\", param = \"P-2\" }},\n  \
             {{ key = \"twice-the-delay-plus-one\", ref = \"P-3_R-3\", param = \"P-3\" }},\n]\n",
            app.id
        ),
    )?;
    std::fs::remove_file(dir.join("devices").join("1.1.4.toml"))?;
    std::fs::write(
        dir.join("devices").join("1.1.1.toml"),
        "address = \"1.1.1\"\nname = \"syn-param-calculation\"\nproduct = \"NEST-CALC\"\n",
    )?;
    Ok((dir, app))
}

/// What the plan's parameter image holds for parameter `param` (app-relative
/// id) with `overrides`, decoded the way a read-back decodes it.
fn planned_value(
    app: &bussard_prod::ApplicationProgram,
    overrides: &std::collections::BTreeMap<String, String>,
    param: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let images = bussard_prod::image::compute_parameter_image(app, overrides, &Default::default())?;
    let param = app
        .parameters
        .get(&format!("{}_{param}", app.id))
        .ok_or("no parameter")?;
    let memory = param.memory.as_ref().ok_or("no memory")?;
    let segment = memory.code_segment.as_deref().ok_or("no segment")?;
    let image = images.get(segment).ok_or("no image of the segment")?;
    let value = bussard_prod::image::decode_parameter_value(
        app,
        param,
        image,
        memory.offset.ok_or("no offset")? as usize,
        memory.bit_offset.unwrap_or(0),
    );
    Ok(value.ok_or("undecodable")?)
}

/// Issue #712: the MCP model tools show a calculation output with the value
/// the plan writes. Setting the input `delay` to 500 (the `calc-input`
/// capture) names the outputs that change, `knx_get_device` lists both
/// outputs computed by `PC-1` with the plan's values, and
/// `knx_set_parameter` refuses the output itself, also with `force`, naming
/// the input to set instead.
#[tokio::test]
async fn test_set_parameter_synthetic_param_calculation_views_agree_with_the_plan() -> TestResult {
    let (dir, app) = param_calculation_dir()?;
    let (client, task) = connect(server_over(&dir)?).await?;

    // At the defaults no calculation runs, so nothing is computed.
    let res = call(&client, "knx_get_device", json!({"address": "1.1.1"})).await;
    assert!(res.get("computed_parameters").is_none(), "{res}");

    let res = call(
        &client,
        "knx_set_parameter",
        json!({"address": "1.1.1", "parameter": "delay-s", "value": "500"}),
    )
    .await;
    assert_eq!(res["ok"], true, "{res}");
    let text = res.to_string();
    assert!(
        text.contains("Computed by calculation PC-1") && text.contains("1001"),
        "the change names the computed output and its new value: {res}"
    );

    let overrides: std::collections::BTreeMap<String, String> =
        [("P-2_R-2".to_string(), "500".to_string())].into();
    let plan_double = planned_value(&app, &overrides, "P-3")?;
    let plan_patch = planned_value(&app, &overrides, "P-4")?;
    assert_eq!((plan_double.as_str(), plan_patch.as_str()), ("1001", "507"));
    let res = call(&client, "knx_get_device", json!({"address": "1.1.1"})).await;
    let computed = res["computed_parameters"]
        .as_array()
        .ok_or_else(|| format!("no computed_parameters: {res}"))?;
    let value_of = |suffix: &str| {
        computed
            .iter()
            .find(|c| c["key"].as_str().is_some_and(|k| k.ends_with(suffix)))
            .map(|c| (c["value"].clone(), c["computed_by"].clone()))
    };
    assert_eq!(
        value_of("twice-the-delay-plus-one@P-3_R-3"),
        Some((json!(plan_double), json!("PC-1"))),
        "{res}"
    );
    assert_eq!(
        value_of("P-4_R-4"),
        Some((json!(plan_patch), json!("PC-1"))),
        "{res}"
    );

    for force in [false, true] {
        let res = call(
            &client,
            "knx_set_parameter",
            json!({"address": "1.1.1", "parameter": "twice-the-delay-plus-one",
                   "value": "7", "force": force}),
        )
        .await;
        assert_eq!(res["ok"], false, "{res}");
        let reason = res["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("calculation PC-1") && reason.contains("delay-s@P-2_R-2"),
            "the refusal names the calculation and its input: {res}"
        );
    }
    let saved = Model::load(&dir)?;
    let device = &saved.devices[&"1.1.1".parse()?].device;
    assert!(
        !device.parameters.keys().any(|k| k.contains("P-3_R-3")),
        "the refused output is not stored: {:?}",
        device.parameters
    );

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

/// The ids a homeowner should not have to read (issue #306) in `text`: group
/// addresses (`1/2/3`), individual addresses (`1.1.4`), ETS references
/// (`MD-…`) and parameter keys (`key@ref`).
fn ids_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in text.split(|c: char| c.is_whitespace() || "(),;:\"`{}[]".contains(c)) {
        let word = word.trim_end_matches('.');
        let three = |sep: char| {
            let p: Vec<&str> = word.split(sep).collect();
            p.len() == 3
                && p.iter()
                    .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        };
        if three('/') || three('.') || word.contains("MD-") || word.contains('@') {
            out.push(word.to_string());
        }
    }
    out
}

/// Every edit, the pending change, a discard and an undo carry a `summary` in
/// names, with no group address, individual address, ETS reference or
/// parameter key; `validation.for_the_human` says in one line whether the
/// edit left anything to worry about (issue #306). The sentences and the
/// structured detail still carry every address.
#[tokio::test]
async fn test_edit_results_summarize_without_ids() -> TestResult {
    let dir = labelled_dir("summary")?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Living room blind actuator\"\n\n\
         [channel.CH-2]\nname = \"B\"\n",
    )?;
    let lock = std::fs::read_to_string(dir.join("bussard.lock"))?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "{lock}\n[[device]]\naddress = \"1.1.4\"\nchannels = [\n  {{ id = \"CH-2\" }},\n]\n\
             objects = [\n  {{ number = 12, channel = \"CH-2\", flags = \"CRT\" }},\n]\n"
        ),
    )?;
    let (client, task) = connect(server_over(&dir)?).await?;
    let edits: [(&'static str, Value); 6] = [
        (
            "knx_set_group",
            json!({"ga": "0/0/4", "name": "Porch light", "dpt": "1.001"}),
        ),
        (
            "knx_add_link",
            json!({"address": "1.1.4", "com_object": 12, "ga": "0/0/4", "role": "listen"}),
        ),
        (
            "knx_set_device",
            json!({"address": "1.1.4", "room": "Wohnzimmer", "floor": "EG"}),
        ),
        (
            "knx_set_parameter",
            json!({"address": "1.1.47", "parameter": "betriebsart", "value": "Rollladen"}),
        ),
        (
            "knx_add_link",
            json!({"address": "1.1.47", "com_object": 144, "ga": "0/0/4", "role": "listen"}),
        ),
        ("knx_describe_change", json!({})),
    ];
    for (tool, args) in edits {
        let res = call(&client, tool, args.clone()).await;
        assert_eq!(res["ok"], true, "{tool} {args}: {res}");
        let summary = res["summary"].as_str().unwrap_or_default();
        assert!(!summary.is_empty(), "{tool}: {res}");
        assert_eq!(ids_in(summary), Vec::<String>::new(), "{tool}: {summary}");
        if tool != "knx_describe_change" {
            assert!(
                res["validation"]["for_the_human"].is_string(),
                "{tool}: {res}"
            );
            // The structured detail keeps the addresses.
            assert!(
                res["detail"].as_array().is_some_and(|d| d
                    .iter()
                    .all(|c| c["group"].is_string() || c["device"].is_string())),
                "{tool}: {res}"
            );
        }
        match tool {
            "knx_set_group" => assert!(summary.contains("Porch light"), "{summary}"),
            "knx_add_link" if args["address"] == "1.1.4" => {
                assert!(
                    summary.contains(
                        "Living room blind actuator, channel B, now listens to Porch light"
                    ),
                    "{summary}"
                );
                assert!(summary.contains("needs to be written"), "{summary}");
            }
            "knx_set_parameter" => {
                assert!(summary.contains("Betriebsart"), "{summary}");
                assert!(summary.contains("Jalousieaktor Kind 2"), "{summary}");
            }
            "knx_add_link" => {
                // The vendor's object text and channel text name it.
                assert!(
                    summary
                        .contains("Langzeitbetrieb on Jalousieaktor Kind 2, channel Fenster Süd"),
                    "{summary}"
                );
            }
            _ => {}
        }
    }

    // The room set above names the device in the next push.
    let res = call(
        &client,
        "knx_remove_link",
        json!({"address": "1.1.4", "com_object": 12, "ga": "0/0/4", "role": "listen"}),
    )
    .await;
    let summary = res["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("Living room blind actuator in Wohnzimmer, EG needs to be written"),
        "{summary}"
    );

    let res = call(&client, "knx_discard_edits", json!({"address": "1.1.47"})).await;
    assert_eq!(res["ok"], true, "{res}");
    let summary = res["summary"].as_str().unwrap_or_default();
    assert_eq!(ids_in(summary), Vec::<String>::new(), "{summary}");

    let res = call(&client, "knx_undo", json!({})).await;
    assert_eq!(res["ok"], true, "{res}");
    let summary = res["summary"].as_str().unwrap_or_default();
    assert!(!summary.is_empty(), "{res}");
    assert_eq!(ids_in(summary), Vec::<String>::new(), "{summary}");

    client.cancel().await?;
    task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
