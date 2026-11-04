//! Mock-gateway test of `knx_discard_edits` (issue #305): discarding one
//! device's edits leaves another device's edits alone, the plan for the
//! discarded device is then empty, and `knx_undo` brings the edits back.
//!
//! The device is the writable System B mock of `bussard-testkit` on a
//! loopback [`MockGateway`] (`127.0.0.1:0`); no test here reaches a real
//! gateway.

use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

const CHANNEL: u8 = 0x56;

/// A table image: a count word, then 16-bit entries.
fn table(entries: &[u16]) -> Vec<u8> {
    let mut image = (entries.len() as u16).to_be_bytes().to_vec();
    for e in entries {
        image.extend_from_slice(&e.to_be_bytes());
    }
    image
}

/// Device 1.1.5 holding exactly what the model says: object 20 sends 1/2/0,
/// object 21 listens to 1/2/1.
fn device() -> anyhow::Result<MockDevice> {
    let ia: IndividualAddress = "1.1.5".parse()?;
    let gas: Vec<u16> = ["1/2/0", "1/2/1"]
        .iter()
        .map(|g| g.parse::<bussard_model::GroupAddress>().map(|g| g.raw()))
        .collect::<Result<_, _>>()?;
    Ok(MockDevice::system_b(ia)
        .with_table(1, &table(&gas))
        .with_table(2, &table(&[1, 20, 2, 21]))
        .with_go_count(60))
}

/// The model: 1.1.5 as the mock holds it, plus 1.1.202 (not on the bus).
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Aktor Küche\"\n\n[links]\n\
         20.send = \"1/2/0\"\n21.listen = [\"1/2/1\"]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.202.toml"),
        "address = \"1.1.202\"\nname = \"Wetterstation\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Light switch\" },\n  \
         { address = \"1/2/1\", name = \"Light status\" },\n  \
         { address = \"1/2/2\", name = \"Light dim\" },\n]\n",
    )?;
    Ok(())
}

/// Calls one tool and returns its structured result.
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let Value::Object(map) = args else {
        anyhow::bail!("tool arguments must be an object");
    };
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        client.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
    )
    .await??;
    res.structured_content
        .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
}

/// Shrinks the management timeouts and the source-address probe for the mock
/// device on loopback, as the CLI mock-device tests do.
fn fast_mock_timeouts() {
    // SAFETY: nextest runs each test in its own process, and every test in
    // this binary sets the same values before the server starts; they are
    // read when a management connection or probe is set up.
    unsafe {
        std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
        std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
    }
}

#[tokio::test]
async fn test_knx_discard_edits_one_device_keeps_the_other_and_undo_restores() -> anyhow::Result<()>
{
    fast_mock_timeouts();
    let gateway = MockGateway::builder()
        .channel(CHANNEL)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .device(device()?)
        .start()
        .await?;
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let connection = ConnectionConfig::tunnel(gateway.addr());
    let config = McpConfig {
        dir: dir.path().to_path_buf(),
        connection: connection.clone(),
        passive: false,
        allow_writes: false,
        no_model_edits: false,
        capture_db: None,
        allow_programming: true,
        allow_remote_gateway: false,
        plan_ttl: Duration::from_secs(600),
        keyring: None,
        allow_home_assistant: false,
    };
    let state = bussard_mcp::build_state(&config)?;
    let service = bussard_service::BusService::open(connection, config.write_policy())?;
    if !service.wait_connected(Duration::from_secs(5)).await {
        anyhow::bail!("the mock tunnel did not come up");
    }
    state.bus.wire(service);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    let device_file =
        |ia: &str| std::fs::read_to_string(dir.path().join(format!("devices/{ia}.toml")));

    // Before any edit the device holds the model.
    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.5"})).await?;
    assert_eq!(plan["noop"], true, "baseline plan: {plan}");

    // One edit on each device.
    for args in [
        json!({"address": "1.1.5", "com_object": 22, "ga": "1/2/2", "role": "listen"}),
        json!({"address": "1.1.202", "com_object": 3, "ga": "1/2/1", "role": "listen"}),
    ] {
        let res = call(&client, "knx_add_link", args).await?;
        assert_eq!(res["ok"], true, "{res}");
    }
    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.5"})).await?;
    assert_eq!(plan["noop"], false, "{plan}");
    assert_eq!(
        plan["pending_model_changes"].as_array().map(Vec::len),
        Some(1)
    );

    // Discard 1.1.5 only.
    let discarded = call(&client, "knx_discard_edits", json!({"address": "1.1.5"})).await?;
    assert_eq!(discarded["ok"], true, "{discarded}");
    assert_eq!(discarded["discarded"], "1.1.5");
    let dropped = discarded["dropped"].to_string();
    // The dropped link names the group address by its name (issue #306);
    // the structured detail keeps the address.
    assert!(dropped.contains("Light dim"), "{discarded}");
    assert!(
        discarded["detail"]
            .as_array()
            .is_some_and(|d| d.iter().any(|c| c["group"] == "1/2/2")),
        "{discarded}"
    );
    assert!(discarded["snapshot"].is_string(), "{discarded}");
    assert!(!device_file("1.1.5")?.contains("1/2/2"));
    assert!(
        device_file("1.1.202")?.contains("1/2/1"),
        "1.1.202 keeps its edit"
    );

    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.5"})).await?;
    assert_eq!(plan["noop"], true, "after discard: {plan}");
    assert_eq!(plan["pending_model_changes"], json!([]), "{plan}");

    // Nothing left to discard on 1.1.5; 1.1.202 still has its edit.
    let again = call(&client, "knx_discard_edits", json!({"address": "1.1.5"})).await?;
    assert_eq!(again["refused"], true, "{again}");

    // Undo the discard: the edit is back in the file and pending again.
    let undone = call(&client, "knx_undo", json!({})).await?;
    assert_eq!(undone["ok"], true, "{undone}");
    assert!(device_file("1.1.5")?.contains("1/2/2"));
    assert!(device_file("1.1.202")?.contains("1/2/1"));
    let plan = call(&client, "knx_plan_device", json!({"address": "1.1.5"})).await?;
    assert_eq!(plan["noop"], false, "after undo: {plan}");
    let pending = &plan["pending_model_changes"];
    assert_eq!(pending.as_array().map(Vec::len), Some(1), "{plan}");
    assert_eq!(pending[0]["tool"], "knx_add_link", "{plan}");

    client.cancel().await?;
    task.abort();
    drop(gateway);
    Ok(())
}
