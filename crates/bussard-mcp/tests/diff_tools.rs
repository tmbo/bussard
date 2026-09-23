//! Integration test for `knx_export_bundle` and `knx_diff_project`
//! (issues #111, #99), over an in-process duplex transport against a real
//! temporary model directory. No bus is involved.

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

/// The client half of an in-process connection.
type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// A fresh temporary model directory with one GA named `name`.
fn model_dir(tag: &str, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-mcp-diff-{tag}-{}-{:?}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("groups.yaml"),
        format!("groups:\n  \"1/0/1\":\n    name: {name}\n    dpt: \"1.001\"\n"),
    )?;
    std::fs::write(dir.join("links.yaml"), "links: {}\n")?;
    Ok(dir)
}

/// A passive server with model edits off: the diff tools must still be there.
fn server_over(dir: &Path) -> Result<BussardMcp, Box<dyn std::error::Error>> {
    let model = Model::load(dir)?;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(dir.to_path_buf(), model),
        dir: dir.to_path_buf(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: true,
        allow_writes: false,
        no_model_edits: true,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
    });
    Ok(BussardMcp::new(state))
}

/// Connects a client to `server`.
async fn connect(
    server: BussardMcp,
) -> Result<(Client, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
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
    client: &Client,
    name: &'static str,
    args: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let map = args.as_object().cloned().unwrap_or_default();
    let result = client
        .call_tool(CallToolRequestParams::new(name).with_arguments(map))
        .await?;
    result
        .structured_content
        .ok_or_else(|| format!("{name} returned no structured content").into())
}

#[tokio::test]
async fn test_export_bundle_and_diff_project_explain_a_rename() -> TestResult {
    let owner = model_dir("owner", "Light Kitchen")?;
    let integrator = model_dir("integrator", "Kitchen ceiling")?;
    let bundle = integrator.join("new.bussard");

    // The integrator's server exports; the owner's server diffs against it.
    let (client, task) = connect(server_over(&integrator)?).await?;
    let res = call(
        &client,
        "knx_export_bundle",
        json!({ "path": bundle.display().to_string() }),
    )
    .await?;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["manifest"]["group_addresses"], 1, "{res}");
    assert!(bundle.is_file());
    client.cancel().await?;
    task.abort();

    let (client, task) = connect(server_over(&owner)?).await?;
    let res = call(
        &client,
        "knx_diff_project",
        json!({ "path": bundle.display().to_string() }),
    )
    .await?;
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["count"], 1, "{res}");
    assert_eq!(res["changes"][0]["kind"], "group_renamed", "{res}");
    assert_eq!(
        res["summary"],
        "Group address 1/0/1 is now called \"Kitchen ceiling\" (was \"Light Kitchen\")."
    );

    // A missing file is a refusal the assistant reads out, not a protocol error.
    let res = call(
        &client,
        "knx_diff_project",
        json!({ "path": owner.join("nope.bussard").display().to_string() }),
    )
    .await?;
    assert_eq!(res["refused"], true, "{res}");
    client.cancel().await?;
    task.abort();

    std::fs::remove_dir_all(&owner)?;
    std::fs::remove_dir_all(&integrator)?;
    Ok(())
}
