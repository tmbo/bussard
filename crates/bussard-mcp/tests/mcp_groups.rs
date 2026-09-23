//! `knx_scaffold_groups` over an in-process MCP client (issue #103).
//!
//! The server runs over a temp model directory; the tool writes `groups.yaml`
//! and `bussard.yaml` there and reports what it added. No bus is involved.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bussard_mcp::SharedState;
use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_transport::TransportKind;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;

/// A fresh model directory holding only a loopback `bussard.yaml`.
fn model_dir() -> Result<PathBuf, Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bussard-mcp-scaffold-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("bussard.yaml"),
        "connection:\n  transport: tunnel\n  gateway: \"127.0.0.1:3671\"\n",
    )?;
    Ok(dir)
}

fn server_over(dir: &Path) -> Result<BussardMcp, Box<dyn Error>> {
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
    });
    Ok(BussardMcp::new(state))
}

#[tokio::test]
async fn test_knx_scaffold_groups_writes_the_plan() -> Result<(), Box<dyn Error>> {
    let dir = model_dir()?;
    let server = server_over(&dir)?;
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;

    let args = serde_json::json!({
        "plan": {"rooms": [{"floor": "Ground floor", "room": "Kitchen",
                            "functions": ["light", "blind"]}]},
        "scheme": "floor-trade-block",
    });
    let serde_json::Value::Object(args) = args else {
        panic!("arguments must be an object");
    };
    let res = client
        .call_tool(CallToolRequestParams::new("knx_scaffold_groups").with_arguments(args))
        .await?;
    let Some(structured) = res.structured_content else {
        panic!("the tool must return structured content");
    };
    // light: switch + status; blind: seven roles.
    assert_eq!(structured["added_count"], 9, "{structured}");
    assert_eq!(structured["added"][0]["address"], "1/1/0", "{structured}");
    assert_eq!(structured["validation"]["errors"], 0, "{structured}");
    assert_eq!(structured["validation"]["warnings"], 0, "{structured}");
    assert_eq!(structured["lint_config_written"], true, "{structured}");

    let model = Model::load(&dir)?;
    assert_eq!(model.groups.groups.len(), 9);
    assert!(model.config.lint.is_some());

    // The write is undoable: one history snapshot was taken before it.
    assert!(structured["snapshot"].is_string(), "{structured}");
    let snapshots = bussard_model::History::open(&dir).list()?;
    assert_eq!(snapshots.len(), 1, "one snapshot before the scaffold write");

    client.cancel().await?;
    server_task.abort();
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
