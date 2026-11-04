//! `knx_viz`: the `bussard viz` page served from inside the MCP server.
//!
//! The page is fed from the server's own model handle and its one bus
//! connection, against a loopback mock gateway: the tests fetch the page, the
//! model API and the live state from the URL the tool returns, check that a
//! second call returns the same URL, that a group write answers `403`, and
//! that the gateway saw one tunnel connection only.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bussard_mcp::server::BussardMcp;
use bussard_mcp::{McpConfig, SharedState, tools_program};
use bussard_model::Model;
use bussard_testkit::{MockGateway, TestResult, ga, ia};
use bussard_transport::ConnectionConfig;
use bussard_transport::cemi::{CemiFrame, MessageCode};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// A passive server config for `dir` against `gateway`.
fn config(dir: &Path, gateway: SocketAddrV4) -> McpConfig {
    McpConfig {
        dir: dir.to_path_buf(),
        connection: ConnectionConfig::tunnel(gateway),
        passive: true,
        allow_writes: false,
        no_model_edits: true,
        capture_db: None,
        allow_programming: false,
        allow_remote_gateway: false,
        plan_ttl: tools_program::DEFAULT_PLAN_TTL,
        keyring: None,
        allow_home_assistant: false,
        viz_listen: None,
    }
}

/// A one-group model written to `dir`, loaded back.
fn write_model(dir: &Path) -> TestResult<Model> {
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/1\", name = \"Light\", dpt = \"1.001\" },\n]\n",
    )?;
    Ok(Model::load(dir)?)
}

/// Serves `state` over an in-memory transport and connects a client.
async fn connect(state: Arc<SharedState>) -> TestResult<(Client, tokio::task::JoinHandle<()>)> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = BussardMcp::new(state);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, task))
}

/// Calls `knx_viz` and returns its structured result.
async fn call_viz(client: &Client) -> TestResult<Value> {
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.call_tool(CallToolRequestParams::new("knx_viz")),
    )
    .await
    .map_err(|_| "knx_viz did not return in time")??;
    Ok(result
        .structured_content
        .ok_or("knx_viz returned no structured content")?)
}

/// One HTTP exchange: the status and the body text.
async fn http(method: &'static str, url: String, body: Option<Value>) -> TestResult<(u16, String)> {
    let reply = tokio::task::spawn_blocking(move || -> anyhow::Result<(u16, String)> {
        let request = ureq::request(method, &url).timeout(Duration::from_secs(5));
        let response = match body {
            Some(body) => request
                .set("Content-Type", "application/json")
                .send_string(&body.to_string()),
            None => request.call(),
        };
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(e) => return Err(e.into()),
        };
        Ok((response.status(), response.into_string()?))
    })
    .await??;
    Ok(reply)
}

#[tokio::test]
async fn test_knx_viz_serves_the_page_from_the_server_bus() -> TestResult {
    let gw = MockGateway::builder().channel(0x51).start().await?;
    let tmp = tempfile::tempdir()?;
    let model = write_model(tmp.path())?;
    let config = config(tmp.path(), gw.addr());
    let state = bussard_mcp::build_state_from_model(model, &config)?;
    // The server's one bus, wired as `run::serve_stdio` does.
    let service =
        bussard_service::BusService::open(config.connection.clone(), config.write_policy())?;
    state.bus.wire(service.clone());
    let (client, task) = connect(Arc::clone(&state)).await?;

    let first = call_viz(&client).await?;
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["read_only"], true);
    assert_eq!(first["live_traffic"], true);
    let url = first["url"].as_str().ok_or("no url")?.to_string();
    assert!(url.starts_with("http://127.0.0.1:"), "{url}");

    let second = call_viz(&client).await?;
    assert_eq!(
        second["url"], first["url"],
        "a second call returns the same url"
    );

    let (status, body) = http("GET", format!("{url}/"), None).await?;
    assert_eq!(status, 200);
    assert!(body.contains('<'), "the page is HTML");

    let (status, body) = http("GET", format!("{url}/api/model"), None).await?;
    assert_eq!(status, 200);
    let projection: Value = serde_json::from_str(&body)?;
    assert_eq!(projection["stats"]["groups"], 1, "{projection}");

    let (status, body) = http(
        "POST",
        format!("{url}/api/group-write"),
        Some(json!({"address": "1/0/1", "value": "on"})),
    )
    .await?;
    assert_eq!(status, 403, "{body}");

    // A telegram on the server's bus reaches the page's live state.
    assert!(
        gw.wait_until(Duration::from_secs(5), |s| s.connects >= 1)
            .await,
        "the server's bus connected"
    );
    // A device's write as the gateway indicates it (`L_Data.ind`).
    let mut indication = CemiFrame::group_write_packed(ga("1/0/1")?, ia("1.1.7")?, &[1]);
    indication.message_code = MessageCode::LDataInd;
    gw.push(indication)?;
    let mut seen = Value::Null;
    for _ in 0..50 {
        let (_, body) = http("GET", format!("{url}/api/state"), None).await?;
        seen = serde_json::from_str(&body)?;
        if seen["values"].get("1/0/1").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen["values"].get("1/0/1").is_some(), "{seen}");
    assert_eq!(
        gw.stats().connects,
        1,
        "the page shares the server's tunnel, it opens none of its own"
    );

    state.viz.stop().await;
    assert!(
        http("GET", format!("{url}/"), None).await.is_err(),
        "the page stops with the server"
    );
    client.cancel().await?;
    task.abort();
    service.close().await;
    Ok(())
}

#[tokio::test]
async fn test_knx_viz_without_a_bus_serves_the_model() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let model = write_model(tmp.path())?;
    // A loopback port nothing listens on; no bus is wired.
    let config = config(tmp.path(), SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let state = bussard_mcp::build_state_from_model(model, &config)?;
    let (client, task) = connect(Arc::clone(&state)).await?;

    let reply = call_viz(&client).await?;
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["live_traffic"], false);
    let url = reply["url"].as_str().ok_or("no url")?.to_string();
    let (status, body) = http("GET", format!("{url}/api/model"), None).await?;
    assert_eq!(status, 200);
    let projection: Value = serde_json::from_str(&body)?;
    assert_eq!(projection["stats"]["groups"], 1, "{projection}");

    // A foreign Host is refused, as by `bussard viz`.
    let foreign = tokio::task::spawn_blocking(move || -> anyhow::Result<u16> {
        let response = match ureq::get(&format!("{url}/api/model"))
            .set("Host", "evil.example")
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(e) => return Err(e.into()),
        };
        Ok(response.status())
    })
    .await??;
    assert_eq!(foreign, 403);

    state.viz.stop().await;
    client.cancel().await?;
    task.abort();
    Ok(())
}
