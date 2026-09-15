//! Integration test: drive the bussard MCP server through the rmcp client over
//! an in-process duplex transport (no subprocess, no real bus).
//!
//! The server is built from an in-code model. Its bus stream task tries to
//! connect to an unreachable gateway and reconnects forever in the background —
//! which is exactly the "bus down at startup" case: model-only tools still work
//! and the bus reports `connecting`/`reconnecting`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use bussard_mcp::server::BussardMcp;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_mcp::{McpConfig, SharedState};
use bussard_model::schema::{BussardConfig, Group, Groups, Link, Links};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_transport::{ConnectionConfig, TransportKind};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}

fn model() -> Model {
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("3/2/0"),
        Group {
            name: "Windalarm".to_string(),
            dpt: Some("1.005".parse().unwrap()),
            description: None,
        },
    );
    let mut links = BTreeMap::new();
    links.insert(
        ia("1.1.30"),
        vec![Link {
            object: 3,
            name: Some("Windalarm 1".to_string()),
            send: Some(ga("3/2/0")),
            listen: vec![],
        }],
    );
    Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: Some("Test".to_string()),
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links { links },
        devices: BTreeMap::new(),
    }
}

/// Builds a server handler over an in-code model without spawning the bus
/// stream (the tools we exercise here don't need live traffic).
fn build_server(passive: bool) -> BussardMcp {
    let connection = ConnectionConfig {
        transport: TransportKind::Tunnel,
        gateway: Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3671)),
        multicast: SocketAddrV4::new(Ipv4Addr::new(224, 0, 23, 12), 3671),
        local_interface: Ipv4Addr::UNSPECIFIED,
    };
    let cfg = McpConfig {
        dir: std::path::PathBuf::from("knx"),
        connection: connection.clone(),
        passive,
        capture_db: None,
    };
    // Reconstruct state directly so we control passivity without touching disk.
    let (outbound, _rx) = if passive {
        (None, None)
    } else {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Some(tx), Some(rx))
    };
    let state = Arc::new(SharedState {
        model: model(),
        dir: cfg.dir.clone(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        outbound,
        passive,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse().unwrap(),
    });
    BussardMcp::new(state)
}

async fn connect_client(
    server: BussardMcp,
) -> (
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
) {
    let (server_io, client_io) = tokio::io::duplex(8 * 1024);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("client connects");
    (client, server_task)
}

#[tokio::test]
async fn tools_list_has_eight_tools_by_default() {
    let (client, server_task) = connect_client(build_server(false)).await;
    let tools = client.list_all_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    let mut expected = bussard_mcp::tool_names(false);
    expected.sort();
    assert_eq!(names, expected, "default mode exposes 8 tools");
    assert_eq!(tools.len(), 8);

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn tools_list_has_seven_tools_in_passive_mode() {
    let (client, server_task) = connect_client(build_server(true)).await;
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(tools.len(), 7, "passive mode omits knx_read_group");
    assert!(!names.contains(&"knx_read_group".to_string()));
    assert!(names.contains(&"knx_project_summary".to_string()));

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn project_summary_returns_sane_json() {
    let (client, server_task) = connect_client(build_server(false)).await;
    let res = client
        .call_tool(CallToolRequestParams::new("knx_project_summary"))
        .await
        .unwrap();
    let structured = res.structured_content.expect("structured content");
    assert_eq!(structured["project"], "Test");
    assert_eq!(structured["counts"]["group_addresses"], 1);
    assert_eq!(structured["counts"]["links"], 1);
    // Bus is not connected (unreachable gateway / no stream task): connecting.
    assert_eq!(structured["bus"]["transport"], "tunnel");
    assert_eq!(structured["bus"]["connected"], false);

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn model_lookup_and_get_group_roundtrip() {
    let (client, server_task) = connect_client(build_server(false)).await;

    // Lookup "wind".
    let mut args = serde_json::Map::new();
    args.insert("query".to_string(), serde_json::json!("wind"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_model_lookup").with_arguments(args))
        .await
        .unwrap();
    let structured = res.structured_content.unwrap();
    assert_eq!(structured["groups"][0]["address"], "3/2/0");

    // get_group for 3/2/0.
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_get_group").with_arguments(args))
        .await
        .unwrap();
    let structured = res.structured_content.unwrap();
    assert_eq!(structured["found"], true);
    assert_eq!(structured["links"][0]["role"], "send");

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn read_group_in_passive_mode_is_absent() {
    // In passive mode the tool is unregistered, so calling it errors at the
    // protocol level (unknown tool) rather than transmitting.
    let (client, server_task) = connect_client(build_server(true)).await;
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_read_group").with_arguments(args))
        .await;
    assert!(
        res.is_err(),
        "knx_read_group must not exist in passive mode"
    );

    client.cancel().await.unwrap();
    server_task.abort();
}
