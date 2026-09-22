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
            protected: true,
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
    build_server_modes(passive, false)
}

fn build_server_modes(passive: bool, allow_writes: bool) -> BussardMcp {
    build_server_over(model(), passive, allow_writes)
}

/// Builds a server handler over a caller-supplied model.
fn build_server_over(model: Model, passive: bool, allow_writes: bool) -> BussardMcp {
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
        allow_writes,
        no_model_edits: true,
        capture_db: None,
    };
    // Reconstruct state directly so we control passivity without touching disk.
    // No bus handle is wired here (the tools we exercise are model-only, and the
    // read/write tools report "bus not connected" without one).
    let _ = &cfg;
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(cfg.dir.clone(), model),
        dir: cfg.dir.clone(),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive,
        allow_writes,
        no_model_edits: true,
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
async fn tools_list_has_twelve_tools_by_default() {
    let (client, server_task) = connect_client(build_server(false)).await;
    let tools = client.list_all_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    let mut expected = bussard_mcp::tool_names(false, false, true);
    expected.sort();
    assert_eq!(
        names, expected,
        "default mode exposes 10 bus/model tools plus the 2 history read tools"
    );
    assert_eq!(tools.len(), 12);
    assert!(names.contains(&"knx_describe_change".to_string()));
    assert!(!names.contains(&"knx_write_group".to_string()));
    assert!(names.contains(&"knx_describe_device".to_string()));

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn tools_list_has_thirteen_tools_with_allow_writes() {
    let (client, server_task) = connect_client(build_server_modes(false, true)).await;
    let tools = client.list_all_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    let mut expected = bussard_mcp::tool_names(false, true, true);
    expected.sort();
    assert_eq!(names, expected, "--allow-writes adds knx_write_group");
    assert_eq!(tools.len(), 13);
    assert!(names.contains(&"knx_write_group".to_string()));
    assert!(names.contains(&"knx_read_group".to_string()));

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn tools_list_has_ten_tools_in_passive_mode() {
    let (client, server_task) = connect_client(build_server(true)).await;
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(
        tools.len(),
        10,
        "passive mode omits knx_read_group and knx_describe_device, and keeps the \
         file-only history tools"
    );
    assert!(!names.contains(&"knx_read_group".to_string()));
    assert!(!names.contains(&"knx_describe_device".to_string()));
    assert!(names.contains(&"knx_project_summary".to_string()));
    assert!(names.contains(&"knx_scaffold_groups".to_string()));

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
async fn write_group_absent_without_allow_writes() {
    // Default mode (no --allow-writes): the write tool is not registered.
    let (client, server_task) = connect_client(build_server(false)).await;
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    args.insert("value".to_string(), serde_json::json!("on"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_write_group").with_arguments(args))
        .await;
    assert!(
        res.is_err(),
        "knx_write_group must not exist without --allow-writes"
    );

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn write_group_refuses_protected_ga() {
    // 3/2/0 (Windalarm) is protected in the fixture model: refuse outright.
    let (client, server_task) = connect_client(build_server_modes(false, true)).await;
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    args.insert("value".to_string(), serde_json::json!("alarm"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_write_group").with_arguments(args))
        .await
        .unwrap();
    let s = res.structured_content.expect("structured");
    assert_eq!(s["ok"], false, "protected write must be refused: {s:?}");
    assert_eq!(s["refused"], true);
    assert!(
        s["reason"].as_str().unwrap().contains("protected"),
        "reason: {}",
        s["reason"]
    );

    client.cancel().await.unwrap();
    server_task.abort();
}

/// A model with one unprotected, typed GA, for the DPT-override cases.
fn typed_model() -> Model {
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("3/0/4"),
        Group {
            name: "Living Room Blind Move".to_string(),
            dpt: Some("1.008".parse().unwrap()),
            description: None,
            protected: false,
        },
    );
    Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: Some("Test".to_string()),
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links {
            links: BTreeMap::new(),
        },
        devices: BTreeMap::new(),
    }
}

#[tokio::test]
async fn write_group_refuses_a_dpt_override_that_contradicts_the_model() {
    // Without this check a caller could send `dpt: "5.001", value: "255"` at a
    // 1.008 GA and put an arbitrary payload byte on the bus, past every type
    // the model declares. The CLI has the same override behind a human y/N;
    // MCP has no human in the loop, so it refuses.
    let (client, server_task) = connect_client(build_server_over(typed_model(), false, true)).await;
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/0/4"));
    args.insert("value".to_string(), serde_json::json!("255"));
    args.insert("dpt".to_string(), serde_json::json!("5.001"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_write_group").with_arguments(args))
        .await
        .unwrap();
    let s = res.structured_content.expect("structured");
    assert_eq!(s["ok"], false, "a contradicting override must be refused");
    assert_eq!(s["refused"], true);
    let reason = s["reason"].as_str().unwrap();
    assert!(
        reason.contains("1.008") && reason.contains("5.001"),
        "{reason}"
    );

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn write_group_accepts_a_dpt_override_matching_the_model() {
    // The same DPT the model declares is not a contradiction: it reaches the
    // encoder (and then fails on the absent bus, not on the override).
    let (client, server_task) = connect_client(build_server_over(typed_model(), false, true)).await;
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/0/4"));
    args.insert("value".to_string(), serde_json::json!("down"));
    args.insert("dpt".to_string(), serde_json::json!("1.008"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_write_group").with_arguments(args))
        .await
        .unwrap();
    let s = res.structured_content.expect("structured");
    assert_eq!(s["ok"], false, "no bus is wired, so the send fails");
    assert!(s.get("refused").is_none(), "but not as a refusal: {s:?}");

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn write_group_reports_parse_error() {
    // A value that cannot be parsed for the DPT is a structured failure, not a
    // bus write. 3/2/0 is protected though, so use a non-existent GA with an
    // explicit DPT to reach the parser (bus is disconnected, so nothing sends).
    let (client, server_task) = connect_client(build_server_modes(false, true)).await;
    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("6/0/0"));
    args.insert(
        "value".to_string(),
        serde_json::json!("definitely-not-a-bool"),
    );
    args.insert("dpt".to_string(), serde_json::json!("1.001"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_write_group").with_arguments(args))
        .await
        .unwrap();
    let s = res.structured_content.expect("structured");
    assert_eq!(s["ok"], false, "parse error must fail: {s:?}");
    assert!(
        s["reason"].as_str().unwrap().contains("1.001"),
        "reason names the DPT: {}",
        s["reason"]
    );

    client.cancel().await.unwrap();
    server_task.abort();
}

/// Builds a server whose state points at a pre-populated capture DB and whose
/// ring is pre-filled, for the `knx_recent_telegrams` fallback tests.
fn build_server_with_capture(
    capture_db: std::path::PathBuf,
    ring: bussard_monitor::TelegramRing,
) -> BussardMcp {
    let state = Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(
            std::path::PathBuf::from("knx"),
            model(),
        ),
        dir: std::path::PathBuf::from("knx"),
        ring,
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: false,
        allow_writes: false,
        no_model_edits: true,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: Some(capture_db),
        source_ia: "0.0.255".parse().unwrap(),
    });
    BussardMcp::new(state)
}

/// A decoded 1-bit write telegram to `dest` from `src` at `ts`, with its frame,
/// for seeding the ring and/or the capture DB identically (so dedup can fire).
fn decoded_pair(
    dest: &str,
    src: &str,
    ts: std::time::SystemTime,
) -> (
    bussard_monitor::DecodedTelegram,
    bussard_transport::TimestampedFrame,
) {
    let frame = bussard_transport::TimestampedFrame {
        received_at: ts,
        frame: bussard_transport::cemi::CemiFrame::group_write_packed(ga(dest), ia(src), &[1]),
    };
    let decoded = bussard_monitor::DecodedTelegram::from_frame(&frame, None);
    (decoded, frame)
}

#[tokio::test]
async fn recent_telegrams_db_fallback_prefix_filters_and_dedupes() {
    use std::time::{Duration, SystemTime};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("capture.db");
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);

    // Seed the capture DB: three OLD rows under prefix "3/2/" plus one that must
    // NOT match the prefix ("4/0/0"), and one row that will ALSO be in the ring
    // (identical fields) to exercise dedup.
    let dup = decoded_pair("3/2/9", "1.1.30", base + Duration::from_secs(50));
    {
        let writer = bussard_monitor::CaptureWriter::open(&db_path).unwrap();
        let seed = |ts_off: u64, dest: &str| {
            let (d, f) = decoded_pair(dest, "1.1.30", base + Duration::from_secs(ts_off));
            bussard_monitor::CaptureRecord::from_decoded(&d, &f)
        };
        assert!(writer.record(seed(1, "3/2/1")));
        assert!(writer.record(seed(2, "3/2/2")));
        assert!(writer.record(seed(3, "4/0/0"))); // out of prefix
        // The duplicate row (same instant/source/dest/payload as a ring row).
        assert!(writer.record(bussard_monitor::CaptureRecord::from_decoded(&dup.0, &dup.1)));
        writer.finish().unwrap();
    }

    // Seed the ring: the newest matching row plus the SAME duplicate row.
    let ring = bussard_monitor::TelegramRing::new();
    ring.push(dup.0.clone()); // duplicate of a DB row
    let newest = decoded_pair("3/2/3", "1.1.30", base + Duration::from_secs(100));
    ring.push(newest.0.clone());

    let server = build_server_with_capture(db_path, ring);
    let (client, server_task) = connect_client(server).await;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/"));
    args.insert("limit".to_string(), serde_json::json!(50));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_recent_telegrams").with_arguments(args))
        .await
        .unwrap();
    let s = res.structured_content.expect("structured");

    let telegrams = s["telegrams"].as_array().expect("telegrams array");
    let dests: Vec<&str> = telegrams
        .iter()
        .map(|t| t["destination"].as_str().unwrap())
        .collect();

    // The out-of-prefix "4/0/0" DB row must be filtered out (this was the bug:
    // a prefix filter previously fell through to an unfiltered SQL query).
    assert!(
        !dests.contains(&"4/0/0"),
        "prefix filter must exclude 4/0/0: {dests:?}"
    );
    // Every returned row is under 3/2/.
    assert!(
        dests.iter().all(|d| d.starts_with("3/2/")),
        "all rows under prefix: {dests:?}"
    );
    // The duplicate row (in both ring and DB) appears exactly once.
    let dup_count = dests.iter().filter(|d| **d == "3/2/9").count();
    assert_eq!(
        dup_count, 1,
        "ring/DB duplicate must be de-duped: {dests:?}"
    );
    // Chronological, newest last: the ring's 3/2/3 at +100s is the final row.
    assert_eq!(
        dests.last().copied(),
        Some("3/2/3"),
        "newest ring row is last: {dests:?}"
    );
    // Expected matching set: DB 3/2/1, 3/2/2, dup 3/2/9, ring 3/2/3 = 4 rows.
    assert_eq!(s["count"], 4, "matched rows: {dests:?}");

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn describe_device_without_a_bus_reports_not_wired() {
    // In default mode the tool is registered; without a wired bus it returns a
    // structured ok:false ("bus is not wired") rather than erroring or hanging.
    let (client, server_task) = connect_client(build_server(false)).await;
    let mut args = serde_json::Map::new();
    args.insert("address".to_string(), serde_json::json!("1.1.4"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_describe_device").with_arguments(args))
        .await
        .expect("describe returns a result");
    let s = res.structured_content.expect("structured");
    assert_eq!(s["address"], "1.1.4");
    assert_eq!(s["ok"], false, "no bus wired → ok:false; was {s:?}");

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn describe_device_rejects_a_bad_address() {
    // A malformed individual address is an invalid-params protocol error.
    let (client, server_task) = connect_client(build_server(false)).await;
    let mut args = serde_json::Map::new();
    args.insert("address".to_string(), serde_json::json!("not-an-address"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_describe_device").with_arguments(args))
        .await;
    assert!(res.is_err(), "a bad address must be rejected");

    client.cancel().await.unwrap();
    server_task.abort();
}

#[tokio::test]
async fn describe_device_in_passive_mode_is_absent() {
    // Introspection transmits management traffic, so passive mode unregisters it.
    let (client, server_task) = connect_client(build_server(true)).await;
    let mut args = serde_json::Map::new();
    args.insert("address".to_string(), serde_json::json!("1.1.4"));
    let res = client
        .call_tool(CallToolRequestParams::new("knx_describe_device").with_arguments(args))
        .await;
    assert!(
        res.is_err(),
        "knx_describe_device must not exist in passive mode"
    );

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
