//! Mock-gateway-driven integration test for `knx_read_group` and
//! `knx_wait_for_telegram`.
//!
//! The shared `bussard-testkit` mock gateway drives the *full* MCP server: the
//! server spawns its real bus stream against the mock, a client calls
//! `knx_read_group`, a mock responder sees the injected `GroupValueRead` and
//! replies with a `GroupValueResponse`, and the decoded value flows back
//! through the tool. A second client waits on
//! `knx_wait_for_telegram` while the mock pushes a matching write.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bussard_mcp::SharedState;
use bussard_mcp::run::serve_stdio;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::Model;
use bussard_model::schema::{BussardConfig, Group, Groups, Links};
use bussard_testkit::{MockGateway, TestResult, ga, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, MessageCode};
use bussard_transport::{ConnectionConfig, TransportKind};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;

type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

fn model() -> TestResult<Model> {
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("3/2/0")?,
        Group {
            name: "Windalarm".to_string(),
            dpt: Some("1.005".parse()?),
            description: None,
            protected: true,
            secure: false,
        },
    );
    // An unprotected blinds GA used by the write round-trip test.
    groups.insert(
        ga("3/0/4")?,
        Group {
            name: "Living Room Blind Move".to_string(),
            dpt: Some("1.008".parse()?),
            description: None,
            protected: false,
            secure: false,
        },
    );
    Ok(Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: Some("Bus".to_string()),
            imported_from: None,
            ranges: BTreeMap::new(),
            groups,
        },
        links: Links {
            links: BTreeMap::new(),
        },
        devices: BTreeMap::new(),
    })
}

/// Builds a live server state (no handle wired yet; the caller spawns the bus).
fn state_for() -> TestResult<Arc<SharedState>> {
    Ok(Arc::new(SharedState {
        model: bussard_mcp::model_handle::ModelHandle::new(
            std::path::PathBuf::from("knx"),
            model()?,
        ),
        dir: std::path::PathBuf::from("knx"),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        passive: false,
        allow_writes: true,
        no_model_edits: true,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse()?,
        programming: None,
    }))
}

async fn connect_client_over(
    state: Arc<SharedState>,
    config: ConnectionConfig,
) -> TestResult<(Client, tokio::task::JoinHandle<()>)> {
    // Replicate serve_stdio's wiring over a duplex transport: spawn the bus
    // actor, wire it into the status, feed the ring from a subscription, serve.
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);

    let (handle, _task) = bussard_bus::Bus::connect(config);
    state.bus.wire(handle.clone());

    let model = state.model.clone();
    let ring = state.ring.clone();
    let feeder_handle = handle.clone();
    let feeder = tokio::spawn(async move {
        let mut sub = feeder_handle.subscribe();
        while let Some(inbound) = sub.recv().await {
            let current = model.current();
            let decoded =
                bussard_monitor::DecodedTelegram::from_frame(&inbound.frame, Some(&current));
            ring.push_with_code(decoded, inbound.message_code);
        }
    });

    let server = bussard_mcp::server::BussardMcp::new(state.clone());
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
        feeder.abort();
    });
    let client = ().serve(client_io).await?;
    Ok((client, server_task))
}

/// Calls `tool` with `args` within `within` and returns its structured result.
async fn call_tool(
    client: &Client,
    tool: &'static str,
    args: serde_json::Value,
    within: Duration,
) -> TestResult<serde_json::Value> {
    let serde_json::Value::Object(map) = args else {
        return Err("tool arguments must be an object".into());
    };
    let res = tokio::time::timeout(
        within,
        client.call_tool(CallToolRequestParams::new(tool).with_arguments(map)),
    )
    .await
    .map_err(|_| format!("{tool} did not return in time"))??;
    Ok(res
        .structured_content
        .ok_or_else(|| format!("{tool} returned no structured content"))?)
}

#[tokio::test]
async fn read_group_sends_read_and_returns_value() -> TestResult {
    // The device answers the injected GroupValueRead with alarm = 1.
    let response = CemiFrame::group_response_packed(ga("3/2/0")?, ia("1.1.30")?, &[1]);
    let gw = MockGateway::builder()
        .channel(0x41)
        .respond(move |frame| {
            if frame.apdu == Apdu::GroupValueRead {
                vec![response.clone()]
            } else {
                Vec::new()
            }
        })
        .start()
        .await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let (client, server_task) = connect_client_over(state_for()?, config).await?;

    // Give the bus a moment to connect.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let s = call_tool(
        &client,
        "knx_read_group",
        serde_json::json!({"ga": "3/2/0"}),
        Duration::from_secs(5),
    )
    .await?;
    assert_eq!(s["ga"], "3/2/0");
    assert_eq!(s["ok"], true, "response was {s:?}");
    assert_eq!(s["value"], "Alarm");
    assert_eq!(s["dpt"], "1.005");

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

/// Issue #32: the gateway echoes our own request back as `L_Data.con` BEFORE
/// the device's response arrives. `knx_read_group` must skip the echo(es) and
/// return the real `L_Data.ind` GroupValueResponse.
#[tokio::test]
async fn read_group_skips_con_echo_and_returns_device_response() -> TestResult {
    // 1. The realistic con echo: our own GroupValueRead back as L_Data.con
    //    (same GA, our source IA 0.0.255).
    let mut read_echo = CemiFrame::group_read(ga("3/2/0")?, ia("0.0.255")?);
    read_echo.message_code = MessageCode::LDataCon;
    // 2. An adversarial con that a GA-only wait WOULD match: a
    //    GroupValueWrite con carrying the WRONG value (No Alarm = 0).
    let mut write_echo = CemiFrame::group_write_packed(ga("3/2/0")?, ia("0.0.255")?, &[0]);
    write_echo.message_code = MessageCode::LDataCon;
    // 3. The device's real answer: alarm = 1.
    let response = CemiFrame::group_response_packed(ga("3/2/0")?, ia("1.1.30")?, &[1]);
    let replies = vec![read_echo, write_echo, response];

    // On the injected GroupValueRead, push the echoes BEFORE the response.
    let gw = MockGateway::builder()
        .channel(0x45)
        .respond(move |frame| {
            if frame.apdu == Apdu::GroupValueRead {
                replies.clone()
            } else {
                Vec::new()
            }
        })
        .start()
        .await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let (client, server_task) = connect_client_over(state_for()?, config).await?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    let s = call_tool(
        &client,
        "knx_read_group",
        serde_json::json!({"ga": "3/2/0"}),
        Duration::from_secs(5),
    )
    .await?;
    assert_eq!(s["ga"], "3/2/0");
    assert_eq!(s["ok"], true, "response was {s:?}");
    assert_eq!(
        s["value"], "Alarm",
        "the DEVICE response (Alarm) must be returned, not the con echo: {s:?}"
    );
    assert_eq!(s["dpt"], "1.005");

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn write_group_sends_write_and_confirms() -> TestResult {
    let gw = MockGateway::builder().channel(0x43).start().await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let (client, server_task) = connect_client_over(state_for()?, config).await?;

    // Give the bus a moment to connect.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let s = call_tool(
        &client,
        "knx_write_group",
        serde_json::json!({"ga": "3/0/4", "value": "down"}),
        Duration::from_secs(5),
    )
    .await?;
    assert_eq!(s["ok"], true, "response was {s:?}");
    assert_eq!(s["written"]["address"], "3/0/4");
    assert_eq!(s["written"]["value"], "Down");
    assert_eq!(s["written"]["dpt"], "1.008");

    // The gateway saw the GroupValueWrite to 3/0/4 (down = 1).
    let writes: Vec<CemiFrame> = gw
        .sent()?
        .into_iter()
        .filter(|f| matches!(f.apdu, Apdu::GroupValueWrite(_)))
        .collect();
    assert_eq!(writes.len(), 1, "one write expected: {writes:?}");
    assert_eq!(writes[0].group_destination(), Some(ga("3/0/4")?));

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn wait_for_telegram_returns_pushed_write() -> TestResult {
    // After a short delay, the gateway pushes a write to 3/2/0 (the "button
    // press").
    let write = CemiFrame::group_write_packed(ga("3/2/0")?, ia("1.1.30")?, &[1]);
    let gw = MockGateway::builder()
        .channel(0x42)
        .push_after_connect(Duration::from_millis(200), write)
        .start()
        .await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let (client, server_task) = connect_client_over(state_for()?, config).await?;

    let s = call_tool(
        &client,
        "knx_wait_for_telegram",
        serde_json::json!({"ga": "3/2/0", "timeout_seconds": 5}),
        Duration::from_secs(6),
    )
    .await?;
    assert_eq!(s["matched"], true, "result was {s:?}");
    assert_eq!(s["telegram"]["destination"], "3/2/0");

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

/// A `serve_stdio` smoke wiring check (compiles + the fn is reachable). We do
/// not exercise stdio here since the other tests own the transport, but this
/// keeps the public entry point covered by a reference.
#[allow(dead_code)]
async fn _serve_stdio_is_public(state: Arc<SharedState>, config: ConnectionConfig) {
    let _ = serve_stdio(state, config).await;
}
