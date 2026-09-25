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
        keyring: None,
    }))
}

async fn connect_client_over(
    state: Arc<SharedState>,
    config: ConnectionConfig,
) -> TestResult<(Client, tokio::task::JoinHandle<()>)> {
    // Replicate serve_stdio's wiring over a duplex transport: spawn the bus
    // actor, wire it into the status, feed the ring from a subscription, serve.
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);

    let (handle, _task) = bussard_bus::Bus::connect(config.clone());
    // The mock gateway is loopback, so the transmitting policy's write gate
    // passes, exactly as `bussard mcp --allow-writes` against the simulator.
    let service = bussard_service::BusService::from_handle(
        config,
        handle.clone(),
        bussard_service::WritePolicy::transmit(false),
    )
    .expect("a loopback gateway passes the write gate");
    state.bus.wire(service);

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
    if let Ok(service) =
        bussard_service::BusService::open(config, bussard_service::WritePolicy::ReadOnly)
    {
        let _ = serve_stdio(state, service).await;
    }
}

// --- The warm management connection (issue #215) ---------------------------

/// A describable System B device: four interface objects with a few property
/// descriptions each, answering after `delay`. Counts the `T_Disconnect`s it
/// sees in `disconnects`.
fn describable_device(
    address: &str,
    delay: Option<Duration>,
    disconnects: Arc<std::sync::atomic::AtomicUsize>,
) -> TestResult<bussard_testkit::MockDevice> {
    let mut dev = bussard_testkit::MockDevice::new(ia(address)?)
        .with_object_types(&[0, 1, 2, 3])
        .with_property(0, 56, 2, &55u16.to_be_bytes())
        .with_control_hook(move |_, kind| {
            if kind == bussard_transport::tpci::TpciKind::Disconnect {
                disconnects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Vec::new()
        });
    for index in 0..4u8 {
        let pids: &[u8] = if index == 0 { &[1, 11, 56] } else { &[1, 5, 7] };
        let descriptions: Vec<bussard_testkit::MockPropertyDescription> = pids
            .iter()
            .map(|&pid| bussard_testkit::MockPropertyDescription {
                pid,
                pdt: 0x04,
                writable: false,
                max_elements: 1,
                read_level: 3,
                write_level: 1,
            })
            .collect();
        dev = dev.with_property_descriptions(index, &descriptions);
    }
    Ok(match delay {
        Some(delay) => dev.with_response_delay(delay),
        None => dev,
    })
}

/// One `knx_describe_device` call: its result, the requests the device saw
/// for it and its wall-clock.
async fn timed_describe(
    client: &Client,
    gw: &MockGateway,
    address: &str,
) -> TestResult<(serde_json::Value, usize, Duration)> {
    let before = gw.with_device(ia(address)?, |d| d.requests.len())?;
    let started = std::time::Instant::now();
    let result = call_tool(
        client,
        "knx_describe_device",
        serde_json::json!({ "address": address }),
        Duration::from_secs(30),
    )
    .await?;
    let elapsed = started.elapsed();
    let after = gw.with_device(ia(address)?, |d| d.requests.len())?;
    Ok((result, after - before, elapsed))
}

/// Issue #215: two consecutive `knx_describe_device` calls to one device share
/// one management connection (one `T_Connect`, no second authorize or max-APDU
/// read) and return the same objects. After the idle window the server has
/// closed it, and the next call connects again.
#[tokio::test]
async fn describe_reuses_the_warm_connection_within_the_idle_window() -> TestResult {
    let disconnects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gw = MockGateway::builder()
        .channel(0x4C)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .device(describable_device(
            "1.1.12",
            None,
            Arc::clone(&disconnects),
        )?)
        .start()
        .await?;
    let (client, server_task) =
        connect_client_over(state_for()?, ConnectionConfig::tunnel(gw.addr())).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (first, first_requests, _) = timed_describe(&client, &gw, "1.1.12").await?;
    let (second, second_requests, _) = timed_describe(&client, &gw, "1.1.12").await?;
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first, second);
    assert_eq!(gw.with_device(ia("1.1.12")?, |d| d.connects)?, 1);
    // The second call skips the authorize and the max-APDU read.
    assert_eq!(second_requests + 2, first_requests);
    assert_eq!(disconnects.load(std::sync::atomic::Ordering::SeqCst), 0);

    // The idle close: the kept connection is disconnected after the window.
    tokio::time::sleep(bussard_mcp::warm::WARM_IDLE_LIMIT + Duration::from_millis(500)).await;
    assert_eq!(disconnects.load(std::sync::atomic::Ordering::SeqCst), 1);
    let (third, third_requests, _) = timed_describe(&client, &gw, "1.1.12").await?;
    assert_eq!(third, first);
    assert_eq!(third_requests, first_requests);
    assert_eq!(gw.with_device(ia("1.1.12")?, |d| d.connects)?, 2);

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

/// Issue #215: a call to another device disconnects the warm connection first
/// (one device at a time), and a call back to the first device connects again.
#[tokio::test]
async fn describe_of_another_device_releases_the_warm_connection() -> TestResult {
    let (a_disconnects, b_disconnects) = (
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    );
    let gw = MockGateway::builder()
        .channel(0x4D)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .device(describable_device(
            "1.1.12",
            None,
            Arc::clone(&a_disconnects),
        )?)
        .device(describable_device(
            "1.1.13",
            None,
            Arc::clone(&b_disconnects),
        )?)
        .start()
        .await?;
    let (client, server_task) =
        connect_client_over(state_for()?, ConnectionConfig::tunnel(gw.addr())).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (a, _, _) = timed_describe(&client, &gw, "1.1.12").await?;
    assert_eq!(a["ok"], true, "{a}");
    let (b, _, _) = timed_describe(&client, &gw, "1.1.13").await?;
    assert_eq!(b["ok"], true, "{b}");
    // 1.1.12's connection was closed before 1.1.13 was connected.
    assert_eq!(a_disconnects.load(std::sync::atomic::Ordering::SeqCst), 1);
    let (a_again, _, _) = timed_describe(&client, &gw, "1.1.12").await?;
    assert_eq!(a_again, a);
    assert_eq!(gw.with_device(ia("1.1.12")?, |d| d.connects)?, 2);
    assert_eq!(b_disconnects.load(std::sync::atomic::Ordering::SeqCst), 1);

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

/// Issue #215 fallback: when the device has dropped the warm connection, the
/// call fails on it and is repeated on a fresh connection, with the same
/// result as a fresh call.
#[tokio::test]
async fn describe_on_a_dropped_warm_connection_reconnects() -> TestResult {
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_armed = Arc::clone(&armed);
    let device = describable_device(
        "1.1.12",
        None,
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )?
    .with_hook(move |_, _, _| {
        // Once armed, the next request is answered with a T_Disconnect: the
        // device has closed the connection.
        hook_armed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
            .then(|| bussard_testkit::Reaction::Script(vec![bussard_testkit::Step::Control(0x81)]))
    });
    let gw = MockGateway::builder()
        .channel(0x4F)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .device(device)
        .start()
        .await?;
    let (client, server_task) =
        connect_client_over(state_for()?, ConnectionConfig::tunnel(gw.addr())).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (first, _, _) = timed_describe(&client, &gw, "1.1.12").await?;
    assert_eq!(first["ok"], true, "{first}");
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let (second, _, _) = timed_describe(&client, &gw, "1.1.12").await?;
    assert_eq!(second, first);
    assert_eq!(gw.with_device(ia("1.1.12")?, |d| d.connects)?, 2);

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

/// Measurement for issue #215 (ignored): two consecutive
/// `knx_describe_device` calls with 200 ms per answer. The first call is what
/// every call cost before the warm connection.
#[tokio::test]
#[ignore = "measurement: 200 ms per answer"]
async fn measure_two_consecutive_describes() -> TestResult {
    let gw = MockGateway::builder()
        .channel(0x4E)
        .keep_serving()
        .idle_timeout(Duration::from_secs(60))
        .device(describable_device(
            "1.1.12",
            Some(Duration::from_millis(200)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )?)
        .start()
        .await?;
    let (client, server_task) =
        connect_client_over(state_for()?, ConnectionConfig::tunnel(gw.addr())).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (_, n1, t1) = timed_describe(&client, &gw, "1.1.12").await?;
    let (_, n2, t2) = timed_describe(&client, &gw, "1.1.12").await?;
    println!(
        "MEASURE two describes: first {n1} requests {:.2} s, second {n2} requests {:.2} s; \
         before the warm connection 2 x first = {} requests {:.2} s, now {} requests {:.2} s",
        t1.as_secs_f64(),
        t2.as_secs_f64(),
        2 * n1,
        2.0 * t1.as_secs_f64(),
        n1 + n2,
        (t1 + t2).as_secs_f64()
    );
    client.cancel().await?;
    server_task.abort();
    Ok(())
}
