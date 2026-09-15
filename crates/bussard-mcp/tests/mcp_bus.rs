//! Mock-gateway-driven integration test for `knx_read_group` and
//! `knx_wait_for_telegram`.
//!
//! A minimal in-process KNXnet/IP tunnel mock (copied from the transport crate's
//! test pattern) drives the *full* MCP server: the server spawns its real bus
//! stream against the mock, a client calls `knx_read_group`, the mock sees the
//! injected `GroupValueRead` and replies with a `GroupValueResponse`, and the
//! decoded value flows back through the tool. A second client waits on
//! `knx_wait_for_telegram` while the mock pushes a matching write.

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use bussard_mcp::SharedState;
use bussard_mcp::run::serve_stdio;
use bussard_mcp::state::{BusStatus, ReadLimiter};
use bussard_model::schema::{BussardConfig, Group, Groups, Links};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_transport::cemi::{Apdu, CemiFrame};
use bussard_transport::knxnet::{self, ServiceType};
use bussard_transport::{ConnectionConfig, TransportKind};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use tokio::net::UdpSocket;

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
    // An unprotected blinds GA used by the write round-trip test.
    groups.insert(
        ga("3/0/4"),
        Group {
            name: "Jalousie Wohnen Süd — Auf/Ab".to_string(),
            dpt: Some("1.008".parse().unwrap()),
            description: None,
            protected: false,
        },
    );
    Model {
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
    }
}

async fn bind_mock() -> (SocketAddrV4, UdpSocket) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = match sock.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected v4"),
    };
    (addr, sock)
}

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(0x06);
    out.push(0x10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn connect_response_body(channel: u8, gw: &UdpSocket) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

/// Builds a live server state with an outbound channel; the bus stream (wired
/// by the caller) targets the mock gateway.
fn state_for() -> (
    Arc<SharedState>,
    tokio::sync::mpsc::UnboundedReceiver<CemiFrame>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let state = Arc::new(SharedState {
        model: model(),
        dir: std::path::PathBuf::from("knx"),
        ring: bussard_monitor::TelegramRing::new(),
        bus: BusStatus::new(TransportKind::Tunnel),
        outbound: Some(tx),
        passive: false,
        allow_writes: true,
        read_limiter: ReadLimiter::new(
            bussard_mcp::READ_MIN_INTERVAL,
            bussard_mcp::READ_MAX_CONCURRENT,
        ),
        capture_db: None,
        source_ia: "0.0.255".parse().unwrap(),
    });
    (state, rx)
}

async fn connect_client_over(
    state: Arc<SharedState>,
    config: ConnectionConfig,
    rx: tokio::sync::mpsc::UnboundedReceiver<CemiFrame>,
) -> (
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
) {
    // We cannot use serve_stdio (it owns real stdio), so replicate its wiring
    // over a duplex transport: spawn the bus stream, then serve MCP.
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state.clone());

    // The bus stream feeding the shared ring + draining outbound.
    let model = state.model.clone();
    let ring = state.ring.clone();
    let bus = state.bus.clone();
    let stream = tokio::spawn(async move {
        struct Sink {
            ring: bussard_monitor::TelegramRing,
            bus: BusStatus,
        }
        impl bussard_monitor::stream::TelegramSink for Sink {
            fn on_telegram(
                &mut self,
                t: &bussard_monitor::DecodedTelegram,
                f: &bussard_transport::TimestampedFrame,
            ) -> bussard_monitor::stream::Flow {
                // Same as run.rs's RingSink: carry the message code so the
                // read tool can skip L_Data.con echoes (issue #32).
                self.ring.push_with_code(t.clone(), f.frame.message_code);
                bussard_monitor::stream::Flow::Continue
            }
            fn on_connect(&mut self, _r: bool) -> bussard_monitor::stream::Flow {
                self.bus.set(bussard_mcp::state::ConnState::Connected);
                bussard_monitor::stream::Flow::Continue
            }
            fn on_disconnect(
                &mut self,
                _e: &bussard_transport::TransportError,
                _b: Duration,
            ) -> bussard_monitor::stream::Flow {
                self.bus.set(bussard_mcp::state::ConnState::Reconnecting);
                bussard_monitor::stream::Flow::Continue
            }
        }
        let mut sink = Sink { ring, bus };
        let _ =
            bussard_monitor::run_stream_with_outbound(&config, Some(&model), &mut sink, Some(rx))
                .await;
    });

    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
        stream.abort();
    });
    let client = ().serve(client_io).await.expect("client connects");
    (client, server_task)
}

#[tokio::test]
async fn read_group_sends_read_and_returns_value() {
    let (addr, gw) = bind_mock().await;
    let channel = 0x41u8;

    let gw_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        // CONNECT handshake.
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Expect the injected GroupValueRead; ACK, then respond with the value.
        loop {
            let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
            let parsed = knxnet::parse(&buf[..n]).unwrap();
            if parsed.service != ServiceType::TunnelingRequest {
                continue;
            }
            let tr = knxnet::parse_tunneling_request(parsed.body).unwrap();
            if tr.cemi.apdu != Apdu::GroupValueRead {
                // ACK anything else and keep going.
                let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                gw.send_to(&ack, peer).await.unwrap();
                continue;
            }
            let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
            gw.send_to(&ack, peer).await.unwrap();

            // Push a GroupValueResponse carrying alarm=1.
            let hdr = knxnet::ConnectionHeader {
                channel_id: channel,
                seq: 0,
            };
            let response = CemiFrame::group_response(ga("3/2/0"), ia("1.1.30"), &[1]);
            let ind = knxnet::tunneling_request(hdr, &response);
            gw.send_to(&ind, peer).await.unwrap();
            let _ = gw.recv_from(&mut buf).await; // client ACK
            break;
        }

        // Drain any later frames (disconnect) quietly.
        let _ = tokio::time::timeout(Duration::from_millis(200), gw.recv_from(&mut buf)).await;
    });

    let config = ConnectionConfig::tunnel(addr);
    let (state, rx) = state_for();
    let (client, server_task) = connect_client_over(state, config, rx).await;

    // Give the bus a moment to connect.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        client.call_tool(CallToolRequestParams::new("knx_read_group").with_arguments(args)),
    )
    .await
    .expect("read_group returns in time")
    .unwrap();

    let s = res.structured_content.expect("structured");
    assert_eq!(s["ga"], "3/2/0");
    assert_eq!(s["ok"], true, "response was {s:?}");
    assert_eq!(s["value"], "Alarm");
    assert_eq!(s["dpt"], "1.005");

    client.cancel().await.unwrap();
    server_task.abort();
    let _ = gw_task.await;
}

/// Issue #32: the gateway echoes our own request back as `L_Data.con` BEFORE
/// the device's response arrives. `knx_read_group` must skip the echo(es) and
/// return the real `L_Data.ind` GroupValueResponse.
#[tokio::test]
async fn read_group_skips_con_echo_and_returns_device_response() {
    use bussard_transport::cemi::MessageCode;

    let (addr, gw) = bind_mock().await;
    let channel = 0x45u8;

    let gw_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        // CONNECT handshake.
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Expect the injected GroupValueRead; ACK it, then push the echo(es)
        // BEFORE the device's response.
        loop {
            let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
            let parsed = knxnet::parse(&buf[..n]).unwrap();
            if parsed.service != ServiceType::TunnelingRequest {
                continue;
            }
            let tr = knxnet::parse_tunneling_request(parsed.body).unwrap();
            let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
            gw.send_to(&ack, peer).await.unwrap();
            if tr.cemi.apdu != Apdu::GroupValueRead {
                continue;
            }

            // 1. The realistic con echo: our own GroupValueRead back as
            //    L_Data.con (same GA, our source IA 0.0.255).
            let mut read_echo = CemiFrame::group_read(ga("3/2/0"), ia("0.0.255"));
            read_echo.message_code = MessageCode::LDataCon;
            // 2. An adversarial con that a GA-only wait WOULD match: a
            //    GroupValueWrite con carrying the WRONG value (No Alarm = 0).
            let mut write_echo = CemiFrame::group_write(ga("3/2/0"), ia("0.0.255"), &[0]);
            write_echo.message_code = MessageCode::LDataCon;
            // 3. The device's real answer: alarm = 1.
            let response = CemiFrame::group_response(ga("3/2/0"), ia("1.1.30"), &[1]);

            for (seq, frame) in [read_echo, write_echo, response].iter().enumerate() {
                let hdr = knxnet::ConnectionHeader {
                    channel_id: channel,
                    seq: seq as u8,
                };
                let ind = knxnet::tunneling_request(hdr, frame);
                gw.send_to(&ind, peer).await.unwrap();
                let _ = gw.recv_from(&mut buf).await; // client ACK
            }
            break;
        }

        // Drain any later frames (disconnect) quietly.
        let _ = tokio::time::timeout(Duration::from_millis(200), gw.recv_from(&mut buf)).await;
    });

    let config = ConnectionConfig::tunnel(addr);
    let (state, rx) = state_for();
    let (client, server_task) = connect_client_over(state, config, rx).await;

    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        client.call_tool(CallToolRequestParams::new("knx_read_group").with_arguments(args)),
    )
    .await
    .expect("read_group returns in time")
    .unwrap();

    let s = res.structured_content.expect("structured");
    assert_eq!(s["ga"], "3/2/0");
    assert_eq!(s["ok"], true, "response was {s:?}");
    assert_eq!(
        s["value"], "Alarm",
        "the DEVICE response (Alarm) must be returned, not the con echo: {s:?}"
    );
    assert_eq!(s["dpt"], "1.005");

    client.cancel().await.unwrap();
    server_task.abort();
    let _ = gw_task.await;
}

#[tokio::test]
async fn write_group_sends_write_and_confirms() {
    let (addr, gw) = bind_mock().await;
    let channel = 0x43u8;

    let gw_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        // CONNECT handshake.
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Expect the injected GroupValueWrite to 3/0/4 (down = 1); ACK it.
        loop {
            let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
            let parsed = knxnet::parse(&buf[..n]).unwrap();
            if parsed.service != ServiceType::TunnelingRequest {
                continue;
            }
            let tr = knxnet::parse_tunneling_request(parsed.body).unwrap();
            let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
            gw.send_to(&ack, peer).await.unwrap();
            if let Apdu::GroupValueWrite(_) = tr.cemi.apdu {
                assert_eq!(tr.cemi.group_destination(), Some(ga("3/0/4")));
                break;
            }
        }
        let _ = tokio::time::timeout(Duration::from_millis(200), gw.recv_from(&mut buf)).await;
    });

    let config = ConnectionConfig::tunnel(addr);
    let (state, rx) = state_for();
    let (client, server_task) = connect_client_over(state, config, rx).await;

    // Give the bus a moment to connect.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/0/4"));
    args.insert("value".to_string(), serde_json::json!("down"));
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        client.call_tool(CallToolRequestParams::new("knx_write_group").with_arguments(args)),
    )
    .await
    .expect("write_group returns in time")
    .unwrap();

    let s = res.structured_content.expect("structured");
    assert_eq!(s["ok"], true, "response was {s:?}");
    assert_eq!(s["written"]["address"], "3/0/4");
    assert_eq!(s["written"]["value"], "Down");
    assert_eq!(s["written"]["dpt"], "1.008");

    client.cancel().await.unwrap();
    server_task.abort();
    let _ = gw_task.await;
}

#[tokio::test]
async fn wait_for_telegram_returns_pushed_write() {
    let (addr, gw) = bind_mock().await;
    let channel = 0x42u8;

    let gw_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // After a short delay, push a write to 3/2/0 (the "button press").
        tokio::time::sleep(Duration::from_millis(200)).await;
        let hdr = knxnet::ConnectionHeader {
            channel_id: channel,
            seq: 0,
        };
        let write = CemiFrame::group_write(ga("3/2/0"), ia("1.1.30"), &[1]);
        let ind = knxnet::tunneling_request(hdr, &write);
        gw.send_to(&ind, peer).await.unwrap();
        let _ = gw.recv_from(&mut buf).await; // client ACK
        let _ = tokio::time::timeout(Duration::from_millis(200), gw.recv_from(&mut buf)).await;
    });

    let config = ConnectionConfig::tunnel(addr);
    let (state, rx) = state_for();
    let (client, server_task) = connect_client_over(state, config, rx).await;

    let mut args = serde_json::Map::new();
    args.insert("ga".to_string(), serde_json::json!("3/2/0"));
    args.insert("timeout_seconds".to_string(), serde_json::json!(5));
    let res = tokio::time::timeout(
        Duration::from_secs(6),
        client.call_tool(CallToolRequestParams::new("knx_wait_for_telegram").with_arguments(args)),
    )
    .await
    .expect("wait_for returns in time")
    .unwrap();

    let s = res.structured_content.expect("structured");
    assert_eq!(s["matched"], true, "result was {s:?}");
    assert_eq!(s["telegram"]["destination"], "3/2/0");

    client.cancel().await.unwrap();
    server_task.abort();
    let _ = gw_task.await;
}

/// A `serve_stdio` smoke wiring check (compiles + the fn is reachable). We do
/// not exercise stdio here since the other tests own the transport, but this
/// keeps the public entry point covered by a reference.
#[allow(dead_code)]
async fn _serve_stdio_is_public(
    state: Arc<SharedState>,
    config: ConnectionConfig,
    rx: Option<tokio::sync::mpsc::UnboundedReceiver<CemiFrame>>,
) {
    let _ = serve_stdio(state, config, rx).await;
}
