//! Actor tests for `bussard-bus` against an in-process mock KNXnet/IP gateway.
//!
//! The mock speaks just enough tunneling to drive the actor: CONNECT handshake,
//! ACKing (or deliberately not ACKing) tunneling requests, pushing indications
//! that must fan out to every subscriber, and a clean DISCONNECT. These cover
//! the guarantees the phase-2 seam rests on:
//!
//! - two subscribers both receive frames while an L4 lease is active,
//! - a send receipt resolves on ACK and errors on ACK exhaustion,
//! - the staleness cutoff drops a frame queued while reconnecting,
//! - lease exclusivity (a second lease waits for the first),
//! - close during reconnect does not open a fresh tunnel.

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_bus::{Bus, BusError, BusState};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::knxnet::{self, ConnectionHeader, ServiceType};
use bussard_transport::{ConnectionConfig, TransportKind};
use tokio::net::UdpSocket;

const CHANNEL: u8 = 0x21;

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

/// A CONNECT_RESPONSE granting `channel` and assigning tunnel IA 1.1.255.
fn connect_response_body(channel: u8, gw: &UdpSocket) -> Vec<u8> {
    let mut body = vec![channel, 0x00];
    body.push(0x08);
    body.push(0x01);
    body.extend_from_slice(&[127, 0, 0, 1]);
    body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
    body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
    body
}

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}

/// How the mock reacts to a tunneling request from the client.
#[derive(Clone, Copy, PartialEq)]
enum AckPolicy {
    /// ACK every request (normal gateway).
    Ack,
    /// Never ACK (forces the client's ACK-timeout + retransmit to exhaust).
    NeverAck,
}

/// Runs a mock gateway: handshake, then per policy ACK requests, optionally push
/// one indication after the first request is seen, and answer a DISCONNECT.
async fn run_mock(
    gw: UdpSocket,
    policy: AckPolicy,
    push_indication: Option<(GroupAddress, IndividualAddress)>,
) {
    let mut buf = [0u8; 1024];
    let mut pushed = false;
    let mut gw_seq: u8 = 0;
    loop {
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(10), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let parsed = match knxnet::parse(&buf[..n]) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, &gw),
                );
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::ConnectionstateRequest => {
                let resp = knxnet::connectionstate_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
            }
            ServiceType::DisconnectRequest => {
                let resp = knxnet::disconnect_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
                return;
            }
            ServiceType::TunnelingRequest => {
                let tr = match knxnet::parse_tunneling_request(parsed.body) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if policy == AckPolicy::Ack {
                    let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                    gw.send_to(&ack, from).await.unwrap();
                }
                // After the first client request, optionally push one indication.
                if !pushed {
                    if let Some((g, src)) = push_indication {
                        let hdr = ConnectionHeader {
                            channel_id: CHANNEL,
                            seq: gw_seq,
                        };
                        let ind = knxnet::tunneling_request(
                            hdr,
                            &CemiFrame::group_write_packed(g, src, &[1]),
                        );
                        gw.send_to(&ind, from).await.unwrap();
                        gw_seq = gw_seq.wrapping_add(1);
                        pushed = true;
                    }
                }
            }
            ServiceType::TunnelingAck => {}
            _ => {}
        }
    }
}

/// Pushes an indication from the mock, independent of client requests, once a
/// peer is known. Used by the multi-subscriber test.
async fn run_mock_push_after_connect(gw: UdpSocket, g: GroupAddress, src: IndividualAddress) {
    let mut buf = [0u8; 1024];
    let mut gw_seq: u8 = 0;
    loop {
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(10), gw.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return,
            };
        let parsed = match knxnet::parse(&buf[..n]) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match parsed.service {
            ServiceType::ConnectRequest => {
                let resp = knxnet_frame(
                    ServiceType::ConnectResponse,
                    &connect_response_body(CHANNEL, &gw),
                );
                gw.send_to(&resp, from).await.unwrap();
                // Push an indication shortly after connect.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let hdr = ConnectionHeader {
                    channel_id: CHANNEL,
                    seq: gw_seq,
                };
                let ind =
                    knxnet::tunneling_request(hdr, &CemiFrame::group_write_packed(g, src, &[1]));
                gw.send_to(&ind, from).await.unwrap();
                gw_seq = gw_seq.wrapping_add(1);
            }
            ServiceType::DisconnectRequest => {
                let resp = knxnet::disconnect_response(CHANNEL, 0);
                gw.send_to(&resp, from).await.unwrap();
                return;
            }
            ServiceType::TunnelingRequest => {
                let tr = knxnet::parse_tunneling_request(parsed.body).unwrap();
                let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                gw.send_to(&ack, from).await.unwrap();
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn two_subscribers_both_receive_frames_during_a_lease() {
    let (addr, gw) = bind_mock().await;
    let gw_task = tokio::spawn(run_mock_push_after_connect(gw, ga("1/2/3"), ia("1.1.10")));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));

    // Hold a lease (an L4 session in flight) — group subscriptions must still see
    // frames, which the old single-consumer recv destroyed.
    let lease = handle.lease().await.unwrap();
    let mut sub_a = handle.subscribe();
    let mut sub_b = lease.subscribe();

    let a = tokio::time::timeout(Duration::from_secs(3), sub_a.recv())
        .await
        .unwrap();
    let b = tokio::time::timeout(Duration::from_secs(3), sub_b.recv())
        .await
        .unwrap();
    assert!(a.is_some(), "subscriber A must receive the frame");
    assert!(
        b.is_some(),
        "subscriber B must receive the frame during the lease"
    );
    assert_eq!(
        a.unwrap()
            .frame
            .frame
            .group_destination()
            .unwrap()
            .to_string(),
        "1/2/3"
    );
    assert_eq!(
        b.unwrap()
            .frame
            .frame
            .group_destination()
            .unwrap()
            .to_string(),
        "1/2/3"
    );

    drop(lease);
    let _ = handle.close().await;
    let _ = gw_task.await;
}

#[tokio::test]
async fn wait_connected_resolves_on_connect() {
    // Event-driven `wait_connected`: it must return `true` once the actor
    // reaches Connected, driven by the watch signal rather than a poll.
    let (addr, gw) = bind_mock().await;
    let gw_task = tokio::spawn(run_mock(gw, AckPolicy::Ack, None));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    let connected = handle.wait_connected(Duration::from_secs(3)).await;
    assert!(connected, "wait_connected returns true once connected");
    assert_eq!(handle.status(), BusState::Connected);

    let _ = handle.close().await;
    let _ = gw_task.await;
}

#[tokio::test(start_paused = true)]
async fn wait_connected_times_out_without_gateway() {
    // No gateway is bound at this address, so the actor never connects. With the
    // clock paused, the deadline elapses in virtual time: the wait returns
    // `false` (and would hang forever if it were not deadline-bounded).
    let addr = SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1);
    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    let connected = handle.wait_connected(Duration::from_millis(50)).await;
    assert!(!connected, "wait_connected times out when never connected");
}

#[tokio::test]
async fn state_changes_observes_connecting_to_connected() {
    // The public `state_changes` watch must surface every transition. A fresh
    // receiver holds the current state (Connecting at startup); once the mock
    // completes the handshake it must observe Connected.
    let (addr, gw) = bind_mock().await;
    let gw_task = tokio::spawn(run_mock(gw, AckPolicy::Ack, None));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    let mut states = handle.state_changes();

    // The initial value is Connecting (the actor has not connected yet).
    assert_eq!(*states.borrow_and_update(), BusState::Connecting);

    // Drive the watch until it reports Connected, bounded so a hang fails fast.
    let connected = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if *states.borrow_and_update() == BusState::Connected {
                return true;
            }
            if states.changed().await.is_err() {
                return false; // actor gone
            }
        }
    })
    .await
    .expect("state_changes reaches Connected in time");
    assert!(
        connected,
        "state_changes must observe Connecting -> Connected"
    );
    assert_eq!(handle.status(), BusState::Connected);

    let _ = handle.close().await;
    let _ = gw_task.await;
}

#[tokio::test]
async fn send_receipt_resolves_on_ack() {
    let (addr, gw) = bind_mock().await;
    let gw_task = tokio::spawn(run_mock(gw, AckPolicy::Ack, None));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    // Wait for the actor to connect.
    wait_connected(&handle).await;

    let receipt = tokio::time::timeout(
        Duration::from_secs(3),
        handle.send(CemiFrame::group_write_packed(
            ga("3/0/4"),
            ia("1.1.255"),
            &[1],
        )),
    )
    .await
    .expect("send returns in time");
    assert!(
        receipt.is_ok(),
        "an ACKed send yields a receipt: {receipt:?}"
    );

    let _ = handle.close().await;
    let _ = gw_task.await;
}

#[tokio::test]
async fn send_errors_on_ack_exhaustion() {
    let (addr, gw) = bind_mock().await;
    // NeverAck: the tunnel retransmits then errors; the actor surfaces that.
    let gw_task = tokio::spawn(run_mock(gw, AckPolicy::NeverAck, None));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));
    wait_connected(&handle).await;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        handle.send(CemiFrame::group_write_packed(
            ga("3/0/4"),
            ia("1.1.255"),
            &[1],
        )),
    )
    .await
    .expect("send returns after ACK exhaustion");
    assert!(
        matches!(result, Err(BusError::Transport(_))),
        "ACK exhaustion must surface as a transport error, got {result:?}"
    );

    let _ = handle.close().await;
    let _ = gw_task.await;
}

#[tokio::test]
async fn staleness_cutoff_drops_queued_frame_while_reconnecting() {
    // No gateway at all: the actor never connects, so a send is queued while
    // reconnecting and must be dropped stale after the cutoff.
    let unreachable = "127.0.0.1:9".parse::<SocketAddrV4>().unwrap();
    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(unreachable));

    // The actor is Connecting/Reconnecting (never Connected).
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        handle.send(CemiFrame::group_write_packed(
            ga("3/0/4"),
            ia("0.0.255"),
            &[1],
        )),
    )
    .await
    .expect("send resolves within the staleness window");
    assert!(
        matches!(result, Err(BusError::Stale)),
        "a frame queued while reconnecting must be dropped stale, got {result:?}"
    );

    let _ = handle.close().await;
}

#[tokio::test]
async fn lease_is_exclusive_second_waits() {
    let (addr, gw) = bind_mock().await;
    let gw_task = tokio::spawn(run_mock(gw, AckPolicy::Ack, None));

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(addr));

    let lease1 = handle.lease().await.unwrap();

    // A second lease must not be grantable while the first is held.
    let h2 = handle.clone();
    let second = tokio::spawn(async move { h2.lease().await.map(|_| ()) });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !second.is_finished(),
        "the second lease must wait for the first"
    );

    // Dropping the first lets the second acquire.
    drop(lease1);
    let got = tokio::time::timeout(Duration::from_secs(2), second).await;
    assert!(
        got.is_ok(),
        "the second lease acquires once the first is dropped"
    );

    let _ = handle.close().await;
    let _ = gw_task.await;
}

#[tokio::test]
async fn close_during_reconnect_opens_no_fresh_tunnel() {
    // Unreachable gateway: the actor is stuck reconnecting. close() must stop it
    // without opening a tunnel (there is nothing to disconnect).
    let unreachable = "127.0.0.1:9".parse::<SocketAddrV4>().unwrap();
    let (handle, task) = Bus::connect(ConnectionConfig::tunnel(unreachable));

    // Give the actor a moment to enter its reconnect/backoff.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_ne!(handle.status(), BusState::Connected);

    // close() returns promptly and the actor task ends.
    tokio::time::timeout(Duration::from_secs(2), handle.close())
        .await
        .expect("close returns promptly during reconnect")
        .unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
    assert!(
        ended.is_ok(),
        "the actor task ends after close during reconnect"
    );
    assert_eq!(handle.status(), BusState::Closed);
}

/// Waits until the handle reports [`BusState::Connected`], up to ~3s.
async fn wait_connected(handle: &bussard_bus::BusHandle) {
    for _ in 0..300 {
        if handle.status() == BusState::Connected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("actor never connected");
}

/// A compile-time reference that the routing transport kind is accepted too.
#[allow(dead_code)]
fn _routing_config() -> ConnectionConfig {
    let mut c = ConnectionConfig::routing();
    c.transport = TransportKind::Routing;
    c
}
