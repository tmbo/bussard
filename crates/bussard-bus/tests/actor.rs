//! Actor tests for `bussard-bus` against the `bussard-testkit` mock KNXnet/IP
//! gateway (loopback only).
//!
//! The mock drives the actor through a CONNECT handshake, ACKs (or deliberately
//! never ACKs) tunneling requests, pushes indications that must fan out to every
//! subscriber, and answers a clean DISCONNECT. These cover
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
use bussard_testkit::{AckPolicy, MockGateway, TestResult, ga, group_dest, ia};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::{ConnectionConfig, TransportKind};

/// The tunnel channel id every mock gateway in this file grants.
const CHANNEL: u8 = 0x21;

/// How long a test waits for the mock gateway to end after the client closes.
const FINISH: Duration = Duration::from_secs(2);

/// Starts a mock gateway that ACKs (or never ACKs) tunneling requests and
/// answers heartbeats and DISCONNECT.
async fn start_mock(policy: AckPolicy) -> TestResult<MockGateway> {
    Ok(MockGateway::builder()
        .channel(CHANNEL)
        .ack_policy(policy)
        .start()
        .await?)
}

#[tokio::test]
async fn two_subscribers_both_receive_frames_during_a_lease() -> TestResult {
    // Push an indication shortly after connect, independent of client requests.
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .push_after_connect(
            Duration::from_millis(50),
            CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.10")?, &[1]),
        )
        .start()
        .await?;

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(gw.addr()));

    // Hold a lease (an L4 session in flight): group subscriptions must still see
    // frames, which the old single-consumer recv destroyed.
    let lease = handle.lease().await?;
    let mut sub_a = handle.subscribe();
    let mut sub_b = lease.subscribe();

    let a = tokio::time::timeout(Duration::from_secs(3), sub_a.recv()).await?;
    let b = tokio::time::timeout(Duration::from_secs(3), sub_b.recv()).await?;
    let a = a.ok_or("subscriber A must receive the frame")?;
    let b = b.ok_or("subscriber B must receive the frame during the lease")?;
    assert_eq!(group_dest(&a.frame.frame)?, "1/2/3");
    assert_eq!(group_dest(&b.frame.frame)?, "1/2/3");

    drop(lease);
    let _ = handle.close().await;
    let _ = gw.finish(FINISH).await;
    Ok(())
}

#[tokio::test]
async fn wait_connected_resolves_on_connect() -> TestResult {
    // Event-driven `wait_connected`: it must return `true` once the actor
    // reaches Connected, driven by the watch signal rather than a poll.
    let gw = start_mock(AckPolicy::Ack).await?;

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(gw.addr()));
    let connected = handle.wait_connected(Duration::from_secs(3)).await;
    assert!(connected, "wait_connected returns true once connected");
    assert_eq!(handle.status(), BusState::Connected);

    let _ = handle.close().await;
    let _ = gw.finish(FINISH).await;
    Ok(())
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
async fn state_changes_observes_connecting_to_connected() -> TestResult {
    // The public `state_changes` watch must surface every transition. A fresh
    // receiver holds the current state (Connecting at startup); once the mock
    // completes the handshake it must observe Connected.
    let gw = start_mock(AckPolicy::Ack).await?;

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(gw.addr()));
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
    .map_err(|_| "state_changes did not reach Connected in time")?;
    assert!(
        connected,
        "state_changes must observe Connecting -> Connected"
    );
    assert_eq!(handle.status(), BusState::Connected);

    let _ = handle.close().await;
    let _ = gw.finish(FINISH).await;
    Ok(())
}

#[tokio::test]
async fn send_receipt_resolves_on_ack() -> TestResult {
    let gw = start_mock(AckPolicy::Ack).await?;

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(gw.addr()));
    // Wait for the actor to connect.
    wait_connected(&handle).await?;

    let receipt = tokio::time::timeout(
        Duration::from_secs(3),
        handle.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[1],
        )),
    )
    .await
    .map_err(|_| "send did not return in time")?;
    assert!(
        receipt.is_ok(),
        "an ACKed send yields a receipt: {receipt:?}"
    );

    let _ = handle.close().await;
    let _ = gw.finish(FINISH).await;
    Ok(())
}

#[tokio::test]
async fn send_errors_on_ack_exhaustion() -> TestResult {
    // Never ACK: the tunnel retransmits then errors; the actor surfaces that.
    let gw = start_mock(AckPolicy::Never).await?;

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(gw.addr()));
    wait_connected(&handle).await?;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        handle.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[1],
        )),
    )
    .await
    .map_err(|_| "send did not return after ACK exhaustion")?;
    assert!(
        matches!(result, Err(BusError::Transport(_))),
        "ACK exhaustion must surface as a transport error, got {result:?}"
    );

    let _ = handle.close().await;
    let _ = gw.finish(FINISH).await;
    Ok(())
}

#[tokio::test]
async fn staleness_cutoff_drops_queued_frame_while_reconnecting() -> TestResult {
    // No gateway at all: the actor never connects, so a send is queued while
    // reconnecting and must be dropped stale after the cutoff.
    let unreachable = "127.0.0.1:9".parse::<SocketAddrV4>()?;
    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(unreachable));

    // The actor is Connecting/Reconnecting (never Connected).
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        handle.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("0.0.255")?,
            &[1],
        )),
    )
    .await
    .map_err(|_| "send did not resolve within the staleness window")?;
    assert!(
        matches!(result, Err(BusError::Stale)),
        "a frame queued while reconnecting must be dropped stale, got {result:?}"
    );

    let _ = handle.close().await;
    Ok(())
}

#[tokio::test]
async fn lease_is_exclusive_second_waits() -> TestResult {
    let gw = start_mock(AckPolicy::Ack).await?;

    let (handle, _task) = Bus::connect(ConnectionConfig::tunnel(gw.addr()));

    let lease1 = handle.lease().await?;

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
    let _ = gw.finish(FINISH).await;
    Ok(())
}

#[tokio::test]
async fn close_during_reconnect_opens_no_fresh_tunnel() -> TestResult {
    // Unreachable gateway: the actor is stuck reconnecting. close() must stop it
    // without opening a tunnel (there is nothing to disconnect).
    let unreachable = "127.0.0.1:9".parse::<SocketAddrV4>()?;
    let (handle, task) = Bus::connect(ConnectionConfig::tunnel(unreachable));

    // Give the actor a moment to enter its reconnect/backoff.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_ne!(handle.status(), BusState::Connected);

    // close() returns promptly and the actor task ends.
    tokio::time::timeout(Duration::from_secs(2), handle.close())
        .await
        .map_err(|_| "close did not return promptly during reconnect")??;
    let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
    assert!(
        ended.is_ok(),
        "the actor task ends after close during reconnect"
    );
    assert_eq!(handle.status(), BusState::Closed);
    Ok(())
}

/// Waits until the handle reports [`BusState::Connected`], up to ~3s.
async fn wait_connected(handle: &bussard_bus::BusHandle) -> TestResult {
    for _ in 0..300 {
        if handle.status() == BusState::Connected {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("actor never connected".into())
}

/// A compile-time reference that the routing transport kind is accepted too.
#[allow(dead_code)]
fn _routing_config() -> ConnectionConfig {
    let mut c = ConnectionConfig::routing();
    c.transport = TransportKind::Routing;
    c
}
