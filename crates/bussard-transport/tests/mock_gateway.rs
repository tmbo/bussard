//! Integration tests against an in-process mock KNXnet/IP gateway.
//!
//! The mock speaks just enough of the tunneling protocol over localhost UDP to
//! exercise the [`Tunnel`] state machine: the CONNECT handshake, heartbeat,
//! send + ACK, an ACK-timeout retransmit, a duplicate-sequence drop, and a
//! server-initiated disconnect. Each test scripts the gateway datagram by
//! datagram with [`RawGateway`] from `bussard-testkit`; the tests that only
//! need a well-behaved gateway use its [`MockGateway`].
//!
//! The multicast [`Router`] loopback test is gated behind the
//! `BUSSARD_TEST_MULTICAST` env var because multicast on loopback is flaky in
//! sandboxed CI.
//!
//! [`Tunnel`]: bussard_transport::Tunnel
//! [`Router`]: bussard_transport::Router

use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_testkit::wire::{
    connect_refusal_body, connect_response_body, description_response_body, hpai_matches,
};
use bussard_testkit::{MockGateway, RawGateway, TestResult, ga, group_dest, ia};
use bussard_transport::cemi::{Apdu, CemiFrame, GroupData};
use bussard_transport::knxnet::{self, ServiceType};
use bussard_transport::{
    BusConnection, ConnectionConfig, LinkState, Transport, TransportError, TunnelReconnect,
};

#[tokio::test]
async fn connect_send_ack_disconnect() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    // Gateway logic runs as a task.
    let gw_task = tokio::spawn(async move {
        // 1. Expect CONNECT_REQUEST. Reply CONNECT_RESPONSE: channel 7, status 0,
        // data HPAI = our addr, CRD tunnel IA 1.1.255.
        let peer = gw.accept_connect(0x07).await?;

        // 2. Expect a TUNNELING_REQUEST (the GroupValueWrite), seq 0. ACK it.
        let req = gw.expect(ServiceType::TunnelingRequest).await?;
        let tr = req.tunneling_request()?;
        assert_eq!(tr.header.seq, 0);
        assert_eq!(tr.cemi.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        gw.ack(req.peer, tr.header.channel_id, tr.header.seq, 0)
            .await?;

        // 3. Server pushes an indication (seq 0) to the client and expects an ACK.
        let ind = CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.10")?, &[0]);
        gw.push(peer, 0x07, 0, &ind).await?;
        // Expect the client's ACK for seq 0.
        let (ack_hdr, status) = gw
            .expect(ServiceType::TunnelingAck)
            .await?
            .tunneling_ack()?;
        assert_eq!(ack_hdr.seq, 0);
        assert_eq!(status, 0);

        // 4. Server initiates DISCONNECT_REQUEST; expect DISCONNECT_RESPONSE.
        let disc = knxnet::disconnect_request(0x07, knxnet::Hpai::wildcard());
        gw.send(&disc, peer).await?;
        gw.expect(ServiceType::DisconnectResponse).await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;

    // Send a GroupValueWrite; the mock ACKs.
    conn.send(CemiFrame::group_write_packed(
        ga("3/0/4")?,
        ia("1.1.255")?,
        &[1],
    ))
    .await?;

    // Receive the indication the server pushed.
    let stamped = conn.recv().await?;
    assert_eq!(group_dest(&stamped.frame)?, "1/2/3");

    // The server then disconnects; the next recv should surface a Disconnected error.
    let err = conn.recv().await;
    assert!(err.is_err(), "expected disconnect error, got {err:?}");

    gw_task.await??;
    Ok(())
}

#[tokio::test]
async fn retransmit_on_ack_timeout() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        // Handshake.
        gw.accept_connect(0x09).await?;

        // First TUNNELING_REQUEST arrives: deliberately DO NOT ACK, forcing the
        // client's 1 s timeout + retransmit.
        let tr1 = gw
            .expect(ServiceType::TunnelingRequest)
            .await?
            .tunneling_request()?;

        // The retransmit should carry the SAME sequence number.
        let second = gw.expect(ServiceType::TunnelingRequest).await?;
        let tr2 = second.tunneling_request()?;
        assert_eq!(tr1.header.seq, tr2.header.seq, "retransmit keeps seq");

        // ACK the retransmit.
        gw.ack(second.peer, tr2.header.channel_id, tr2.header.seq, 0)
            .await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;
    // This should succeed only after the retransmit is ACKed.
    conn.send(CemiFrame::group_write_packed(
        ga("3/0/4")?,
        ia("1.1.255")?,
        &[1],
    ))
    .await?;

    gw_task.await??;
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn duplicate_incoming_sequence_is_dropped() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let peer = gw.accept_connect(0x0A).await?;
        let src = ia("1.1.10")?;

        // Send indication seq 0.
        let f0 = CemiFrame::group_write_packed(ga("1/2/3")?, src, &[0]);
        gw.push(peer, 0x0A, 0, &f0).await?;
        gw.expect(ServiceType::TunnelingAck).await?; // client ACK seq 0

        // Re-send the SAME seq 0 (a duplicate). Client must ACK but not deliver.
        gw.push(peer, 0x0A, 0, &f0).await?;
        let (h, _st) = gw
            .expect(ServiceType::TunnelingAck)
            .await?
            .tunneling_ack()?;
        assert_eq!(h.seq, 0, "duplicate is ACKed with its own seq");

        // Now send a fresh seq 1 with a distinct GA to prove ordering resumed.
        let f1 = CemiFrame::group_write_packed(ga("4/5/6")?, src, &[1]);
        gw.push(peer, 0x0A, 1, &f1).await?;
        gw.expect(ServiceType::TunnelingAck).await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;

    // First delivered frame: 1/2/3.
    let first = conn.recv().await?;
    assert_eq!(group_dest(&first.frame)?, "1/2/3");

    // The duplicate must NOT be delivered; the next delivered frame is 4/5/6.
    let second = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("should receive the fresh frame")?;
    assert_eq!(group_dest(&second.frame)?, "4/5/6");

    gw_task.await??;
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn out_of_window_sequence_is_silently_discarded_without_ack() -> TestResult {
    // Issue #60 (C2): a TUNNELING_REQUEST whose sequence is out of window (neither
    // the expected seq nor the exact seq-1 duplicate) must be SILENTLY DISCARDED:
    // no ACK. ACKing a frame we then drop would wrongly tell the gateway we
    // accepted it.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let peer = gw.accept_connect(0x0A).await?;
        let src = ia("1.1.10")?;

        // Deliver seq 0 (expected) and collect its ACK: this fixes the window at
        // "expecting seq 1 next".
        let f0 = CemiFrame::group_write_packed(ga("1/2/3")?, src, &[0]);
        gw.push(peer, 0x0A, 0, &f0).await?;
        gw.expect(ServiceType::TunnelingAck).await?;

        // Now send a far-out-of-window seq 5. It must be silently dropped: NO ACK.
        let f5 = CemiFrame::group_write_packed(ga("4/5/6")?, src, &[1]);
        gw.push(peer, 0x0A, 5, &f5).await?;

        // No ACK should arrive for the out-of-window frame.
        let got = gw.recv_within(Duration::from_millis(400)).await?;
        assert!(
            got.is_none(),
            "out-of-window sequence must NOT be ACKed (got a datagram back)"
        );
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;

    // The expected frame is delivered.
    let first = conn.recv().await?;
    assert_eq!(group_dest(&first.frame)?, "1/2/3");
    // The out-of-window frame is never delivered.
    let dropped = tokio::time::timeout(Duration::from_millis(500), conn.recv()).await;
    assert!(
        dropped.is_err(),
        "out-of-window frame must not be delivered"
    );

    gw_task.await??;
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn retransmit_two_behind_is_acked_and_dropped_then_resyncs() -> TestResult {
    // Issue #58: a gateway retransmitting a frame *two* behind the expected
    // sequence (its ACK-timeout resend after several of our ACKs were lost) must
    // be ACKed-and-dropped, not silently discarded. The old one-frame window
    // dropped it silently, so the gateway kept retransmitting and the tunnel
    // desynced. After ACK-and-drop the next in-order frame is still delivered.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let peer = gw.accept_connect(0x0A).await?;
        let src = ia("1.1.10")?;
        let frame = |ga: GroupAddress, val: u8| CemiFrame::group_write_packed(ga, src, &[val]);

        // Deliver seq 0, 1, 2 in order (expected advances to 3), collecting ACKs.
        for (seq, g) in [(0u8, "1/2/3"), (1, "1/2/4"), (2, "1/2/5")] {
            gw.push(peer, 0x0A, seq, &frame(ga(g)?, seq)).await?;
            gw.expect(ServiceType::TunnelingAck).await?;
        }

        // Now retransmit seq 1, two behind the expected seq 3. It must be ACKed
        // (its own seq) and dropped, NOT silently discarded.
        gw.push(peer, 0x0A, 1, &frame(ga("1/2/4")?, 1)).await?;
        let ack = gw.recv().await?;
        assert_eq!(
            ack.service,
            ServiceType::TunnelingAck,
            "2-behind retransmit is ACKed"
        );
        let (h, _st) = ack.tunneling_ack()?;
        assert_eq!(h.seq, 1, "duplicate is ACKed with its own seq");

        // A fresh seq 3 proves the window never desynced.
        gw.push(peer, 0x0A, 3, &frame(ga("12/3/45")?, 3)).await?;
        gw.expect(ServiceType::TunnelingAck).await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;

    // The three in-order frames are delivered.
    for expect in ["1/2/3", "1/2/4", "1/2/5"] {
        let f = tokio::time::timeout(Duration::from_secs(2), conn.recv())
            .await
            .expect("in-order frame delivered")?;
        assert_eq!(group_dest(&f.frame)?, expect);
    }

    // The 2-behind retransmit is NOT re-delivered; the next delivered frame is the
    // fresh 12/3/45.
    let next = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("fresh frame after the retransmit")?;
    assert_eq!(group_dest(&next.frame)?, "12/3/45");

    gw_task.await??;
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn unknown_message_code_is_acked_then_ignored() -> TestResult {
    // Issue #60 (C3): a cEMI carrying an unknown message code cannot be decoded,
    // but the in-sequence frame must still be ACKed so the gateway advances (an
    // un-ACKed frame would be retransmitted forever and stall the tunnel). The
    // undecodable payload is simply not delivered.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let peer = gw.accept_connect(0x0A).await?;

        // Build a TUNNELING_REQUEST body by hand: connection header (len 4,
        // channel, seq 0, reserved) + a cEMI with an UNKNOWN message code 0xFF and
        // a minimal tail. `CemiFrame::decode` rejects the message code, so this is
        // the C3 path.
        let mut body = vec![0x04, 0x0A, 0x00, 0x00];
        body.extend_from_slice(&[0xFF, 0x00]); // unknown message code + AI length 0
        gw.send_frame(ServiceType::TunnelingRequest, &body, peer)
            .await?;

        // The client must still ACK seq 0 (so the gateway advances).
        let ack = gw.recv().await?;
        assert_eq!(
            ack.service,
            ServiceType::TunnelingAck,
            "unknown-code frame must be ACKed"
        );
        let (h, _st) = ack.tunneling_ack()?;
        assert_eq!(h.seq, 0);

        // Then a real in-sequence frame (seq 1) proves the window advanced.
        let f1 = CemiFrame::group_write_packed(ga("4/5/6")?, ia("1.1.10")?, &[1]);
        gw.push(peer, 0x0A, 1, &f1).await?;
        gw.expect(ServiceType::TunnelingAck).await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;

    // The undecodable frame is not delivered; the next delivered frame is 4/5/6,
    // proving the window advanced past the ACKed-but-ignored unknown frame.
    let delivered = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("the fresh in-sequence frame arrives")?;
    assert_eq!(group_dest(&delivered.frame)?, "4/5/6");

    gw_task.await??;
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn heartbeat_is_answered() -> TestResult {
    // We cannot wait the real 60 s heartbeat interval in a unit test, so this
    // test drives the heartbeat *handler* indirectly: it confirms the connection
    // stays alive through a normal send while the mock answers any
    // CONNECTIONSTATE_REQUEST it happens to see. It primarily guards that
    // connect + send + close all succeed without a heartbeat firing.
    let gw = MockGateway::builder()
        .channel(0x0B)
        .idle_timeout(Duration::from_secs(2))
        .start()
        .await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let mut conn = Transport::connect(&config).await?;
    conn.send(CemiFrame::group_write_packed(
        ga("3/0/4")?,
        ia("1.1.255")?,
        &[1],
    ))
    .await?;
    conn.close().await?;
    let _ = gw.finish(Duration::from_secs(3)).await;
    Ok(())
}

#[tokio::test]
async fn connect_rejected_status_is_error() -> TestResult {
    // Status 0x24 (no more connections).
    let gw = MockGateway::builder().refuse_connect(0x24).start().await?;
    let config = ConnectionConfig::tunnel(gw.addr());
    let result = Transport::connect(&config).await;
    assert!(result.is_err(), "rejected connect should error");
    Ok(())
}

#[tokio::test]
async fn dropping_tunnel_sends_disconnect_request() -> TestResult {
    // Issue #31: dropping a `Tunnel` (without calling close) must still tear the
    // connection down cleanly: the background task's command channel closes,
    // which runs `do_close` and sends a DISCONNECT_REQUEST, so the gateway slot
    // is released rather than leaked for its ~2-minute timeout.
    let gw = MockGateway::builder().channel(0x0C).start().await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let conn = Transport::connect(&config).await?;
    // Drop the connection without calling close(). The graceful DISCONNECT must
    // still be sent by the detached background task.
    drop(conn);

    let saw_disconnect = gw
        .wait_until(Duration::from_secs(5), |s| s.disconnects > 0)
        .await;
    assert!(
        saw_disconnect,
        "dropping a Tunnel must send a DISCONNECT_REQUEST (no slot leak)"
    );
    Ok(())
}

#[tokio::test]
async fn control_hpais_are_the_real_endpoint_everywhere() -> TestResult {
    // Interop finding (KNX Virtual): literal-minded gateways reply to the HPAI
    // they are given, so a wildcard 0.0.0.0:0 CONNECT never completes. All
    // control HPAIs (CONNECT, CONNECTIONSTATE, DISCONNECT) must consistently
    // carry the REAL local endpoint, which every gateway supports on
    // loopback/LAN/routed paths (classic mode).
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        // 1. CONNECT_REQUEST: assert its control HPAI (first HPAI in the body).
        let req = gw.expect(ServiceType::ConnectRequest).await?;
        assert!(
            hpai_matches(&req.body[0..8], req.peer),
            "CONNECT control HPAI must be the real local endpoint {}, got {:?}",
            req.peer,
            &req.body[0..8]
        );
        gw.send_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0D, gw.port()),
            req.peer,
        )
        .await?;

        // 2. The client calls close(): capture the DISCONNECT_REQUEST and assert
        // its control HPAI (body after channel_id + reserved) is the real one too.
        loop {
            let Some(dgram) = gw.recv_within(Duration::from_secs(5)).await? else {
                return TestResult::Ok(false);
            };
            match dgram.service {
                ServiceType::DisconnectRequest => {
                    // body: [channel_id, reserved, HPAI(8)]
                    assert!(
                        hpai_matches(&dgram.body[2..10], dgram.peer),
                        "DISCONNECT control HPAI must be the real local endpoint, got {:?}",
                        &dgram.body[2..10]
                    );
                    let resp = knxnet::disconnect_response(0x0D, 0);
                    let _ = gw.send(&resp, dgram.peer).await;
                    return Ok(true);
                }
                ServiceType::ConnectionstateRequest => {
                    // body: [channel_id, reserved, HPAI(8)]
                    assert!(
                        hpai_matches(&dgram.body[2..10], dgram.peer),
                        "CONNECTIONSTATE control HPAI must be the real local endpoint, got {:?}",
                        &dgram.body[2..10]
                    );
                    let resp = knxnet::connectionstate_response(0x0D, 0);
                    let _ = gw.send(&resp, dgram.peer).await;
                }
                _ => {}
            }
        }
    });

    let config = ConnectionConfig::tunnel(addr);
    let conn = Transport::connect(&config).await?;
    conn.close().await?;

    let saw_disconnect = tokio::time::timeout(Duration::from_secs(5), gw_task)
        .await
        .expect("gateway task should finish")??;
    assert!(saw_disconnect, "close() must send a DISCONNECT_REQUEST");
    Ok(())
}

// --- Optional multicast loopback test, gated behind an env var ---

#[tokio::test]
async fn routing_loopback() -> TestResult {
    if std::env::var("BUSSARD_TEST_MULTICAST").is_err() {
        eprintln!("skipping routing_loopback (set BUSSARD_TEST_MULTICAST=1 to enable)");
        return Ok(());
    }
    use bussard_transport::Router;
    let config = ConnectionConfig::routing();
    let mut a = Router::connect(&config).await?;
    let mut b = Router::connect(&config).await?;

    a.send(CemiFrame::group_write_packed(
        ga("7/0/1")?,
        ia("1.1.1")?,
        &[1],
    ))
    .await?;

    let stamped = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .expect("multicast frame should arrive")?;
    assert_eq!(group_dest(&stamped.frame)?, "7/0/1");
    Ok(())
}

// --- helpers ---

/// The group address burst frame `i` carries, distinct for every index so the
/// delivery order can be asserted.
fn burst_ga(i: usize) -> Result<GroupAddress, bussard_testkit::BoxError> {
    ga(&format!("1/{}/{}", i / 256, i % 256))
}

// --- Issue #82: inbound buffering must never block the tunnel task ---

#[tokio::test]
async fn inbound_burst_during_ack_wait_does_not_stall_the_tunnel() -> TestResult {
    // The tunnel task delivers inbound frames from inside `await_ack`, i.e. while
    // it still owes the caller the reply to an in-flight send. The caller (the bus
    // actor) cannot drain meanwhile, because it is awaiting that reply. While the
    // inbound channel was bounded at 256, a burst that filled it during one ACK
    // window left the task waiting for capacity that only the blocked caller could
    // free: a permanent deadlock.
    //
    // Here the gateway pushes BURST (> the old 256 bound) indications *before*
    // ACKing our request, and the test never calls `recv` until the send returns.
    // Every indication must still be ACKed (so the mock's per-frame ACK wait
    // completes) and the send must finish.
    const BURST: usize = 300;

    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        gw.accept_connect(0x1A).await?;

        // Our TUNNELING_REQUEST arrives. Hold its ACK back: the client stays
        // inside `await_ack` for the whole burst below.
        let req = gw.expect(ServiceType::TunnelingRequest).await?;
        let peer = req.peer;
        let ours = req.tunneling_request()?;

        // Burst: one indication at a time, each awaiting the client's ACK. A
        // client that stops ACKing (the deadlock) hangs this loop.
        let src = ia("1.1.10")?;
        for i in 0..BURST {
            let seq = i as u8;
            let ind = CemiFrame::group_write_packed(burst_ga(i)?, src, &[1]);
            gw.push(peer, 0x1A, seq, &ind).await?;
            let status = gw.await_client_ack(seq, Duration::from_secs(5)).await?;
            assert_eq!(status, 0);
        }

        // Only now ACK the client's own request.
        gw.ack(peer, ours.header.channel_id, ours.header.seq, 0)
            .await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;

    // The send must complete: with the old bounded channel the tunnel task was
    // blocked on delivery number 257 and this never returned.
    tokio::time::timeout(
        Duration::from_secs(10),
        conn.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[1],
        )),
    )
    .await
    .expect("send must not deadlock behind a full inbound channel")
    .expect("the gateway ACKed the request");

    tokio::time::timeout(Duration::from_secs(10), gw_task)
        .await
        .expect("the gateway must never stall waiting for an ACK")??;

    // Nothing was dropped or reordered: the whole burst is still queued, in order.
    for i in 0..BURST {
        let f = tokio::time::timeout(Duration::from_secs(2), conn.recv())
            .await
            .unwrap_or_else(|_| panic!("burst frame {i} must be delivered"))?;
        assert_eq!(
            group_dest(&f.frame)?,
            burst_ga(i)?.to_string(),
            "burst frames must arrive in order"
        );
    }

    let _ = conn.close().await;
    Ok(())
}

// --- Previously untested tunnel failure paths (protocol audit) ---

#[tokio::test]
async fn non_zero_tunneling_ack_status_fails_the_send() -> TestResult {
    // A TUNNELING_ACK carrying a non-zero status is a rejection, not a success:
    // it must surface as GatewayStatus rather than resolving the send, and must
    // not be retried (only a timeout is retried).
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        gw.accept_connect(0x1B).await?;

        let req = gw.expect(ServiceType::TunnelingRequest).await?;
        let tr = req.tunneling_request()?;
        // 0x29 = E_TUNNELING_LAYER (a plausible refusal).
        gw.ack(req.peer, tr.header.channel_id, tr.header.seq, 0x29)
            .await?;

        // The rejected request must NOT be retransmitted.
        if let Some(next) = gw.recv_within(Duration::from_secs(2)).await? {
            assert_ne!(
                next.service,
                ServiceType::TunnelingRequest,
                "a status-rejected request must not be retransmitted"
            );
        }
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        conn.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[1],
        )),
    )
    .await
    .expect("a rejected send must resolve promptly, not wait out the ACK timeout")
    .expect_err("non-zero ACK status must fail the send");
    assert!(
        matches!(
            err,
            TransportError::GatewayStatus {
                status: 0x29,
                context: "TUNNELING_ACK"
            }
        ),
        "expected a TUNNELING_ACK GatewayStatus, got {err:?}"
    );

    gw_task.await??;
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn disconnect_request_during_ack_wait_ends_the_send_and_the_stream() -> TestResult {
    // A server-initiated DISCONNECT_REQUEST can arrive while we are inside
    // `await_ack`. It must be answered with a DISCONNECT_RESPONSE, fail the
    // in-flight send with Disconnected, and surface the same error on the frame
    // stream - not sit there until the ACK timeout.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        gw.accept_connect(0x1C).await?;

        // Our request arrives; instead of ACKing it, disconnect.
        let req = gw.expect(ServiceType::TunnelingRequest).await?;
        let disc = knxnet::disconnect_request(0x1C, knxnet::Hpai::wildcard());
        gw.send(&disc, req.peer).await?;

        // The client must answer the disconnect even mid-await.
        let reply = gw
            .recv_within(Duration::from_secs(2))
            .await?
            .expect("a DISCONNECT_RESPONSE must follow promptly");
        assert_eq!(reply.service, ServiceType::DisconnectResponse);
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await?;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        conn.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[1],
        )),
    )
    .await
    .expect("a disconnect must end the ACK wait immediately")
    .expect_err("a disconnect during the ACK wait must fail the send");
    assert!(
        matches!(err, TransportError::Disconnected(0x1C)),
        "expected Disconnected, got {err:?}"
    );

    // The consumer learns about it too.
    let stream_err = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("the frame stream must report the disconnect")
        .expect_err("the frame stream must report the disconnect");
    assert!(
        matches!(stream_err, TransportError::Disconnected(0x1C)),
        "expected Disconnected on the stream, got {stream_err:?}"
    );

    gw_task.await??;
    Ok(())
}

#[tokio::test]
async fn heartbeat_lost_after_retries_is_surfaced_to_the_consumer() -> TestResult {
    // A gateway that stops answering CONNECTIONSTATE_REQUESTs (the cable-pull
    // drill) must be declared dead after HEARTBEAT_RETRIES attempts, and the
    // consumer must see HeartbeatLost rather than a silently wedged stream.
    //
    // The real schedule is 60 s + 3 x 10 s, so the clock is paused *after* the
    // handshake (pausing before it would auto-advance through the real round
    // trip) and the runtime auto-advances it while both sides idle. The raw
    // gateway's `recv` has no deadline of its own, so it does not race the
    // paused clock.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        gw.accept_connect(0x1D).await?;

        // Count the heartbeat attempts, answering none of them.
        let mut attempts = 0u32;
        while attempts < bussard_transport::config::HEARTBEAT_RETRIES {
            if gw.recv().await?.service == ServiceType::ConnectionstateRequest {
                attempts += 1;
            }
        }
        TestResult::Ok(attempts)
    });

    // Re-establishing is off here: this pins the bare heartbeat verdict. The
    // re-establish path after a heartbeat loss has its own test below.
    let config = ConnectionConfig::tunnel(addr).with_reconnect(TunnelReconnect::disabled());
    let mut conn = Transport::connect(&config).await?;

    // From here on nothing real is in flight: the mock never replies, so the
    // auto-advancing paused clock drives the whole heartbeat schedule.
    tokio::time::pause();
    let err = conn
        .recv()
        .await
        .expect_err("an unanswered heartbeat must end the stream");
    assert!(
        matches!(err, TransportError::HeartbeatLost),
        "expected HeartbeatLost, got {err:?}"
    );

    let attempts = gw_task.await??;
    assert_eq!(
        attempts,
        bussard_transport::config::HEARTBEAT_RETRIES,
        "every heartbeat retry must actually be sent"
    );
    Ok(())
}

// --- tunnelling capacity (issue #105) ---------------------------------------

#[tokio::test]
async fn description_response_reports_tunnel_slots() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let req = gw.expect(ServiceType::DescriptionRequest).await?;
        let body = description_response_body("Mock IP Interface", 4, 3);
        gw.send_frame(ServiceType::DescriptionResponse, &body, req.peer)
            .await?;
        TestResult::Ok(())
    });

    let description = bussard_transport::describe_gateway(addr, Duration::from_secs(2))
        .await
        .expect("the gateway describes itself");
    gw_task.await??;

    assert_eq!(description.name.as_deref(), Some("Mock IP Interface"));
    assert_eq!(description.individual_address, Some(0x1000));
    assert_eq!(description.max_apdu_length, Some(248));
    let slots = description.tunnel_slots.as_ref().expect("a tunnelling DIB");
    assert_eq!(slots.len(), 4);
    assert!(slots.iter().all(|s| s.usable && s.authorized));
    assert_eq!(slots.iter().filter(|s| s.free).count(), 1);
    assert_eq!(slots[0].individual_address, 0x10F1);

    let capacity = description.tunnel_capacity().expect("a capacity");
    assert_eq!(capacity.total, 4);
    assert_eq!(capacity.in_use, 3);
    Ok(())
}

#[tokio::test]
async fn description_without_tunnelling_dib_reports_no_capacity() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let req = gw.expect(ServiceType::DescriptionRequest).await?;
        // Only the device-info DIB: an older interface that never reports slots.
        let body = description_response_body("Legacy Interface", 0, 0);
        // Drop the (empty) tunnelling DIB the helper appended.
        gw.send_frame(ServiceType::DescriptionResponse, &body[..54], req.peer)
            .await?;
        TestResult::Ok(())
    });

    let description = bussard_transport::describe_gateway(addr, Duration::from_secs(2))
        .await
        .expect("the gateway describes itself");
    gw_task.await??;

    assert_eq!(description.name.as_deref(), Some("Legacy Interface"));
    assert!(description.tunnel_slots.is_none());
    assert!(
        description.tunnel_capacity().is_none(),
        "an interface that reports nothing must not be claimed to have zero tunnels"
    );
    Ok(())
}

#[tokio::test]
async fn connect_refused_with_no_more_connections() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let req = gw.expect(ServiceType::ConnectRequest).await?;
        // E_NO_MORE_CONNECTIONS: channel 0, status 0x24, no HPAI/CRD follows.
        gw.send_frame(
            ServiceType::ConnectResponse,
            &connect_refusal_body(0x24),
            req.peer,
        )
        .await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let err = Transport::connect(&config)
        .await
        .err()
        .expect("a full interface refuses the connect");
    gw_task.await??;

    assert!(
        matches!(err, TransportError::NoMoreConnections),
        "a 0x24 refusal must be its own variant, not a generic gateway status: {err:?}"
    );
    let text = err.to_string();
    assert!(text.contains("E_NO_MORE_CONNECTIONS"), "{text}");
    Ok(())
}

#[tokio::test]
async fn other_connect_status_stays_a_gateway_status() -> TestResult {
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        let req = gw.expect(ServiceType::ConnectRequest).await?;
        // E_CONNECTION_TYPE (0x22): a different refusal, not a capacity problem.
        gw.send_frame(
            ServiceType::ConnectResponse,
            &connect_refusal_body(0x22),
            req.peer,
        )
        .await?;
        TestResult::Ok(())
    });

    let config = ConnectionConfig::tunnel(addr);
    let err = Transport::connect(&config).await.err().expect("refused");
    gw_task.await??;

    assert!(
        matches!(err, TransportError::GatewayStatus { status: 0x22, .. }),
        "{err:?}"
    );
    Ok(())
}

// --- tunnel re-establish after a lost link (issue #177) ---------------------

/// A re-establish policy fast enough for tests: attempts every 100-200 ms,
/// each waiting 300 ms for the CONNECT_RESPONSE, within `budget`.
fn fast_reconnect(budget: Duration) -> TunnelReconnect {
    TunnelReconnect {
        budget,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(200),
        attempt_timeout: Duration::from_millis(300),
        ..TunnelReconnect::default()
    }
}

#[tokio::test]
async fn test_tunnel_reestablish_disconnects_reconnects_and_resends_pending_frame() -> TestResult {
    // The exact wire sequence of a re-establish: the pending frame goes
    // unacknowledged (sent + one retransmit), then DISCONNECT for the old
    // channel, CONNECT, and the pending frame again on the NEW channel with the
    // sequence counter reset to 0. The inbound counter resets too: the gateway's
    // first indication on the new channel may start at any sequence.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        gw.accept_connect(0x07).await?;

        // Frame 1 (seq 0) is ACKed normally.
        let first = gw.expect(ServiceType::TunnelingRequest).await?;
        let tr = first.tunneling_request()?;
        assert_eq!((tr.header.channel_id, tr.header.seq), (0x07, 0));
        gw.ack(first.peer, 0x07, 0, 0).await?;

        // Frame 2 (seq 1): the link "dies". Swallow it and its retransmit.
        let lost = gw
            .expect(ServiceType::TunnelingRequest)
            .await?
            .tunneling_request()?;
        assert_eq!((lost.header.channel_id, lost.header.seq), (0x07, 1));
        let retry = gw
            .expect(ServiceType::TunnelingRequest)
            .await?
            .tunneling_request()?;
        assert_eq!(retry.header.seq, 1, "the retransmit keeps its sequence");

        // The link is back: the client first releases the old channel ...
        let disc = gw.expect(ServiceType::DisconnectRequest).await?;
        assert_eq!(knxnet::parse_disconnect_request(&disc.body)?, 0x07);
        gw.send(&knxnet::disconnect_response(0x07, 0), disc.peer)
            .await?;
        // ... then opens a new one, which gets a different channel id.
        let peer = gw.accept_connect(0x08).await?;

        // The pending frame is re-sent on the new channel, sequence reset.
        let resent = gw.expect(ServiceType::TunnelingRequest).await?;
        let rtr = resent.tunneling_request()?;
        assert_eq!((rtr.header.channel_id, rtr.header.seq), (0x08, 0));
        assert_eq!(
            rtr.cemi, lost.cemi,
            "the pending frame is re-sent unchanged"
        );
        gw.ack(resent.peer, 0x08, 0, 0).await?;

        // The next frame continues the new channel's counter.
        let next = gw
            .expect(ServiceType::TunnelingRequest)
            .await?
            .tunneling_request()?;
        assert_eq!((next.header.channel_id, next.header.seq), (0x08, 1));
        gw.ack(peer, 0x08, 1, 0).await?;

        // An indication on the new channel starting at seq 5 is accepted.
        let ind = CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.10")?, &[1]);
        gw.push(peer, 0x08, 5, &ind).await?;
        let acked = gw.await_client_ack(5, Duration::from_secs(2)).await?;
        TestResult::Ok(acked)
    });

    let config =
        ConnectionConfig::tunnel(addr).with_reconnect(fast_reconnect(Duration::from_secs(10)));
    let mut conn = Transport::connect(&config).await?;
    let mut link = conn
        .link_state()
        .ok_or("a tunnel publishes its link state")?;
    assert!(matches!(*link.borrow_and_update(), LinkState::Up { .. }));

    let write = |v: u8| -> TestResult<CemiFrame> {
        Ok(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[v],
        ))
    };
    conn.send(write(0)?).await?;
    // This send rides out the loss: it returns once the re-sent frame is ACKed.
    conn.send(write(1)?).await?;
    // The link went through Reconnecting and is Up again.
    assert!(matches!(*link.borrow_and_update(), LinkState::Up { .. }));
    conn.send(write(0)?).await?;

    let stamped = tokio::time::timeout(Duration::from_secs(2), conn.recv()).await??;
    assert_eq!(group_dest(&stamped.frame)?, "1/2/3");

    let status = gw_task.await??;
    assert_eq!(
        status, 0,
        "the client ACKs the new channel's first indication"
    );
    Ok(())
}

#[tokio::test]
async fn test_tunnel_reestablish_rides_out_mock_gateway_outage() -> TestResult {
    // The testkit's outage fault: after frame 2 the gateway swallows everything
    // for 2.5 s, then grants a new channel. The pending send completes on it.
    let gw = MockGateway::builder()
        .outage(2, Duration::from_millis(2500))
        .idle_timeout(Duration::from_secs(20))
        .start()
        .await?;
    let config =
        ConnectionConfig::tunnel(gw.addr()).with_reconnect(fast_reconnect(Duration::from_secs(15)));
    let mut conn = Transport::connect(&config).await?;
    for v in [1u8, 0, 1, 0] {
        conn.send(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[v],
        ))
        .await?;
    }
    let stats = gw.stats();
    assert_eq!(
        stats.channels,
        vec![0x21, 0x22],
        "one re-established channel"
    );
    assert!(
        stats.outage_dropped >= 2,
        "the outage swallowed the retransmits"
    );
    let sent = gw.sent()?;
    assert_eq!(sent.len(), 4, "every frame served exactly once: {sent:?}");
    let _ = conn.close().await;
    Ok(())
}

#[tokio::test]
async fn test_tunnel_reestablish_after_heartbeat_loss() -> TestResult {
    // A heartbeat failure takes the same path: the gateway stops answering
    // CONNECTIONSTATE_REQUESTs, the tunnel reconnects instead of ending the
    // stream, and an indication on the new channel still arrives.
    //
    // As in the bare heartbeat test, the clock is paused after the handshake and
    // auto-advances through the 60 s + 3 x 10 s schedule. It resumes as soon as
    // the re-establish starts (the DISCONNECT for the old channel): a paused
    // clock auto-advances whenever the runtime is idle, even while a loopback
    // datagram is still in flight, so it could expire reconnect attempts before
    // the mock had a chance to answer them.
    //
    // The mock keeps its socket open until the client ACKs the indication. On
    // Linux a datagram to a closed port makes the client's next send or recv
    // fail with ECONNREFUSED; the test must not depend on that timing.
    let gw = RawGateway::bind().await?;
    let addr = gw.addr();

    let gw_task = tokio::spawn(async move {
        gw.accept_connect(0x1D).await?;
        let mut attempts = 0u32;
        while attempts < bussard_transport::config::HEARTBEAT_RETRIES {
            if gw.recv().await?.service == ServiceType::ConnectionstateRequest {
                attempts += 1;
            }
        }
        // Old channel released, new one granted.
        let disc = gw.expect(ServiceType::DisconnectRequest).await?;
        tokio::time::resume();
        gw.send(&knxnet::disconnect_response(0x1D, 0), disc.peer)
            .await?;
        let peer = gw.accept_connect(0x1E).await?;
        let ind = CemiFrame::group_write_packed(ga("1/2/3")?, ia("1.1.10")?, &[1]);
        gw.push(peer, 0x1E, 0, &ind).await?;
        let acked = gw.await_client_ack(0, Duration::from_secs(5)).await?;
        TestResult::Ok(acked)
    });

    let config =
        ConnectionConfig::tunnel(addr).with_reconnect(fast_reconnect(Duration::from_secs(10)));
    let mut conn = Transport::connect(&config).await?;
    tokio::time::pause();
    let received = conn.recv().await;
    // A failure on either side names both: the mock's error explains a client
    // error (it stopped answering), not the other way round.
    let status = match (received, gw_task.await?) {
        (Ok(stamped), Ok(status)) => {
            assert_eq!(group_dest(&stamped.frame)?, "1/2/3");
            status
        }
        (client, mock) => {
            return Err(format!("client: {:?}; mock gateway: {mock:?}", client.map(|_| ())).into());
        }
    };
    assert_eq!(status, 0, "the client ACKs the new channel's indication");
    Ok(())
}

#[tokio::test]
async fn test_tunnel_lost_after_budget_names_the_gateway() -> TestResult {
    // The link never comes back: after the budget the pending send fails with
    // TunnelLost, carrying the original ACK timeout and the gateway address.
    let gw = MockGateway::builder()
        .outage(1, Duration::MAX)
        .idle_timeout(Duration::from_secs(20))
        .start()
        .await?;
    let config = ConnectionConfig::tunnel(gw.addr())
        .with_reconnect(fast_reconnect(Duration::from_millis(1500)));
    let mut conn = Transport::connect(&config).await?;
    let frame = || -> TestResult<CemiFrame> {
        Ok(CemiFrame::group_write_packed(
            ga("3/0/4")?,
            ia("1.1.255")?,
            &[1],
        ))
    };
    conn.send(frame()?).await?;
    let started = std::time::Instant::now();
    let err = conn
        .send(frame()?)
        .await
        .expect_err("a link that never returns must fail the send");
    let elapsed = started.elapsed();
    match &err {
        TransportError::TunnelLost { gateway, cause, .. } => {
            assert_eq!(*gateway, gw.addr());
            assert!(matches!(**cause, TransportError::Timeout("TUNNELING_ACK")));
        }
        other => return Err(format!("expected TunnelLost, got {other:?}").into()),
    }
    let text = err.to_string();
    assert!(
        text.contains("timed out waiting for TUNNELING_ACK"),
        "{text}"
    );
    assert!(text.contains(&gw.addr().to_string()), "{text}");
    // ~2 s ACK budget + 1.5 s re-establish budget, bounded.
    assert!(
        elapsed < Duration::from_secs(6),
        "gave up after {elapsed:?}"
    );
    let connect_requests = gw
        .stats()
        .services
        .iter()
        .filter(|s| **s == ServiceType::ConnectRequest)
        .count();
    assert!(connect_requests >= 2, "re-establish attempts were made");
    Ok(())
}
