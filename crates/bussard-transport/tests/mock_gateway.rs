//! Integration tests against an in-process mock KNXnet/IP gateway.
//!
//! The mock speaks just enough of the tunneling protocol over localhost UDP to
//! exercise the [`Tunnel`] state machine: the CONNECT handshake, heartbeat,
//! send + ACK, an ACK-timeout retransmit, a duplicate-sequence drop, and a
//! server-initiated disconnect.
//!
//! The multicast [`Router`] loopback test is gated behind the
//! `BUSSARD_TEST_MULTICAST` env var because multicast on loopback is flaky in
//! sandboxed CI.

use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::net::UdpSocket;

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, GroupData};
use bussard_transport::knxnet::{self, ServiceType};
use bussard_transport::{BusConnection, ConnectionConfig, Transport};

/// Spawns a mock gateway bound to an ephemeral localhost port and returns its
/// address plus a handle to drive it.
async fn bind_mock() -> (SocketAddrV4, UdpSocket) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = match sock.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected v4"),
    };
    (addr, sock)
}

/// Reads one datagram and returns (peer, parsed service, body bytes).
async fn recv_frame(sock: &UdpSocket) -> (std::net::SocketAddr, ServiceType, Vec<u8>) {
    let mut buf = [0u8; 1024];
    let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
    let parsed = knxnet::parse(&buf[..n]).unwrap();
    (peer, parsed.service, parsed.body.to_vec())
}

#[tokio::test]
async fn connect_send_ack_disconnect() {
    let (addr, gw) = bind_mock().await;

    // Gateway logic runs as a task.
    let gw_task = tokio::spawn(async move {
        // 1. Expect CONNECT_REQUEST.
        let (peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::ConnectRequest);
        // Reply CONNECT_RESPONSE: channel 7, status 0, data HPAI = our addr,
        // CRD tunnel IA 1.1.255.
        let mut body = vec![0x07u8, 0x00];
        // data HPAI
        body.push(0x08);
        body.push(0x01);
        body.extend_from_slice(&[127, 0, 0, 1]);
        body.extend_from_slice(&gw.local_addr().unwrap().port().to_be_bytes());
        // CRD
        body.extend_from_slice(&[0x04, 0x04, 0x11, 0xFF]);
        let resp = knxnet_frame(ServiceType::ConnectResponse, &body);
        gw.send_to(&resp, peer).await.unwrap();

        // 2. Expect a TUNNELING_REQUEST (the GroupValueWrite), seq 0. ACK it.
        let (peer, service, body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::TunnelingRequest);
        let tr = knxnet::parse_tunneling_request(&body).unwrap();
        assert_eq!(tr.header.seq, 0);
        assert_eq!(tr.cemi.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
        gw.send_to(&ack, peer).await.unwrap();

        // 3. Server pushes an indication (seq 0) to the client and expects an ACK.
        let ga: GroupAddress = "1/2/3".parse().unwrap();
        let ia: IndividualAddress = "1.1.10".parse().unwrap();
        let ind = CemiFrame::group_write_packed(ga, ia, &[0]);
        let hdr = knxnet::ConnectionHeader {
            channel_id: 0x07,
            seq: 0,
        };
        let ind_frame = knxnet::tunneling_request(hdr, &ind);
        gw.send_to(&ind_frame, peer).await.unwrap();
        // Expect the client's ACK for seq 0.
        let (_peer, service, body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::TunnelingAck);
        let (ack_hdr, status) = knxnet::parse_tunneling_ack(&body).unwrap();
        assert_eq!(ack_hdr.seq, 0);
        assert_eq!(status, 0);

        // 4. Server initiates DISCONNECT_REQUEST; expect DISCONNECT_RESPONSE.
        let disc = knxnet::disconnect_request(0x07, knxnet::Hpai::wildcard());
        gw.send_to(&disc, peer).await.unwrap();
        let (_peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::DisconnectResponse);
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    // Send a GroupValueWrite; the mock ACKs.
    let ga: GroupAddress = "3/0/4".parse().unwrap();
    let ia: IndividualAddress = "1.1.255".parse().unwrap();
    conn.send(CemiFrame::group_write_packed(ga, ia, &[1]))
        .await
        .unwrap();

    // Receive the indication the server pushed.
    let stamped = conn.recv().await.unwrap();
    assert_eq!(
        stamped.frame.group_destination().unwrap().to_string(),
        "1/2/3"
    );

    // The server then disconnects; the next recv should surface a Disconnected error.
    let err = conn.recv().await;
    assert!(err.is_err(), "expected disconnect error, got {err:?}");

    gw_task.await.unwrap();
}

#[tokio::test]
async fn retransmit_on_ack_timeout() {
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        // Handshake.
        let (peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x09, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // First TUNNELING_REQUEST arrives — deliberately DO NOT ACK, forcing the
        // client's 1 s timeout + retransmit.
        let (peer, service, body1) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::TunnelingRequest);
        let tr1 = knxnet::parse_tunneling_request(&body1).unwrap();

        // The retransmit should carry the SAME sequence number.
        let (peer2, service2, body2) = recv_frame(&gw).await;
        assert_eq!(service2, ServiceType::TunnelingRequest);
        let tr2 = knxnet::parse_tunneling_request(&body2).unwrap();
        assert_eq!(tr1.header.seq, tr2.header.seq, "retransmit keeps seq");

        // ACK the retransmit.
        let ack = knxnet::tunneling_ack(tr2.header.channel_id, tr2.header.seq, 0);
        gw.send_to(&ack, peer2).await.unwrap();
        let _ = peer;
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();
    let ga: GroupAddress = "3/0/4".parse().unwrap();
    let ia: IndividualAddress = "1.1.255".parse().unwrap();
    // This should succeed only after the retransmit is ACKed.
    conn.send(CemiFrame::group_write_packed(ga, ia, &[1]))
        .await
        .unwrap();

    gw_task.await.unwrap();
    let _ = conn.close().await;
}

#[tokio::test]
async fn duplicate_incoming_sequence_is_dropped() {
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0A, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        let ga: GroupAddress = "1/2/3".parse().unwrap();
        let ia: IndividualAddress = "1.1.10".parse().unwrap();

        // Send indication seq 0.
        let f0 = knxnet::tunneling_request(
            knxnet::ConnectionHeader {
                channel_id: 0x0A,
                seq: 0,
            },
            &CemiFrame::group_write_packed(ga, ia, &[0]),
        );
        gw.send_to(&f0, peer).await.unwrap();
        let (_p, s, _b) = recv_frame(&gw).await; // client ACK seq 0
        assert_eq!(s, ServiceType::TunnelingAck);

        // Re-send the SAME seq 0 (a duplicate). Client must ACK but not deliver.
        gw.send_to(&f0, peer).await.unwrap();
        let (_p, s, body) = recv_frame(&gw).await;
        assert_eq!(s, ServiceType::TunnelingAck);
        let (h, _st) = knxnet::parse_tunneling_ack(&body).unwrap();
        assert_eq!(h.seq, 0, "duplicate is ACKed with its own seq");

        // Now send a fresh seq 1 with a distinct GA to prove ordering resumed.
        let ga2: GroupAddress = "4/5/6".parse().unwrap();
        let f1 = knxnet::tunneling_request(
            knxnet::ConnectionHeader {
                channel_id: 0x0A,
                seq: 1,
            },
            &CemiFrame::group_write_packed(ga2, ia, &[1]),
        );
        gw.send_to(&f1, peer).await.unwrap();
        let (_p, s, _b) = recv_frame(&gw).await;
        assert_eq!(s, ServiceType::TunnelingAck);
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    // First delivered frame: 1/2/3.
    let first = conn.recv().await.unwrap();
    assert_eq!(
        first.frame.group_destination().unwrap().to_string(),
        "1/2/3"
    );

    // The duplicate must NOT be delivered; the next delivered frame is 4/5/6.
    let second = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("should receive the fresh frame")
        .unwrap();
    assert_eq!(
        second.frame.group_destination().unwrap().to_string(),
        "4/5/6"
    );

    gw_task.await.unwrap();
    let _ = conn.close().await;
}

#[tokio::test]
async fn out_of_window_sequence_is_silently_discarded_without_ack() {
    // Issue #60 (C2): a TUNNELING_REQUEST whose sequence is out of window (neither
    // the expected seq nor the exact seq-1 duplicate) must be SILENTLY DISCARDED —
    // no ACK. ACKing a frame we then drop would wrongly tell the gateway we
    // accepted it.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0A, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        let ga: GroupAddress = "1/2/3".parse().unwrap();
        let ia: IndividualAddress = "1.1.10".parse().unwrap();

        // Deliver seq 0 (expected) and collect its ACK — this fixes the window at
        // "expecting seq 1 next".
        let f0 = knxnet::tunneling_request(
            knxnet::ConnectionHeader {
                channel_id: 0x0A,
                seq: 0,
            },
            &CemiFrame::group_write_packed(ga, ia, &[0]),
        );
        gw.send_to(&f0, peer).await.unwrap();
        let (_p, s, _b) = recv_frame(&gw).await;
        assert_eq!(s, ServiceType::TunnelingAck);

        // Now send a far-out-of-window seq 5. It must be silently dropped: NO ACK.
        let ga2: GroupAddress = "4/5/6".parse().unwrap();
        let f5 = knxnet::tunneling_request(
            knxnet::ConnectionHeader {
                channel_id: 0x0A,
                seq: 5,
            },
            &CemiFrame::group_write_packed(ga2, ia, &[1]),
        );
        gw.send_to(&f5, peer).await.unwrap();

        // No ACK should arrive for the out-of-window frame.
        let mut buf = [0u8; 1024];
        let got = tokio::time::timeout(Duration::from_millis(400), gw.recv_from(&mut buf)).await;
        assert!(
            got.is_err(),
            "out-of-window sequence must NOT be ACKed (got a datagram back)"
        );
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    // The expected frame is delivered.
    let first = conn.recv().await.unwrap();
    assert_eq!(
        first.frame.group_destination().unwrap().to_string(),
        "1/2/3"
    );
    // The out-of-window frame is never delivered.
    let dropped = tokio::time::timeout(Duration::from_millis(500), conn.recv()).await;
    assert!(
        dropped.is_err(),
        "out-of-window frame must not be delivered"
    );

    gw_task.await.unwrap();
    let _ = conn.close().await;
}

#[tokio::test]
async fn retransmit_two_behind_is_acked_and_dropped_then_resyncs() {
    // Issue #58: a gateway retransmitting a frame *two* behind the expected
    // sequence (its ACK-timeout resend after several of our ACKs were lost) must
    // be ACKed-and-dropped, not silently discarded. The old one-frame window
    // dropped it silently, so the gateway kept retransmitting and the tunnel
    // desynced. After ACK-and-drop the next in-order frame is still delivered.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0A, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        let ia: IndividualAddress = "1.1.10".parse().unwrap();
        let send = |seq: u8, ga: GroupAddress, val: u8| {
            knxnet::tunneling_request(
                knxnet::ConnectionHeader {
                    channel_id: 0x0A,
                    seq,
                },
                &CemiFrame::group_write_packed(ga, ia, &[val]),
            )
        };

        // Deliver seq 0, 1, 2 in order (expected advances to 3), collecting ACKs.
        for (seq, ga) in [(0u8, "1/2/3"), (1, "1/2/4"), (2, "1/2/5")] {
            gw.send_to(&send(seq, ga.parse().unwrap(), seq), peer)
                .await
                .unwrap();
            let (_p, s, _b) = recv_frame(&gw).await;
            assert_eq!(s, ServiceType::TunnelingAck);
        }

        // Now retransmit seq 1 — two behind the expected seq 3. It must be ACKed
        // (its own seq) and dropped, NOT silently discarded.
        gw.send_to(&send(1, "1/2/4".parse().unwrap(), 1), peer)
            .await
            .unwrap();
        let (_p, s, body) = recv_frame(&gw).await;
        assert_eq!(s, ServiceType::TunnelingAck, "2-behind retransmit is ACKed");
        let (h, _st) = knxnet::parse_tunneling_ack(&body).unwrap();
        assert_eq!(h.seq, 1, "duplicate is ACKed with its own seq");

        // A fresh seq 3 proves the window never desynced.
        gw.send_to(&send(3, "12/3/45".parse().unwrap(), 3), peer)
            .await
            .unwrap();
        let (_p, s, _b) = recv_frame(&gw).await;
        assert_eq!(s, ServiceType::TunnelingAck);
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    // The three in-order frames are delivered.
    for expect in ["1/2/3", "1/2/4", "1/2/5"] {
        let f = tokio::time::timeout(Duration::from_secs(2), conn.recv())
            .await
            .expect("in-order frame delivered")
            .unwrap();
        assert_eq!(f.frame.group_destination().unwrap().to_string(), expect);
    }

    // The 2-behind retransmit is NOT re-delivered; the next delivered frame is the
    // fresh 12/3/45.
    let next = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("fresh frame after the retransmit")
        .unwrap();
    assert_eq!(
        next.frame.group_destination().unwrap().to_string(),
        "12/3/45"
    );

    gw_task.await.unwrap();
    let _ = conn.close().await;
}

#[tokio::test]
async fn unknown_message_code_is_acked_then_ignored() {
    // Issue #60 (C3): a cEMI carrying an unknown message code cannot be decoded,
    // but the in-sequence frame must still be ACKed so the gateway advances (an
    // un-ACKed frame would be retransmitted forever and stall the tunnel). The
    // undecodable payload is simply not delivered.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0A, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Build a TUNNELING_REQUEST body by hand: connection header (len 4,
        // channel, seq 0, reserved) + a cEMI with an UNKNOWN message code 0xFF and
        // a minimal tail. `CemiFrame::decode` rejects the message code, so this is
        // the C3 path.
        let mut body = vec![0x04, 0x0A, 0x00, 0x00];
        body.extend_from_slice(&[0xFF, 0x00]); // unknown message code + AI length 0
        let req = knxnet_frame(ServiceType::TunnelingRequest, &body);
        gw.send_to(&req, peer).await.unwrap();

        // The client must still ACK seq 0 (so the gateway advances).
        let (_p, s, ack_body) = recv_frame(&gw).await;
        assert_eq!(
            s,
            ServiceType::TunnelingAck,
            "unknown-code frame must be ACKed"
        );
        let (h, _st) = knxnet::parse_tunneling_ack(&ack_body).unwrap();
        assert_eq!(h.seq, 0);

        // Then a real in-sequence frame (seq 1) proves the window advanced.
        let ga: GroupAddress = "4/5/6".parse().unwrap();
        let ia: IndividualAddress = "1.1.10".parse().unwrap();
        let f1 = knxnet::tunneling_request(
            knxnet::ConnectionHeader {
                channel_id: 0x0A,
                seq: 1,
            },
            &CemiFrame::group_write_packed(ga, ia, &[1]),
        );
        gw.send_to(&f1, peer).await.unwrap();
        let (_p, s, _b) = recv_frame(&gw).await;
        assert_eq!(s, ServiceType::TunnelingAck);
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    // The undecodable frame is not delivered; the next delivered frame is 4/5/6,
    // proving the window advanced past the ACKed-but-ignored unknown frame.
    let delivered = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("the fresh in-sequence frame arrives")
        .unwrap();
    assert_eq!(
        delivered.frame.group_destination().unwrap().to_string(),
        "4/5/6"
    );

    gw_task.await.unwrap();
    let _ = conn.close().await;
}

#[tokio::test]
async fn heartbeat_is_answered() {
    // We cannot wait the real 60 s heartbeat interval in a unit test, so this
    // test drives the heartbeat *handler* indirectly: it verifies that if the
    // gateway sends a CONNECTIONSTATE_REQUEST-style exchange is not required, and
    // instead confirms the connection stays alive through a normal send while the
    // mock answers any CONNECTIONSTATE_REQUEST it happens to see. It primarily
    // guards that connect + send + close all succeed without a heartbeat firing.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0B, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Answer whatever comes next: a TUNNELING_REQUEST (ack) or a
        // CONNECTIONSTATE_REQUEST (respond OK).
        loop {
            let mut buf = [0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(2), gw.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    let parsed = knxnet::parse(&buf[..n]).unwrap();
                    match parsed.service {
                        ServiceType::TunnelingRequest => {
                            let tr = knxnet::parse_tunneling_request(parsed.body).unwrap();
                            let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
                            gw.send_to(&ack, peer).await.unwrap();
                        }
                        ServiceType::ConnectionstateRequest => {
                            let resp = knxnet::connectionstate_response(0x0B, 0);
                            gw.send_to(&resp, peer).await.unwrap();
                        }
                        ServiceType::DisconnectRequest => {
                            let resp = knxnet::disconnect_response(0x0B, 0);
                            gw.send_to(&resp, peer).await.unwrap();
                            return;
                        }
                        _ => {}
                    }
                }
                _ => return,
            }
        }
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();
    let ga: GroupAddress = "3/0/4".parse().unwrap();
    let ia: IndividualAddress = "1.1.255".parse().unwrap();
    conn.send(CemiFrame::group_write_packed(ga, ia, &[1]))
        .await
        .unwrap();
    conn.close().await.unwrap();
    let _ = gw_task.await;
}

#[tokio::test]
async fn connect_rejected_status_is_error() {
    let (addr, gw) = bind_mock().await;
    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        // Status 0x24 (no more connections).
        let resp = knxnet_frame(ServiceType::ConnectResponse, &[0x00, 0x24]);
        gw.send_to(&resp, peer).await.unwrap();
    });
    let config = ConnectionConfig::tunnel(addr);
    let result = Transport::connect(&config).await;
    assert!(result.is_err(), "rejected connect should error");
    let _ = gw_task.await;
}

#[tokio::test]
async fn dropping_tunnel_sends_disconnect_request() {
    // Issue #31: dropping a `Tunnel` (without calling close) must still tear the
    // connection down cleanly — the background task's command channel closes,
    // which runs `do_close` and sends a DISCONNECT_REQUEST — so the gateway slot
    // is released rather than leaked for its ~2-minute timeout.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        // Handshake.
        let (peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0C, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // The client is dropped by the test below; expect a DISCONNECT_REQUEST,
        // answering any heartbeat that races it.
        loop {
            let mut buf = [0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), gw.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    let Ok(parsed) = knxnet::parse(&buf[..n]) else {
                        continue;
                    };
                    match parsed.service {
                        ServiceType::DisconnectRequest => {
                            let resp = knxnet::disconnect_response(0x0C, 0);
                            let _ = gw.send_to(&resp, peer).await;
                            return true;
                        }
                        ServiceType::ConnectionstateRequest => {
                            let resp = knxnet::connectionstate_response(0x0C, 0);
                            let _ = gw.send_to(&resp, peer).await;
                        }
                        _ => {}
                    }
                }
                _ => return false,
            }
        }
    });

    let config = ConnectionConfig::tunnel(addr);
    let conn = Transport::connect(&config).await.unwrap();
    // Drop the connection without calling close(). The graceful DISCONNECT must
    // still be sent by the detached background task.
    drop(conn);

    let saw_disconnect = tokio::time::timeout(Duration::from_secs(5), gw_task)
        .await
        .expect("gateway task should finish")
        .unwrap();
    assert!(
        saw_disconnect,
        "dropping a Tunnel must send a DISCONNECT_REQUEST (no slot leak)"
    );
}

#[tokio::test]
async fn control_hpais_are_the_real_endpoint_everywhere() {
    // Interop finding (KNX Virtual): literal-minded gateways reply to the HPAI
    // they are given, so a wildcard 0.0.0.0:0 CONNECT never completes. All
    // control HPAIs (CONNECT, CONNECTIONSTATE, DISCONNECT) must consistently
    // carry the REAL local endpoint, which every gateway supports on
    // loopback/LAN/routed paths (classic mode).
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        // 1. CONNECT_REQUEST: assert its control HPAI (first HPAI in the body).
        let (peer, service, body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::ConnectRequest);
        assert!(
            hpai_matches(&body[0..8], peer),
            "CONNECT control HPAI must be the real local endpoint {peer}, got {:?}",
            &body[0..8]
        );
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x0D, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // 2. The client calls close(): capture the DISCONNECT_REQUEST and assert
        // its control HPAI (body after channel_id + reserved) is wildcard too.
        loop {
            let mut buf = [0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), gw.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    let Ok(parsed) = knxnet::parse(&buf[..n]) else {
                        continue;
                    };
                    match parsed.service {
                        ServiceType::DisconnectRequest => {
                            // body: [channel_id, reserved, HPAI(8)]
                            assert!(
                                hpai_matches(&parsed.body[2..10], peer),
                                "DISCONNECT control HPAI must be the real local endpoint, got {:?}",
                                &parsed.body[2..10]
                            );
                            let resp = knxnet::disconnect_response(0x0D, 0);
                            let _ = gw.send_to(&resp, peer).await;
                            return true;
                        }
                        ServiceType::ConnectionstateRequest => {
                            // body: [channel_id, reserved, HPAI(8)]
                            assert!(
                                hpai_matches(&parsed.body[2..10], peer),
                                "CONNECTIONSTATE control HPAI must be the real local endpoint, got {:?}",
                                &parsed.body[2..10]
                            );
                            let resp = knxnet::connectionstate_response(0x0D, 0);
                            let _ = gw.send_to(&resp, peer).await;
                        }
                        _ => {}
                    }
                }
                _ => return false,
            }
        }
    });

    let config = ConnectionConfig::tunnel(addr);
    let conn = Transport::connect(&config).await.unwrap();
    conn.close().await.unwrap();

    let saw_disconnect = tokio::time::timeout(Duration::from_secs(5), gw_task)
        .await
        .expect("gateway task should finish")
        .unwrap();
    assert!(saw_disconnect, "close() must send a DISCONNECT_REQUEST");
}

// --- Optional multicast loopback test, gated behind an env var ---

#[tokio::test]
async fn routing_loopback() {
    if std::env::var("BUSSARD_TEST_MULTICAST").is_err() {
        eprintln!("skipping routing_loopback (set BUSSARD_TEST_MULTICAST=1 to enable)");
        return;
    }
    use bussard_transport::Router;
    let config = ConnectionConfig::routing();
    let mut a = Router::connect(&config).await.unwrap();
    let mut b = Router::connect(&config).await.unwrap();

    let ga: GroupAddress = "7/0/1".parse().unwrap();
    let ia: IndividualAddress = "1.1.1".parse().unwrap();
    a.send(CemiFrame::group_write_packed(ga, ia, &[1]))
        .await
        .unwrap();

    let stamped = tokio::time::timeout(Duration::from_secs(2), b.recv())
        .await
        .expect("multicast frame should arrive")
        .unwrap();
    assert_eq!(
        stamped.frame.group_destination().unwrap().to_string(),
        "7/0/1"
    );
}

// --- helpers ---

fn knxnet_frame(service: ServiceType, body: &[u8]) -> Vec<u8> {
    // Re-wrap using the public framing helper via a routing_indication-like path
    // is not available, so build the header manually to match the crate.
    let total = (6 + body.len()) as u16;
    let mut out = Vec::with_capacity(total as usize);
    out.push(0x06);
    out.push(0x10);
    out.extend_from_slice(&(service as u16).to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Whether an 8-byte HPAI slice encodes exactly the given peer socket address
/// (structure `[len=0x08, code=0x01, ip(4), port(2)]`).
fn hpai_matches(hpai: &[u8], peer: std::net::SocketAddr) -> bool {
    let std::net::SocketAddr::V4(v4) = peer else {
        return false;
    };
    hpai.len() == 8
        && hpai[0] == 0x08
        && hpai[1] == 0x01
        && hpai[2..6] == v4.ip().octets()
        && hpai[6..8] == v4.port().to_be_bytes()
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

/// The group address burst frame `i` carries, distinct for every index so the
/// delivery order can be asserted.
fn burst_ga(i: usize) -> GroupAddress {
    format!("1/{}/{}", i / 256, i % 256).parse().unwrap()
}

/// Reads from the mock socket until the client's TUNNELING_ACK for `seq` arrives,
/// ignoring anything else (e.g. a retransmit of our own request).
async fn await_client_ack(gw: &UdpSocket, seq: u8) {
    loop {
        let (_peer, service, body) = tokio::time::timeout(Duration::from_secs(5), recv_frame(gw))
            .await
            .unwrap_or_else(|_| panic!("client stopped ACKing at seq {seq}"));
        if service == ServiceType::TunnelingAck {
            let (hdr, status) = knxnet::parse_tunneling_ack(&body).unwrap();
            assert_eq!(status, 0);
            if hdr.seq == seq {
                return;
            }
        }
    }
}

// --- Issue #82: inbound buffering must never block the tunnel task ---

#[tokio::test]
async fn inbound_burst_during_ack_wait_does_not_stall_the_tunnel() {
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

    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x1A, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Our TUNNELING_REQUEST arrives. Hold its ACK back: the client stays
        // inside `await_ack` for the whole burst below.
        let (peer, service, body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::TunnelingRequest);
        let ours = knxnet::parse_tunneling_request(&body).unwrap();

        // Burst: one indication at a time, each awaiting the client's ACK. A
        // client that stops ACKing (the deadlock) hangs this loop.
        let src: IndividualAddress = "1.1.10".parse().unwrap();
        for i in 0..BURST {
            let seq = i as u8;
            let ind = knxnet::tunneling_request(
                knxnet::ConnectionHeader {
                    channel_id: 0x1A,
                    seq,
                },
                &CemiFrame::group_write_packed(burst_ga(i), src, &[1]),
            );
            gw.send_to(&ind, peer).await.unwrap();
            await_client_ack(&gw, seq).await;
        }

        // Only now ACK the client's own request.
        let ack = knxnet::tunneling_ack(ours.header.channel_id, ours.header.seq, 0);
        gw.send_to(&ack, peer).await.unwrap();
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    let ga: GroupAddress = "3/0/4".parse().unwrap();
    let ia: IndividualAddress = "1.1.255".parse().unwrap();
    // The send must complete: with the old bounded channel the tunnel task was
    // blocked on delivery number 257 and this never returned.
    tokio::time::timeout(
        Duration::from_secs(10),
        conn.send(CemiFrame::group_write_packed(ga, ia, &[1])),
    )
    .await
    .expect("send must not deadlock behind a full inbound channel")
    .expect("the gateway ACKed the request");

    tokio::time::timeout(Duration::from_secs(10), gw_task)
        .await
        .expect("the gateway must never stall waiting for an ACK")
        .unwrap();

    // Nothing was dropped or reordered: the whole burst is still queued, in order.
    for i in 0..BURST {
        let f = tokio::time::timeout(Duration::from_secs(2), conn.recv())
            .await
            .unwrap_or_else(|_| panic!("burst frame {i} must be delivered"))
            .unwrap();
        assert_eq!(
            f.frame.group_destination().unwrap().to_string(),
            burst_ga(i).to_string(),
            "burst frames must arrive in order"
        );
    }

    let _ = conn.close().await;
}

// --- Previously untested tunnel failure paths (protocol audit) ---

#[tokio::test]
async fn non_zero_tunneling_ack_status_fails_the_send() {
    // A TUNNELING_ACK carrying a non-zero status is a rejection, not a success:
    // it must surface as GatewayStatus rather than resolving the send, and must
    // not be retried (only a timeout is retried).
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x1B, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        let (peer, service, body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::TunnelingRequest);
        let tr = knxnet::parse_tunneling_request(&body).unwrap();
        // 0x29 = E_TUNNELING_LAYER (a plausible refusal).
        let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0x29);
        gw.send_to(&ack, peer).await.unwrap();

        // The rejected request must NOT be retransmitted.
        let mut buf = [0u8; 1024];
        if let Ok(Ok((n, _p))) =
            tokio::time::timeout(Duration::from_secs(2), gw.recv_from(&mut buf)).await
        {
            let parsed = knxnet::parse(&buf[..n]).unwrap();
            assert_ne!(
                parsed.service,
                ServiceType::TunnelingRequest,
                "a status-rejected request must not be retransmitted"
            );
        }
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();
    let ga: GroupAddress = "3/0/4".parse().unwrap();
    let ia: IndividualAddress = "1.1.255".parse().unwrap();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        conn.send(CemiFrame::group_write_packed(ga, ia, &[1])),
    )
    .await
    .expect("a rejected send must resolve promptly, not wait out the ACK timeout")
    .expect_err("non-zero ACK status must fail the send");
    assert!(
        matches!(
            err,
            bussard_transport::TransportError::GatewayStatus {
                status: 0x29,
                context: "TUNNELING_ACK"
            }
        ),
        "expected a TUNNELING_ACK GatewayStatus, got {err:?}"
    );

    gw_task.await.unwrap();
    let _ = conn.close().await;
}

#[tokio::test]
async fn disconnect_request_during_ack_wait_ends_the_send_and_the_stream() {
    // A server-initiated DISCONNECT_REQUEST can arrive while we are inside
    // `await_ack`. It must be answered with a DISCONNECT_RESPONSE, fail the
    // in-flight send with Disconnected, and surface the same error on the frame
    // stream - not sit there until the ACK timeout.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, _s, _b) = recv_frame(&gw).await;
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x1C, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Our request arrives; instead of ACKing it, disconnect.
        let (peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::TunnelingRequest);
        let disc = knxnet::disconnect_request(0x1C, knxnet::Hpai::wildcard());
        gw.send_to(&disc, peer).await.unwrap();

        // The client must answer the disconnect even mid-await.
        let (_p, service, _b) = tokio::time::timeout(Duration::from_secs(2), recv_frame(&gw))
            .await
            .expect("a DISCONNECT_RESPONSE must follow promptly");
        assert_eq!(service, ServiceType::DisconnectResponse);
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();
    let ga: GroupAddress = "3/0/4".parse().unwrap();
    let ia: IndividualAddress = "1.1.255".parse().unwrap();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        conn.send(CemiFrame::group_write_packed(ga, ia, &[1])),
    )
    .await
    .expect("a disconnect must end the ACK wait immediately")
    .expect_err("a disconnect during the ACK wait must fail the send");
    assert!(
        matches!(err, bussard_transport::TransportError::Disconnected(0x1C)),
        "expected Disconnected, got {err:?}"
    );

    // The consumer learns about it too.
    let stream_err = tokio::time::timeout(Duration::from_secs(2), conn.recv())
        .await
        .expect("the frame stream must report the disconnect")
        .expect_err("the frame stream must report the disconnect");
    assert!(
        matches!(
            stream_err,
            bussard_transport::TransportError::Disconnected(0x1C)
        ),
        "expected Disconnected on the stream, got {stream_err:?}"
    );

    gw_task.await.unwrap();
}

#[tokio::test]
async fn heartbeat_lost_after_retries_is_surfaced_to_the_consumer() {
    // A gateway that stops answering CONNECTIONSTATE_REQUESTs (the cable-pull
    // drill) must be declared dead after HEARTBEAT_RETRIES attempts, and the
    // consumer must see HeartbeatLost rather than a silently wedged stream.
    //
    // The real schedule is 60 s + 3 x 10 s, so the clock is paused *after* the
    // handshake (pausing before it would auto-advance through the real round
    // trip) and the runtime auto-advances it while both sides idle.
    let (addr, gw) = bind_mock().await;

    let gw_task = tokio::spawn(async move {
        let (peer, service, _body) = recv_frame(&gw).await;
        assert_eq!(service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(0x1D, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Count the heartbeat attempts, answering none of them.
        let mut attempts = 0u32;
        while attempts < bussard_transport::config::HEARTBEAT_RETRIES {
            let (_p, service, _b) = recv_frame(&gw).await;
            if service == ServiceType::ConnectionstateRequest {
                attempts += 1;
            }
        }
        attempts
    });

    let config = ConnectionConfig::tunnel(addr);
    let mut conn = Transport::connect(&config).await.unwrap();

    // From here on nothing real is in flight: the mock never replies, so the
    // auto-advancing paused clock drives the whole heartbeat schedule.
    tokio::time::pause();
    let err = conn
        .recv()
        .await
        .expect_err("an unanswered heartbeat must end the stream");
    assert!(
        matches!(err, bussard_transport::TransportError::HeartbeatLost),
        "expected HeartbeatLost, got {err:?}"
    );

    let attempts = gw_task.await.unwrap();
    assert_eq!(
        attempts,
        bussard_transport::config::HEARTBEAT_RETRIES,
        "every heartbeat retry must actually be sent"
    );
}
