//! End-to-end integration test of the monitor pipeline against an in-process
//! mock KNXnet/IP gateway.
//!
//! The mock speaks just enough tunneling to complete the CONNECT handshake and
//! then push three `L_Data.ind` telegrams. The test drives
//! [`run_stream`](bussard_monitor::run_stream) with a collecting sink and
//! asserts that three decoded telegrams come out, resolved against a small
//! in-code model.

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::mpsc;
use std::time::Duration;

use tokio::net::UdpSocket;

use bussard_model::schema::{BussardConfig, Group, Groups, Links};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{
    CancelToken, DecodedTelegram, run_stream, run_stream_cancellable, run_stream_with_outbound,
};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::knxnet::{self, ServiceType};
use bussard_transport::{ConnectionConfig, TimestampedFrame, TransportError};

fn ga(s: &str) -> GroupAddress {
    s.parse().unwrap()
}
fn ia(s: &str) -> IndividualAddress {
    s.parse().unwrap()
}

/// A small model: 3/2/0 is a 1-bit alarm named "Windalarm".
fn model() -> Model {
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("3/2/0"),
        Group {
            name: "Windalarm".to_string(),
            dpt: Some("1.005".parse().unwrap()),
            description: None,
            ..Default::default()
        },
    );
    Model {
        config: BussardConfig::default(),
        groups: Groups {
            project: None,
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

/// Binds a mock gateway on an ephemeral localhost port.
async fn bind_mock() -> (SocketAddrV4, UdpSocket) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = match sock.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected v4"),
    };
    (addr, sock)
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

/// A sink that forwards each decoded telegram over a std mpsc channel and stops
/// after `expected` telegrams.
struct CollectSink {
    tx: mpsc::Sender<DecodedTelegram>,
    remaining: usize,
}

impl TelegramSink for CollectSink {
    fn on_telegram(&mut self, telegram: &DecodedTelegram, _frame: &TimestampedFrame) -> Flow {
        let _ = self.tx.send(telegram.clone());
        self.remaining -= 1;
        if self.remaining == 0 {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn on_disconnect(&mut self, _error: &TransportError, _backoff: Duration) -> Flow {
        // In this test a drop means we are done; stop rather than reconnect.
        Flow::Stop
    }
}

#[tokio::test]
async fn monitor_decodes_three_pushed_frames() {
    let (addr, gw) = bind_mock().await;
    let channel = 0x21u8;

    let gw_task = tokio::spawn(async move {
        // 1. CONNECT handshake.
        let mut buf = [0u8; 1024];
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // 2. Push three indications with distinct GAs and sources, ACKing our
        //    own header seq numbers and consuming the client's ACKs.
        let frames = [
            CemiFrame::group_write(ga("3/2/0"), ia("1.1.30"), &[1]),
            CemiFrame::group_write(ga("5/0/1"), ia("1.1.31"), &[0]),
            CemiFrame::group_read(ga("3/2/0"), ia("1.1.32")),
        ];
        for (seq, frame) in frames.into_iter().enumerate() {
            let hdr = knxnet::ConnectionHeader {
                channel_id: channel,
                seq: seq as u8,
            };
            let ind = knxnet::tunneling_request(hdr, &frame);
            gw.send_to(&ind, peer).await.unwrap();
            // Consume the client's ACK so sequencing stays in step.
            let (n, _peer) = gw.recv_from(&mut buf).await.unwrap();
            let parsed = knxnet::parse(&buf[..n]).unwrap();
            assert_eq!(parsed.service, ServiceType::TunnelingAck);
        }

        // After the pushes, answer a clean DISCONNECT_REQUEST (the sink stops
        // the stream, which closes the tunnel) so the client's close does not
        // block on its 5 s disconnect timeout.
        if let Ok(Ok((n, peer))) =
            tokio::time::timeout(Duration::from_secs(2), gw.recv_from(&mut buf)).await
        {
            if let Ok(parsed) = knxnet::parse(&buf[..n]) {
                if parsed.service == ServiceType::DisconnectRequest {
                    let resp = knxnet::disconnect_response(channel, 0);
                    let _ = gw.send_to(&resp, peer).await;
                }
            }
        }
    });

    let (tx, rx) = mpsc::channel();
    let mut sink = CollectSink { tx, remaining: 3 };
    let config = ConnectionConfig::tunnel(addr);
    let model = model();

    // Run the pipeline until the sink stops (after 3 telegrams).
    tokio::time::timeout(
        Duration::from_secs(5),
        run_stream(&config, Some(&model), &mut sink),
    )
    .await
    .expect("stream should finish once 3 telegrams arrive")
    .expect("stream ran cleanly");

    let collected: Vec<DecodedTelegram> = rx.try_iter().collect();
    assert_eq!(collected.len(), 3, "expected 3 decoded telegrams");

    // First: resolved write to Windalarm with a typed alarm value.
    assert_eq!(collected[0].destination.to_string(), "3/2/0");
    assert_eq!(collected[0].destination_name.as_deref(), Some("Windalarm"));
    assert_eq!(collected[0].source, ia("1.1.30"));
    assert_eq!(
        collected[0].value,
        Some(bussard_model::codec::TypedValue::Bool {
            value: true,
            label: "Alarm"
        })
    );

    // Second: an unknown GA degrades to numeric + raw.
    assert_eq!(collected[1].destination.to_string(), "5/0/1");
    assert_eq!(collected[1].destination_name, None);

    // Third: a read (no value) to the known GA.
    assert_eq!(collected[2].destination.to_string(), "3/2/0");
    assert!(collected[2].value.is_none());

    let _ = gw_task.await;
}

/// The MCP `knx_read_group` / `bussard read` path: an outbound `GroupValueRead`
/// injected through the channel is transmitted on the live connection, and its
/// `GroupValueResponse` comes back through the same stream.
#[tokio::test]
async fn outbound_read_is_sent_and_response_flows_back() {
    let (addr, gw) = bind_mock().await;
    let channel = 0x33u8;

    let gw_task = tokio::spawn(async move {
        // CONNECT handshake.
        let mut buf = [0u8; 1024];
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::ConnectRequest);
        let resp = knxnet_frame(
            ServiceType::ConnectResponse,
            &connect_response_body(channel, &gw),
        );
        gw.send_to(&resp, peer).await.unwrap();

        // Expect the injected GroupValueRead as a TUNNELING_REQUEST; ACK it.
        let (n, peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::TunnelingRequest);
        let tr = knxnet::parse_tunneling_request(parsed.body).unwrap();
        assert_eq!(tr.cemi.apdu, bussard_transport::cemi::Apdu::GroupValueRead);
        assert_eq!(tr.cemi.group_destination().unwrap().to_string(), "3/2/0");
        let ack = knxnet::tunneling_ack(tr.header.channel_id, tr.header.seq, 0);
        gw.send_to(&ack, peer).await.unwrap();

        // Push a GroupValueResponse indication carrying the alarm value.
        let hdr = knxnet::ConnectionHeader {
            channel_id: channel,
            seq: 0,
        };
        let response = CemiFrame::group_response(ga("3/2/0"), ia("1.1.30"), &[1]);
        let ind = knxnet::tunneling_request(hdr, &response);
        gw.send_to(&ind, peer).await.unwrap();
        // Consume the client's ACK.
        let (n, _peer) = gw.recv_from(&mut buf).await.unwrap();
        let parsed = knxnet::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.service, ServiceType::TunnelingAck);

        // Clean disconnect when the sink stops.
        if let Ok(Ok((n, peer))) =
            tokio::time::timeout(Duration::from_secs(2), gw.recv_from(&mut buf)).await
        {
            if let Ok(parsed) = knxnet::parse(&buf[..n]) {
                if parsed.service == ServiceType::DisconnectRequest {
                    let resp = knxnet::disconnect_response(channel, 0);
                    let _ = gw.send_to(&resp, peer).await;
                }
            }
        }
    });

    let (tx, rx) = mpsc::channel();
    // Only the response counts as a "collected" telegram (a read is 1 indication).
    let mut sink = CollectSink { tx, remaining: 1 };
    let config = ConnectionConfig::tunnel(addr);
    let model = model();

    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
    // Inject a GroupValueRead once the stream is running.
    out_tx
        .send(CemiFrame::group_read(ga("3/2/0"), ia("1.1.255")))
        .unwrap();

    tokio::time::timeout(
        Duration::from_secs(5),
        run_stream_with_outbound(&config, Some(&model), &mut sink, Some(out_rx)),
    )
    .await
    .expect("stream should finish once the response arrives")
    .expect("stream ran cleanly");

    let collected: Vec<DecodedTelegram> = rx.try_iter().collect();
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].destination.to_string(), "3/2/0");
    assert_eq!(
        collected[0].apci,
        bussard_monitor::ApciKind::Response,
        "expected a GroupValueResponse"
    );
    assert_eq!(
        collected[0].value,
        Some(bussard_model::codec::TypedValue::Bool {
            value: true,
            label: "Alarm"
        })
    );

    let _ = gw_task.await;
}

/// A sink that never stops the stream on its own — used for the cancellation
/// test, where the stream is ended by a [`CancelToken`], not by the sink.
struct NeverStopSink;

impl TelegramSink for NeverStopSink {
    fn on_telegram(&mut self, _telegram: &DecodedTelegram, _frame: &TimestampedFrame) -> Flow {
        Flow::Continue
    }
    fn on_disconnect(&mut self, _error: &TransportError, _backoff: Duration) -> Flow {
        Flow::Continue
    }
}

/// Issue #31: cancelling a running stream must close the tunnel cleanly — the
/// gateway receives a DISCONNECT_REQUEST rather than having its slot leaked.
#[tokio::test]
async fn cancelling_the_stream_sends_disconnect_request() {
    let (addr, gw) = bind_mock().await;
    let channel = 0x44u8;

    // The gateway records whether it saw a DISCONNECT_REQUEST after cancel.
    let (saw_disc_tx, saw_disc_rx) = std::sync::mpsc::channel::<bool>();

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

        // Wait for the client's DISCONNECT_REQUEST (sent when it is cancelled),
        // answering heartbeats meanwhile.
        loop {
            match tokio::time::timeout(Duration::from_secs(5), gw.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    let Ok(parsed) = knxnet::parse(&buf[..n]) else {
                        continue;
                    };
                    match parsed.service {
                        ServiceType::DisconnectRequest => {
                            let resp = knxnet::disconnect_response(channel, 0);
                            let _ = gw.send_to(&resp, peer).await;
                            let _ = saw_disc_tx.send(true);
                            return;
                        }
                        ServiceType::ConnectionstateRequest => {
                            let resp = knxnet::connectionstate_response(channel, 0);
                            let _ = gw.send_to(&resp, peer).await;
                        }
                        _ => {}
                    }
                }
                _ => {
                    let _ = saw_disc_tx.send(false);
                    return;
                }
            }
        }
    });

    let config = ConnectionConfig::tunnel(addr);
    let model = model();
    let (cancel, cancel_watch) = CancelToken::new();

    // Cancel shortly after the stream is up.
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel.cancel();
    });

    let mut sink = NeverStopSink;
    tokio::time::timeout(
        Duration::from_secs(5),
        run_stream_cancellable(&config, Some(&model), &mut sink, cancel_watch),
    )
    .await
    .expect("cancel should end the stream")
    .expect("stream ran cleanly");

    canceller.await.unwrap();
    let saw = saw_disc_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or(false);
    assert!(
        saw,
        "the gateway must receive a DISCONNECT_REQUEST when the stream is cancelled"
    );
    let _ = gw_task.await;
}
