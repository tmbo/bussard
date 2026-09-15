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
use bussard_monitor::{run_stream, DecodedTelegram};
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
