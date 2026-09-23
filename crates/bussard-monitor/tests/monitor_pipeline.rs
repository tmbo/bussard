//! End-to-end integration test of the monitor pipeline against the
//! `bussard-testkit` mock KNXnet/IP gateway (loopback only).
//!
//! The mock completes the CONNECT handshake and then pushes three `L_Data.ind`
//! telegrams. The test drives [`run_stream`](bussard_monitor::run_stream) with a
//! collecting sink and asserts that three decoded telegrams come out, resolved
//! against a small in-code model.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use bussard_model::Model;
use bussard_model::schema::{BussardConfig, Group, Groups, Links};
use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{
    CancelToken, DecodedTelegram, run_stream, run_stream_cancellable, run_stream_with_outbound,
};
use bussard_testkit::{MockGateway, TestResult, ga, group_dest, ia};
use bussard_transport::cemi::{Apdu, CemiFrame};
use bussard_transport::{ConnectionConfig, TimestampedFrame, TransportError};

/// A small model: 3/2/0 is a 1-bit alarm named "Windalarm".
fn model() -> TestResult<Model> {
    let mut groups = BTreeMap::new();
    groups.insert(
        ga("3/2/0")?,
        Group {
            name: "Windalarm".to_string(),
            dpt: Some("1.005".parse()?),
            description: None,
            ..Default::default()
        },
    );
    Ok(Model {
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
    })
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
async fn monitor_decodes_three_pushed_frames() -> TestResult {
    // Push three indications with distinct GAs and sources after CONNECT. The
    // staggered delays keep them in order on the wire.
    let gw = MockGateway::builder()
        .channel(0x21)
        .push_after_connect(
            Duration::from_millis(50),
            CemiFrame::group_write_packed(ga("3/2/0")?, ia("1.1.30")?, &[1]),
        )
        .push_after_connect(
            Duration::from_millis(100),
            CemiFrame::group_write_packed(ga("5/0/1")?, ia("1.1.31")?, &[0]),
        )
        .push_after_connect(
            Duration::from_millis(150),
            CemiFrame::group_read(ga("3/2/0")?, ia("1.1.32")?),
        )
        .start()
        .await?;

    let (tx, rx) = mpsc::channel();
    let mut sink = CollectSink { tx, remaining: 3 };
    let config = ConnectionConfig::tunnel(gw.addr());
    let model = model()?;

    // Run the pipeline until the sink stops (after 3 telegrams).
    tokio::time::timeout(
        Duration::from_secs(5),
        run_stream(&config, Some(&model), &mut sink),
    )
    .await
    .map_err(|_| "stream should finish once 3 telegrams arrive")??;

    let collected: Vec<DecodedTelegram> = rx.try_iter().collect();
    assert_eq!(collected.len(), 3, "expected 3 decoded telegrams");

    // First: resolved write to Windalarm with a typed alarm value.
    assert_eq!(collected[0].destination.to_string(), "3/2/0");
    assert_eq!(collected[0].destination_name.as_deref(), Some("Windalarm"));
    assert_eq!(collected[0].source, ia("1.1.30")?);
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

    // The client ACKed each pushed indication, so sequencing stayed in step.
    assert!(
        gw.wait_until(Duration::from_secs(2), |s| s.client_acks >= 3)
            .await,
        "the client must ACK all three indications, got {:?}",
        gw.stats()
    );
    let _ = gw.finish(Duration::from_secs(2)).await;
    Ok(())
}

/// The MCP `knx_read_group` / `bussard read` path: an outbound `GroupValueRead`
/// injected through the channel is transmitted on the live connection, and its
/// `GroupValueResponse` comes back through the same stream.
#[tokio::test]
async fn outbound_read_is_sent_and_response_flows_back() -> TestResult {
    // Answer a GroupValueRead with a GroupValueResponse carrying the alarm value.
    let response = CemiFrame::group_response_packed(ga("3/2/0")?, ia("1.1.30")?, &[1]);
    let gw = MockGateway::builder()
        .channel(0x33)
        .respond(move |frame| {
            if frame.apdu == Apdu::GroupValueRead {
                vec![response.clone()]
            } else {
                vec![]
            }
        })
        .start()
        .await?;

    let (tx, rx) = mpsc::channel();
    // Only the response counts as a "collected" telegram (a read is 1 indication).
    let mut sink = CollectSink { tx, remaining: 1 };
    let config = ConnectionConfig::tunnel(gw.addr());
    let model = model()?;

    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
    // Inject a GroupValueRead once the stream is running.
    out_tx.send(CemiFrame::group_read(ga("3/2/0")?, ia("1.1.255")?))?;

    tokio::time::timeout(
        Duration::from_secs(5),
        run_stream_with_outbound(&config, Some(&model), &mut sink, Some(out_rx)),
    )
    .await
    .map_err(|_| "stream should finish once the response arrives")??;

    // The injected GroupValueRead reached the gateway as a TUNNELING_REQUEST.
    let sent = gw.sent()?;
    assert_eq!(sent.len(), 1, "exactly the injected read is sent: {sent:?}");
    assert_eq!(sent[0].apdu, Apdu::GroupValueRead);
    assert_eq!(group_dest(&sent[0])?, "3/2/0");

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

    let _ = gw.finish(Duration::from_secs(2)).await;
    Ok(())
}
/// A sink that never stops the stream on its own, used for the cancellation
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

/// Issue #31: cancelling a running stream must close the tunnel cleanly: the
/// gateway receives a DISCONNECT_REQUEST rather than having its slot leaked.
#[tokio::test]
async fn cancelling_the_stream_sends_disconnect_request() -> TestResult {
    // The gateway answers heartbeats and counts the DISCONNECT_REQUEST.
    let gw = MockGateway::builder().channel(0x44).start().await?;

    let config = ConnectionConfig::tunnel(gw.addr());
    let model = model()?;
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
    .map_err(|_| "cancel should end the stream")??;

    canceller.await?;
    assert!(
        gw.wait_until(Duration::from_secs(2), |s| s.disconnects > 0)
            .await,
        "the gateway must receive a DISCONNECT_REQUEST when the stream is cancelled"
    );
    Ok(())
}
