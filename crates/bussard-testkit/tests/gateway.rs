//! Self-tests of the mock gateway against the real `bussard-transport` tunnel.
//! Every gateway binds `127.0.0.1:0`.

use std::time::Duration;

use bussard_testkit::consts::{A_DEVICE_DESCRIPTOR_READ, A_DEVICE_DESCRIPTOR_RESPONSE};
use bussard_testkit::wire::description_response_body;
use bussard_testkit::{AckPolicy, MockDevice, MockGateway, TestResult, ga, group_dest, ia};
use bussard_transport::cemi::{Apdu, CemiFrame};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{BusConnection, ConnectionConfig, Transport, TransportError};

const WAIT: Duration = Duration::from_secs(3);

#[tokio::test]
async fn test_mock_gateway_captures_and_responds() -> TestResult {
    let answer = CemiFrame::group_response_packed(ga("3/2/0")?, ia("1.1.30")?, &[1]);
    let gw = MockGateway::builder()
        .respond(move |frame| {
            if frame.apdu == Apdu::GroupValueRead {
                vec![answer.clone()]
            } else {
                vec![]
            }
        })
        .start()
        .await?;

    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::group_read(ga("3/2/0")?, ia("1.1.255")?))
        .await?;
    let got = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(
        got.frame.apdu,
        Apdu::GroupValueResponse(bussard_transport::cemi::GroupData::Small(1))
    );
    conn.close().await?;

    let stats = gw.finish(WAIT).await?;
    assert_eq!(stats.connects, 1);
    assert_eq!(stats.disconnects, 1);
    assert_eq!(stats.requests, 1);
    assert!(
        stats.client_acks >= 1,
        "the client ACKs the pushed response"
    );
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_sent_records_client_frames() -> TestResult {
    let gw = MockGateway::builder().start().await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::group_write_packed(
        ga("1/2/3")?,
        ia("1.1.255")?,
        &[1],
    ))
    .await?;
    let sent = gw.sent()?;
    assert_eq!(sent.len(), 1);
    assert_eq!(group_dest(&sent[0])?, "1/2/3");
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_push_after_connect_and_on_demand() -> TestResult {
    let gw = MockGateway::builder()
        .push_after_connect(
            Duration::from_millis(20),
            CemiFrame::group_write_packed(ga("1/1/1")?, ia("1.1.10")?, &[1]),
        )
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let first = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(group_dest(&first.frame)?, "1/1/1");

    gw.push(CemiFrame::group_write_packed(
        ga("2/2/2")?,
        ia("1.1.10")?,
        &[0],
    ))?;
    let second = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(group_dest(&second.frame)?, "2/2/2");
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_refuses_connect() -> TestResult {
    let gw = MockGateway::builder().refuse_connect(0x24).start().await?;
    let result = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await;
    assert!(matches!(result, Err(TransportError::NoMoreConnections)));
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_ack_status_fails_the_send() -> TestResult {
    let gw = MockGateway::builder()
        .ack_policy(AckPolicy::Status(0x29))
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let result = conn
        .send(CemiFrame::group_write_packed(
            ga("1/2/3")?,
            ia("1.1.255")?,
            &[1],
        ))
        .await;
    assert!(matches!(
        result,
        Err(TransportError::GatewayStatus { status: 0x29, .. })
    ));
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_describes_itself() -> TestResult {
    let gw = MockGateway::builder()
        .description(description_response_body("Kit Gate", 2, 1))
        .start()
        .await?;
    let desc = bussard_transport::describe_gateway(gw.addr(), WAIT).await?;
    assert_eq!(desc.name.as_deref(), Some("Kit Gate"));
    assert_eq!(gw.stats().connects, 0);
    Ok(())
}

#[tokio::test]
async fn test_mock_device_answers_connected_descriptor_read() -> TestResult {
    let device = ia("1.1.4")?;
    let tool = ia("1.1.255")?;
    let gw = MockGateway::builder()
        .device(MockDevice::new(device).with_mask(0x0705))
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::t_control(device, tool, 0x80)).await?; // T_Connect
    conn.send(CemiFrame::t_data_connected(
        device,
        tool,
        tpci::ndt(0),
        A_DEVICE_DESCRIPTOR_READ,
        &[],
    ))
    .await?;

    let ack = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(tpci::classify(ack.frame.tpci_octet()), TpciKind::Ack(0));
    let resp = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(
        tpci::classify(resp.frame.tpci_octet()),
        TpciKind::NumberedData(0)
    );
    assert_eq!(
        resp.frame.apdu,
        Apdu::Other {
            apci: A_DEVICE_DESCRIPTOR_RESPONSE,
            data: vec![0x07, 0x05]
        }
    );
    conn.close().await?;

    let telegrams = gw.with_device(device, |d| (d.connects, d.telegrams))?;
    assert_eq!(telegrams, (1, 1));
    Ok(())
}

#[tokio::test]
async fn test_mock_device_script_folds_ack_and_replays_stale_seq() -> TestResult {
    use bussard_testkit::{Reaction, Step};
    let device = ia("1.1.4")?;
    let tool = ia("1.1.255")?;
    let gw = MockGateway::builder()
        .device(MockDevice::new(device).with_hook(|dev, apci, _| {
            (apci == A_DEVICE_DESCRIPTOR_READ).then(|| {
                // Folded ACK: the answer alone, then a replay one behind.
                let seq = dev.send_seq().unwrap_or(0);
                Reaction::Script(vec![
                    Step::Data(A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]),
                    Step::Pause(Duration::from_millis(5)),
                    Step::DataAtSeq(seq, A_DEVICE_DESCRIPTOR_RESPONSE, vec![0x07, 0xB0]),
                ])
            })
        }))
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::t_control(device, tool, 0x80)).await?;
    conn.send(CemiFrame::t_data_connected(
        device,
        tool,
        tpci::ndt(0),
        A_DEVICE_DESCRIPTOR_READ,
        &[],
    ))
    .await?;
    let first = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(
        tpci::classify(first.frame.tpci_octet()),
        TpciKind::NumberedData(0)
    );
    let replay = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(
        tpci::classify(replay.frame.tpci_octet()),
        TpciKind::NumberedData(0)
    );
    let seq = gw.with_device(device, |d| d.send_seq())?;
    assert_eq!(seq, Some(1), "only Step::Data advances the send sequence");
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_mock_device_control_hook_answers_t_connect() -> TestResult {
    use bussard_testkit::Step;
    let device = ia("1.1.4")?;
    let tool = ia("1.1.255")?;
    let gw = MockGateway::builder()
        .device(
            MockDevice::new(device).with_control_hook(|_, kind| match kind {
                TpciKind::Connect => vec![Step::Control(0x81)],
                _ => vec![],
            }),
        )
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::t_control(device, tool, 0x80)).await?;
    let refusal = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(
        tpci::classify(refusal.frame.tpci_octet()),
        TpciKind::Disconnect
    );
    assert_eq!(refusal.frame.source, device);
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_intercept_swallows_without_ack() -> TestResult {
    use bussard_testkit::Verdict;
    let gw = MockGateway::builder()
        .intercept(|inbound| match inbound.cemi {
            Some(frame) if group_dest(frame).is_ok_and(|g| g == "9/7/9") => Verdict::Swallow,
            _ => Verdict::Serve,
        })
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::group_write_packed(
        ga("1/1/1")?,
        ia("1.1.255")?,
        &[1],
    ))
    .await?;
    let swallowed = tokio::time::timeout(
        WAIT,
        conn.send(CemiFrame::group_write_packed(
            ga("9/7/9")?,
            ia("1.1.255")?,
            &[1],
        )),
    )
    .await;
    assert!(
        !matches!(swallowed, Ok(Ok(()))),
        "no ACK for a swallowed request"
    );
    let sent = gw.sent()?;
    assert_eq!(sent.len(), 1, "a swallowed frame is not captured");
    assert!(gw.stats().intercepted >= 1);
    Ok(())
}

#[tokio::test]
async fn test_mock_device_hook_sees_raw_request_tpci() -> TestResult {
    use std::sync::{Arc, Mutex};
    let device = ia("1.1.4")?;
    let tool = ia("1.1.255")?;
    let seen = Arc::new(Mutex::new(None));
    let record = Arc::clone(&seen);
    let gw = MockGateway::builder()
        .device(MockDevice::new(device).with_hook(move |dev, _, _| {
            if let Ok(mut slot) = record.lock() {
                *slot = Some((dev.request_tpci, dev.client_seq, dev.tool));
            }
            None
        }))
        .start()
        .await?;
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    conn.send(CemiFrame::t_control(device, tool, 0x80)).await?;
    conn.send(CemiFrame::t_data_connected(
        device,
        tool,
        tpci::ndt(0),
        A_DEVICE_DESCRIPTOR_READ,
        &[],
    ))
    .await?;
    tokio::time::timeout(WAIT, conn.recv()).await??;
    let got = *seen.lock().map_err(|_| "hook record poisoned")?;
    // T_Data_Connected seq 0 (0x40) plus the two high APCI bits of 0x300.
    assert_eq!(got, Some((0x43, 0, tool)));
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_with_line_swaps_devices() -> TestResult {
    let gw = MockGateway::builder()
        .device(MockDevice::new(ia("1.1.4")?))
        .start()
        .await?;
    let spare = ia("15.15.255")?;
    gw.with_line(|line| *line = vec![MockDevice::new(spare).with_programming(true)])?;
    let line = gw.devices()?;
    assert_eq!(line.len(), 1);
    assert_eq!(line[0].address, spare);
    assert!(line[0].programming);
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_restarts_its_send_sequence_on_connect() -> TestResult {
    let gw = MockGateway::builder()
        .keep_serving()
        .push_after_connect(
            Duration::ZERO,
            CemiFrame::group_write_packed(ga("1/1/1")?, ia("1.1.10")?, &[1]),
        )
        .start()
        .await?;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let hpai = match client.local_addr()? {
        std::net::SocketAddr::V4(v4) => {
            let mut h = vec![0x08, 0x01];
            h.extend_from_slice(&v4.ip().octets());
            h.extend_from_slice(&v4.port().to_be_bytes());
            h
        }
        std::net::SocketAddr::V6(_) => return Err("expected IPv4".into()),
    };
    let mut connect = hpai.clone();
    connect.extend_from_slice(&hpai);
    connect.extend_from_slice(&[0x04, 0x04, 0x02, 0x00]);
    let request = bussard_testkit::wire::frame(
        bussard_transport::knxnet::ServiceType::ConnectRequest,
        &connect,
    );
    let mut buf = [0u8; 256];
    for _ in 0..2 {
        client.send_to(&request, gw.addr()).await?;
        // CONNECT_RESPONSE, then the pushed indication.
        let _ = tokio::time::timeout(WAIT, client.recv_from(&mut buf)).await??;
        let (n, _) = tokio::time::timeout(WAIT, client.recv_from(&mut buf)).await??;
        let parsed = bussard_transport::knxnet::parse(&buf[..n])?;
        let tr = bussard_transport::knxnet::parse_tunneling_request(parsed.body)?;
        assert_eq!(tr.header.seq, 0, "every connection starts at sequence 0");
    }
    Ok(())
}

#[tokio::test]
async fn test_mock_gateway_push_once_after_connect_skips_a_probe_connection() -> TestResult {
    let gw = MockGateway::builder()
        .keep_serving()
        .push_once_after_connect(
            Duration::from_millis(150),
            CemiFrame::group_write_packed(ga("1/1/1")?, ia("1.1.10")?, &[1]),
        )
        .start()
        .await?;
    // A short probe connection, closed before the delay: nothing is pushed.
    let probe = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    probe.close().await?;
    // The long-lived session sees the frame exactly once.
    let mut conn = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let first = tokio::time::timeout(WAIT, conn.recv()).await??;
    assert_eq!(group_dest(&first.frame)?, "1/1/1");
    let again = tokio::time::timeout(Duration::from_millis(400), conn.recv()).await;
    assert!(again.is_err(), "the frame goes out once, not per CONNECT");
    conn.close().await?;
    Ok(())
}
