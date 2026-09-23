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
