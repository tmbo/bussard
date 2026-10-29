//! Transport-layer conformance of the management connection against the
//! testkit mock gateway and [`MockDevice`]: the priority of the control and
//! management frames (03_03_04 Transport Layer §3.7, §3.8, §5.3; 03_03_07
//! Application Layer §3.2).

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::{DeviceConnection, write_individual_address};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockError, MockGateway, Reaction, TestResult};
use bussard_transport::cemi::{CemiFrame, Priority};
use bussard_transport::tpci::{self, TpciKind};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x15;

/// Starts a testkit gateway with `devices` on the line.
async fn start_mock(devices: Vec<MockDevice>) -> Result<MockGateway, MockError> {
    MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .devices(devices)
        .start()
        .await
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(addr)).await?)
}

/// A device that answers the descriptor read with mask `0x07B0`.
fn answering(addr: &str) -> Result<MockDevice, BoxError> {
    Ok(MockDevice::new(addr.parse()?)
        .with_mask(0x07B0)
        .with_hook(|dev, apci_val, _data| match apci_val {
            apci::A_DEVICE_DESCRIPTOR_READ => Some(Reaction::Answer(
                apci::A_DEVICE_DESCRIPTOR_RESPONSE,
                dev.mask.to_be_bytes().to_vec(),
            )),
            _ => Some(Reaction::Ack),
        }))
}

/// The client frames of one transport kind.
fn of_kind(sent: &[CemiFrame], want: fn(TpciKind) -> bool) -> Vec<&CemiFrame> {
    sent.iter()
        .filter(|f| f.group_destination().is_none() && want(tpci::classify(f.tpci_octet())))
        .collect()
}

#[tokio::test]
async fn test_connection_frames_go_out_at_system_priority() -> TestResult {
    let gw = start_mock(vec![answering("1.1.7")?]).await?;
    let mut bus = open_bus(gw.addr()).await?;
    let target: IndividualAddress = "1.1.7".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;

    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;
    assert_eq!(dev.device_descriptor().await?, 0x07B0);
    dev.disconnect().await?;
    write_individual_address(&mut bus, source, "1.1.8".parse()?).await?;

    let sent = gw.sent()?;
    let connects = of_kind(&sent, |k| matches!(k, TpciKind::Connect));
    let acks = of_kind(&sent, |k| matches!(k, TpciKind::Ack(_)));
    let disconnects = of_kind(&sent, |k| matches!(k, TpciKind::Disconnect));
    let data = of_kind(&sent, |k| matches!(k, TpciKind::NumberedData(_)));
    assert_eq!(connects.len(), 1);
    assert_eq!(acks.len(), 1, "the descriptor response is acknowledged");
    assert_eq!(disconnects.len(), 1);
    assert!(!data.is_empty());
    for frame in connects
        .iter()
        .chain(&acks)
        .chain(&disconnects)
        .chain(&data)
    {
        assert_eq!(frame.control1.priority, Priority::System, "{frame:?}");
        // Standard frame, not repeated, broadcast, system priority, ack requested.
        assert_eq!(frame.encode()[2], 0xB2, "{frame:?}");
    }
    let broadcasts: Vec<&CemiFrame> = sent
        .iter()
        .filter(|f| f.group_destination().is_some_and(|ga| ga.raw() == 0))
        .collect();
    assert_eq!(broadcasts.len(), 1, "one A_IndividualAddress_Write");
    assert_eq!(broadcasts[0].control1.priority, Priority::System);
    Ok(())
}
