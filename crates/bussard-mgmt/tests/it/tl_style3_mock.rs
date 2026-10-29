//! Transport-layer conformance of the management connection against the
//! testkit mock gateway and [`MockDevice`]: the priority of the control and
//! management frames (03_03_04 Transport Layer §3.7, §3.8, §5.3; 03_03_07
//! Application Layer §3.2) and the Style 3 error paths (03_03_04 §5.4.3 with
//! AN210 §2.2.1).

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::{DeviceConnection, MgmtError, Timeouts, write_individual_address};
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

/// A short budget so the timeout paths run in tens of milliseconds.
fn fast() -> Timeouts {
    Timeouts {
        ack_timeout: Duration::from_millis(80),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(80),
        absent_on_negative_confirmation: false,
    }
}

fn disconnects(sent: &[CemiFrame]) -> usize {
    of_kind(sent, |k| matches!(k, TpciKind::Disconnect)).len()
}

#[tokio::test]
async fn test_ack_timeout_after_an_answer_sends_one_t_disconnect() -> TestResult {
    // E18, A6: the device answers the first read and then stops acknowledging.
    // Giving up puts one T_Disconnect on the bus, so the device does not hold
    // the connection until its 6 s timeout and ignore the next T_Connect.
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let device = MockDevice::new("1.1.7".parse()?)
        .with_mask(0x07B0)
        .with_hook(move |dev, _apci, _data| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                Some(Reaction::Answer(
                    apci::A_DEVICE_DESCRIPTOR_RESPONSE,
                    dev.mask.to_be_bytes().to_vec(),
                ))
            } else {
                Some(Reaction::Silent)
            }
        });
    let gw = start_mock(vec![device]).await?;
    let mut bus = open_bus(gw.addr()).await?;
    let target: IndividualAddress = "1.1.7".parse()?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut dev = DeviceConnection::connect_with(&mut bus, target, source, fast()).await?;
    assert_eq!(dev.device_descriptor().await?, 0x07B0);
    let Err(err) = dev.device_descriptor().await else {
        return Err("the second read goes unacknowledged".into());
    };
    assert!(
        matches!(err, MgmtError::MidSessionSilence { exchanges: 1, .. }),
        "a device that stopped answering: {err:?}"
    );
    dev.disconnect().await?;
    let sent = gw.sent()?;
    assert_eq!(disconnects(&sent), 1, "exactly one T_Disconnect");
    let last = sent.last().ok_or("frames sent")?;
    assert_eq!(last.tpci_octet(), tpci::T_DISCONNECT);
    assert_eq!(last.control1.priority, Priority::System);
    Ok(())
}

#[tokio::test]
async fn test_nak_exhaustion_sends_one_t_disconnect() -> TestResult {
    // E13, A6: a device that NAKs every repetition gets one T_Disconnect.
    let device = MockDevice::new("1.1.7".parse()?).with_hook(|_, _, _| Some(Reaction::Nak));
    let gw = start_mock(vec![device]).await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut dev =
        DeviceConnection::connect_with(&mut bus, "1.1.7".parse()?, "0.0.255".parse()?, fast())
            .await?;
    let Err(err) = dev.device_descriptor().await else {
        return Err("a NAKing device fails the read".into());
    };
    assert!(matches!(err, MgmtError::Nak { .. }), "got {err:?}");
    dev.disconnect().await?;
    let sent = gw.sent()?;
    assert_eq!(disconnects(&sent), 1);
    let data = of_kind(&sent, |k| matches!(k, TpciKind::NumberedData(_)));
    assert_eq!(data.len(), 2, "the first send and one repetition");
    Ok(())
}

#[tokio::test]
async fn test_rejected_t_connect_fails_without_waiting() -> TestResult {
    // E20, A5: the interface reports a negative L_Data.con for the T_Connect
    // (no device acknowledged it). The connection fails at once on the
    // standard budget, without the 3 s acknowledge timeout, and sends
    // nothing more.
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .confirmations()
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let started = std::time::Instant::now();
    let mut dev = DeviceConnection::connect(&mut bus, "1.1.9".parse()?, "0.0.255".parse()?).await?;
    let Err(err) = dev.device_descriptor().await else {
        return Err("nobody is at 1.1.9".into());
    };
    assert!(matches!(err, MgmtError::NotConfirmed { .. }), "got {err:?}");
    assert!(!err.device_present());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "failed on the con, not the 3 s ACK timeout: {:?}",
        started.elapsed()
    );
    dev.disconnect().await?;
    assert_eq!(disconnects(&gw.sent()?), 0, "the connection never opened");
    Ok(())
}
