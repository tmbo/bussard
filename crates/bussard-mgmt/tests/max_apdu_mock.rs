//! `PID_MAX_APDU_LENGTH` negotiation once per connection (issue #215) against
//! the testkit mock device: a value, an answer without a value, and a read the
//! device acknowledges but never answers each cost exactly one request per
//! connection, and the unanswered read leaves the connection usable.

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::apci::{self, A_PROPERTY_VALUE_READ};
use bussard_mgmt::{Layer4Connection, MaxApduAbsence, Timeouts, read_device_descriptor};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x32;
const PID_MAX_APDU_LENGTH: u8 = 56;

fn target() -> Result<IndividualAddress, BoxError> {
    Ok("1.1.12".parse()?)
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(addr)).await?)
}

/// The `PID_MAX_APDU_LENGTH` reads in a request log.
fn max_apdu_reads(requests: &[(u16, Vec<u8>)]) -> usize {
    requests
        .iter()
        .filter(|(apci, _)| *apci == A_PROPERTY_VALUE_READ)
        .filter_map(|(_, data)| apci::decode_property_value_read(data))
        .filter(|pv| pv.object_index == 0 && pv.property_id == PID_MAX_APDU_LENGTH)
        .count()
}

/// Negotiates three times on one connection, then reads the descriptor on
/// it; returns the negotiated value, the absence verdict, whether the
/// descriptor read succeeded, and the number of max-APDU reads sent.
async fn negotiate_thrice(
    device: MockDevice,
) -> Result<(Option<u16>, Option<MaxApduAbsence>, bool, usize), BoxError> {
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(10))
        .device(device)
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    // A short response window keeps the unanswered case quick; the rule
    // under test does not depend on its length.
    let timeouts = Timeouts {
        response_timeout: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let mut l4 =
        Layer4Connection::connect_with(&mut bus, target()?, "0.0.255".parse()?, timeouts).await?;
    let first = l4.negotiate_max_apdu().await?;
    let second = l4.negotiate_max_apdu().await?;
    let third = l4.negotiate_max_apdu().await?;
    assert_eq!((first, second), (third, third));
    let absence = l4.max_apdu_absence();
    let usable = read_device_descriptor(&mut l4).await.is_ok();
    let _ = l4.disconnect().await;
    let requests = gw.with_device(target()?, |d| d.requests.clone())?;
    Ok((first, absence, usable, max_apdu_reads(&requests)))
}

#[tokio::test]
async fn test_negotiate_max_apdu_reads_a_value_once() -> TestResult {
    let device =
        MockDevice::new(target()?).with_property(0, PID_MAX_APDU_LENGTH, 2, &233u16.to_be_bytes());
    let (value, absence, usable, reads) = negotiate_thrice(device).await?;
    assert_eq!((value, absence, usable, reads), (Some(233), None, true, 1));
    Ok(())
}

#[tokio::test]
async fn test_negotiate_max_apdu_remembers_an_answered_absence() -> TestResult {
    // The mock answers an unknown property with zero elements. Before issue
    // #215 each of the three calls read it again.
    let (value, absence, usable, reads) = negotiate_thrice(MockDevice::new(target()?)).await?;
    assert_eq!(
        (value, absence, usable, reads),
        (None, Some(MaxApduAbsence::Answered), true, 1)
    );
    Ok(())
}

#[tokio::test]
async fn test_negotiate_max_apdu_reopens_after_an_unanswered_read() -> TestResult {
    // Acknowledged, never answered: the response timeout marked the
    // connection closed, so the descriptor read after it failed with
    // `Disconnected`, and every call paid the timeout again.
    let device = MockDevice::new(target()?).with_hook(|_, apci, data| {
        let is_max_apdu = apci == A_PROPERTY_VALUE_READ
            && apci::decode_property_value_read(data)
                .is_some_and(|pv| pv.object_index == 0 && pv.property_id == PID_MAX_APDU_LENGTH);
        is_max_apdu.then_some(Reaction::Ack)
    });
    let (value, absence, usable, reads) = negotiate_thrice(device).await?;
    assert_eq!(
        (value, absence, usable, reads),
        (None, Some(MaxApduAbsence::Unanswered), true, 1)
    );
    Ok(())
}

#[tokio::test]
async fn test_set_max_apdu_absent_skips_the_read() -> TestResult {
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(10))
        .device(MockDevice::new(target()?))
        .start()
        .await?;
    let mut bus = open_bus(gw.addr()).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, target()?, "0.0.255".parse()?).await?;
    l4.set_max_apdu_absent();
    assert_eq!(l4.negotiate_max_apdu().await?, None);
    assert_eq!(l4.max_memory_chunk(), 12, "the conservative chunk stays");
    let _ = l4.disconnect().await;
    let requests = gw.with_device(target()?, |d| d.requests.clone())?;
    assert_eq!(max_apdu_reads(&requests), 0);
    Ok(())
}
