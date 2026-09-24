//! Integration tests for the `bussard assign` primitives against an in-process
//! mock KNX device reached through the mock-gateway (tunneling) pattern.
//!
//! The testkit mock device understands the **broadcast** management services assign uses:
//! a device in programming mode answers `A_IndividualAddress_Read` (source = its
//! current address), applies an `A_IndividualAddress_Write` (adopting the new
//! address and leaving programming mode), and afterwards answers a connected
//! `A_DeviceDescriptor_Read` on the NEW address. A serial-number variant answers
//! `A_IndividualAddressSerialNumber_Read` and applies the serial-number write.
//!
//! This exercises the full round trip: discover → write → verify.

use std::net::SocketAddrV4;
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::{
    DeviceConnection, broadcast, read_individual_address_by_serial, write_individual_address,
    write_individual_address_by_serial,
};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockError, MockGateway, Reaction, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x15;

/// A tight programming-mode collection window for the broadcast tests. The mock
/// gateway answers instantly, so this replaces the production 1500ms window
/// without weakening any assertion.
const SHORT_WINDOW: Duration = Duration::from_millis(150);

/// The manufacturer id every simulated device reports.
const MANUFACTURER: u16 = 0x0083;
/// The order info every simulated device reports.
const ORDER: &[u8] = b"MDT-JAL0410";

/// Starts a testkit gateway with `devices` on the line.
///
/// The testkit devices answer the broadcast services (`A_IndividualAddress_Read`
/// from devices in programming mode, the address write that adopts the address
/// and leaves programming mode, and the serial-number read and write) natively.
/// The connected services go through [`connected_response`].
async fn start_mock(devices: Vec<MockDevice>) -> Result<MockGateway, MockError> {
    MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(5))
        .devices(devices)
        .start()
        .await
}

/// A connected request is always `T_ACK`ed; a known one is also answered.
fn connected_response(device: &MockDevice, apci_val: u16, data: &[u8]) -> Reaction {
    match apci_val {
        apci::A_DEVICE_DESCRIPTOR_READ => Reaction::Answer(
            apci::A_DEVICE_DESCRIPTOR_RESPONSE,
            device.mask.to_be_bytes().to_vec(),
        ),
        apci::A_PROPERTY_VALUE_READ => {
            let Some(pv) = apci::decode_property_value_read(data) else {
                return Reaction::Ack;
            };
            let value = match pv.property_id {
                apci::PID_MANUFACTURER_ID => MANUFACTURER.to_be_bytes().to_vec(),
                apci::PID_SERIAL_NUMBER => device.serial.to_vec(),
                apci::PID_ORDER_INFO => ORDER.to_vec(),
                _ => Vec::new(),
            };
            let count = if value.is_empty() { 0u8 } else { 1 };
            let mut resp = vec![
                pv.object_index,
                pv.property_id,
                (count << 4) | ((pv.start >> 8) as u8 & 0x0f),
                (pv.start & 0xff) as u8,
            ];
            resp.extend_from_slice(&value);
            Reaction::Answer(apci::A_PROPERTY_VALUE_RESPONSE, resp)
        }
        _ => Reaction::Ack,
    }
}

async fn open_bus(addr: SocketAddrV4) -> Result<Transport, BoxError> {
    let config = ConnectionConfig::tunnel(addr);
    Ok(Transport::connect(&config).await?)
}

/// Returns the error of a call that must fail.
fn must_fail<T, E>(result: Result<T, E>) -> Result<E, BoxError> {
    match result {
        Ok(_) => Err("expected the call to fail, it succeeded".into()),
        Err(e) => Ok(e),
    }
}

/// A simulated device: mask `0x07B0`, serial `00 01 02 03 04 05`.
fn device(addr: &str, programming: bool) -> Result<MockDevice, BoxError> {
    Ok(MockDevice::new(addr.parse()?)
        .with_mask(0x07B0)
        .with_programming(programming)
        .with_serial([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        .with_hook(|dev, apci_val, data| Some(connected_response(dev, apci_val, data))))
}

#[tokio::test]
async fn discover_write_and_verify_round_trip() -> TestResult {
    // A factory device in programming mode at 15.15.255.
    let gw = start_mock(vec![device("15.15.255", true)?]).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;

    // 1. Discover exactly one device in programming mode. The mock answers
    //    instantly, so a short collection window keeps the test fast without
    //    changing what it proves.
    let found =
        broadcast::devices_in_programming_mode_within(&mut bus, source, SHORT_WINDOW).await?;
    assert_eq!(found, vec!["15.15.255".parse()?]);

    // 2. Write the new address.
    let target: IndividualAddress = "1.1.7".parse()?;
    write_individual_address(&mut bus, source, target).await?;

    // 3. Verify: connect to the NEW address and read the descriptor.
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;
    let mask = dev.device_descriptor().await?;
    assert_eq!(mask, 0x07B0);
    let order = dev.read_device_property(apci::PID_ORDER_INFO).await?;
    assert_eq!(order, b"MDT-JAL0410");
    dev.disconnect().await?;

    // The device left programming mode and now lives at the new address.
    {
        let devs = gw.devices()?;
        assert_eq!(devs[0].address, target);
        assert!(!devs[0].programming);
    }

    drop(gw);
    Ok(())
}

#[tokio::test]
async fn zero_devices_in_programming_mode_is_empty() -> TestResult {
    let gw = start_mock(vec![device("1.1.4", false)?]).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let found =
        broadcast::devices_in_programming_mode_within(&mut bus, source, SHORT_WINDOW).await?;
    assert!(found.is_empty());
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn two_devices_in_programming_mode_both_reported() -> TestResult {
    let gw = start_mock(vec![device("15.15.255", true)?, device("15.15.254", true)?]).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let found =
        broadcast::devices_in_programming_mode_within(&mut bus, source, SHORT_WINDOW).await?;
    assert_eq!(found.len(), 2, "both responders surface: {found:?}");
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn verify_fails_when_address_not_applied() -> TestResult {
    // The device stays at its old address (models a write that did not land):
    // it is NOT in programming mode and lives at 15.15.255, so a connect to the
    // intended new address 1.1.7 finds nobody.
    let gw = start_mock(vec![device("15.15.255", false)?]).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let target: IndividualAddress = "1.1.7".parse()?;

    // Nobody answers at 1.1.7, so this connect rules out an absent address at
    // `2 × ack_timeout`. discovery()'s 1500ms attempts would waste ~3s; a tight
    // budget keeps the test fast without changing what it proves.
    let fast = bussard_mgmt::Timeouts {
        ack_timeout: Duration::from_millis(50),
        max_repetitions: 1,
        response_timeout: Duration::from_millis(50),
    };
    let mut dev = DeviceConnection::connect_with(&mut bus, target, source, fast).await?;
    let err = must_fail(dev.device_descriptor().await)?;
    assert!(
        !err.device_present(),
        "no device at the new address: {err:?}"
    );
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn serial_number_read_and_write_round_trip() -> TestResult {
    // A device NOT in programming mode, addressed by its serial number instead.
    let gw = start_mock(vec![device("15.15.255", false)?]).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let serial = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

    // Read the current address by serial number (no button press).
    let current = read_individual_address_by_serial(&mut bus, source, serial).await?;
    assert_eq!(current, Some("15.15.255".parse()?));

    // Write a new address by serial number.
    let target: IndividualAddress = "1.1.9".parse()?;
    write_individual_address_by_serial(&mut bus, source, serial, target).await?;

    // Verify on the new address.
    let mut dev = DeviceConnection::connect(&mut bus, target, source).await?;
    assert_eq!(dev.device_descriptor().await?, 0x07B0);
    dev.disconnect().await?;

    {
        let devs = gw.devices()?;
        assert_eq!(devs[0].address, target);
    }
    drop(gw);
    Ok(())
}

#[tokio::test]
async fn serial_read_unknown_serial_is_none() -> TestResult {
    let gw = start_mock(vec![device("15.15.255", false)?]).await?;
    let addr = gw.addr();

    let mut bus = open_bus(addr).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let unknown = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    // An unknown serial is ruled out only once the window elapses; a short one
    // keeps this absent-path test fast.
    let found = broadcast::read_individual_address_by_serial_within(
        &mut bus,
        source,
        unknown,
        SHORT_WINDOW,
    )
    .await?;
    assert_eq!(found, None);
    drop(gw);
    Ok(())
}
