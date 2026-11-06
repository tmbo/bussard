//! Integration tests for [`bussard_mgmt::knxnet`] (issue #391): the KNXnet/IP
//! parameter object of a mock IP interface, read by object index with the
//! plain property services and by object type and instance with the extended
//! ones, with the same result.

use std::time::Duration;

use bussard_mgmt::knxnet::{
    FIRST_SECURE_PID, KnxnetAccess, read_knxnet_parameters, read_knxnet_property,
};
use bussard_mgmt::{Layer4Connection, Timeouts};
use bussard_model::IndividualAddress;
use bussard_testkit::{BoxError, MockDevice, MockGateway, MockKnxnet, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

const CHANNEL: u8 = 0x32;

fn knxnet() -> Result<MockKnxnet, BoxError> {
    Ok(MockKnxnet {
        tunnels: (22..=29)
            .map(|n| format!("1.1.{n}").parse())
            .collect::<Result<Vec<IndividualAddress>, _>>()?,
        friendly_name: "Bocklisch Alpha".to_string(),
        ..MockKnxnet::default()
    })
}

/// Reads the whole object through `access` from a mock interface at 1.1.200
/// (device object at index 0, the KNXnet/IP object at index 1).
async fn read_all(
    access: KnxnetAccess,
    max_apdu: Option<u16>,
) -> Result<(bussard_mgmt::knxnet::KnxnetValues, usize), BoxError> {
    let target: IndividualAddress = "1.1.200".parse()?;
    let device = MockDevice::new(target)
        .with_mask(0x0021)
        .with_knxnet(&knxnet()?);
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 =
        Layer4Connection::connect(&mut bus, target, source, Timeouts::discovery().into()).await?;
    l4.set_max_apdu(max_apdu);
    let values = read_knxnet_parameters(&mut l4, access).await?;
    let refused = read_knxnet_property(&mut l4, access, FIRST_SECURE_PID + 1, 1, false).await;
    assert!(refused.is_err(), "a KNXnet/IP Secure PID is never read");
    let _ = l4.disconnect().await;
    let writes = gw.devices()?.first().map(|d| d.writes).unwrap_or_default();
    Ok((values, writes))
}

#[tokio::test]
async fn test_read_knxnet_parameters_by_index() -> TestResult {
    let (v, writes) = read_all(KnxnetAccess::Index(1), None).await?;
    assert_eq!(writes, 0, "read-only");
    assert_eq!(v.individual_address, Some("1.1.200".parse()?));
    assert_eq!(v.additional_addresses.len(), 8);
    assert_eq!(v.additional_addresses[0], "1.1.22".parse()?);
    assert_eq!(v.additional_addresses[7], "1.1.29".parse()?);
    assert_eq!(v.current_assignment, Some(0x04));
    assert_eq!(v.current_ip, Some([192, 168, 1, 74]));
    assert_eq!(v.mac, Some([0x00, 0x00, 0x5E, 0x00, 0x53, 0x01]));
    assert_eq!(v.capabilities, Some(0x0003));
    assert_eq!(v.friendly_name.as_deref(), Some("Bocklisch Alpha"));
    Ok(())
}

#[tokio::test]
async fn test_read_knxnet_parameters_by_type_and_instance_matches_index() -> TestResult {
    let (by_index, _) = read_all(KnxnetAccess::Index(1), Some(55)).await?;
    let (by_type, writes) = read_all(KnxnetAccess::Ext { instance: 1 }, Some(55)).await?;
    assert_eq!(writes, 0);
    assert_eq!(by_type, by_index);
    Ok(())
}

#[tokio::test]
async fn test_read_knxnet_parameters_on_another_instance_is_empty() -> TestResult {
    let (v, _) = read_all(KnxnetAccess::Ext { instance: 2 }, None).await?;
    assert_eq!(v, bussard_mgmt::knxnet::KnxnetValues::default());
    Ok(())
}

/// Opens a connection to `device` (at 1.1.200) with the standard budget and
/// runs `f` on it.
async fn with_device<T>(
    device: MockDevice,
    f: impl AsyncFnOnce(&mut Layer4Connection<&mut Transport>) -> Result<T, BoxError>,
) -> Result<T, BoxError> {
    let target = device.address;
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device)
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect(
        &mut bus,
        target,
        source,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let out = f(&mut l4).await;
    let _ = l4.disconnect().await;
    out
}

/// The IPS 300 SREG shape (issue #391): the walk lists no object type 11, the
/// object answers by type and instance. The probe finds it and the extended
/// read returns what the by-index read of a listed object returns.
#[tokio::test]
async fn test_probe_knxnet_ext_finds_an_unlisted_object() -> TestResult {
    let device = MockDevice::new("1.1.200".parse()?)
        .with_mask(0x0021)
        .with_knxnet_unlisted(&knxnet()?);
    let values = with_device(device, async |l4| {
        assert!(
            bussard_mgmt::knxnet::knxnet_index_from_io_list(l4)
                .await?
                .is_none()
        );
        assert!(bussard_mgmt::knxnet::probe_knxnet_ext(l4, 1).await?);
        Ok(read_knxnet_parameters(l4, KnxnetAccess::Ext { instance: 1 }).await?)
    })
    .await?;
    let (by_index, _) = read_all(KnxnetAccess::Index(1), None).await?;
    assert_eq!(values, by_index);
    Ok(())
}

/// A device that `T_ACK`s an extended read and never answers (knx-sim's plain
/// devices, and any device without the extended services): the probe says
/// "no object" after the short probe timeout, not the 3 s response timeout,
/// and the connection still serves the next read.
#[tokio::test]
async fn test_probe_knxnet_ext_on_a_silent_device_keeps_the_connection() -> TestResult {
    let device = MockDevice::new("1.1.5".parse()?).with_hook(|_, apci, _| {
        (apci == bussard_mgmt::property_ext::A_PROPERTY_EXT_VALUE_READ)
            .then_some(bussard_testkit::Reaction::Ack)
    });
    let (found, elapsed, object_type) = with_device(device, async |l4| {
        let started = std::time::Instant::now();
        let found = bussard_mgmt::knxnet::probe_knxnet_ext(l4, 1).await?;
        let elapsed = started.elapsed();
        let object_type = bussard_mgmt::probe_object_type(l4, 0).await?;
        Ok((found, elapsed, object_type))
    })
    .await?;
    assert!(!found);
    assert!(
        elapsed < Duration::from_millis(2000),
        "the probe waited {elapsed:?}"
    );
    assert_eq!(object_type, Some(0), "the connection is still usable");
    Ok(())
}

/// A device that answers the extended read with zero elements: no object, at
/// once.
#[tokio::test]
async fn test_probe_knxnet_ext_on_a_refusing_device_is_false() -> TestResult {
    let device = MockDevice::new("1.1.5".parse()?);
    let found = with_device(device, async |l4| {
        Ok(bussard_mgmt::knxnet::probe_knxnet_ext(l4, 1).await?)
    })
    .await?;
    assert!(!found);
    Ok(())
}

/// `PID_IO_LIST` as a second source of the object's index.
#[tokio::test]
async fn test_knxnet_index_from_io_list_reads_the_list() -> TestResult {
    let device = MockDevice::new("1.1.200".parse()?).with_knxnet(&knxnet()?);
    let index = with_device(device, async |l4| {
        Ok(bussard_mgmt::knxnet::knxnet_index_from_io_list(l4).await?)
    })
    .await?;
    assert_eq!(index, Some(1));
    Ok(())
}
