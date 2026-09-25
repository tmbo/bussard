//! Integration tests for [`bussard_mgmt::property_ext::read_property_ext_table`]
//! (issue #201): reading the security object's array properties back over a
//! KNX Data Secure session against a `bussard-testkit` mock device.
//!
//! All key material is SYNTHETIC.

use std::time::Duration;

use bussard_mgmt::property_ext::{
    self, OT_SECURITY, PID_GO_SECURITY_FLAGS, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE,
    PropertyExtAddress,
};
use bussard_mgmt::{Layer4Connection, MgmtError, SecureLayer, Timeouts};
use bussard_model::IndividualAddress;
use bussard_secure::{DataSecureSession, Key16};
use bussard_testkit::{BoxError, MockDevice, MockGateway, TestResult};
use bussard_transport::{ConnectionConfig, Transport};

/// The channel id the mock gateway hands out.
const CHANNEL: u8 = 0x31;

/// A synthetic tool key.
const TOOL_KEY: [u8; 16] = [0x5A; 16];

/// What one read produced, and the element reads the device served.
struct Run {
    result: Result<Vec<u8>, MgmtError>,
    reads: Vec<(u16, u8, u16)>,
}

/// Reads PID `pid` (`element_size` octets per element) from `device` over a
/// secured session with a 233-octet APDU budget.
async fn read(device: MockDevice, pid: u16, element_size: usize) -> Result<Run, BoxError> {
    let target = device.address;
    let gw = MockGateway::builder()
        .channel(CHANNEL)
        .idle_timeout(Duration::from_secs(30))
        .device(device.with_data_secure(TOOL_KEY))
        .start()
        .await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let source: IndividualAddress = "0.0.255".parse()?;
    let mut l4 = Layer4Connection::connect_with_secure(
        &mut bus,
        target,
        source,
        Timeouts::discovery(),
        SecureLayer::activated(DataSecureSession::new(Key16::new(TOOL_KEY))),
    )
    .await?;
    l4.set_max_apdu(Some(233));
    let result = property_ext::read_property_ext_table(
        &mut l4,
        PropertyExtAddress::security(pid),
        element_size,
    )
    .await;
    let _ = l4.disconnect().await;
    let reads = gw
        .devices()?
        .first()
        .map(|d| d.ext_reads.clone())
        .unwrap_or_default();
    Ok(Run { result, reads })
}

fn device() -> Result<MockDevice, BoxError> {
    Ok(MockDevice::new("1.1.12".parse()?))
}

#[tokio::test]
async fn test_read_property_ext_table_reads_1333_flags_in_ets_sized_chunks() -> TestResult {
    // 1333 group objects (the reference 1.1.12), object 1289 secured.
    let mut flags = vec![0u8; 1333];
    flags[1288] = 0x03;
    let dev = device()?.with_property_ext(OT_SECURITY, PID_GO_SECURITY_FLAGS, 1, &flags);
    let run = read(dev, PID_GO_SECURITY_FLAGS, 1).await?;
    assert_eq!(run.result?, flags);
    // The count, then 211-element chunks (233 - 13 - 9), as ETS writes them.
    assert_eq!(run.reads.first(), Some(&(61, 1, 0)));
    assert_eq!(run.reads.get(1), Some(&(61, 211, 1)));
    assert_eq!(run.reads.len(), 1 + 1333_usize.div_ceil(211));
    Ok(())
}

#[tokio::test]
async fn test_read_property_ext_table_halves_a_refused_chunk() -> TestResult {
    let table: Vec<u8> = (1u8..=24).collect(); // three 8-octet elements
    let dev = device()?
        .with_property_ext(OT_SECURITY, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, 8, &table)
        .with_ext_read_limit(1);
    let run = read(dev, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, 8).await?;
    assert_eq!(run.result?, table);
    // 3 refused, 1 served, then single elements.
    let starts: Vec<(u8, u16)> = run.reads.iter().skip(1).map(|r| (r.1, r.2)).collect();
    assert_eq!(starts, vec![(3, 1), (1, 1), (1, 2), (1, 3)]);
    Ok(())
}

#[tokio::test]
async fn test_read_property_ext_table_empty_and_refused() -> TestResult {
    let dev = device()?.with_property_ext(OT_SECURITY, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, 8, &[]);
    let run = read(dev, PID_SECURITY_INDIVIDUAL_ADDRESS_TABLE, 8).await?;
    assert!(run.result?.is_empty());
    // A property the device does not serve is refused.
    let run = read(device()?, PID_GO_SECURITY_FLAGS, 1).await?;
    assert!(
        matches!(run.result, Err(MgmtError::ServiceRejected { .. })),
        "a refused count is ServiceRejected"
    );
    Ok(())
}
