//! The management layer over a KNXnet/IP device management connection
//! (issue #523) against the `bussard-testkit` mock gateway: the same
//! `Layer4Connection` and property functions as over a tunnel, with the
//! extended property services carried as the local `M_PropRead.req` /
//! `M_PropWrite.req` and every other service as a cEMI `T_Data_Connected.req`.

use std::time::Duration;

use bussard_mgmt::property_ext::{self, PropertyExtAddress};
use bussard_mgmt::{Layer4Connection, MgmtError, read_device_descriptor};
use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway, MockKnxnet, TestResult};
use bussard_transport::devmgmt::{M_PROP_READ_REQ, M_PROP_WRITE_REQ, T_DATA_CONNECTED_REQ};
use bussard_transport::{ConnectionConfig, Transport};

/// The friendly name (PID 76) of the KNXnet/IP parameter object.
const FRIENDLY_NAME: PropertyExtAddress = PropertyExtAddress {
    object_type: 11,
    object_instance: 1,
    property_id: 76,
};

#[tokio::test]
async fn test_layer4_reads_and_writes_properties_over_device_management() -> TestResult {
    let target: IndividualAddress = "1.1.200".parse()?;
    let knxnet = MockKnxnet {
        friendly_name: "Bocklisch Alpha".to_string(),
        ..MockKnxnet::default()
    };
    let gw = MockGateway::builder()
        .interface_device(target)
        .device(
            MockDevice::new(target)
                .with_mask(0x0021)
                .with_knxnet_unlisted_writable(&knxnet, 8),
        )
        .idle_timeout(Duration::from_secs(10))
        .start()
        .await?;
    let mut dm = Transport::connect(&ConnectionConfig::device_management(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(
        &mut dm,
        target,
        IndividualAddress::from_raw(0),
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;

    assert_eq!(read_device_descriptor(&mut l4).await?, 0x0021);
    let name = property_ext::read_property_ext(&mut l4, FRIENDLY_NAME, 9, 1).await?;
    assert_eq!(name.data, b"Bocklisch");
    property_ext::write_property_ext_con(&mut l4, FRIENDLY_NAME, 5, 1, b"Gamma").await?;
    let name = property_ext::read_property_ext(&mut l4, FRIENDLY_NAME, 5, 1).await?;
    assert_eq!(name.data, b"Gamma");
    // A property the object lacks: the negative confirmation is the
    // device's refusal, as over a tunnel.
    let missing = PropertyExtAddress {
        property_id: 200,
        ..FRIENDLY_NAME
    };
    let refused = property_ext::read_property_ext(&mut l4, missing, 1, 1).await;
    assert!(
        matches!(refused, Err(MgmtError::ServiceRejected { .. })),
        "{refused:?}"
    );
    let _ = l4.disconnect().await;
    bussard_transport::BusConnection::close(dm).await?;

    let stats = gw.finish(Duration::from_secs(2)).await?;
    let codes: Vec<u8> = stats
        .device_configuration
        .iter()
        .filter_map(|c| c.first().copied())
        .collect();
    assert_eq!(
        codes,
        vec![
            T_DATA_CONNECTED_REQ,
            M_PROP_READ_REQ,
            M_PROP_WRITE_REQ,
            M_PROP_READ_REQ,
            M_PROP_READ_REQ
        ]
    );
    Ok(())
}
