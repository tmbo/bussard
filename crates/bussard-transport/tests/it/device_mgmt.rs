//! Device management connections (issue #523) against the `bussard-testkit`
//! mock gateway: CRI `02 03`, DEVICE_CONFIGURATION_REQUEST/ACK over UDP, the
//! local property services and the transport-layer bridge.

use std::time::Duration;

use bussard_testkit::{MockDevice, MockGateway, MockKnxnet, TestResult, ia};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::devmgmt::{
    LocalProperty, M_PROP_READ_REQ, M_PROP_WRITE_REQ, T_DATA_CONNECTED_REQ, prop_read_req,
    prop_write_req,
};
use bussard_transport::knxnet::ServiceType;
use bussard_transport::tpci;
use bussard_transport::{
    BusConnection, ConnectionConfig, DeviceManagement, Transport, TransportError,
};

/// The KNXnet/IP parameter object's friendly name (PID 76).
const FRIENDLY_NAME: LocalProperty = LocalProperty {
    object_type: 11,
    instance: 1,
    pid: 76,
};

/// The interface 1.1.200 with its KNXnet/IP parameter object reached by type
/// only, as the Jung IPS 300 SREG.
fn interface() -> TestResult<MockDevice> {
    let knxnet = MockKnxnet {
        friendly_name: "Bocklisch Alpha".to_string(),
        ..MockKnxnet::default()
    };
    Ok(MockDevice::new(ia("1.1.200")?)
        .with_mask(0x0021)
        .with_knxnet_unlisted_writable(&knxnet, 8))
}

async fn gateway() -> TestResult<MockGateway> {
    Ok(MockGateway::builder()
        .interface_device(ia("1.1.200")?)
        .device(interface()?)
        .idle_timeout(Duration::from_secs(10))
        .start()
        .await?)
}

#[tokio::test]
async fn test_device_management_reads_and_writes_local_properties() -> TestResult {
    let gw = gateway().await?;
    let mut dm = DeviceManagement::connect(&ConnectionConfig::device_management(gw.addr())).await?;
    assert_eq!(dm.secure_user_id(), None);

    let read = prop_read_req(FRIENDLY_NAME, 9, 1).ok_or("fits")?;
    let con = dm.request_local(read, Duration::from_secs(2)).await?;
    assert_eq!(con.error, None);
    assert_eq!(con.data, b"Bocklisch");

    let write = prop_write_req(FRIENDLY_NAME, 5, 1, b"Gamma").ok_or("fits")?;
    let con = dm.request_local(write, Duration::from_secs(2)).await?;
    assert_eq!((con.write, con.count, con.error), (true, 5, None));

    // A property the object does not have: a negative confirmation.
    let missing = LocalProperty {
        pid: 200,
        ..FRIENDLY_NAME
    };
    let con = dm
        .request_local(
            prop_read_req(missing, 1, 1).ok_or("fits")?,
            Duration::from_secs(2),
        )
        .await?;
    assert_eq!((con.count, con.error), (0, Some(0x07)));
    BusConnection::close(dm).await?;

    let device = gw.devices()?.into_iter().next().ok_or("no device")?;
    let name = device.property_ext(11, 76).ok_or("no friendly name")?;
    assert!(name.starts_with(b"Gamma"), "{name:?}");
    let stats = gw.finish(Duration::from_secs(2)).await?;
    assert_eq!(stats.connects, 1);
    assert_eq!(stats.disconnects, 1);
    assert_eq!(
        stats
            .device_configuration
            .iter()
            .map(|c| c[0])
            .collect::<Vec<_>>(),
        vec![M_PROP_READ_REQ, M_PROP_WRITE_REQ, M_PROP_READ_REQ]
    );
    // Every answer of the server was acknowledged (UDP, 3/8/3 §2.3.2).
    assert_eq!(stats.device_configuration_acks, 3);
    assert!(
        stats
            .services
            .contains(&ServiceType::DeviceConfigurationRequest)
    );
    Ok(())
}

#[tokio::test]
async fn test_device_management_bridges_numbered_data_to_t_data_connected() -> TestResult {
    let gw = gateway().await?;
    let mut conn = Transport::connect(&ConnectionConfig::device_management(gw.addr())).await?;
    assert_eq!(conn.assigned_individual_address(), None);
    let tool = ia("0.0.0")?;
    let device = ia("1.1.200")?;
    conn.send(CemiFrame::t_control(device, tool, tpci::T_CONNECT))
        .await?;
    // A_DeviceDescriptor_Read (type 0) as numbered data, sequence 0.
    conn.send(CemiFrame::t_data_connected(
        device,
        tool,
        tpci::ndt(0),
        0x300,
        &[],
    ))
    .await?;
    // The bridge's T_ACK first, then the device's answer, numbered from 0.
    let ack = conn.recv().await?.frame;
    assert_eq!(ack.tpci_octet(), tpci::t_ack(0));
    assert_eq!(
        (ack.source, ack.individual_destination()),
        (device, Some(tool))
    );
    let answer = tokio::time::timeout(Duration::from_secs(2), conn.recv()).await??;
    assert_eq!(answer.frame.tpci_octet() & 0xFC, tpci::ndt(0));
    let bussard_transport::cemi::Apdu::Other { apci, data } = &answer.frame.apdu else {
        return Err("expected a management APDU".into());
    };
    assert_eq!((*apci, data.as_slice()), (0x340, &[0x00, 0x21][..]));
    conn.close().await?;

    let stats = gw.finish(Duration::from_secs(2)).await?;
    assert_eq!(
        stats
            .device_configuration
            .first()
            .and_then(|c| c.first())
            .copied(),
        Some(T_DATA_CONNECTED_REQ)
    );
    Ok(())
}

#[tokio::test]
async fn test_device_management_refuses_group_telegrams() -> TestResult {
    let gw = gateway().await?;
    let mut conn = Transport::connect(&ConnectionConfig::device_management(gw.addr())).await?;
    let write = CemiFrame::group_write_packed("1/0/1".parse()?, ia("0.0.0")?, &[1]);
    let err = conn.send(write).await.err().ok_or("refused")?;
    assert!(
        matches!(err, TransportError::NotOnDeviceManagement { .. }),
        "{err:?}"
    );
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_device_management_connect_refused_without_the_service() -> TestResult {
    // A server that serves tunnelling only answers E_CONNECTION_TYPE.
    let gw = MockGateway::builder().start().await?;
    let err = match DeviceManagement::connect(&ConnectionConfig::device_management(gw.addr())).await
    {
        Ok(_) => return Err("connected".into()),
        Err(err) => err,
    };
    assert!(
        matches!(err, TransportError::GatewayStatus { status: 0x22, .. }),
        "{err:?}"
    );
    Ok(())
}
