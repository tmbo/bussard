//! The KNXnet/IP parameter writes of an IP-enabled device's download (issue
//! #455) against a `bussard-testkit` device: the program the ALLinBOX 1612
//! sweep capture shows, written to the object the device has, each write
//! read back; a device without the object fails the step.

use bussard_download::{KnxnetIpProgram, PropObject, knxnet_ip_program, write_knxnet_ip};
use bussard_mgmt::connection::Layer4Connection;
use bussard_model::knxnet::KnxnetConfig;
use bussard_prod::application::ApplicationProgram;
use bussard_testkit::{MockDevice, MockGateway, MockKnxnet, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

/// The ALLinBOX 1612 1.3 program (`M-0071_A-4A11-13-48E1`, mask 07B0, five
/// tunnelling addresses, not Data-Secure-capable) with the sweep project's
/// `[knxnet]` table.
fn allinbox_program() -> TestResult<KnxnetIpProgram> {
    let app = ApplicationProgram {
        id: "M-0071_A-4A11-13-48E1".to_string(),
        additional_addresses_count: Some(5),
        ..ApplicationProgram::default()
    };
    let config = KnxnetConfig {
        friendly_name: Some("ALLinBOX 1612".to_string()),
        tunnels: ["1.1.251", "1.1.252", "1.1.253", "1.1.254", "1.1.255"]
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()?,
        ..KnxnetConfig::default()
    };
    knxnet_ip_program(&app, 0x07B0, ia("1.1.1")?, Some(&config))?
        .ok_or_else(|| "an IP-enabled application gets the writes".into())
}

/// Runs `program` against `device` on a fresh mock gateway and returns the
/// device afterwards.
async fn run(device: MockDevice, program: &KnxnetIpProgram) -> TestResult<(MockDevice, String)> {
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?;
    let mut l4 = Layer4Connection::connect(&mut bus, ia("1.1.1")?, ia("0.0.255")?).await?;
    let result = write_knxnet_ip(&mut l4, program).await;
    let _ = l4.disconnect().await;
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    Ok((
        dev,
        match result {
            Ok(()) => String::new(),
            Err(err) => err.to_string(),
        },
    ))
}

/// A System B device whose object table puts the KNXnet/IP parameter object
/// at `index` (filler objects before it), holding the interface defaults.
fn ip_device(index: usize) -> TestResult<MockDevice> {
    let mut types = vec![0u16, 1, 2, 3, 4, 5];
    types.truncate(index);
    let knxnet = MockKnxnet {
        tunnels: Vec::new(),
        friendly_name: String::new(),
        ttl: 16,
        ..MockKnxnet::default()
    };
    Ok(MockDevice::new(ia("1.1.1")?)
        .with_object_types(&types)
        .with_knxnet_writable(&knxnet, 16))
}

fn assert_written(dev: &MockDevice) {
    assert_eq!(dev.knxnet_property(51), Some(&[0x00, 0x00][..]));
    assert_eq!(dev.knxnet_property(66), Some(&[224, 0, 23, 12][..]));
    assert_eq!(dev.knxnet_property(67), Some(&[0x20][..]));
    let mut name = b"ALLinBOX 1612".to_vec();
    name.resize(30, 0);
    assert_eq!(dev.knxnet_property(76), Some(&name[..]));
    assert_eq!(dev.knxnet_property(55), Some(&[0x04][..]));
    assert_eq!(
        dev.knxnet_property(53),
        Some(&[0x11, 0xFB, 0x11, 0xFC, 0x11, 0xFD, 0x11, 0xFE, 0x11, 0xFF][..])
    );
}

/// The object at index 6, where ETS writes it on 07B0: the type check passes
/// and every value lands there.
#[tokio::test]
async fn test_write_knxnet_ip_writes_the_capture_values_at_object_6() -> TestResult {
    let program = allinbox_program()?;
    assert_eq!(program.object, PropObject::Index(6));
    let (dev, err) = run(ip_device(6)?, &program).await?;
    assert_eq!(err, "");
    assert_written(&dev);
    Ok(())
}

/// The object at another index: `PID_OBJECT_TYPE` at 6 is not 11, so the
/// device's object list names the index and the values land there.
#[tokio::test]
async fn test_write_knxnet_ip_finds_the_object_at_another_index() -> TestResult {
    let program = allinbox_program()?;
    let (dev, err) = run(ip_device(4)?, &program).await?;
    assert_eq!(err, "");
    assert_written(&dev);
    Ok(())
}

/// A device without the object fails the step with the reason, before any
/// write.
#[tokio::test]
async fn test_write_knxnet_ip_fails_without_the_object() -> TestResult {
    let program = allinbox_program()?;
    let device = MockDevice::new(ia("1.1.1")?).with_object_types(&[0, 1, 2, 3, 4, 5, 9]);
    let (dev, err) = run(device, &program).await?;
    assert!(err.contains("no KNXnet/IP parameter object"), "{err}");
    assert_eq!(dev.writes, 0);
    Ok(())
}
