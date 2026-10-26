//! Property operations in load procedures (issue #390): a property-only
//! procedure (the Jung IPS 300 SREG's shape, mask 0021) planned and flashed
//! against a `bussard-testkit` device, the extended-service fallback, a failed
//! precondition, a `Verify` mismatch and the element chunking of a
//! `Count`-carrying write.

use std::collections::BTreeMap;

use bussard_download::{FlashStep, PlanError, PropObject, Session, flash, plan_flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::WriteError;
use bussard_prod::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

/// The KNXnet/IP parameter object type.
const OT_KNXNETIP: u16 = 11;
/// The vendor object of the IPS 300 SREG's telegram-rate limit.
const OT_VENDOR: u16 = 50001;

/// A fabricated program with the IPS 300 SREG's procedure: two compares on the
/// device object (by type and by index), then three writes whose values the
/// property-located parameters compose.
fn ip_interface_app(mask: &str) -> TestResult<ApplicationProgram> {
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="M-0004_A-1" ApplicationNumber="22" ApplicationVersion="16"
        MaskVersion="MV-{mask}" Name="IP">
      <Static>
       <ParameterTypes>
        <ParameterType Id="M-0004_A-1_PT-ip" Name="ip"><TypeIPAddress AddressType="HostAddress" /></ParameterType>
        <ParameterType Id="M-0004_A-1_PT-u8" Name="u8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
       </ParameterTypes>
       <Parameters>
        <Parameter Id="M-0004_A-1_P-10" Name="timeout" ParameterType="M-0004_A-1_PT-u8" Value="10">
         <Property ObjectType="11" PropertyId="204" Offset="0" BitOffset="0" />
        </Parameter>
        <Parameter Id="M-0004_A-1_P-100" Name="ip1" ParameterType="M-0004_A-1_PT-ip" Value="192.168.255.255">
         <Property ObjectType="11" PropertyId="205" Offset="0" BitOffset="0" />
        </Parameter>
        <Parameter Id="M-0004_A-1_P-101" Name="ip2" ParameterType="M-0004_A-1_PT-ip" Value="10.0.0.2">
         <Property ObjectType="11" PropertyId="205" Offset="4" BitOffset="0" />
        </Parameter>
        <Parameter Id="M-0004_A-1_P-1" Name="rate" ParameterType="M-0004_A-1_PT-u8" Value="50">
         <Property ObjectType="50001" PropertyId="211" Offset="0" BitOffset="0" />
        </Parameter>
       </Parameters>
       <ParameterRefs>
        <ParameterRef Id="M-0004_A-1_P-10_R-10" RefId="M-0004_A-1_P-10" />
        <ParameterRef Id="M-0004_A-1_P-100_R-100" RefId="M-0004_A-1_P-100" />
        <ParameterRef Id="M-0004_A-1_P-101_R-101" RefId="M-0004_A-1_P-101" />
        <ParameterRef Id="M-0004_A-1_P-1_R-1" RefId="M-0004_A-1_P-1" Value="40" />
       </ParameterRefs>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlCompareProp InlineData="0004" ObjType="0" PropId="12" />
         <LdCtrlCompareProp InlineData="000000160000" Mask="FFFFFFFF0000" ObjIdx="0" PropId="78" />
         <LdCtrlWriteProp ObjType="11" PropId="204" Verify="true" />
         <LdCtrlWriteProp ObjType="11" PropId="205" Count="2" Verify="true" />
         <LdCtrlWriteProp ObjType="50001" PropId="211" Verify="false" />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    );
    Ok(parse_application_program("M-0004_A-1", xml.as_bytes())?)
}

/// The values the fabricated program's parameters compose.
const TIMEOUT: [u8; 1] = [10];
const PREFERRED: [u8; 8] = [192, 168, 255, 255, 10, 0, 0, 2];
const RATE: [u8; 1] = [40];

/// A device answering the procedure's compares, with the KNXnet/IP and vendor
/// objects behind both the extended services and their indices.
fn ip_interface(ext: bool) -> TestResult<MockDevice> {
    let mut device = MockDevice::new(ia("1.1.200")?)
        .with_mask(0x0021)
        .with_manufacturer(0x0004)
        .with_property(0, 78, 6, &[0, 0, 0, 0x16, 0x12, 0x34])
        .with_object_types(&[0, OT_KNXNETIP, OT_VENDOR]);
    if ext {
        device = device
            .with_writable_property_ext(OT_KNXNETIP, 204, 1, &[0])
            .with_writable_property_ext(OT_KNXNETIP, 205, 4, &[0; 8])
            .with_writable_property_ext(OT_VENDOR, 211, 1, &[0]);
    } else {
        device = device
            .with_writable_property(1, 204, 1, &[0])
            .with_writable_property(1, 205, 4, &[0; 8])
            .with_writable_property(2, 211, 1, &[0]);
    }
    Ok(device)
}

/// Opens the client side: a tunnel to `gw` and an L4 connection to 1.1.200.
async fn connect(gw: &MockGateway) -> TestResult<Transport> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?)
}

fn plan_for(app: &ApplicationProgram, mask: u16) -> Result<bussard_download::FlashPlan, PlanError> {
    plan_flash(
        app,
        "1.1.200",
        mask,
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
}

#[test]
fn test_plan_flash_lowers_a_property_only_procedure_on_mask_0021() -> TestResult {
    let app = ip_interface_app("0021")?;
    let plan = plan_for(&app, 0x0021)?;
    assert!(plan.is_property_only());
    assert_eq!(
        plan.steps,
        vec![
            FlashStep::CompareProp {
                object: PropObject::Index(0),
                prop_id: 12,
                expected: Some(vec![0x00, 0x04]),
                mask: None,
            },
            FlashStep::CompareProp {
                object: PropObject::Index(0),
                prop_id: 78,
                expected: Some(vec![0, 0, 0, 0x16, 0, 0]),
                mask: Some(vec![0xFF, 0xFF, 0xFF, 0xFF, 0, 0]),
            },
            FlashStep::WriteProp {
                object: PropObject::Type {
                    object_type: OT_KNXNETIP,
                    occurrence: 0,
                },
                prop_id: 204,
                value: TIMEOUT.to_vec(),
                start_element: 1,
                count: 1,
                verify: true,
            },
            FlashStep::WriteProp {
                object: PropObject::Type {
                    object_type: OT_KNXNETIP,
                    occurrence: 0,
                },
                prop_id: 205,
                value: PREFERRED.to_vec(),
                start_element: 1,
                count: 2,
                verify: true,
            },
            FlashStep::WriteProp {
                object: PropObject::Type {
                    object_type: OT_VENDOR,
                    occurrence: 0,
                },
                prop_id: 211,
                value: RATE.to_vec(),
                start_element: 1,
                count: 1,
                verify: false,
            },
        ]
    );
    Ok(())
}

#[test]
fn test_plan_flash_keeps_refusing_a_property_only_procedure_on_other_families() -> TestResult {
    let app = ip_interface_app("0012")?;
    match plan_for(&app, 0x0012) {
        Err(PlanError::NotSystemB { device_mask, .. }) => assert_eq!(device_mask, 0x0012),
        other => return Err(format!("expected NotSystemB, got {other:?}").into()),
    }
    // The mask match still applies on 0021.
    let app = ip_interface_app("0025")?;
    assert!(matches!(
        plan_for(&app, 0x0021),
        Err(PlanError::MaskMismatch { .. })
    ));
    Ok(())
}

#[test]
fn test_plan_flash_refuses_a_write_prop_without_a_value_source() -> TestResult {
    let mut app = ip_interface_app("0021")?;
    // No parameter is located in PID 205 any more.
    for param in app.parameters.values_mut() {
        if param
            .property
            .as_ref()
            .is_some_and(|p| p.property_id == 205)
        {
            param.property = None;
        }
    }
    match plan_for(&app, 0x0021) {
        Err(PlanError::UnsupportedWriteProp { reason, .. }) => {
            assert!(reason.contains("object type 11 PID 205"), "{reason}");
        }
        other => return Err(format!("expected UnsupportedWriteProp, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn test_flash_property_procedure_writes_and_reads_back() -> TestResult {
    let gw = MockGateway::builder()
        .device(ip_interface(true)?)
        .start()
        .await?;
    let app = ip_interface_app("0021")?;
    let plan = plan_for(&app, 0x0021)?;
    let mut bus = connect(&gw).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.200")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    assert!(outcome.property_only);
    assert!(outcome.ok(), "{outcome:?}");
    let dev = gw.with_device(ia("1.1.200")?, |d| d.clone())?;
    assert_eq!(dev.property_ext(OT_KNXNETIP, 204), Some(&TIMEOUT[..]));
    assert_eq!(dev.property_ext(OT_KNXNETIP, 205), Some(&PREFERRED[..]));
    assert_eq!(dev.property_ext(OT_VENDOR, 211), Some(&RATE[..]));
    // The writes and nothing else (no memory, no load-state machine): PID
    // 205's two 4-octet elements go one per request on the 15-octet budget
    // the unnegotiated connection keeps (6 octets after the extended header).
    assert_eq!(dev.writes, 4);
    Ok(())
}

#[tokio::test]
async fn test_flash_property_procedure_falls_back_to_the_object_index() -> TestResult {
    let gw = MockGateway::builder()
        .device(ip_interface(false)?)
        .start()
        .await?;
    let app = ip_interface_app("0021")?;
    let plan = plan_for(&app, 0x0021)?;
    let mut bus = connect(&gw).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.200")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    assert!(outcome.ok(), "{outcome:?}");
    let dev = gw.with_device(ia("1.1.200")?, |d| d.clone())?;
    assert_eq!(dev.property(1, 204), Some(&TIMEOUT[..]));
    assert_eq!(dev.property(1, 205), Some(&PREFERRED[..]));
    assert_eq!(dev.property(2, 211), Some(&RATE[..]));
    Ok(())
}

#[tokio::test]
async fn test_flash_property_procedure_stops_on_a_failed_precondition() -> TestResult {
    let device = ip_interface(true)?.with_manufacturer(0x0083);
    let gw = MockGateway::builder().device(device).start().await?;
    let app = ip_interface_app("0021")?;
    let plan = plan_for(&app, 0x0021)?;
    let mut bus = connect(&gw).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.200")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let err = flash(
        &mut session,
        &plan,
        bussard_download::FlashOptions::default(),
        |_| {},
    )
    .await
    .err()
    .ok_or("a manufacturer mismatch must stop the flash")?;
    let _ = session.into_disconnect().await;
    assert!(
        matches!(
            err,
            WriteError::PropCompareMismatch {
                property_id: 12,
                ..
            }
        ),
        "{err:?}"
    );
    let dev = gw.with_device(ia("1.1.200")?, |d| d.clone())?;
    assert_eq!(dev.writes, 0, "nothing is written after a failed compare");
    Ok(())
}

#[tokio::test]
async fn test_write_property_value_fails_a_verify_mismatch() -> TestResult {
    // The device keeps only one octet of what it is sent: the confirmed write
    // passes, the Verify read-back does not.
    let device = MockDevice::new(ia("1.1.200")?).with_hook(|dev, apci, data| {
        if apci == 0x1CE {
            let mut out = data.get(..8)?.to_vec();
            out.push(0);
            let _ = dev;
            return Some(bussard_testkit::Reaction::Answer(0x1CF, out));
        }
        None
    });
    let device = device.with_property_ext(OT_KNXNETIP, 204, 1, &[0x05]);
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = connect(&gw).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.200")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let err = bussard_download::write_property_value(
        session.l4(),
        PropObject::Type {
            object_type: OT_KNXNETIP,
            occurrence: 0,
        },
        204,
        1,
        1,
        &[0x0A],
        true,
    )
    .await
    .err()
    .ok_or("a verify mismatch must fail")?;
    let _ = session.into_disconnect().await;
    match err {
        WriteError::PropertyMismatch {
            expected, actual, ..
        } => {
            assert_eq!(expected, vec![0x0A]);
            assert_eq!(actual, vec![0x05]);
        }
        other => return Err(format!("expected PropertyMismatch, got {other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn test_write_property_value_splits_elements_to_the_apdu_budget() -> TestResult {
    // Eight 4-octet elements on the 15-octet standard-frame budget: two
    // elements (8 octets) per A_PropertyValue_Write.
    let device = MockDevice::new(ia("1.1.200")?).with_writable_property(3, 205, 4, &[0; 32]);
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = connect(&gw).await?;
    let l4 = Layer4Connection::connect(&mut bus, ia("1.1.200")?, ia("0.0.255")?).await?;
    let mut session = Session::from_connection(l4);
    let value: Vec<u8> = (0..32).collect();
    bussard_download::write_property_value(
        session.l4(),
        PropObject::Index(3),
        205,
        1,
        8,
        &value,
        true,
    )
    .await?;
    let _ = session.into_disconnect().await;
    let dev = gw.with_device(ia("1.1.200")?, |d| d.clone())?;
    assert_eq!(dev.property(3, 205), Some(&value[..]));
    let writes: Vec<(u8, u16)> = dev
        .requests
        .iter()
        .filter(|(apci, _)| *apci == 0x3D7)
        .map(|(_, d)| (d[2] >> 4, u16::from_be_bytes([d[2] & 0x0F, d[3]])))
        .collect();
    assert_eq!(writes, vec![(2, 1), (2, 3), (2, 5), (2, 7)]);
    Ok(())
}
