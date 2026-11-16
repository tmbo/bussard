//! A parameter-only download writes the octets of a reached `Access="None"`
//! parameter at the model's value whatever its baseline holds (issue #1168).
//!
//! The shape is the Jung heating actuator's (`A-20E0`, mask 07B0): object
//! 4's `PID_MCB_TABLE` has two entries, the parameter memory and one octet
//! with CRC control `0x01` that holds the download flag (`Access="None"`,
//! `Value="1"`). The device clears the flag on its own during the load,
//! after the baseline read. A download that leaves the flag out because the
//! baseline already held `01` fails the MCB check of entry 2.

use std::collections::{BTreeMap, BTreeSet};

use bussard_download::{
    FlashOptions, FlashPlan, FlashStep, Session, flash, read_parameter_regions, verify_readback,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::WriteError;
use bussard_product::application::{ApplicationProgram, parse_application_program};
use bussard_testkit::consts::{
    A_MEMORY_WRITE, LS_LOADED, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE,
    OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::plan_flash_default;

/// The application's id.
const APP_ID: &str = "M-00FA_A-1168";

/// The parameter segment.
const SEGMENT: &str = "M-00FA_A-1168_RS-04-00000";

/// The `value` parameter (octet 0), app-relative.
const VALUE: &str = "P-1_R-1";

/// The download flag's octet: the last octet of the segment.
const FLAG: usize = 7;

/// Where the mock places object 4's segment.
const BASE: u32 = 0x6000;

/// A fabricated 07B0 application in the Jung `A-20E0` shape: an 8-octet
/// parameter segment, `value` at octet 0, the download flag
/// (`Access="None"`, `Value="1"`) at octet 7, a Mode 0 allocation and the MCB
/// check of object 4 over two entries.
fn app() -> TestResult<ApplicationProgram> {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-00FA_A-1168" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Flag" LoadProcedureStyle="MergedProcedure">
      <Static>
       <Code>
        <RelativeSegment Id="M-00FA_A-1168_RS-04-00000" Size="8" LoadStateMachine="4" Offset="0"><Data>AAAAAAAAAAA=</Data></RelativeSegment>
       </Code>
       <ParameterTypes>
        <ParameterType Id="M-00FA_A-1168_PT-1" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
       </ParameterTypes>
       <Parameters>
        <Parameter Id="M-00FA_A-1168_P-1" Name="value" ParameterType="M-00FA_A-1168_PT-1" Value="5"><Memory CodeSegment="M-00FA_A-1168_RS-04-00000" Offset="0" BitOffset="0" /></Parameter>
        <Parameter Id="M-00FA_A-1168_P-2" Name="_Allg_Download" ParameterType="M-00FA_A-1168_PT-1" Access="None" Value="1"><Memory CodeSegment="M-00FA_A-1168_RS-04-00000" Offset="7" BitOffset="0" /></Parameter>
       </Parameters>
       <ParameterRefs>
        <ParameterRef Id="M-00FA_A-1168_P-1_R-1" RefId="M-00FA_A-1168_P-1" />
        <ParameterRef Id="M-00FA_A-1168_P-2_R-2" RefId="M-00FA_A-1168_P-2" />
       </ParameterRefs>
       <LoadProcedures>
        <LoadProcedure MergeId="1">
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="8" Mode="0" Fill="0" />
         <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="8" Verify="false" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlLoadImageProp ObjIdx="4" PropId="27" Count="2" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
      <Dynamic>
       <ChannelIndependentBlock>
        <ParameterBlock Id="M-00FA_A-1168_PB-1" Name="general">
         <ParameterRefRef RefId="M-00FA_A-1168_P-1_R-1" />
         <ParameterRefRef RefId="M-00FA_A-1168_P-2_R-2" />
        </ParameterBlock>
       </ChannelIndependentBlock>
      </Dynamic>
     </ApplicationProgram></KNX>"#;
    Ok(parse_application_program(APP_ID, xml.as_bytes())?)
}

/// The complete download of [`app`] for 1.1.1 with `value` set.
fn plan_of(app: &ApplicationProgram, value: Option<u8>) -> TestResult<FlashPlan> {
    let overrides: BTreeMap<String, String> = value
        .map(|v| BTreeMap::from([(VALUE.to_string(), v.to_string())]))
        .unwrap_or_default();
    Ok(plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )
    .map_err(|e| e.to_string())?)
}

/// The device: object 4's MCB in the actuator's two entries (the parameter
/// memory, CRC control `0x00`, then the flag, CRC control `0x01`), and an
/// application that clears the flag when object 4 starts loading.
fn device() -> TestResult<MockDevice> {
    Ok(MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_segment_base(4, BASE)
        .with_mcb_split(4, &[FLAG as u32, 1])
        .with_mcb_crc_controls(4, &[0x00, 0x01])
        .with_load_rewrite(4, FLAG as u32, 0x00))
}

/// Opens `$session` to 1.1.1 behind `$gw` over the transport `$bus`.
macro_rules! open {
    ($gw:expr, $bus:ident, $session:ident) => {
        let mut $bus = Transport::connect(&ConnectionConfig::tunnel($gw.addr())).await?;
        let l4 = Layer4Connection::connect(
            &mut $bus,
            ia("1.1.1")?,
            ia("0.0.255")?,
            bussard_mgmt::ConnectOptions::default(),
        )
        .await?;
        let mut $session = Session::from_connection(l4);
    };
}

/// The plain memory writes the device saw into the segment: address and
/// length of each.
fn segment_writes(dev: &MockDevice) -> Vec<(u32, usize)> {
    dev.requests
        .iter()
        .filter(|(apci, data)| apci & !0x3F == A_MEMORY_WRITE && data.len() >= 2)
        .map(|(_, data)| {
            (
                u32::from(u16::from_be_bytes([data[0], data[1]])),
                data.len() - 2,
            )
        })
        .filter(|&(addr, _)| (BASE..BASE + 8).contains(&addr))
        .collect()
}

#[test]
fn test_forced_octets_names_the_flag_the_baseline_already_holds() -> TestResult {
    let app = app()?;
    let defaults = plan_of(&app, None)?;
    assert_eq!(
        defaults.device_managed(SEGMENT),
        Some(&BTreeSet::from([FLAG]))
    );
    let full = plan_of(&app, Some(9))?;
    let mut regions = bussard_download::planned_parameter_regions(&defaults);
    for region in regions.values_mut() {
        region.address = BASE;
    }
    let partial = full.parameters_only(&regions)?;
    // Only `value` differs; the flag is written besides it, not counted.
    assert_eq!(partial.changed_octets(), 1);
    assert_eq!(
        partial.forced_octets(),
        BTreeMap::from([(SEGMENT.to_string(), vec![FLAG])])
    );
    // Issue #289: a device that holds every value, the flag included, has
    // nothing to change, and the flag alone never makes a download.
    let same = defaults.parameters_only(&regions)?;
    assert_eq!(same.changed_octets(), 0);
    Ok(())
}

#[test]
fn test_forced_octets_leaves_out_a_flag_that_differs() -> TestResult {
    // Issue #289's case: the device cleared the flag, nothing else differs.
    // The flag is a changed octet (the service plans it as noop, see
    // `device_managed_only`), not a forced one.
    let app = app()?;
    let defaults = plan_of(&app, None)?;
    let mut regions = bussard_download::planned_parameter_regions(&defaults);
    for region in regions.values_mut() {
        region.address = BASE;
        region.bytes[FLAG] = 0;
    }
    let partial = defaults.parameters_only(&regions)?;
    assert_eq!(partial.changed_octets(), 1);
    assert!(partial.forced_octets().is_empty());
    Ok(())
}

#[tokio::test]
async fn test_flash_parameters_only_writes_the_device_managed_flag_the_baseline_holds() -> TestResult
{
    let app = app()?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    open!(gw, bus, session);
    // The complete download leaves the flag at `01`.
    let defaults = plan_of(&app, None)?;
    let outcome = flash(&mut session, &defaults, FlashOptions::default(), |_| {}).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let flag = gw.with_device(ia("1.1.1")?, |d| {
        d.requests.clear();
        d.restarts = 0;
        d.read_mem(BASE + FLAG as u32, 1)
    })?;
    assert_eq!(flag, vec![0x01]);

    let full = plan_of(&app, Some(9))?;
    let regions = read_parameter_regions(session.l4(), &full, &[]).await;
    let partial = full.parameters_only(&regions)?;
    assert!(
        partial
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::LoadImageProp { .. })),
        "{:?}",
        partial.steps
    );
    let result = flash(&mut session, &partial, FlashOptions::default(), |_| {}).await;
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(e @ WriteError::ImagePropMismatch { .. }) => {
            return Err(format!("the MCB check failed (issue #1168): {e}").into());
        }
        Err(e) => return Err(e.into()),
    };
    assert!(outcome.ok(), "{outcome:?}");
    let after = read_parameter_regions(session.l4(), &full, &[]).await;
    let checked = verify_readback(&partial, &after, &BTreeSet::new())?;
    assert!(checked > 0);
    let _ = session.into_disconnect().await;
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    // `value` at octet 0 and the flag at octet 7, joined over the six
    // unchanged octets between them into one request (the sparse merge).
    let writes = segment_writes(&dev);
    assert_eq!(writes, vec![(BASE, 8)], "{writes:?}");
    assert_eq!(dev.read_mem(BASE, 8), vec![9, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(dev.load_state(4), LS_LOADED);
    assert_eq!(dev.restarts, 1);
    Ok(())
}
