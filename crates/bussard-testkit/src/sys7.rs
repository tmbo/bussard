//! A System 7 device fixture (issue #314): a mask 0705 [`MockDevice`] that
//! runs a small synthetic application (bussard's own work, MIT; no vendor
//! data), for the flash-gate tests of the MCP server and the CLI.
//!
//! [`MockDevice`] serves System 7 with what it has: the three load-state
//! machines are objects 1 to 3 (the property realisation, which the System 7
//! plan uses by default), `A_Memory_Read`/`A_Memory_Write` cover the absolute
//! segments and the link tables at their System 7 addresses, and
//! `PID_TABLE_REFERENCE` of objects 1 and 2 points at those tables.

use bussard_model::IndividualAddress;

use crate::consts::{LS_LOADED, OT_DEVICE};
use crate::device::MockDevice;

/// The fixture application's id.
pub const SYS7_APP_ID: &str = "M-00FA_A-0007";

/// Where the fixture application's code segment (`AS-4`) sits.
pub const SYS7_CODE_BASE: u32 = 0x4600;

/// The fixture application's code, as its product file carries it.
pub const SYS7_CODE: [u8; 4] = [0x0A, 0x0B, 0x0C, 0x0D];

/// Where the parameter segment (`AS-3`) sits: an 8-bit threshold, then a
/// 1-bit switch in bit 7 of the second octet that shows com-object 2.
pub const SYS7_PARAM_BASE: u32 = 0x4400;

/// The group address object 1 listens on (`1/2/0`), raw.
pub const SYS7_GROUP_ADDRESS: u16 = 0x0A00;

/// The fixture application program (mask 0705). LSM 1 holds the address
/// table region, LSM 2 the association table, LSM 3 the parameters and the
/// code.
pub const SYS7_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram PeiType="0" Id="M-00FA_A-0007" ApplicationNumber="7" ApplicationVersion="1"
            MaskVersion="MV-0705" Name="bussard System 7 flash test app" LoadProcedureStyle="ProductProcedure">
          <Static>
            <Code>
              <AbsoluteSegment Id="M-00FA_A-0007_AS-1" Size="256" Address="16384" />
              <AbsoluteSegment Id="M-00FA_A-0007_AS-2" Size="64" Address="16897" />
              <AbsoluteSegment Id="M-00FA_A-0007_AS-3" Size="2" Address="17408"><Data>AAA=</Data></AbsoluteSegment>
              <AbsoluteSegment Id="M-00FA_A-0007_AS-4" Size="4" Address="17920"><Data>CgsMDQ==</Data></AbsoluteSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0007_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
              <ParameterType Id="M-00FA_A-0007_PT-1" Name="onoff"><TypeRestriction Base="Value" SizeInBit="1">
                <Enumeration Text="Off" Value="0" /><Enumeration Text="On" Value="1" />
              </TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0007_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0007_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0007_AS-3" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0007_P-1" Name="obj2" Text="Object 2" ParameterType="M-00FA_A-0007_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0007_AS-3" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0007_P-0_R-1" RefId="M-00FA_A-0007_P-0" />
              <ParameterRef Id="M-00FA_A-0007_P-1_R-2" RefId="M-00FA_A-0007_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0007_O-1" Number="1" Text="Switch" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" DatapointType="DPST-1-1" />
              <ComObject Id="M-00FA_A-0007_O-2" Number="2" Text="Alarm" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" DatapointType="DPST-1-5" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0007_O-1_R-1" RefId="M-00FA_A-0007_O-1" />
              <ComObjectRef Id="M-00FA_A-0007_O-2_R-2" RefId="M-00FA_A-0007_O-2" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="1" />
                <LdCtrlUnload LsmIdx="2" />
                <LdCtrlUnload LsmIdx="3" />
                <LdCtrlLoad LsmIdx="1" />
                <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="256" />
                <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
                <LdCtrlLoadCompleted LsmIdx="1" />
                <LdCtrlLoad LsmIdx="2" />
                <LdCtrlAbsSegment LsmIdx="2" Address="16897" Size="64" />
                <LdCtrlTaskSegment LsmIdx="2" Address="16897" />
                <LdCtrlLoadCompleted LsmIdx="2" />
                <LdCtrlLoad LsmIdx="3" />
                <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
                <LdCtrlAbsSegment LsmIdx="3" Address="17920" Size="4" />
                <LdCtrlTaskSegment LsmIdx="3" Address="17920" />
                <LdCtrlLoadCompleted LsmIdx="3" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0007_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0007_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0007_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0007_O-1_R-1" />
                <choose ParamRefId="M-00FA_A-0007_P-1_R-2">
                  <when test="1"><ComObjectRefRef RefId="M-00FA_A-0007_O-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

/// A System 7 device at `address` running the fixture application: all
/// three load-state machines `Loaded`, object 1 linked to
/// [`SYS7_GROUP_ADDRESS`], threshold 9 and object 2 off, and `code` at
/// [`SYS7_CODE_BASE`] ([`SYS7_CODE`] for the product's code).
pub fn system7_device(address: IndividualAddress, code: &[u8]) -> MockDevice {
    let mut address_table = vec![2u8];
    address_table.extend_from_slice(&address.raw().to_be_bytes());
    address_table.extend_from_slice(&SYS7_GROUP_ADDRESS.to_be_bytes());
    // The group-object table after it: count 1, RAM flags at 0x0700, one
    // descriptor.
    address_table.extend_from_slice(&[0x01, 0x07, 0x00, 0x07, 0x00, 0xDF, 0x00]);
    let mut dev = MockDevice::new(address)
        .with_mask(0x0705)
        // Objects 1 to 3 carry the load-state machines.
        .with_object_types(&[OT_DEVICE, 1, 2, 3])
        .with_memory(0x4000, &address_table)
        .with_memory(0x4201, &[1, 1, 1])
        .with_memory(SYS7_PARAM_BASE, &[9, 0x00])
        .with_memory(SYS7_CODE_BASE, code);
    // PID_TABLE_REFERENCE of the table objects: the System 7 table regions.
    dev.segments.insert(1, (0x4000, 256));
    dev.segments.insert(2, (0x4201, 64));
    for lsm in [1u8, 2, 3] {
        dev.load_states.insert(lsm, LS_LOADED);
    }
    dev
}
