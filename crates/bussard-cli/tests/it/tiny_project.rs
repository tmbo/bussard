//! A tiny fabricated `.knxproj` (no vendor content) the import, diff and
//! setup tests start from: device 1.1.1 "Test Switch Actuator" (order number
//! `TST-1`, application [`APP_ID`]) on line 1.1, its switch object 0 listening
//! on 1/0/1 "Living room light switch" (DPT 1.001) and its status object 1
//! sending on 1/0/2 "Living room light status" (DPT 1), in the ranges
//! 1 "Ground floor" and 1/0 "Lighting".

use std::io::Write as _;
use std::path::Path;

use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The device's application program id.
pub const APP_ID: &str = "M-9999_A-0001-1-0000";

/// The switch program: object 0 "Switch output A" and object 1 "Status
/// output A", both 1 bit.
pub const SWITCH_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21"><ManufacturerData><Manufacturer RefId="M-9999"><ApplicationPrograms>
<ApplicationProgram Id="M-9999_A-0001-1-0000" ApplicationNumber="1" ApplicationVersion="0" MaskVersion="MV-07B0" Name="Test" LoadProcedureStyle="MergedProcedure"><Static>
<ComObjectTable>
 <ComObject Id="M-9999_A-0001-1-0000_O-0" Number="0" Name="Switch" Text="Switch output A" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" DatapointType="DPST-1-1" />
 <ComObject Id="M-9999_A-0001-1-0000_O-1" Number="1" Name="Status" Text="Status output A" FunctionText="Status" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Disabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" DatapointType="DPT-1" />
</ComObjectTable>
<ComObjectRefs>
 <ComObjectRef Id="M-9999_A-0001-1-0000_O-0_R-1" RefId="M-9999_A-0001-1-0000_O-0" />
 <ComObjectRef Id="M-9999_A-0001-1-0000_O-1_R-2" RefId="M-9999_A-0001-1-0000_O-1" />
</ComObjectRefs>
</Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;

const MASTER_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21"><MasterData><Manufacturers><Manufacturer Id="M-9999" Name="Test Manufacturer" /></Manufacturers></MasterData></KNX>"#;

const PROJECT_INFO_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21"><Project Id="P-TEST"><ProjectInformation Name="Tiny Test Project" GroupAddressStyle="ThreeLevel" /></Project></KNX>"#;

const PROJECT_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21">
 <Project Id="P-TEST">
  <Installations><Installation Name="">
   <Topology><Area Address="1"><Line Address="1">
    <DeviceInstance Id="P-TEST-0_DI-1" Address="1" Name="Test Switch Actuator" ProductRefId="M-9999_H-1_P-1" Hardware2ProgramRefId="M-9999_H-1_HP-0001-01-0000">
     <ComObjectInstanceRefs>
      <ComObjectInstanceRef RefId="O-0_R-1" Links="GA-1" />
      <ComObjectInstanceRef RefId="O-1_R-2" Links="GA-2" />
     </ComObjectInstanceRefs>
    </DeviceInstance>
   </Line></Area></Topology>
   <GroupAddresses><GroupRanges>
    <GroupRange Id="P-TEST-0_GR-1" RangeStart="2048" RangeEnd="4095" Name="Ground floor">
     <GroupRange Id="P-TEST-0_GR-2" RangeStart="2048" RangeEnd="2303" Name="Lighting">
      <GroupAddress Id="P-TEST-0_GA-1" Address="2049" Name="Living room light switch" DatapointType="DPST-1-1" />
      <GroupAddress Id="P-TEST-0_GA-2" Address="2050" Name="Living room light status" DatapointType="DPT-1" />
     </GroupRange>
    </GroupRange>
   </GroupRanges></GroupAddresses>
  </Installation></Installations>
 </Project>
</KNX>"#;

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/21"><ManufacturerData><Manufacturer RefId="M-9999"><Hardware>
<Hardware Id="M-9999_H-1" Name="Test Switch Actuator">
<Products><Product Id="M-9999_H-1_P-1" Text="Test Switch Actuator" OrderNumber="TST-1" /></Products>
<Hardware2Programs><Hardware2Program Id="M-9999_H-1_HP-0001-01-0000"><ApplicationProgramRef RefId="M-9999_A-0001-1-0000" /></Hardware2Program></Hardware2Programs>
</Hardware></Hardware></Manufacturer></ManufacturerData></KNX>"#;

/// Writes the tiny project with the switch program to `path`.
pub fn write(path: &Path) -> TestResult {
    write_with(path, SWITCH_APP_XML)
}

/// Writes the tiny project to `path`, with `app_xml` (a program with id
/// [`APP_ID`]) as the device's application program.
pub fn write_with(path: &Path, app_xml: &str) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    for (name, body) in [
        ("knx_master.xml", MASTER_XML),
        ("P-TEST/project.xml", PROJECT_INFO_XML),
        ("P-TEST/0.xml", PROJECT_XML),
        ("M-9999/Hardware.xml", HARDWARE_XML),
        (&format!("M-9999/{APP_ID}.xml") as &str, app_xml),
    ] {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}
