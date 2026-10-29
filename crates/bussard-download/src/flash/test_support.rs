//! Shared fixtures for the flash unit tests.

use std::collections::BTreeMap;

use bussard_prod::application::ApplicationProgram;

use bussard_prod::application::parse_application_program;

/// A minimal single-application System B app: two relative segments (code +
/// parameters) with a straightforward relative-segment procedure.
pub(super) fn fabricated_app() -> ApplicationProgram {
    // Code segment RS-1 carries a 6-byte code image (base64 of 00..05).
    // Parameter segment RS-2 has an 8-bit param at offset 0 default 7, over a
    // 1-byte zero base.
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
      <Static>
       <Code>
        <RelativeSegment Id="M-1_A-1_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
        <RelativeSegment Id="M-1_A-1_RS-2" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
       </Code>
       <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
       <Parameters><Parameter Id="M-1_A-1_P-0" Name="thr" ParameterType="M-1_A-1_PT-0" Value="7"><Memory CodeSegment="M-1_A-1_RS-2" Offset="0" BitOffset="0" /></Parameter></Parameters>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlConnect />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
         <LdCtrlRelSegment LsmIdx="4" Size="1" AppliesTo="par" />
         <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="1" AppliesTo="par" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
         <LdCtrlDisconnect />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#;
    parse_application_program("M-1_A-1", xml.as_bytes()).expect("the fixture app parses")
}

pub(super) fn no_overrides() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// A secure-capable 07B0 app with the house shape of issue #490: the
/// template's unload of object 5, which it never loads, and the `full`
/// (`Mode="1"`) and `par` (`Mode="0"`) allocations of one six-octet segment
/// on object 4, written by one `full,par` write.
fn par_pair_xml(par: bool) -> String {
    let par_alloc = if par {
        r#"<LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="6" Mode="0" Fill="0" />"#
    } else {
        ""
    };
    format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23">
     <ApplicationProgram Id="M-4_A-1" ApplicationNumber="1" ApplicationVersion="1"
        MaskVersion="MV-07B0" Name="Pair" LoadProcedureStyle="ProductDefault" IsSecureEnabled="true">
      <Static>
       <Code><RelativeSegment Id="M-4_A-1_RS-4" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment></Code>
       <LoadProcedures>
        <LoadProcedure>
         <LdCtrlUnload LsmIdx="5" />
         <LdCtrlUnload LsmIdx="4" />
         <LdCtrlLoad LsmIdx="4" />
         <LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6" Mode="1" Fill="0" />
         {par_alloc}
         <LdCtrlWriteRelMem AppliesTo="full,par" ObjIdx="4" Offset="0" Size="6" Verify="true" />
         <LdCtrlLoadCompleted LsmIdx="4" />
         <LdCtrlRestart />
        </LoadProcedure>
       </LoadProcedures>
      </Static>
     </ApplicationProgram></KNX>"#
    )
}

/// The full plan of [`par_pair_xml`] with the `par` allocation.
pub(super) fn par_pair_plan() -> Result<super::FlashPlan, Box<dyn std::error::Error>> {
    let app = parse_application_program("M-4_A-1", par_pair_xml(true).as_bytes())?;
    Ok(super::plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?)
}

/// The full plan of [`par_pair_xml`] without the `par` allocation.
pub(super) fn full_only_plan() -> Result<super::FlashPlan, Box<dyn std::error::Error>> {
    let app = parse_application_program("M-4_A-1", par_pair_xml(false).as_bytes())?;
    Ok(super::plan_flash(
        &app,
        "1.1.4",
        0x07B0,
        &no_overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?)
}
