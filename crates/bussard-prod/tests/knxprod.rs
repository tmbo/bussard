//! Integration test: assemble a tiny `.knxprod` ZIP in a temp dir and read it
//! end-to-end, checking order-number matching and that signature entries are
//! ignored. The fixture XML is fabricated here — no vendor data is committed.

use std::io::Write;

use zip::write::SimpleFileOptions;

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-00FA">
    <Hardware>
      <Products><Product OrderNumber="TEST-1" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-00FA_A-0001-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="M-00FA_A-0001-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Fixture" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-00FA_A-0001-11-ABCD-O000A_O-0" Number="0" Text="Switch" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-00FA_A-0001-11-ABCD-O000A_O-0_R-1" RefId="M-00FA_A-0001-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
   <LoadProcedures>
    <LoadProcedure MergeId="1"><LdCtrlConnect /><LdCtrlRestart /></LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn build_knxprod(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let f = std::fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    zip.start_file("M-00FA/Hardware.xml", opts)?;
    zip.write_all(HARDWARE_XML.as_bytes())?;
    zip.start_file("M-00FA/M-00FA_A-0001-11-ABCD-O000A.xml", opts)?;
    zip.write_all(APP_XML.as_bytes())?;
    // Non-application entries that must be ignored.
    zip.start_file("M-00FA/Catalog.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    zip.start_file("M-00FA/M-00FA.signature", opts)?;
    zip.write_all(&[0u8, 1, 2, 3])?;
    zip.finish()?;
    Ok(())
}

#[test]
fn reads_knxprod_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build_knxprod(&path)?;

    let product = bussard_prod::read_knxprod(&path)?;

    assert_eq!(product.manufacturers, vec!["M-00FA".to_string()]);
    // Exactly one application (Catalog/signature ignored).
    assert_eq!(product.applications.len(), 1);
    let app = &product.applications[0];
    assert_eq!(app.id, "M-00FA_A-0001-11-ABCD-O000A");
    assert_eq!(app.name.as_deref(), Some("Fixture"));
    assert_eq!(app.resolved_com_objects().len(), 1);

    // Order-number matching resolves to the parsed application.
    let matched = product.application_for_order_number("TEST-1");
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].id, app.id);
    assert!(product.application_for_order_number("NOPE").is_empty());
    Ok(())
}
