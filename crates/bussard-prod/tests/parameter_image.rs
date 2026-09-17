//! Integration tests for code-segment data capture and the parameter memory
//! image builder.
//!
//! Two layers:
//!
//! * A fabricated `.knxprod` round trip proves the reader carries a segment's
//!   `<Data>`/`<Mask>` through to [`bussard_prod::ProductData`] and that
//!   `compute_parameter_image` lays a parameter over that base image.
//! * A read-only smoke test against the developer's local `home_test.knxproj`
//!   (never committed) exercises every real ETS application program. It is
//!   skipped automatically when the file is absent, so CI stays green.

use std::collections::BTreeMap;
use std::io::Write;

use bussard_prod::compute_parameter_image;
use zip::write::SimpleFileOptions;

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-00FA">
    <Hardware>
      <Products><Product OrderNumber="SEG-1" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-00FA_A-0001-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

// A parameter segment carrying a base <Data> image [0xAA,0xBB,0xCC,0xDD]
// ("qrvM3Q==") and a full <Mask>, plus one 8-bit parameter at offset 2 with
// default 5 that must overwrite byte 2 while the other bytes survive.
const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="M-00FA_A-0001-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Seg" LoadProcedureStyle="MergedProcedure">
   <Static>
    <Code>
     <RelativeSegment Id="M-00FA_A-0001-11-ABCD-O000A_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>qrvM3Q==</Data><Mask>/////w==</Mask></RelativeSegment>
    </Code>
    <ParameterTypes>
     <ParameterType Id="M-00FA_A-0001-11-ABCD-O000A_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
    </ParameterTypes>
    <Parameters>
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_P-0" Name="thr" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-0" Value="5"><Memory CodeSegment="M-00FA_A-0001-11-ABCD-O000A_RS-1" Offset="2" BitOffset="0" /></Parameter>
    </Parameters>
   </Static>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn build_knxprod(path: &std::path::Path) {
    let f = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts).unwrap();
    zip.write_all(b"<KNX/>").unwrap();
    zip.start_file("M-00FA/Hardware.xml", opts).unwrap();
    zip.write_all(HARDWARE_XML.as_bytes()).unwrap();
    zip.start_file("M-00FA/M-00FA_A-0001-11-ABCD-O000A.xml", opts)
        .unwrap();
    zip.write_all(APP_XML.as_bytes()).unwrap();
    zip.finish().unwrap();
}

#[test]
fn segment_data_and_mask_round_trip_and_param_overlay() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("seg.knxprod");
    build_knxprod(&path);

    let product = bussard_prod::read_knxprod(&path).unwrap();
    let app = &product.applications[0];

    // The <Data>/<Mask> survived into the model as decoded bytes.
    let seg = app
        .code_segments
        .get("M-00FA_A-0001-11-ABCD-O000A_RS-1")
        .unwrap();
    assert_eq!(
        seg.data.as_deref(),
        Some([0xAA, 0xBB, 0xCC, 0xDD].as_slice())
    );
    assert_eq!(
        seg.mask.as_deref(),
        Some([0xFF, 0xFF, 0xFF, 0xFF].as_slice())
    );

    // compute_parameter_image lays the parameter over the base image.
    let images = compute_parameter_image(app, &BTreeMap::new(), &BTreeMap::new()).unwrap();
    let img = &images["M-00FA_A-0001-11-ABCD-O000A_RS-1"];
    assert_eq!(img, &vec![0xAA, 0xBB, 0x05, 0xDD]);
}

// A fabricated app mirroring the Zennio FIX2 dimmer's union shape: a 4-byte base
// image, one plain 8-bit parameter, and two `<Union>` blocks. The first union
// (base offset 1, 8-bit) has a default member with value 75 (0x4B) that must
// overwrite the base byte; its two non-default members (values 1 and 9) must NOT
// win. The second union (base offset 3) demonstrates sub-byte packing: a default
// member is a 2-bit field of value 3 at bit offset 0, laid MSB-first (0b11 into
// the top two bits => 0xC0) over a zero base byte.
const UNION_APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="M-00FA_A-0001-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Uni" LoadProcedureStyle="MergedProcedure">
   <Static>
    <Code>
     <RelativeSegment Id="M-00FA_A-0001-11-ABCD-O000A_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>AAAAAA==</Data><Mask>/////w==</Mask></RelativeSegment>
    </Code>
    <ParameterTypes>
     <ParameterType Id="M-00FA_A-0001-11-ABCD-O000A_PT-8" Name="n8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
     <ParameterType Id="M-00FA_A-0001-11-ABCD-O000A_PT-2" Name="n2"><TypeNumber SizeInBit="2" Type="unsignedInt" minInclusive="0" maxInclusive="3" /></ParameterType>
    </ParameterTypes>
    <Parameters>
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_P-0" Name="thr" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-8" Value="170"><Memory CodeSegment="M-00FA_A-0001-11-ABCD-O000A_RS-1" Offset="0" BitOffset="0" /></Parameter>
    </Parameters>
    <Union SizeInBit="8">
     <Memory CodeSegment="M-00FA_A-0001-11-ABCD-O000A_RS-1" Offset="1" BitOffset="0" />
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_UP-1" Name="u1a" DefaultUnionParameter="1" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-8" Value="75" Offset="0" BitOffset="0" />
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_UP-2" Name="u1b" DefaultUnionParameter="0" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-8" Value="1" Offset="0" BitOffset="0" />
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_UP-3" Name="u1c" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-8" Value="9" Offset="0" BitOffset="0" />
    </Union>
    <Union SizeInBit="8">
     <Memory CodeSegment="M-00FA_A-0001-11-ABCD-O000A_RS-1" Offset="3" BitOffset="0" />
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_UP-4" Name="u2a" DefaultUnionParameter="1" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-2" Value="3" Offset="0" BitOffset="0" />
     <Parameter Id="M-00FA_A-0001-11-ABCD-O000A_UP-5" Name="u2b" ParameterType="M-00FA_A-0001-11-ABCD-O000A_PT-2" Value="0" Offset="0" BitOffset="0" />
    </Union>
   </Static>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

fn build_union_knxprod(path: &std::path::Path) {
    let f = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts).unwrap();
    zip.write_all(b"<KNX/>").unwrap();
    zip.start_file("M-00FA/Hardware.xml", opts).unwrap();
    zip.write_all(HARDWARE_XML.as_bytes()).unwrap();
    zip.start_file("M-00FA/M-00FA_A-0001-11-ABCD-O000A.xml", opts)
        .unwrap();
    zip.write_all(UNION_APP_XML.as_bytes()).unwrap();
    zip.finish().unwrap();
}

#[test]
fn union_default_member_overlays_shared_region_exact_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("union.knxprod");
    build_union_knxprod(&path);

    let product = bussard_prod::read_knxprod(&path).unwrap();
    let app = &product.applications[0];

    // Both unions parsed, each with the expected member counts.
    assert_eq!(app.unions.len(), 2);
    assert_eq!(app.unions[0].members.len(), 3);
    assert!(app.unions[0].members[0].is_default);

    let images = compute_parameter_image(app, &BTreeMap::new(), &BTreeMap::new()).unwrap();
    let img = &images["M-00FA_A-0001-11-ABCD-O000A_RS-1"];

    // byte0: plain parameter 170 (0xAA).
    // byte1: union-1 default member value 75 (0x4B) — NOT 1 or 9.
    // byte2: untouched base 0x00.
    // byte3: union-2 default 2-bit field value 3 => 0b11 in the top two bits (0xC0).
    assert_eq!(img, &vec![0xAA, 0x4B, 0x00, 0xC0]);
}

/// Env-gated real-product union regression: the Zennio FIX2 dimmer
/// (`T4940275_KNX_FIX2_Dimmaktor_V1.0_ETS4.knxprod`) declares a `<Union>` at
/// segment `AS-48D0` offset 56 whose `DefaultUnionParameter` member is an 8-bit
/// value 75 (0x4B). Its base `<Data>` byte there is 0x00, so the computed image
/// byte must be exactly 0x4B — the value ETS itself would write. Set
/// `BUSSARD_PRODUCT_CORPUS=<vendor-dir>` to run it; skipped when unset (CI never
/// ships the copyrighted vendor file, which the fabricated union test covers).
#[test]
fn real_zennio_fix2_union_byte_is_vendor_default() {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the FIX2 union byte check.");
        return;
    };
    let path = std::path::PathBuf::from(dir).join("T4940275_KNX_FIX2_Dimmaktor_V1.0_ETS4.knxprod");
    if !path.exists() {
        eprintln!("FIX2 dimmer not in corpus dir; skipping.");
        return;
    }

    let product = bussard_prod::read_knxprod(&path).unwrap();
    // Find the application that carries the AS-48D0 segment (the dimmer app).
    let app = product
        .applications
        .iter()
        .find(|a| a.code_segments.keys().any(|k| k.ends_with("_AS-48D0")))
        .expect("FIX2 dimmer application with segment AS-48D0");

    let images = compute_parameter_image(app, &BTreeMap::new(), &BTreeMap::new()).unwrap();
    let seg_id = app
        .code_segments
        .keys()
        .find(|k| k.ends_with("_AS-48D0"))
        .unwrap();
    let img = &images[seg_id];
    assert!(
        img.len() > 56,
        "segment image too short: {} bytes",
        img.len()
    );
    assert_eq!(
        img[56], 0x4B,
        "union default member (value 75) must land at offset 56, got {:#04X}",
        img[56]
    );
}

/// Read-only smoke test over the developer's local `home_test.knxproj`.
///
/// Not committed data; skipped when absent so CI is unaffected. Reports (as test
/// output) how many application programs carry segment `<Data>` and the total
/// decoded byte count, and asserts that the Jung 23024 application's parameter
/// image builds without error.
#[test]
fn real_knxproj_smoke() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../home_test.knxproj");
    if !path.exists() {
        eprintln!("home_test.knxproj absent; skipping real-data smoke test");
        return;
    }

    // A `.knxproj` is a plain-zip container of `M-*/` manufacturer folders whose
    // application-program XML entries parse with the same shared parser; read
    // them directly (no password: the manufacturer folders are not encrypted).
    let file = std::fs::File::open(&path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();

    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    let app_entries: Vec<String> = names
        .iter()
        .filter(|n| {
            n.split_once('/').is_some_and(|(dir, file)| {
                dir.starts_with("M-") && file.contains("_A-") && n.ends_with(".xml")
            })
        })
        .cloned()
        .collect();

    let mut apps_with_data = 0usize;
    let mut total_bytes = 0usize;
    let mut jung_ok = false;

    for entry in &app_entries {
        let mut f = zip.by_name(entry).unwrap();
        let mut xml = String::new();
        use std::io::Read as _;
        if f.read_to_string(&mut xml).is_err() {
            continue; // skip any non-UTF-8 baggage that slipped the filter
        }
        drop(f);

        let id = entry
            .rsplit('/')
            .next()
            .unwrap()
            .strip_suffix(".xml")
            .unwrap();
        let app = bussard_prod::parse_application_program(id, xml.as_bytes()).unwrap();

        let seg_bytes: usize = app
            .code_segments
            .values()
            .filter_map(|s| s.data.as_ref())
            .map(|d| d.len())
            .sum();
        if app.code_segments.values().any(|s| s.data.is_some()) {
            apps_with_data += 1;
        }
        total_bytes += seg_bytes;

        // The Jung 23024 application (mask 26, id …A-20D7-26-…): its parameter
        // image must build with no overrides and no error.
        if id.contains("A-20D7-26-") {
            let images = compute_parameter_image(&app, &BTreeMap::new(), &BTreeMap::new()).unwrap();
            let total: usize = images.values().map(Vec::len).sum();
            eprintln!(
                "Jung 23024 ({id}): {} segment images, {total} total image bytes",
                images.len()
            );
            for (seg, img) in &images {
                eprintln!("  {seg}: {} bytes", img.len());
            }
            jung_ok = true;
        }
    }

    eprintln!(
        "real-data: {} application programs, {apps_with_data} carrying segment <Data>, \
         {total_bytes} total decoded segment bytes",
        app_entries.len()
    );

    assert!(
        apps_with_data > 0,
        "expected some apps to carry segment data"
    );
    assert!(
        jung_ok,
        "Jung 23024 application not found in home_test.knxproj"
    );
}
