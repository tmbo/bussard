//! Golden tests for issue #123: bussard must reproduce, byte for byte, the
//! group-object tables (obj3) and parameter segments (obj4) ETS 6 wrote to real
//! System B devices, from the vendor product, the device's links and its
//! non-default parameters.
//!
//! - Jung 52921ST (F50 push-button module, app `M-0004_A-D142-21-8848-O000A`):
//!   module-based, obj3 and obj4, and the fill flag of its obj4 allocation.
//! - Jung 390041SR (LED dimmer, `M-0004_A-3030-23`), ABB BE/S16
//!   (`M-0002_A-A0ED-10`), Helios KWL (`M-0112_A-0003-10`): flat applications,
//!   obj3 (and obj4 for the Helios).
//!
//! The ETS images are committed under `tests/fixtures/ets-golden/` (see the
//! README there); the vendor products are not, so the tests are gated on
//! `BUSSARD_PRODUCT_CORPUS` like the other corpus tests and skip when a product
//! is not in the cache.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use bussard_download::{FlashStep, LinkedObject, dynamic_group_object_table, plan_flash};
use bussard_prod::{ApplicationProgram, compute_parameter_image, parse_application_program};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

/// Where an application lives in the corpus cache: the product file, an inner
/// product archive if the file nests one, and the application id.
struct Source {
    product: &'static str,
    inner: Option<&'static str>,
    app_id: &'static str,
}

const F50: Source = Source {
    product: "Tastsensoren_Universal_F50_Secure_2v1_Jung_DE_EN_FR_NL_ES_RU_IT.knxprod",
    inner: None,
    app_id: "M-0004_A-D142-21-8848-O000A",
};
const F50_SEGMENT: &str = "M-0004_A-D142-21-8848-O000A_RS-04-00000";

/// The com-objects the F50 links (buttons 1 and 2 switching + status, the
/// rocker-2 blind objects, the temperature object).
const F50_LINKED: [u16; 7] = [65, 66, 69, 70, 285, 286, 1289];

/// The device's non-default parameters, keyed like a device file (app-relative
/// ref id, module-instance selector where the parameter belongs to a module).
///
/// Six are display-only and only steer which modules, objects and parameters
/// the configuration shows: the button operating concept (`P-1313`, buttons
/// instead of rocker 1), rocker 2's function (`P-583`, blind), the temperature
/// measurement (`P-5`), the brightness-reduction object (`P-180`, which shows
/// object 7) and the status-LED function of buttons 1 and 2 (`P-251`, `P-346`).
/// The rest are written: LED night brightness (`P-182`, `P-184`), two hidden
/// application-instance bytes at 0 where the shown ref defaults to 46 (`P-643`,
/// `P-733`) and the blind operating concept of the rocker module (union member
/// `UP-22`).
///
/// The values were read back from the ETS image and the shown objects: the
/// model's device file carries only `P-182`/`P-184`, because the importer
/// dropped display-only parameters, union members and values equal to one of
/// several ref defaults (fixed with this test).
fn overrides() -> BTreeMap<String, String> {
    [
        ("P-1313_R-191", "1"),
        ("P-583_R-1114", "2"),
        ("P-5_R-1", "1"),
        ("P-180_R-87", "1"),
        ("P-182_R-93", "1"),
        ("P-184_R-95", "1"),
        ("P-643_R-427", "0"),
        ("P-733_R-428", "0"),
        ("P-251_R-310", "4"),
        ("P-346_R-436", "4"),
        ("MD-15_M-26_MI-1_UP-22_R-27", "2"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// An ETS image from `tests/fixtures/ets-golden/`.
fn fixture(name: &str) -> Result<Vec<u8>, Error> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ets-golden")
        .join(name);
    let text = std::fs::read_to_string(path)?;
    let hex: String = text.split_whitespace().collect();
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[i..i + 2], 16)?);
    }
    Ok(out)
}

/// One entry of a zip archive.
fn zip_entry(bytes: Vec<u8>, name: &str) -> Result<Vec<u8>, Error> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut entry = archive.by_name(name)?;
    let mut out = Vec::new();
    entry.read_to_end(&mut out)?;
    Ok(out)
}

/// The application from the product cache, or `None` (skip) when the corpus
/// or the product is absent. Only the one application XML is parsed.
fn load(source: &Source) -> Result<Option<ApplicationProgram>, Error> {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("BUSSARD_PRODUCT_CORPUS unset; skipping the ETS golden test.");
        return Ok(None);
    };
    // The corpus root holds `cache/vendor/`; a vendor directory may be given
    // directly too.
    let dir = PathBuf::from(dir);
    let Some(path) = [dir.join("cache/vendor"), dir.join("vendor"), dir]
        .into_iter()
        .map(|d| d.join(source.product))
        .find(|p| p.is_file())
    else {
        eprintln!("{} not in the corpus cache; skipping.", source.product);
        return Ok(None);
    };
    let mut bytes = std::fs::read(path)?;
    if let Some(inner) = source.inner {
        bytes = zip_entry(bytes, inner)?;
    }
    let manufacturer = source.app_id.split('_').next().unwrap_or_default();
    let xml = zip_entry(bytes, &format!("{manufacturer}/{}.xml", source.app_id))?;
    Ok(Some(parse_application_program(source.app_id, &xml)?))
}

/// Byte positions where two images differ, for a readable failure.
fn diff(ours: &[u8], ets: &[u8]) -> Vec<usize> {
    (0..ours.len().max(ets.len()))
        .filter(|&i| ours.get(i) != ets.get(i))
        .collect()
}

/// Asserts an image equals the ETS fixture.
fn assert_image(what: &str, ours: &[u8], ets: &[u8]) {
    let d = diff(ours, ets);
    assert!(
        d.is_empty(),
        "{what} differs from ETS in {} octets (len {} vs {}), first at {:#x?}",
        d.len(),
        ours.len(),
        ets.len(),
        &d[..d.len().min(8)]
    );
}

/// Linked objects as a device file lists them: number, com-object ref, flags.
fn linked(objects: &[(u16, &str, &str)]) -> Result<BTreeMap<u16, LinkedObject>, Error> {
    let mut out = BTreeMap::new();
    for &(number, reference, flags) in objects {
        out.insert(
            number,
            LinkedObject {
                com_object_ref: Some(reference.to_string()),
                flags: Some(flags.parse()?),
            },
        );
    }
    Ok(out)
}

#[test]
fn test_f50_group_object_table_matches_ets() -> TestResult {
    let Some(app) = load(&F50)? else {
        return Ok(());
    };
    let ets = fixture("f50-obj3.hex")?;
    // Only the object numbers: flags and sizes come from the product.
    let linked: BTreeMap<u16, LinkedObject> = F50_LINKED
        .into_iter()
        .map(|o| (o, LinkedObject::default()))
        .collect();
    let ours =
        dynamic_group_object_table(&app, &overrides(), &linked).ok_or("no group-object table")?;
    let d = diff(&ours, &ets);
    assert!(
        d.is_empty(),
        "obj3 differs from ETS in {} octets (len {} vs {}), first at {:?}",
        d.len(),
        ours.len(),
        ets.len(),
        d.first()
    );
    Ok(())
}

#[test]
fn test_f50_parameter_image_matches_ets() -> TestResult {
    let Some(app) = load(&F50)? else {
        return Ok(());
    };
    let ets = fixture("f50-obj4.hex")?;
    let images = compute_parameter_image(&app, &overrides(), &BTreeMap::new())?;
    let ours = images
        .get(F50_SEGMENT)
        .ok_or("no image for the parameter segment")?;
    let d = diff(ours, &ets);
    assert!(
        d.is_empty(),
        "obj4 differs from ETS in {} octets, first at {:#x?}",
        d.len(),
        &d[..d.len().min(8)]
    );
    Ok(())
}

#[test]
fn test_f50_plan_allocates_the_parameter_segment_with_fill() -> TestResult {
    let Some(app) = load(&F50)? else {
        return Ok(());
    };
    let plan = plan_flash(
        &app,
        "1.1.18",
        0x07B0,
        &overrides(),
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
    )?;
    let allocs: Vec<_> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            FlashStep::AllocateSegment { size, fill, .. } => Some((*size, *fill)),
            _ => None,
        })
        .collect();
    // `<LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="6152" Mode="1"
    // Fill="0"/>`: ETS sends `03 0b 00 00 18 08 01 00 00 00`.
    assert_eq!(allocs, [(6152, Some(0))]);
    Ok(())
}

#[test]
fn test_a3030_group_object_table_matches_ets() -> TestResult {
    let source = Source {
        product: "all_390041SR_20230313.knxprod",
        inner: None,
        app_id: "M-0004_A-3030-23-F0EA-O000A",
    };
    let Some(app) = load(&source)? else {
        return Ok(());
    };
    let objects = [
        (31, "O-31_R-16", "CWU"),
        (32, "O-32_R-1", "CRTU"),
        (34, "O-34_R-26", "CWU"),
        (35, "O-35_R-29", "CWU"),
        (36, "O-36_R-28", "CRTU"),
        (51, "O-51_R-155", "CWU"),
        (52, "O-52_R-158", "CRTU"),
        (54, "O-54_R-156", "CWU"),
        (55, "O-55_R-157", "CWU"),
        (56, "O-56_R-160", "CRTU"),
        (71, "O-71_R-56", "CWU"),
        (72, "O-72_R-59", "CRTU"),
        (74, "O-74_R-57", "CWU"),
        (75, "O-75_R-58", "CWU"),
        (76, "O-76_R-61", "CRTU"),
        (91, "O-91_R-69", "CWU"),
        (92, "O-92_R-72", "CRTU"),
        (94, "O-94_R-70", "CWU"),
        (95, "O-95_R-71", "CWU"),
        (96, "O-96_R-90", "CRTU"),
    ];
    let ours = dynamic_group_object_table(&app, &BTreeMap::new(), &linked(&objects)?)
        .ok_or("no group-object table")?;
    assert_image("A-3030 obj3", &ours, &fixture("a3030-obj3.hex")?);
    Ok(())
}

#[test]
fn test_a0ed_group_object_table_matches_ets() -> TestResult {
    let source = Source {
        product: "IBUS_ETS5_ABB_XX_V24-12-20_9AKK107046A7479-Rev_P.knxprod",
        inner: None,
        app_id: "M-0002_A-A0ED-10-9B4E",
    };
    let Some(app) = load(&source)? else {
        return Ok(());
    };
    // The project sets the Read flag on the inputs' switch objects: ETS
    // writes the per-object flags (`df00`), not the product's (`d700`).
    let objects = [
        (89, "O-89_R-89", "CRWTU"),
        (98, "O-98_R-252", "CRWTU"),
        (100, "O-100_R-254", "CWTU"),
        (107, "O-107_R-369", "CRWTU"),
        (116, "O-116_R-532", "CRWTU"),
        (125, "O-125_R-649", "CRWTU"),
        (134, "O-134_R-812", "CRWTU"),
        (143, "O-143_R-929", "CRWTU"),
        (152, "O-152_R-1092", "CRWTU"),
        (161, "O-161_R-1209", "CRWTU"),
        (170, "O-170_R-1372", "CRWTU"),
        (179, "O-179_R-1489", "CRWTU"),
        (188, "O-188_R-1652", "CWTU"),
        (197, "O-197_R-1769", "CWTU"),
        (206, "O-206_R-1932", "CWTU"),
        (215, "O-215_R-2049", "CWTU"),
    ];
    let overrides: BTreeMap<String, String> = [("P-16252_R-19496", "8"), ("P-508_R-541", "1")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let ours = dynamic_group_object_table(&app, &overrides, &linked(&objects)?)
        .ok_or("no group-object table")?;
    assert_image("A-A0ED obj3", &ours, &fixture("a0ed-obj3.hex")?);
    Ok(())
}

#[test]
fn test_helios_tables_match_ets() -> TestResult {
    // The cached archive nests the product file; its A-0003-10 build is the
    // 8AB9 one (the device reports D375), and ETS's images match it.
    let source = Source {
        product: "helios_kwl_knx_connect.knxprod",
        inner: Some("MV_KNX-Bus-Einheit_OEM_2020-11-17_cert.knxprod"),
        app_id: "M-0112_A-0003-10-8AB9-O0115",
    };
    let Some(app) = load(&source)? else {
        return Ok(());
    };
    let objects = [
        (1, "O-1_R-1", "CW"),
        (2, "O-2_R-2", "CRT"),
        (3, "O-3_R-3", "CW"),
        (4, "O-4_R-4", "CRT"),
        (13, "O-13_R-13", "CW"),
        (14, "O-14_R-14", "CRT"),
        (23, "O-23_R-23", "CW"),
        (24, "O-24_R-24", "CRT"),
        (34, "O-34_R-34", "CW"),
        (35, "O-35_R-35", "CRT"),
    ];
    let ours = dynamic_group_object_table(&app, &BTreeMap::new(), &linked(&objects)?)
        .ok_or("no group-object table")?;
    assert_image("Helios obj3", &ours, &fixture("helios-obj3.hex")?);
    let images = compute_parameter_image(&app, &BTreeMap::new(), &BTreeMap::new())?;
    let segment = format!("{}_RS-04-00000", source.app_id);
    let ours = images.get(&segment).ok_or("no parameter segment image")?;
    assert_image("Helios obj4", ours, &fixture("helios-obj4.hex")?);
    Ok(())
}
