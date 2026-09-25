//! `read_knxprod_selected` and the parsed-product cache (issue #214): a
//! narrowed read parses only the selected programs, each identical to what the
//! full `read_knxprod` returns for it, and a cached read returns the very same
//! data. The fixture is fabricated here; no vendor data is committed.

use std::io::Write;
use std::path::Path;

use bussard_prod::{AppSelection, ProductData, read_knxprod, read_knxprod_selected};
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const APP_A: &str = "M-00FA_A-0001-11-ABCD-O000A";
const PEI_A: &str = "M-00FA_A-0001-20-ABCD-O000A";
const APP_B: &str = "M-00FA_A-0002-10-1234-O000A";

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-00FA"><Hardware>
    <Hardware Id="M-00FA_H-1" Name="A">
      <Products><Product Id="M-00FA_H-1_P-1" OrderNumber="ORDER-A" /></Products>
      <Hardware2Programs><Hardware2Program Id="M-00FA_H-1_HP-1">
        <ApplicationProgramRef RefId="M-00FA_A-0001-11-ABCD-O000A" />
        <ApplicationProgramRef RefId="M-00FA_A-0001-20-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
    <Hardware Id="M-00FA_H-2" Name="B">
      <Products><Product Id="M-00FA_H-2_P-2" OrderNumber="ORDER-B" /></Products>
      <Hardware2Programs><Hardware2Program Id="M-00FA_H-2_HP-2">
        <ApplicationProgramRef RefId="M-00FA_A-0002-10-1234-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Hardware></Manufacturer></ManufacturerData>
</KNX>"#;

/// One ApplicationProgram with a float parameter type (whose bounds must
/// survive the cache exactly) and one com object.
fn app_xml(id: &str, name: &str, program_type: Option<&str>) -> String {
    let program_type = program_type
        .map(|t| format!(r#" ProgramType="{t}""#))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="{name}" LoadProcedureStyle="MergedProcedure"{program_type}>
   <Static>
    <ParameterTypes>
     <ParameterType Id="{id}_PT-Float" Name="Float"><TypeFloat Encoding="DPT 9" minInclusive="-671088.64" maxInclusive="0.1" /></ParameterType>
    </ParameterTypes>
    <ComObjectTable>
     <ComObject Id="{id}_O-0" Number="0" Text="Switch" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="{id}_O-0_R-1" RefId="{id}_O-0" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
   <LoadProcedures>
    <LoadProcedure MergeId="1"><LdCtrlConnect /><LdCtrlRestart /></LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#
    )
}

/// Writes the three-program fixture; `name_a` names program A so a test can
/// tell two archive versions apart.
fn build(path: &Path, name_a: &str) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    zip.start_file("M-00FA/Hardware.xml", opts)?;
    zip.write_all(HARDWARE_XML.as_bytes())?;
    for (id, name, program_type) in [
        (APP_A, name_a, None),
        (PEI_A, "Pei", Some("PeiProgram")),
        (APP_B, "Other", None),
    ] {
        zip.start_file(format!("M-00FA/{id}.xml"), opts)?;
        zip.write_all(app_xml(id, name, program_type).as_bytes())?;
    }
    zip.finish()?;
    Ok(())
}

/// The programs as a canonical JSON value (maps sorted), for equality.
fn apps_json(product: &ProductData) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(&product.applications)
}

fn ids(product: &ProductData) -> Vec<&str> {
    product.applications.iter().map(|a| a.id.as_str()).collect()
}

#[test]
fn test_read_knxprod_selected_parses_only_the_selection() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build(&path, "Fixture")?;
    let full = read_knxprod(&path)?;
    assert_eq!(ids(&full), vec![APP_A, PEI_A, APP_B]);

    let narrowed = read_knxprod_selected(&path, None, None, |catalog| {
        assert_eq!(catalog.application_ids, vec![APP_A, PEI_A, APP_B]);
        AppSelection::Only(vec![APP_B.to_string()])
    })?;
    assert_eq!(ids(&narrowed), vec![APP_B]);
    let full_b = full.application_by_id(APP_B).ok_or("no B")?;
    let narrowed_b = narrowed.application_by_id(APP_B).ok_or("no B")?;
    assert_eq!(
        serde_json::to_value(full_b)?,
        serde_json::to_value(narrowed_b)?
    );
    // The catalogue parts are complete whatever the selection.
    assert_eq!(narrowed.hardware.order_to_apps.len(), 2);
    assert!(narrowed.master.is_some());
    Ok(())
}

#[test]
fn test_read_knxprod_selected_attaches_the_companion_program() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build(&path, "Fixture")?;
    let full = read_knxprod(&path)?;
    let narrowed = read_knxprod_selected(&path, None, None, |_| {
        AppSelection::Only(vec![APP_A.to_string()])
    })?;
    // The PEI program its Hardware2Program lists is parsed and attached too.
    assert_eq!(ids(&narrowed), vec![APP_A, PEI_A]);
    let a = narrowed.application_by_id(APP_A).ok_or("no A")?;
    assert_eq!(a.companion_programs.len(), 1);
    assert_eq!(
        serde_json::to_value(a)?,
        serde_json::to_value(full.application_by_id(APP_A).ok_or("no A")?)?
    );
    Ok(())
}

#[test]
fn test_read_knxprod_selected_unknown_id_reads_everything() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build(&path, "Fixture")?;
    let full = read_knxprod(&path)?;
    let all = read_knxprod_selected(&path, None, None, |_| {
        AppSelection::Only(vec!["M-00FA_A-FFFF-10-0000".to_string()])
    })?;
    assert_eq!(apps_json(&all)?, apps_json(&full)?);
    Ok(())
}

#[test]
fn test_read_knxprod_selected_exact_empty_is_catalogue_only() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build(&path, "Fixture")?;
    let catalogue = read_knxprod_selected(&path, None, None, |_| AppSelection::Exact(Vec::new()))?;
    assert!(catalogue.applications.is_empty());
    assert!(catalogue.hardware.order_to_apps.contains_key("ORDER-B"));
    let missing = read_knxprod_selected(&path, None, None, |_| {
        AppSelection::Exact(vec!["M-00FA_A-FFFF-10-0000".to_string()])
    })?;
    assert!(missing.applications.is_empty());
    Ok(())
}

#[test]
fn test_read_knxprod_selected_cache_round_trip_is_identical() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build(&path, "Fixture")?;
    let cache = tmp.path().join("cache");
    let full = read_knxprod(&path)?;

    let cold = read_knxprod_selected(&path, None, Some(&cache), |_| AppSelection::All)?;
    let entries: Vec<_> = std::fs::read_dir(&cache)?.flatten().collect();
    assert_eq!(entries.len(), 1, "one entry per archive");
    let entry = entries.first().ok_or("no entry")?.path();
    for name in [
        "catalog.json",
        &format!("{APP_A}.json"),
        &format!("{APP_B}.json"),
    ] {
        assert!(entry.join(name).is_file(), "{name} not cached");
    }
    let warm = read_knxprod_selected(&path, None, Some(&cache), |_| AppSelection::All)?;
    assert_eq!(apps_json(&cold)?, apps_json(&full)?);
    assert_eq!(apps_json(&warm)?, apps_json(&full)?);
    assert_eq!(
        serde_json::to_value(&warm.hardware)?,
        serde_json::to_value(&full.hardware)?
    );
    assert_eq!(
        serde_json::to_value(&warm.master)?,
        serde_json::to_value(&full.master)?
    );
    assert_eq!(warm.manufacturers, full.manufacturers);
    assert_eq!(warm.is_project_export, full.is_project_export);

    // The float bounds come back bit for bit.
    let pt = |p: &ProductData| -> Option<String> {
        let app = p.application_by_id(APP_B)?;
        let decl = app.parameter_types.get(&format!("{APP_B}_PT-Float"))?;
        Some(format!("{:?}", decl.kind))
    };
    assert_eq!(pt(&warm), pt(&full));
    assert!(pt(&full).is_some_and(|s| s.contains("-671088.64")));
    Ok(())
}

#[test]
fn test_read_knxprod_selected_warm_read_comes_from_the_cache() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    build(&path, "Fixture")?;
    let cache = tmp.path().join("cache");
    let only_b = |_: &bussard_prod::ProductCatalog| AppSelection::Only(vec![APP_B.to_string()]);
    read_knxprod_selected(&path, None, Some(&cache), only_b)?;
    let entry = std::fs::read_dir(&cache)?
        .flatten()
        .next()
        .ok_or("no entry")?
        .path();
    // Mark the cached program: a warm read that shows the mark was served
    // from the cache, not parsed.
    let file = entry.join(format!("{APP_B}.json"));
    let marked = std::fs::read_to_string(&file)?.replace("\"Other\"", "\"From cache\"");
    std::fs::write(&file, marked)?;
    let warm = read_knxprod_selected(&path, None, Some(&cache), only_b)?;
    let b = warm.application_by_id(APP_B).ok_or("no B")?;
    assert_eq!(b.name.as_deref(), Some("From cache"));

    // A corrupt file is a miss: the program is parsed again.
    std::fs::write(&file, b"{ not json")?;
    let reparsed = read_knxprod_selected(&path, None, Some(&cache), only_b)?;
    let b = reparsed.application_by_id(APP_B).ok_or("no B")?;
    assert_eq!(b.name.as_deref(), Some("Other"));
    Ok(())
}

#[test]
fn test_read_knxprod_selected_cache_misses_on_a_changed_archive() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("fixture.knxprod");
    let cache = tmp.path().join("cache");
    let only_a = |_: &bussard_prod::ProductCatalog| AppSelection::Only(vec![APP_A.to_string()]);
    build(&path, "First")?;
    let first = read_knxprod_selected(&path, None, Some(&cache), only_a)?;
    build(&path, "Second")?;
    let second = read_knxprod_selected(&path, None, Some(&cache), only_a)?;
    let name = |p: &ProductData| p.application_by_id(APP_A).and_then(|a| a.name.clone());
    assert_eq!(name(&first).as_deref(), Some("First"));
    assert_eq!(name(&second).as_deref(), Some("Second"));
    assert_eq!(
        std::fs::read_dir(&cache)?.count(),
        2,
        "a new entry per archive hash"
    );
    Ok(())
}

/// Against real vendor archives (env-gated on `BUSSARD_PRODUCT_CORPUS`,
/// skips green without it): every program of the first
/// `BUSSARD_SELECTED_CORPUS_LIMIT` archives (default 6), read alone, cold
/// through the cache and warm from it, equals the program of the full read.
#[test]
fn test_read_knxprod_selected_matches_full_read_on_the_corpus() -> TestResult {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("skipping: BUSSARD_PRODUCT_CORPUS is not set");
        return Ok(());
    };
    let limit: usize = std::env::var("BUSSARD_SELECTED_CORPUS_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let mut files: Vec<std::path::PathBuf> = walk(Path::new(&dir))
        .into_iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("knxprod"))
        })
        .collect();
    files.sort();
    let tmp = tempfile::tempdir()?;
    let mut compared = 0usize;
    for file in files.iter().take(limit) {
        let Ok(full) = read_knxprod(file) else {
            continue;
        };
        let cache = tmp.path().join("cache");
        for app in &full.applications {
            let want = serde_json::to_value(app)?;
            for pass in ["cold", "warm"] {
                let one = read_knxprod_selected(file, None, Some(&cache), |_| {
                    AppSelection::Only(vec![app.id.clone()])
                })?;
                let got = one
                    .application_by_id(&app.id)
                    .ok_or("selected program missing")?;
                assert_eq!(
                    serde_json::to_value(got)?,
                    want,
                    "{} {} ({pass})",
                    file.display(),
                    app.id
                );
            }
            compared += 1;
        }
    }
    eprintln!("compared {compared} programs");
    Ok(())
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}
