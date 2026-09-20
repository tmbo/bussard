//! Committed-fixture conformance sweep — the CI-runnable half of the corpus gate.
//!
//! The full 500-product sweep (`flash_corpus.rs`) needs the large, git-ignored
//! vendor cache and only runs when `BUSSARD_PRODUCT_CORPUS` is set. This test
//! runs in *normal* CI with no cache: it assembles the committed, fabricated
//! fixtures under `tests/fixtures/corpus/` into `.knxprod` ZIPs in a temp dir,
//! runs the real `read_knxprod` + [`bussard_download::sweep_corpus`] pipeline over
//! them, and asserts:
//!
//! 1. each fixture lands in the bucket its shape implies (multi-app System 7,
//!    union-image, extension-lie, enum-leniency, parse-fail);
//! 2. **nothing panics** anywhere in the pipeline (a panic bucket is a hard
//!    failure — panics break the gate and must be fixed in the engine);
//! 3. the rendered manifest matches the checked-in baseline
//!    `tests-support/product-corpus/fixture-conformance.json` byte-for-byte, so a
//!    silent conformance drift shows up as a reviewable diff.
//!
//! Regenerate the baseline (and its markdown twin) by running this test with
//! `BUSSARD_UPDATE_SWEEP_MANIFEST=1`.

use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::{ImageClass, ParseClass, PlanClass, SweepManifest, sweep_corpus};
use zip::write::SimpleFileOptions;

/// Repo root (two levels up from this crate's manifest dir).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize repo root")
}

/// The committed fixture directory.
fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("corpus")
}

/// The checked-in baseline manifest + its markdown twin.
fn baseline_json() -> PathBuf {
    repo_root().join("tests-support/product-corpus/fixture-conformance.json")
}
fn baseline_md() -> PathBuf {
    repo_root().join("tests-support/product-corpus/fixture-conformance.md")
}

/// Writes a single-app `.knxprod` from a committed `.app.xml`, wrapping it in the
/// minimal container `read_knxprod` expects (`knx_master.xml`, `Hardware.xml`,
/// the app xml). The app id is read from the file's `Id="…"` attribute.
fn build_single_app_knxprod(app_xml_path: &Path, out: &Path) {
    let xml = std::fs::read_to_string(app_xml_path).expect("read fixture app xml");
    let app_id = extract_attr(&xml, "Id").unwrap_or_else(|| "M-0000_A-0000".to_string());
    let manuf = app_id.split('_').next().unwrap_or("M-0000").to_string();

    let hardware = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/20">
 <ManufacturerData><Manufacturer RefId="{manuf}">
  <Hardware>
   <Products><Product OrderNumber="FIX-1" /></Products>
   <Hardware2Programs><Hardware2Program>
    <ApplicationProgramRef RefId="{app_id}" />
   </Hardware2Program></Hardware2Programs>
  </Hardware>
 </Manufacturer></ManufacturerData>
</KNX>"#
    );

    let f = std::fs::File::create(out).expect("create knxprod");
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts).unwrap();
    zip.write_all(b"<KNX/>").unwrap();
    zip.start_file(format!("{manuf}/Hardware.xml"), opts)
        .unwrap();
    zip.write_all(hardware.as_bytes()).unwrap();
    zip.start_file(format!("{manuf}/{app_id}.xml"), opts)
        .unwrap();
    zip.write_all(xml.as_bytes()).unwrap();
    zip.finish().unwrap();
}

/// Writes a multi-app `.knxprod` from a committed `*.knxprod.d/` directory that
/// holds a `Hardware.xml` plus several `M-*.xml` application programs.
fn build_multi_app_knxprod(dir: &Path, out: &Path) {
    let hardware = std::fs::read_to_string(dir.join("Hardware.xml")).expect("read Hardware.xml");
    let manuf = extract_attr(&hardware, "RefId").unwrap_or_else(|| "M-0000".to_string());

    let f = std::fs::File::create(out).expect("create knxprod");
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts).unwrap();
    zip.write_all(b"<KNX/>").unwrap();
    zip.start_file(format!("{manuf}/Hardware.xml"), opts)
        .unwrap();
    zip.write_all(hardware.as_bytes()).unwrap();

    let mut app_files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("M-") && n.ends_with(".xml"))
        })
        .collect();
    app_files.sort();
    for p in &app_files {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let xml = std::fs::read_to_string(p).unwrap();
        zip.start_file(format!("{manuf}/{name}"), opts).unwrap();
        zip.write_all(xml.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
}

/// Minimal attribute extractor for the fixture assembly (avoids pulling an XML
/// dep into the test just to read one `Id`/`RefId`). Returns the first
/// space-preceded `key="…"`, so a request for `Id` does not accidentally match
/// the `Id` inside `RefId="…"`.
fn extract_attr(xml: &str, key: &str) -> Option<String> {
    let needle = format!(" {key}=\"");
    let start = xml.find(&needle)? + needle.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_string())
}

/// Assembles every committed fixture into a temp corpus dir and returns it.
fn assemble_corpus(tmp: &Path) {
    let fx = fixtures_dir();
    // Single-app fixtures: every *.app.xml.
    for entry in std::fs::read_dir(&fx).unwrap().flatten() {
        let p = entry.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".app.xml") {
            let stem = name.trim_end_matches(".app.xml");
            build_single_app_knxprod(&p, &tmp.join(format!("{stem}.knxprod")));
        }
    }
    // Multi-app fixtures: every *.knxprod.d/ directory.
    for entry in std::fs::read_dir(&fx).unwrap().flatten() {
        let p = entry.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() && name.ends_with(".knxprod.d") {
            let stem = name.trim_end_matches(".d");
            build_multi_app_knxprod(&p, &tmp.join(stem));
        }
    }
}

#[test]
fn fixture_corpus_sweep_buckets_as_expected() {
    let tmp = tempfile::tempdir().unwrap();
    assemble_corpus(tmp.path());
    let manifest = sweep_corpus(tmp.path());

    // Regenerate the baseline first, so a deliberate refresh does not trip the
    // shape assertions below (which encode the *current* intent).
    if std::env::var_os("BUSSARD_UPDATE_SWEEP_MANIFEST").is_some() {
        std::fs::write(baseline_json(), manifest.to_json()).expect("write baseline json");
        std::fs::write(baseline_md(), manifest.to_markdown()).expect("write baseline md");
        eprintln!("baseline regenerated (BUSSARD_UPDATE_SWEEP_MANIFEST set)");
    }

    // No panic anywhere — a panic bucket is never acceptable.
    assert_eq!(
        manifest.totals.parse_panicked, 0,
        "a fixture parse panicked — convert the panic to a refusal in the parser"
    );
    assert_eq!(
        manifest.totals.image_panicked, 0,
        "a fixture image build panicked — convert the panic to a refusal"
    );
    assert_eq!(
        manifest.totals.plan_panicked, 0,
        "a fixture plan lowering panicked — convert the panic to a refusal"
    );

    // Per-fixture bucket assertions.
    let by_file = |name: &str| {
        manifest
            .products
            .iter()
            .find(|p| p.file == name)
            .unwrap_or_else(|| panic!("fixture {name} missing from sweep"))
    };

    // Multi-app / multi-mask Theben RM 4 shape: 8 application programs across two
    // masks (four 0705 + four 0701) in one product file. The regression this
    // guards is that a multi-app, multi-mask container fully parses and every app
    // is classified (never a panic, never left unclassified) — System 7 (0705 and
    // 0701) is a supported family, so these lower rather than refusing up front.
    let rm4 = by_file("theben_rm4_multiapp.knxprod");
    assert!(
        matches!(rm4.parse, ParseClass::Ok { apps: 8 }),
        "RM4 must parse 8 apps"
    );
    assert_eq!(rm4.apps.len(), 8);
    assert!(
        rm4.apps.iter().any(|a| a.mask.as_deref() == Some("0705"))
            && rm4.apps.iter().any(|a| a.mask.as_deref() == Some("0701")),
        "RM4 fixture must span both System 7 masks (0705 and 0701)"
    );
    assert!(
        rm4.apps
            .iter()
            .all(|a| !matches!(a.plan, PlanClass::Panicked)),
        "no RM4 app may panic during lowering"
    );

    // Union-heavy Zennio: image ok, plan executable (System B).
    let union = by_file("zennio_union.knxprod");
    let ua = &union.apps[0];
    assert!(
        matches!(ua.image, ImageClass::Ok { .. }),
        "union image must synthesize"
    );
    assert!(
        matches!(ua.plan, PlanClass::Executable { .. }),
        "union System B app must lower to an executable plan"
    );

    // Interra extension-lie: parses despite the version disagreement; executable.
    let interra = by_file("interra_extension_lie.knxprod");
    assert!(matches!(interra.parse, ParseClass::Ok { .. }));
    assert!(matches!(interra.apps[0].plan, PlanClass::Executable { .. }));

    // Enum default out of range: leniency -> image ok, plan executable.
    let enum_fx = by_file("enum_default_out_of_range.knxprod");
    assert!(matches!(enum_fx.apps[0].image, ImageClass::Ok { .. }));
    assert!(matches!(enum_fx.apps[0].plan, PlanClass::Executable { .. }));

    // Truncated: a clean parse-failure bucket, never a panic.
    let trunc = by_file("truncated.knxprod");
    assert!(
        matches!(trunc.parse, ParseClass::Failed { .. }),
        "a truncated app xml must be a parse-failure bucket, got {:?}",
        trunc.parse
    );

    // Baseline diff (skipped on a regen run, which already wrote it above).
    if std::env::var_os("BUSSARD_UPDATE_SWEEP_MANIFEST").is_some() {
        return;
    }
    let expected = std::fs::read_to_string(baseline_json()).unwrap_or_else(|_| {
        panic!(
            "baseline {} missing; regenerate with BUSSARD_UPDATE_SWEEP_MANIFEST=1",
            baseline_json().display()
        )
    });
    let expected_manifest = SweepManifest::from_json(&expected).expect("parse baseline");
    assert_eq!(
        manifest,
        expected_manifest,
        "fixture conformance drifted from the checked-in baseline \
         ({}). If this change is intended, regenerate with \
         BUSSARD_UPDATE_SWEEP_MANIFEST=1 and review the diff.",
        baseline_json().display()
    );
}
