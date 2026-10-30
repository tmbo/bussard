//! The synthetic product catalogue (epic #596) reads with `read_knxprod`.
//!
//! `tests-support/synthetic-products/<name>/xml/` holds the product XML that
//! `generate.py` renders from `<name>/product.toml` (committed; Python is not a
//! test dependency). Each product's XML is zipped here with the stub
//! `knx_master.xml` the catalogue ships, the way `generate.py --zip` packs it,
//! and must read back as one application whose id is the file name, reachable
//! from the order number in `Hardware.xml`.

use std::io::Write;
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/` in the repository.
fn catalogue_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests-support/synthetic-products")
}

/// Every product directory (one holding a `product.toml`), sorted.
fn products() -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(catalogue_dir())? {
        let dir = entry?.path();
        if dir.join("product.toml").is_file() {
            out.push(dir);
        }
    }
    out.sort();
    Ok(out)
}

/// The files under `dir`, as `(path relative to dir with '/', absolute path)`.
fn files_under(dir: &Path) -> Result<Vec<(String, PathBuf)>, std::io::Error> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(rel) = p.strip_prefix(dir) {
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, p));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Zips `<product>/xml/` with a stub master into `out`.
fn zip_product(product: &Path, out: &Path) -> TestResult {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    for (rel, path) in files_under(&product.join("xml"))? {
        zip.start_file(rel, opts)?;
        zip.write_all(&std::fs::read(path)?)?;
    }
    zip.finish()?;
    Ok(())
}

/// The value of the first `attr="..."` in `xml`.
fn attribute<'a>(xml: &'a str, attr: &str) -> Option<&'a str> {
    let needle = format!("{attr}=\"");
    let start = xml.find(&needle)? + needle.len();
    let len = xml[start..].find('"')?;
    Some(&xml[start..start + len])
}

#[test]
fn test_read_knxprod_synthetic_catalogue() -> TestResult {
    let products = products()?;
    let names: Vec<String> = products
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert!(
        names.iter().any(|n| n == "syn-minimal"),
        "the baseline product is missing: {names:?}"
    );
    let tmp = tempfile::tempdir()?;
    for (product, name) in products.iter().zip(&names) {
        let manufacturer_dir = product.join("xml/M-00FA");
        let app_files: Vec<String> = files_under(&manufacturer_dir)?
            .into_iter()
            .filter(|(rel, _)| rel.contains("_A-"))
            .map(|(rel, _)| rel.trim_end_matches(".xml").to_string())
            .collect();
        assert_eq!(
            app_files.len(),
            1,
            "{name}: application files {app_files:?}"
        );
        let expected_id = &app_files[0];
        // The generator leaves the fingerprint to the signer: `..-0000`.
        assert!(
            expected_id.starts_with("M-00FA_A-27") && expected_id.ends_with("-0000"),
            "{name}: {expected_id} is outside the synthetic id rule"
        );

        let path = tmp.path().join(format!("{name}.knxprod"));
        zip_product(product, &path)?;
        let data = bussard_prod::read_knxprod(&path)?;
        assert_eq!(data.manufacturers, vec!["M-00FA".to_string()], "{name}");
        assert_eq!(data.applications.len(), 1, "{name}");
        let app = &data.applications[0];
        assert_eq!(&app.id, expected_id, "{name}");

        let hardware = std::fs::read_to_string(manufacturer_dir.join("Hardware.xml"))?;
        let order = attribute(&hardware, "OrderNumber").ok_or("no OrderNumber in Hardware.xml")?;
        let by_order = data.application_for_order_number(order);
        assert_eq!(by_order.len(), 1, "{name}: order number {order}");
        assert_eq!(&by_order[0].id, expected_id, "{name}");
    }
    Ok(())
}

#[test]
fn test_read_knxprod_synthetic_minimal_contents() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-minimal.knxprod");
    zip_product(&catalogue_dir().join("syn-minimal"), &path)?;
    let data = bussard_prod::read_knxprod(&path)?;
    let app = data.applications.first().ok_or("no application")?;
    assert_eq!(app.id, "M-00FA_A-2700-10-0000");
    assert_eq!(app.application_number, Some(0x2700));
    assert_eq!(app.application_version, Some(0x10));
    assert_eq!(app.mask_version.as_deref(), Some("07B0"));
    assert_eq!(app.resolved_com_objects().len(), 2);
    assert_eq!(app.parameters.len(), 2);
    // The stub master carries no load-procedure template; the built-in one
    // takes its place (issue #607).
    assert_eq!(
        data.master
            .as_ref()
            .and_then(|m| m.full_load_procedure("07B0"))
            .cloned(),
        bussard_prod::MasterTemplate::builtin_for_mask("07B0")
    );
    Ok(())
}
