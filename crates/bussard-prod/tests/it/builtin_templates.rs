//! The built-in mask load-procedure templates against the master data
//! (issue #607).
//!
//! bussard carries the complete-download `Load` template of the System B
//! masks as Rust data ([`MasterTemplate::builtin_for_mask`]), for products
//! without `knx_master.xml`. This test (env-gated on `BUSSARD_PRODUCT_CORPUS`,
//! skips green without it) parses the `knx_master.xml` of every corpus archive
//! and asserts that each built-in mask's template there equals the built-in
//! one: the same sub-type, ops, order and attributes. A master-data version
//! that changes a template fails here.

use std::io::Read;
use std::path::{Path, PathBuf};

use bussard_prod::{BUILTIN_TEMPLATE_MASKS, MasterTemplate, parse_master_template};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Every `.knxprod` under `dir`, sorted.
fn knxprods(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("knxprod"))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The archive's `knx_master.xml`, or `None` when it has none.
fn master_xml(path: &Path) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path)?)?;
    let mut out = Vec::new();
    match zip.by_name("knx_master.xml") {
        Ok(mut entry) => entry.read_to_end(&mut out)?,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(out))
}

#[test]
fn test_builtin_for_mask_matches_corpus_master() -> TestResult {
    let Some(dir) = std::env::var_os("BUSSARD_PRODUCT_CORPUS") else {
        eprintln!("skipping: BUSSARD_PRODUCT_CORPUS is not set");
        return Ok(());
    };
    // The corpus root, its `cache/`, or the vendor directory (dev/testing.md).
    let dir = PathBuf::from(dir);
    let dir = [dir.join("cache/vendor"), dir.join("vendor")]
        .into_iter()
        .find(|d| d.is_dir())
        .unwrap_or(dir);
    let mut compared = [0usize; BUILTIN_TEMPLATE_MASKS.len()];
    let mut mismatches = Vec::new();
    for file in knxprods(&dir) {
        // An archive the zip reader refuses is the reader tests' business.
        let Ok(Some(xml)) = master_xml(&file) else {
            continue;
        };
        let master = parse_master_template(&xml, "knx_master.xml")?;
        for (i, mask) in BUILTIN_TEMPLATE_MASKS.iter().enumerate() {
            let Some(parsed) = master.full_load_procedure(mask) else {
                continue;
            };
            compared[i] += 1;
            if Some(parsed) != MasterTemplate::builtin_for_mask(mask).as_ref() {
                mismatches.push(format!("{} MV-{mask}", file.display()));
            }
        }
    }
    eprintln!("compared per mask {BUILTIN_TEMPLATE_MASKS:?}: {compared:?}");
    assert!(
        mismatches.is_empty(),
        "the built-in template differs from the master data in {} archive(s): {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    assert!(
        compared.iter().all(|&n| n > 0),
        "a built-in mask no corpus master declares: {compared:?}"
    );
    Ok(())
}
