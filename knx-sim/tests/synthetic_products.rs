//! The synthetic product catalogue (epic #596) loads into knx-sim.
//!
//! `tests-support/synthetic-products/<name>/xml/` holds the committed product
//! XML of each synthetic product. This test zips it with the stub
//! `knx_master.xml` (`<KNX/>`) the catalogue ships and reads it with knx-sim's
//! own reader, so the simulator checks the same files bussard's
//! `bussard-prod` test reads, with no shared code: knx-sim depends on no
//! bussard crate.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use knx_sim::prod::{LdCtrl, read_knxprod_bytes};
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `tests-support/synthetic-products/` in the repository.
fn catalogue_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests-support/synthetic-products")
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

/// The `M-00FA/*.xml` files of a product, as `(entry name, contents)`, sorted.
fn product_xml(product: &Path) -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(product.join("xml/M-00FA"))? {
        let p = entry?.path();
        if let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) {
            out.push((format!("M-00FA/{name}"), std::fs::read(&p)?));
        }
    }
    out.sort();
    Ok(out)
}

/// The `.knxprod` of a product: the stub master plus its XML.
fn knxprod(product: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    for (name, data) in product_xml(product)? {
        zip.start_file(name, opts)?;
        zip.write_all(&data)?;
    }
    Ok(zip.finish()?.into_inner())
}

#[test]
fn test_read_knxprod_bytes_synthetic_catalogue() -> TestResult {
    let products = products()?;
    assert!(
        products.iter().any(|p| p.ends_with("syn-minimal")),
        "the baseline product is missing: {products:?}"
    );
    for product in &products {
        let apps: Vec<String> = product_xml(product)?
            .into_iter()
            .filter(|(name, _)| name.contains("_A-"))
            .map(|(name, _)| name["M-00FA/".len()..].trim_end_matches(".xml").to_string())
            .collect();
        assert_eq!(apps.len(), 1, "{}: {apps:?}", product.display());
        let id = &apps[0];
        let bytes = knxprod(product)?;
        let data = read_knxprod_bytes(&bytes, Some(id))?;
        assert_eq!(&data.application_id, id);
        // M-00FA_A-<number>-<version>-0000: the number and version the id names.
        let number = u32::from_str_radix(&id[9..13], 16)?;
        let version = u32::from_str_radix(&id[14..16], 16)?;
        assert_eq!(data.application_number, number, "{id}");
        assert_eq!(data.application_version, version, "{id}");
    }
    Ok(())
}

#[test]
fn test_read_knxprod_bytes_synthetic_minimal_contents() -> TestResult {
    let bytes = knxprod(&catalogue_dir().join("syn-minimal"))?;
    let data = read_knxprod_bytes(&bytes, Some("M-00FA_A-2700-10-0000"))?;
    assert_eq!(data.mask_version, "MV-07B0");
    assert_eq!(data.segments.len(), 1);
    assert_eq!(data.segments[0].lsm_index, 4);
    assert_eq!(data.segments[0].size, 256);
    let steps: Vec<&LdCtrl> = data.load_procedures.iter().flat_map(|p| &p.steps).collect();
    assert_eq!(
        steps,
        vec![
            &LdCtrl::RelSegment {
                lsm_index: 4,
                size: 256,
                mode: 0,
                fill: 0
            },
            &LdCtrl::WriteRelMem {
                obj_index: 4,
                offset: 0,
                size: 256,
                verify: false
            },
        ]
    );
    Ok(())
}
