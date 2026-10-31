//! The group-object table of the synthetic product `syn-com-objects` (#604
//! row 27) is the one ETS wrote (issue #686).
//!
//! The product declares 33 com objects: one per size code from 1 bit to 14
//! octets, the 32 combinations of the C, R, W, T and U flags, priorities Low,
//! High and Alert, and one ReadOnInit. Object 2 is shown, unlinked and has
//! every flag disabled. ETS 6.4.1 downloaded the product at its defaults into
//! knx-sim on 2026-10-31 (`captures/synthetic/syn-com-objects/defaults/`,
//! `image.json`, object 3 at 0x8000, 68 octets) and wrote object 2 as `03 00`:
//! the priority (Low) and the size code (1 bit), no flags.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bussard_download::build_table_images;
use bussard_prod::ProductData;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The group-object table ETS wrote, from the capture's `image.json`.
const ETS_GROUP_OBJECT_TABLE: &str = "00214b00030001010a020b03110412051b06190742084309490a4a0b530c510d5a0e5b0f811082118b1289139214b30099009a00c300c100ca00cb00d100d200db00d900";

/// `tests-support/synthetic-products/syn-com-objects/xml/`.
fn product_xml() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products/syn-com-objects/xml")
}

/// The product, zipped with the stub master the way the catalogue ships it.
fn product(dir: &Path) -> Result<ProductData, Box<dyn std::error::Error>> {
    let out = dir.join("syn-com-objects.knxprod");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(product_xml().join("M-00FA"))? {
        files.push(entry?.path());
    }
    files.sort();
    for path in files {
        let name = path.file_name().ok_or("a file name")?.to_string_lossy();
        zip.start_file(format!("M-00FA/{name}"), opts)?;
        zip.write_all(&std::fs::read(&path)?)?;
    }
    zip.finish()?;
    Ok(bussard_prod::read_knxprod(&out)?)
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn test_build_table_images_flagless_object_keeps_type_octet() -> TestResult {
    let dir = tempfile::tempdir()?;
    let product = product(dir.path())?;
    let app = product.applications.first().ok_or("one application")?;
    let target: bussard_model::IndividualAddress = "1.1.1".parse()?;
    let tables = build_table_images(None, target, app, &BTreeMap::new());
    let table = tables.get(&3).ok_or("a group-object table")?;
    // Object 2 sits at +0x4 (word 0 is the count).
    assert_eq!(hex(table.get(4..6).ok_or("object 2")?), "0300");
    // The other 32 descriptors and the count are unchanged.
    assert_eq!(hex(table), ETS_GROUP_OBJECT_TABLE);
    Ok(())
}
