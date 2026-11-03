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

/// The synthetic identity `tools/ets-sweep/secure.py` (`synthetic_identity`)
/// derives for syn-secure's rendered application id `M-00FA_A-2900-10-0000`:
/// the serial number (manufacturer 00FA, four hash octets) and the FDSK.
/// Synthetic, never a real device's; `capture.py` writes the same pair into
/// the capture's `sim.yaml` (`test_ets_sweep.py` checks that side).
const SYN_SECURE_SERIAL: &str = "00fad4730c98";
const SYN_SECURE_FDSK: &str = "5e2c820a4e1b264302afda130b69c915";

/// syn-secure (bussard #604 row 18, #423) is a Data Secure capable 07B0
/// product. knx-sim builds its device in factory state, as ETS meets it before
/// commissioning: security mode off, the FDSK as tool key, the serial number
/// on the device object, and the security object sized by the product's
/// `MaxSecurityGroupKeyTableEntries` and `MaxSecurityIndividualAddressEntries`
/// (4 and 4).
#[test]
fn test_build_bus_synthetic_secure_factory_device() -> TestResult {
    use std::sync::Arc;

    use knx_sim::bus::event::RecordingSink;
    use knx_sim::config::SimConfig;
    use knx_sim::wire::IndividualAddress;

    let app = "M-00FA_A-2900-10-0000";
    let bytes = knxprod(&catalogue_dir().join("syn-secure"))?;
    let data = read_knxprod_bytes(&bytes, Some(app))?;
    assert_eq!(data.security_capacity.group_key_rows, Some(4));
    assert_eq!(data.security_capacity.ia_rows, Some(4));

    let dir = std::env::temp_dir().join(format!("knx-sim-syn-secure-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("syn-secure.knxprod"), &bytes)?;
    let yaml = format!(
        "gateway:\n  host: 127.0.0.1\n  port: 3672\n\
         devices:\n- address: 1.1.1\n  knxprod: syn-secure.knxprod\n  application: {app}\n  \
         initial_state: unloaded\n  security:\n    status: factory\n    tool_key: {SYN_SECURE_FDSK}\n  \
         properties:\n  - object: 0\n    pid: 11\n    value: {SYN_SECURE_SERIAL}\n"
    );
    let built = SimConfig::from_yaml(&yaml)?.build_bus(&dir, Arc::new(RecordingSink::new()));
    let _ = std::fs::remove_dir_all(&dir);
    let bus = built?;

    let address: IndividualAddress = "1.1.1".parse()?;
    let device = bus.device(address).ok_or("no device 1.1.1")?;
    let security = device.security_object().ok_or("no security object")?;
    assert_eq!(
        security.security_mode(),
        0,
        "factory state: security mode off"
    );
    assert_eq!(security.group_key_capacity(), 4);
    assert_eq!(security.ia_capacity(), 4);
    Ok(())
}
