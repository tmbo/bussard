//! The re-capture rule of the synthetic products (epic #596, step 10).
//!
//! `captures/synthetic/manifest.json` records, per product and variant, the
//! digest of the product XML the ETS capture was taken with (the digest
//! `tests-support/synthetic-products/generate.py` writes into `signed.toml`).
//! A capture of other XML proves nothing about the committed product, so this
//! test fails when a product's committed `xml/` no longer matches its entry,
//! and names the command that re-captures it. It also checks that every file
//! a capture entry promises is committed. Ungated: it reads committed files
//! only.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The files every capture directory holds (`captures/synthetic/<product>/<variant>/`).
const CAPTURE_FILES: [&str; 6] = [
    "image.json",
    "ets.pcapng",
    "sim.yaml",
    "driver.json",
    "ops.txt",
    "requests.txt",
];

/// The workspace root.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `generate.py`'s `xml_digest`: sha256 over every `*.xml` under `xml/`, in
/// order of the relative path, each as `path NUL contents NUL`.
fn xml_digest(xml: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    let mut stack = vec![xml.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "xml") {
                let rel = path
                    .strip_prefix(xml)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push((rel, path));
            }
        }
    }
    files.sort();
    let mut hasher = Sha256::new();
    for (rel, path) in files {
        hasher.update(rel.as_bytes());
        hasher.update([0]);
        hasher.update(std::fs::read(&path)?);
        hasher.update([0]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The manifest's capture entries.
fn manifest() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let path = workspace_root().join("captures/synthetic/manifest.json");
    let text = std::fs::read_to_string(&path)?;
    let doc: serde_json::Value = serde_json::from_str(&text)?;
    let captures = doc["captures"]
        .as_array()
        .ok_or("manifest.json: no `captures` array")?;
    Ok(captures.clone())
}

#[test]
fn test_xml_digest_matches_signed_toml() -> TestResult {
    // The digest this test computes is the one generate.py records; the
    // product's signed.toml is written by the same function.
    let product = workspace_root().join("tests-support/synthetic-products/syn-minimal");
    let signed = std::fs::read_to_string(product.join("signed.toml"))?;
    let digest = xml_digest(&product.join("xml"))?;
    assert!(
        signed.contains(&format!("xml_sha256 = \"{digest}\"")),
        "syn-minimal: signed.toml does not record {digest}; run \
         `uv run tests-support/synthetic-products/generate.py --check`"
    );
    Ok(())
}

#[test]
fn test_manifest_captures_match_committed_xml() -> TestResult {
    let root = workspace_root();
    let entries = manifest()?;
    assert!(
        !entries.is_empty(),
        "captures/synthetic/manifest.json lists no capture"
    );
    let mut stale = Vec::new();
    for e in &entries {
        let product = e["product"].as_str().ok_or("an entry without `product`")?;
        let variant = e["variant"].as_str().ok_or("an entry without `variant`")?;
        let recorded = e["xml_sha256"]
            .as_str()
            .ok_or("an entry without `xml_sha256`")?;
        let xml = root
            .join("tests-support/synthetic-products")
            .join(product)
            .join("xml");
        let digest = xml_digest(&xml)?;
        if digest != recorded {
            stale.push(format!(
                "{product}/{variant}: captured from xml/ {recorded}, the committed xml/ is \
                 {digest}. Re-capture it with ETS: `uv run tools/ets-sweep/synthetic/capture.py \
                 {product}` (tests-support/synthetic-products/README.md, \"Captures\"), and \
                 commit captures/synthetic/ with the product."
            ));
        }
        let dir = root.join("captures/synthetic").join(product).join(variant);
        for file in CAPTURE_FILES {
            if !dir.join(file).is_file() {
                stale.push(format!("{product}/{variant}: {file} is not committed"));
            }
        }
    }
    assert!(stale.is_empty(), "{}", stale.join("\n"));
    Ok(())
}
