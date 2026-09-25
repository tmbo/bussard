//! Integration tests for transparently unwrapping ZIP-served `.knxprod` files.
//!
//! Many vendors publish product data as a ZIP containing the actual `.knxprod`
//! (sometimes nested in a folder next to a readme/PDF). Since a `.knxprod` is
//! itself a ZIP, such a wrapper otherwise looks like a `.knxprod` with the wrong
//! entries. These tests assemble a tiny fixture `.knxprod`, wrap it various
//! ways, and assert the unwrap behavior. All fixture data is fabricated here —
//! no vendor data is committed.

use std::io::Write;
use std::path::Path;

use zip::write::SimpleFileOptions;

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-00FA">
    <Hardware>
      <Products><Product OrderNumber="TEST-1" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-00FA_A-0001-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
  <ApplicationProgram Id="M-00FA_A-0001-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Fixture" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-00FA_A-0001-11-ABCD-O000A_O-0" Number="0" Text="Switch" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-00FA_A-0001-11-ABCD-O000A_O-0_R-1" RefId="M-00FA_A-0001-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
   <LoadProcedures>
    <LoadProcedure MergeId="1"><LdCtrlConnect /><LdCtrlRestart /></LoadProcedure>
   </LoadProcedures>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

/// Builds a real (unwrapped) fixture `.knxprod` into a byte buffer.
fn knxprod_bytes() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default();
        zip.start_file("knx_master.xml", opts)?;
        zip.write_all(b"<KNX/>")?;
        zip.start_file("M-00FA/Hardware.xml", opts)?;
        zip.write_all(HARDWARE_XML.as_bytes())?;
        zip.start_file("M-00FA/M-00FA_A-0001-11-ABCD-O000A.xml", opts)?;
        zip.write_all(APP_XML.as_bytes())?;
        zip.finish()?;
    }
    Ok(buf)
}

/// Wraps the given (name, bytes) entries into a ZIP written to `path`.
fn write_wrapper(path: &Path, entries: &[(&str, &[u8])]) -> Result<(), Box<dyn std::error::Error>> {
    let f = std::fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default();
    for (name, bytes) in entries {
        zip.start_file(*name, opts)?;
        zip.write_all(bytes)?;
    }
    zip.finish()?;
    Ok(())
}

/// A direct read and a read through a single-inner wrapper produce identical
/// product data (transparent unwrap).
#[test]
fn test_read_knxprod_transparent_wrapper_equals_direct() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let inner = knxprod_bytes()?;

    // Direct read of the plain `.knxprod`.
    let direct_path = tmp.path().join("direct.knxprod");
    std::fs::write(&direct_path, &inner)?;
    let direct = bussard_prod::read_knxprod(&direct_path)?;

    // Wrapper: the `.knxprod` nested one folder deep, next to a readme (as many
    // real vendor ZIPs are laid out).
    let wrapped_path = tmp.path().join("wrapped.zip");
    write_wrapper(
        &wrapped_path,
        &[
            ("product-3.0/Readme.txt", b"read me"),
            ("product-3.0/fixture.knxprod", &inner),
        ],
    )?;
    let wrapped = bussard_prod::read_knxprod(&wrapped_path)?;

    assert_eq!(direct.manufacturers, wrapped.manufacturers);
    assert_eq!(direct.applications.len(), wrapped.applications.len());
    assert_eq!(direct.applications[0].id, wrapped.applications[0].id);
    assert_eq!(direct.applications[0].name, wrapped.applications[0].name);
    assert_eq!(
        wrapped.application_for_order_number("TEST-1").len(),
        1,
        "order-number matching survives the unwrap"
    );
    Ok(())
}

/// A wrapper with the `.knxprod` at the archive root (no folder) also unwraps.
#[test]
fn test_read_knxprod_wrapper_at_root() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let inner = knxprod_bytes()?;
    let path = tmp.path().join("root.zip");
    write_wrapper(&path, &[("Fixture.KNXPROD", &inner)])?;

    let product = bussard_prod::read_knxprod(&path)?;
    assert_eq!(product.applications.len(), 1);
    Ok(())
}

/// A wrapper with several inner `.knxprod` files errors, listing the entries.
#[test]
fn test_read_knxprod_multi_inner_lists_entries() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let inner = knxprod_bytes()?;
    let path = tmp.path().join("multi.zip");
    write_wrapper(
        &path,
        &[
            ("pkg/first.knxprod", &inner),
            ("pkg/second.knxprod", &inner),
        ],
    )?;

    let err = bussard_prod::read_knxprod(&path)
        .err()
        .ok_or("expected an error")?
        .to_string();
    assert!(err.contains("multiple .knxprod"), "{err}");
    assert!(err.contains("first.knxprod"), "{err}");
    assert!(err.contains("second.knxprod"), "{err}");
    assert!(err.contains("--inner"), "{err}");
    Ok(())
}

/// `read_knxprod_inner` selects one of several inner `.knxprod` files by name.
#[test]
fn test_read_knxprod_inner_selects_by_name() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let inner = knxprod_bytes()?;
    let path = tmp.path().join("multi.zip");
    write_wrapper(
        &path,
        &[
            ("pkg/first.knxprod", &inner),
            ("pkg/second.knxprod", &inner),
        ],
    )?;

    // Bare file name matches.
    let product = bussard_prod::read_knxprod_inner(&path, Some("second.knxprod"))?;
    assert_eq!(product.applications.len(), 1);

    // Full entry path also matches.
    let product = bussard_prod::read_knxprod_inner(&path, Some("pkg/first.knxprod"))?;
    assert_eq!(product.applications.len(), 1);

    // A name that matches nothing errors with the candidate list.
    let err = bussard_prod::read_knxprod_inner(&path, Some("nope.knxprod"))
        .err()
        .ok_or("expected an error")?
        .to_string();
    assert!(
        err.contains("first.knxprod") && err.contains("second.knxprod"),
        "{err}"
    );
    Ok(())
}

/// A ZIP that contains no `.knxprod` inside is not a wrapper; it surfaces as an
/// ordinary (empty) product, so the caller's "no application programs" check
/// fires with a clear message.
#[test]
fn test_read_knxprod_no_inner_knxprod() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("junk.zip");
    write_wrapper(
        &path,
        &[("Readme.txt", b"nothing here"), ("notes.pdf", b"%PDF-1.4")],
    )?;

    // Not treated as a wrapper (no inner `.knxprod`): reads as an empty product
    // rather than erroring at the container layer.
    let product = bussard_prod::read_knxprod(&path)?;
    assert!(product.manufacturers.is_empty());
    assert!(product.applications.is_empty());
    Ok(())
}

/// A doubly wrapped archive (a wrapper whose single inner `.knxprod` is itself a
/// wrapper) is rejected — unwrapping recurses at most one level.
#[test]
fn test_read_knxprod_nested_wrapper_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let inner = knxprod_bytes()?;

    // Middle layer: a ZIP whose only `.knxprod` entry is the real one.
    let mut middle = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut middle));
        let opts = SimpleFileOptions::default();
        zip.start_file("inner.knxprod", opts)?;
        zip.write_all(&inner)?;
        zip.finish()?;
    }

    // Outer layer wraps the middle wrapper under a `.knxprod` name.
    let path = tmp.path().join("double.zip");
    write_wrapper(&path, &[("outer.knxprod", &middle)])?;

    let err = bussard_prod::read_knxprod(&path)
        .err()
        .ok_or("expected an error")?
        .to_string();
    assert!(err.contains("nested wrappers are not supported"), "{err}");
    Ok(())
}

/// An inner `.knxprod` whose decompressed size exceeds the cap is rejected
/// rather than buffered (zip-bomb guard). Uses a tiny cap indirectly by making
/// the inner larger than the real cap would be impractical, so we assert the
/// guard fires against a huge highly-compressible payload.
#[test]
fn test_read_knxprod_oversized_inner_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;

    // Build an "inner" entry that decompresses well past the 100 MiB cap but
    // compresses tiny (a run of zeros). It is not a valid `.knxprod`, but the
    // size guard trips before any parsing.
    let path = tmp.path().join("bomb.zip");
    let f = std::fs::File::create(&path)?;
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("huge.knxprod", opts)?;
    // 200 MiB of zeros, written in chunks to keep test memory bounded.
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..200 {
        zip.write_all(&chunk)?;
    }
    zip.finish()?;

    let err = bussard_prod::read_knxprod(&path)
        .err()
        .ok_or("expected an error")?
        .to_string();
    assert!(
        err.contains("decompression cap") || err.contains("refusing to buffer"),
        "{err}"
    );
    Ok(())
}
