//! Calibration against the committed ETS captures of the synthetic products
//! (epic #596, step 6).
//!
//! Every `captures/synthetic/<product>/<variant>/` holds `requests.txt`, the
//! tool's request TPDUs of an ETS download into knx-sim (distilled from
//! `ets.pcapng` by `tools/ets-sweep/synthetic/distil.py`), and `image.json`,
//! the segments ETS allocated and the octets it wrote (`knxtrace image` of
//! the same capture). This test builds the device from the product's
//! committed `tests-support/synthetic-products/<product>/xml/`, zipped with
//! the stub `knx_master.xml` as `synthetic_products.rs` does, replays the
//! requests into it the way `ets_calibration.rs` replays the DA.tp stream,
//! and requires: no request rejected, every load-state object `Loaded`, every
//! segment where ETS allocated it, and memory holding what ETS wrote. A new
//! product joins when its capture is committed. Ungated: committed files only,
//! no Python and no bussard crate.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::device::{Device, LoadState, ProfileOverrides, profile};
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};
use serde::Deserialize;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One request of `requests.txt`: source, destination, TPDU.
type Request = (u16, u16, Vec<u8>);

/// `image.json` of a capture.
#[derive(Deserialize)]
struct Image {
    /// The relative segments ETS allocated, per load-state object.
    segments: Vec<SegmentRec>,
    /// The contiguous runs of octets ETS wrote.
    regions: Vec<Region>,
}

/// One allocation of `image.json`.
#[derive(Deserialize)]
struct SegmentRec {
    object: u8,
    base: u32,
    size: u32,
}

/// One written run of `image.json`.
#[derive(Deserialize)]
struct Region {
    start: u32,
    hex: String,
}

/// The repository root (knx-sim is a workspace of its own one level down).
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every committed capture directory, `captures/synthetic/<product>/<variant>/`.
fn captures() -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    for product in std::fs::read_dir(repo().join("captures/synthetic"))? {
        let product = product?.path();
        if !product.is_dir() {
            continue;
        }
        for variant in std::fs::read_dir(&product)? {
            let variant = variant?.path();
            if variant.join("requests.txt").is_file() {
                out.push(variant);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The product's `.knxprod` (stub master plus its committed XML) and its
/// rendered application id.
fn product(name: &str) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let dir = repo()
        .join("tests-support/synthetic-products")
        .join(name)
        .join("xml/M-00FA");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        files.push((file, std::fs::read(&path)?));
    }
    files.sort();
    let app = files
        .iter()
        .find(|(file, _)| file.contains("_A-"))
        .map(|(file, _)| file.trim_end_matches(".xml").to_string())
        .ok_or_else(|| format!("{}: no application file", dir.display()))?;
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    for (file, data) in files {
        zip.start_file(format!("M-00FA/{file}"), opts)?;
        zip.write_all(&data)?;
    }
    Ok((zip.finish()?.into_inner(), app))
}

/// Hex text to octets.
fn hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..(i + 2).min(s.len())], 16))
        .collect()
}

/// `requests.txt` as `(source, destination, TPDU)`.
fn requests(path: &Path) -> Result<Vec<Request>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for line in std::fs::read_to_string(path)?.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let [src, dst, tpdu] = f[..] else {
            return Err(format!("{}: bad line {line:?}", path.display()).into());
        };
        out.push((
            u16::from_str_radix(src, 16)?,
            u16::from_str_radix(dst, 16)?,
            hex(tpdu)?,
        ));
    }
    Ok(out)
}

/// Replays one capture; returns its failures (empty when it calibrates).
fn replay(capture: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let label = capture
        .strip_prefix(repo())
        .unwrap_or(capture)
        .display()
        .to_string();
    let name = capture
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{label}: no product directory"))?;
    let (bytes, app) = product(&name)?;
    let pd = read_knxprod_bytes(&bytes, Some(&app))?;
    let stream = requests(&capture.join("requests.txt"))?;
    let image: Image =
        serde_norway::from_str(&std::fs::read_to_string(capture.join("image.json"))?)?;
    // The sweep's sim device: Unloaded, at the first individual destination.
    let ia = stream
        .iter()
        .map(|(_, dst, _)| *dst)
        .find(|dst| *dst != 0)
        .ok_or_else(|| format!("{label}: no individually addressed request"))?;
    let sink = Arc::new(RecordingSink::new());
    let mut bus = Bus::new(sink.clone());
    // The load-state machine the profile makes mandatory for the mask, as a
    // `sim.yaml` without `lsm_access` gets it: memory mapped on 0700 and
    // 0701, property on 0705 (`Device::from_product` would keep property).
    let mask = profile::parse_mask(&pd.mask_version).unwrap_or(0x07B0);
    bus.add_device(Device::from_product_with_overrides(
        IndividualAddress(ia),
        &pd,
        LoadState::Unloaded,
        ProfileOverrides {
            lsm_access: profile::default_lsm_access_for_mask(mask),
            ..Default::default()
        },
        sink.clone(),
    )?);
    for (src, dst, tpdu) in stream {
        let _ = bus.deliver_from_tool(&CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress(src),
            dest: dst,
            tpdu,
        });
    }
    let mut failures: Vec<String> = sink
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Telegram { summary, .. } if summary.contains("REJECTED") => {
                Some(format!("{label}: rejected {summary}"))
            }
            _ => None,
        })
        .collect();
    let dev = bus
        .device(IndividualAddress(ia))
        .ok_or_else(|| format!("{label}: device {ia:04x} missing"))?;
    for o in &pd.objects {
        let state = dev.load_state(o.lsm_index);
        if state != Some(LoadState::Loaded) {
            failures.push(format!("{label}: object {} is {state:?}", o.lsm_index));
        }
    }
    for s in &image.segments {
        let got = dev.memory().segment_of(s.object).map(|g| (g.base, g.len));
        if got != Some((s.base, s.size)) {
            failures.push(format!(
                "{label}: object {} segment {got:x?}, ETS allocated ({:#x}, {:#x})",
                s.object, s.base, s.size
            ));
        }
    }
    // On a memory-mapped load-state machine the 11-octet records ETS writes
    // to the control address are load events, not memory the device keeps.
    let lsm_access = profile::default_lsm_access_for_mask(mask);
    let control = profile::MemoryMappedLsm::default().control_addr;
    for r in &image.regions {
        if lsm_access == profile::LsmAccess::MemoryMapped && r.start == u32::from(control) {
            continue;
        }
        let want = hex(&r.hex)?;
        let got = dev.memory().read(r.start, want.len());
        if got != want {
            let at = got.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(0);
            failures.push(format!(
                "{label}: memory at {:#x} differs from what ETS wrote ({} octets, first at {:#x})",
                r.start,
                want.len(),
                r.start as usize + at
            ));
        }
    }
    Ok(failures)
}

#[test]
fn test_replay_synthetic_captures_match_ets() -> TestResult {
    let captures = captures()?;
    assert!(
        captures.iter().any(|c| c.ends_with("syn-minimal/defaults")),
        "the baseline capture is missing: {captures:?}"
    );
    let mut failures = Vec::new();
    for capture in &captures {
        failures.extend(replay(capture)?);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
