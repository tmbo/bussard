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
//!
//! A run variant whose capture is a download into a device that an earlier
//! download of the same sim session already programmed (`reload`,
//! `other-app`, `partial`: `tools/ets-sweep/synthetic/capture.py --variant`)
//! commits those earlier downloads as `base-requests.txt`. They are replayed
//! first, into the same device, so the captured download meets the device ETS
//! met; the checks then apply to the captured download as above.
//!
//! A device whose `sim.yaml` has a `knxnet` block (an IP-enabled TP product,
//! `syn-ip-enabled-tp`, bussard issue #455) gets that KNXnet/IP parameter
//! object, as the sim in the VM had it, so ETS's writes to it are replayed too.
//!
//! A device whose `sim.yaml` has a `security` block (a KNX Data Secure capable
//! product, `syn-secure`, bussard issue #423) starts as the sim in the VM did:
//! in factory state under the synthetic FDSK, with the `properties` overrides
//! (its serial number). The replay then runs ETS's secured requests through
//! the device's Data Secure layer: the FDSK session, the tool key ETS writes,
//! and the download under it. ETS sent its second S-A_Sync_Req seconds after
//! the first; the replay waits out the device's 1 s Sync window before it
//! (`SYNC_WINDOW`), since the sim keeps that window on the wall clock. The
//! refusals the sim in the VM gave ETS too are listed in `KNOWN_REFUSALS`.
//! A `security` block with `status: activated` (the `reload`, `partial` and
//! `apply` rows of bussard issue #1054) starts the device as an earlier secured
//! download left it: the tool key, the sending sequence and the group keys from
//! the block or its `keyring`, the senders and flags from the block; the group
//! keys by address resolve once `base-requests.txt` has loaded the address
//! table.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::config::{
    KnxnetSimConfig, PropertyOverride, SecurityConfig, SecurityStatus, serial_override,
};
use knx_sim::device::{Device, LoadState, MasterResetSupport, ProfileOverrides, profile};
use knx_sim::prod::read_knxprod_bytes;
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};
use serde::Deserialize;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A little over the 1 s in which a Data Secure device ignores a further
/// S-A_Sync_Req after its S-A_Sync_Res (KNX 3/3/7 §5.3.2 step 1).
const SYNC_WINDOW: std::time::Duration = std::time::Duration::from_millis(1100);

/// Refusals the replay reproduces from the live run: (capture directory
/// suffix, the rejected request's summary, how many). The sim in the VM gave
/// ETS the same, and the capture shows ETS waiting them out.
const KNOWN_REFUSALS: &[(&str, &str, usize)] = &[
    // The plain PID_SERIAL_NUMBER reads before the FDSK Sync: the factory
    // device refuses them, ETS times out twice and goes on (bussard #859).
    (
        "syn-secure/defaults",
        "REJECTED by 1.1.1: secure refused: plain access refused: device requires KNX Data Secure",
        2,
    ),
    // The same two reads on the second secure product (bussard #859, #1054).
    (
        "syn-secure-property/defaults",
        "REJECTED by 1.1.1: secure refused: plain access refused: device requires KNX Data Secure",
        2,
    ),
];

/// Whether `tpdu` is an S-A_Sync_Req (A_SecureData, SCF service 2).
fn is_sync_request(tpdu: &[u8]) -> bool {
    tpdu.len() > 2 && tpdu[0] & 0x03 == 0x03 && tpdu[1] == 0xF1 && tpdu[2] & 0x07 == 0x02
}

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

/// The part of a capture's `sim.yaml` the replay reads: the device's
/// `knxnet` block, if any.
#[derive(Deserialize)]
struct SimYaml {
    devices: Vec<SimDevice>,
}

/// One device of `sim.yaml`.
#[derive(Deserialize, Default)]
struct SimDevice {
    #[serde(default)]
    knxnet: Option<KnxnetSimConfig>,
    /// The device's answer to a Master Reset (the `bare-restart` variant of
    /// `syn-master-reset` refuses it, bussard #611).
    #[serde(default)]
    master_reset: MasterResetSupport,
    /// The device's KNX Data Secure block (`syn-secure`, bussard #423).
    #[serde(default)]
    security: Option<SecurityConfig>,
    /// Property values the device starts with (the serial number of a
    /// secure device, which its certificate names).
    #[serde(default)]
    properties: Vec<PropertyOverride>,
}

/// The device of the capture's `sim.yaml` (the defaults without the file).
fn sim_device(capture: &Path) -> Result<SimDevice, Box<dyn std::error::Error>> {
    let path = capture.join("sim.yaml");
    if !path.is_file() {
        return Ok(SimDevice::default());
    }
    let sim: SimYaml = serde_norway::from_str(&std::fs::read_to_string(path)?)?;
    Ok(sim.devices.into_iter().next().unwrap_or_default())
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
    // The earlier downloads of a run variant (module doc), replayed first.
    let base = capture.join("base-requests.txt");
    let base = if base.is_file() {
        requests(&base)?
    } else {
        Vec::new()
    };
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
    let sim = sim_device(capture)?;
    // The security block as the sim in the VM resolved it: `factory` under
    // the FDSK, or `activated` with the tool key and tables from the block or
    // the keyring committed next to it (bussard issue #1054).
    let (secure, activated_tables) = match &sim.security {
        Some(sec) if sec.status != SecurityStatus::Plain => {
            let (activation, tables) = sec
                .resolve(
                    capture,
                    IndividualAddress(ia),
                    serial_override(&sim.properties),
                )
                .map_err(|e| format!("{label}: sim.yaml security: {e}"))?;
            (Some(activation), Some(tables))
        }
        _ => (None, None),
    };
    let device = Device::from_product_with_overrides(
        IndividualAddress(ia),
        &pd,
        LoadState::Unloaded,
        ProfileOverrides {
            lsm_access: profile::default_lsm_access_for_mask(mask),
            secure,
            ..Default::default()
        },
        sink.clone(),
    )?;
    let device = device.with_master_reset(sim.master_reset);
    let device = match &sim.security {
        Some(sec) if sec.status == SecurityStatus::Factory => device.with_factory_security(),
        Some(sec) if sec.status == SecurityStatus::Activated => device
            .with_activated_tables(activated_tables.unwrap_or_default())
            .map_err(|e| format!("{label}: {e}"))?,
        _ => device,
    };
    let mut device = device;
    for p in &sim.properties {
        let value: String = p.value.chars().filter(|c| !c.is_whitespace()).collect();
        device = device.with_property(p.object, p.pid, hex(&value)?);
    }
    let device = match sim.knxnet {
        Some(k) => device.with_knxnet(&k.parameters(IndividualAddress(ia))?, k.listed),
        None => device,
    };
    bus.add_device(device);
    // The tunnel's address. ETS sends a plain request from 0.0.0 and the
    // gateway fills in its tunnel address; a secured request carries that
    // address itself, since it is part of the authenticated data. The replay
    // fills it in for the plain requests too, so the connection ETS opened
    // plain continues under the secured requests (`syn-secure`, #423). A
    // capture without a secured request has no other source and is unchanged.
    let tunnel = base
        .iter()
        .chain(&stream)
        .map(|(src, _, _)| *src)
        .find(|src| *src != 0)
        .unwrap_or(0);
    let mut synced = false;
    let base_len = base.len();
    // The events of the earlier downloads are the start state's setup, not
    // the capture: only the capture's refusals are judged. On a Data Secure
    // variant (bussard #1054) the device starts `activated` under the tool
    // key, so the base's commissioning under the FDSK, which the sim in the
    // VM accepted from the factory device, fails its MAC here.
    let mut base_events = 0;
    for (i, (src, dst, tpdu)) in base.into_iter().chain(stream).enumerate() {
        if i == base_len {
            base_events = sink.events().len();
            // The start state's group keys by address resolve against the
            // address table the earlier downloads loaded, as the sim does
            // before its gateway opens.
            bus.settle_activated_tables()
                .map_err(|e| format!("{label}: {e}"))?;
        }
        if is_sync_request(&tpdu) {
            if synced {
                std::thread::sleep(SYNC_WINDOW);
            }
            synced = true;
        }
        let _ = bus.deliver_from_tool(&CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress(if src == 0 { tunnel } else { src }),
            dest: dst,
            tpdu,
        });
    }
    let mut known: Vec<(&str, usize)> = KNOWN_REFUSALS
        .iter()
        .filter(|(dir, _, _)| label.ends_with(dir))
        .map(|(_, summary, n)| (*summary, *n))
        .collect();
    let mut failures: Vec<String> = sink
        .events()
        .into_iter()
        .skip(base_events)
        .filter_map(|e| match e {
            Event::Telegram { summary, .. } if summary.contains("REJECTED") => {
                match known.iter_mut().find(|(s, n)| *s == summary && *n > 0) {
                    Some((_, n)) => {
                        *n -= 1;
                        None
                    }
                    None => Some(format!("{label}: rejected {summary}")),
                }
            }
            _ => None,
        })
        .collect();
    // A known refusal that no longer happens is stale: the entry goes.
    for (summary, n) in known {
        if n > 0 {
            failures.push(format!(
                "{label}: {n} known refusal(s) did not happen, remove them from KNOWN_REFUSALS: {summary}"
            ));
        }
    }
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
