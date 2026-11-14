//! Calibration of the BCU 2 device (masks 0020 / 0021 / 0025, bussard issue
//! #525) against the corpus products' own load procedures.
//!
//! No ETS capture of a BCU 2 download exists yet, so this test is the ETS
//! side: a small executor of the load-control elements runs each corpus BCU 2
//! application's own `LoadProcedure` against the simulated device, the way a
//! scripted client would, and checks that the device takes every telegram,
//! ends with the three LSMs `Loaded`, and holds the memory image the product
//! declares (`Static/Code/AbsoluteSegment`, the octets its `<Mask>` defines).
//!
//! What the executor assumes ETS does, until a capture says otherwise
//! (`knx-sim/DESIGN.md`, "System 2"):
//!
//! - after an `LdCtrlAbsSegment` it writes the octets of the matching code
//!   segment that the mask defines, in runs of at most 12 octets;
//! - `LdCtrlTaskSegment` sends the Segment Control Record with the program's
//!   PEI type and id on the application LSM and zeros on the table LSMs
//!   (KNX 2/3/1 Cookbook §3, the table records);
//! - controls on LSM 5 (`AbsCObjSeg`, Cookbook §2.3) are ETS-internal and
//!   never reach the bus.
//!
//! The corpus is copyrighted and not committed: the test reads the cache
//! under `BUSSARD_PRODUCT_CORPUS` (else the repository's
//! `tests-support/product-corpus`) and the committed application list
//! `tools/ets-sweep/catalog-apps.json`, and skips when either is absent.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use knx_sim::bus::Bus;
use knx_sim::bus::event::{Event, RecordingSink};
use knx_sim::device::{Device, LoadState, ProfileOverrides};
use knx_sim::prod::{ProductData, read_knxprod_bytes};
use knx_sim::wire::{CemiLData, IndividualAddress, MessageCode};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DEV: u16 = 0x1101; // 1.1.1, as the sweep places it

/// The BCU 2 programs this test expects to refuse, with the reason. Every
/// other corpus BCU 2 program with a load procedure must load.
const EXPECTED_REFUSALS: &[(&str, &str)] = &[(
    "M-0004_A-9019-01-6428-O00A6",
    "writes parameters into LSM 3 without allocating a segment: the hardware keeps \
     factory segments the product data does not describe",
)];

/// One load-control element: its name and attributes.
#[derive(Debug, Clone)]
struct Step {
    name: String,
    attrs: BTreeMap<String, String>,
}

impl Step {
    fn num(&self, key: &str) -> u32 {
        self.attrs
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        let s = self.attrs.get(key).map(String::as_str).unwrap_or("");
        (0..s.len() / 2)
            .filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
            .collect()
    }
}

/// A scripted client on one simulated device.
struct Client {
    bus: Bus,
    sink: Arc<RecordingSink>,
    seq: u8,
    connected: bool,
}

impl Client {
    fn new(product: &ProductData) -> TestResult<Self> {
        let sink = Arc::new(RecordingSink::new());
        let dev = Device::from_product_with_overrides(
            IndividualAddress(DEV),
            product,
            LoadState::Unloaded,
            ProfileOverrides::default(),
            sink.clone(),
        )?;
        let mut bus = Bus::new(sink.clone());
        bus.add_device(dev);
        Ok(Self {
            bus,
            sink,
            seq: 0,
            connected: false,
        })
    }

    fn frame(tpdu: Vec<u8>) -> CemiLData {
        CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress(0x0000),
            dest: DEV,
            tpdu,
        }
    }

    fn connect(&mut self) {
        self.bus.deliver_from_tool(&Self::frame(vec![0x80]));
        self.seq = 0;
        self.connected = true;
        self.ndt(0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    fn disconnect(&mut self) {
        self.bus.deliver_from_tool(&Self::frame(vec![0x81]));
        self.connected = false;
    }

    fn ndt(&mut self, apci10: u16, payload: &[u8]) -> Vec<CemiLData> {
        if !self.connected {
            self.connect();
        }
        let mut tpdu = vec![
            0x40 | ((self.seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
            (apci10 & 0xFF) as u8,
        ];
        tpdu.extend_from_slice(payload);
        self.seq = (self.seq + 1) & 0x0F;
        self.bus.deliver_from_tool(&Self::frame(tpdu))
    }

    fn pid5(&mut self, object: u8, record: [u8; 10]) {
        let mut payload = vec![object, 0x05, 0x10, 0x01];
        payload.extend_from_slice(&record);
        self.ndt(0x3D7, &payload);
    }

    fn mem_write(&mut self, address: u16, data: &[u8]) {
        for (i, piece) in data.chunks(12).enumerate() {
            let at = address.wrapping_add((i * 12) as u16);
            let mut payload = at.to_be_bytes().to_vec();
            payload.extend_from_slice(piece);
            self.ndt(0x280 | piece.len() as u16, &payload);
        }
    }

    /// Reads a property's value (the response after the 4-octet header).
    fn read_prop(&mut self, object: u8, pid: u8, start: u16, count: u8) -> Vec<u8> {
        let header = [
            object,
            pid,
            (count << 4) | ((start >> 8) as u8 & 0x0F),
            (start & 0xFF) as u8,
        ];
        self.ndt(0x3D5, &header)
            .into_iter()
            .find(|r| r.tpdu.len() >= 6 && r.tpdu[0] & 0x03 == 0x03 && r.tpdu[1] == 0xD6)
            .map(|r| r.tpdu[6..].to_vec())
            .unwrap_or_default()
    }

    fn device(&self) -> TestResult<&Device> {
        self.bus
            .device(IndividualAddress(DEV))
            .ok_or_else(|| "device gone".into())
    }

    fn rejections(&self) -> Vec<String> {
        self.sink
            .events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Telegram { summary, .. } if summary.contains("REJECTED") => Some(summary),
                _ => None,
            })
            .collect()
    }
}

/// The load-control elements of the program's first `LoadProcedure`.
fn procedure(xml: &str) -> TestResult<Vec<Step>> {
    use quick_xml::events::Event as X;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut steps = Vec::new();
    let mut inside = false;
    loop {
        match reader.read_event()? {
            X::Eof => break,
            X::Start(e) if e.name().as_ref() == b"LoadProcedure" => inside = true,
            X::End(e) if e.name().as_ref() == b"LoadProcedure" => break,
            X::Start(e) | X::Empty(e) if inside && e.name().as_ref().starts_with(b"LdCtrl") => {
                let mut attrs = BTreeMap::new();
                for a in e.attributes().flatten() {
                    attrs.insert(
                        String::from_utf8_lossy(a.key.as_ref()).into_owned(),
                        String::from_utf8_lossy(&a.value).into_owned(),
                    );
                }
                steps.push(Step {
                    name: String::from_utf8_lossy(e.name().as_ref()).into_owned(),
                    attrs,
                });
            }
            _ => {}
        }
    }
    Ok(steps)
}

/// The program id a Segment Control Record carries: manufacturer, application
/// number, version (KNX 3/5/2 §3.31.3.4, AllocAbsTaskSeg).
fn program_id(product: &ProductData) -> [u8; 5] {
    let manufacturer = knx_sim::prod::program_manufacturer(&product.application_id).unwrap_or(0);
    let [m0, m1] = manufacturer.to_be_bytes();
    let [a0, a1] = u16::try_from(product.application_number)
        .unwrap_or(0)
        .to_be_bytes();
    let v = u8::try_from(product.application_version).unwrap_or(0);
    [m0, m1, a0, a1, v]
}

/// The octets of the code segment at exactly `[address, address + size)` that
/// its mask defines, as `(address, run)` runs.
fn masked_runs(product: &ProductData, address: u16, size: u16) -> Vec<(u16, Vec<u8>)> {
    let Some(seg) = product
        .absolute_segments
        .iter()
        .find(|s| s.address == address && s.size == size)
    else {
        return Vec::new();
    };
    let mut runs: Vec<(u16, Vec<u8>)> = Vec::new();
    for (i, byte) in seg.data.iter().enumerate() {
        let defined = seg.mask.is_empty() || seg.mask.get(i).is_some_and(|m| *m == 0xFF);
        if !defined {
            continue;
        }
        let at = address.wrapping_add(i as u16);
        match runs.last_mut() {
            Some((start, run)) if start.wrapping_add(run.len() as u16) == at => run.push(*byte),
            _ => runs.push((at, vec![*byte])),
        }
    }
    runs
}

/// Runs the program's own procedure; returns why it did not load, if so.
fn run_procedure(product: &ProductData, steps: &[Step]) -> TestResult<Option<String>> {
    let mut client = Client::new(product)?;
    let mut allocated: Vec<(u16, u16)> = Vec::new();
    let mut lsms: Vec<u8> = Vec::new();
    let mut task_segment_3 = false;
    for step in steps {
        let lsm = u8::try_from(step.num("LsmIdx")).unwrap_or(0);
        if lsm == 5 {
            continue; // ETS-internal (AbsCObjSeg)
        }
        let event = |code: u8| {
            let mut r = [0u8; 10];
            r[0] = code;
            r
        };
        match step.name.as_str() {
            "LdCtrlConnect" => client.connect(),
            "LdCtrlDisconnect" => client.disconnect(),
            "LdCtrlRestart" => {
                client.ndt(0x380, &[]);
                client.connected = false;
            }
            "LdCtrlDelay" => {}
            "LdCtrlUnload" => client.pid5(lsm, event(0x04)),
            "LdCtrlLoad" => {
                client.pid5(lsm, event(0x01));
                lsms.push(lsm);
            }
            "LdCtrlLoadCompleted" => client.pid5(lsm, event(0x02)),
            "LdCtrlAbsSegment" => {
                let address = u16::try_from(step.num("Address"))?;
                let size = u16::try_from(step.num("Size"))?;
                let [a0, a1] = address.to_be_bytes();
                let [s0, s1] = size.to_be_bytes();
                let record = [
                    0x03,
                    u8::try_from(step.num("SegType"))?,
                    a0,
                    a1,
                    s0,
                    s1,
                    u8::try_from(step.num("Access"))?,
                    u8::try_from(step.num("MemType"))?,
                    u8::try_from(step.num("SegFlags"))?,
                    0x00,
                ];
                client.pid5(lsm, record);
                for (at, run) in masked_runs(product, address, size) {
                    client.mem_write(at, &run);
                }
                allocated.push((address, size));
            }
            "LdCtrlTaskSegment" => {
                let [a0, a1] = u16::try_from(step.num("Address"))?.to_be_bytes();
                task_segment_3 |= lsm == 3;
                let (pei, id) = if lsm == 3 {
                    (product.pei_type.unwrap_or(0), program_id(product))
                } else {
                    (0, [0; 5])
                };
                client.pid5(
                    lsm,
                    [0x03, 0x02, a0, a1, pei, id[0], id[1], id[2], id[3], id[4]],
                );
            }
            "LdCtrlTaskPtr" => {
                let [i0, i1] = u16::try_from(step.num("InitPtr"))?.to_be_bytes();
                let [s0, s1] = u16::try_from(step.num("SavePtr"))?.to_be_bytes();
                let [p0, p1] = u16::try_from(step.num("SerialPtr"))?.to_be_bytes();
                client.pid5(lsm, [0x03, 0x03, i0, i1, s0, s1, p0, p1, 0, 0]);
            }
            "LdCtrlTaskCtrl1" => {
                let [a0, a1] = u16::try_from(step.num("Address"))?.to_be_bytes();
                let n = u8::try_from(step.num("Count"))?;
                client.pid5(lsm, [0x03, 0x04, a0, a1, n, 0, 0, 0, 0, 0]);
            }
            "LdCtrlTaskCtrl2" => {
                let [c0, c1] = u16::try_from(step.num("Callback"))?.to_be_bytes();
                let [o0, o1] = u16::try_from(step.num("Address"))?.to_be_bytes();
                let [x0, x1] = u16::try_from(step.num("Seg0"))?.to_be_bytes();
                let [y0, y1] = u16::try_from(step.num("Seg1"))?.to_be_bytes();
                client.pid5(lsm, [0x03, 0x05, c0, c1, o0, o1, x0, x1, y0, y1]);
            }
            "LdCtrlWriteProp" => {
                let object = u8::try_from(step.num("ObjIdx"))?;
                let pid = u8::try_from(step.num("PropId"))?;
                let start = u16::try_from(step.num("StartElement").max(1))?;
                let count = u8::try_from(step.num("Count").max(1))?;
                let mut payload = vec![
                    object,
                    pid,
                    (count << 4) | ((start >> 8) as u8 & 0x0F),
                    (start & 0xFF) as u8,
                ];
                payload.extend_from_slice(&step.hex("InlineData"));
                client.ndt(0x3D7, &payload);
            }
            "LdCtrlCompareProp" => {
                let object = u8::try_from(step.num("ObjIdx"))?;
                let pid = u8::try_from(step.num("PropId"))?;
                let want = step.hex("InlineData");
                let mask = step.hex("Mask");
                let got = client.read_prop(object, pid, 1, 1);
                let same = want.len() == got.len()
                    && want.iter().zip(&got).enumerate().all(|(i, (w, g))| {
                        let m = mask.get(i).copied().unwrap_or(0xFF);
                        w & m == g & m
                    });
                if !same {
                    return Ok(Some(format!(
                        "CompareProp object {object} PID {pid}: device holds {got:02X?}"
                    )));
                }
            }
            "LdCtrlWriteMem" => {
                let address = u16::try_from(step.num("Address"))?;
                let size = usize::try_from(step.num("Size"))?;
                let mut data = step.hex("InlineData");
                data.truncate(size);
                if data.len() < size {
                    return Ok(Some("LdCtrlWriteMem without InlineData".into()));
                }
                client.mem_write(address, &data);
            }
            other => return Ok(Some(format!("executor does not model {other}"))),
        }
        if let Some(first) = client.rejections().first() {
            return Ok(Some(format!("{}: {first}", step.name)));
        }
    }
    let dev = client.device()?;
    for lsm in lsms {
        if dev.load_state(lsm) != Some(LoadState::Loaded) {
            return Ok(Some(format!("LSM {lsm} ends {:?}", dev.load_state(lsm))));
        }
    }
    // The application id and PEI type (0103h to 0109h) come from the Segment
    // Control Record when the procedure sends one for LSM 3; the image some
    // 0025 programs declare there names a sibling program (`M-0001_A-980D`
    // declares 9809h version 1), which a capture has to settle.
    let managed = |at: u32| task_segment_3 && (0x0103..=0x0109).contains(&at);
    for (address, size) in allocated {
        for (at, run) in masked_runs(product, address, size) {
            for (i, want) in run.iter().enumerate() {
                let cell = u32::from(at) + i as u32;
                if !managed(cell) && dev.memory().read(cell, 1) != [*want] {
                    return Ok(Some(format!("image differs at {cell:04X}h")));
                }
            }
        }
    }
    if task_segment_3 && dev.memory().read(0x0103, 5) != program_id(product) {
        return Ok(Some("application id at 0103h differs".into()));
    }
    Ok(None)
}

fn corpus_root() -> std::path::PathBuf {
    std::env::var_os("BUSSARD_PRODUCT_CORPUS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../tests-support/product-corpus")
        })
}

/// The corpus BCU 2 programs as `(file, application id, mask)`, from the
/// committed catalog list.
fn bcu2_programs() -> TestResult<Option<Vec<(String, String, String)>>> {
    #[derive(serde::Deserialize)]
    struct App {
        id: String,
        mask: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        apps: Vec<App>,
    }
    let list = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tools/ets-sweep/catalog-apps.json");
    let Ok(text) = std::fs::read_to_string(list) else {
        return Ok(None);
    };
    let catalog: BTreeMap<String, Entry> = serde_norway::from_str(&text)?;
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (file, entry) in catalog {
        for app in entry.apps {
            let mask = app.mask.unwrap_or_default();
            if matches!(mask.as_str(), "0020" | "0021" | "0025") && seen.insert(app.id.clone()) {
                out.push((file.clone(), app.id, mask));
            }
        }
    }
    Ok(Some(out))
}

fn app_xml(bytes: &[u8], app: &str) -> TestResult<String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    let suffix = format!("{app}.xml");
    let mut name = None;
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?.name()?.into_owned();
        if entry.ends_with(&suffix) {
            name = Some(entry);
            break;
        }
    }
    let name = name.ok_or("no application XML")?;
    let mut xml = String::new();
    zip.by_name(&name)?.read_to_string(&mut xml)?;
    Ok(xml)
}

#[test]
fn test_bcu2_corpus_procedures_load_on_the_simulated_device() -> TestResult {
    let Some(programs) = bcu2_programs()? else {
        eprintln!("SKIP: tools/ets-sweep/catalog-apps.json not found");
        return Ok(());
    };
    let vendor = corpus_root().join("cache").join("vendor");
    if !vendor.is_dir() {
        eprintln!("SKIP: no product-corpus cache at {}", vendor.display());
        return Ok(());
    }
    let mut loaded: BTreeMap<String, usize> = BTreeMap::new();
    let mut property_only = 0;
    let mut failures = Vec::new();
    for (file, app, mask) in &programs {
        let Ok(bytes) = std::fs::read(vendor.join(file)) else {
            continue;
        };
        let product = read_knxprod_bytes(&bytes, Some(app))?;
        if product.property_only {
            property_only += 1;
            continue;
        }
        let steps = procedure(&app_xml(&bytes, app)?)?;
        let outcome = run_procedure(&product, &steps)?;
        let expected = EXPECTED_REFUSALS.iter().any(|(id, _)| id == app);
        match (outcome, expected) {
            (None, false) => *loaded.entry(mask.clone()).or_default() += 1,
            (None, true) => failures.push(format!("{app}: expected a refusal, it loaded")),
            (Some(_), true) => {}
            (Some(why), false) => failures.push(format!("{app} ({mask}): {why}")),
        }
    }
    eprintln!(
        "BCU 2 corpus procedures loaded per mask: {loaded:?}; property-only: {property_only}; \
         expected refusals: {}",
        EXPECTED_REFUSALS.len()
    );
    assert!(failures.is_empty(), "{failures:#?}");
    let total: usize = loaded.values().sum();
    assert!(
        total >= 10 && loaded.len() == 3,
        "at least ten programs over the three masks"
    );
    Ok(())
}

/// The synthetic BCU 2 product (`tests-support/synthetic-products/syn-bcu2-0021`,
/// committed XML, no vendor data): its own procedure loads in CI.
#[test]
fn test_bcu2_synthetic_procedure_loads_on_the_simulated_device() -> TestResult {
    use std::io::Write;
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests-support/synthetic-products/syn-bcu2-0021/xml/M-00FA");
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut names: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    names.sort();
    for path in names {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        zip.start_file(format!("M-00FA/{}", name.unwrap_or_default()), opts)?;
        zip.write_all(&std::fs::read(&path)?)?;
    }
    let bytes = zip.finish()?.into_inner();
    let app = "M-00FA_A-2880-10-0000";
    let product = read_knxprod_bytes(&bytes, Some(app))?;
    assert_eq!(product.mask_version, "MV-0021");
    let steps = procedure(&app_xml(&bytes, app)?)?;
    assert_eq!(run_procedure(&product, &steps)?, None);
    Ok(())
}
