//! The keep before a download (issues #1127, #1128), against a `MockDevice`
//! that serves `PID_MCB_TABLE` as the standard defines it: element 0 the
//! number of entries (Application Layer 03_03_07 §3.4.4.1), elements 1 to n
//! the entries (Resources 03_05_01 §4.2.27).
//!
//! The rule is the one the house captures show ETS following in a download
//! onto a device that holds the same application: the group-object table
//! (object 3) is left alone when its MCB matches, objects 4, 2 and 1 are
//! reloaded and the device restarts. Where the product declares no MCB check
//! (`syn-minimal` as committed, every synthetic `reload` capture) ETS reads
//! no MCB and runs the whole procedure. The tests flash `syn-minimal` with
//! an `LdCtrlLoadImageProp` of objects 3 and 4 added (the house products'
//! MergeId 7 block) onto a fresh device, then again.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bussard_download::{
    FlashOptions, FlashOutcome, FlashPlan, FlashStep, Session, build_table_images, flash,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_testkit::consts::{
    A_PROPERTY_VALUE_READ, A_PROPERTY_VALUE_RESPONSE, A_PROPERTY_VALUE_WRITE, A_RESTART,
    OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE,
    OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};
use zip::write::SimpleFileOptions;

use crate::support::plan_flash_default;

/// `PID_PROGRAM_VERSION`.
const PID_PROGRAM_VERSION: u8 = 13;
/// `PID_LOAD_STATE_CONTROL`.
const PID_LOAD_STATE_CONTROL: u8 = 5;
/// `PID_MCB_TABLE`.
const PID_MCB_TABLE: u8 = 27;
/// `A_Memory_Write`.
const A_MEMORY_WRITE: u16 = 0x280;
/// The MCB checks the house Jung products declare (MergeId 7).
const IMAGE_PROPS: &str = r#"<LoadProcedure MergeId="7"><LdCtrlLoadImageProp ObjIdx="3" PropId="27" /><LdCtrlLoadImageProp ObjIdx="4" PropId="27" /></LoadProcedure>"#;

/// Zips `syn-minimal`'s XML with the stub master into `out`, with the
/// house products' MCB checks added when `image_props`.
fn zip_syn_minimal(out: &Path, image_props: bool) -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests-support/synthetic-products/syn-minimal/xml/M-00FA");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(out)?);
    let opts = SimpleFileOptions::default();
    zip.start_file("knx_master.xml", opts)?;
    zip.write_all(b"<KNX/>")?;
    let mut files: Vec<_> = std::fs::read_dir(&root)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    files.sort();
    for path in files {
        let name = path
            .file_name()
            .ok_or("a file name")?
            .to_string_lossy()
            .to_string();
        let mut bytes = std::fs::read(&path)?;
        if image_props && name.contains("_A-") {
            let text = String::from_utf8(bytes)?;
            let patched = text.replacen(
                "</LoadProcedures>",
                &format!("{IMAGE_PROPS}</LoadProcedures>"),
                1,
            );
            assert_ne!(patched, text, "the application has load procedures");
            bytes = patched.into_bytes();
        }
        zip.start_file(format!("M-00FA/{name}"), opts)?;
        zip.write_all(&bytes)?;
    }
    zip.finish()?;
    Ok(())
}

/// The plan `bussard flash` makes for `syn-minimal` on 1.1.1, spliced into
/// the built-in 07B0 template, with or without the MCB checks.
fn plan(image_props: bool) -> TestResult<FlashPlan> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-minimal.knxprod");
    zip_syn_minimal(&path, image_props)?;
    let product = bussard_product::read_knxprod(&path)?;
    let app = product.applications.first().ok_or("one application")?;
    let template = bussard_download::template_ops_for(&product, app).ok_or("a 07B0 template")?;
    let overrides = BTreeMap::new();
    let tables = build_table_images(
        None,
        "1.1.1".parse()?,
        app,
        &overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    Ok(plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        &overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?)
}

/// The length of the group-object table image the plan writes.
fn group_object_table_len(plan: &FlashPlan) -> TestResult<u32> {
    plan.steps
        .iter()
        .find_map(|s| match s {
            FlashStep::WriteRelMem { image, .. } if image.segment_id == "obj-table-3" => {
                plan.image_bytes(&image.segment_id).map(|b| b.len() as u32)
            }
            _ => None,
        })
        .ok_or_else(|| "the group-object table image".into())
}

/// The fresh System B device `syn-minimal` loads onto, objects 0 to 5, its
/// MCB tables served.
fn device() -> TestResult<MockDevice> {
    Ok(MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, PID_PROGRAM_VERSION, 5, &[0; 5])
        .with_writable_property(5, PID_PROGRAM_VERSION, 5, &[0; 5])
        .with_mcb_tables())
}

/// Opens the tunnel to the mock gateway.
async fn tunnel(gw: &MockGateway) -> TestResult<Transport> {
    Ok(Transport::connect(&ConnectionConfig::tunnel(gw.addr())).await?)
}

/// Flashes `plan` over a fresh connection to 1.1.1 with the keep on.
async fn flash_once(bus: &mut Transport, plan: &FlashPlan) -> TestResult<FlashOutcome> {
    let l4 = Layer4Connection::connect(
        bus,
        ia("1.1.1")?,
        ia("0.0.255")?,
        bussard_mgmt::ConnectOptions::default(),
    )
    .await?;
    let mut session = Session::from_connection(l4);
    let outcome = flash(
        &mut session,
        plan,
        FlashOptions {
            skip_matching_mcb: true,
            ..Default::default()
        },
        |_| {},
    )
    .await?;
    let _ = session.into_disconnect().await;
    Ok(outcome)
}

/// What 1.1.1 was sent since a request index.
#[derive(Debug, Default)]
struct Sent {
    /// Load-state controls (PID 5 writes) per object index.
    load_controls: BTreeMap<u8, usize>,
    /// Memory writes.
    memory: usize,
    /// `PID_MCB_TABLE` reads as (object, element).
    mcb_reads: Vec<(u8, u16)>,
    /// `A_Restart`s.
    restarts: usize,
}

/// What 1.1.1 was sent since request `from`.
fn sent_since(gw: &MockGateway, from: usize) -> TestResult<Sent> {
    Ok(gw.with_device(ia("1.1.1")?, |d| {
        let mut sent = Sent::default();
        for (apci, data) in d.requests.get(from..).unwrap_or_default() {
            let obj = data.first().copied().unwrap_or(0);
            let pid = data.get(1).copied();
            let start = (u16::from(data.get(2).copied().unwrap_or(0) & 0x0F) << 8)
                | u16::from(data.get(3).copied().unwrap_or(0));
            if *apci & 0x3F0 == A_MEMORY_WRITE {
                sent.memory += 1;
            } else if *apci == A_PROPERTY_VALUE_WRITE && pid == Some(PID_LOAD_STATE_CONTROL) {
                *sent.load_controls.entry(obj).or_default() += 1;
            } else if *apci == A_PROPERTY_VALUE_READ && pid == Some(PID_MCB_TABLE) {
                sent.mcb_reads.push((obj, start));
            } else if *apci == A_RESTART {
                sent.restarts += 1;
            }
        }
        sent
    })?)
}

/// The number of requests 1.1.1 has seen.
fn requests(gw: &MockGateway) -> TestResult<usize> {
    Ok(gw.with_device(ia("1.1.1")?, |d| d.requests.len())?)
}

/// Whether `obj` got a load-state control.
fn reloaded(sent: &Sent, obj: u8) -> bool {
    sent.load_controls.get(&obj).is_some_and(|n| *n > 0)
}

/// Asserts the keep left object 3 alone and reloaded 4, 2, 1 with a restart.
fn assert_object_3_kept(sent: &Sent) {
    assert!(!reloaded(sent, 3), "object 3 kept: {sent:?}");
    for obj in [4u8, 2, 1] {
        assert!(reloaded(sent, obj), "object {obj} reloaded: {sent:?}");
    }
    assert!(sent.memory > 0 && sent.restarts > 0, "{sent:?}");
}

/// Issue #1127: on a re-flash the group-object table, whose MCB matches,
/// is kept, as ETS keeps it; objects 4, 2 and 1 are reloaded and the device
/// restarts. The MCB is read from element 1 (#1128), never 0.
#[tokio::test]
async fn test_flash_keeps_the_group_object_table_when_its_mcb_matches() -> TestResult {
    let plan = plan(true)?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    let before = requests(&gw)?;
    let again = flash_once(&mut bus, &plan).await?;
    assert!(again.ok(), "{again:?}");
    let sent = sent_since(&gw, before)?;
    assert_object_3_kept(&sent);
    assert!(
        sent.mcb_reads.iter().all(|&(_, e)| e != 0) && sent.mcb_reads.first() == Some(&(3, 1)),
        "{sent:?}"
    );
    assert_eq!(
        again.warnings.first().map(String::as_str),
        Some(
            "kept object(s) {3}: their MCB entries match the image and they are Loaded, so they \
             were not reloaded"
        )
    );
    Ok(())
}

/// Issue #1127: where the product declares no MCB check (the synthetic
/// `reload` captures) ETS reads no MCB and runs the whole procedure; so
/// does bussard.
#[tokio::test]
async fn test_flash_without_an_mcb_check_reloads_every_object() -> TestResult {
    let plan = plan(false)?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    let before = requests(&gw)?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    let sent = sent_since(&gw, before)?;
    assert!(sent.mcb_reads.is_empty(), "no MCB read: {sent:?}");
    assert!(reloaded(&sent, 3), "{sent:?}");
    Ok(())
}

/// Flips the last octet of `obj`'s segment on the device.
fn corrupt_last_octet(gw: &MockGateway, obj: u8) -> TestResult {
    let (base, size) = gw
        .with_device(ia("1.1.1")?, |d| d.segments.get(&obj).copied())?
        .ok_or("the object's segment")?;
    gw.with_device(ia("1.1.1")?, |d| {
        let last = base + size - 1;
        let old = d.memory.get(&last).copied().unwrap_or(0);
        d.memory.insert(last, old ^ 0xFF);
    })?;
    Ok(())
}

/// Issue #1128: a group-object table the device holds with another image
/// is reloaded.
#[tokio::test]
async fn test_flash_reloads_a_group_object_table_with_another_image() -> TestResult {
    let plan = plan(true)?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    corrupt_last_octet(&gw, 3)?;
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &plan).await?;
    assert!(outcome.ok(), "{outcome:?}");
    assert!(reloaded(&sent_since(&gw, before)?, 3));
    Ok(())
}

/// Issue #1128: a table of two entries is compared entry by entry: both
/// entries over the image keep the object; a changed octet under entry 2
/// reloads it.
#[tokio::test]
async fn test_flash_compares_a_multi_entry_mcb_table_entry_by_entry() -> TestResult {
    let plan = plan(true)?;
    let len = group_object_table_len(&plan)?;
    assert!(len >= 2, "a table to split: {len}");
    let device = device()?.with_mcb_split(3, &[len - 1, 1]);
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    let before = requests(&gw)?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    let sent = sent_since(&gw, before)?;
    assert_object_3_kept(&sent);
    assert!(sent.mcb_reads.contains(&(3, 2)), "entry 2 read: {sent:?}");

    corrupt_last_octet(&gw, 3)?;
    let before = requests(&gw)?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    assert!(reloaded(&sent_since(&gw, before)?, 3), "entry 2 differs");
    Ok(())
}

/// A refused read answers count 0 with no data.
fn refusal(data: &[u8]) -> Reaction {
    let mut answer = data.get(..4).unwrap_or_default().to_vec();
    if let Some(n) = answer.get_mut(2) {
        *n &= 0x0F;
    }
    Reaction::Answer(A_PROPERTY_VALUE_RESPONSE, answer)
}

/// A device that refuses the `n`-th `PID_MCB_TABLE` read of object 3 after
/// `arm` is set to `n` (0 refuses nothing).
fn device_refusing_mcb_read(arm: &Arc<AtomicUsize>) -> TestResult<MockDevice> {
    let counter = Arc::clone(arm);
    Ok(device()?.with_hook(move |_, apci, data| {
        if apci != A_PROPERTY_VALUE_READ || data.get(..2) != Some(&[3, PID_MCB_TABLE][..]) {
            return None;
        }
        match counter.load(Ordering::SeqCst) {
            0 => None,
            1 => {
                counter.store(0, Ordering::SeqCst);
                Some(refusal(data))
            }
            n => {
                counter.store(n - 1, Ordering::SeqCst);
                None
            }
        }
    }))
}

/// Speed Changes rule (CLAUDE.md): a refused MCB read before the download
/// keeps nothing; object 3 is reloaded.
#[tokio::test]
async fn test_flash_refused_mcb_read_reloads_the_object() -> TestResult {
    let plan = plan(true)?;
    let arm = Arc::new(AtomicUsize::new(0));
    let gw = MockGateway::builder()
        .device(device_refusing_mcb_read(&arm)?)
        .start()
        .await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    arm.store(1, Ordering::SeqCst);
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &plan).await?;
    assert!(outcome.ok(), "{outcome:?}");
    assert!(reloaded(&sent_since(&gw, before)?, 3));
    Ok(())
}

/// Speed Changes rule (CLAUDE.md): a refusal after the keep (the
/// procedure's MCB check of the kept object) runs the download again in
/// full, and the outcome says so.
#[tokio::test]
async fn test_flash_refusal_after_the_keep_runs_the_download_in_full() -> TestResult {
    let plan = plan(true)?;
    let arm = Arc::new(AtomicUsize::new(0));
    let gw = MockGateway::builder()
        .device(device_refusing_mcb_read(&arm)?)
        .start()
        .await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    // The keep reads object 3's entry 1; the check after the load is refused.
    arm.store(2, Ordering::SeqCst);
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &plan).await?;
    assert!(outcome.ok(), "{outcome:?}");
    assert!(reloaded(&sent_since(&gw, before)?, 3));
    assert!(
        outcome.warnings.iter().any(|w| {
            w.starts_with("the download with object(s) {3} kept failed (")
                && w.ends_with("): it ran again in full")
        }),
        "{:?}",
        outcome.warnings
    );
    Ok(())
}
