//! The resident check before a download (issues #1127, #1128), against a
//! `MockDevice` that serves `PID_MCB_TABLE` as the standard defines it:
//! element 0 the number of entries (Application Layer 03_03_07 §3.4.4.1),
//! elements 1 to n the entries (Resources 03_05_01 §4.2.27).
//!
//! The synthetic product `syn-minimal` (07B0, ETS's `reload` capture in
//! `captures/synthetic/syn-minimal/reload`) is flashed onto a fresh device,
//! then flashed again: the device then holds every object's image, so the
//! second flash writes nothing. A device holding another image, or a table
//! whose second entry differs, gets the full download; a refusal during the
//! check, or after it, falls back to the full download.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bussard_download::{FlashOptions, FlashOutcome, FlashPlan, Session, build_table_images, flash};
use bussard_mgmt::connection::Layer4Connection;
use bussard_testkit::consts::{
    A_PROPERTY_VALUE_READ, A_PROPERTY_VALUE_RESPONSE, A_PROPERTY_VALUE_WRITE, OT_ADDRESS_TABLE,
    OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE, OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::builtin_template::zip_synthetic;
use crate::support::plan_flash_default;

/// `PID_PROGRAM_VERSION`.
const PID_PROGRAM_VERSION: u8 = 13;
/// `PID_LOAD_STATE_CONTROL`.
const PID_LOAD_STATE_CONTROL: u8 = 5;
/// `PID_MCB_TABLE`.
const PID_MCB_TABLE: u8 = 27;
/// `A_Memory_Write`.
const A_MEMORY_WRITE: u16 = 0x280;

/// The plan `bussard flash` makes for `syn-minimal` on 1.1.1 with the
/// parameter `overrides`, spliced into the built-in 07B0 template.
fn plan(overrides: &BTreeMap<String, String>) -> TestResult<FlashPlan> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("syn-minimal.knxprod");
    zip_synthetic("syn-minimal", &path).map_err(|e| e.to_string())?;
    let product = bussard_product::read_knxprod(&path)?;
    let app = product.applications.first().ok_or("one application")?;
    let template = bussard_download::template_ops_for(&product, app).ok_or("a 07B0 template")?;
    let tables = build_table_images(
        None,
        "1.1.1".parse()?,
        app,
        overrides,
        &bussard_product::dynamic::DynamicMemo::new(app),
    );
    Ok(plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template),
        &tables,
    )?)
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

/// Flashes `plan` over a fresh connection to 1.1.1 with the resident check
/// on, and returns the outcome.
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

/// The requests 1.1.1 has seen since `from`: (memory writes, property
/// writes including load controls, `PID_MCB_TABLE` reads by element).
fn writes_since(gw: &MockGateway, from: usize) -> TestResult<(usize, usize, Vec<u16>)> {
    Ok(gw.with_device(ia("1.1.1")?, |d| {
        let new = d.requests.get(from..).unwrap_or_default();
        let mem = new
            .iter()
            .filter(|(a, _)| *a & 0x3F0 == A_MEMORY_WRITE)
            .count();
        let props = new
            .iter()
            .filter(|(a, _)| *a == A_PROPERTY_VALUE_WRITE)
            .count();
        let mcb = new
            .iter()
            .filter(|(a, d)| *a == A_PROPERTY_VALUE_READ && d.get(1) == Some(&PID_MCB_TABLE))
            .map(|(_, d)| {
                u16::from(d.get(2).copied().unwrap_or(0) & 0x0F) << 8
                    | u16::from(d.get(3).copied().unwrap_or(0))
            })
            .collect();
        (mem, props, mcb)
    })?)
}

/// The number of requests 1.1.1 has seen.
fn requests(gw: &MockGateway) -> TestResult<usize> {
    Ok(gw.with_device(ia("1.1.1")?, |d| d.requests.len())?)
}

/// Issue #1127: a device that holds every object's image, Loaded, and the
/// program version gets nothing written: no unload, no version write, no
/// restart. The MCB entries are read from element 1 (#1128), never 0.
#[tokio::test]
async fn test_flash_writes_nothing_to_a_device_that_holds_the_download() -> TestResult {
    let plan = plan(&BTreeMap::new())?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    let mut bus = tunnel(&gw).await?;
    let first = flash_once(&mut bus, &plan).await?;
    assert!(first.ok(), "{first:?}");
    let (mem, _, _) = writes_since(&gw, 0)?;
    assert!(mem > 0, "a fresh device gets the full download");

    let before = requests(&gw)?;
    let again = flash_once(&mut bus, &plan).await?;
    assert!(again.ok(), "{again:?}");
    let (mem, props, mcb) = writes_since(&gw, before)?;
    assert_eq!(
        (mem, props),
        (0, 0),
        "nothing written over a matching device"
    );
    assert!(
        !mcb.is_empty() && !mcb.contains(&0),
        "MCB elements read: {mcb:?}"
    );
    assert!(
        again
            .warnings
            .iter()
            .any(|w| w.contains("already holds this download")),
        "{:?}",
        again.warnings
    );
    let restarts = gw.with_device(ia("1.1.1")?, |d| {
        d.requests
            .get(before..)
            .unwrap_or_default()
            .iter()
            .filter(|(a, _)| *a == bussard_testkit::consts::A_RESTART)
            .count()
    })?;
    assert_eq!(restarts, 0, "no restart when nothing was written");
    Ok(())
}

/// Issue #1128: a device that holds another image (another parameter
/// value) is not skipped: the full download writes the new one.
#[tokio::test]
async fn test_flash_full_download_over_a_device_with_another_image() -> TestResult {
    let gw = MockGateway::builder().device(device()?).start().await?;
    let mut bus = tunnel(&gw).await?;
    let defaults = plan(&BTreeMap::new())?;
    assert!(flash_once(&mut bus, &defaults).await?.ok());
    let changed = plan(&BTreeMap::from([("P-2_R-2".to_string(), "17".to_string())]))?;
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &changed).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let (mem, props, _) = writes_since(&gw, before)?;
    assert!(mem > 0 && props > 0, "the full download ran: {mem} {props}");
    assert!(
        !outcome.warnings.iter().any(|w| w.contains("already holds")),
        "{:?}",
        outcome.warnings
    );
    Ok(())
}

/// Issue #1128: a table of two entries is compared entry by entry. With
/// both entries over the image the device is recognised; with the second
/// entry's octets changed on the device the full download runs.
#[tokio::test]
async fn test_flash_compares_a_multi_entry_mcb_table_entry_by_entry() -> TestResult {
    let plan = plan(&BTreeMap::new())?;
    let image_len = plan
        .steps
        .iter()
        .find_map(|s| match s {
            bussard_download::FlashStep::WriteRelMem {
                image,
                target: Some(4),
                ..
            } => plan.image_bytes(&image.segment_id).map(<[u8]>::len),
            _ => None,
        })
        .ok_or("object 4's image")? as u32;
    let device = device()?.with_mcb_split(4, &[image_len - 4, 4]);
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());

    let before = requests(&gw)?;
    let again = flash_once(&mut bus, &plan).await?;
    assert!(again.ok(), "{again:?}");
    let (mem, props, mcb) = writes_since(&gw, before)?;
    assert_eq!((mem, props), (0, 0), "both entries match: nothing written");
    assert!(mcb.contains(&2), "entry 2 of object 4 read: {mcb:?}");

    // A changed octet under entry 2 only.
    let (base, size) = gw
        .with_device(ia("1.1.1")?, |d| d.segments.get(&4).copied())?
        .ok_or("object 4's segment")?;
    gw.with_device(ia("1.1.1")?, |d| {
        let last = base + size - 1;
        let old = d.memory.get(&last).copied().unwrap_or(0);
        d.memory.insert(last, old ^ 0xFF);
    })?;
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &plan).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let (mem, _, _) = writes_since(&gw, before)?;
    assert!(mem > 0, "entry 2 differs: the full download ran");
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

/// Speed Changes rule (CLAUDE.md): a refusal during the check (the program
/// version read) runs the full download.
#[tokio::test]
async fn test_flash_check_refusal_runs_the_full_download() -> TestResult {
    let plan = plan(&BTreeMap::new())?;
    let refuse = Arc::new(AtomicUsize::new(0));
    let armed = Arc::clone(&refuse);
    let device = device()?.with_hook(move |_, apci, data| {
        (apci == A_PROPERTY_VALUE_READ
            && data.get(..2) == Some(&[4, PID_PROGRAM_VERSION][..])
            && armed.load(Ordering::SeqCst) > 0
            && armed.fetch_sub(1, Ordering::SeqCst) > 0)
            .then(|| refusal(data))
    });
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    refuse.store(1, Ordering::SeqCst);
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &plan).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let (mem, props, _) = writes_since(&gw, before)?;
    assert!(mem > 0 && props > 0, "the full download ran: {mem} {props}");
    Ok(())
}

/// Speed Changes rule (CLAUDE.md): a refusal after the check passed (the
/// verify's load-state read of object 4) falls back to the full download,
/// and the outcome says so.
#[tokio::test]
async fn test_flash_refusal_after_the_check_falls_back_to_the_full_download() -> TestResult {
    let plan = plan(&BTreeMap::new())?;
    // Object 4's load-state reads to let through before the refused one.
    let pass = Arc::new(AtomicUsize::new(usize::MAX));
    let counter = Arc::clone(&pass);
    let device = device()?.with_hook(move |_, apci, data| {
        if apci != A_PROPERTY_VALUE_READ || data.get(..2) != Some(&[4, PID_LOAD_STATE_CONTROL][..])
        {
            return None;
        }
        match counter.load(Ordering::SeqCst) {
            0 => {
                counter.store(usize::MAX, Ordering::SeqCst);
                Some(refusal(data))
            }
            usize::MAX => None,
            n => {
                counter.store(n - 1, Ordering::SeqCst);
                None
            }
        }
    });
    let gw = MockGateway::builder().device(device).start().await?;
    let mut bus = tunnel(&gw).await?;
    assert!(flash_once(&mut bus, &plan).await?.ok());
    // The check reads object 4's state once; the verify's read is refused.
    pass.store(1, Ordering::SeqCst);
    let before = requests(&gw)?;
    let outcome = flash_once(&mut bus, &plan).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let (mem, props, _) = writes_since(&gw, before)?;
    assert!(mem > 0 && props > 0, "the full download ran: {mem} {props}");
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.contains("the full download ran")),
        "{:?}",
        outcome.warnings
    );
    Ok(())
}
