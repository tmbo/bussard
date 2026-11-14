//! The parameter-only download of a program with parameter memory by the
//! mask's `par` procedure (issue #1085): `syn-minimal` (07B0, spliced into
//! the master template, `mode` at octet 0 and `delay` at octets 1 and 2 of
//! object 4's segment). ETS's partial download of it
//! (`captures/synthetic/syn-minimal/partial`, ops 14 to 22) reads the base
//! pointer, unloads and loads object 4, allocates it in Mode 0, reads the
//! base pointer again, writes the parameter memory and the program version,
//! completes the load and restarts. Every flash here ends with the
//! independent read-back of what it wrote.

use std::collections::BTreeMap;

use bussard_download::{
    Connector, FlashOptions, FlashOutcome, FlashPlan, FlashStep, ImageKind, PartialPlanError,
    ProcedureKind, Session, add_par_procedure, build_table_images, flash, read_back_properties,
    read_parameter_regions, regions_memory, verify_readback,
};
use bussard_mgmt::connection::Layer4Connection;
use bussard_mgmt::load::WriteError;
use bussard_product::application::{ApplicationProgram, LoadOp, parse_application_program};
use bussard_product::master::MasterTemplate;
use bussard_testkit::consts::{
    A_MEMORY_WRITE, LS_LOADED, OT_ADDRESS_TABLE, OT_APPLICATION_PROGRAM, OT_ASSOCIATION_TABLE,
    OT_DEVICE, OT_GROUP_OBJECT_TABLE,
};
use bussard_testkit::{MockDevice, MockGateway, Reaction, TestResult, ia};
use bussard_transport::{ConnectionConfig, Transport};

use crate::support::plan_flash_default;

/// The synthetic product's application program (bussard's own work, MIT).
const XML: &str = include_str!(
    "../../../../tests-support/synthetic-products/syn-minimal/xml/M-00FA/M-00FA_A-2700-10-0000.xml"
);

/// The application's id.
const APP_ID: &str = "M-00FA_A-2700-10-0000";

/// The parameter segment.
const SEGMENT: &str = "M-00FA_A-2700-10-0000_RS-04-00000";

/// Object 4's MergeId 2 block: the allocation.
const ALLOCATION: &str = r#"<LdCtrlRelSegment LsmIdx="4" Size="256" Mode="0" Fill="0" />"#;

/// Object 4's MergeId 4 block: the parameter write.
const WRITE: &str = r#"<LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="256" Verify="false" />"#;

/// The `delay` parameter (16 bits at octets 1 and 2), app-relative.
const DELAY: &str = "P-2_R-2";

/// Where the mock places object 4's segment.
const BASE: u32 = 0x6000;

/// `syn-minimal` with `from` replaced by `to` in its XML.
fn app_with(from: &str, to: &str) -> TestResult<ApplicationProgram> {
    assert!(XML.contains(from), "{from}");
    Ok(parse_application_program(
        APP_ID,
        XML.replace(from, to).as_bytes(),
    )?)
}

/// `syn-minimal` as committed.
fn app() -> TestResult<ApplicationProgram> {
    Ok(parse_application_program(APP_ID, XML.as_bytes())?)
}

/// The complete download of `app` for 1.1.1 under `overrides`, with the
/// lowering of the parameter-only procedure `par` (the built-in 07B0 one,
/// as for a product without master data).
fn plan_with_par(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    par: &[LoadOp],
) -> TestResult<FlashPlan> {
    let template = MasterTemplate::builtin_for_mask("07B0").ok_or("07B0 template")?;
    let memo = bussard_product::dynamic::DynamicMemo::new(app);
    let tables = build_table_images(None, "1.1.1".parse()?, app, overrides, &memo);
    let mut plan = plan_flash_default(
        app,
        "1.1.1",
        0x07B0,
        overrides,
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )
    .map_err(|e| e.to_string())?;
    add_par_procedure(
        &mut plan,
        app,
        "1.1.1",
        overrides,
        &BTreeMap::new(),
        Some(par),
        &tables,
        &BTreeMap::new(),
        &memo,
    );
    Ok(plan)
}

/// The built-in 07B0 parameter-only procedure.
fn builtin_par() -> TestResult<Vec<LoadOp>> {
    Ok(MasterTemplate::builtin_par_for_mask("07B0")
        .ok_or("07B0 par procedure")?
        .ops)
}

/// [`plan_with_par`] of `app` with the built-in procedure.
fn plan_of(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> TestResult<FlashPlan> {
    plan_with_par(app, overrides, &builtin_par()?)
}

/// The delay set to `seconds`.
fn delay(seconds: u16) -> BTreeMap<String, String> {
    BTreeMap::from([(DELAY.to_string(), seconds.to_string())])
}

/// The device holding the parameter image of `plan` at [`BASE`].
fn regions_as_planned(plan: &FlashPlan) -> bussard_download::ParamRegions {
    let mut regions = bussard_download::planned_parameter_regions(plan);
    for region in regions.values_mut() {
        region.address = BASE;
    }
    regions
}

/// A System B device of 1.1.1 with the objects the product loads.
fn device() -> TestResult<MockDevice> {
    Ok(MockDevice::system_b(ia("1.1.1")?)
        .with_object_types(&[
            OT_DEVICE,
            OT_ADDRESS_TABLE,
            OT_ASSOCIATION_TABLE,
            OT_GROUP_OBJECT_TABLE,
            OT_APPLICATION_PROGRAM,
        ])
        .with_writable_property(4, 13, 5, &[0; 5])
        .with_segment_base(4, BASE))
}

/// Opens `$session` to 1.1.1 behind `$gw` over the transport `$bus`.
macro_rules! open {
    ($gw:expr, $bus:ident, $session:ident) => {
        let mut $bus = Transport::connect(&ConnectionConfig::tunnel($gw.addr())).await?;
        let l4 = Layer4Connection::connect(
            &mut $bus,
            ia("1.1.1")?,
            ia("0.0.255")?,
            bussard_mgmt::ConnectOptions::default(),
        )
        .await?;
        let mut $session = Session::from_connection(l4);
    };
}

/// Runs `plan` over `session`.
async fn run<C: Connector>(
    session: &mut Session<C>,
    plan: &FlashPlan,
) -> Result<FlashOutcome, WriteError> {
    flash(session, plan, FlashOptions::default(), |_| {}).await
}

/// The plain memory writes the device saw into `[from, to)`: address and
/// length of each.
fn writes_into(dev: &MockDevice, from: u32, to: u32) -> Vec<(u32, usize)> {
    dev.requests
        .iter()
        .filter(|(apci, data)| apci & !0x3F == A_MEMORY_WRITE && data.len() >= 2)
        .map(|(_, data)| {
            (
                u32::from(u16::from_be_bytes([data[0], data[1]])),
                data.len() - 2,
            )
        })
        .filter(|&(addr, _)| (from..to).contains(&addr))
        .collect()
}

/// Flashes the defaults of `app` over `session` and forgets the requests.
async fn flash_defaults<C: Connector>(
    gw: &MockGateway,
    session: &mut Session<C>,
    app: &ApplicationProgram,
) -> TestResult {
    let defaults = plan_of(app, &BTreeMap::new())?;
    let outcome = run(session, &defaults).await?;
    assert!(outcome.ok(), "{outcome:?}");
    gw.with_device(ia("1.1.1")?, |d| d.requests.clear())?;
    Ok(())
}

/// The independent read-back of a parameter-only download: the memory it
/// changed and every property it wrote.
async fn read_back<C: Connector>(
    session: &mut Session<C>,
    full: &FlashPlan,
    partial: &FlashPlan,
) -> TestResult<usize> {
    let after = read_parameter_regions(session.l4(), full, &[]).await;
    let octets = verify_readback(partial, &after, &std::collections::BTreeSet::new())?;
    let elements = read_back_properties(session.l4(), partial).await?;
    Ok(octets + elements)
}

#[test]
fn test_parameters_only_memory_program_runs_the_par_procedure() -> TestResult {
    let app = app()?;
    let full = plan_of(&app, &delay(20))?;
    let defaults = plan_of(&app, &BTreeMap::new())?;
    let partial = full.parameters_only(&regions_as_planned(&defaults))?;
    assert_eq!(partial.procedure_kind(), ProcedureKind::ParametersByPar);
    let shape: Vec<String> = partial
        .steps
        .iter()
        .map(|s| match s {
            FlashStep::ReadTableReference { obj_idx } => format!("read PID 7 obj{obj_idx}"),
            FlashStep::CompareTableReference { obj_idx } => format!("compare PID 7 obj{obj_idx}"),
            FlashStep::Unload { target, .. } => format!("unload {target:?}"),
            FlashStep::StartLoading { target } => format!("load {target:?}"),
            FlashStep::AllocateSegment { size, fill, .. } => {
                format!("alloc {size} {:02x}", fill.mode)
            }
            FlashStep::WriteRelMem { image, .. } => format!("write {:?}", image.kind),
            FlashStep::WriteProp { prop_id, .. } => format!("prop {prop_id}"),
            FlashStep::LoadCompleted { target } => format!("complete {target:?}"),
            other => format!("{other:?}"),
        })
        .collect();
    // ETS's `syn-minimal/partial`, ops 14 to 22.
    assert_eq!(
        shape,
        [
            "read PID 7 obj4",
            "unload Some(4)",
            "load Some(4)",
            "alloc 256 00",
            "compare PID 7 obj4",
            "write Parameters",
            "prop 13",
            "complete Some(4)",
            "Restart",
        ]
    );
    // Only the delay differs from what the device holds.
    assert_eq!(partial.changed_octets(), 2);
    assert_eq!(partial.baseline_address(SEGMENT), Some(BASE));
    Ok(())
}

#[test]
fn test_parameters_only_without_a_par_procedure_keeps_the_cut() -> TestResult {
    // A mask with neither master data nor a built-in `par` procedure keeps
    // the cut of the complete download (issue #1052's fallback).
    let app = app()?;
    let template = MasterTemplate::builtin_for_mask("07B0").ok_or("07B0 template")?;
    let memo = bussard_product::dynamic::DynamicMemo::new(&app);
    let tables = build_table_images(None, "1.1.1".parse()?, &app, &delay(20), &memo);
    let mut full = plan_flash_default(
        &app,
        "1.1.1",
        0x07B0,
        &delay(20),
        &BTreeMap::new(),
        Some(&template.ops),
        &tables,
    )
    .map_err(|e| e.to_string())?;
    add_par_procedure(
        &mut full,
        &app,
        "1.1.1",
        &delay(20),
        &BTreeMap::new(),
        None,
        &tables,
        &BTreeMap::new(),
        &memo,
    );
    let defaults = plan_of(&app, &BTreeMap::new())?;
    let partial = full.parameters_only(&regions_as_planned(&defaults))?;
    assert_eq!(partial.procedure_kind(), ProcedureKind::Parameters);
    assert!(
        !partial
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::ReadTableReference { .. })),
        "{:?}",
        partial.steps
    );
    assert_eq!(partial.changed_octets(), 2);
    Ok(())
}

#[tokio::test]
async fn test_flash_parameters_only_memory_program_writes_the_change_and_reads_it_back()
-> TestResult {
    let app = app()?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    open!(gw, bus, session);
    flash_defaults(&gw, &mut session, &app).await?;
    let full = plan_of(&app, &delay(20))?;
    let regions = read_parameter_regions(session.l4(), &full, &[]).await;
    let partial = full.parameters_only(&regions)?;
    assert_eq!(partial.procedure_kind(), ProcedureKind::ParametersByPar);
    let outcome = run(&mut session, &partial).await?;
    assert!(outcome.ok(), "{outcome:?}");
    let checked = read_back(&mut session, &full, &partial).await?;
    let _ = session.into_disconnect().await;
    assert!(checked > 0);
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    // The delay's two octets, and nothing else of the segment.
    assert_eq!(writes_into(&dev, BASE, BASE + 256), vec![(BASE + 1, 2)]);
    assert_eq!(dev.read_mem(BASE + 1, 2), vec![0, 20]);
    assert_eq!(dev.load_state(4), LS_LOADED);
    Ok(())
}

#[tokio::test]
async fn test_restoring_memory_program_backup_round_trips() -> TestResult {
    let app = app()?;
    let gw = MockGateway::builder().device(device()?).start().await?;
    open!(gw, bus, session);
    flash_defaults(&gw, &mut session, &app).await?;
    let defaults = plan_of(&app, &BTreeMap::new())?;
    // The backup an `apply` takes before it writes.
    let backup = regions_memory(&read_parameter_regions(session.l4(), &defaults, &[]).await);

    let full = plan_of(&app, &delay(20))?;
    let partial = full.parameters_only(&read_parameter_regions(session.l4(), &full, &[]).await)?;
    let outcome = run(&mut session, &partial).await?;
    assert!(outcome.ok(), "{outcome:?}");
    read_back(&mut session, &full, &partial).await?;

    // The restore puts the backup's octets back through the same procedure.
    let partial = full.parameters_only(&read_parameter_regions(session.l4(), &full, &[]).await)?;
    let restore = partial.restoring(&backup, &bussard_product::PlacedOctets::new());
    assert_eq!(restore.procedure_kind(), ProcedureKind::ParametersByPar);
    gw.with_device(ia("1.1.1")?, |d| d.requests.clear())?;
    let outcome = run(&mut session, &restore).await?;
    assert!(outcome.ok(), "{outcome:?}");
    read_back(&mut session, &full, &restore).await?;
    let after = regions_memory(&read_parameter_regions(session.l4(), &defaults, &[]).await);
    let _ = session.into_disconnect().await;
    assert_eq!(after, backup, "the read-back holds the backup");
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert_eq!(writes_into(&dev, BASE, BASE + 256), vec![(BASE + 1, 2)]);
    Ok(())
}

#[tokio::test]
async fn test_flash_parameters_only_memory_program_fails_when_a_written_octet_reads_back_wrong()
-> TestResult {
    let app = app()?;
    // Once armed, the device stores every memory write with its first octet
    // flipped, and acknowledges it.
    let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trigger = armed.clone();
    let faulty = device()?.with_hook(move |dev: &mut MockDevice, apci: u16, data: &[u8]| {
        if !trigger.load(std::sync::atomic::Ordering::SeqCst) || apci & !0x3F != A_MEMORY_WRITE {
            return None;
        }
        let at = data
            .get(..2)
            .map(|a| u32::from(u16::from_be_bytes([a[0], a[1]])))?;
        for (i, b) in data.get(2..)?.iter().enumerate() {
            let b = if i == 0 { !b } else { *b };
            dev.memory.insert(at + i as u32, b);
        }
        Some(Reaction::Ack)
    });
    let gw = MockGateway::builder().device(faulty).start().await?;
    open!(gw, bus, session);
    flash_defaults(&gw, &mut session, &app).await?;
    let full = plan_of(&app, &delay(20))?;
    let partial = full.parameters_only(&read_parameter_regions(session.l4(), &full, &[]).await)?;
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let flashed_ok = matches!(run(&mut session, &partial).await, Ok(outcome) if outcome.ok());
    let read_back_ok = read_back(&mut session, &full, &partial).await.is_ok();
    let _ = session.into_disconnect().await;
    assert!(
        !(flashed_ok && read_back_ok),
        "a written octet that reads back wrong fails the download or its read-back"
    );
    assert!(!read_back_ok, "the read-back finds the wrong octet");
    Ok(())
}

#[test]
fn test_parameters_only_memory_program_refuses_before_anything_is_sent() -> TestResult {
    // Each refusal comes from the plan, before a session sends anything.
    let defaults_regions = |app: &ApplicationProgram| -> TestResult<_> {
        Ok(regions_as_planned(&plan_of(app, &BTreeMap::new())?))
    };

    // The parameter segment could not be read.
    let app = app()?;
    let full = plan_of(&app, &delay(20))?;
    assert!(matches!(
        full.parameters_only(&bussard_download::ParamRegions::new()),
        Err(PartialPlanError::UnreadableSegment { segment }) if segment == SEGMENT
    ));

    // A procedure that does not write the parameter segment (MergeId 4 left
    // out).
    let without_write: Vec<LoadOp> = builtin_par()?
        .into_iter()
        .filter(|op| !matches!(op, LoadOp::Merge { merge_id } if merge_id.as_deref() == Some("4")))
        .collect();
    let full = plan_with_par(&app, &delay(20), &without_write)?;
    assert!(matches!(
        full.parameters_only(&defaults_regions(&app)?),
        Err(PartialPlanError::ParameterNotInProcedure { property }) if property.contains(SEGMENT)
    ));

    // A procedure that unloads object 4 and allocates nothing for it
    // (MergeId 2 left out).
    let without_allocation: Vec<LoadOp> = builtin_par()?
        .into_iter()
        .filter(|op| !matches!(op, LoadOp::Merge { merge_id } if merge_id.as_deref() == Some("2")))
        .collect();
    let full = plan_with_par(&app, &delay(20), &without_allocation)?;
    assert!(matches!(
        full.parameters_only(&defaults_regions(&app)?),
        Err(PartialPlanError::DropsSegment {
            object: 4,
            size: 256
        })
    ));

    // A `par` allocation of another size than the complete one.
    let app = app_with(
        ALLOCATION,
        r#"<LdCtrlRelSegment AppliesTo="full" LsmIdx="4" Size="256" Mode="0" Fill="0" />
                <LdCtrlRelSegment AppliesTo="par" LsmIdx="4" Size="128" Mode="0" Fill="0" />"#,
    )?;
    let full = plan_of(&app, &delay(20))?;
    assert!(matches!(
        full.parameters_only(&defaults_regions(&app)?),
        Err(PartialPlanError::NoParAllocation)
    ));

    // A `par` allocation that refills the segment, with no MCB check of
    // the rewritten image.
    let app = app_with(
        ALLOCATION,
        r#"<LdCtrlRelSegment LsmIdx="4" Size="256" Mode="1" Fill="255" />"#,
    )?;
    let full = plan_of(&app, &delay(20))?;
    assert!(matches!(
        full.parameters_only(&defaults_regions(&app)?),
        Err(PartialPlanError::RefilledSegmentUnwritten {
            object: 4,
            rewritten: true,
            ..
        })
    ));

    // A master reset erasing more than the parameters.
    let app = app_with(
        WRITE,
        &format!(r#"<LdCtrlMasterReset EraseCode="2" ChannelNumber="0" />{WRITE}"#),
    )?;
    let full = plan_of(&app, &delay(20))?;
    assert!(matches!(
        full.parameters_only(&defaults_regions(&app)?),
        Err(PartialPlanError::ResetLosesState { erase_code: 2, .. })
    ));
    Ok(())
}

#[tokio::test]
async fn test_flash_parameters_only_memory_program_refuses_changed_tables_untouched() -> TestResult
{
    // MergeId 7 checks the address table's MCB, as the Jung
    // `M-0004_A-20DE-22-C7D8` does: a device whose table differs from the
    // project's is refused before the first unload, nothing written.
    let check = r#"</LoadProcedure>
              <LoadProcedure MergeId="7">
                <LdCtrlLoadImageProp ObjIdx="1" PropId="27" />"#;
    let app = app_with(
        &format!("{WRITE}\n              </LoadProcedure>"),
        &format!("{WRITE}\n              {check}\n              </LoadProcedure>"),
    )?;
    let full = plan_of(&app, &delay(20))?;
    let regions = regions_as_planned(&plan_of(&app, &BTreeMap::new())?);
    let partial = full.parameters_only(&regions)?;
    assert!(
        partial.steps.iter().any(|s| matches!(
            s,
            FlashStep::LoadImageProp { obj_idx: 1, image: Some(image), .. } if image.kind == ImageKind::Table
        )),
        "{:?}",
        partial.steps
    );
    // The device's address table MCB: one entry whose CRC matches no
    // project table. The device holds the defaults of the committed program.
    let mcb = [0, 0, 0, 4, 0, 0, 0xDE, 0xAD];
    let gw = MockGateway::builder()
        .device(device()?.with_property(1, 27, 8, &mcb))
        .start()
        .await?;
    open!(gw, bus, session);
    flash_defaults(&gw, &mut session, &self::app()?).await?;
    let result = run(&mut session, &partial).await;
    let _ = session.into_disconnect().await;
    assert!(
        matches!(
            result,
            Err(WriteError::TablesChanged {
                object_index: 1,
                ..
            })
        ),
        "{result:?}"
    );
    let dev = gw.with_device(ia("1.1.1")?, |d| d.clone())?;
    assert!(writes_into(&dev, 0, 0x1_0000).is_empty());
    assert_eq!(dev.load_state(4), LS_LOADED, "nothing unloaded");
    Ok(())
}

#[test]
fn test_parameters_only_compares_a_valued_table_reference_as_a_property() -> TestResult {
    // Review of #1072: only the master's placeholder compare (all zeros,
    // after a read of the same object) is the base pointer check; a compare
    // with a value of its own keeps that value.
    let app = app()?;
    let valued: Vec<LoadOp> = builtin_par()?
        .into_iter()
        .map(|op| match op {
            LoadOp::CompareProp {
                obj_idx: Some(4),
                obj_type,
                prop_id: Some(7),
                mask,
                range,
                occurrence,
                start_element,
                ..
            } => LoadOp::CompareProp {
                obj_idx: Some(4),
                obj_type,
                prop_id: Some(7),
                inline_data: Some(vec![0, 0, 0x60, 0]),
                mask,
                range,
                occurrence,
                start_element,
            },
            other => other,
        })
        .collect();
    let full = plan_with_par(&app, &delay(20), &valued)?;
    let regions = regions_as_planned(&plan_of(&app, &BTreeMap::new())?);
    let partial = full.parameters_only(&regions)?;
    assert!(
        !partial
            .steps
            .iter()
            .any(|s| matches!(s, FlashStep::CompareTableReference { .. })),
        "{:?}",
        partial.steps
    );
    assert!(
        partial.steps.iter().any(|s| matches!(
            s,
            FlashStep::CompareProp { prop_id: 7, expected: Some(e), .. } if e == &[0, 0, 0x60, 0]
        )),
        "{:?}",
        partial.steps
    );
    Ok(())
}

#[test]
fn test_parameters_only_keeps_object_5_when_application_program_2_has_full_ops_only() -> TestResult
{
    // Review of #1072: Application Program 2 is loaded whatever the `par`
    // filter leaves of its blocks, so the procedure's object 5 rows run
    // (KNX 3/5/3 §3.9.3.6). Here they unload object 5 and allocate nothing
    // for it, which the planner refuses rather than drop object 5.
    let app = app_with(
        r#"<LoadProcedure MergeId="2">"#,
        r#"<LoadProcedure MergeId="3">
                <LdCtrlRelSegment AppliesTo="full" LsmIdx="5" Size="16" Mode="0" Fill="0" />
              </LoadProcedure>
              <LoadProcedure MergeId="2">"#,
    )?;
    let full = plan_of(&app, &delay(20))?;
    let regions = regions_as_planned(&plan_of(&app, &BTreeMap::new())?);
    assert!(matches!(
        full.parameters_only(&regions),
        Err(PartialPlanError::DropsSegment {
            object: 5,
            size: 16
        })
    ));
    Ok(())
}
