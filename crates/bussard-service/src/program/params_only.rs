//! `bussard flash --parameters-only` (issues #119, #543): rewrite only the
//! parameter memory of a device that already runs the application.
//!
//! The full flash's pre-flight ([`super::flash::probe`]) builds the plan and
//! reads the parameter regions on its connection; this module takes over:
//!
//! 1. **Refuse** unless the device runs the very application the product
//!    describes (System B: `PID_PROGRAM_VERSION` matches; System 7, which has
//!    no readable application id: every load-state machine is `Loaded` and
//!    the application's code segments read back as the product's bytes).
//! 2. Cut the full plan down to the parameter memory
//!    ([`FlashPlan::parameters_only`]). Refuse when a parameter segment cannot
//!    be read, when the new values change the group-object table or a System
//!    7 allocation, or (System 7) when the model's links differ from the
//!    device's link tables (`apply` rewrites them, issue #146).
//! 3. Ask, back the parameter memory up, write only the changed octets,
//!    complete the load, restart, and verify by reading the memory back on
//!    the download's last connection (issue #215).

use std::path::PathBuf;

use bussard_download::{
    FlashOptions, FlashOutcome, FlashPlan, FlashStep, ParamPlan, ParamProperty, ParamRegions,
    ResidentState,
};
use bussard_mgmt::load::WriteError;
use bussard_mgmt::memory::read_memory_range;
use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::IndividualAddress;
use bussard_model::facts::DeviceFactsRecord;
use bussard_product::ApplicationProgram;
use bussard_secure::{Key16, SequenceHighWater};

use super::apply::BackupError;
use crate::flash::FlashInputs;
use crate::observer::{Declined, Event, Note, Observer, Question, Step};
use crate::{Authorize, BusService, L4Options, Management, ServiceError};

/// What one read-only pass over the parameter memory learned.
pub struct ParamsRead {
    /// The parameter regions.
    pub regions: ParamRegions,
    /// The properties the parameters are placed in (issue #706).
    pub properties: Vec<ParamProperty>,
    /// Why the System 7 code comparison says this is another application.
    pub code_mismatch: Option<String>,
    /// Which System 7 link table the model would change (issue #146).
    pub table_change: Option<String>,
}

/// Reads the parameter regions (plus, on System 7, the code-segment samples
/// and the link-table comparison) on an open connection.
pub async fn read_parameters_on<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
    app: &ApplicationProgram,
) -> ParamsRead {
    let regions = bussard_download::read_parameter_regions(l4, plan, &[]).await;
    let properties = bussard_download::read_parameter_properties(l4, plan, app).await;
    let (code_mismatch, table_change) = if plan.is_sys7() {
        (
            bussard_download::sys7_code_mismatch(l4, plan).await,
            sys7_table_change(l4, plan).await,
        )
    } else {
        (None, None)
    };
    ParamsRead {
        regions,
        properties,
        code_mismatch,
        table_change,
    }
}

/// The session a parameter read opens when the pre-flight did not make it.
pub struct ParamsSession<'a> {
    /// The bus.
    pub service: &'a BusService,
    /// The device.
    pub target: IndividualAddress,
    /// The BCU key, `None` for free access.
    pub bcu_key: Option<u32>,
    /// The KNX Data Secure tool key.
    pub tool_key: Option<Key16>,
    /// The command-wide send-sequence high-water mark.
    pub high_water: SequenceHighWater,
    /// `PID_MAX_APDU_LENGTH` as the pre-flight negotiated it (issue #194).
    pub max_apdu: Option<u16>,
}

/// Opens a read-only session and reads the parameters
/// ([`read_parameters_on`]).
///
/// # Errors
///
/// The session could not be opened.
pub async fn read_parameters(
    session: &ParamsSession<'_>,
    plan: &FlashPlan,
    app: &ApplicationProgram,
) -> Result<ParamsRead, ServiceError> {
    // Best-effort: a denial or a device without authorize still reads.
    let options = L4Options::secured(
        session.service.handle().group_source(),
        session.tool_key.clone(),
        session.high_water.clone(),
    )
    .with_authorize(Authorize::BestEffort(
        session
            .bcu_key
            .unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY),
    ));
    session
        .service
        .with_l4(session.target, &options, async |l4| {
            // The pre-flight negotiated PID_MAX_APDU_LENGTH; seed it so the
            // read goes out in APDU-sized chunks without re-reading it.
            l4.set_max_apdu(session.max_apdu);
            Ok::<_, ServiceError>(read_parameters_on(l4, plan, app).await)
        })
        .await
}

/// Names the first System 7 link table (LSM 1 group addresses, LSM 2
/// associations) whose resident content differs from what the full plan
/// computes from the model, or that cannot be read (issue #146). `None` when
/// every table matches.
///
/// The group-address table is compared octet by octet under its mask (the
/// own-address slot is device-owned); the association table as a set of
/// `(TSAP, ASAP)` pairs, since the order of equal links carries no meaning.
pub async fn sys7_table_change<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> Option<String> {
    for step in &plan.steps {
        let FlashStep::Sys7AbsSegment {
            lsm,
            address,
            size,
            image: Some(image),
            ..
        } = step
        else {
            continue;
        };
        if image.kind != bussard_download::ImageKind::Table {
            continue;
        }
        let Some(desired) = plan.image_bytes(&image.segment_id) else {
            continue;
        };
        let got = match read_memory_range(l4, *address, desired.len()).await {
            Ok(got) => got,
            Err(err) => {
                return Some(format!(
                    "the LSM {lsm} link table at {address:#06X} could not be read ({err})"
                ));
            }
        };
        let mask = plan.segment_mask(&image.segment_id);
        let same_octets = desired
            .iter()
            .enumerate()
            .all(|(i, b)| mask.is_some_and(|m| m.get(i) != Some(&0xFF)) || got.get(i) == Some(b));
        if same_octets {
            continue;
        }
        let capacity = usize::try_from(*size).unwrap_or(usize::MAX);
        let same_links = *lsm == 2
            && match (
                bussard_download::decode_sys7_association_table(desired, capacity),
                bussard_download::decode_sys7_association_table(&got, capacity),
            ) {
                (Ok(mut want), Ok(mut have)) => {
                    want.sort_unstable();
                    have.sort_unstable();
                    want == have
                }
                _ => false,
            };
        if !same_links {
            let table = match *lsm {
                1 => "group-address table",
                2 => "association table",
                _ => "link table",
            };
            return Some(format!(
                "the model's links differ from the device's {table} (LSM {lsm} at {address:#06X})"
            ));
        }
    }
    None
}

/// The parameter-only download planned against what the device holds.
pub struct ParamsPlanned {
    /// The download: only the parameter octets that differ.
    pub partial: FlashPlan,
    /// The parameter memory as read (it is backed up before the write).
    pub regions: ParamRegions,
    /// What changes, in the vendor's words.
    pub params: ParamPlan,
    /// The properties a parameter is placed in that differ (issue #706).
    pub properties: Vec<ParamProperty>,
}

impl ParamsPlanned {
    /// Whether the device already holds these values: nothing is written
    /// and no load state is touched.
    pub fn is_noop(&self) -> bool {
        self.partial.changed_octets() == 0 && self.properties.is_empty()
    }

    /// The one question before the write.
    pub fn question(&self, target: IndividualAddress, gateway: &str) -> Question {
        let octets = self.partial.changed_octets();
        let what = if self.properties.is_empty() {
            format!("{octets} octet(s)")
        } else {
            format!(
                "{octets} octet(s), {} propert(y/ies)",
                self.properties.len()
            )
        };
        Question {
            kind: crate::observer::Ask::Write,
            prompt: format!("download the parameters ({what}) to {target} via {gateway}?"),
            action: format!("flash the parameters of {target} via {gateway}"),
        }
    }
}

/// Plans the parameter-only download of the full plan `plan` against the
/// device's parameter memory `read`. `Err` is the refusal, one sentence
/// after "refusing the parameter-only download to `<ia>`: ".
///
/// # Errors
///
/// The device runs another application, the links or the group-object table
/// would change, or a parameter segment could not be read.
pub fn plan_parameters_only(
    target: IndividualAddress,
    inputs: &FlashInputs<'_>,
    plan: &FlashPlan,
    read: ParamsRead,
) -> Result<ParamsPlanned, String> {
    if let Some(reason) = read.code_mismatch {
        return Err(reason);
    }
    // A parameter-only download leaves the table load-state machines alone.
    if let Some(reason) = read.table_change {
        return Err(format!(
            "{reason}. A parameter-only download does not rewrite the link tables; run `bussard \
             apply` for the links first, then re-run `bussard flash --parameters-only {target}`."
        ));
    }
    let app = inputs.app();
    let regions = read.regions;
    let partial = plan.parameters_only(&regions).map_err(|e| e.to_string())?;
    // A parameter that shows or hides a com-object changes the group-object
    // table, which this download does not rewrite. The device's values come
    // from the decoder the read-back uses (issue #142).
    let current = bussard_download::regions_memory(&regions);
    let memo = bussard_product::dynamic::DynamicMemo::new(app);
    let decoded = bussard_download::decode_parameters(
        app,
        inputs.overrides(),
        inputs.base_offsets(),
        &current,
        &memo,
    );
    let change =
        bussard_download::group_object_change(app, &decoded.values, inputs.overrides(), &memo);
    if !change.is_empty() {
        return Err(format!(
            "the new parameter values change the group-object table ({}); a parameter-only \
             download leaves that table as it is. Run a full `bussard flash {target}` instead.",
            bussard_download::describe_group_object_change(&change)
        ));
    }
    // Issue #411: a System 7 load procedure that allocates the segments
    // differently under the new values needs the full download.
    if let Some(why) =
        bussard_download::allocation_change(app, &decoded.values, inputs.overrides(), &memo)
    {
        return Err(format!(
            "{why}; a parameter-only download sends no allocation record. Run a full `bussard \
             flash {target}` instead."
        ));
    }
    let properties: Vec<ParamProperty> = bussard_download::changed_properties(&read.properties)
        .into_iter()
        .cloned()
        .collect();
    // Issue #944: no ETS capture confirms this download yet (#572).
    if !properties.is_empty()
        && let Some(why) = crate::params::uncaptured_property_download(target, &partial)
    {
        return Err(why);
    }
    Ok(ParamsPlanned {
        partial,
        regions,
        params: ParamPlan {
            changes: decoded.differences,
            unknown: decoded.unknown,
            note: None,
            kept: decoded.kept,
        },
        properties,
    })
}

/// The parameter-only download's write.
pub struct ParamsWrite<'a> {
    /// The session of a read-back the download's last connection could not
    /// make, and the download's own options.
    pub session: ParamsSession<'a>,
    /// The checked source address.
    pub source: IndividualAddress,
    /// The model directory (the backup).
    pub dir: &'a std::path::Path,
    /// The full plan (the read-back reads its regions).
    pub plan: &'a FlashPlan,
    /// The application.
    pub app: &'a ApplicationProgram,
    /// What the pre-flight learned, seeding the download.
    pub facts: DeviceFactsRecord,
    /// The pre-flight's connection, taken over under `--yes` (issue #213).
    pub handover: Option<Management>,
    /// The question.
    pub question: Question,
}

/// How a parameter-only download ended.
pub enum ParamsWritten {
    /// The human said no: nothing written.
    Declined,
    /// The download ran.
    Ran {
        /// The parameter memory backup taken before the first write.
        backup: PathBuf,
        /// The download, its restart and its load-state verification.
        outcome: Result<FlashOutcome, WriteError>,
        /// The read-back after it: the octets verified, or what differs.
        verified: Option<Result<usize, String>>,
    },
}

/// Asks, backs the parameter memory up, writes only the changed octets,
/// completes the load, restarts, and verifies by reading the memory back.
///
/// # Errors
///
/// No one could be asked (the refusal), the backup could not be written, or
/// the read-back session could not be opened.
pub async fn write_parameters_only(
    write: ParamsWrite<'_>,
    planned: &ParamsPlanned,
    observer: &mut impl Observer,
) -> Result<ParamsWritten, ParamsWriteError> {
    match crate::observer::ask(observer, &write.question) {
        Ok(()) => {}
        Err(Declined::No) => return Ok(ParamsWritten::Declined),
        Err(Declined::Refused(refusal)) => return Err(ParamsWriteError::Refused(refusal)),
    }
    let target = write.session.target;
    // A backup of no memory (a program whose parameters all live in
    // properties, issue #944) restores nothing: no write.
    if planned.regions.is_empty() {
        return Err(ParamsWriteError::Backup(BackupError::NoParameterMemory));
    }
    // Back up the parameter memory before the first write; no backup, no
    // write.
    let backup = bussard_download::write_parameter_memory_backup(
        write.dir,
        target,
        write.plan,
        &planned.regions,
    )
    .map_err(|e| ParamsWriteError::Backup(BackupError::Parameters(e)))?;
    observer.event(Event::Note(Note::Say(format!(
        "parameter backup written to {}",
        backup.display()
    ))));
    let run = crate::download::FlashRun {
        service: write.session.service,
        target,
        source: write.source,
        options: FlashOptions {
            bcu_key: write.session.bcu_key,
            verify_after_restart: true,
            skip_matching_mcb: false,
        },
        facts: write.facts,
        tool_key: write.session.tool_key.clone(),
        high_water: write.session.high_water.clone(),
        handover: write.handover,
    };
    observer.event(Event::Step(Step::Download {
        plan: &planned.partial,
    }));
    let (plan, app) = (write.plan, write.app);
    // Write, restart, verify, then read the parameters back on the same
    // (post-restart) connection (issue #215).
    let (outcome, after) =
        crate::download::flash_session(run, &planned.partial, &mut *observer, async |l4| {
            (
                bussard_download::read_parameter_regions(l4, plan, &[]).await,
                bussard_download::read_parameter_properties(l4, plan, app).await,
            )
        })
        .await;
    let verified = match &outcome {
        Ok(done) if done.ok() => {
            let (after, after_props) = match after {
                Some(read) => read,
                None => {
                    let read = read_parameters(&write.session, plan, app)
                        .await
                        .map_err(ParamsWriteError::Session)?;
                    (read.regions, read.properties)
                }
            };
            // The properties the download wrote read back as the model.
            let unverified: Vec<String> = bussard_download::changed_properties(&after_props)
                .iter()
                .map(|p| p.sentence())
                .collect();
            Some(if unverified.is_empty() {
                bussard_download::verify_readback(
                    &planned.partial,
                    &after,
                    &bussard_download::runtime_segments(plan),
                )
            } else {
                Err(unverified.join("; "))
            })
        }
        _ => None,
    };
    Ok(ParamsWritten::Ran {
        backup,
        outcome,
        verified,
    })
}

/// Why a parameter-only download did not run.
#[derive(Debug, thiserror::Error)]
pub enum ParamsWriteError {
    /// No one could be asked.
    #[error("{0}")]
    Refused(String),
    /// The backup could not be written.
    #[error(transparent)]
    Backup(BackupError),
    /// The read-back session could not be opened.
    #[error(transparent)]
    Session(ServiceError),
}

/// The offline plan of `flash --parameters-only --dry-run`: the op sequence
/// the download would send, each parameter write at its full segment length
/// (on the bus only the octets that differ are written).
///
/// # Errors
///
/// The plan cannot be cut down to the parameter memory.
pub fn dry_run(plan: &FlashPlan) -> Result<FlashPlan, String> {
    let regions = bussard_download::planned_parameter_regions(plan);
    plan.parameters_only(&regions).map_err(|e| e.to_string())
}

/// The identity gate of the parameter-only download: the device must run
/// this very application. `Err` is the refusal reason.
///
/// # Errors
///
/// Another application, none loaded, or an unreadable state.
pub fn identity_gate(plan: &FlashPlan, resident: Option<&ResidentState>) -> Result<(), String> {
    bussard_download::identity_gate(plan, resident)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_download::{ResidentObject, plan_flash};
    use bussard_mgmt::load::LoadState;
    use bussard_product::application::parse_application_program;
    use std::collections::BTreeMap;

    /// A System B application with a known identity (manufacturer 1, number 1,
    /// version 1) and one parameter segment.
    fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0001_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>
            <RelativeSegment Id="M-0001_A-0001-01-0000_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
           </Code>
           <ParameterTypes><ParameterType Id="M-0001_A-0001-01-0000_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
           <Parameters><Parameter Id="M-0001_A-0001-01-0000_P-0" Name="thr" ParameterType="M-0001_A-0001-01-0000_PT-0" Value="7"><Memory CodeSegment="M-0001_A-0001-01-0000_RS-1" Offset="0" BitOffset="0" /></Parameter></Parameters>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="4" />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="1" AppliesTo="par" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="1" AppliesTo="par" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        Ok(parse_application_program(
            "M-0001_A-0001-01-0000",
            xml.as_bytes(),
        )?)
    }

    fn plan() -> Result<FlashPlan, Box<dyn std::error::Error>> {
        Ok(plan_flash(
            &app()?,
            "1.1.4",
            0x07B0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &bussard_product::dynamic::DynamicMemo::new(&app()?),
        )?)
    }

    fn state(load: LoadState, app_id: Option<Vec<u8>>) -> ResidentState {
        ResidentState {
            objects: vec![ResidentObject {
                index: 3,
                object_type: Some(3),
                state: load,
            }],
            app_id,
            ..ResidentState::default()
        }
    }

    #[test]
    fn test_identity_gate_same_application_passes() -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Loaded, Some(vec![0x00, 0x01, 0x00, 0x01, 0x01]));
        assert_eq!(identity_gate(&plan()?, Some(&st)), Ok(()));
        Ok(())
    }

    #[test]
    fn test_identity_gate_other_application_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Loaded, Some(vec![0x00, 0x02, 0x00, 0x09, 0x01]));
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("runs application M-0002 A-0009 v1"), "{err}");
        Ok(())
    }

    #[test]
    fn test_identity_gate_unloaded_device_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Unloaded, None);
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("not Loaded"), "{err}");
        Ok(())
    }

    #[test]
    fn test_identity_gate_unidentified_system_b_application_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let st = state(LoadState::Loaded, None);
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("cannot be read"), "{err}");
        Ok(())
    }

    #[test]
    fn test_identity_gate_unreadable_state_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let st = ResidentState {
            unreadable: Some("no answer".into()),
            ..ResidentState::default()
        };
        let err = identity_gate(&plan()?, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("no answer"), "{err}");
        assert!(identity_gate(&plan()?, None).is_err());
        Ok(())
    }

    /// A System 7 application (mask 0705) whose procedure loads LSMs 1 and 3.
    fn sys7_plan() -> Result<FlashPlan, Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0083_A-000E-23-0000" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="S7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0083_A-000E-23-0000_AS-1" Size="4" Address="16384"><Data>AAECAw==</Data></AbsoluteSegment>
            <AbsoluteSegment Id="M-0083_A-000E-23-0000_AS-4" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlUnload LsmIdx="1" />
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="1" />
             <LdCtrlAbsSegment LsmIdx="1" Address="16384" Size="4" />
             <LdCtrlTaskSegment LsmIdx="1" Address="16384" />
             <LdCtrlLoadCompleted LsmIdx="1" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
             <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0083_A-000E-23-0000", xml.as_bytes())?;
        Ok(plan_flash(
            &app,
            "1.1.32",
            0x0705,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &bussard_product::dynamic::DynamicMemo::new(&app),
        )?)
    }

    fn lsm(index: u8, state: LoadState) -> ResidentObject {
        ResidentObject {
            index,
            object_type: None,
            state,
        }
    }

    #[test]
    fn test_identity_gate_system7_ignores_lsms_the_procedure_never_loads()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = sys7_plan()?;
        assert!(plan.is_sys7());
        // LSM 2 and 5 are not the application's: their state does not matter.
        let st = ResidentState {
            objects: vec![
                lsm(1, LoadState::Loaded),
                lsm(2, LoadState::Unloaded),
                lsm(3, LoadState::Loaded),
                lsm(5, LoadState::Unloaded),
            ],
            ..ResidentState::default()
        };
        assert_eq!(identity_gate(&plan, Some(&st)), Ok(()));
        // An application LSM that is not Loaded still refuses.
        let st = ResidentState {
            objects: vec![lsm(1, LoadState::Loaded), lsm(3, LoadState::Unloaded)],
            ..ResidentState::default()
        };
        let err = identity_gate(&plan, Some(&st)).err().unwrap_or_default();
        assert!(err.contains("not fully Loaded"), "{err}");
        Ok(())
    }

    #[test]
    fn test_describe_group_object_change_names_objects() {
        let change = bussard_download::GroupObjectChange {
            shown: vec![7],
            hidden: vec![3, 4],
            table_differs: true,
        };
        assert_eq!(
            bussard_download::describe_group_object_change(&change),
            "shows object(s) 7, hides object(s) 3, 4"
        );
    }

    #[test]
    fn test_check_parameter_backup_refuses_an_empty_backup()
    -> Result<(), Box<dyn std::error::Error>> {
        // Issue #944: a program whose parameters all live in properties has
        // no memory region; a backup of nothing restores nothing, so the
        // write that needs it does not start.
        let detail = crate::params::ParamDetail {
            plan: plan()?,
            regions: ParamRegions::new(),
            decoded: bussard_download::DecodedParameters::default(),
            resident: ResidentState::default(),
            needs_flash: None,
            octets: Vec::new(),
            unwritten: Vec::new(),
            object_table: None,
            properties: Vec::new(),
        };
        let dir = std::env::temp_dir().join(format!("bussard-empty-backup-{}", std::process::id()));
        let result = super::super::apply::check_parameter_backup(&detail);
        assert!(
            matches!(result, Err(BackupError::NoParameterMemory)),
            "{result:?}"
        );
        assert!(!bussard_download::backup::parameter_backups_dir(&dir).exists());
        Ok(())
    }
}
