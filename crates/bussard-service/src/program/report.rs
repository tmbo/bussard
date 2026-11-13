//! The text and the `--json` documents of a flash's pre-flight (`bussard
//! flash`, `--parameters-only`, `--dry-run`): what the plan writes, in the
//! vendor's words first and the memory-level plan under `-v` (issue #109).
//! Built from the plan the flow returns, so the surfaces only print them.

use std::collections::BTreeMap;

use bussard_download::{FlashPlan, ParamChange, ParamPlan, ParamValue, region_rows, trace};
use serde::Serialize;

use crate::report::Report;
use bussard_model::IndividualAddress;

use super::params_only::ParamsPlanned;

/// Appends one line to a `String` report.
macro_rules! w {
    ($out:expr, $($arg:tt)*) => {{
        $out.push_str(&format!($($arg)*));
        $out.push('\n');
    }};
}

/// The parameter-level plan: what changes, in the vendor's own words.
fn param_plan_text(out: &mut String, params: &ParamPlan) {
    if let Some(note) = &params.note {
        w!(out, "  note        : {note}");
    }
    kept_params_text(out, params);
    if params.changes.is_empty() {
        w!(out, "  parameters  : no parameter change");
        return;
    }
    w!(
        out,
        "  parameters  : {} change(s){}:",
        params.changes.len(),
        if params.unknown > 0 {
            format!(", {} without a readable current value", params.unknown)
        } else {
            String::new()
        }
    );
    for change in &params.changes {
        w!(out, "      {}", change.line());
    }
}

/// The parameters the download leaves as the device holds them (issue #411):
/// neither written nor ignored, and not verifiable after a fresh allocation.
fn kept_params_text(out: &mut String, params: &ParamPlan) {
    if params.kept.is_empty() {
        return;
    }
    w!(
        out,
        "  kept        : {} parameter(s) kept on the device: the load procedure's branch does \
         not write their octets (as ETS's download), so the device keeps what it holds; after a \
         fresh allocation that is whatever the allocation left, so your project's value is not \
         verified:",
        params.kept.len()
    );
    for kept in &params.kept {
        w!(out, "      {}", kept.kept_line());
    }
}

/// The octet runs the download leaves as the device holds them (issue
/// #411), one line each: `object 4 octets 128..256 kept`.
fn kept_memory_lines(plan: &FlashPlan) -> Vec<String> {
    plan.kept()
        .iter()
        .map(|k| match k.address {
            // System 7: the taken branch allocates the segment in parts and
            // the gap in no allocation (issue #411).
            Some(_) => format!(
                "{} (segment {} of {} octets: not allocated, not written, not compared)",
                k.label(),
                k.segment,
                k.allocated
            ),
            // A segment without `<Data>` keeps what the device held where no
            // parameter lives (issue #1084).
            None if k.unoccupied => format!(
                "{} (segment {} of {} octets: not written, as in ETS's download; no MCB CRC \
                 compared)",
                k.label(),
                k.segment,
                k.allocated
            ),
            None => format!(
                "{} (segment {} of {} octets: not written, not read back, no MCB CRC compared)",
                k.label(),
                k.segment,
                k.allocated
            ),
        })
        .collect()
}

/// The application a download writes.
#[derive(Debug, Clone, Serialize)]
pub struct ApplicationIdentity {
    /// The application-program id.
    pub id: String,
    /// Its display name.
    pub name: Option<String>,
    /// The KNX application number.
    pub number: Option<u32>,
    /// The application version.
    pub version: Option<u32>,
    /// The mask version it is for.
    pub mask: String,
}

/// One parameter a download changes: its key, its vendor text, and the
/// device's and the project's value (`None`: unreadable).
#[derive(Debug, Clone, Serialize)]
pub struct ParameterValues {
    /// The `ParameterRef` id.
    pub key: String,
    /// The vendor's text.
    pub name: String,
    /// What the device holds.
    pub device: Option<String>,
    /// What the project holds.
    pub model: Option<String>,
    /// The vendor's unit.
    pub unit: Option<String>,
}

impl ParameterValues {
    /// `change` in words.
    fn of(change: &ParamChange) -> ParameterValues {
        let text = |v: &ParamValue| v.known().map(str::to_string);
        ParameterValues {
            key: change.key.clone(),
            name: change.name.clone(),
            device: text(&change.old),
            model: text(&change.new),
            unit: change.unit.clone(),
        }
    }
}

/// One parameter the download keeps on the device (issue #411): not
/// written, not verified.
#[derive(Debug, Clone, Serialize)]
pub struct KeptParameter {
    /// The parameter and both values.
    #[serde(flatten)]
    pub values: ParameterValues,
    /// Always `false`.
    pub written: bool,
    /// Always `false`.
    pub verified: bool,
}

/// One octet run the download keeps on the device (issue #411).
#[derive(Debug, Clone, Serialize)]
pub struct KeptMemory {
    /// The load-state machine.
    pub object: u32,
    /// The code segment.
    pub segment: String,
    /// The octets the allocation holds.
    pub allocated: usize,
    /// The segment's base address on System 7.
    pub address: Option<u32>,
    /// The `[start, end)` runs kept.
    pub ranges: Vec<[usize; 2]>,
    /// `object 4 octets 128..256`.
    pub label: String,
}

/// The security-object change of a flash pre-flight (issue #336), with
/// the line the text output prints.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityLine {
    /// The change.
    #[serde(flatten)]
    pub change: bussard_download::PlanChange,
    /// `- security object: Data Secure off for …`.
    pub line: String,
}

/// The size of a download.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryPlan {
    /// Octets written.
    pub write_bytes: usize,
    /// Steps of the load procedure.
    pub steps: usize,
    /// Telegrams the writes take.
    pub frames: usize,
    /// The estimated duration, in seconds.
    pub estimated_seconds: f64,
}

/// The `flash --json` pre-flight (issue #904): what the download writes, in
/// the vendor's words, and the memory-level plan.
#[derive(Debug, Clone, Serialize)]
pub struct FlashPlanReport {
    /// The device.
    pub address: String,
    /// The mask the device reported, hex.
    pub mask: String,
    /// The application written.
    pub application: ApplicationIdentity,
    /// The parameters that change (issue #109).
    pub parameters: Vec<ParameterValues>,
    /// Why the parameters were not compared, when they were not.
    pub parameter_note: Option<String>,
    /// The parameters the download keeps on the device (issue #411).
    pub kept_parameters: Vec<KeptParameter>,
    /// The octets the download keeps on the device (issue #411).
    pub kept_memory: Vec<KeptMemory>,
    /// The security-object change (issue #336).
    pub security_object: Option<SecurityLine>,
    /// The size of the download.
    pub memory: MemoryPlan,
    /// The load procedure, one line per step.
    pub procedure: Vec<String>,
}

impl FlashPlanReport {
    /// The pre-flight of writing `plan` (with the parameter plan `params`)
    /// to `target`, which reported `device_mask`.
    pub fn new(
        target: IndividualAddress,
        device_mask: u16,
        plan: &FlashPlan,
        params: &ParamPlan,
        security_change: Option<&bussard_download::PlanChange>,
    ) -> FlashPlanReport {
        FlashPlanReport {
            address: target.to_string(),
            mask: format!("{device_mask:04X}"),
            application: ApplicationIdentity {
                id: plan.identity.id.clone(),
                name: plan.identity.name.clone(),
                number: plan.identity.application_number,
                version: plan.identity.application_version,
                mask: plan.identity.mask_version.clone(),
            },
            parameters: params.changes.iter().map(ParameterValues::of).collect(),
            parameter_note: params.note.clone(),
            kept_parameters: params
                .kept
                .iter()
                .map(|c| KeptParameter {
                    values: ParameterValues::of(c),
                    written: false,
                    verified: false,
                })
                .collect(),
            kept_memory: plan
                .kept()
                .iter()
                .map(|k| KeptMemory {
                    object: k.object,
                    segment: k.segment.clone(),
                    allocated: k.allocated,
                    address: k.address,
                    ranges: k.ranges.iter().map(|&(s, e)| [s, e]).collect(),
                    label: k.label(),
                })
                .collect(),
            security_object: security_change.map(|change| SecurityLine {
                change: change.clone(),
                line: change.line(),
            }),
            memory: MemoryPlan {
                write_bytes: plan.total_write_bytes(),
                steps: plan.steps.len(),
                frames: plan.estimated_write_frames(),
                estimated_seconds: plan.estimated_duration().as_secs_f64(),
            },
            procedure: trace(plan),
        }
    }
}

impl Report for FlashPlanReport {
    const SCHEMA: u32 = 2;
}

/// The `flash` pre-flight in text: the application identity, the mask, the
/// parameter-level plan, the overrides and the memory-level plan under `-v`.
pub fn flash_plan_text(
    target: IndividualAddress,
    device_mask: u16,
    plan: &FlashPlan,
    overrides: &BTreeMap<String, String>,
    params: &ParamPlan,
    verbose: u8,
) -> String {
    let mut out = String::new();
    let out = &mut out;
    w!(out, "Flash plan for {target}");
    w!(
        out,
        "  application : {} {}",
        plan.identity.id,
        plan.identity.name.as_deref().unwrap_or(""),
    );
    if let (Some(num), Some(ver)) = (
        plan.identity.application_number,
        plan.identity.application_version,
    ) {
        w!(out, "  app number  : {num} (version {ver})");
    }
    w!(
        out,
        "  mask        : app {} vs device {device_mask:04X} — compatible",
        plan.identity.mask_version,
    );
    // The parameter-level plan first (issue #109): an owner reads "night setback:
    // 18 to 17 °C", not a byte offset. The model's own override keys follow only
    // when asked for, and the memory-level plan only under `-v`.
    param_plan_text(out, params);
    if verbose > 0 && !overrides.is_empty() {
        w!(
            out,
            "  overrides   : {} project value(s), keyed by the app-relative ParameterRef id:",
            overrides.len()
        );
        for (key, value) in overrides {
            w!(out, "      {key} = {value}");
        }
    }
    w!(
        out,
        "  writes      : {} byte(s) across {} step(s), ~{} memory frame(s), est. {:.1}s on TP1",
        plan.total_write_bytes(),
        plan.steps.len(),
        plan.estimated_write_frames(),
        plan.estimated_duration().as_secs_f64(),
    );
    if plan.has_security_program() {
        // Data Secure (issue #156): the security object is part of the
        // download; name what it receives, never a key.
        let (senders, keys, secured) =
            plan.steps
                .iter()
                .fold((0usize, 0usize, 0usize), |(s, k, o), step| match step {
                    bussard_download::FlashStep::SecuritySenders { entries } => {
                        (s + entries.len(), k, o)
                    }
                    bussard_download::FlashStep::SecurityGroupKeys { entries } => {
                        (s, k + entries.len(), o)
                    }
                    bussard_download::FlashStep::SecurityGoFlags { flags } => {
                        (s, k, o + flags.iter().filter(|f| **f != 0).count())
                    }
                    _ => (s, k, o),
                });
        w!(
            out,
            "  data secure : security object reprogrammed: {senders} secured sender(s), {keys} \
             group key(s), {secured} secured group object(s)"
        );
    }
    for line in kept_memory_lines(plan) {
        w!(out, "  kept memory : {line}");
    }
    if verbose > 0 {
        w!(out, "  procedure   :");
        for line in trace(plan) {
            w!(out, "    {line}");
        }
    } else {
        w!(
            out,
            "  procedure   : {} step(s); re-run with -v for the memory-level plan",
            plan.steps.len()
        );
    }
    std::mem::take(out)
}

/// The parameter-only plan in text.
pub fn params_plan_text(target: IndividualAddress, planned: &ParamsPlanned) -> String {
    let (partial, regions, params) = (&planned.partial, &planned.regions, &planned.params);
    let properties = &planned.properties;
    let mut out = String::new();
    let out = &mut out;
    w!(out, "Parameter-only download for {target}");
    w!(
        out,
        "  application : {} {}",
        partial.identity.id,
        partial.identity.name.as_deref().unwrap_or("")
    );
    if params.changes.is_empty() {
        w!(out, "  parameters  : no parameter change");
    } else {
        w!(out, "  parameters  : {} change(s):", params.changes.len());
        for change in &params.changes {
            w!(out, "      {}", change.line());
        }
    }
    w!(out, "  memory      :");
    for (segment, address, len, changed) in region_rows(partial, regions) {
        w!(
            out,
            "      {segment} at {address:#08X}: {changed} of {len} octet(s) change"
        );
    }
    if !properties.is_empty() {
        w!(out, "  properties  :");
        for p in properties {
            let names = if p.parameters.is_empty() {
                String::new()
            } else {
                format!(" ({})", p.parameters.join(", "))
            };
            w!(out, "      {}{names}: written", p.sentence());
        }
    }
    for (segment, octets) in partial.unwritten_bits() {
        let offsets: Vec<String> = octets.iter().map(|(i, _)| i.to_string()).collect();
        w!(
            out,
            "      {segment}: {} octet(s) differ where no parameter the configuration reaches \
             is placed (offset {}): not written; ETS does not write these octets in a download",
            octets.len(),
            offsets.join(", ")
        );
    }
    w!(
        out,
        "  procedure   : {} (no table write)",
        procedure_summary(partial)
    );
    std::mem::take(out)
}

/// A one-line summary of the op sequence, e.g. `StartLoading, 1 write,
/// LoadCompleted, restart`.
fn procedure_summary(partial: &FlashPlan) -> String {
    partial
        .steps
        .iter()
        .map(|s| partial.step_label(s))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One parameter memory region a parameter-only download compares.
#[derive(Debug, Clone, Serialize)]
pub struct RegionRow {
    /// The code segment.
    pub segment: String,
    /// Its base address, `0x000000`.
    pub address: String,
    /// Its length in octets.
    pub octets: usize,
    /// The octets that differ.
    pub changed_octets: usize,
}

/// Octets of a segment no parameter the configuration reaches is placed in.
#[derive(Debug, Clone, Serialize)]
pub struct UnwrittenOctets {
    /// The code segment.
    pub segment: String,
    /// The offsets left as the device holds them.
    pub offsets: Vec<usize>,
    /// Always `false`.
    pub written: bool,
    /// Why.
    pub reason: String,
}

/// A property a parameter is placed in (issue #706).
#[derive(Debug, Clone, Serialize)]
pub struct PropertyValue {
    /// `object 0 property 61`.
    pub property: String,
    /// The parameters placed in it.
    pub parameters: Vec<String>,
    /// The value the project composes, hex.
    pub model: String,
    /// What the device holds, hex.
    pub device: Option<String>,
}

/// The `flash --parameters-only --json` plan (issue #904); `dry_run` is
/// the offline plan with no device read.
#[derive(Debug, Clone, Serialize)]
pub struct ParamsPlanReport {
    /// The device.
    pub address: String,
    /// Always `parameters-only`.
    pub mode: String,
    /// The offline plan: nothing was read.
    #[serde(skip_serializing_if = "crate::report::is_false")]
    pub dry_run: bool,
    /// The application id.
    pub application: String,
    /// The parameters that change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<ParameterValues>>,
    /// The regions compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regions: Option<Vec<RegionRow>>,
    /// The octets left as the device holds them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwritten: Option<Vec<UnwrittenOctets>>,
    /// The properties the parameters are placed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<PropertyValue>>,
    /// The load procedure, one line per step.
    pub procedure: Vec<String>,
}

impl Report for ParamsPlanReport {
    const SCHEMA: u32 = 2;
}

/// Hex of `bytes`, no separator.
fn hex_run(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

impl ParamsPlanReport {
    /// The plan of a parameter-only download to `target`.
    pub fn new(target: IndividualAddress, planned: &ParamsPlanned) -> ParamsPlanReport {
        let (partial, regions, params) = (&planned.partial, &planned.regions, &planned.params);
        ParamsPlanReport {
            address: target.to_string(),
            mode: "parameters-only".to_string(),
            dry_run: false,
            application: partial.identity.id.clone(),
            parameters: Some(params.changes.iter().map(ParameterValues::of).collect()),
            regions: Some(
                region_rows(partial, regions)
                    .into_iter()
                    .map(|(segment, address, octets, changed_octets)| RegionRow {
                        segment,
                        address: format!("{address:#08X}"),
                        octets,
                        changed_octets,
                    })
                    .collect(),
            ),
            unwritten: Some(
                partial
                    .unwritten_bits()
                    .into_iter()
                    .map(|(segment, octets)| UnwrittenOctets {
                        segment,
                        offsets: octets.iter().map(|(i, _)| *i).collect(),
                        written: false,
                        reason: "no parameter the configuration reaches is placed there; ETS \
                                 does not write this octet in a download"
                            .to_string(),
                    })
                    .collect(),
            ),
            properties: Some(
                planned
                    .properties
                    .iter()
                    .map(|p| PropertyValue {
                        property: p.label(),
                        parameters: p.parameters.clone(),
                        model: hex_run(&p.model),
                        device: p.device.as_deref().map(hex_run),
                    })
                    .collect(),
            ),
            procedure: bussard_download::trace(partial),
        }
    }

    /// The offline plan of `flash --parameters-only --dry-run`.
    pub fn dry_run(target: IndividualAddress, partial: &FlashPlan) -> ParamsPlanReport {
        ParamsPlanReport {
            address: target.to_string(),
            mode: "parameters-only".to_string(),
            dry_run: true,
            application: partial.identity.id.clone(),
            parameters: None,
            regions: None,
            unwritten: None,
            properties: None,
            procedure: bussard_download::trace(partial),
        }
    }
}

/// The offline plan of `flash --parameters-only --dry-run` in text. With no
/// device memory to diff against, each parameter write is shown at its full
/// segment length; on the bus only the octets that differ are written.
pub fn params_dry_run_text(target: IndividualAddress, partial: &FlashPlan) -> String {
    let mut out = String::new();
    let out = &mut out;
    w!(out, "Parameter-only download for {target} (offline plan)");
    w!(
        out,
        "  application : {} {}",
        partial.identity.id,
        partial.identity.name.as_deref().unwrap_or("")
    );
    w!(
        out,
        "  memory      : only the octets a parameter is placed in under the configuration \
         that differ from the device's parameter memory are written (read before the first \
         write); ETS does not write the others in a download either"
    );
    w!(out, "  procedure   :");
    for (i, step) in partial.steps.iter().enumerate() {
        w!(out, "      {:>2}. {}", i + 1, partial.step_label(step));
    }
    std::mem::take(out)
}

/// The `flash -v` timing line (issues #194, #212): the pre-flight, the
/// download up to the terminal restart, and the restart with the post-reboot
/// verification, then per restart the device confirmed the time to its first
/// answered readiness probe; and the System 7 verify-mode echoes (issue
/// #524).
pub fn flash_timing(
    app_id: &str,
    preflight: std::time::Duration,
    written: &super::flash::FlashWritten,
) -> String {
    let outcome = written.flashed.outcome.as_ref().ok();
    let readiness = outcome
        .map(|o| o.reboot_readiness.as_slice())
        .unwrap_or_default();
    let mut out = String::new();
    w!(
        out,
        "{}{}",
        phase_timings(
            preflight,
            written.download_started,
            written.restart_started,
            written.finished
        ),
        readiness_summary(app_id, readiness)
    );
    if let Some(echoes) = outcome.and_then(|o| o.verify_echoes) {
        w!(
            out,
            "verify mode: {} of {} memory-write echoes compared, set again on {} reconnect(s)",
            echoes.echoes_compared,
            echoes.chunks_written,
            echoes.re_enabled
        );
    }
    out
}

/// The phases of the `flash -v` timing line.
fn phase_timings(
    preflight: std::time::Duration,
    download_started: std::time::Instant,
    restart_started: Option<std::time::Instant>,
    finished: std::time::Instant,
) -> String {
    let secs = |d: std::time::Duration| format!("{:.1} s", d.as_secs_f64());
    match restart_started {
        Some(at) => format!(
            "timing: pre-flight {}, download {}, restart + verification {}",
            secs(preflight),
            secs(at.saturating_duration_since(download_started)),
            secs(finished.saturating_duration_since(at)),
        ),
        None => format!(
            "timing: pre-flight {}, download {} (did not reach the terminal restart)",
            secs(preflight),
            secs(finished.saturating_duration_since(download_started)),
        ),
    }
}

/// The readiness part of the `flash -v` timing line (issue #212): per restart
/// the device confirmed, the time from its `A_Restart_Response` to the first
/// answered readiness probe and the process time it reported, keyed by the
/// application id so the waits can be tuned per product. Empty when the flash
/// confirmed no restart.
fn readiness_summary(app_id: &str, readiness: &[bussard_download::RebootReadiness]) -> String {
    if readiness.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = readiness
        .iter()
        .map(|r| {
            let ready = r.ready_after.map_or("no probe answered".to_string(), |d| {
                format!("{:.1} s", d.as_secs_f64())
            });
            format!(
                "{} {} (process time {} s)",
                r.kind,
                ready,
                r.process_time.as_secs()
            )
        })
        .collect();
    format!("; readiness {app_id}: {}", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str) -> Result<bussard_product::ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
             <ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1"
                MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
              <Static>
               <Code>
                <RelativeSegment Id="{id}_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
               </Code>
               <LoadProcedures>
                <LoadProcedure><LdCtrlConnect /><LdCtrlDisconnect /></LoadProcedure>
               </LoadProcedures>
              </Static>
             </ApplicationProgram></KNX>"#
        );
        Ok(bussard_product::parse_application_program(
            id,
            xml.as_bytes(),
        )?)
    }

    #[test]
    fn test_readiness_summary_names_each_confirmed_restart() {
        use bussard_download::{RebootReadiness, RestartKind};
        use std::time::Duration;
        assert_eq!(readiness_summary("M-1_A-1", &[]), "");
        let readiness = [
            RebootReadiness {
                kind: RestartKind::FactoryReset,
                process_time: Duration::from_secs(8),
                ready_after: Some(Duration::from_millis(3050)),
            },
            RebootReadiness {
                kind: RestartKind::Restart,
                process_time: Duration::ZERO,
                ready_after: None,
            },
        ];
        assert_eq!(
            readiness_summary("M-1_A-1", &readiness),
            "; readiness M-1_A-1: factory reset 3.0 s (process time 8 s), \
             restart no probe answered (process time 0 s)"
        );
    }

    #[test]
    fn test_flash_plan_json_carries_the_security_object_line()
    -> Result<(), Box<dyn std::error::Error>> {
        // Issue #336: `flash --json` carries the "Data Secure off for <GA>"
        // line the text output prints from the pre-flight PID 61 read.
        let app = app("M-0083_A-0001-01-0001")?;
        let plan = bussard_download::plan_flash(
            &app,
            "1.1.10",
            0x07B0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &bussard_product::dynamic::DynamicMemo::new(&app),
        )?;
        let change = bussard_download::PlanChange {
            mark: bussard_download::ChangeMark::Removed,
            subject: bussard_download::ChangeSubject::Security,
            channel: None,
            key: "security object".to_string(),
            object: None,
            sentence: "security object: Data Secure off for 1/2/3 (Level): its group key leaves \
                       the group key table (PID 53) and object 22 loses its security flag (PID \
                       61 0x03 to 0x00)"
                .to_string(),
        };
        let target: IndividualAddress = "1.1.10".parse()?;
        let params = ParamPlan::default();
        let with = serde_json::to_value(FlashPlanReport::new(
            target,
            0x07B0,
            &plan,
            &params,
            Some(&change),
        ))?;
        assert_eq!(with["security_object"]["line"], change.line());
        assert!(
            with["security_object"]["line"]
                .as_str()
                .is_some_and(|l| l.starts_with("- security object: Data Secure off for 1/2/3")),
            "{with}"
        );
        assert_eq!(with["security_object"]["subject"], "security");
        let without =
            serde_json::to_value(FlashPlanReport::new(target, 0x07B0, &plan, &params, None))?;
        assert!(without["security_object"].is_null(), "{without}");
        Ok(())
    }
}
