//! The text and the `--json` documents of a flash's pre-flight (`bussard
//! flash`, `--parameters-only`, `--dry-run`): what the plan writes, in the
//! vendor's words first and the memory-level plan under `-v` (issue #109).
//! Built from the plan the flow returns, so the surfaces only print them.

use std::collections::BTreeMap;

use bussard_download::{FlashPlan, ParamPlan, ParamValue, region_rows, trace};
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
         fresh allocation that is whatever the allocation left, so the model's value is not \
         verified:",
        params.kept.len()
    );
    for kept in &params.kept {
        w!(out, "      {}", kept.kept_line());
    }
}

/// The `kept_memory` array of the JSON plan (issue #411).
fn kept_memory_json(plan: &FlashPlan) -> Vec<serde_json::Value> {
    plan.kept()
        .iter()
        .map(|k| {
            serde_json::json!({
                "object": k.object,
                "segment": k.segment,
                "allocated": k.allocated,
                "address": k.address,
                "ranges": k.ranges.iter().map(|(s, e)| [s, e]).collect::<Vec<_>>(),
                "label": k.label(),
            })
        })
        .collect()
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
            None => format!(
                "{} (segment {} of {} octets: not written, not read back, no MCB CRC compared)",
                k.label(),
                k.segment,
                k.allocated
            ),
        })
        .collect()
}

/// The `flash --json` document (schema `FLASH`): the pre-flight, including
/// the `parameters` array (issue #109) and, when the pre-flight read PID 61
/// and a group address leaves or joins Data Secure, the `security_object`
/// change the text output prints (issue #336): `line` as printed (`- security
/// object: Data Secure off for …`), with its `mark`, `subject` and
/// `sentence`.
pub fn flash_plan_json(
    target: IndividualAddress,
    device_mask: u16,
    plan: &FlashPlan,
    params: &ParamPlan,
    security_change: Option<&bussard_download::PlanChange>,
) -> serde_json::Value {
    let parameters: Vec<serde_json::Value> = params
        .changes
        .iter()
        .map(|c| {
            serde_json::json!({
                "key": c.key,
                "name": c.name,
                "old": match &c.old {
                    ParamValue::Known(v) => serde_json::Value::String(v.clone()),
                    ParamValue::Unknown => serde_json::Value::Null,
                },
                "new": match &c.new {
                    ParamValue::Known(v) => serde_json::Value::String(v.clone()),
                    ParamValue::Unknown => serde_json::Value::Null,
                },
                "unit": c.unit,
            })
        })
        .collect();
    serde_json::json!({
        "device": target.to_string(),
        "device_mask": format!("{device_mask:04X}"),
        "application": {
            "id": plan.identity.id,
            "name": plan.identity.name,
            "number": plan.identity.application_number,
            "version": plan.identity.application_version,
            "mask": plan.identity.mask_version,
        },
        "parameters": parameters,
        "parameter_note": params.note,
        // Issue #411: the parameters and octets the download keeps on the
        // device (not written, not verified).
        "kept_parameters": params.kept.iter().map(|c| serde_json::json!({
            "key": c.key,
            "name": c.name,
            "device": match &c.old {
                ParamValue::Known(v) => serde_json::Value::String(v.clone()),
                ParamValue::Unknown => serde_json::Value::Null,
            },
            "model": c.new.to_string(),
            "unit": c.unit,
            "written": false,
            "verified": false,
        })).collect::<Vec<_>>(),
        "kept_memory": kept_memory_json(plan),
        "security_object": security_change.map(|change| {
            let mut value = serde_json::json!(change);
            value["line"] = serde_json::Value::String(change.line());
            value
        }),
        "memory": {
            "write_bytes": plan.total_write_bytes(),
            "steps": plan.steps.len(),
            "frames": plan.estimated_write_frames(),
            "estimated_seconds": plan.estimated_duration().as_secs_f64(),
        },
        "procedure": trace(plan),
    })
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
            "  overrides   : {} model value(s), keyed by the app-relative ParameterRef id:",
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

/// The `flash --parameters-only --json` document (schema
/// `FLASH_PARAMETERS`).
pub fn params_plan_json(target: IndividualAddress, planned: &ParamsPlanned) -> serde_json::Value {
    let (partial, regions, params) = (&planned.partial, &planned.regions, &planned.params);
    let properties = &planned.properties;
    serde_json::json!({
        "device": target.to_string(),
        "mode": "parameters-only",
        "application": partial.identity.id,
        "parameters": params.changes.iter().map(|c| serde_json::json!({
            "key": c.key,
            "name": c.name,
            "old": c.old.to_string(),
            "new": c.new.to_string(),
            "unit": c.unit,
        })).collect::<Vec<_>>(),
        "regions": region_rows(partial, regions).into_iter().map(|(segment, address, len, changed)| serde_json::json!({
            "segment": segment,
            "address": format!("{address:#08X}"),
            "octets": len,
            "changed_octets": changed,
        })).collect::<Vec<_>>(),
        "unwritten": partial.unwritten_bits().into_iter().map(|(segment, octets)| serde_json::json!({
            "segment": segment,
            "offsets": octets.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            "written": false,
            "reason": "no parameter the configuration reaches is placed there; ETS does not write this octet in a download",
        })).collect::<Vec<_>>(),
        "properties": properties.iter().map(|p| serde_json::json!({
            "property": p.label(),
            "parameters": p.parameters,
            "model": p.model.iter().map(|b| format!("{b:02X}")).collect::<String>(),
            "device": p.device.as_ref().map(|d| d.iter().map(|b| format!("{b:02X}")).collect::<String>()),
        })).collect::<Vec<_>>(),
        "procedure": bussard_download::trace(partial),
    })
}

/// The offline plan of `flash --parameters-only --dry-run` as JSON.
pub fn params_dry_run_json(target: IndividualAddress, partial: &FlashPlan) -> serde_json::Value {
    serde_json::json!({
        "device": target.to_string(),
        "mode": "parameters-only",
        "dry_run": true,
        "application": partial.identity.id,
        "procedure": bussard_download::trace(partial),
    })
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

    fn app(id: &str) -> Result<bussard_prod::ApplicationProgram, Box<dyn std::error::Error>> {
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
        Ok(bussard_prod::parse_application_program(id, xml.as_bytes())?)
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
            &bussard_prod::dynamic::DynamicMemo::new(&app),
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
        let with = flash_plan_json(target, 0x07B0, &plan, &params, Some(&change));
        assert_eq!(with["security_object"]["line"], change.line());
        assert!(
            with["security_object"]["line"]
                .as_str()
                .is_some_and(|l| l.starts_with("- security object: Data Secure off for 1/2/3")),
            "{with}"
        );
        assert_eq!(with["security_object"]["subject"], "security");
        let without = flash_plan_json(target, 0x07B0, &plan, &params, None);
        assert!(without["security_object"].is_null(), "{without}");
        Ok(())
    }
}
