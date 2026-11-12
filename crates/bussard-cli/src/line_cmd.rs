//! `bussard plan --line` and `bussard apply --line` — the whole-line runner
//! (issue #100).
//!
//! Commissioning day is a batch job: sixty devices on a line, one model, one
//! operator. The single-device `plan` and `apply` handle one address each and
//! ask for one confirmation each, which does not scale to a line. This module
//! iterates the model's devices on a line in address order and reports one
//! summary table.
//!
//! Each device is visited by [`bussard_service::line::visit_device`], the
//! function `knx_plan_device` and `knx_apply_device` call with `line` too
//! (issue #748): the same read, the same per-device backup, the same load
//! sequence and the same read-back verify as the single-device path.
//!
//! Two things are new here.
//!
//! **One confirmation for the run.** `apply --line` asks once, naming the
//! resolved gateway and the device count, then runs unattended. A device that
//! fails does not stop the run: it is reported and the next device is tried, so
//! one bad device on a line of sixty does not cost the other fifty-nine.
//!
//! **A resumable state file.** Every device outcome is written to
//! `<dir>/captures/apply-line-<line>.json` as it happens. A tunnel drop, a
//! killed process or a Ctrl-C therefore leaves a record of what was already
//! written; `--resume` reads it back and skips the finished devices without
//! touching the bus at all. A run that ends with no failures deletes the file.

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use bussard_model::{IndividualAddress, Model};
use bussard_service::line::resume::{LineState, Opened};
use bussard_service::line::{
    DeviceStatus, LineMode as Mode, LineOutcome as Outcome, LineTarget as Target, LineVisit,
    targets_on_line, visit_device,
};
use bussard_service::observer::{Event, Note};
use bussard_service::{BusService, WritePolicy};

use crate::cli::Resolved;
use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, gateway_display, load_model_required, open_checked,
    resolve_config,
};
use bussard_service::line::LineReport;
use bussard_service::secure::ToolKeySource;

/// Each visited device's outcome with the notes its visit made.
type Collected = Arc<Mutex<Vec<(Outcome, Vec<String>)>>>;

/// Parses an `area.line` string (e.g. `1.1`) into its two parts
/// ([`bussard_service::line::parse_line`]).
pub(crate) fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
    Ok(bussard_service::line::parse_line(line)?)
}

/// Runs `bussard plan --line`.
pub(crate) fn run_plan(
    line: &str,
    tool_key_source: ToolKeySource<'_>,
    g: &Resolved,
) -> anyhow::Result<ExitCode> {
    run_line(
        line,
        g.dir(),
        Mode::Plan,
        LineOptions {
            json: g.json,
            yes: false,
            resume: false,
            allow_remote_gateway: false,
            allow_unsupported: false,
        },
        tool_key_source,
        g.mgmt_with_facts(),
    )
}

/// Runs `bussard apply --line`.
pub(crate) fn run_apply(
    line: &str,
    yes: bool,
    resume: bool,
    allow_unsupported: bool,
    tool_key_source: ToolKeySource<'_>,
    g: &Resolved,
) -> anyhow::Result<ExitCode> {
    run_line(
        line,
        g.dir(),
        Mode::Apply,
        LineOptions {
            json: g.json,
            yes,
            resume,
            allow_remote_gateway: g.allow_remote_gateway,
            allow_unsupported,
        },
        tool_key_source,
        g.mgmt_with_facts(),
    )
}

/// The flags a whole-line run takes, bundled so the runner keeps one signature.
struct LineOptions {
    /// Emit the JSON summary instead of the table.
    json: bool,
    /// Skip the single run confirmation (`apply` only).
    yes: bool,
    /// Continue a previous run from its state file (`apply` only).
    resume: bool,
    /// Permit a write to a non-loopback gateway (`apply` only).
    allow_remote_gateway: bool,
    /// Write devices that are not on the supported list (`apply` only,
    /// issue #1089).
    allow_unsupported: bool,
}

/// The shared body of `plan --line` and `apply --line`.
fn run_line(
    line: &str,
    dir: &Path,
    mode: Mode,
    options: LineOptions,
    tool_key_source: ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let (area, line_no) = parse_line(line)?;
    let line = format!("{area}.{line_no}");

    let Some(mut model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                &format!(
                    "`bussard {} --line` visits the devices your project has on the line",
                    mode.verb()
                )
            )
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    if mode == Mode::Apply {
        // Safety envelope (issue #74): the same gate every write goes through.
        enforce_write_gate(&config, options.allow_remote_gateway)?;
        // A group address a device file uses first is declared in groups.toml.
        crate::history_cmd::capture_external_edit(dir);
        crate::groups_cmd::declare_used(dir, &mut model, "apply --line", options.json)?;
        // Validation is part of apply: a model with errors is never written.
        if !crate::validate_cmd::gate(&model, dir, "apply") {
            return Ok(ExitCode::FAILURE);
        }
    }
    let gateway = gateway_display(&config);
    // Applying writes the devices' tables; the other modes only read.
    let line_policy = if mode == Mode::Apply {
        WritePolicy::transmit(options.allow_remote_gateway)
    } else {
        WritePolicy::ReadOnly
    };

    let targets = targets_on_line(&model, area, line_no);
    if targets.is_empty() {
        bail!(
            "your project has no devices on line {line} (looked in {}/devices)",
            dir.display()
        );
    }

    // Resume bookkeeping. `--resume` reads the previous run's record; a fresh run
    // starts a new one but says so when it finds an unfinished file, so an
    // interrupted run is never silently restarted from the top.
    let state_path = LineState::path(dir, &line);
    let mut state = if mode == Mode::Apply {
        Some(open_state(&state_path, &line, &gateway, options.resume))
    } else {
        None
    };

    if mode == Mode::Apply {
        let pending = targets
            .iter()
            .filter(|t| !is_done(state.as_ref(), t.address))
            .count();
        if pending == 0 {
            eprintln!(
                "every device on line {line} is already recorded as done in {}; nothing to do",
                state_path.display()
            );
            let _ = std::fs::remove_file(&state_path);
            return Ok(ExitCode::SUCCESS);
        }
        if !confirm(&line, pending, &gateway, options.yes)? {
            eprintln!("aborted — no changes written.");
            return Ok(ExitCode::FAILURE);
        }

        // One history snapshot for the whole run, before the first bus write, so
        // `bussard history` records what the line was asked to become (#110).
        crate::history_cmd::capture_external_edit(dir);
        crate::history_cmd::snapshot(
            dir,
            bussard_model::history::SnapshotReason::new("apply")
                .with_args(["--line".to_string(), line.clone()])
                .with_gateway(Some(gateway.clone()))
                .with_result("before writing the line's device tables"),
        );
    }

    let target_count = targets.len();
    let outcomes: Collected = Arc::new(Mutex::new(Vec::new()));
    let runtime = tokio::runtime::Runtime::new()?;
    let (interrupted, mut state) = {
        let collected = Arc::clone(&outcomes);
        let config = config.clone();
        let state_path = state_path.clone();
        let conn = overrides.clone();
        let model = &model;
        runtime.block_on(async move {
            let (service, source) = open_checked(config, line_policy, &conn).await?;
            // Guard the run with Ctrl-C (issue #31): the state file is already
            // current, so the interrupt only needs to release the tunnel slot.
            let interrupted = tokio::select! {
                () = visit_all(
                    &service,
                    source,
                    model,
                    &targets,
                    mode,
                    dir,
                    tool_key_source,
                    &mut state,
                    &state_path,
                    &collected,
                    options.allow_unsupported,
                ) => false,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\ninterrupted; closing the bus connection");
                    true
                }
            };
            service.close().await;
            anyhow::Ok((interrupted, state))
        })?
    };

    let outcomes = std::mem::take(&mut *outcomes.lock().map_err(|_| {
        anyhow::anyhow!("the summary collector was poisoned by a panic in the run")
    })?);

    let failed = outcomes
        .iter()
        .filter(|(o, _)| matches!(o.status, DeviceStatus::Failed(_) | DeviceStatus::Refused(_)))
        .count();

    // A clean sweep retires the state file; anything left undone keeps it so
    // `--resume` has something to read.
    let mut kept_state = None;
    if let Some(state) = state.as_mut() {
        let all_done = failed == 0 && !interrupted && outcomes.len() == target_count;
        let kept = state
            .finish(all_done, &state_path)
            .with_context(|| format!("writing the resume state file {}", state_path.display()))?;
        kept_state = kept.then(|| state_path.display().to_string());
    }

    if options.json {
        let mut out = LineReport::new(&model, &line, mode, &gateway, &outcomes);
        out.state_file = kept_state.clone();
        crate::output::report(&out)?;
    } else {
        let outcomes: Vec<Outcome> = outcomes.into_iter().map(|(o, _)| o).collect();
        print_summary(&line, mode, &gateway, &outcomes);
        if let Some(path) = &kept_state {
            eprintln!(
                "\nstate written to {path}\nre-run with `bussard apply --line {line} --resume` \
                 to continue without rewriting the finished devices."
            );
        }
    }

    if failed > 0 || interrupted {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Whether the state file already records `address` as finished.
fn is_done(state: Option<&LineState>, address: IndividualAddress) -> bool {
    state.is_some_and(|s| s.is_done(address))
}

/// Visits every target in address order, recording one outcome each.
///
/// Nothing in here returns early: a device that fails is recorded and the run
/// continues, which is the whole point of a batch command.
#[allow(clippy::too_many_arguments)] // one run's worth of context; bundling it would only hide the wiring
async fn visit_all(
    service: &BusService,
    source: IndividualAddress,
    model: &Model,
    targets: &[Target],
    mode: Mode,
    dir: &Path,
    tool_key_source: ToolKeySource<'_>,
    state: &mut Option<LineState>,
    state_path: &Path,
    collected: &Collected,
    allow_unsupported: bool,
) {
    // KNX Data Secure (issue #71): one key per device, since a keyring holds
    // one per address; the admitted tunnelling addresses (issue #297).
    let material = |address: IndividualAddress| {
        let activated = bussard_service::secure::model_activated(Some(model), address);
        crate::timing::time("tool keys", || {
            bussard_service::secure::resolve_material(address, tool_key_source, activated)
        })
        .map_err(|err| format!("{err:#}"))
    };
    let tunnel = |secured: bool| {
        crate::secure_key::admitted_tunnel(Some(model), tool_key_source, secured)
            .map_err(|err| format!("{err:#}"))
    };
    let visit = LineVisit {
        service,
        source,
        model,
        dir,
        mode,
        material: &material,
        tunnel: &tunnel,
        on_parse: Some(crate::timing::record_product_parse),
        expected: None,
        allow_unsupported,
    };
    let total = targets.len();
    for (index, target) in targets.iter().enumerate() {
        eprintln!(
            "[{}/{total}] {} {} ({})",
            index + 1,
            mode.verb(),
            target.address,
            target.name
        );
        // A line about the device goes under it, a warning as is; both
        // are kept for the JSON row.
        let mut notes = Vec::new();
        let mut print_note = |event: Event<'_>| match event {
            Event::Note(Note::Say(line)) => {
                eprintln!("  {line}");
                notes.push(line);
            }
            Event::Note(Note::Warn(line)) => {
                eprintln!("{line}");
                notes.push(line);
            }
            _ => {}
        };
        let outcome = if is_done(state.as_ref(), target.address) {
            eprintln!("  already done in an earlier run; skipping (--resume)");
            LineState::done_earlier(target)
        } else {
            visit_device(&visit, target, &mut print_note).await
        };
        eprintln!("  {}", outcome.status.label());

        if let Some(state) = state.as_mut()
            && let Err(err) = state.record(&outcome, state_path)
        {
            eprintln!("warning: could not update the resume state file: {err}");
        }
        match collected.lock() {
            Ok(mut v) => v.push((outcome, notes)),
            Err(_) => return,
        }
    }
}

/// Loads (with `--resume`) or starts the run's state.
///
/// Without `--resume` a leftover file is reported and replaced, so an
/// interrupted run is never silently restarted from the top without the operator
/// hearing that `--resume` exists.
fn open_state(path: &Path, line: &str, gateway: &str, resume: bool) -> LineState {
    let (state, opened) = LineState::open(path, line, gateway, resume);
    let path = path.display();
    match opened {
        Opened::Resumed(done) => {
            eprintln!("resuming the run recorded in {path} ({done} device(s) already done)")
        }
        Opened::NothingToResume => {
            eprintln!("no resumable run recorded in {path}; starting a fresh one")
        }
        Opened::Replaced => eprintln!(
            "note: {path} records an unfinished run; starting from the top \
             (pass --resume to continue it instead)"
        ),
        Opened::Fresh => {}
    }
    state
}

/// Asks the one confirmation for the whole run, naming the resolved gateway
/// (issue #74). Non-interactive without `--yes` is refused.
fn confirm(line: &str, devices: usize, gateway: &str, yes: bool) -> anyhow::Result<bool> {
    crate::confirm::confirm(
        yes,
        &format!(
            "apply the links in your project to {devices} device(s) on line {line} via {gateway}?"
        ),
        &format!("apply line {line} ({devices} device(s)) via {gateway}"),
    )
}

/// Prints the one summary table the whole run ends with.
fn print_summary(line: &str, mode: Mode, gateway: &str, outcomes: &[Outcome]) {
    println!(
        "\n{} line {line} via {gateway} — {} device(s)\n",
        mode.verb(),
        outcomes.len()
    );
    let name_width = outcomes
        .iter()
        .map(|o| o.name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 32);
    println!(
        "{:<9} {:<name_width$} {:<6} status",
        "address", "name", "mask"
    );
    for o in outcomes {
        let name: String = o.name.chars().take(name_width).collect();
        let mask = o
            .mask
            .map(|m| format!("{m:04X}"))
            .unwrap_or_else(|| "—".to_string());
        println!(
            "{:<9} {:<name_width$} {:<6} {}",
            o.address.to_string(),
            name,
            mask,
            o.status.label()
        );
    }

    let count = |f: fn(&DeviceStatus) -> bool| outcomes.iter().filter(|o| f(&o.status)).count();
    let changed = count(|s| matches!(s, DeviceStatus::Changes(_) | DeviceStatus::Applied(_)));
    let unchanged = count(|s| matches!(s, DeviceStatus::Unchanged));
    let skipped = count(|s| matches!(s, DeviceStatus::Skipped(_)));
    let failed = count(|s| matches!(s, DeviceStatus::Failed(_)));
    let refused = count(|s| matches!(s, DeviceStatus::Refused(_)));
    let verb = match mode {
        Mode::Plan => "with changes",
        Mode::Apply => "applied",
    };
    let refused = if refused > 0 {
        format!(", {refused} refused (not on the supported list; --allow-unsupported)")
    } else {
        String::new()
    };
    println!(
        "\n{changed} {verb}, {unchanged} unchanged, {skipped} skipped, {failed} failed{refused}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_accepts_area_line() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_line("1.1")?, (1, 1));
        assert_eq!(parse_line("0.15")?, (0, 15));
        // A full address is accepted, its device part ignored.
        assert_eq!(parse_line("2.3.47")?, (2, 3));
        Ok(())
    }

    #[test]
    fn test_parse_line_rejects_nonsense() {
        assert!(parse_line("1").is_err());
        assert!(parse_line("16.1").is_err());
        assert!(parse_line("a.b").is_err());
    }

    #[test]
    fn test_device_status_labels_and_keys() {
        assert_eq!(DeviceStatus::Changes(3).label(), "changes: 3");
        assert_eq!(DeviceStatus::Applied(2).key(), "applied");
        assert_eq!(DeviceStatus::Unchanged.changes(), 0);
        assert_eq!(
            DeviceStatus::Skipped("unsupported mask 0012 (System 1)".to_string()).label(),
            "skipped: unsupported mask 0012 (System 1)"
        );
    }
}
