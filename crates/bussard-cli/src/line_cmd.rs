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

use std::collections::BTreeMap;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use bussard_mgmt::system_type;
use bussard_model::{IndividualAddress, Model};
use bussard_service::line::{
    DeviceStatus, LineMode as Mode, LineNote, LineOutcome as Outcome, LineTarget as Target,
    LineVisit, targets_on_line, visit_device,
};
use bussard_service::{BusService, WritePolicy};

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display,
    load_model_required, open_service, resolve_config,
};
use crate::secure_key::ToolKeySource;

/// The state-file format version, bumped if the shape ever changes.
const STATE_VERSION: u32 = 1;

/// The stable JSON shape of one device row.
#[derive(Debug, serde::Serialize)]
struct DeviceJson {
    address: String,
    name: String,
    mask: Option<String>,
    system_type: Option<String>,
    status: &'static str,
    changes: usize,
    detail: Option<String>,
}

/// The stable JSON shape of a whole-line run.
#[derive(Debug, serde::Serialize)]
struct LineJson {
    line: String,
    mode: &'static str,
    gateway: String,
    devices: Vec<DeviceJson>,
    total: usize,
    changed: usize,
    unchanged: usize,
    skipped: usize,
    failed: usize,
    state_file: Option<String>,
}

/// One device's persisted outcome in the resume state file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeviceRecord {
    /// The status key (`applied`, `unchanged`, `skipped`, `failed`).
    status: String,
    /// How many link changes were written.
    #[serde(default)]
    changes: usize,
    /// The skip or failure reason.
    #[serde(default)]
    detail: Option<String>,
    /// When this outcome was recorded (seconds since the Unix epoch).
    #[serde(default)]
    unix: u64,
}

impl DeviceRecord {
    /// Whether a later `--resume` may skip this device untouched.
    fn is_finished(&self) -> bool {
        self.status != "failed"
    }
}

/// The resume state file: what a whole-line `apply` has already done.
///
/// It is rewritten after every device, so a process killed at any point leaves a
/// truthful record. A run that ends with no failures deletes it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LineState {
    /// The format version ([`STATE_VERSION`]).
    version: u32,
    /// The line this run covers, e.g. `1.1`.
    line: String,
    /// The gateway the run wrote through, for the operator's benefit.
    gateway: String,
    /// When the run started (seconds since the Unix epoch).
    started_unix: u64,
    /// When the file was last written.
    updated_unix: u64,
    /// Whether every device reached a finished state.
    completed: bool,
    /// Per-device outcomes, keyed by individual address.
    devices: BTreeMap<String, DeviceRecord>,
}

impl LineState {
    /// A fresh state for a run over `line` through `gateway`.
    fn new(line: &str, gateway: &str) -> Self {
        let now = unix_now();
        LineState {
            version: STATE_VERSION,
            line: line.to_string(),
            gateway: gateway.to_string(),
            started_unix: now,
            updated_unix: now,
            completed: false,
            devices: BTreeMap::new(),
        }
    }
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses an `area.line` string (e.g. `1.1`) into its two parts
/// ([`bussard_service::line::parse_line`]).
pub(crate) fn parse_line(line: &str) -> anyhow::Result<(u8, u8)> {
    Ok(bussard_service::line::parse_line(line)?)
}

/// Runs `bussard plan --line`.
pub fn run_plan(
    line: &str,
    dir: &Path,
    json: bool,
    tool_key_source: ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    run_line(
        line,
        dir,
        Mode::Plan,
        LineOptions {
            json,
            yes: false,
            resume: false,
            allow_remote_gateway: false,
        },
        tool_key_source,
        overrides,
    )
}

/// Runs `bussard apply --line`.
///
/// The argument list mirrors the subcommand's flags 1:1 (as `flash_cmd::run`
/// does); bundling them would only obscure that mapping.
#[allow(clippy::too_many_arguments)]
pub fn run_apply(
    line: &str,
    dir: &Path,
    yes: bool,
    json: bool,
    resume: bool,
    allow_remote_gateway: bool,
    tool_key_source: ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    run_line(
        line,
        dir,
        Mode::Apply,
        LineOptions {
            json,
            yes,
            resume,
            allow_remote_gateway,
        },
        tool_key_source,
        overrides,
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
                    "`bussard {} --line` visits the devices the model has on the line",
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
            "the model has no devices on line {line} (looked in {}/devices)",
            dir.display()
        );
    }

    // Resume bookkeeping. `--resume` reads the previous run's record; a fresh run
    // starts a new one but says so when it finds an unfinished file, so an
    // interrupted run is never silently restarted from the top.
    let state_path = state_file_path(dir, &line);
    let mut state = if mode == Mode::Apply {
        Some(open_state(&state_path, &line, &gateway, options.resume)?)
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
    let outcomes: Arc<Mutex<Vec<Outcome>>> = Arc::new(Mutex::new(Vec::new()));
    let runtime = tokio::runtime::Runtime::new()?;
    let (interrupted, mut state) = {
        let collected = Arc::clone(&outcomes);
        let config = config.clone();
        let state_path = state_path.clone();
        let conn = overrides.clone();
        runtime.block_on(async move {
            let service = open_service(config, line_policy).await?;
            let source = checked_source_or_close(&service, &conn).await?;
            // Guard the run with Ctrl-C (issue #31): the state file is already
            // current, so the interrupt only needs to release the tunnel slot.
            let interrupted = tokio::select! {
                () = visit_all(
                    &service,
                    source,
                    &model,
                    &targets,
                    mode,
                    dir,
                    tool_key_source,
                    &mut state,
                    &state_path,
                    &collected,
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
        .filter(|o| matches!(o.status, DeviceStatus::Failed(_)))
        .count();

    // A clean sweep retires the state file; anything left undone keeps it so
    // `--resume` has something to read.
    let mut kept_state = None;
    if let Some(state) = state.as_mut() {
        let all_done = failed == 0 && !interrupted && outcomes.len() == target_count;
        state.completed = all_done;
        state.updated_unix = unix_now();
        if all_done {
            let _ = std::fs::remove_file(&state_path);
        } else {
            write_state(&state_path, state)?;
            kept_state = Some(state_path.display().to_string());
        }
    }

    if options.json {
        let out = to_json(&line, mode, &gateway, &outcomes, kept_state.clone());
        crate::output::print(crate::output::schema::LINE, &out)?;
    } else {
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
    state
        .and_then(|s| s.devices.get(&address.to_string()))
        .map(|r| r.is_finished())
        .unwrap_or(false)
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
    collected: &Arc<Mutex<Vec<Outcome>>>,
) {
    // KNX Data Secure (issue #71): one key per device, since a keyring holds
    // one per address; the admitted tunnelling addresses (issue #297).
    let material = |address: IndividualAddress| {
        let activated = crate::secure_key::model_activated(Some(model), address);
        crate::secure_key::resolve_material(address, tool_key_source, activated)
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
        on_parse: Some(crate::product_cache::record_parse),
        expected: None,
    };
    let mut print_note = |note: LineNote| match note {
        LineNote::Detail(line) => eprintln!("  {line}"),
        LineNote::Warning(line) => eprintln!("{line}"),
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
        let outcome = if is_done(state.as_ref(), target.address) {
            eprintln!("  already done in an earlier run; skipping (--resume)");
            Outcome {
                address: target.address,
                name: target.name.clone(),
                mask: None,
                status: DeviceStatus::Skipped("done in an earlier run".to_string()),
                report: None,
                fingerprint: None,
                backup: None,
            }
        } else {
            visit_device(&visit, target, &mut print_note).await
        };
        eprintln!("  {}", outcome.status.label());

        if let Some(state) = state.as_mut() {
            state.devices.insert(
                outcome.address.to_string(),
                DeviceRecord {
                    status: outcome.status.key().to_string(),
                    changes: outcome.status.changes(),
                    detail: outcome.status.detail().map(str::to_string),
                    unix: unix_now(),
                },
            );
            state.updated_unix = unix_now();
            if let Err(err) = write_state(state_path, state) {
                eprintln!("warning: could not update the resume state file: {err:#}");
            }
        }
        match collected.lock() {
            Ok(mut v) => v.push(outcome),
            Err(_) => return,
        }
    }
}

/// The resume state file for `line` under the model directory.
fn state_file_path(dir: &Path, line: &str) -> PathBuf {
    dir.join("captures").join(format!("apply-line-{line}.json"))
}

/// Loads (with `--resume`) or starts the run's state.
///
/// Without `--resume` a leftover file is reported and replaced, so an
/// interrupted run is never silently restarted from the top without the operator
/// hearing that `--resume` exists.
fn open_state(path: &Path, line: &str, gateway: &str, resume: bool) -> anyhow::Result<LineState> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<LineState>(&text).ok(),
        Err(_) => None,
    };
    match (resume, existing) {
        (true, Some(mut state)) => {
            let done = state.devices.values().filter(|r| r.is_finished()).count();
            eprintln!(
                "resuming the run recorded in {} ({done} device(s) already done)",
                path.display()
            );
            state.gateway = gateway.to_string();
            state.completed = false;
            Ok(state)
        }
        (true, None) => {
            eprintln!(
                "no resumable run recorded in {}; starting a fresh one",
                path.display()
            );
            Ok(LineState::new(line, gateway))
        }
        (false, Some(_)) => {
            eprintln!(
                "note: {} records an unfinished run; starting from the top \
                 (pass --resume to continue it instead)",
                path.display()
            );
            Ok(LineState::new(line, gateway))
        }
        (false, None) => Ok(LineState::new(line, gateway)),
    }
}

/// Writes the state file, creating `captures/` if needed.
fn write_state(path: &Path, state: &LineState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, serde_json::to_string_pretty(state)?)
        .with_context(|| format!("writing the resume state file {}", path.display()))
}

/// Asks the one confirmation for the whole run, naming the resolved gateway
/// (issue #74). Non-interactive without `--yes` is refused.
fn confirm(line: &str, devices: usize, gateway: &str, yes: bool) -> anyhow::Result<bool> {
    crate::confirm::confirm(
        yes,
        &format!("apply the model's links to {devices} device(s) on line {line} via {gateway}?"),
        &format!("apply line {line} ({devices} device(s)) via {gateway}"),
    )
}

/// Builds the JSON summary.
fn to_json(
    line: &str,
    mode: Mode,
    gateway: &str,
    outcomes: &[Outcome],
    state_file: Option<String>,
) -> LineJson {
    let devices: Vec<DeviceJson> = outcomes
        .iter()
        .map(|o| DeviceJson {
            address: o.address.to_string(),
            name: o.name.clone(),
            mask: o.mask.map(|m| format!("{m:04X}")),
            system_type: o.mask.map(|m| system_type(m).to_string()),
            status: o.status.key(),
            changes: o.status.changes(),
            detail: o.status.detail().map(str::to_string),
        })
        .collect();
    let count = |key: &str| devices.iter().filter(|d| d.status == key).count();
    LineJson {
        line: line.to_string(),
        mode: mode.verb(),
        gateway: gateway.to_string(),
        total: devices.len(),
        changed: count("changes") + count("applied"),
        unchanged: count("unchanged"),
        skipped: count("skipped"),
        failed: count("failed"),
        devices,
        state_file,
    }
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
    let verb = match mode {
        Mode::Plan => "with changes",
        Mode::Apply => "applied",
    };
    println!("\n{changed} {verb}, {unchanged} unchanged, {skipped} skipped, {failed} failed");
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

    #[test]
    fn test_state_file_path_names_the_line() {
        let path = state_file_path(Path::new("knx"), "1.1");
        assert!(path.ends_with("captures/apply-line-1.1.json"), "{path:?}");
    }

    #[test]
    fn test_is_done_only_for_finished_records() -> anyhow::Result<()> {
        let mut state = LineState::new("1.1", "127.0.0.1:3671");
        state.devices.insert(
            "1.1.4".to_string(),
            DeviceRecord {
                status: "applied".to_string(),
                changes: 2,
                detail: None,
                unix: 0,
            },
        );
        state.devices.insert(
            "1.1.5".to_string(),
            DeviceRecord {
                status: "failed".to_string(),
                changes: 0,
                detail: Some("nak".to_string()),
                unix: 0,
            },
        );
        let done: IndividualAddress = "1.1.4".parse()?;
        let failed: IndividualAddress = "1.1.5".parse()?;
        let unseen: IndividualAddress = "1.1.6".parse()?;
        assert!(is_done(Some(&state), done));
        assert!(!is_done(Some(&state), failed));
        assert!(!is_done(Some(&state), unseen));
        assert!(!is_done(None, done));
        Ok(())
    }
}
