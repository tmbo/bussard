//! The `bussard groups` subcommands, and the "declare where first used" hook
//! the model-writing commands share.
//!
//! `bussard groups reserve "<Floor> <Room>" <function>...` appends the
//! conventional block for that room and trade to `groups.toml` under the
//! project's scheme (`[lint.groups] scheme` in `bussard.toml`) and prints the
//! addresses. It replaces the plan-file driven `bussard scaffold`.
//!
//! [`declare_used`] adds the group addresses a device file links but
//! `groups.toml` does not define yet (see [`bussard_model::declare`]); `import`
//! and `apply` call it, `validate` alone only warns.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::scaffold::{self, Plan, PlanRoom, Scheme};
use bussard_model::{DeclaredGroup, Model, Severity};
use bussard_service::groups_report::ReserveReport;

use crate::cli::{Resolved, Run, Spec};

/// The `bussard groups` subcommands.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum GroupsCommand {
    /// Append the conventional group-address block for a room and trade to
    /// `groups.toml` and print the addresses.
    ///
    /// The scheme is `[lint.groups] scheme` in `bussard.toml` (written on the
    /// first reservation). Re-running for a room and function that already
    /// have their block adds nothing.
    Reserve {
        /// The room, floor first, as one argument: `"EG Küche"`.
        #[arg(value_name = "FLOOR ROOM")]
        room: String,
        /// The functions the room needs: light, light-dim, blind, heating,
        /// socket.
        #[arg(value_name = "FUNCTION", required = true)]
        functions: Vec<String>,
        /// The addressing scheme for a project that has none yet (default
        /// floor-trade-block). Refused when it contradicts `bussard.toml`.
        #[arg(long, value_enum)]
        scheme: Option<SchemeArg>,
    },
    /// Switch KNX Data Secure on or off for one group address.
    ///
    /// `off` removes the group key from the key store (`bussard.keys`) and
    /// clears the `secure` flag of the group and of every com-object linked
    /// to it on every device; `on` sets them and keeps the store's key, or
    /// generates a new random one as ETS does. One change, snapshotted with
    /// the key store, so `bussard undo` restores all three. Needs
    /// `BUSSARD_KEYRING_PASSWORD`. The Secure devices linked to the group
    /// address then need `bussard plan` and `bussard apply`, and every user
    /// of an exported keyring (Home Assistant) a new `bussard keys export`.
    // Issue #331.
    Secure {
        /// The group address, e.g. `1/0/4`.
        #[arg(value_name = "GA")]
        ga: String,
        /// `on` or `off`.
        #[arg(value_name = "on|off")]
        state: String,
    },
}

impl Run for GroupsCommand {
    fn spec(&self) -> Spec {
        Spec::FILES.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        match self {
            GroupsCommand::Reserve {
                room,
                functions,
                scheme,
            } => run_reserve(g.dir(), &room, &functions, scheme.map(Into::into), g.json),
            GroupsCommand::Secure { ga, state } => run_secure(g.dir(), &ga, &state, g.json),
        }
    }
}

/// The group-address addressing scheme, as a CLI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum SchemeArg {
    /// `main` = floor, `middle` = trade.
    FloorTradeBlock,
    /// `main` = trade, `middle` = floor.
    FunctionFloor,
}

impl From<SchemeArg> for Scheme {
    fn from(value: SchemeArg) -> Self {
        match value {
            SchemeArg::FloorTradeBlock => Scheme::FloorTradeBlock,
            SchemeArg::FunctionFloor => Scheme::FunctionFloor,
        }
    }
}

/// Runs `bussard groups reserve`.
fn run_reserve(
    dir: &Path,
    room: &str,
    functions: &[String],
    scheme: Option<Scheme>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let room = PlanRoom::from_label(room, functions)?;
    let config_path = dir.join("bussard.toml");
    let configured = bussard_model::load_config(dir)
        .ok()
        .and_then(|c| c.lint)
        .and_then(|l| l.groups)
        .and_then(|g| g.scheme);
    let scheme = match (configured, scheme) {
        (Some(have), Some(want)) if have != want => bail!(
            "{} declares the {have} scheme; `--scheme {want}` would mix two schemes in one \
             plan. Change `[lint.groups] scheme` there first if the project really moves.",
            config_path.display()
        ),
        (Some(have), _) => have,
        (None, Some(want)) => want,
        (None, None) => Scheme::FloorTradeBlock,
    };

    crate::history_cmd::capture_external_edit(dir);
    let mut args = vec![format!("{} {}", room.floor, room.room)];
    args.extend(functions.iter().cloned());
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("groups reserve")
            .with_args(args)
            .with_result("before reserving group addresses"),
    );

    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let groups_path = dir.join("groups.toml");
    let label = format!("{} {}", room.floor, room.room);
    let plan = Plan { rooms: vec![room] };
    let report = scaffold::scaffold_file(&groups_path, &plan, scheme)
        .with_context(|| format!("reserving into {}", groups_path.display()))?;
    // The scheme lives in `bussard.toml`: write it the first time, so the next
    // reservation (and `bussard validate`) follows the same convention.
    let lint_written = scaffold::ensure_lint_config(&config_path, scheme, &report.trades_used)
        .with_context(|| format!("updating {}", config_path.display()))?;
    let (errors, warnings) = validation_counts(dir);

    if json {
        crate::output::report(&ReserveReport {
            room: Some(label.clone()),
            ..ReserveReport::new(
                scheme.as_str(),
                &groups_path,
                &report,
                lint_written,
                (errors, warnings),
            )
        })?;
    } else {
        if report.added.is_empty() {
            println!(
                "{label} already has its addresses for {}; nothing added.",
                functions.join(", ")
            );
        } else {
            println!(
                "reserved {} group address(es) for {label} in {} ({scheme} scheme):",
                report.added.len(),
                groups_path.display()
            );
        }
        for a in &report.added {
            println!(
                "  {:<9} {:<8} {}",
                a.address.to_string(),
                a.dpt.to_string(),
                a.name
            );
        }
        if lint_written {
            println!(
                "wrote the {scheme} scheme to the [lint] table of {}; `bussard validate` now \
                 checks the convention.",
                config_path.display()
            );
        }
        println!("validation: {errors} error(s), {warnings} warning(s).");
    }
    Ok(if errors > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Runs `bussard groups secure <GA> on|off` (issue #331): the group's and
/// every linked com-object's `secure` flag, and the group key in the key
/// store, as one change. The history snapshot taken first keeps a copy of
/// the key store, so `bussard undo` restores all three.
fn run_secure(dir: &Path, ga: &str, state: &str, json: bool) -> anyhow::Result<ExitCode> {
    use bussard_service::group_security as gs;
    use bussard_service::groups_report::GroupSecureReport;
    let ga: bussard_model::GroupAddress = ga
        .parse()
        .map_err(|_| anyhow::anyhow!("{ga:?} is not a group address like \"1/0/4\""))?;
    let secure = match state.to_ascii_lowercase().as_str() {
        "on" | "true" => true,
        "off" | "false" => false,
        other => bail!("{other:?} is neither `on` nor `off`"),
    };
    let password = bussard_model::dotenv::var(bussard_service::secure::KEYRING_PASSWORD_ENV).ok();
    // Nothing is written unless the store loads.
    let mut store = gs::load_store(dir, password.as_deref())?;
    let before =
        Model::load(dir).with_context(|| format!("loading the model in {}", dir.display()))?;
    let mut edited = before.clone();
    let edit = gs::edit_model(&mut edited, ga, secure).map_err(|reason| anyhow::anyhow!(reason))?;
    let action = gs::apply_group_key(&mut store, ga, secure)?;
    let changes = bussard_model::change::describe(&before, &edited);
    if changes.is_empty() && !action.changed() {
        if json {
            crate::output::report(&GroupSecureReport::new(
                ga,
                secure,
                &changes,
                action.label(),
            ))?;
        } else {
            println!(
                "{ga} already runs {}; nothing changed.",
                if secure { "secured" } else { "plain" }
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    crate::history_cmd::capture_external_edit(dir);
    let snapshot = crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("groups secure")
            .with_args([ga.to_string(), state.to_string()])
            .with_result("before switching Data Secure for a group address"),
    );
    let kept = match &snapshot {
        Some(id) => gs::keep_keystore(
            dir,
            &bussard_model::history::History::open(dir).snapshot_dir(id),
        )?,
        None => false,
    };
    if action.changed() {
        gs::save_store(dir, &store, password.as_deref().unwrap_or_default())?;
    }
    edited
        .save(dir)
        .with_context(|| format!("saving the model in {}", dir.display()))?;
    let devices = edit.secure_devices(&edited);
    let note = gs::export_note(ga, secure);
    if json {
        let report = GroupSecureReport {
            snapshot: snapshot.as_ref().map(ToString::to_string),
            snapshot_keeps_key_store: Some(kept),
            note: Some(note),
            ..GroupSecureReport::new(ga, secure, &changes, action.label())
                .with_devices(&edit.devices, &devices)
        };
        crate::output::report(&report)?;
        return Ok(ExitCode::SUCCESS);
    }
    print!("{}", bussard_model::change::render_text(&changes));
    println!("{}", action.sentence(ga));
    if !devices.is_empty() {
        let list: Vec<String> = devices.iter().map(ToString::to_string).collect();
        println!(
            "The security object of {} changes: run `bussard plan <ia>` and `bussard apply \
             <ia>` for each to {} the group key table entry (PID 53) and the objects' security \
             flags (PID 61).",
            list.join(", "),
            if secure { "add" } else { "remove" }
        );
    }
    println!("{note}");
    // The edit changes the key store only: a keyring that bus commands read
    // instead keeps the old state (issue #331).
    let env =
        bussard_model::dotenv::var_os(crate::conn_cmd::KEYRING_ENV).map(std::path::PathBuf::from);
    if let Some(other) = bussard_service::secure::keyring_file(dir, None, env.as_deref())
        .filter(|r| r.source != bussard_service::secure::KeyringSource::Store)
    {
        eprintln!(
            "warning: bus commands read their keys from {} ({}), not from the key store; it \
             still has the old state of {ga}. Import it with `bussard keys import` and drop it.",
            other.path.display(),
            other.source.describe()
        );
    }
    if let Some(id) = snapshot {
        println!("`bussard undo` goes back to snapshot {id} (the key store included).");
    }
    Ok(ExitCode::SUCCESS)
}

/// The model's error and warning counts, `(0, 0)` when it does not load.
fn validation_counts(dir: &Path) -> (usize, usize) {
    match Model::load(dir) {
        Ok(model) => {
            let diags = bussard_model::validate_in_dir(&model, dir);
            let count = |s: Severity| diags.iter().filter(|d| d.severity == s).count();
            (count(Severity::Error), count(Severity::Warning))
        }
        Err(_) => (0, 0),
    }
}

/// Adds the group addresses the device files link but `groups.toml` does not
/// define, saves `groups.toml` (behind a history snapshot) and prints one line
/// per addition (on stderr when `json`, so stdout stays one JSON document).
/// `verb` names the command in the snapshot. The write is
/// [`bussard_service::declare::declare_used`], shared with the MCP apply.
///
/// Returns what was added; an empty list writes nothing.
pub(crate) fn declare_used(
    dir: &Path,
    model: &mut Model,
    verb: &str,
    json: bool,
) -> anyhow::Result<Vec<DeclaredGroup>> {
    let added =
        bussard_service::declare::declare_used(dir, model, verb, &mut crate::console::Console)?;
    for d in &added {
        if json {
            eprintln!("{}", d.sentence());
        } else {
            println!("{}", d.sentence());
        }
    }
    Ok(added)
}
