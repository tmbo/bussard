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

/// Runs `bussard groups reserve`.
pub fn run_reserve(
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
        let added: Vec<serde_json::Value> = report
            .added
            .iter()
            .map(|a| {
                serde_json::json!({
                    "address": a.address.to_string(),
                    "name": a.name,
                    "dpt": a.dpt.to_string(),
                })
            })
            .collect();
        let value = serde_json::json!({
            "room": label,
            "scheme": scheme.as_str(),
            "file": groups_path.display().to_string(),
            "added": added,
            "lint_config_written": lint_written,
            "validation": { "errors": errors, "warnings": warnings },
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
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
/// `verb` names the command in the snapshot.
///
/// Returns what was added; an empty list writes nothing.
pub(crate) fn declare_used(
    dir: &Path,
    model: &mut Model,
    verb: &str,
    json: bool,
) -> anyhow::Result<Vec<DeclaredGroup>> {
    let mut edited = model.clone();
    let added = bussard_model::declare_used_groups(&mut edited);
    if added.is_empty() {
        return Ok(added);
    }
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new(verb)
            .with_result("before declaring the group addresses the device files use"),
    );
    let path = dir.join("groups.toml");
    bussard_model::loader::save_groups(&path, &edited.groups)
        .with_context(|| format!("writing {}", path.display()))?;
    for d in &added {
        if json {
            eprintln!("{}", d.sentence());
        } else {
            println!("{}", d.sentence());
        }
    }
    *model = edited;
    Ok(added)
}
