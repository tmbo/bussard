//! The `bussard scaffold` subcommand (issue #103).
//!
//! Turns a room-and-function plan into a group-address plan: reserved blocks,
//! conventional names, DPTs filled, gaps left for growth. Re-running on an
//! extended plan adds addresses without renumbering the ones already there.
//!
//! The scheme comes from `--scheme`, else from `lint.groups.scheme` in
//! `bussard.toml`, else defaults to `floor-trade-block`. Unless
//! `--no-lint-config` is passed, a matching `[lint]` table is appended to
//! `bussard.toml` when it has none, so `bussard validate` starts checking the
//! convention right away.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::scaffold::{self, Plan, Scheme};
use bussard_model::{Model, Severity};

/// Runs the scaffold command.
pub fn run(
    plan_path: &Path,
    dir: &Path,
    scheme: Option<Scheme>,
    out: Option<&Path>,
    json: bool,
    no_lint_config: bool,
) -> anyhow::Result<ExitCode> {
    let text = std::fs::read_to_string(plan_path)
        .with_context(|| format!("reading the plan {}", plan_path.display()))?;
    let plan =
        Plan::parse(&text).with_context(|| format!("parsing the plan {}", plan_path.display()))?;

    let config_path = dir.join("bussard.toml");
    let scheme = match scheme {
        Some(s) => s,
        None => scheme_from_config(&config_path).unwrap_or(Scheme::FloorTradeBlock),
    };

    let groups_path: PathBuf = match out {
        Some(p) => p.to_path_buf(),
        None => dir.join("groups.toml"),
    };

    // History (issue #110): keep the pre-scaffold files so `bussard undo` can
    // put them back, recording any edit made outside bussard first.
    crate::history_cmd::capture_external_edit(dir);
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("scaffold")
            .with_args([plan_path.display().to_string()])
            .with_result("before writing the scaffolded group addresses"),
    );

    let report = scaffold::scaffold_file(&groups_path, &plan, scheme)
        .with_context(|| format!("scaffolding into {}", groups_path.display()))?;

    let lint_written = if no_lint_config {
        false
    } else {
        scaffold::ensure_lint_config(&config_path, scheme, &report.trades_used)
            .with_context(|| format!("updating {}", config_path.display()))?
    };

    // Validate what we just wrote, so the operator sees the state of the model
    // rather than having to run a second command.
    let (errors, warnings) = match Model::load(dir) {
        Ok(model) => {
            let diags = bussard_model::validate_in_dir(&model, dir);
            (
                diags
                    .iter()
                    .filter(|d| d.severity == Severity::Error)
                    .count(),
                diags
                    .iter()
                    .filter(|d| d.severity == Severity::Warning)
                    .count(),
            )
        }
        // A `--out` outside the model directory means there is nothing to load.
        Err(_) => (0, 0),
    };

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
            "scheme": scheme.as_str(),
            "out": groups_path.display().to_string(),
            "added": added,
            "lint_config_written": lint_written,
            "validation": { "errors": errors, "warnings": warnings },
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!(
            "Scaffolded {} group address(es) into {} using the {scheme} scheme.",
            report.added.len(),
            groups_path.display()
        );
        for a in &report.added {
            println!(
                "  {:<9} {:<8} {}",
                a.address.to_string(),
                a.dpt.to_string(),
                a.name
            );
        }
        if report.added.is_empty() {
            println!("  (nothing to add: every room and function is already addressed)");
        }
        if lint_written {
            println!(
                "Wrote a matching [lint] table to {} — `bussard validate` now checks the convention.",
                config_path.display()
            );
        }
        println!("Validation: {errors} error(s), {warnings} warning(s).");
    }

    Ok(if errors > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// The scheme already declared in `bussard.toml`, if any.
fn scheme_from_config(config_path: &Path) -> Option<Scheme> {
    let dir = config_path.parent()?;
    let model = Model::load(dir).ok()?;
    model.config.lint?.groups?.scheme
}
