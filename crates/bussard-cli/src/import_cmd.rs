//! The `bussard import` subcommand.
//!
//! Imports a `.knxproj` (or an `xknxproject` JSON dump) into the YAML model,
//! writing it to an output directory via the model's deterministic saver.
//!
//! A **re-import** into a directory that already holds a model does not clobber:
//! it refreshes the generated sections (com-object tables, links wiring,
//! parameters) from ETS truth while preserving hand-authored fields (names,
//! locations, DPTs, `protected:` flags), **reporting** any hand-authored field
//! the fresh import disagrees with rather than overwriting it. See
//! [`bussard_model::merge`].

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use bussard_model::{MergeReport, Model};

/// Exit code returned when a re-import left hand-authored conflicts un-applied.
/// Distinct from success (0) so scripts/CI can detect that a human must
/// reconcile the reported fields; the write still happened (hand edits intact).
const EXIT_CONFLICTS: u8 = 3;

/// Runs `bussard import` from a `.knxproj` file.
///
/// Password resolution order: the `--password` flag, then the
/// `BUSSARD_PROJECT_PASSWORD` environment variable, then an interactive prompt
/// (only when stdin is a TTY).
///
/// A re-import always refreshes the generated sections (com-object tables, link
/// wiring, parameters) from the project and always preserves hand-authored
/// fields, reporting any difference instead of overwriting it. There is no flag
/// for that: it is the only behaviour the merge implements.
pub fn run_knxproj(
    path: &Path,
    dir: &Path,
    password_flag: Option<String>,
) -> anyhow::Result<ExitCode> {
    let password = resolve_password(password_flag);

    let model = match bussard_project::import(path, password.as_deref()) {
        Ok(model) => model,
        Err(bussard_project::ImportError::PasswordRequired) => {
            // If we have no password yet and a TTY is available, prompt once.
            if password.is_none() && std::io::stdin().is_terminal() {
                let pw = prompt_password()?;
                bussard_project::import(path, Some(&pw))?
            } else {
                anyhow::bail!(
                    "project is password-protected; provide --password, set \
                     BUSSARD_PROJECT_PASSWORD, or run in a terminal to be prompted"
                );
            }
        }
        Err(e) => return Err(e.into()),
    };

    write_model(model, dir)
}

/// Runs `bussard import --from-json`.
pub fn run_json(path: &Path, dir: &Path) -> anyhow::Result<ExitCode> {
    let model = bussard_project::import_from_json(path)?;
    write_model(model, dir)
}

/// Writes the freshly-imported `model` to `dir`.
///
/// On a **fresh** target (no existing model) this saves the whole model. On a
/// **re-import** (an existing model is present) it merges: generated sections
/// come from the fresh import, hand-authored fields are preserved from disk, and
/// any hand-authored conflict is reported (path, field, ours vs theirs) instead
/// of being overwritten. Returns [`EXIT_CONFLICTS`] when conflicts were
/// reported so the outcome is non-zero-ish while the on-disk hand edits stay
/// intact.
fn write_model(model: Model, dir: &Path) -> anyhow::Result<ExitCode> {
    // A re-import is any target that already holds a loadable model.
    let existing = load_existing_model(dir);

    let (to_save, merge_report) = match existing {
        Some(ours) => {
            let (merged, report) = bussard_model::merge(&ours, &model);
            (merged, Some(report))
        }
        None => (model, None),
    };

    let report = to_save.save_pruning(dir)?;
    println!(
        "imported {} group addresses, {} devices, {} link entries → {}",
        to_save.groups.groups.len(),
        to_save.devices.len(),
        to_save.links.links.values().map(Vec::len).sum::<usize>(),
        dir.display()
    );
    if !report.renamed.is_empty() {
        println!("renamed {} device file(s)", report.renamed.len());
    }
    if !report.pruned.is_empty() {
        println!("pruned {} stale device file(s)", report.pruned.len());
    }

    if let Some(merge) = merge_report {
        return Ok(report_merge(&merge));
    }
    Ok(ExitCode::SUCCESS)
}

/// Loads an existing model from `dir`, or `None` if the directory holds no
/// model yet (fresh import) or cannot be loaded as one.
fn load_existing_model(dir: &Path) -> Option<Model> {
    // Only treat the target as a re-import if it actually has model content: a
    // groups file or at least one device file. An empty/absent directory is a
    // fresh import.
    let has_groups = dir.join("groups.yaml").exists();
    let has_devices = dir
        .join("devices")
        .read_dir()
        .map(|mut rd| rd.any(|e| e.is_ok()))
        .unwrap_or(false);
    if !has_groups && !has_devices {
        return None;
    }
    Model::load(dir).ok()
}

/// Prints the re-import merge outcome and returns the process exit code.
fn report_merge(report: &MergeReport) -> ExitCode {
    if report.groups_added + report.devices_added > 0 {
        println!(
            "re-import: added {} new device(s), {} new group address(es)",
            report.devices_added, report.groups_added
        );
    }
    if report.groups_removed + report.devices_removed > 0 {
        println!(
            "re-import: {} device(s) and {} group address(es) left the project",
            report.devices_removed, report.groups_removed
        );
    }

    if !report.has_conflicts() {
        println!("re-import: generated sections refreshed; no hand-edited conflicts.");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "\nre-import: {} hand-edited field(s) differ from the project and were KEPT \
         (not overwritten):",
        report.conflicts.len()
    );
    for c in &report.conflicts {
        eprintln!(
            "  {} · {}: ours={:?} theirs={:?}",
            c.path, c.field, c.ours, c.theirs
        );
    }
    eprintln!(
        "\nGenerated sections (com_objects, links wiring, parameters) were refreshed. \
         The hand-edited fields above were preserved; reconcile them by hand if the \
         project's values are the ones you want."
    );
    ExitCode::from(EXIT_CONFLICTS)
}

/// Resolves the password from the flag or the environment (no prompt here).
fn resolve_password(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("BUSSARD_PROJECT_PASSWORD").ok())
        .filter(|s| !s.is_empty())
}

/// Prompts for the project password on the terminal.
fn prompt_password() -> anyhow::Result<String> {
    let pw = rpassword::prompt_password("Project password: ")?;
    Ok(pw)
}
