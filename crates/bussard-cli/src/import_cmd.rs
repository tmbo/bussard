//! The `bussard import` subcommand.
//!
//! Imports a `.knxproj` (or an `xknxproject` JSON dump) into the TOML model,
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

use crate::import_bundle::ConflictChoice;

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
    choice: ConflictChoice,
    consent: crate::product_fetch::Consent,
) -> anyhow::Result<ExitCode> {
    let password = resolve_password(password_flag);
    let options = bussard_project::ImportOptions::for_dir(dir);

    let model = match bussard_project::import_with(path, password.as_deref(), &options) {
        Ok(model) => model,
        Err(bussard_project::ImportError::PasswordRequired) => {
            // If we have no password yet and a TTY is available, prompt once.
            if password.is_none() && std::io::stdin().is_terminal() {
                let pw = prompt_password()?;
                bussard_project::import_with(path, Some(&pw), &options)?
            } else {
                anyhow::bail!(
                    "project is password-protected; provide --password, set \
                     BUSSARD_PROJECT_PASSWORD, or run in a terminal to be prompted"
                );
            }
        }
        Err(e) => return Err(e.into()),
    };

    write_model(model, dir, choice, "project", Some(consent), Some(path))
}

/// Runs `bussard import --from-json`.
pub fn run_json(
    path: &Path,
    dir: &Path,
    choice: ConflictChoice,
    consent: crate::product_fetch::Consent,
) -> anyhow::Result<ExitCode> {
    let model = bussard_project::import_from_json(path)?;
    write_model(model, dir, choice, "project", Some(consent), None)
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
///
/// `choice` settles hand-authored conflicts (see [`ConflictChoice`]); `source`
/// names the incoming side in sentences (`"project"` or `"bundle"`).
/// `fetch` runs the product-data download step for the devices' order
/// numbers ([`crate::product_fetch`]); `None` skips it. `project` is the ETS
/// export read, which `bussard.lock` pins as the devices' product source
/// until a vendor archive serves them (lock v2, issue #228).
pub(crate) fn write_model(
    model: Model,
    dir: &Path,
    choice: ConflictChoice,
    source: &str,
    fetch: Option<crate::product_fetch::Consent>,
    project: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    // History (issue #110): record an edit made outside bussard before the
    // import overwrites it, then snapshot the pre-import state so `bussard undo`
    // can put it back.
    if dir.is_dir() {
        crate::product_store::prepare(dir);
    }
    crate::history_cmd::capture_external_edit(dir);
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("import")
            .with_result("before writing the imported model"),
    );

    // A re-import is any target that already holds a loadable model.
    let existing = load_existing_model(dir);

    let (mut to_save, merge_report) = match existing {
        Some(mut ours) => {
            bussard_model::normalize_spellings(&mut ours, &model);
            let (mut merged, report) = bussard_model::merge(&ours, &model);
            let kept = crate::import_bundle::resolve_conflicts(
                &ours,
                &model,
                &mut merged,
                &report,
                choice,
                source,
            )?;
            (merged, Some((ours, report, kept)))
        }
        None => (model, None),
    };

    // A group address a device file uses but the plan does not define is
    // declared in groups.toml, named after the object that uses it first.
    let declared = bussard_model::declare_used_groups(&mut to_save);

    // An import that changes nothing leaves the files alone, so hand-written
    // comments and formatting survive a no-op re-import.
    if let Some((ours, merge, kept)) = &merge_report
        && *ours == to_save
    {
        println!(
            "{} already matches the import; no file written",
            dir.display()
        );
        crate::import_bundle::print_changes(ours, &to_save);
        if fetch.is_some() {
            crate::lock_pin::pin_import(dir, project, &to_save);
        }
        fetch_product_data(dir, &to_save, fetch)?;
        crate::validate_cmd::print_summary(dir);
        return Ok(report_merge(merge, *kept, choice));
    }

    let report = to_save.save_pruning(dir)?;
    println!(
        "imported {} group addresses, {} devices, {} link entries → {}",
        to_save.groups.groups.len(),
        to_save.devices.len(),
        to_save.links.links.values().map(Vec::len).sum::<usize>(),
        dir.display()
    );
    for d in &declared {
        println!("{}", d.sentence());
    }
    if !report.renamed.is_empty() {
        println!("renamed {} device file(s)", report.renamed.len());
    }
    if !report.pruned.is_empty() {
        println!("pruned {} stale device file(s)", report.pruned.len());
    }

    // The lock pins where each device's product data comes from.
    if fetch.is_some() {
        crate::lock_pin::pin_import(dir, project, &to_save);
    }
    // Product data fetches itself: every order number without it is looked up
    // in the pointer index, with one question for the whole list.
    fetch_product_data(dir, &to_save, fetch)?;
    // Validation is part of import: the summary says what to fix next.
    crate::validate_cmd::print_summary(dir);
    if let Some((ours, merge, kept)) = merge_report {
        crate::import_bundle::print_changes(&ours, &to_save);
        return Ok(report_merge(&merge, kept, choice));
    }
    Ok(ExitCode::SUCCESS)
}

/// The download step of `import`: fetch what is missing, then say how many
/// devices are written without product data and where to get it.
fn fetch_product_data(
    dir: &Path,
    model: &Model,
    fetch: Option<crate::product_fetch::Consent>,
) -> anyhow::Result<()> {
    let Some(consent) = fetch else {
        return Ok(());
    };
    let orders: Vec<String> = model
        .devices
        .values()
        .filter_map(|d| d.device.product.as_ref()?.order_number.clone())
        .collect();
    let outcome = crate::product_fetch::fetch_missing(dir, &orders, consent)?;
    let missing: std::collections::BTreeSet<String> = outcome
        .missing()
        .iter()
        .map(|o| bussard_prod::normalize_order_number(o))
        .collect();
    let without = model
        .devices
        .values()
        .filter(|d| {
            match d
                .device
                .product
                .as_ref()
                .and_then(|p| p.order_number.as_deref())
            {
                Some(order) => missing.contains(&bussard_prod::normalize_order_number(order)),
                None => true,
            }
        })
        .count();
    if without > 0 {
        println!(
            "{without} device(s) written without product data: their files carry identity, \
             location and links by number; `apply` writes their links, not their parameters"
        );
    }
    crate::product_fetch::print_missing(&outcome, dir);
    Ok(())
}

/// Loads an existing model from `dir`, or `None` if the directory holds no
/// model yet (fresh import) or cannot be loaded as one.
fn load_existing_model(dir: &Path) -> Option<Model> {
    // Only treat the target as a re-import if it actually has model content: a
    // groups file, a lock or at least one `devices/*.toml`. An empty/absent
    // directory (or one `bussard init` just created) is a fresh import.
    let has_groups = dir.join("groups.toml").exists() || dir.join("bussard.lock").exists();
    let has_devices = dir
        .join("devices")
        .read_dir()
        .map(|mut rd| {
            rd.any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".toml")))
        })
        .unwrap_or(false);
    if !has_groups && !has_devices {
        return None;
    }
    Model::load(dir).ok()
}

/// Prints the re-import merge outcome and returns the process exit code.
///
/// `kept` is how many conflicts still hold the local value. They exit
/// [`EXIT_CONFLICTS`] only when nobody chose (no `--mine`, `--theirs` or
/// `--interactive`); the sentences were already printed by
/// [`crate::import_bundle::resolve_conflicts`].
fn report_merge(report: &MergeReport, kept: usize, choice: ConflictChoice) -> ExitCode {
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

    // Informational notes: generated identity that moved with the project
    // (application_ref / mask), channels that left, dangling channel references
    // dropped. Not conflicts: nothing hand-authored was overridden.
    for note in &report.notes {
        println!("re-import: note: {note}");
    }

    if !report.has_conflicts() {
        println!("re-import: generated sections refreshed; no hand-edited conflicts.");
        return ExitCode::SUCCESS;
    }
    if choice != ConflictChoice::Report || kept == 0 {
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "\nGenerated sections (com_objects, links wiring, parameters) were refreshed. \
         The {kept} hand-edited field(s) above were KEPT. Re-run with --theirs to take the \
         incoming values, --mine to keep these and exit 0, or --interactive to choose each."
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
