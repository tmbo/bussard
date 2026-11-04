//! Writing an imported model into a directory that may already hold one:
//! `bussard import` of a `.knxproj`, an `xknxproject` JSON dump or a
//! `.bussard` bundle, and `knx_import_file` (issue #743). A fresh directory
//! gets [`crate::setup::import::write_fresh`].
//!
//! A **re-import** does not clobber: it refreshes the generated sections
//! (com-object tables, links wiring, parameters) from the incoming side while
//! preserving hand-authored fields (names, locations, DPTs, `protected`
//! flags), saying each hand-authored field the incoming side disagrees with
//! as a sentence. See [`bussard_model::merge`]. A [`ConflictChoice`] settles
//! those.

use std::path::Path;

use bussard_model::bundle::Bundle;
use bussard_model::change::{describe, render_text};
use bussard_model::reconcile::{conflict_sentence, take_theirs};
use bussard_model::{MergeReport, Model};

use crate::setup::{self, Context as _, DownloadPrompt, Output, SetupError};

/// How an import settles hand-authored conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// Keep the local values and report them so a human reconciles them
    /// (the default; the CLI exits 3).
    Report,
    /// Keep the local value for every conflict (`--mine`).
    Mine,
    /// Take the incoming value for every conflict (`--theirs`).
    Theirs,
    /// Ask per conflict ([`ConflictPrompt`], `--interactive`).
    Interactive,
}

impl ConflictChoice {
    /// Builds the choice from the three mutually exclusive flags.
    pub fn from_flags(mine: bool, theirs: bool, interactive: bool) -> Self {
        match (mine, theirs, interactive) {
            (true, _, _) => ConflictChoice::Mine,
            (_, true, _) => ConflictChoice::Theirs,
            (_, _, true) => ConflictChoice::Interactive,
            _ => ConflictChoice::Report,
        }
    }
}

/// The per-conflict question of [`ConflictChoice::Interactive`]. The
/// defaults are those of a caller that cannot ask.
pub trait ConflictPrompt {
    /// Whether [`ConflictPrompt::take_theirs`] can ask (a terminal is
    /// attached).
    fn can_ask(&self) -> bool {
        false
    }

    /// Shows one hand-edited conflict and asks whether to take the incoming
    /// value. The default keeps the local one.
    ///
    /// # Errors
    ///
    /// The answer could not be read.
    fn take_theirs(&mut self, sentence: &str) -> Result<bool, SetupError> {
        let _ = sentence;
        Ok(false)
    }
}

/// A [`ConflictPrompt`] that never asks.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPrompt;

impl ConflictPrompt for NoPrompt {}

/// What an import did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOutcome {
    /// The model files were written (false for a no-op re-import).
    pub written: bool,
    /// A re-import merged into an existing model.
    pub merged: bool,
    /// Hand-edited fields that differ from the incoming side.
    pub conflicts: usize,
    /// How many of them still hold the local value.
    pub kept: usize,
    /// Conflicts are left for a human to settle: nobody chose (the
    /// [`ConflictChoice::Report`] default) and some were kept.
    pub unresolved: bool,
}

/// Imports a `.bussard` bundle: into a directory without a model it is
/// extracted byte for byte, history included; into an existing model it runs
/// the re-import merge.
///
/// # Errors
///
/// The bundle cannot be read or extracted, or the merge fails.
pub fn import_bundle(
    path: &Path,
    dir: &Path,
    choice: ConflictChoice,
    ask: &mut dyn ConflictPrompt,
    out: &mut dyn Output,
) -> Result<ImportOutcome, SetupError> {
    let bundle = Bundle::read(path).ctx(|| format!("reading bundle {}", path.display()))?;
    let m = &bundle.manifest;
    out.say(&format!(
        "bundle {}: exported {} by bussard {}, {} device(s), {} group address(es), {} history \
         snapshot(s)",
        path.display(),
        m.exported_at,
        m.bussard_version,
        m.devices,
        m.group_addresses,
        m.history_snapshots
    ));

    if !has_model(dir) {
        bundle
            .extract(dir, true)
            .ctx(|| format!("extracting into {}", dir.display()))?;
        out.say(&format!(
            "imported the bundle into {} (model and history)",
            dir.display()
        ));
        return Ok(ImportOutcome {
            written: true,
            ..ImportOutcome::default()
        });
    }

    let model = bundle.model().map_err(SetupError::source)?;
    if m.history_snapshots > 0 {
        out.say(&format!(
            "note: {} keeps its own history; the bundle's snapshots were not merged into it",
            dir.display()
        ));
    }
    write_model(model, dir, choice, "bundle", None, None, ask, out)
}

/// Whether `dir` already holds a model to merge into (a `groups.toml`, a
/// `bussard.lock` or a device file; a lone `bussard.toml` from `bussard init`
/// does not count).
pub fn has_model(dir: &Path) -> bool {
    dir.join("groups.toml").exists()
        || dir.join("bussard.lock").exists()
        || std::fs::read_dir(dir.join("devices"))
            .map(|rd| {
                rd.flatten().any(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.ends_with(".toml") && !name.starts_with('.')
                })
            })
            .unwrap_or(false)
}

/// Writes the freshly-imported `model` to `dir`.
///
/// On a **fresh** target (no existing model) this is
/// [`setup::import::write_fresh`]. On a **re-import** it merges: generated
/// sections come from the fresh import, hand-authored fields are preserved
/// from disk, and any hand-authored conflict is said instead of being
/// overwritten.
///
/// `choice` settles hand-authored conflicts (asking `ask` for
/// [`ConflictChoice::Interactive`]); `source` names the incoming side in
/// sentences (`"project"` or `"bundle"`). `fetch` runs the product-data
/// download step for the devices' order numbers; `None` skips it. `project`
/// is the ETS export read, which `bussard.lock` pins as the devices' product
/// source until a vendor archive serves them (lock v2, issue #228).
///
/// # Errors
///
/// The model cannot be written, a question cannot be answered, or the
/// download step fails to load the index.
#[allow(clippy::too_many_arguments)] // The import's inputs, each used once; a struct would only rename them.
pub fn write_model(
    model: Model,
    dir: &Path,
    choice: ConflictChoice,
    source: &str,
    fetch: Option<&mut dyn DownloadPrompt>,
    project: Option<&Path>,
    ask: &mut dyn ConflictPrompt,
    out: &mut dyn Output,
) -> Result<ImportOutcome, SetupError> {
    if dir.is_dir() {
        super::products::prepare(dir, out);
    }
    setup::import::before_write(dir, out);

    // A re-import is any target that already holds a loadable model.
    let Some(mut ours) = load_existing_model(dir) else {
        setup::import::write_fresh(model, dir, project, fetch, out)?;
        return Ok(ImportOutcome {
            written: true,
            ..ImportOutcome::default()
        });
    };

    bussard_model::normalize_spellings(&mut ours, &model);
    let (mut to_save, merge) = bussard_model::merge(&ours, &model);
    let kept = resolve_conflicts(
        &ours,
        &model,
        &mut to_save,
        &merge,
        choice,
        source,
        ask,
        out,
    )?;

    // A group address a device file uses but the plan does not define is
    // declared in groups.toml, named after the object that uses it first.
    let declared = bussard_model::declare_used_groups(&mut to_save);

    // An import that changes nothing leaves the files alone, so hand-written
    // comments and formatting survive a no-op re-import.
    if ours == to_save {
        out.say(&format!(
            "{} already matches the import; no file written",
            dir.display()
        ));
        report_changes(&ours, &to_save, out);
        setup::import::after_write(dir, &to_save, project, fetch, out)?;
        return Ok(outcome(false, &merge, kept, choice, out));
    }

    // An import writes the files a fresh import would, in the same order,
    // even over a model an older writer laid out differently (issue #235).
    let report = to_save
        .save_pruning_as_import(dir)
        .map_err(SetupError::source)?;
    out.say(&format!(
        "imported {} group addresses, {} devices, {} link entries → {}",
        to_save.groups.groups.len(),
        to_save.devices.len(),
        to_save.links.links.values().map(Vec::len).sum::<usize>(),
        setup::skeleton::describe_dir(dir)
    ));
    for d in &declared {
        out.say(&d.sentence());
    }
    setup::import::knxnet_summary(&to_save, out);
    if !report.renamed.is_empty() {
        out.say(&format!("renamed {} device file(s)", report.renamed.len()));
    }
    if !report.pruned.is_empty() {
        out.say(&format!(
            "pruned {} stale device file(s)",
            report.pruned.len()
        ));
    }

    setup::import::after_write(dir, &to_save, project, fetch, out)?;
    // W042 (issue #348): a group address the model ran plain that the
    // project secures again needs an apply on the devices it names.
    setup::import::warn_diagnostics(&bussard_model::resecured_by_import(&ours, &to_save), out);
    report_changes(&ours, &to_save, out);
    Ok(outcome(true, &merge, kept, choice, out))
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

/// Says the re-import merge outcome and returns it.
fn outcome(
    written: bool,
    report: &MergeReport,
    kept: usize,
    choice: ConflictChoice,
    out: &mut dyn Output,
) -> ImportOutcome {
    if report.groups_added + report.devices_added > 0 {
        out.say(&format!(
            "re-import: added {} new device(s), {} new group address(es)",
            report.devices_added, report.groups_added
        ));
    }
    if report.groups_removed + report.devices_removed > 0 {
        out.say(&format!(
            "re-import: {} device(s) and {} group address(es) left the project",
            report.devices_removed, report.groups_removed
        ));
    }

    // Informational notes: generated identity that moved with the project
    // (application_ref / mask), channels that left, dangling channel references
    // dropped. Not conflicts: nothing hand-authored was overridden.
    for note in &report.notes {
        out.say(&format!("re-import: note: {note}"));
    }

    if !report.has_conflicts() {
        out.say("re-import: generated sections refreshed; no hand-edited conflicts.");
    }
    ImportOutcome {
        written,
        merged: true,
        conflicts: report.conflicts.len(),
        kept,
        unresolved: report.has_conflicts() && choice == ConflictChoice::Report && kept > 0,
    }
}

/// Says every conflict as a sentence and applies `choice` to `merged`.
/// Returns how many conflicts still hold the local value.
///
/// # Errors
///
/// [`ConflictChoice::Interactive`] without anyone to ask, or a failure to
/// read an answer.
#[allow(clippy::too_many_arguments)] // Both models, the merge and how to settle it; a struct would only rename them.
pub fn resolve_conflicts(
    ours: &Model,
    theirs: &Model,
    merged: &mut Model,
    report: &MergeReport,
    choice: ConflictChoice,
    source: &str,
    ask: &mut dyn ConflictPrompt,
    out: &mut dyn Output,
) -> Result<usize, SetupError> {
    if report.conflicts.is_empty() {
        return Ok(0);
    }
    if choice == ConflictChoice::Interactive && !ask.can_ask() {
        return Err(SetupError::Message(
            "--interactive needs a terminal; use --mine or --theirs to settle all conflicts"
                .to_string(),
        ));
    }
    out.say(&format!(
        "\n{} hand-edited field(s) differ from the {source}:",
        report.conflicts.len()
    ));
    let mut kept = 0;
    for conflict in &report.conflicts {
        let sentence = conflict_sentence(conflict, ours, source);
        let take = match choice {
            ConflictChoice::Report | ConflictChoice::Mine => false,
            ConflictChoice::Theirs => true,
            ConflictChoice::Interactive => ask.take_theirs(&sentence)?,
        };
        let applied = take && take_theirs(merged, theirs, conflict);
        let outcome = if applied {
            format!("Took the {source}'s value.")
        } else {
            kept += 1;
            "Kept this model's value.".to_string()
        };
        if choice == ConflictChoice::Interactive {
            out.say(&format!("    {outcome}"));
        } else {
            out.say(&format!("  {sentence} {outcome}"));
        }
    }
    Ok(kept)
}

/// Says what the import changes in the local model, as sentences.
pub fn report_changes(ours: &Model, merged: &Model, out: &mut dyn Output) {
    let changes = describe(ours, merged);
    if changes.is_empty() {
        out.say("\nThe import changes nothing in your project.");
        return;
    }
    out.say(&format!("\nThe import changes {} thing(s):", changes.len()));
    for line in render_text(&changes).lines() {
        out.say(&format!("  {line}"));
    }
}
