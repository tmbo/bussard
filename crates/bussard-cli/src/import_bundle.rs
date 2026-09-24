//! `bussard import <file.bussard>` and conflict resolution for every import
//! (issue #111).
//!
//! A bundle into a directory without a model is extracted byte for byte,
//! history included. A bundle into an existing model runs the same merge as a
//! `.knxproj` re-import: generated data follows the bundle, hand-authored
//! fields stay local, and every disagreement is printed as a sentence.
//! `--mine`, `--theirs` and `--interactive` settle those disagreements.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::bundle::Bundle;
use bussard_model::change::{describe, render_text};
use bussard_model::reconcile::{conflict_sentence, take_theirs};
use bussard_model::{MergeReport, Model};

/// How an import settles hand-authored conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// Keep the local values and exit 3 so a human reconciles them (default).
    Report,
    /// Keep the local value for every conflict and exit 0 (`--mine`).
    Mine,
    /// Take the incoming value for every conflict (`--theirs`).
    Theirs,
    /// Ask per conflict on the terminal (`--interactive`).
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

/// Runs `bussard import <file.bussard>`.
pub fn run_bundle(path: &Path, dir: &Path, choice: ConflictChoice) -> anyhow::Result<ExitCode> {
    let bundle =
        Bundle::read(path).with_context(|| format!("reading bundle {}", path.display()))?;
    let m = &bundle.manifest;
    println!(
        "bundle {}: exported {} by bussard {}, {} device(s), {} group address(es), {} history \
         snapshot(s)",
        path.display(),
        m.exported_at,
        m.bussard_version,
        m.devices,
        m.group_addresses,
        m.history_snapshots
    );

    if !has_model(dir) {
        bundle
            .extract(dir, true)
            .with_context(|| format!("extracting into {}", dir.display()))?;
        println!(
            "imported the bundle into {} (model and history)",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let model = bundle.model()?;
    if m.history_snapshots > 0 {
        println!(
            "note: {} keeps its own history; the bundle's snapshots were not merged into it",
            dir.display()
        );
    }
    crate::import_cmd::write_model(model, dir, choice, "bundle")
}

/// Whether `dir` already holds a model to merge into (a `groups.toml` or a
/// device file; a lone `bussard.toml` from `bussard init` does not count).
fn has_model(dir: &Path) -> bool {
    dir.join("groups.toml").exists()
        || std::fs::read_dir(dir.join("devices"))
            .map(|rd| {
                rd.flatten().any(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.ends_with(".yaml") || name.ends_with(".yml")
                })
            })
            .unwrap_or(false)
}

/// Prints every conflict as a sentence and applies `choice` to `merged`.
/// Returns how many conflicts still hold the local value.
pub fn resolve_conflicts(
    ours: &Model,
    theirs: &Model,
    merged: &mut Model,
    report: &MergeReport,
    choice: ConflictChoice,
    source: &str,
) -> anyhow::Result<usize> {
    if report.conflicts.is_empty() {
        return Ok(0);
    }
    if choice == ConflictChoice::Interactive && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "--interactive needs a terminal; use --mine or --theirs to settle all conflicts"
        );
    }
    println!(
        "\n{} hand-edited field(s) differ from the {source}:",
        report.conflicts.len()
    );
    let mut kept = 0;
    let stdin = std::io::stdin();
    for conflict in &report.conflicts {
        let sentence = conflict_sentence(conflict, ours, source);
        let take = match choice {
            ConflictChoice::Report | ConflictChoice::Mine => false,
            ConflictChoice::Theirs => true,
            ConflictChoice::Interactive => {
                print!("  {sentence}\n    keep [m]ine or take [t]heirs? [m] ");
                std::io::stdout().flush()?;
                let mut line = String::new();
                stdin.lock().read_line(&mut line)?;
                matches!(line.trim(), "t" | "T" | "theirs")
            }
        };
        let applied = take && take_theirs(merged, theirs, conflict);
        let outcome = if applied {
            format!("Took the {source}'s value.")
        } else {
            kept += 1;
            "Kept this model's value.".to_string()
        };
        if choice == ConflictChoice::Interactive {
            println!("    {outcome}");
        } else {
            println!("  {sentence} {outcome}");
        }
    }
    Ok(kept)
}

/// Prints what the import changes in the local model, as sentences.
pub fn print_changes(ours: &Model, merged: &Model) {
    let changes = describe(ours, merged);
    if changes.is_empty() {
        println!("\nThe import changes nothing in the model.");
        return;
    }
    println!("\nThe import changes {} thing(s):", changes.len());
    for line in render_text(&changes).lines() {
        println!("  {line}");
    }
}
