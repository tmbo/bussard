//! The `status`, `history`, `show` and `undo` subcommands (issues #110, #112).
//!
//! These four read and write `<dir>/.bussard/history`, never the bus. They are
//! the owner-facing half of the model: what changed, when, why, and how to put
//! it back without knowing git.
//!
//! The module also holds the two hooks every model- or bus-writing command
//! calls: [`capture_external_edit`] at the start (so an edit made in an editor
//! or by an assistant writing TOML is never lost) and [`snapshot`] right before
//! it writes. Both are best-effort: a history that cannot be written warns on
//! stderr and never fails the command the user actually asked for.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::Model;
use bussard_model::change::{ChangeSet, describe, render_text};
use bussard_model::history::{History, Pending, Snapshot, SnapshotId, SnapshotReason};

use bussard_service::history::{HistoryFlowError, UndoOutcome};
use bussard_service::model_edit::{ChangeReport, HistoryReport, UndoReport};

use crate::cli::{Resolved, Run, Spec};

/// `bussard history`.
#[derive(Debug, clap::Args)]
pub(crate) struct HistoryArgs {}

impl Run for HistoryArgs {
    fn spec(&self) -> Spec {
        Spec::FILES.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run_history(g.dir(), g.json)
    }
}

/// `bussard show`.
#[derive(Debug, clap::Args)]
pub(crate) struct ShowArgs {
    /// The snapshot: its id, or its number from `bussard history`.
    #[arg(value_name = "SNAPSHOT")]
    snapshot: String,
    /// A second snapshot: show the change from the first one to this one.
    #[arg(value_name = "SNAPSHOT")]
    to: Option<String>,
}

impl Run for ShowArgs {
    fn spec(&self) -> Spec {
        Spec::FILES.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run_show(g.dir(), &self.snapshot, self.to.as_deref(), g.json)
    }
}

/// `bussard undo`.
#[derive(Debug, clap::Args)]
pub(crate) struct UndoArgs {
    /// The snapshot to restore: its id, or its number from `bussard history`
    /// (default: the newest one that differs from the working files, which
    /// reverts the last change).
    #[arg(value_name = "SNAPSHOT")]
    snapshot: Option<String>,
}

impl Run for UndoArgs {
    fn spec(&self) -> Spec {
        Spec::FILES.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run_undo(g.dir(), self.snapshot.as_deref(), g.json)
    }
}

/// The model files a raw diff compares, in the order it prints them.
const TOP_LEVEL_FILES: [&str; 5] = bussard_model::loader::MODEL_FILES;

/// Records a snapshot of `dir` before a command writes, warning (never failing)
/// if the history cannot be written.
///
/// Returns the new snapshot's id when one was taken.
pub fn snapshot(dir: &Path, reason: SnapshotReason) -> Option<SnapshotId> {
    bussard_service::setup::import::snapshot(dir, reason, &mut crate::console::Console)
}

/// Records an `external edit` snapshot when the working model differs from the
/// latest one, warning (never failing) if the history cannot be written.
pub fn capture_external_edit(dir: &Path) {
    bussard_service::setup::import::capture_external_edit(dir, &mut crate::console::Console);
}

/// The pending change of the working model against the latest snapshot, or
/// `None` when the history is empty or unreadable. Used by `plan` to print the
/// rendering above its table diff.
pub fn pending_changes(dir: &Path) -> Option<Pending> {
    match History::open(dir).pending() {
        Ok(pending) if pending.base.is_some() && !pending.changes.is_empty() => Some(pending),
        _ => None,
    }
}

/// Runs `bussard status`: what has changed since the last snapshot.
///
/// Always exits 0 — "nothing pending" is an answer, not a failure.
pub(crate) fn run_status(dir: &Path, json: bool, raw: bool) -> anyhow::Result<ExitCode> {
    let history = History::open(dir);
    let latest = history
        .latest()
        .context("reading the history in .bussard/history")?;

    let Some(latest) = latest else {
        if json {
            crate::output::report(&ChangeReport::no_history())?;
        } else {
            println!(
                "No history yet for {}. bussard records a snapshot the first time it \
                 writes your project.",
                dir.display()
            );
        }
        return Ok(ExitCode::SUCCESS);
    };

    if raw && !json {
        print_raw_diff(&history, &latest)?;
        return Ok(ExitCode::SUCCESS);
    }

    let old = history.load(&latest.id)?;
    let new =
        Model::load(dir).with_context(|| format!("loading the project from {}", dir.display()))?;
    let changes = describe(&old, &new);

    if json {
        crate::output::report(&ChangeReport::new(
            Some(latest.id.to_string()),
            &changes,
            None,
        ))?;
        return Ok(ExitCode::SUCCESS);
    }

    if changes.is_empty() {
        println!(
            "No pending changes since snapshot {} ({}).",
            latest.id, latest.manifest.created_at
        );
        return Ok(ExitCode::SUCCESS);
    }

    let style = crate::style::Style::stdout();
    println!(
        "{} {}\n",
        style.bold(&crate::style::count(
            changes.len(),
            "pending change",
            "pending changes"
        )),
        style.dim(&format!(
            "since snapshot {} ({})",
            latest.id, latest.manifest.created_at
        ))
    );
    print!("{}", render_text(&changes));
    println!("\n{}\n", style.warn("Nothing has reached any device yet."));
    print!(
        "{}",
        style.next_steps(&[
            (
                "bussard plan <ADDRESS>",
                "shows what writing a device would change"
            ),
            ("bussard apply <ADDRESS>", "writes it to the device"),
            (
                "bussard undo",
                "puts the files back as they were at the snapshot"
            ),
        ])
    );
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard history`: the snapshot list, oldest first.
fn run_history(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let rows = bussard_service::history::list(dir, None).map_err(history_error)?;
    if json {
        crate::output::report(&HistoryReport::new(rows))?;
        return Ok(ExitCode::SUCCESS);
    }

    if rows.is_empty() {
        println!(
            "No history yet for {}. bussard records a snapshot the first time it writes your project.",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    for row in &rows {
        println!(
            "{:>3}  {}  {}",
            row.index,
            row.id,
            reason_text(&row.command, &row.args, row.gateway.as_deref(), &row.result)
        );
        if !row.summary.is_empty() {
            println!("     {}", row.summary);
        }
    }
    println!("\nShow one with `bussard show <n>`; put your project back with `bussard undo <n>`.");
    Ok(ExitCode::SUCCESS)
}

/// A history error in the words the CLI always printed: the list read with
/// its context, everything else as the history reported it.
fn history_error(err: HistoryFlowError) -> anyhow::Error {
    match err {
        HistoryFlowError::List(err) => anyhow::Error::from(err).context("reading .bussard/history"),
        HistoryFlowError::Target(err)
        | HistoryFlowError::Resolve(err)
        | HistoryFlowError::Restore(err)
        | HistoryFlowError::Load { source: err, .. } => err.into(),
    }
}

/// Runs `bussard show <id|N> [<id|N>]`: the change one snapshot introduced, or
/// the change between two snapshots.
fn run_show(dir: &Path, first: &str, second: Option<&str>, json: bool) -> anyhow::Result<ExitCode> {
    let Some(shown) = bussard_service::history::show(dir, first, second).map_err(history_error)?
    else {
        if json {
            crate::output::report(&ChangeReport::no_history())?;
        } else {
            println!("No history yet for {}.", dir.display());
        }
        return Ok(ExitCode::SUCCESS);
    };
    let (from, to, changes) = (&shown.from, &shown.to, &shown.changes);
    if json {
        crate::output::report(&ChangeReport {
            from: from.as_ref().map(|s| s.id.to_string()),
            to: Some(to.id.to_string()),
            reason: Some(reason_line(to)),
            ..ChangeReport::new(None, changes, None)
        })?;
        return Ok(ExitCode::SUCCESS);
    }
    match from {
        Some(snapshot) => println!("Change from snapshot {} to {}:\n", snapshot.id, to.id),
        None => println!("Snapshot {} (the first one):\n", to.id),
    }
    println!("  {}\n", reason_line(to));
    if changes.is_empty() {
        println!("The project files are identical.");
    } else {
        print!("{}", render_text(changes));
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard undo [<id|N>]`: restores the model files to a snapshot
/// (default: the newest one that differs from the working files, which reverts
/// the last change).
///
/// Files only. Devices keep their tables until a human runs `plan` and `apply`.
fn run_undo(dir: &Path, target: Option<&str>, json: bool) -> anyhow::Result<ExitCode> {
    // What `undo --json` prints when nothing was restored.
    let nothing = |reason: &str| {
        crate::output::report(&UndoReport {
            ok: true,
            reason: Some(reason.to_string()),
            ..UndoReport::default()
        })
    };
    let undone = match bussard_service::history::undo(dir, target).map_err(history_error)? {
        UndoOutcome::Restored(undone) => undone,
        UndoOutcome::NoHistory if json => {
            nothing("no history")?;
            return Ok(ExitCode::SUCCESS);
        }
        UndoOutcome::NoHistory => {
            println!(
                "No history yet for {}, so there is nothing to undo.",
                dir.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
        UndoOutcome::NothingToUndo if json => {
            nothing("the project files already match every snapshot")?;
            return Ok(ExitCode::SUCCESS);
        }
        UndoOutcome::NothingToUndo => {
            println!(
                "The project files already match every snapshot, so there is nothing to undo."
            );
            println!("`bussard undo <n>` restores a specific one; `bussard history` lists them.");
            return Ok(ExitCode::SUCCESS);
        }
    };
    let (target, changes) = (&undone.target, &undone.changes);
    if json {
        let key_store = match &undone.key_store {
            Some(follow)
                if !follow.ok || follow.sentences.as_ref().is_some_and(|s| !s.is_empty()) =>
            {
                serde_json::to_value(follow).ok()
            }
            _ => None,
        };
        crate::output::report(&UndoReport {
            ok: true,
            restored: Some(target.id.to_string()),
            created_at: Some(target.manifest.created_at.clone()),
            undo_snapshot: Some(undone.undo_snapshot.to_string()),
            reason: None,
            changes: changes.changes.clone(),
            key_store,
        })?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(follow) = &undone.key_store {
        for note in follow.sentences.iter().flatten() {
            println!("{note}");
        }
        if let Some(reason) = &follow.reason {
            eprintln!("warning: {reason}");
        }
    }
    println!(
        "Restored the project files to snapshot {} ({}).",
        target.id, target.manifest.created_at
    );
    println!(
        "The state before this undo is kept as snapshot {}.\n",
        undone.undo_snapshot
    );
    if changes.is_empty() {
        println!("The files were already identical to that snapshot.");
    } else {
        print!("{}", render_text(changes));
    }
    println!();
    print_apply_hint(changes);
    Ok(ExitCode::SUCCESS)
}

/// Prints the "now push it to the devices" hint after an undo.
fn print_apply_hint(changes: &ChangeSet) {
    let devices: BTreeSet<&str> = changes
        .changes
        .iter()
        .filter_map(|c| c.device.as_deref())
        .collect();
    match devices.len() {
        1 => {
            let ia = devices.iter().next().copied().unwrap_or("<ia>");
            println!("Run `bussard plan {ia}` and `bussard apply {ia}` to push this to devices.");
        }
        _ => {
            println!("Run `bussard plan <ia>` and `bussard apply <ia>` to push this to devices.");
            if !devices.is_empty() {
                println!(
                    "Devices touched: {}.",
                    devices.into_iter().collect::<Vec<_>>().join(", ")
                );
            }
        }
    }
}

/// `apply 1.1.4 → 127.0.0.1:3671 (before writing the device tables)`.
fn reason_line(snapshot: &Snapshot) -> String {
    let manifest = &snapshot.manifest;
    reason_text(
        &manifest.reason.command,
        &manifest.reason.args,
        manifest.gateway.as_deref(),
        &manifest.result,
    )
}

/// The reason line of a snapshot from its parts.
fn reason_text(command: &str, args: &[String], gateway: Option<&str>, result: &str) -> String {
    let mut line = command.to_string();
    if !args.is_empty() {
        line.push(' ');
        line.push_str(&args.join(" "));
    }
    if let Some(gateway) = gateway {
        line.push_str(&format!(" → {gateway}"));
    }
    if !result.is_empty() {
        line.push_str(&format!(" ({result})"));
    }
    line
}

// ---------------------------------------------------------------------------
// `--raw`: the file-level diff, for the people who do read TOML.
// ---------------------------------------------------------------------------

/// Prints a file-level diff of the working model against a snapshot.
fn print_raw_diff(history: &History, latest: &Snapshot) -> anyhow::Result<()> {
    let snapshot_dir = history.snapshot_dir(&latest.id);
    let working = history.model_dir();

    let mut names: Vec<String> = TOP_LEVEL_FILES.iter().map(|s| s.to_string()).collect();
    let mut devices: BTreeSet<String> = BTreeSet::new();
    for dir in [snapshot_dir.join("devices"), working.join("devices")] {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && name.ends_with(".toml")
                {
                    devices.insert(format!("devices/{name}"));
                }
            }
        }
    }
    names.extend(devices);

    let mut any = false;
    for name in names {
        let old = std::fs::read_to_string(snapshot_dir.join(&name)).unwrap_or_default();
        let new = std::fs::read_to_string(working.join(&name)).unwrap_or_default();
        if old == new {
            continue;
        }
        any = true;
        println!("--- snapshot/{name}");
        println!("+++ working/{name}");
        print!("{}", unified_body(&old, &new));
    }
    if !any {
        println!("No file differences since snapshot {}.", latest.id);
    }
    Ok(())
}

/// A minimal unified-ish diff body: common head and tail are trimmed, then the
/// differing middles are printed as removals followed by additions.
///
/// This is deliberately simple. The model files are deterministic and sorted, so
/// an edit shows up as a small contiguous middle; `bussard status` without
/// `--raw` is the readable view, and `git diff` is there for anyone who wants a
/// real one.
pub(crate) fn unified_body(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut head = 0;
    while head < old_lines.len() && head < new_lines.len() && old_lines[head] == new_lines[head] {
        head += 1;
    }
    let mut tail = 0;
    while tail < old_lines.len() - head
        && tail < new_lines.len() - head
        && old_lines[old_lines.len() - 1 - tail] == new_lines[new_lines.len() - 1 - tail]
    {
        tail += 1;
    }

    let mut out = String::new();
    out.push_str(&format!("@@ line {} @@\n", head + 1));
    for line in &old_lines[head..old_lines.len() - tail] {
        out.push_str(&format!("-{line}\n"));
    }
    for line in &new_lines[head..new_lines.len() - tail] {
        out.push_str(&format!("+{line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_body_trims_common_head_and_tail() {
        let old = "a\nb\nc\n";
        let new = "a\nB\nc\n";
        assert_eq!(unified_body(old, new), "@@ line 2 @@\n-b\n+B\n");
    }

    #[test]
    fn test_unified_body_handles_a_pure_addition() {
        assert_eq!(unified_body("a\n", "a\nb\n"), "@@ line 2 @@\n+b\n");
    }

    #[test]
    fn test_unified_body_handles_an_empty_side() {
        assert_eq!(unified_body("", "a\n"), "@@ line 1 @@\n+a\n");
    }
}
