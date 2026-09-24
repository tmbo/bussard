//! The `status`, `history`, `show` and `undo` subcommands (issues #110, #112).
//!
//! These four read and write `<dir>/.bussard/history`, never the bus. They are
//! the owner-facing half of the model: what changed, when, why, and how to put
//! it back without knowing git.
//!
//! The module also holds the two hooks every model- or bus-writing command
//! calls: [`capture_external_edit`] at the start (so an edit made in an editor
//! or by an assistant writing YAML is never lost) and [`snapshot`] right before
//! it writes. Both are best-effort: a history that cannot be written warns on
//! stderr and never fails the command the user actually asked for.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::change::{ChangeSet, describe, render_text};
use bussard_model::history::{History, Pending, Snapshot, SnapshotId, SnapshotReason};
use bussard_model::{Model, schema};

/// The model files a raw diff compares, in the order it prints them.
const TOP_LEVEL_FILES: [&str; 3] = ["bussard.yaml", "groups.yaml", "links.yaml"];

/// Records a snapshot of `dir` before a command writes, warning (never failing)
/// if the history cannot be written.
///
/// Returns the new snapshot's id when one was taken.
pub fn snapshot(dir: &Path, reason: SnapshotReason) -> Option<SnapshotId> {
    let history = History::open(dir);
    // An empty or absent directory has no state worth keeping, and snapshotting
    // it would create a model directory where there was none.
    if !history.has_model_files() {
        return None;
    }
    match history.snapshot(reason) {
        Ok(id) => Some(id),
        Err(err) => {
            eprintln!("warning: could not record a history snapshot: {err}");
            None
        }
    }
}

/// Records an `external edit` snapshot when the working model differs from the
/// latest one, warning (never failing) if the history cannot be written.
pub fn capture_external_edit(dir: &Path) {
    match History::open(dir).snapshot_if_changed_externally() {
        Ok(Some(id)) => {
            eprintln!("recorded the current model as history snapshot {id} (external edit)");
        }
        Ok(None) => {}
        Err(err) => eprintln!("warning: could not record a history snapshot: {err}"),
    }
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
pub fn run_status(dir: &Path, json: bool, raw: bool) -> anyhow::Result<ExitCode> {
    let history = History::open(dir);
    let latest = history
        .latest()
        .context("reading the history in .bussard/history")?;

    let Some(latest) = latest else {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "base": serde_json::Value::Null,
                    "changes": [],
                }))?
            );
        } else {
            println!(
                "No history yet for {}. bussard records a snapshot the first time it \
                 writes the model.",
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
    let new = Model::load(dir)
        .with_context(|| format!("loading the working model from {}", dir.display()))?;
    let changes = describe(&old, &new);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&change_json(Some(&latest.id), &changes))?
        );
        return Ok(ExitCode::SUCCESS);
    }

    if changes.is_empty() {
        println!(
            "No pending changes since snapshot {} ({}).",
            latest.id, latest.manifest.created_at
        );
        return Ok(ExitCode::SUCCESS);
    }

    println!(
        "{} pending change(s) since snapshot {} ({}):\n",
        changes.len(),
        latest.id,
        latest.manifest.created_at
    );
    print!("{}", render_text(&changes));
    println!("\nNothing has reached any device yet. Run `bussard plan <ia>` to check a device,");
    println!("`bussard apply <ia>` to write it, or `bussard undo` to put the files back.");
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard history`: the snapshot list, oldest first.
pub fn run_history(dir: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let history = History::open(dir);
    let snapshots = history.list().context("reading .bussard/history")?;

    if json {
        let mut rows = Vec::new();
        for (index, snapshot) in snapshots.iter().enumerate() {
            rows.push(serde_json::json!({
                "index": index + 1,
                "id": snapshot.id,
                "created_at": snapshot.manifest.created_at,
                "command": snapshot.manifest.reason.command,
                "args": snapshot.manifest.reason.args,
                "gateway": snapshot.manifest.gateway,
                "result": snapshot.manifest.result,
                "summary": summary_of(&history, &snapshots, index),
            }));
        }
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(ExitCode::SUCCESS);
    }

    if snapshots.is_empty() {
        println!(
            "No history yet for {}. bussard records a snapshot the first time it writes the model.",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    for (index, snapshot) in snapshots.iter().enumerate() {
        println!(
            "{:>3}  {}  {}",
            index + 1,
            snapshot.id,
            reason_line(snapshot)
        );
        let summary = summary_of(&history, &snapshots, index);
        if !summary.is_empty() {
            println!("     {summary}");
        }
    }
    println!("\nShow one with `bussard show <n>`; put the model back with `bussard undo <n>`.");
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard show <id|N> [<id|N>]`: the change one snapshot introduced, or
/// the change between two snapshots.
pub fn run_show(dir: &Path, first: &str, second: Option<&str>) -> anyhow::Result<ExitCode> {
    let history = History::open(dir);
    let snapshots = history.list().context("reading .bussard/history")?;
    if snapshots.is_empty() {
        println!("No history yet for {}.", dir.display());
        return Ok(ExitCode::SUCCESS);
    }

    let (from, to) = match second {
        Some(second) => {
            let a = history.resolve(first)?;
            let b = history.resolve(second)?;
            (Some(a), b)
        }
        None => {
            let b = history.resolve(first)?;
            let index = snapshots.iter().position(|s| s.id == b.id).unwrap_or(0);
            let a = index.checked_sub(1).map(|i| snapshots[i].clone());
            (a, b)
        }
    };

    let old = match &from {
        Some(snapshot) => history.load(&snapshot.id)?,
        None => empty_model(),
    };
    let new = history.load(&to.id)?;
    let changes = describe(&old, &new);

    match &from {
        Some(snapshot) => println!("Change from snapshot {} to {}:\n", snapshot.id, to.id),
        None => println!("Snapshot {} (the first one):\n", to.id),
    }
    println!("  {}\n", reason_line(&to));
    if changes.is_empty() {
        println!("The model files are identical.");
    } else {
        print!("{}", render_text(&changes));
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard undo [<id|N>]`: restores the model files to a snapshot
/// (default: the newest one that differs from the working files, which reverts
/// the last change).
///
/// Files only. Devices keep their tables until a human runs `plan` and `apply`.
pub fn run_undo(dir: &Path, target: Option<&str>) -> anyhow::Result<ExitCode> {
    let history = History::open(dir);
    let snapshots = history.list().context("reading .bussard/history")?;
    if snapshots.is_empty() {
        println!(
            "No history yet for {}, so there is nothing to undo.",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let target = match target {
        Some(spec) => history.resolve(spec)?,
        None => match history.undo_target()? {
            Some(snapshot) => snapshot,
            None => {
                println!(
                    "The model files already match every snapshot, so there is nothing to undo."
                );
                println!(
                    "`bussard undo <n>` restores a specific one; `bussard history` lists them."
                );
                return Ok(ExitCode::SUCCESS);
            }
        },
    };

    // What the restore reverts, in the owner's words: the working model as it is
    // now, against the snapshot we are about to put back.
    let working = Model::load(dir).ok();
    let restored = history.load(&target.id)?;
    let changes = working
        .as_ref()
        .map(|w| describe(w, &restored))
        .unwrap_or_default();

    let undo_snapshot = history.restore(&target.id)?;
    println!(
        "Restored the model files to snapshot {} ({}).",
        target.id, target.manifest.created_at
    );
    println!("The state before this undo is kept as snapshot {undo_snapshot}.\n");
    if changes.is_empty() {
        println!("The files were already identical to that snapshot.");
    } else {
        print!("{}", render_text(&changes));
    }
    println!();
    print_apply_hint(&changes);
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

/// The JSON body shared by `status --json` and the MCP change tool.
fn change_json(base: Option<&SnapshotId>, changes: &ChangeSet) -> serde_json::Value {
    serde_json::json!({
        "base": base.map(|id| id.to_string()),
        "changes": changes.changes,
    })
}

/// `apply 1.1.4 → 127.0.0.1:3671 (before writing the device tables)`.
fn reason_line(snapshot: &Snapshot) -> String {
    let manifest = &snapshot.manifest;
    let mut line = manifest.reason.command.clone();
    if !manifest.reason.args.is_empty() {
        line.push(' ');
        line.push_str(&manifest.reason.args.join(" "));
    }
    if let Some(gateway) = &manifest.gateway {
        line.push_str(&format!(" → {gateway}"));
    }
    if !manifest.result.is_empty() {
        line.push_str(&format!(" ({})", manifest.result));
    }
    line
}

/// The one-line plain-language summary of what a snapshot changed, compared
/// with the snapshot before it. Empty when it cannot be computed.
fn summary_of(history: &History, snapshots: &[Snapshot], index: usize) -> String {
    let Ok(new) = history.load(&snapshots[index].id) else {
        return String::new();
    };
    let old = match index.checked_sub(1) {
        Some(previous) => match history.load(&snapshots[previous].id) {
            Ok(model) => model,
            Err(_) => return String::new(),
        },
        None => return "the first snapshot of the model".to_string(),
    };
    describe(&old, &new).summary()
}

/// An empty model, used as the "before" of the very first snapshot.
fn empty_model() -> Model {
    Model {
        config: schema::BussardConfig::default(),
        groups: schema::Groups::default(),
        links: schema::Links::default(),
        devices: std::collections::BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// `--raw`: the file-level diff, for the people who do read YAML.
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
                    && (name.ends_with(".yaml") || name.ends_with(".yml"))
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
