//! The `bussard export` subcommand (issue #111).
//!
//! Writes the model directory as one `.bussard` file: the model, its history
//! and a manifest with counts and a SHA-256 digest. Nothing vendor-derived,
//! local or secret goes in; see [`bussard_model::bundle`].

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::bundle::{self, ExportOptions};
use bussard_model::history::History;

/// Runs `bussard export [FILE] [--no-history] [--json]`.
///
/// Without `FILE` the bundle goes next to the model directory, named after it
/// and today's date.
pub fn run(
    file: Option<&Path>,
    dir: &Path,
    no_history: bool,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let out = file.map_or_else(|| bundle::default_bundle_path(dir), Path::to_path_buf);
    let manifest = bundle::export(
        dir,
        &out,
        ExportOptions {
            include_history: !no_history,
        },
    )
    .with_context(|| format!("exporting {}", dir.display()))?;

    if json {
        let value = serde_json::json!({ "path": out.display().to_string(), "manifest": manifest });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "exported {} device(s), {} group address(es), {} history snapshot(s) → {}",
        manifest.devices,
        manifest.group_addresses,
        manifest.history_snapshots,
        out.display()
    );
    println!("model sha256 {}", manifest.model_sha256);
    println!("never included: {}", manifest.excluded.join(", "));
    Ok(ExitCode::SUCCESS)
}

/// The one-line hint `apply` prints when the handover file is stale, or `None`.
///
/// Stale means: the last export recorded in `.bussard/last_export.json` is
/// older than the newest `apply` snapshot **and** the model files have changed
/// since that export (an apply of an unchanged model needs no new export). A
/// model that was never exported gets the hint too.
pub fn stale_export_hint(dir: &Path) -> Option<String> {
    let newest_apply = History::open(dir)
        .list()
        .ok()?
        .into_iter()
        .rev()
        .find(|s| s.manifest.reason.command == "apply")?;
    let Some(last) = bundle::last_export(dir) else {
        return Some(
            "hint: this model has never been exported; `bussard export` writes the one file \
             to hand over or keep as a backup"
                .to_string(),
        );
    };
    if last.exported_at >= newest_apply.manifest.created_at {
        return None;
    }
    if bundle::current_model_digest(dir).ok()? == last.model_sha256 {
        return None;
    }
    Some(format!(
        "hint: the last export ({}, {}) predates this apply; run `bussard export` to refresh it",
        last.path, last.exported_at
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::history::SnapshotReason;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_stale_export_hint_follows_apply_and_model_changes() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "bussard-export-hint-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?
        ));
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::write(dir.join("groups.toml"), "groups: {}\n")?;
        let history = History::open(&dir);

        // No apply yet: nothing to say.
        assert_eq!(stale_export_hint(&dir), None);

        // An apply without any export: hint.
        history.snapshot(SnapshotReason::new("apply"))?;
        assert!(stale_export_hint(&dir).is_some_and(|h| h.contains("never been exported")));

        // An export after the apply: quiet.
        bundle::export(&dir, &dir.join("house.bussard"), ExportOptions::default())?;
        assert_eq!(stale_export_hint(&dir), None);

        // A later apply of an unchanged model: still quiet. The record's second
        // resolution means the apply may share its timestamp, so backdate it.
        let record_path = dir.join(bundle::LAST_EXPORT);
        let mut record = bundle::last_export(&dir).ok_or("record")?;
        record.exported_at = "2000-01-01T00:00:00Z".to_string();
        std::fs::write(&record_path, serde_json::to_string(&record)?)?;
        history.snapshot(SnapshotReason::new("apply"))?;
        assert_eq!(stale_export_hint(&dir), None);

        // The model changed and was applied: hint.
        std::fs::write(
            dir.join("groups.toml"),
            "groups:\n  \"0/0/1\":\n    name: A\n",
        )?;
        history.snapshot(SnapshotReason::new("apply"))?;
        assert!(stale_export_hint(&dir).is_some_and(|h| h.contains("predates this apply")));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
