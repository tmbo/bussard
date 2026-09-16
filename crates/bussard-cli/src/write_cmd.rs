//! The `bussard write <ga> <value>` subcommand: encode a human value and send a
//! `GroupValueWrite` on the bus.
//!
//! Runs over the [`bussard_bus`] actor: it opens a [`Bus`], calls the shared
//! [`ops::write_group`] (which sends completion-tracked against the gateway ACK
//! and watches for a confirmation), then reports what it wrote. The write's exit
//! code is now honest — a send receipt failure (ACK exhaustion, staleness) exits
//! non-zero (review A3).
//!
//! Safety: a GA marked `protected: true` in `groups.yaml` is refused unless
//! `--force` is given (see the design document §8). That policy stays at this
//! edge; `ops` transmits whatever it is handed.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_bus::ops::{self, WriteOptions};
use bussard_bus::{Bus, BusError};
use bussard_model::{Dpt, GroupAddress, Model, encode, parse_value};

use crate::conn_cmd::{ConnOverrides, load_model_required, resolve_config};

/// Sends a `GroupValueWrite` to the bus.
///
/// Resolves the DPT (`--dpt` wins, else the GA's DPT from the model), refuses
/// protected GAs without `--force`, encodes the human value, transmits, and
/// confirms. Returns a failure exit code on parse/encode/connect/send errors.
pub fn run(
    ga_str: &str,
    value: &str,
    dpt_override: Option<&str>,
    force: bool,
    dir: &Path,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let ga: GroupAddress = ga_str
        .parse()
        .map_err(|_| anyhow!("invalid group address {ga_str:?}"))?;

    // A write is a management command: a model that is present but fails to
    // parse is a hard error (never fail the protected-GA gate open). An absent
    // model directory is a fresh project — proceed unmodeled with `--dpt`.
    let model = load_model_required(dir)?;

    // Resolve the DPT: --dpt wins, else the GA's dpt from groups.yaml.
    let dpt = resolve_dpt(dpt_override, model.as_ref(), ga)?;

    // Refuse a protected GA unless --force.
    if let Some(reason) = protected_refusal(model.as_ref(), ga, force) {
        bail!("{reason}");
    }

    // Parse the human value and encode it against the DPT.
    let typed =
        parse_value(&dpt, value).with_context(|| format!("parsing value {value:?} for GA {ga}"))?;
    let payload = encode(&dpt, &typed)
        .with_context(|| format!("encoding {typed} as DPT {dpt} for GA {ga}"))?;

    // A friendly name for the confirmation line, if the model knows it.
    let ga_name = model
        .as_ref()
        .and_then(|m| m.groups.groups.get(&ga))
        .map(|g| g.name.clone());

    let config = resolve_config(model.as_ref(), &overrides)?;

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let result =
            ops::write_group(&handle, ga, &payload, dpt.is_packable(), WriteOptions::default())
                .await;
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        let _ = handle.close().await;
        result
    });

    let value_display = typed.to_string();
    match outcome {
        Ok(write) => {
            // Confirmation line, e.g.
            // `3/0/4 Jalousie Wohnen Süd — Auf/Ab ← Down (1.008)`.
            match &ga_name {
                Some(name) => println!("{ga} {name} ← {value_display} ({dpt})"),
                None => println!("{ga} ← {value_display} ({dpt})"),
            }
            if !write.confirmed {
                // Not an error: KNX group writes are fire-and-forget. Note the
                // missing confirmation on stderr so scripts still see success.
                eprintln!("note: sent (no bus confirmation observed)");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(BusError::Stale) => {
            eprintln!(
                "error: could not write {ga}: bus not connected (dropped after staleness cutoff)"
            );
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("error: could not write {ga}: {err}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Returns a refusal message if `ga` is protected in the model and `force` is
/// not set; otherwise `None` (the write may proceed).
fn protected_refusal(model: Option<&Model>, ga: GroupAddress, force: bool) -> Option<String> {
    if force {
        return None;
    }
    let group = model?.groups.groups.get(&ga)?;
    if group.protected {
        Some(format!(
            "refusing to write to protected GA {ga} ({:?}); pass --force to override",
            group.name
        ))
    } else {
        None
    }
}

/// Resolves the DPT to encode against: `--dpt` wins, else the GA's DPT from the
/// model. Errors (suggesting `--dpt`) when neither is available.
fn resolve_dpt(
    dpt_override: Option<&str>,
    model: Option<&Model>,
    ga: GroupAddress,
) -> anyhow::Result<Dpt> {
    if let Some(s) = dpt_override {
        return s.parse().map_err(|e| anyhow!("invalid --dpt {s:?}: {e}"));
    }
    let group = model.and_then(|m| m.groups.groups.get(&ga));
    match group.and_then(|g| g.dpt) {
        Some(dpt) => Ok(dpt),
        None => {
            if model.is_none() {
                bail!(
                    "no model loaded and no --dpt given for {ga}; pass --dpt <dpt> (e.g. --dpt 1.001)"
                );
            }
            bail!("GA {ga} has no DPT in groups.yaml; pass --dpt <dpt> (e.g. --dpt 1.001)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    fn model_with(protected: bool, dpt: Option<&str>) -> Model {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/0/4"),
            Group {
                name: "Jalousie Wohnen Süd — Auf/Ab".to_string(),
                dpt: dpt.map(|d| d.parse().unwrap()),
                description: None,
                protected,
            },
        );
        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        }
    }

    #[test]
    fn protected_ga_refused_without_force() {
        let m = model_with(true, Some("1.008"));
        let msg = protected_refusal(Some(&m), ga("3/0/4"), false).expect("must refuse");
        assert!(msg.contains("protected"));
        assert!(msg.contains("--force"));
        assert!(msg.contains("Jalousie"));
    }

    #[test]
    fn protected_ga_allowed_with_force() {
        let m = model_with(true, Some("1.008"));
        assert!(protected_refusal(Some(&m), ga("3/0/4"), true).is_none());
    }

    #[test]
    fn unprotected_ga_not_refused() {
        let m = model_with(false, Some("1.008"));
        assert!(protected_refusal(Some(&m), ga("3/0/4"), false).is_none());
    }

    #[test]
    fn dpt_override_wins() {
        let m = model_with(false, Some("1.008"));
        let d = resolve_dpt(Some("5.001"), Some(&m), ga("3/0/4")).unwrap();
        assert_eq!(d.to_string(), "5.001");
    }

    #[test]
    fn dpt_from_model_when_no_override() {
        let m = model_with(false, Some("1.008"));
        let d = resolve_dpt(None, Some(&m), ga("3/0/4")).unwrap();
        assert_eq!(d.to_string(), "1.008");
    }

    #[test]
    fn dpt_missing_errors_with_suggestion() {
        let m = model_with(false, None);
        let err = resolve_dpt(None, Some(&m), ga("3/0/4")).unwrap_err();
        assert!(err.to_string().contains("--dpt"), "got {err}");
        // No model at all also errors and suggests --dpt.
        let err = resolve_dpt(None, None, ga("3/0/4")).unwrap_err();
        assert!(err.to_string().contains("--dpt"), "got {err}");
    }
}
