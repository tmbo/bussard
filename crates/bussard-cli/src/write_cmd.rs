//! The `bussard write <ga> <value>` subcommand: encode a human value and send a
//! `GroupValueWrite` on the bus.
//!
//! The write policy (protected-GA check, DPT resolution, encoding, the single
//! send) lives in [`bussard_service::write`], shared with the MCP server and
//! the viz server (issue #86). This module only parses the flags, asks for
//! confirmation and renders the outcome or the [`WriteRefusal`] in CLI words.
//! The exit code is honest: a send receipt failure (ACK exhaustion, staleness)
//! exits non-zero (review A3).
//!
//! Safety: a GA marked `protected: true` in `groups.yaml` is refused unless
//! `--force` is given (see the design document §8), and the service is opened
//! under the non-loopback write gate (issue #74).

use std::path::Path;
use std::process::ExitCode;

use anyhow::anyhow;
use bussard_bus::BusError;
use bussard_model::{GroupAddress, Model};
use bussard_service::{
    DptOverridePolicy, PreparedWrite, WriteCheck, WritePolicy, WriteRefusal, WriteValue,
    prepare_group_write,
};

use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, gateway_display, load_model_required, open_service,
    resolve_config,
};

/// Sends a `GroupValueWrite` to the bus.
///
/// Resolves the DPT (`--dpt` wins, else the GA's DPT from the model), refuses
/// protected GAs without `--force`, encodes the human value, transmits, and
/// confirms. Returns a failure exit code on parse/encode/connect/send errors.
///
/// The argument list mirrors the `write` subcommand's flags 1:1; bundling them
/// would only obscure that mapping, so the clippy arity lint is allowed here.
#[allow(clippy::too_many_arguments)]
pub fn run(
    ga_str: &str,
    value: &str,
    dpt_override: Option<&str>,
    force: bool,
    yes: bool,
    allow_remote_gateway: bool,
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

    // Every check short of sending: protected (unless --force), the DPT
    // (--dpt wins, else groups.yaml), parse and encode.
    let check = WriteCheck {
        dpt: dpt_override,
        dpt_policy: DptOverridePolicy::Trust,
        force,
    };
    let write = prepare_group_write(model.as_ref(), ga, WriteValue::Human(value), &check)
        .map_err(render_refusal)?;

    let config = resolve_config(model.as_ref(), &overrides)?;
    let gateway = gateway_display(&config);

    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in, and always name the resolved gateway
    // on stderr before acting so a scripted write cannot hit the real house
    // silently. The service applies the same gate again when it opens.
    enforce_write_gate(&config, allow_remote_gateway)?;
    eprintln!("gateway: {gateway}");

    // Confirmation naming the GA, value, and gateway. `--yes` skips the prompt.
    let label = write_label(&write);
    let confirmed = crate::confirm::confirm(yes, &format!("write {label} via {gateway}?"), || {
        format!(
            "refusing to write {label} via {gateway} without a terminal to confirm on; pass \
             --yes to write non-interactively"
        )
    })?;
    if !confirmed {
        eprintln!("aborted; nothing was written.");
        return Ok(ExitCode::FAILURE);
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        let service = open_service(config, WritePolicy::transmit(allow_remote_gateway)).await?;
        let result = service.send_prepared(write).await;
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        service.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(sent) => {
            // Confirmation line, e.g.
            // `3/0/4 Living Room Blind Move ← Down (1.008)`.
            println!("{}", write_label(&sent.write));
            if !sent.confirmed {
                // Not an error: KNX group writes are fire-and-forget. Note the
                // missing confirmation on stderr so scripts still see success.
                eprintln!("note: sent (no bus confirmation observed)");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(WriteRefusal::Bus(BusError::Stale)) => {
            eprintln!(
                "error: could not write {ga}: bus not connected (dropped after staleness cutoff)"
            );
            Ok(ExitCode::FAILURE)
        }
        Err(WriteRefusal::Bus(err)) => {
            eprintln!("error: could not write {ga}: {err}");
            Ok(ExitCode::FAILURE)
        }
        Err(refusal) => Err(render_refusal(refusal)),
    }
}

/// `3/0/4 Living Room Blind Move ← Down (1.008)`: the GA (with its model name
/// when known), the value and the DPT, as the prompt and the result line show
/// them.
fn write_label(write: &PreparedWrite) -> String {
    let ga = match &write.name {
        Some(name) => format!("{} {name}", write.ga),
        None => write.ga.to_string(),
    };
    let value = write.value.as_deref().unwrap_or("?");
    match write.dpt {
        Some(dpt) => format!("{ga} ← {value} ({dpt})"),
        None => format!("{ga} ← {value}"),
    }
}

/// Renders a [`WriteRefusal`] in the CLI's words (naming `--force` and
/// `--dpt`).
fn render_refusal(refusal: WriteRefusal) -> anyhow::Error {
    match refusal {
        WriteRefusal::Protected { ga, name } => {
            anyhow!("refusing to write to protected GA {ga} ({name:?}); pass --force to override")
        }
        WriteRefusal::InvalidDpt { input, reason } => anyhow!("invalid --dpt {input:?}: {reason}"),
        WriteRefusal::NoDpt {
            ga,
            model_loaded: false,
        } => anyhow!(
            "no model loaded and no --dpt given for {ga}; pass --dpt <dpt> (e.g. --dpt 1.001)"
        ),
        WriteRefusal::NoDpt {
            ga,
            model_loaded: true,
        } => anyhow!("GA {ga} has no DPT in groups.yaml; pass --dpt <dpt> (e.g. --dpt 1.001)"),
        WriteRefusal::InvalidValue {
            ga, value, reason, ..
        } => anyhow!(reason).context(format!("parsing value {value:?} for GA {ga}")),
        WriteRefusal::Encode {
            ga,
            value,
            dpt,
            reason,
        } => anyhow!(reason).context(format!("encoding {value} as DPT {dpt} for GA {ga}")),
        other => anyhow!(other),
    }
}

/// Returns a refusal message if `ga` is protected in the model and `force` is
/// not set; otherwise `None` (the write may proceed).
///
/// `bussard test` warns with the same words as `bussard write` before its
/// acceptance runs; the decision itself is [`bussard_service::protected_group`].
pub(crate) fn protected_refusal(
    model: Option<&Model>,
    ga: GroupAddress,
    force: bool,
) -> Option<String> {
    if force {
        return None;
    }
    let name = bussard_service::protected_group(model?, ga)?;
    Some(format!(
        "refusing to write to protected GA {ga} ({name:?}); pass --force to override"
    ))
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
                name: "Living Room Blind Move".to_string(),
                dpt: dpt.map(|d| d.parse().unwrap()),
                description: None,
                protected,
                secure: false,
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
        assert!(msg.contains("Living Room Blind"));
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

    /// The rendered refusal of a write that must be refused.
    fn refusal(model: Option<&Model>, value: &str) -> anyhow::Result<String> {
        match prepare_group_write(
            model,
            ga("3/0/4"),
            WriteValue::Human(value),
            &WriteCheck::default(),
        ) {
            Ok(write) => Err(anyhow!("expected a refusal, got {write:?}")),
            Err(refusal) => Ok(render_refusal(refusal).to_string()),
        }
    }

    #[test]
    fn dpt_missing_errors_with_suggestion() -> anyhow::Result<()> {
        let m = model_with(false, None);
        let err = refusal(Some(&m), "on")?;
        assert!(err.contains("--dpt"), "got {err}");
        // No model at all also errors and suggests --dpt.
        let err = refusal(None, "on")?;
        assert!(
            err.contains("no model loaded") && err.contains("--dpt"),
            "got {err}"
        );
        Ok(())
    }

    #[test]
    fn protected_refusal_is_rendered_with_the_force_hint() -> anyhow::Result<()> {
        let m = model_with(true, Some("1.008"));
        let err = refusal(Some(&m), "down")?;
        assert!(
            err.contains("protected") && err.contains("--force"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn write_label_names_ga_value_and_dpt() -> anyhow::Result<()> {
        let m = model_with(false, Some("1.008"));
        let write = prepare_group_write(
            Some(&m),
            ga("3/0/4"),
            WriteValue::Human("down"),
            &WriteCheck::default(),
        )?;
        assert_eq!(
            write_label(&write),
            "3/0/4 Living Room Blind Move ← Down (1.008)"
        );
        Ok(())
    }
}
