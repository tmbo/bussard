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
//! On a secured GA the tunnel's address is checked against the evidence that
//! the devices on the GA admit it as a secure sender
//! ([`bussard_service::admission`], issue #297) before anything is sent, and
//! the result says only what KNX confirms: the interface's L_Data.con.
//!
//! Safety: a GA marked `protected: true` in `groups.toml` is refused unless
//! `--force` is given (see the design document §8), and the service is opened
//! under the non-loopback write gate (issue #74).

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_bus::BusError;
use bussard_model::{GroupAddress, Model};
use bussard_service::admission::{self, Admission, AdmissionEvidence};
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
    keyring: Option<&Path>,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let ga: GroupAddress = ga_str
        .parse()
        .map_err(|_| anyhow!("invalid group address {ga_str:?}"))?;

    // A write is a management command: a model that is present but fails to
    // parse is a hard error (never fail the protected-GA gate open). An absent
    // model directory is a fresh project — proceed unmodeled with `--dpt`.
    let model = load_model_required(dir)?;
    // KNX Data Secure group keys (issue #172): a secured GA is sealed under its
    // group key; a secured GA without one is refused below.
    let group_keys = crate::secure_key::group_keys(keyring)?;

    // Every check short of sending: protected (unless --force), the DPT
    // (--dpt wins, else groups.toml), parse and encode.
    let check = WriteCheck {
        dpt: dpt_override,
        dpt_policy: DptOverridePolicy::Trust,
        force,
        group_keys: group_keys.as_ref(),
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
    if write.is_secured() {
        eprintln!("secured: KNX Data Secure group write with the group key of {ga}");
    }
    let confirmed = crate::confirm::confirm(
        yes,
        &format!("write {label} via {gateway}?"),
        &format!("write {label} via {gateway}"),
    )?;
    if !confirmed {
        eprintln!("aborted; nothing was written.");
        return Ok(ExitCode::FAILURE);
    }

    let secured = write.is_secured();
    // Sender admission (issue #297): the evidence besides the lock is the
    // keyring's interface entries. Loaded from the same memoized decrypt as
    // the group keys.
    let evidence = match (secured, keyring) {
        (true, Some(path)) => bussard_service::secure::load_admission_evidence(path)
            .with_context(|| format!("loading the interfaces of {}", path.display()))?,
        _ => AdmissionEvidence::default(),
    };
    // Issue #316: the receivers' tool keys, to read an unknown admission
    // from their PID 54 before sending.
    let keys = match (secured, keyring) {
        (true, Some(path)) => {
            bussard_service::secure::ToolKeys::load(crate::secure_key::ToolKeySource {
                keyring: Some(path),
                tool_key: None,
            })?
        }
        _ => bussard_service::secure::ToolKeys::default(),
    };
    let runtime = tokio::runtime::Runtime::new()?;
    let model_ref = model.as_ref();
    let lock_dir = model_ref.map(|_| dir);
    let (outcome, resolved) = runtime.block_on(async move {
        let service = open_service(config, WritePolicy::transmit(allow_remote_gateway)).await?;
        // The tunnel's address is known once the tunnel is up: check that the
        // devices on a secured GA admit it before anything is sent; an
        // unknown verdict reads the receivers' PID 54 first (issue #316).
        let source = bussard_bus::ops::group_source(service.handle());
        let resolved = if secured {
            let mut live = admission::LiveTables::new();
            Some(
                admission::resolve_unknown(&service, lock_dir, &keys, &mut live, |live| {
                    admission::check_tunnel_write_with(model_ref, ga, source, &evidence, live)
                })
                .await,
            )
        } else {
            None
        };
        let result = if resolved.as_ref().is_some_and(|r| r.admission.is_refused()) {
            None
        } else {
            Some(service.send_prepared(write).await)
        };
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        service.close().await;
        anyhow::Ok((result, resolved))
    })?;
    for device in resolved.iter().flat_map(|r| &r.read) {
        eprintln!(
            "read {device}'s security individual address table (PID 54) and recorded it in \
             bussard.lock"
        );
    }
    let admission = resolved.as_ref().map(|r| r.admission.clone());
    let Some(outcome) = outcome else {
        // Refused before sending: the devices would discard the telegram.
        let admission = admission.as_ref();
        let refusal = admission.and_then(Admission::refusal).unwrap_or_default();
        let hint = admission
            .and_then(Admission::admit_hint)
            .unwrap_or_default();
        if json {
            crate::output::print(
                crate::output::schema::WRITE,
                &serde_json::json!({
                    "ga": ga.to_string(),
                    "secured": true,
                    "gateway": gateway,
                    "sent": false,
                    "admission": "refused",
                    "reason": refusal,
                    "hint": hint,
                }),
            )?;
        }
        eprintln!("error: {refusal}\n{hint}");
        return Ok(ExitCode::FAILURE);
    };
    let note = resolved.as_ref().and_then(admission::Resolved::note);

    match outcome {
        Ok(sent) => {
            let result = if sent.confirmed {
                admission::WRITE_RESULT
            } else {
                admission::WRITE_RESULT_UNCONFIRMED
            };
            if json {
                let w = &sent.write;
                let payload: String = w.payload.iter().map(|b| format!("{b:02x}")).collect();
                crate::output::print(
                    crate::output::schema::WRITE,
                    &serde_json::json!({
                        "ga": w.ga.to_string(),
                        "name": w.name,
                        "value": w.value,
                        "dpt": w.dpt.as_ref().map(ToString::to_string),
                        "payload": payload,
                        "secured": w.is_secured(),
                        "gateway": gateway,
                        "confirmed": sent.confirmed,
                        "result": result,
                        "admission": admission.as_ref().map(Admission::label),
                        "note": note,
                    }),
                )?;
            } else {
                // Confirmation line, e.g.
                // `3/0/4 Living Room Blind Move ← Down (1.008)`.
                println!("{}", write_label(&sent.write));
            }
            // What KNX confirmed, exactly (issue #297): the interface's
            // L_Data.con at most. Not an error when it is missing: group
            // writes are fire-and-forget, so scripts still see success.
            eprintln!("{result}");
            if let Some(note) = &note {
                eprintln!("note: {note}");
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
        } => anyhow!("GA {ga} has no DPT in groups.toml; pass --dpt <dpt> (e.g. --dpt 1.001)"),
        WriteRefusal::InvalidValue {
            ga, value, reason, ..
        } => anyhow!(reason).context(format!("parsing value {value:?} for GA {ga}")),
        WriteRefusal::Encode {
            ga,
            value,
            dpt,
            reason,
        } => anyhow!(reason).context(format!("encoding {value} as DPT {dpt} for GA {ga}")),
        WriteRefusal::SecureNoKey { ga, keyring_given } => {
            anyhow!(crate::secure_key::no_group_key_hint(ga, keyring_given))
        }
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

    use bussard_model::IndividualAddress;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("test fixture")
    }

    fn model_with(protected: bool, dpt: Option<&str>) -> Model {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/0/4"),
            Group {
                name: "Living Room Blind Move".to_string(),
                dpt: dpt.map(|d| d.parse().expect("test fixture")),
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

    #[test]
    fn test_linked_devices_lists_the_receivers_of_a_secured_write() -> anyhow::Result<()> {
        let ga: GroupAddress = "1/2/3".parse()?;
        let mut model = model_with(false, Some("1.001"));
        let listener: IndividualAddress = "1.1.5".parse()?;
        let sender: IndividualAddress = "1.1.6".parse()?;
        let other: IndividualAddress = "1.1.7".parse()?;
        let link =
            |send: Option<GroupAddress>, listen: Vec<GroupAddress>| bussard_model::schema::Link {
                object: 1,
                name: None,
                send,
                listen,
            };
        model
            .links
            .links
            .insert(listener, vec![link(None, vec![ga])]);
        model
            .links
            .links
            .insert(sender, vec![link(Some(ga), Vec::new())]);
        model
            .links
            .links
            .insert(other, vec![link(Some("1/2/4".parse()?), Vec::new())]);
        let tunnel: IndividualAddress = "1.1.255".parse()?;
        let receivers = bussard_service::admission::linked_devices(Some(&model), ga, tunnel);
        assert_eq!(receivers, vec![listener, sender]);
        // The sender itself is never its own receiver.
        let without = bussard_service::admission::linked_devices(Some(&model), ga, sender);
        assert_eq!(without, vec![listener]);
        assert!(bussard_service::admission::linked_devices(None, ga, tunnel).is_empty());
        Ok(())
    }
}
