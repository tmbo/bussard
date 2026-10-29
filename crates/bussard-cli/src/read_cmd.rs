//! The `bussard read <ga>` subcommand: send a GroupValueRead and print the
//! typed response.
//!
//! Runs over a read-only [`bussard_service::BusService`], calls the shared
//! [`bussard_service::BusService::read_group`] (the plain path is
//! [`bussard_bus::ops::read_group`], which subscribes, sends the read completion-tracked,
//! skips the gateway's `L_Data.con` echo and decodes the answer), prints the
//! typed value, and closes the bus cleanly. Exits non-zero on timeout so scripts
//! can detect a non-responding object, and on a send failure (honest exit codes,
//! review A3).
//!
//! A secured GA (`secure: true` in the model, or a group key in `--keyring`) is
//! read with a KNX Data Secure `GroupValueRead` and only a response whose MAC
//! verifies under the group key is accepted (issue #172). A secured GA without
//! a key is refused before anything is sent, and so is one whose responders
//! are known not to admit the tunnel address (issue #297).

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_service::admission::{self, Admission, AdmissionEvidence};
use bussard_service::{SecureGroupError, WritePolicy, group_key_for};

use crate::conn_cmd::{ConnOverrides, load_model_optional, open_service, resolve_config};

/// How long to wait for a GroupValueResponse before giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Environment variable that overrides [`READ_TIMEOUT`] in milliseconds. Set by
/// the integration tests whose responder stays silent on purpose; unset in
/// normal use.
const READ_TIMEOUT_MS_ENV: &str = "BUSSARD_READ_TIMEOUT_MS";

/// The response wait, honouring [`READ_TIMEOUT_MS_ENV`] when set.
fn read_timeout() -> Duration {
    bussard_model::dotenv::var(READ_TIMEOUT_MS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(READ_TIMEOUT)
}

/// `timeout` as the error messages print it: whole seconds (`3s`), or
/// milliseconds when the test knob set a fraction.
fn timeout_label(timeout: Duration) -> String {
    if timeout.subsec_millis() == 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
}

/// Runs `bussard read <ga>`.
pub fn run(
    ga_str: &str,
    dir: &Path,
    keyring: Option<&Path>,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let ga: GroupAddress = ga_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid group address {ga_str:?}"))?;

    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;
    // The DPT to decode against: the GA's DPT from the model, if known.
    let dpt = model
        .as_ref()
        .and_then(|m| m.groups.groups.get(&ga))
        .and_then(|g| g.dpt);
    let ga_name = model
        .as_ref()
        .and_then(|m| m.groups.groups.get(&ga))
        .map(|g| g.name.clone());
    // KNX Data Secure (issue #172): decide plain vs secured before connecting.
    let group_keys = crate::secure_key::group_keys(keyring)?;
    let key = group_key_for(model.as_ref(), ga, group_keys.as_ref()).map_err(
        |SecureGroupError::NoKey { ga, keyring_given }| {
            anyhow::anyhow!(crate::secure_key::no_group_key_hint(ga, keyring_given))
        },
    )?;
    let secured = key.is_some();
    // Sender admission (issue #297): a secured read the responder does not
    // admit is never answered.
    let evidence = match (secured, keyring) {
        (true, Some(path)) => bussard_service::secure::load_admission_evidence(path)
            .with_context(|| format!("loading the interfaces of {}", path.display()))?,
        _ => AdmissionEvidence::default(),
    };
    // Issue #316: the responders' tool keys, to read an unknown admission
    // from their PID 54 before asking.
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
    let (outcome, resolved, source) = runtime.block_on(async move {
        // A read never writes, so the service is read-only and ungated.
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let source = bussard_bus::ops::group_source(service.handle());
        let resolved = if secured {
            let mut live = admission::LiveTables::new();
            Some(
                admission::resolve_unknown(&service, lock_dir, &keys, &mut live, |live| {
                    admission::check_sender_admission_with(model_ref, ga, source, &evidence, live)
                })
                .await,
            )
        } else {
            None
        };
        let admission = resolved.as_ref().map(|r| r.admission.clone());
        let result = if admission.as_ref().is_some_and(Admission::is_refused) {
            None
        } else {
            Some(
                service
                    .read_group(ga, dpt, key.as_ref(), read_timeout())
                    .await,
            )
        };
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        service.close().await;
        anyhow::Ok((result, resolved, source))
    })?;
    let admission = resolved.as_ref().map(|r| r.admission.clone());
    let Some(outcome) = outcome else {
        let admission = admission.as_ref();
        let refusal = admission.and_then(Admission::refusal).unwrap_or_default();
        let hint = admission
            .and_then(Admission::admit_hint)
            .unwrap_or_default();
        if json {
            crate::output::print(
                crate::output::schema::READ,
                &serde_json::json!({
                    "ga": ga.to_string(),
                    "name": ga_name,
                    "answered": false,
                    "secured": true,
                    "sent": false,
                    "admission": "refused",
                    "error": refusal,
                    "hint": hint,
                }),
            )?;
        }
        eprintln!("error: {refusal}\n{hint}");
        return Ok(ExitCode::FAILURE);
    };
    let note = resolved.as_ref().and_then(admission::Resolved::note);

    if json {
        return print_json(ga, ga_name.as_deref(), secured, source, &outcome);
    }
    match outcome {
        Ok(Some(read)) => {
            if let Some(name) = &ga_name {
                eprintln!("{ga} {name}");
            }
            if read.secured {
                eprintln!(
                    "secured: KNX Data Secure response from {} verified with the group key of \
                     {ga}",
                    read.outcome.source
                );
            }
            let outcome = read.outcome;
            match (&outcome.value, &outcome.dpt) {
                (Some(v), Some(dpt)) => println!("{v} ({dpt})"),
                (Some(v), None) => println!("{v}"),
                (None, _) => {
                    // A response with no decodable value (e.g. unknown DPT).
                    let hex: String = outcome.payload.iter().map(|b| format!("{b:02x}")).collect();
                    println!("0x{hex}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Ok(None) => {
            if secured {
                eprintln!(
                    "error: {} ({})",
                    admission::secured_read_timeout(ga, source),
                    timeout_label(read_timeout())
                );
                if let Some(note) = &note {
                    eprintln!("note: {note}");
                }
            } else {
                eprintln!(
                    "error: no response for {ga} within {}",
                    timeout_label(read_timeout())
                );
            }
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("error: could not read {ga}: {err}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// `read --json`: one document whether or not the GA answered; the exit code
/// says the same as the text output's.
fn print_json(
    ga: GroupAddress,
    name: Option<&str>,
    secured: bool,
    source: IndividualAddress,
    outcome: &Result<Option<bussard_service::GroupRead>, bussard_service::GroupSendError>,
) -> anyhow::Result<ExitCode> {
    let (body, code) = match outcome {
        Ok(Some(read)) => {
            let o = &read.outcome;
            let raw: String = o.payload.iter().map(|b| format!("{b:02x}")).collect();
            (
                serde_json::json!({
                    "ga": ga.to_string(),
                    "name": name,
                    "answered": true,
                    "value": o.value.as_ref().map(ToString::to_string),
                    "dpt": o.dpt.as_ref().map(ToString::to_string),
                    "raw": raw,
                    "source": o.source.to_string(),
                    "secured": read.secured,
                }),
                ExitCode::SUCCESS,
            )
        }
        Ok(None) => (
            serde_json::json!({
                "ga": ga.to_string(),
                "name": name,
                "answered": false,
                "secured": secured,
                "timeout_seconds": read_timeout().as_secs(),
                "reason": secured.then(|| admission::secured_read_timeout(ga, source)),
            }),
            ExitCode::FAILURE,
        ),
        Err(err) => (
            serde_json::json!({
                "ga": ga.to_string(),
                "name": name,
                "answered": false,
                "secured": secured,
                "error": err.to_string(),
            }),
            ExitCode::FAILURE,
        ),
    };
    crate::output::print(crate::output::schema::READ, &body)?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_timeout_label_keeps_whole_seconds() {
        assert_eq!(super::timeout_label(super::READ_TIMEOUT), "3s");
        assert_eq!(
            super::timeout_label(std::time::Duration::from_millis(200)),
            "200ms"
        );
    }
}
