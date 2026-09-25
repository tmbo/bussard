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
//! a key is refused before anything is sent.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_service::{SecureGroupError, WritePolicy, group_key_for};

use crate::conn_cmd::{ConnOverrides, load_model_optional, open_service, resolve_config};

/// How long to wait for a GroupValueResponse before giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

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

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        // A read never writes, so the service is read-only and ungated.
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let result = service
            .read_group(ga, dpt, key.as_ref(), READ_TIMEOUT)
            .await;
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        service.close().await;
        anyhow::Ok(result)
    })?;

    if json {
        return print_json(ga, ga_name.as_deref(), secured, &outcome);
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
                    "error: no verified secured response for {ga} within {}s (a device \
                     answers a secured read only when bussard's source address is in its \
                     security individual address table)",
                    READ_TIMEOUT.as_secs()
                );
            } else {
                eprintln!(
                    "error: no response for {ga} within {}s",
                    READ_TIMEOUT.as_secs()
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
                "timeout_seconds": READ_TIMEOUT.as_secs(),
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
