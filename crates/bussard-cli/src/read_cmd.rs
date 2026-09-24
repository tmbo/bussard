//! The `bussard read <ga>` subcommand: send a GroupValueRead and print the
//! typed response.
//!
//! Runs over a read-only [`bussard_service::BusService`], calls the shared
//! [`ops::read_group`] (which subscribes, sends the read completion-tracked,
//! skips the gateway's `L_Data.con` echo and decodes the answer), prints the
//! typed value, and closes the bus cleanly. Exits non-zero on timeout so scripts
//! can detect a non-responding object, and on a send failure (honest exit codes,
//! review A3).

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use bussard_bus::ops;
use bussard_model::GroupAddress;
use bussard_service::WritePolicy;

use crate::conn_cmd::{ConnOverrides, load_model_optional, open_service, resolve_config};

/// How long to wait for a GroupValueResponse before giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Runs `bussard read <ga>`.
pub fn run(ga_str: &str, dir: &Path, overrides: ConnOverrides) -> anyhow::Result<ExitCode> {
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

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        // A read never writes, so the service is read-only and ungated.
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let result = ops::read_group(service.handle(), ga, dpt, READ_TIMEOUT).await;
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        service.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(Some(outcome)) => {
            if let Some(name) = &ga_name {
                eprintln!("{ga} {name}");
            }
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
            eprintln!(
                "error: no response for {ga} within {}s",
                READ_TIMEOUT.as_secs()
            );
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("error: could not read {ga}: {err}");
            Ok(ExitCode::FAILURE)
        }
    }
}
