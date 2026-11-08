//! The `bussard read <ga>` subcommand: send a GroupValueRead and print the
//! typed response.
//!
//! Runs over a read-only [`bussard_service::BusService`], calls the shared
//! [`bussard_service::BusService::read_group`] (the plain path is
//! [`bussard_service::group::read_group`], which subscribes, sends the read completion-tracked,
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

use std::process::ExitCode;
use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_service::admission;
use bussard_service::group::GroupError;
use bussard_service::group_report::GroupReadReport;
use bussard_service::{SecureGroupError, WritePolicy};

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{load_model_optional, open_service, resolve_config};

/// `bussard read`.
#[derive(Debug, clap::Args)]
pub(crate) struct ReadArgs {
    /// The group address to read, e.g. `3/2/0`.
    #[arg(value_name = "GA")]
    ga: String,
}

impl Run for ReadArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(&self.ga, g)
    }
}

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
fn run(ga_str: &str, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (dir, keyring, json, overrides) = (g.dir(), g.keyring(), g.json, g.group());
    let ga: GroupAddress = ga_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid group address {ga_str:?}"))?;

    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;
    let ga_name = model
        .as_ref()
        .and_then(|m| m.groups.groups.get(&ga))
        .map(|g| g.name.clone());
    // KNX Data Secure (issue #172): decide plain vs secured before connecting.
    let key = bussard_service::group::read_key(model.as_ref(), ga, keyring).map_err(group_error)?;
    let secured = key.is_some();

    let runtime = tokio::runtime::Runtime::new()?;
    let live = tokio::sync::Mutex::default();
    let ctx = bussard_service::group::GroupContext {
        model: model.as_ref(),
        keyring,
        lock_dir: model.as_ref().map(|_| dir),
        live: &live,
        warm: None,
        limiter: None,
    };
    let outcome = runtime.block_on(async {
        // A read never writes, so the service is read-only and ungated.
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let outcome = bussard_service::group::read(&service, &ctx, ga, key, read_timeout()).await;
        // Close the bus cleanly (release the gateway tunnel slot) — issue #31.
        service.close().await;
        anyhow::Ok(outcome.map_err(group_error)?)
    })?;
    if json {
        let report = GroupReadReport::of(ga, ga_name, secured, read_timeout(), &outcome);
        crate::output::report(&report)?;
        return Ok(if report.ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }
    let source = outcome.sender;
    let outcome_result = match outcome.result {
        Ok(result) => result,
        Err(refused) => {
            let refusal = refused.refusal().unwrap_or_default();
            let hint = refused.admit_hint().unwrap_or_default();
            eprintln!("error: {refusal}\n{hint}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let note = outcome.note;
    let outcome = outcome_result;

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

/// A group read or write that could not start, in the CLI's words.
pub(crate) fn group_error(err: GroupError) -> anyhow::Error {
    match err {
        GroupError::NoKey(SecureGroupError::NoKey { ga, keyring_given }) => {
            anyhow::anyhow!(crate::secure_key::no_group_key_hint(ga, keyring_given))
        }
        GroupError::ToolKeys(err) => err.into(),
        other => other.into(),
    }
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
