//! `bussard secure diag <ADDRESS> [--clear]` (issue #533): a Data Secure
//! device's security failures log (PID 55), security report (PID 57) and
//! report control (PID 58), read over a session with its tool key.
//!
//! Read-only without `--clear`. `--clear` asks first, then clears the log and
//! resets the report, and reads both back: the command fails unless the
//! counters read zero and the report clear afterwards.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_service::{L4Options, SourcePolicy, WritePolicy};

use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, load_model_required, open_service, resolve_config,
};

/// The `secure diag --json` report.
#[derive(Debug, serde::Serialize)]
struct Report<'a> {
    /// The device address.
    address: String,
    /// Whether the log was cleared (and read back clear) by this run.
    cleared: bool,
    /// What the device holds.
    diagnostics: &'a bussard_download::SecurityDiagnostics,
}

/// Runs `bussard secure diag`.
#[allow(clippy::too_many_arguments)] // one command's flags, passed through
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    clear: bool,
    yes: bool,
    allow_remote_gateway: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    let model = load_model_required(dir)?;
    // The log is tool-only (KNX 3/5/1 §6.3.9.2): a tool key is required, so
    // the device counts as activated for the key rule.
    let (tool_key, factory_key) =
        crate::secure_key::resolve_session_keys(target, tool_key_source, true)?;
    if tool_key.is_none() {
        bail!(
            "{target}: the security failures log is readable with the device's tool key only: \
             {}",
            bussard_service::guidance::tool_key_hint()
        );
    }
    let config = resolve_config(model.as_ref(), &overrides)?;
    if clear {
        enforce_write_gate(&config, allow_remote_gateway)?;
        if !crate::confirm::confirm(
            yes,
            &format!(
                "Clear the security failures log and reset the security report of {target}? \
                 [y/N] "
            ),
            &format!("clear the security failures log of {target}"),
        )? {
            eprintln!("aborted; nothing was written");
            return Ok(ExitCode::FAILURE);
        }
    }
    let policy = if clear {
        WritePolicy::transmit(allow_remote_gateway)
    } else {
        WritePolicy::ReadOnly
    };
    let runtime = tokio::runtime::Runtime::new()?;
    let diag = runtime
        .block_on(async move {
            let service = open_service(config, policy).await?;
            let options = L4Options {
                source: SourcePolicy::Check {
                    skip: overrides.skip_address_check,
                },
                tool_key,
                factory_key,
                ..L4Options::default()
            };
            let outcome = if clear {
                bussard_service::security_diag::clear(&service, target, &options).await
            } else {
                bussard_service::security_diag::read(&service, target, &options).await
            };
            service.close().await;
            anyhow::Ok(outcome?)
        })
        .map_err(|err| crate::secure_key::secure_hint(target, true, err))?;
    if json {
        crate::output::print(
            crate::output::schema::SECURE_DIAG,
            &Report {
                address: target.to_string(),
                cleared: clear,
                diagnostics: &diag,
            },
        )?;
    } else {
        println!("device {target} — KNX Data Secure diagnostics");
        for line in diag.lines() {
            println!("  {line}");
        }
        if clear {
            println!("cleared and read back: every counter is 0 and no failure is flagged");
        }
    }
    Ok(ExitCode::SUCCESS)
}
