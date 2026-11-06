//! `bussard secure diag <ADDRESS> [--clear]` (issue #533): a Data Secure
//! device's security failures log (PID 55), security report (PID 57) and
//! report control (PID 58), read over a session with its tool key.
//!
//! Read-only without `--clear`. `--clear` asks first, then clears the log and
//! resets the report, and reads both back: the command fails unless the
//! counters read zero and the report clear afterwards.

use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_service::{L4Options, SourcePolicy, WritePolicy};

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{enforce_write_gate, load_model_required, open_service, resolve_config};

/// The `bussard secure` subcommands (issue #533).
#[derive(Debug, clap::Subcommand)]
pub(crate) enum SecureCommand {
    /// Read a Data Secure device's security failures log (PID 55: the
    /// sequence, cryptographic and access error counters and the latest
    /// failure), its security report (PID 57) and whether it broadcasts the
    /// report (PID 58), with its tool key.
    ///
    /// After a secured write that did nothing, the counts tell the causes
    /// apart: no new count means the sender is not in the device's security
    /// individual address table, a cryptographic count a wrong or stale group
    /// key, an access count a group-object security flag mismatch.
    Diag(DiagArgs),
}

/// `bussard secure diag`.
#[derive(Debug, clap::Args)]
pub(crate) struct DiagArgs {
    /// The device, e.g. `1.1.5`.
    #[arg(value_name = "ADDRESS")]
    address: String,
    /// Clear the log and reset the report after a confirmation, then read
    /// both back.
    #[arg(long)]
    clear: bool,
    /// Skip the confirmation prompt of --clear.
    #[arg(long)]
    yes: bool,
    /// The raw 32-hex-character KNX Data Secure tool key, for a test
    /// device. Prefer `--keyring`.
    #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
    tool_key: Option<String>,
}

impl Run for SecureCommand {
    fn spec(&self) -> Spec {
        let SecureCommand::Diag(args) = self;
        Spec::BUS.json().tool_key(args.tool_key.is_some())
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        match self {
            SecureCommand::Diag(args) => run(&args, g),
        }
    }
}

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
fn run(args: &DiagArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (address, clear, yes) = (args.address.as_str(), args.clear, args.yes);
    let (dir, json, allow_remote_gateway) = (g.dir(), g.json, g.allow_remote_gateway);
    let (tool_key_source, overrides) = (g.tool_keys(args.tool_key.as_deref()), g.mgmt());
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    let model = load_model_required(dir)?;
    // The log is tool-only (KNX 3/5/1 §6.3.9.2): a tool key is required, so
    // the device counts as activated for the key rule.
    let (tool_key, factory_key) = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_session_keys(target, tool_key_source, true)
    })?;
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
                "{} [y/N] ",
                bussard_service::security_diag::clear_question(target)
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
