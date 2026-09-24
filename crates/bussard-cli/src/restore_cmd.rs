//! The `bussard restore` subcommand — write a device's backed-up tables back
//! onto it (issue #96).
//!
//! A backup is only as good as the command that puts it back. `restore` takes a
//! backup directory (a `bussard backup` run, or `<model>/captures/backups` where
//! `apply` leaves its pre-write snapshots), finds the newest file for the named
//! device, and hands its tables to the very same plan, confirm, back-up, write
//! and verify path `bussard apply` uses — see
//! [`apply_cmd::apply_desired`](crate::apply_cmd::apply_desired). The only
//! difference is where the desired tables came from: a backup file instead of
//! `links.yaml`.
//!
//! That sharing is the point. There is no second write primitive to review, no
//! second confirmation to get wrong, and no path by which a restore can write
//! something an `apply` could not. It sits behind the same non-loopback gateway
//! gate as every other write, and it takes its own pre-write backup first,
//! because the state a restore overwrites is still the only copy of what is on
//! the device right now.
//!
//! Restoring a backup onto a device that has not changed since it was taken
//! produces an empty plan and exits without touching a load state.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_download::backup::{find_device_backup, read_device_backup};
use bussard_model::IndividualAddress;

use crate::apply_cmd::{self, DesiredSource};
use crate::conn_cmd::{ConnOverrides, load_model_required, resolve_config};

/// Runs `bussard restore`.
#[allow(clippy::too_many_arguments)] // one command's worth of flags
pub fn run(
    backup_dir: &Path,
    address: &str,
    dir: &Path,
    yes: bool,
    allow_remote_gateway: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    if !backup_dir.is_dir() {
        bail!(
            "{} is not a backup directory; pass the directory a `bussard backup` run wrote \
             (it holds manifest.json and one <ia>-<timestamp>.json per device)",
            backup_dir.display()
        );
    }
    let path = find_device_backup(backup_dir, target)?;
    let backup = read_device_backup(&path)?;
    let desired = backup.desired_tables(&path)?;

    // A restore is a management write, so a present-but-broken model is a hard
    // error; an absent one is fine, since the tables come from the backup and
    // not from links.yaml.
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;

    println!(
        "restore {target} from {} (read {}, mask {})",
        path.display(),
        backup.read_time.as_deref().unwrap_or("time unknown"),
        backup.mask,
    );
    if let Some(parameters) = &backup.parameters {
        println!(
            "note: the backup also carries {} octet(s) of parameter memory at {:#X}; \
             `restore` writes the link tables only. Re-run `bussard flash` with the \
             vendor product data to put parameters back.",
            parameters.length, parameters.base
        );
    }

    apply_cmd::apply_desired(
        target,
        &desired,
        dir,
        config,
        yes,
        allow_remote_gateway,
        tool_key_source,
        None,
        &DesiredSource::Backup(path),
        &overrides,
        model.as_ref(),
    )
}
