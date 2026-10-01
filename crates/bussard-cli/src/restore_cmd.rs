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
//! device files' links.
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
//!
//! # `restore --parameters <backup.json> <ADDRESS>` (issue #290)
//!
//! Replays a parameter backup (`<dir>/captures/backups/parameters/<ia>-<ts>.json`,
//! the pre-write snapshot `apply`, `flash --parameters-only` and
//! `knx_apply_device` keep) with the parameter-only download `apply` uses:
//! the plan comes from [`bussard_service::restore`], the write from
//! [`bussard_service::download::write_parameters`]. A backup of another
//! device, application or mask is refused; only the octets a parameter is
//! placed in under the model's configuration are written, device-managed
//! octets keep the device's value, and the write is verified by read-back.
//! The gates are `apply`'s: the real-gateway opt-in, the confirmation, the
//! identity verdict against `bussard.lock`, the parameter-only identity gate
//! (a device that does not run the application, such as a factory-fresh one,
//! is refused), and a backup of the memory it overwrites.

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
    // not from the device files' links.
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
        apply_cmd::ModelWrite::default(),
    )
}

/// Runs `bussard restore --parameters <backup> <address>` (module docs).
#[allow(clippy::too_many_arguments)] // one command's worth of flags
pub fn run_parameters(
    backup_path: &Path,
    address: &str,
    dir: &Path,
    yes: bool,
    allow_remote_gateway: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    use bussard_service::{L4Options, SourcePolicy};

    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    let backup = bussard_download::backup::read_parameter_backup(backup_path)?;
    let Some(model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                "`bussard restore --parameters` decodes the parameter memory with the product \
                 data bussard.lock pins for the device"
            )
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    let product = crate::param_readback::resolve(
        dir,
        crate::param_readback::Selection::default(),
        Some(&model),
        target,
        crate::param_readback::MissingProduct::Refuse,
    )?;
    let Some(product) = product else {
        bail!(
            "no product data for {target}: `bussard restore --parameters` needs the archive \
             bussard.lock pins for the device (run `bussard import-product`)"
        );
    };
    println!(
        "restore the parameter memory of {target} from {} (read {}, application {}, mask {})",
        backup_path.display(),
        backup.read_time,
        backup.application,
        backup.mask
    );

    let activated = crate::secure_key::model_activated(Some(&model), target);
    let material = crate::secure_key::resolve_material(target, tool_key_source, activated)?;
    let tool_key = material.tool_key.clone();
    let secure_seq = bussard_secure::SequenceHighWater::new();
    crate::conn_cmd::enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = crate::conn_cmd::gateway_display(&config);
    let runtime = tokio::runtime::Runtime::new()?;
    let bus = crate::conn_cmd::BusSession::open(
        &runtime,
        config,
        bussard_service::WritePolicy::transmit(allow_remote_gateway),
    )?;
    let source = runtime.block_on(bus.service().checked_source(overrides.skip_address_check))?;
    let service = bus.service();
    let mut facts = crate::device_facts::cache(dir, true, overrides.refresh_facts);
    let read_options = L4Options {
        source: SourcePolicy::Known(source),
        tool_key: tool_key.clone(),
        high_water: secure_seq.clone(),
        authorize: crate::device_facts::read_only_authorize(&mut facts, target),
        ..L4Options::default()
    };
    let device = model.devices.get(&target).map(|d| &d.device);
    let read = runtime.block_on(async {
        service
            .with_l4(target, &read_options, async |l4| {
                let identified = crate::device_facts::identify(l4, &facts, device).await?;
                let read = crate::plan_cmd::read_live_tables(l4).await?;
                let state = match &read {
                    crate::plan_cmd::LiveRead::Tables(live) => Some(
                        crate::param_readback::read_state(
                            l4,
                            &product,
                            Some(&model),
                            target,
                            live.tables().mask,
                        )
                        .await,
                    ),
                    crate::plan_cmd::LiveRead::UnsupportedMask { .. } => None,
                };
                anyhow::Ok((read, identified, state))
            })
            .await
    });
    let (read, identified, state) = read?;
    if let Some(check) = &identified.check {
        eprintln!("{}", crate::device_facts::identity_line(target, check));
        if let Err(err) = crate::device_facts::refuse_drift(target, check, "restore to") {
            eprintln!("{err}");
            return Ok(ExitCode::FAILURE);
        }
    }
    if let crate::plan_cmd::LiveRead::UnsupportedMask { address, mask } = read {
        crate::plan_cmd::report_unsupported_mask("restore", address, mask);
        return Ok(ExitCode::FAILURE);
    }
    let Some(state) = state else {
        return Ok(ExitCode::FAILURE);
    };
    let Some(detail) = state.detail.as_ref() else {
        eprintln!(
            "refusing to restore the parameters of {target}: {}",
            state
                .readback
                .note
                .as_deref()
                .unwrap_or("the parameter memory could not be read")
        );
        return Ok(ExitCode::FAILURE);
    };
    let Some(app) = product.app() else {
        bail!(
            "the application {} is not in the product data",
            product.app_id
        );
    };
    let plan = match bussard_service::restore::build_restore_plan(
        app,
        Some(&model),
        target,
        detail,
        &backup,
    ) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("refusing to restore the parameters of {target}: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };
    print!("{}", plan.render_text(target));
    let Some(partial) = plan.partial.as_ref() else {
        return Ok(ExitCode::SUCCESS);
    };
    if !crate::confirm::confirm(
        yes,
        &plan.question(target, &gateway),
        &format!("restore the parameters of {target} via {gateway}"),
    )? {
        eprintln!("aborted: nothing written.");
        return Ok(ExitCode::FAILURE);
    }
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("restore --parameters")
            .with_args([target.to_string(), backup_path.display().to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result("before restoring the parameter memory"),
    );
    // The memory this restore overwrites is still the only copy of what the
    // device holds now: back it up first, as `apply` does.
    let pre = crate::flash_params::write_backup(dir, target, &detail.plan, &detail.regions)
        .context("writing the parameter backup (refusing to write without a backup)")?;
    println!("parameter backup written to {}", pre.display());
    let mut observer = crate::apply_cmd::ParamDisplay::new(partial);
    let outcome = runtime.block_on(bussard_service::download::write_parameters(
        service,
        target,
        source,
        partial,
        detail,
        tool_key,
        secure_seq,
        &read_options,
        &mut observer,
    ))?;
    match (&outcome, outcome.failure()) {
        (bussard_service::download::ParamWriteOutcome::Verified { octets }, _) => {
            println!(
                "parameters restored and verified: {octets} octet(s) read back from {target}; \
                 the application is Loaded"
            );
            Ok(ExitCode::SUCCESS)
        }
        (_, failure) => {
            eprintln!("\nERROR: {}", failure.unwrap_or_default());
            eprintln!(
                "The parameter memory before the restore was backed up to:\n    {}",
                pre.display()
            );
            Ok(ExitCode::FAILURE)
        }
    }
}
