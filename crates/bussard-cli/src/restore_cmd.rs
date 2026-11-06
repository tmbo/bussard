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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_download::backup::{find_device_backup, read_device_backup};
use bussard_model::IndividualAddress;
use bussard_service::secure::ToolKeySource;

use crate::apply_cmd::{self, DesiredSource};
use crate::cli::{BenchToolKey, Consent, Resolved, Run, Spec};
use crate::conn_cmd::{load_model_required, resolve_config};

/// `bussard restore`.
#[derive(Debug, clap::Args)]
pub(crate) struct RestoreArgs {
    /// `<BACKUP_DIR> <ADDRESS>`: the backup directory (a `bussard backup`
    /// run, or `<dir>/captures/backups` for the per-device snapshots
    /// `apply` leaves) and the device, e.g. `1.1.4`. With `--parameters`,
    /// only `<ADDRESS>`.
    #[arg(value_name = "BACKUP_DIR> <ADDRESS", num_args = 1..=2, required = true)]
    args: Vec<String>,
    /// Replay this parameter backup
    /// (`<dir>/captures/backups/parameters/<ia>-<ts>.json`) instead of
    /// link tables: refused unless the backup's device, application and
    /// mask match; writes only the octets a parameter is placed in under
    /// the project's configuration, keeps device-managed octets, verifies by
    /// read-back.
    #[arg(long, value_name = "BACKUP_JSON")]
    parameters: Option<PathBuf>,
    #[command(flatten)]
    consent: Consent,
    #[command(flatten)]
    tool_key: BenchToolKey,
}

impl Run for RestoreArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.tool_key(self.tool_key.tool_key.is_some())
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        let tool_keys = g.tool_keys(self.tool_key.tool_key.as_deref());
        let yes = self.consent.yes;
        match (&self.parameters, self.args.as_slice()) {
            (Some(backup), [address]) => run_parameters(backup, address, yes, tool_keys, g),
            (None, [backup_dir, address]) => run(Path::new(backup_dir), address, yes, tool_keys, g),
            (Some(_), _) => anyhow::bail!(
                "`restore --parameters <BACKUP_JSON>` takes one more argument, the device \
                 address: `bussard restore --parameters <BACKUP_JSON> <ADDRESS>`"
            ),
            (None, _) => anyhow::bail!(
                "`restore` takes the backup directory and the device address: `bussard restore \
                 <BACKUP_DIR> <ADDRESS>` (or `bussard restore --parameters <BACKUP_JSON> \
                 <ADDRESS>`)"
            ),
        }
    }
}

/// Runs `bussard restore`.
fn run(
    backup_dir: &Path,
    address: &str,
    yes: bool,
    tool_key_source: ToolKeySource<'_>,
    g: &Resolved,
) -> anyhow::Result<ExitCode> {
    let (dir, allow_remote_gateway, overrides) = (g.dir(), g.allow_remote_gateway, g.mgmt());
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

    apply_cmd::apply_desired(apply_cmd::WriteJob {
        target,
        desired: &desired,
        dir,
        config,
        yes,
        allow_remote_gateway,
        tool_key_source,
        secure_sender: None,
        origin: &DesiredSource::Backup(path),
        overrides: &overrides,
        model: model.as_ref(),
        write: apply_cmd::ModelWrite::default(),
    })
}

/// Runs `bussard restore --parameters <backup> <address>` (module docs).
fn run_parameters(
    backup_path: &Path,
    address: &str,
    yes: bool,
    tool_key_source: ToolKeySource<'_>,
    g: &Resolved,
) -> anyhow::Result<ExitCode> {
    use bussard_service::{L4Options, SourcePolicy};
    let (dir, allow_remote_gateway, overrides) = (g.dir(), g.allow_remote_gateway, g.mgmt());

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
        bussard_service::params::Selection::default(),
        Some(&model),
        target,
        bussard_service::params::MissingProduct::Refuse,
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

    let activated = bussard_service::secure::model_activated(Some(&model), target);
    let material = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_material(target, tool_key_source, activated)
    })?;
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
    let mut facts = crate::conn_cmd::facts_cache(dir, true, overrides.refresh_facts);
    let read_options = L4Options {
        source: SourcePolicy::Known(source),
        tool_key: tool_key.clone(),
        high_water: secure_seq.clone(),
        authorize: bussard_service::status::read_only_authorize(&mut facts, target),
        ..L4Options::default()
    };
    let request = bussard_service::program::read::ReadRequest {
        target,
        model: Some(&model),
        product: Some(&product),
        facts: &facts,
        tunnel: &[],
        secured: false,
        flags_cache: bussard_service::program::read::FlagsCache::Off,
        properties: None,
    };
    let read = runtime.block_on(bussard_service::program::read::read_device(
        service,
        &read_options,
        &request,
    ))?;
    if let Some(check) = read.check() {
        eprintln!("{}", bussard_service::identity_line(target, check));
        if let Some(err) = bussard_service::drift_refusal(target, check, "restore to") {
            eprintln!("{err}");
            return Ok(ExitCode::FAILURE);
        }
    }
    let read = match read.into_tables() {
        Ok(read) => read,
        Err((address, mask)) => {
            crate::plan_cmd::report_unsupported_mask("restore", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let Some(state) = read.params.as_ref() else {
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
    let pre = bussard_service::program::apply::back_up_parameters(dir, target, detail)
        .context("writing the parameter backup (refusing to write without a backup)")?;
    println!("parameter backup written to {}", pre.display());
    let mut observer = crate::progress::Terminal::new(yes, false);
    bussard_service::program::Observer::step(
        &mut observer,
        bussard_service::program::Step::WriteParameters { plan: partial },
    );
    let outcome = runtime.block_on(bussard_service::download::write_parameters(
        bussard_service::download::ParamWrite {
            service,
            target,
            source,
            partial,
            detail,
            tool_key,
            high_water: secure_seq,
            read_options: &read_options,
        },
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
