//! The `bussard apply` subcommand — write the model to one device.
//!
//! One verb writes a device. The flow, in order:
//! 1. Load the model, declare the group addresses the device files use first,
//!    and validate: an error stops here, before the bus is touched.
//! 2. Read the device's live tables and, when product data is at hand (the
//!    `.knxprod` in `<dir>/vendor/` for the device's order number, or
//!    `--product`), its parameter memory, over one management session.
//! 3. Refuse a mask outside the two supported families — the same gate as
//!    `reconstruct`.
//! 4. Show the plan in the model's words ([`bussard_service::program::plan`]): the objects
//!    and parameters that change, what stays, what is written, where the
//!    backup goes. An empty plan prints `<ia> matches your project; nothing to
//!    write` and exits 0 **without touching any load state**. With
//!    `--plan <hash>`, a device whose state no longer hashes to what the
//!    approved plan read is refused.
//! 5. Ask once (`y/N`) on a TTY unless `--yes`.
//! 6. **Back up** the pre-state tables to `<dir>/captures/backups/<ia>-<ts>.json`
//!    and, when parameters change, the parameter memory.
//! 7. Write the minimum: the tables when a link changes (see
//!    `bussard_download::apply`), and only the parameter octets that differ
//!    (the `flash --parameters-only` download), each verified by reading back.
//! 8. On any failure, print the backup path and recovery guidance loudly and
//!    exit non-zero.
//!
//! A parameter change that shows or hides a com-object changes the
//! group-object table, which a parameter download does not rewrite: that
//! device is refused with the `bussard flash` it needs.
//!
//! # Two device families
//!
//! **System B** (mask `x7B0`) writes its tables into two loadable interface
//! objects (`bussard_download::apply`). **System 7** (mask `0705` / `0701`) has
//! no such objects: its tables are absolute memory regions driven by two of the
//! three parallel load-state machines, so the write runs
//! `bussard_download::apply_sys7` instead — `Unload` the two table LSMs, then
//! load each in turn: allocate its region, stream it in 12-octet chunks with a
//! read-back verify, `TaskSegment`, `LoadCompleted` (issue #91). The parameter
//! image and the application are never rewritten, which is the whole point: a
//! link change must not reset the device's parameters. Only the group-object
//! table's communication flags follow the links, inside an LSM 3 bracket.
//!
//! A System B table write does not restart the device — a table object
//! activates its content on `LoadCompleted`. A System 7 one ends with a basic
//! restart, as ETS's table-only downloads do, and `apply` waits for the device
//! to answer again before it goes on. See the ordering and restart rationale in
//! `bussard_download::apply_sys7`.
//!
//! # Safety
//!
//! This is the only command that writes device tables. Per the phase-2 spec the
//! first real table writes must happen on a sacrificial device; running `apply`
//! against the live reference bus is out of scope until that device exists. The
//! command still gates on the mask family and always writes a backup first.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_service::L4Options;
use bussard_service::download::backup::{backups_root, has_installation_backup};
use bussard_service::download::{DesiredTables, PlanReport};
use bussard_service::program;
use bussard_service::secure::ToolKeySource;

use bussard_service::transport::ConnectionConfig;

use crate::cli::{Consent, Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{
    BusSession, ConnOverrides, enforce_write_gate, gateway_display, load_model_required,
    resolve_config,
};
use crate::plan_cmd;

/// Where the tables a write phase is about to load came from.
///
/// `apply` and `restore` are the same command with a different source of truth,
/// so they share [`apply_desired`] and differ only in this: the verb they print,
/// and whether the desired tables were computed from the device files' links or read out of
/// a backup file (issue #96).
#[derive(Debug, Clone)]
pub(crate) enum DesiredSource {
    /// The links in the model's device files, computed by `bussard plan`.
    Model,
    /// A device backup file written by `bussard backup` or a previous `apply`.
    Backup(std::path::PathBuf),
}

impl DesiredSource {
    /// The command verb, for the plan header, the confirmation and the errors.
    pub(crate) fn verb(&self) -> &'static str {
        match self {
            DesiredSource::Model => "apply",
            DesiredSource::Backup(_) => "restore",
        }
    }

    /// A one-line description of where the desired tables came from.
    fn origin(&self) -> String {
        match self {
            DesiredSource::Model => "the device files in your project".to_string(),
            DesiredSource::Backup(path) => format!("the backup {}", path.display()),
        }
    }
}

/// `bussard apply`.
#[derive(Debug, Clone, Default, clap::Args)]
pub(crate) struct ApplyArgs {
    /// The device to write, e.g. `1.1.4` (mutually exclusive with
    /// `--line`).
    #[arg(value_name = "ADDRESS", required_unless_present = "line")]
    pub address: Option<String>,
    /// Apply to every device the project has on this line, e.g. `1.1`, in
    /// address order: one confirmation for the run, one summary table, and a
    /// resumable state file.
    // Issue #100.
    #[arg(long, value_name = "LINE", conflicts_with = "address")]
    pub line: Option<String>,
    /// Line mode only: continue the run recorded in
    /// `<dir>/captures/apply-line-<line>.json`, skipping the devices it
    /// already finished.
    #[arg(long, requires = "line")]
    pub resume: bool,
    #[command(flatten)]
    pub consent: Consent,
    /// Refuse unless the device state still hashes to this `state_hash`
    /// from `bussard plan --json`: the plan a human approved is the plan
    /// written.
    #[arg(long = "plan", value_name = "HASH", conflicts_with = "line")]
    pub plan_hash: Option<String>,
    /// Use a `--product` / `--application` that contradicts `bussard.lock`
    /// (the product archive is then pinned for the device).
    #[arg(long, conflicts_with = "line")]
    pub force: bool,
    /// The device's vendor `.knxprod`, to compare and write its parameter
    /// memory. Default: the archive `bussard.lock` pins for the device in
    /// `<dir>/products/`. One that contradicts the lock needs `--force`.
    #[arg(long, value_name = "FILE", conflicts_with = "line")]
    pub product: Option<PathBuf>,
    /// The application program id to decode the parameters with (default:
    /// the program the lock pins, else the order number, else the sole one).
    #[arg(long, value_name = "REF", conflicts_with = "line")]
    pub application: Option<String>,
    #[command(flatten)]
    pub tool_key: ToolKey,
    /// Also list this individual address (bussard's own tunnel address) as a
    /// secured sender, sequence 0, in the security individual address table
    /// (PID 54) the security object is reprogrammed with, so the device
    /// accepts `bussard write --keyring` to its secured group addresses.
    /// Off by default: without it the device drops bussard's secured group
    /// telegrams silently. See https://bussard.tmbo.dev/docs/explanation/safety/.
    #[arg(long, value_name = "IA", conflicts_with = "line")]
    pub secure_sender: Option<IndividualAddress>,
    /// For a KNX IP interface (a device file with a `[knxnet]` table):
    /// write a change of its IP assignment, static address set or tunnel
    /// addresses (PID 53) although bussard tunnels through that
    /// interface. The tunnel drops (for PID 53: may drop) when the
    /// interface applies it, so the read-back may not reach the device;
    /// without this flag such a plan is refused.
    #[arg(long, conflicts_with = "line")]
    pub allow_self_reconfigure: bool,
}

impl Run for ApplyArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
            .json()
            .tool_key(self.tool_key.tool_key.is_some())
            .device_management()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        let tool_keys = g.tool_keys(self.tool_key.tool_key.as_deref());
        match (&self.line, &self.address) {
            (Some(line), _) => {
                crate::line_cmd::run_apply(line, self.consent.yes, self.resume, tool_keys, g)
            }
            (None, _) if g.json => anyhow::bail!(
                "`bussard apply --json` needs --line: a single-device apply has no JSON output"
            ),
            (None, Some(address)) => run(address, &self, tool_keys, g),
            // clap requires ADDRESS without --line.
            (None, None) => anyhow::bail!("give a device ADDRESS or --line"),
        }
    }
}

/// Writes the model to a device: validate, plan, ask once, back up, write the
/// minimum, verify.
fn run(
    address: &str,
    args: &ApplyArgs,
    tool_key_source: ToolKeySource<'_>,
    g: &Resolved,
) -> anyhow::Result<ExitCode> {
    let (dir, yes, allow_remote_gateway) = (g.dir(), args.consent.yes, g.allow_remote_gateway);
    let (secure_sender, overrides) = (args.secure_sender, g.mgmt_with_facts());
    let selection = bussard_service::params::Selection {
        product: args.product.as_deref(),
        application: args.application.as_deref(),
    };
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // A parse error is a hard failure here (surfaced with the file detail).
    let Some(mut model) = load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                "`bussard apply` writes a device's devices/<address>.toml to it"
            )
        );
    };
    let config = resolve_config(Some(&model), &overrides)?;
    // An edit made outside bussard (an editor, an assistant writing TOML) is
    // recorded before this command acts on it, so it is never lost.
    crate::history_cmd::capture_external_edit(dir);
    // A group address the device files use but groups.toml does not define is
    // declared there first, named after the object that uses it.
    crate::groups_cmd::declare_used(dir, &mut model, "apply", false)?;
    // Validation is part of apply: a model with errors is never written.
    if !crate::validate_cmd::gate(&model, dir, "apply") {
        return Ok(ExitCode::FAILURE);
    }
    // An override that contradicts the lock is refused unless --force (issue
    // #228, item 4), before anything reaches the bus.
    if let Some(loaded) = model.devices.get(&target) {
        crate::lock_pin::enforce_override(
            dir,
            &loaded.device,
            selection.product,
            selection.application,
            args.force,
            "apply to",
        )?;
    }
    // The product data the parameter half decodes with, when it is at hand.
    let product = crate::param_readback::resolve(
        dir,
        selection,
        Some(&model),
        target,
        bussard_service::params::MissingProduct::Refuse,
    )?;
    // A KNX IP interface (a `[knxnet]` table, no links) is written as
    // properties of its KNXnet/IP parameter object (issue #391); a
    // property-only load procedure it also has stays `flash`'s.
    crate::interface_cmd::refuse_device_management(&overrides, &model, target)?;
    if crate::interface_cmd::interface_only(&model, target).is_some() {
        hint_installation_backup(dir);
        return crate::interface_cmd::apply(
            target,
            dir,
            &model,
            config,
            &overrides,
            tool_key_source,
            crate::interface_cmd::InterfaceApplyInputs {
                yes,
                allow_remote_gateway,
                plan_hash: args.plan_hash.as_deref(),
                allow_self_reconfigure: args.allow_self_reconfigure,
            },
        );
    }
    let desired = plan_cmd::compute_desired(&model, target, product.as_ref())?;
    hint_installation_backup(dir);
    apply_desired(WriteJob {
        target,
        desired: &desired,
        dir,
        config,
        yes,
        allow_remote_gateway,
        tool_key_source,
        secure_sender,
        origin: &DesiredSource::Model,
        overrides: &overrides,
        model: Some(&model),
        write: ModelWrite {
            product: product.as_ref(),
            plan_hash: args.plan_hash.as_deref(),
        },
    })
}

/// One write of `apply` or `restore` ([`apply_desired`]).
pub(crate) struct WriteJob<'a> {
    /// The device.
    pub target: IndividualAddress,
    /// The tables to write.
    pub desired: &'a DesiredTables,
    /// The model directory.
    pub dir: &'a Path,
    /// The resolved connection.
    pub config: ConnectionConfig,
    /// `--yes`.
    pub yes: bool,
    /// `--allow-remote-gateway`.
    pub allow_remote_gateway: bool,
    /// Where the tool keys come from.
    pub tool_key_source: ToolKeySource<'a>,
    /// `--secure-sender`.
    pub secure_sender: Option<IndividualAddress>,
    /// Where the tables came from.
    pub origin: &'a DesiredSource,
    /// The connection overrides.
    pub overrides: &'a ConnOverrides,
    /// The model, when one is loaded.
    pub model: Option<&'a bussard_model::Model>,
    /// The model half: product data and the approved plan's hash.
    pub write: ModelWrite<'a>,
}

/// The model half of [`apply_desired`]: the product data to read and write
/// the parameter memory with, and the approved plan's hash. Empty for
/// `restore`, which writes tables out of a backup.
#[derive(Default, Clone, Copy)]
pub(crate) struct ModelWrite<'a> {
    /// The product data for the parameter half, when at hand.
    pub product: Option<&'a bussard_service::params::ProductSource>,
    /// `--plan <hash>`.
    pub plan_hash: Option<&'a str>,
}

/// Prints the one-line nudge when the model has no installation-wide backup.
///
/// `apply`'s own pre-write backup covers the device it is about to touch. It
/// does not cover the installation, and the moment to take that snapshot is
/// before the first write, not after (issue #96).
fn hint_installation_backup(dir: &Path) {
    if !has_installation_backup(dir) {
        eprintln!(
            "No installation-wide backup yet. Run `bussard backup` first. \
             (Snapshots land in {}.)",
            backups_root(dir).display()
        );
    }
}

/// The shared plan, confirm, back up, write and verify path behind both
/// `bussard apply` and `bussard restore`: the read, the plan and the write
/// are [`bussard_service::program`]'s, the CLI asks and prints.
///
/// `desired` is whatever the caller decided the device's tables should be. The
/// device is read, diffed, shown, confirmed, backed up and written exactly the
/// same way whichever it is.
pub(crate) fn apply_desired(job: WriteJob<'_>) -> anyhow::Result<ExitCode> {
    let WriteJob {
        target,
        desired,
        dir,
        config,
        yes,
        allow_remote_gateway,
        tool_key_source,
        secure_sender,
        origin,
        overrides,
        model,
        write,
    } = job;
    // KNX Data Secure (issue #71, spec §6.2): every management APDU rides
    // A_SecureData when the device is security-activated and a tool key is
    // given; one high-water mark keeps the send sequence monotonic (§5.9).
    let activated = bussard_service::secure::model_activated(model, target);
    let material = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_material(target, tool_key_source, activated)
    })?;
    let tool_key = material.tool_key.clone();
    let secure_seq = bussard_service::secure::SequenceHighWater::new();
    // `[connection] admit_tunnel_senders` (issue #297): the key store's
    // tunnelling addresses join the security individual address table.
    let tunnel = crate::secure_key::admitted_tunnel(model, tool_key_source, tool_key.is_some())?;
    // A secured System B write also reprograms the security object (issue
    // #156); a program the device cannot hold refuses before the gateway is
    // contacted (issue #537).
    let security = program::plan::security_inputs(
        model,
        target,
        desired,
        &material,
        &secure_sender.into_iter().collect::<Vec<_>>(),
        &tunnel,
        dir,
    )
    .map_err(|e| anyhow::anyhow!("{target}'s security object cannot be programmed: {e}"))?;

    // Safety envelope (issue #74).
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);

    // ONE tunnel for the whole command: the read, the confirmation, the
    // backup and the write run over it; `BusSession` closes it on every exit.
    let runtime = tokio::runtime::Runtime::new()?;
    let bus = BusSession::open(
        &runtime,
        config,
        bussard_service::WritePolicy::transmit(allow_remote_gateway),
    )?;
    let service = bus.service();
    let source = runtime.block_on(service.checked_source(overrides.skip_address_check))?;

    // The read: identity, live tables, parameter memory (with product data),
    // PID 54 and PID 61, on one session. The device facts (issue #209) spare
    // the reader its object walk and seed the write and read-back.
    let mut facts = crate::conn_cmd::facts_cache(dir, model.is_some(), overrides.refresh_facts);
    // A device reset to default answers only under its FDSK (issue #532).
    let read_options = L4Options::secured(source, tool_key.clone(), secure_seq.clone())
        .with_factory_key(material.fdsk.clone())
        .with_authorize(bussard_service::status::read_only_authorize(
            &mut facts, target,
        ));
    let request = program::read::ReadRequest {
        target,
        model,
        product: write.product,
        facts: &facts,
        tunnel: &tunnel,
        secured: tool_key.is_some(),
        // The apply may change the flags: the next plan reads PID 61 again
        // (issue #336).
        flags_cache: program::read::FlagsCache::Forget { dir },
        properties: None,
    };
    let read = runtime.block_on(program::read::read_device(service, &read_options, &request))?;
    let seed = read.seed();

    // One identity verdict (issue #228, item 5): a device that reports
    // another application (or mask) than bussard.lock pins needs a flash
    // first. A restore writes a backup, not the model: it only reports it.
    if let Some(check) = read.check() {
        eprintln!("{}", bussard_service::identity_line(target, check));
        if matches!(origin, DesiredSource::Model)
            && let Some(err) = bussard_service::drift_refusal(target, check, "apply to")
        {
            eprintln!("{err}");
            return Ok(ExitCode::FAILURE);
        }
    }
    let read = match read.into_tables() {
        Ok(read) => read,
        Err((address, mask)) => {
            // A property-only load procedure (issue #390) has no tables to
            // apply: its properties are written by `flash`.
            if write
                .product
                .and_then(|p| p.app())
                .is_some_and(bussard_service::download::has_no_group_objects)
            {
                eprintln!(
                    "{address}'s application has no group objects and no tables to apply; \
                     `bussard plan {address}` shows its properties and `bussard flash {address}` \
                     writes them"
                );
                return Ok(ExitCode::FAILURE);
            }
            plan_cmd::report_unsupported_mask(origin.verb(), address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let tables = read.live.tables();
    // The family gate, asserted again before any write.
    if let Some(refusal) = program::plan::family_refusal(target, tables.mask) {
        eprintln!("{refusal}");
        return Ok(ExitCode::FAILURE);
    }

    // The model's plan, in its own words, with the tunnel admission (issue
    // #297) and the security-object change (issue #331). `restore` keeps the
    // table rendering (its truth is a backup).
    let planned = match (origin, model) {
        (DesiredSource::Model, Some(model)) => Some(program::plan::plan_device(
            &program::plan::PlanInputs {
                model,
                target,
                gateway: &gateway,
                dir,
                desired,
                tunnel: &tunnel,
                group_keys: material.group_keys.as_ref(),
                parameters_skipped: None,
            },
            &read,
        )),
        _ => None,
    };
    let report = match &planned {
        Some(planned) => planned.report.clone(),
        None => program::plan::table_plan(&read, desired),
    };
    match &planned {
        Some(planned) => {
            let built = &planned.built;
            if let Some(hash) = write.plan_hash
                && !hash.trim().eq_ignore_ascii_case(&built.plan.state_hash)
            {
                eprintln!(
                    "refusing to apply to {target}: the device state no longer matches the plan \
                     (plan {}, device now {}). Run `bussard plan {target}` again and approve \
                     the new plan.",
                    hash.trim(),
                    built.plan.state_hash
                );
                return Ok(ExitCode::FAILURE);
            }
            print!(
                "{}",
                crate::plan_view::render(&built.plan, crate::style::Style::stdout())
            );
            if let Some(refusal) = &built.refusal {
                eprintln!(
                    "{}",
                    crate::style::Style::stderr()
                        .error_line(&format!("refusing to apply to {target}: {refusal}"))
                );
                return Ok(ExitCode::FAILURE);
            }
        }
        None => {
            if matches!(origin, DesiredSource::Backup(_)) {
                println!("restoring {} to {target}", origin.origin());
            }
            plan_cmd::print_text(target, tables, &report);
        }
    }
    let built = planned.as_ref().map(|p| &p.built);
    let partial = built.and_then(|b| b.partial.as_ref());
    let param_detail = read.params.as_ref().and_then(|p| p.detail.as_ref());
    // The System 7 region images refuse before anything is confirmed, backed
    // up or written.
    let images = program::plan::sys7_images(&read, desired)
        .context("computing the System 7 table images")?;

    // Zero-change: nothing to do, WITHOUT touching load states. A missing
    // tunnelling address, a security-flag change and a System 7
    // communication flag that does not follow its links rewrite the tables
    // too; a System B group-object table that differs from the full flash's
    // image is reloaded (issue #540).
    let admits = planned
        .as_ref()
        .and_then(|p| p.admission.as_ref())
        .is_some_and(|a| a.changes());
    let flags_change = planned
        .as_ref()
        .and_then(|p| p.security_change.as_ref())
        .is_some_and(|c| c.changes());
    let object_flags = images
        .as_ref()
        .is_some_and(|images| !images.flag_writes.is_empty());
    let tables_change = !report.is_noop() || admits || flags_change || object_flags;
    let object_table = built.and_then(|b| b.object_table.as_deref());
    if !tables_change && object_table.is_none() && partial.is_none() {
        return Ok(ExitCode::SUCCESS);
    }

    // Data Secure: say what the security object will receive (never a key).
    let security = security.filter(|_| images.is_none());
    if let Some(inputs) = &security {
        println!("{}", inputs.describe(&desired.addresses));
    }

    // Ask once for the whole write; on a yes the history snapshot records
    // what the installation was asked to become (`bussard undo`).
    let verb = origin.verb();
    let mut observer = crate::progress::Terminal::new(yes, false)
        .tables(format!("{verb} {target}: writing the tables"))
        .snapshot(
            dir,
            bussard_model::history::SnapshotReason::new(verb)
                .with_args([target.to_string()])
                .with_gateway(Some(gateway.clone()))
                .with_result(if partial.is_some() {
                    "before writing the device tables and parameters"
                } else {
                    "before writing the device tables"
                }),
        );
    let changes = report.additions.len() + report.removals.len();
    let question = program::Question {
        kind: bussard_service::observer::Ask::Write,
        prompt: match built {
            // The question the MCP approval asks too (issue #1052).
            Some(built) => bussard_service::params::apply_question(&built.plan, partial),
            None => format!("{verb} {changes} change(s) to {target} via {gateway}?"),
        },
        action: format!("{verb} {target} via {gateway}"),
    };
    match program::ask(&mut observer, &question) {
        Ok(()) => {}
        Err(program::Declined::No) => {
            eprintln!("aborted; nothing was written.");
            return Ok(ExitCode::FAILURE);
        }
        Err(program::Declined::Refused(refusal)) => anyhow::bail!("{refusal}"),
    }

    // Back up the pre-state before writing anything; a restore takes one too.
    // A parameter backup of no memory restores nothing (issue #944).
    if let Some(detail) = partial.and(param_detail) {
        program::apply::check_parameter_backup(detail)
            .context("writing the parameter backup (refusing to write without a backup)")?;
    }
    let backups = program::apply::back_up(dir, target, &read.live, partial.and(param_detail));
    let backups = match backups {
        Ok(backups) => backups,
        Err(err @ program::apply::BackupError::Tables(_)) => {
            return Err(anyhow::Error::new(err).context(format!(
                "writing the pre-{verb} backup (refusing to write without a backup)"
            )));
        }
        Err(err) => {
            return Err(anyhow::Error::new(err)
                .context("writing the parameter backup (refusing to write without a backup)"));
        }
    };
    let backup_path = backups.tables.clone().unwrap_or_default();
    println!(
        "{}",
        crate::style::Style::stdout().dim(&format!("backup written to {}", backup_path.display()))
    );
    if let Some(path) = &backups.parameters {
        println!("parameter backup written to {}", path.display());
    }
    let written = runtime.block_on(program::apply::apply_device(
        program::apply::ApplyRequest {
            service,
            target,
            source,
            dir,
            model,
            product: write.product,
            mask: tables.mask,
            desired,
            tables_change,
            object_table,
            images: images.as_ref(),
            security: security.as_ref(),
            parameters: partial.zip(param_detail),
            tool_key,
            high_water: secure_seq,
            options: read_options,
            seed,
        },
        &mut observer,
    ));
    render_written(
        target,
        verb,
        dir,
        &report,
        written,
        &backup_path,
        backups.parameters.as_deref(),
    )
}

/// Prints how the write went, in the order it ran; the exit code says
/// whether the device holds what was written.
fn render_written(
    target: IndividualAddress,
    verb: &str,
    dir: &Path,
    report: &PlanReport,
    mut written: program::apply::Written,
    backup_path: &Path,
    param_backup: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    // A bus that could not be leased stops the command, as any session error.
    if let Some(program::apply::TablesWritten::Lease(_)) = &written.tables
        && let Some(program::apply::TablesWritten::Lease(err)) = written.tables.take()
    {
        return Err(err.into());
    }
    let (out, err) = (crate::style::Style::stdout(), crate::style::Style::stderr());
    let mut code = ExitCode::SUCCESS;
    match &written.tables {
        // Handled above.
        Some(program::apply::TablesWritten::Lease(_)) => {}
        Some(program::apply::TablesWritten::Failed(why)) => {
            eprintln!("\n{}", err.error_line(&format!("{verb} failed: {why}")));
            recovery_notice(backup_path, target);
            return Ok(ExitCode::FAILURE);
        }
        Some(program::apply::TablesWritten::Ran(summary)) if !summary.ok => {
            eprintln!(
                "\n{}",
                err.error_line(&format!("{verb} did not verify: {}", summary.detail))
            );
            recovery_notice(backup_path, target);
            code = ExitCode::FAILURE;
        }
        Some(program::apply::TablesWritten::Ran(summary)) => {
            if let Some(table) = &summary.object_table {
                println!(
                    "\ngroup-object table reloaded and read back: {} ({} entries)",
                    table.state, table.entries
                );
            }
            println!(
                "\n{}",
                out.ok(&format!(
                    "{verb} verified: address table {} ({} entries), association table {} ({} \
                     entries)",
                    summary.address_state,
                    report.resulting_address_count,
                    summary.association_state,
                    report.resulting_association_count,
                ))
            );
        }
        None => {}
    }
    match &written.restarted {
        Some(Ok(after)) => println!(
            "restarted {target}: it answered again after {:.1} s",
            after.as_secs_f64()
        ),
        Some(Err(why)) => {
            eprintln!("\n{}", err.error_line(&format!("{verb} {target}: {why}")));
            recovery_notice(backup_path, target);
            return Ok(ExitCode::FAILURE);
        }
        None => {}
    }
    // The verified secured write's PID 54 table and PID 61 flags, saved to
    // the lock as `adopt` does (issues #297, #331).
    let records = [
        (
            &written.lock.senders,
            "security individual address table (PID 54",
            ("sender", "senders"),
        ),
        (
            &written.lock.flags,
            "group-object security flags (PID 61",
            ("secured object", "secured objects"),
        ),
    ];
    for (recorded, what, (one, many)) in records {
        match recorded {
            Some((Ok(true), count)) => println!(
                "saved {target}'s {what}, {}) to your project",
                crate::style::count(*count, one, many)
            ),
            Some((Err(why), _)) => eprintln!("{}", err.warning_line(why)),
            _ => {}
        }
    }
    match &written.parameters {
        Some(Ok(bussard_service::download::ParamWriteOutcome::Verified { octets, .. })) => {
            println!(
                "{}",
                out.ok(&format!(
                    "parameters verified: {octets} changed octet(s) read back from {target}; the \
                 application is Loaded"
                ))
            )
        }
        Some(Ok(failed)) => {
            eprintln!(
                "\n{}",
                err.error_line(&failed.failure().unwrap_or_default())
            );
            if let Some(path) = param_backup {
                eprintln!(
                    "The pre-apply parameter memory was backed up to:\n    {}\nRe-running \
                     `bussard apply {target}` rewrites only the octets that still differ.",
                    path.display()
                );
            }
            code = ExitCode::FAILURE;
        }
        Some(Err(why)) => anyhow::bail!("{why}"),
        None => {}
    }
    // Verified means read back and compared (issues #319, #349).
    let Some(readback) = &written.readback else {
        return Ok(code);
    };
    for note in &readback.notes {
        eprintln!("{}", err.warning_line(note));
    }
    match readback.failure() {
        Some(failure) => {
            eprintln!(
                "\n{}",
                err.error_line(&format!("{verb} {target}: {failure}"))
            );
            if code == ExitCode::SUCCESS {
                recovery_notice(backup_path, target);
            }
            Ok(ExitCode::FAILURE)
        }
        None => {
            println!(
                "{}",
                out.ok(&format!(
                    "read back from {target} and compared with your project: {}",
                    readback.summary()
                ))
            );
            if code == ExitCode::SUCCESS
                && let Some(hint) = crate::export_cmd::stale_export_hint(dir)
            {
                eprintln!("{hint}");
            }
            Ok(code)
        }
    }
}

/// Prints the loud recovery guidance on any apply failure.
fn recovery_notice(backup_path: &Path, target: IndividualAddress) {
    eprintln!(
        "\nThe device may be left with partially-written or unloaded tables.\n\
         The pre-apply state was backed up to:\n    {}\n\
         Recover by re-running `bussard apply {target}` (the tables are rewritten\n\
         wholesale, so a re-apply is safe and idempotent), or by re-downloading the\n\
         device with ETS. Do not assume the device is functional until a re-apply or\n\
         `bussard plan {target}` reports no differences.",
        backup_path.display()
    );
}
