//! The `bussard flash` subcommand — first application download into a
//! factory-fresh device (phase 3).
//!
//! The flow mirrors `bussard apply`'s ladder, adapted for an application
//! download:
//! 1. Read the vendor `.knxprod`, select the application program (by `--application`
//!    id, or the sole candidate).
//! 2. Read the device descriptor (mask). Gate on System B (07B0); refuse others.
//! 3. Build a pre-flight `FlashPlan` — this also refuses a mask mismatch or any
//!    unsupported op — and show it. A refused plan exits non-zero before any write.
//! 4. Check the device is **factory-fresh** (issue #79): the read-only probe in
//!    step 2 read the load state of every object this flash would rewrite, plus
//!    the resident application id. A device carrying a *different* application is
//!    refused unless `--force`; an unreadable state is refused as unknown;
//!    re-flashing the *same* application is allowed (it is the documented
//!    recovery path) with a notice. Then state that **no backup is possible** and
//!    confirm on a TTY unless `--yes`.
//! 5. Execute with a progress line, then verify: the application object must be
//!    `Loaded`, and a sample of each written segment is read back.
//! 6. On any failure, print recovery guidance and exit non-zero.
//!
//! # Safety
//!
//! This is a device-mutating command. Per the phase-3 spec the first real flash
//! must happen against the thelsing virtual device or KNX Virtual, not the live
//! reference bus; the mask gate and the pre-flight validation are the guard-rails
//! that keep it from touching an unsupported or mismatched device.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_service::flash::FlashInputs;
use bussard_service::program::flash::{self as flow, FlashChoices, FlashStop};
use bussard_service::program::{Declined, report};

use crate::cli::{Consent, Resolved, Run, Spec, ToolKey};
use crate::conn_cmd::{
    BusSession, enforce_write_gate, gateway_display, load_model_required, resolve_config,
};

/// `bussard flash`.
#[derive(Debug, Clone, Default, clap::Args)]
pub(crate) struct FlashArgs {
    /// The device to program, e.g. `1.0.10`.
    #[arg(value_name = "ADDRESS")]
    pub address: String,
    /// The vendor `.knxprod` (or ETS export) containing the application
    /// program. Default: the archive `bussard.lock` pins for the device in
    /// `<dir>/products/`. One that contradicts the lock needs `--force`,
    /// which also pins it.
    #[arg(long, value_name = "FILE")]
    pub product: Option<PathBuf>,
    /// The application program id (default: the program the lock pins,
    /// else the order number's, else the sole application).
    #[arg(long, value_name = "REF", conflicts_with = "order_number")]
    pub application: Option<String>,
    /// Select the application program by hardware order number (e.g.
    /// `AKK-0216.03`) instead of a raw application ref. Resolved through the
    /// product's hardware catalogue; exactly one match is required.
    #[arg(long, value_name = "ORDER")]
    pub order_number: Option<String>,
    #[command(flatten)]
    pub consent: Consent,
    /// Override the not-factory-fresh refusal: flash a device
    /// that already carries a different application. A flash takes no
    /// backup, so this destroys the resident application, its parameters
    /// and its links. Re-flashing the same application does not need it.
    // Issue #79.
    #[arg(long)]
    pub force: bool,
    /// Skip nothing: re-stream every object. By default an object whose
    /// resident image already matches (MCB size and CRC, object `Loaded`)
    /// is skipped when re-flashing the same application, so a
    /// parameter-only change does not re-download the code segment. On
    /// System 7 (mask 0701/0705) it also first unloads load-state machines
    /// 1 to 4 and restarts the device, as ETS does when its Unload command
    /// precedes the download; a plain flash, like ETS's application
    /// download, sends neither.
    // Issue #488.
    #[arg(long)]
    pub full: bool,
    /// Skip the factory reset before the download. By default a System B
    /// flash of an application that supports Secure and writes filled segments
    /// sparsely, or that replaces a device that is not factory-fresh, first
    /// sends a confirmed master reset (erase code 7): the device erases its application, parameters and links and
    /// keeps its address, so no octet of a previous image survives
    /// where the new one writes nothing. Use this only when you
    /// know the device holds no stale image.
    // Issue #117.
    #[arg(long)]
    pub no_factory_reset: bool,
    /// Rewrite only the parameter memory of a device that already runs this
    /// application: no table write. On System B it runs the
    /// standard's partial download (unload, load, Mode 0 re-allocation that
    /// keeps the memory). Only the octets that differ from what
    /// the device holds are written, then the load completes and the device
    /// restarts. Refused when
    /// the device runs another application or is not Loaded, and when a
    /// changed parameter shows or hides a com-object (that needs a full flash).
    /// The parameter memory is backed up first. With `--dry-run`, prints the
    /// op sequence offline.
    // Issues #119, #543.
    #[arg(long, conflicts_with_all = ["full", "force", "no_factory_reset"])]
    pub parameters_only: bool,
    /// The device's BCU access key, in hex (e.g. `FFFFFFFF` or `0x11223344`),
    /// presented with A_Authorize on every management connect.
    /// Unset presents the free-access key (FFFFFFFF) — correct for an unkeyed
    /// device (ETS uses free access by default). A keyed device needs its
    /// project key here or it will deny access.
    // Issue #52.
    #[arg(long, value_name = "HEX")]
    pub bcu_key: Option<String>,
    #[command(flatten)]
    pub tool_key: ToolKey,
    /// Also list this individual address (bussard's own tunnel address) as a
    /// secured sender, sequence 0, in the security individual address table
    /// (PID 54) the security object is reprogrammed with, so the device
    /// accepts `bussard write --keyring` to its secured group addresses.
    /// Off by default: without it the device drops bussard's secured group
    /// telegrams silently. See https://bussard.tmbo.dev/docs/explanation/safety/.
    #[arg(long, value_name = "IA")]
    pub secure_sender: Option<IndividualAddress>,
    /// Plan offline and stop: no gateway is resolved and no connection is
    /// opened. The plan is checked against the application's own mask.
    #[arg(long)]
    pub dry_run: bool,
    /// With `--dry-run`, write `plan.json` and the exact memory images the
    /// flash would stream (one `.bin` each, plus the table images) into DIR.
    #[arg(long, value_name = "DIR", requires = "dry_run")]
    pub dump_images: Option<PathBuf>,
    /// With `--dry-run`, plan against the device state recorded in FILE
    /// (JSON: the application objects' load states, the application id
    /// and the MCB entries, as `knxtrace image` writes it from an ETS
    /// capture) instead of no device: the freshness verdict, the
    /// product's `par` procedure for a device holding this application,
    /// and the skip of objects whose image already matches take the shape
    /// a live flash takes on that device.
    // Issue #490.
    #[arg(long, value_name = "FILE", requires = "dry_run")]
    pub resident: Option<PathBuf>,
    /// Write the device even though its application program is not on
    /// bussard's list of supported devices (`bussard device --supported`).
    /// Back the device up first. A loopback gateway (a simulator) is never
    /// refused.
    // Issue #1089.
    #[arg(long)]
    pub allow_unsupported: bool,
    /// The grant an outer command (`replace`, `commission`) already made
    /// for this device (issue #1089); never a command-line flag.
    #[arg(skip)]
    pub support: Option<bussard_service::support::SupportGrant>,
}

impl Run for FlashArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json().tool_key(self.tool_key.tool_key.is_some())
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(self, g)
    }
}

/// Flashes an application program from vendor product data into a device.
fn run(args: FlashArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (address, product, bcu_key) = (
        args.address.as_str(),
        args.product.as_deref(),
        args.bcu_key.as_deref(),
    );
    let (application, order_number) = (args.application.as_deref(), args.order_number.as_deref());
    let choices = FlashChoices {
        force: args.force,
        full: args.full,
        no_factory_reset: args.no_factory_reset,
        parameters_only: args.parameters_only,
    };
    let (dir, yes, allow_remote_gateway) = (g.dir(), args.consent.yes, g.allow_remote_gateway);
    let tool_key_source = g.tool_keys(args.tool_key.tool_key.as_deref());
    let overrides = g.mgmt_with_facts();
    let (json, verbose) = (g.json, g.verbose);
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // A flash is a management command: a present-but-broken model is a hard
    // error (its parameter values drive what is written to the device). It is
    // loaded first because it also says whether a device the keyring does not
    // list is security-activated (issue #189).
    let model = load_model_required(dir)?;
    // Issue #321: a value the file stores for a parameter the configuration
    // does not show is not in the image; say so before anything is planned.
    if let Some(m) = model.as_ref() {
        for line in bussard_service::params::ignored_override_notes(m, target, dir) {
            eprintln!("note: {line}");
        }
    }
    // KNX Data Secure (issue #71, spec §6.2): the target's tool key, from the
    // keyring or a raw `--tool-key`; `None` is the plain path. Never printed.
    let activated = bussard_service::secure::model_activated(model.as_ref(), target);
    let secure_material = crate::timing::time("tool keys", || {
        bussard_service::secure::resolve_material(target, tool_key_source, activated)
    })?;
    // The extra secured senders of PID 54: `--secure-sender` and, with
    // `admit_tunnel_senders` (issue #297), the key store's tunnelling
    // addresses.
    let mut extra_senders: Vec<IndividualAddress> = args.secure_sender.into_iter().collect();
    extra_senders.extend(crate::secure_key::admitted_tunnel(
        model.as_ref(),
        tool_key_source,
        secure_material.tool_key.is_some(),
    )?);
    // Unset presents the free-access key on every management connect; a keyed
    // device needs its project BCU key (issue #52).
    let bcu_key = bcu_key.map(parse_bcu_key).transpose()?;

    // The product data: `--product`, else the archive bussard.lock pins for
    // the device in `<dir>/products/`, verified by its SHA-256 (issue #228);
    // a pinned archive that is missing or changed refuses before any bus
    // access.
    let model_device = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    let device_product = model_device.and_then(|d| d.product.clone());
    let product_path = match product {
        Some(path) => path.to_path_buf(),
        None => match model_device
            .map(|d| bussard_service::params::device_archive(dir, d))
            .transpose()?
            .flatten()
        {
            Some(path) => path,
            None => {
                let Some(order) = device_product.as_ref().and_then(|p| p.order_number.clone())
                else {
                    bail!(
                        "no --product given and your project names no product for {target} (the \
                         `product` order number in devices/{target}.toml); pass --product <FILE>"
                    );
                };
                crate::product_store::resolve(dir, None, model_device, &order)?
            }
        },
    };
    // Only the selected program is parsed (issue #214), in the lock's
    // language (issue #231).
    let language = bussard_service::params::model_language(model.as_ref(), dir);
    let pinned_app = device_product
        .as_ref()
        .and_then(|p| p.application_ref.as_deref());
    let product_data = bussard_service::params::read_product(
        &product_path,
        None,
        dir,
        language.as_deref(),
        |catalog| flow::app_selection(catalog, order_number, application, pinned_app),
        Some(crate::timing::record_product_parse),
    )
    .with_context(|| format!("reading product data from {}", product_path.display()))?;
    let app = match flow::select_app(
        &product_data,
        order_number,
        application,
        device_product.as_ref(),
    ) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("{err}");
            return Ok(ExitCode::FAILURE);
        }
    };
    // The image inputs from the model (issue #303): parameter values keyed by
    // ParameterRef id, module bases, the master-template load procedure and
    // the table images from the links.
    let (inputs, malformed) =
        FlashInputs::from_model(&product_data, app, address, model.as_ref(), target);
    let inputs = inputs.for_parameters_only(args.parameters_only);
    for warning in malformed {
        eprintln!("{warning}");
    }

    // `--dry-run` (the offline conformance oracle, #89): no gateway, no
    // connection, nothing recorded in the history.
    if args.dry_run {
        if let Some(device) = model_device
            && let Some(conflict) =
                crate::lock_pin::override_conflict(device, product, application)?
        {
            eprintln!("warning: {conflict} (a dry run writes nothing, so it is not refused)");
        }
        let request = flow::OfflineRequest {
            inputs: &inputs,
            model: model.as_ref(),
            target,
            resident: args.resident.as_deref(),
            choices,
            material: &secure_material,
            extra_senders: &extra_senders,
        };
        return dry_run(&request, args.dump_images.as_deref(), json, verbose);
    }
    // An override that contradicts the lock is refused unless `--force`,
    // which pins the archive for the device (issue #228, item 4).
    if let Some(device) = model_device {
        crate::lock_pin::enforce_override(
            dir,
            device,
            product,
            application,
            choices.force,
            "flash",
        )?;
    }

    let config = resolve_config(model.as_ref(), &overrides)?;
    // Safety envelope (issue #74).
    enforce_write_gate(&config, allow_remote_gateway)?;
    // The supported-device list (issue #1089), for the application this
    // download loads, before the bus is opened.
    let support = crate::support_gate::authorize(
        &config,
        target,
        (model_device, Some(&app.id)),
        args.allow_unsupported,
        args.support.as_ref(),
    )?;
    let gateway = gateway_display(&config);
    // An edit made outside bussard is recorded before this command acts on it.
    crate::history_cmd::capture_external_edit(dir);

    // ONE tunnel for the whole command: the pre-flight, the confirmation and
    // the write phase run over it, and `BusSession` closes it on every exit.
    let runtime = tokio::runtime::Runtime::new()?;
    let bus = BusSession::open(
        &runtime,
        config,
        bussard_service::WritePolicy::transmit(allow_remote_gateway),
    )?;
    let service = bus.service();
    let source = runtime.block_on(service.checked_source(overrides.skip_address_check))?;
    let request = flow::FlashRequest {
        service,
        target,
        source,
        dir,
        model: model.as_ref(),
        inputs: &inputs,
        material: &secure_material,
        extra_senders: &extra_senders,
        // One send-sequence high-water mark for the whole command (§5.9).
        high_water: bussard_service::secure::SequenceHighWater::new(),
        bcu_key,
        facts: crate::conn_cmd::facts_cache(dir, model.is_some(), overrides.refresh_facts),
        choices,
        keep_connection: crate::flash_handover::wanted(yes),
    };
    // Under `--yes` the pre-flight's connection is handed to the write phase
    // (issue #213); declared after the bus session so an unused connection is
    // disconnected before the tunnel closes.
    let mut handover = crate::flash_handover::Handover::new(&runtime);
    let mut probed = match runtime.block_on(flow::probe(&request)) {
        Ok(probed) => probed,
        Err(stop) => return stopped(target, stop, json),
    };
    if let Some(l4) = probed.kept.take() {
        handover.keep(l4);
    }
    if choices.parameters_only {
        return crate::flash_params::run(crate::flash_params::Context {
            runtime: &runtime,
            request: &request,
            gateway,
            yes,
            json,
            probed,
            handover,
            support: &support,
        });
    }
    let planned = match flow::plan_full(&request, probed, &gateway) {
        Ok(planned) => planned,
        Err(stop) => return stopped(target, stop, json),
    };
    let plan = &planned.plan;
    // The identity verdict (issue #228, item 5): a flash is how drift is
    // fixed, so it is not refused here.
    if !json {
        eprintln!("{}", bussard_service::identity_line(target, &planned.check));
    }
    if let (Some(change), false) = (&planned.security_change, json) {
        println!("{}", change.line());
    }
    if json {
        crate::output::report(&report::FlashPlanReport::new(
            target,
            planned.device_mask,
            plan,
            &planned.params,
            planned.security_change.as_ref(),
        ))?;
    } else {
        print!(
            "{}",
            report::flash_plan_text(
                target,
                planned.device_mask,
                plan,
                inputs.overrides(),
                &planned.params,
                verbose,
            )
        );
    }
    // The factory-freshness gate (issue #79): a flash takes no backup.
    if plan.is_property_only() {
        eprintln!(
            "\npre-flight: {target} runs a property-only load procedure: it loads no object \
             and erases nothing; every property it writes is read back after the download."
        );
    } else {
        eprintln!("{}", planned.decision.message);
    }
    if !planned.decision.proceed {
        return Ok(ExitCode::FAILURE);
    }

    let mut observer = crate::progress::Terminal::new(yes, json).snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("flash")
            .with_args([target.to_string()])
            .with_gateway(Some(gateway.clone()))
            .with_result(crate::support_gate::history_result(
                "before flashing the application program",
                &support,
            )),
    );
    let execution = flow::FlashExecution {
        service,
        target,
        source,
        dir,
        plan,
        options: planned.options,
        facts: planned.facts.clone(),
        tool_key: secure_material.tool_key.clone(),
        high_water: request.high_water.clone(),
        handover: handover.take(),
        // Issues #319, #349: the tables, the group-object count, the
        // parameters and the security object, read back on the flash's last
        // connection after the restart.
        readback: Some(bussard_service::flash_flow::ReadbackInputs {
            product: &product_data,
            app,
            model: model.as_ref(),
            device_mask: planned.device_mask,
        }),
        senders: planned.senders.as_deref().filter(|_| model.is_some()),
        question: planned.question(target, &gateway),
        differential: planned.differential(),
        support: &support,
    };
    let written = match runtime.block_on(flow::execute(execution, &mut observer)) {
        Ok(written) => written,
        Err(Declined::No) => {
            eprintln!("aborted — nothing written.");
            return Ok(ExitCode::FAILURE);
        }
        Err(Declined::Refused(refusal)) => bail!("{refusal}"),
    };
    if verbose > 0 {
        eprint!(
            "{}",
            report::flash_timing(&plan.identity.id, planned.preflight, &written)
        );
    }
    let links_note = bussard_service::flash_flow::links_left_note(plan, target);
    Ok(render_outcome(
        target,
        &plan.identity.id,
        &written,
        links_note.as_deref(),
    ))
}

/// Prints how the download ended and what it recorded in the lock; the exit
/// code says whether the device holds the model. `links_note` is said after a
/// verified download that wrote no link table (issue #779).
fn render_outcome(
    target: IndividualAddress,
    id: &str,
    written: &flow::FlashWritten,
    links_note: Option<&str>,
) -> ExitCode {
    let flashed = &written.flashed;
    let readback = flashed.readback.as_ref();
    let verify = match &flashed.outcome {
        Ok(verify) if verify.ok() => verify,
        Ok(verify) => {
            eprintln!("\nERROR: flash did not verify: {verify:?}");
            // Issue #349: the read-back names what differs.
            if let Some(failure) = flashed.failure() {
                eprintln!("ERROR: flash {target}: {failure}");
            }
            eprintln!("{}", bussard_service::flash_flow::recovery_text(target));
            return ExitCode::FAILURE;
        }
        Err(err) => {
            eprintln!("\nERROR: flash failed: {err}");
            eprintln!("{}", bussard_service::flash_flow::recovery_text(target));
            return ExitCode::FAILURE;
        }
    };
    // The application is loaded; the parameters must match the model too, or
    // the flash did not do what the plan said (issue #319).
    let params_failure = flashed.failure();
    let not_compared = readback
        .and_then(|f| f.parameters.as_ref())
        .and_then(|p| p.note.as_ref());
    if let Some(failure) = &params_failure {
        eprintln!("\nERROR: flash {target}: {failure}");
        eprintln!(
            "the application program {id} is {} on {target}, but the device does not hold the \
             configuration in your project; run `bussard plan {target}` to see what is left",
            verify.load_state,
        );
    } else if verify.property_only {
        // A property-only procedure (issue #390) loads no object.
        println!(
            "\nflash verified: the property procedure of {id} ran on {target} and every \
             property it wrote reads back as written",
        );
        if let Some(note) = not_compared {
            eprintln!("note: parameters not compared with your project: {note}");
        }
    } else if let Some(note) = not_compared {
        println!(
            "\nflash verified: application program {id} is {} on {target}",
            verify.load_state,
        );
        eprintln!("warning: parameters not compared with your project: {note}");
    } else {
        println!(
            "\nflash verified: application program {id} is {} on {target}, and its parameters \
             match your project",
            verify.load_state,
        );
    }
    if let Some(readback) = readback {
        for note in readback
            .notes
            .iter()
            .filter(|n| !n.starts_with("parameters not compared"))
        {
            eprintln!("warning: {note}");
        }
        if params_failure.is_none() {
            println!(
                "read back from {target} and compared with your project: {}",
                readback.summary()
            );
        }
    }
    if let (None, Some(note)) = (&params_failure, links_note) {
        println!("{note}");
    }
    // Advisory findings (issue #145) do not fail the flash.
    for warning in &verify.warnings {
        eprintln!("{warning}");
    }
    // The verified flash wrote this PID 54 table and these PID 61 flags:
    // recorded in the lock, as `adopt` does (issues #297, #331).
    let record = written.lock.as_ref();
    let lines = [
        (
            record.and_then(|r| r.senders.as_ref()),
            "security individual address table (PID 54",
            "sender(s)",
        ),
        (
            record.and_then(|r| r.flags.as_ref()),
            "group-object security flags (PID 61",
            "secured object(s)",
        ),
    ];
    for (recorded, what, unit) in lines {
        match recorded {
            Some((Ok(true), count)) => {
                println!("recorded {target}'s {what}, {count} {unit}) in bussard.lock");
            }
            Some((Err(err), _)) => eprintln!("warning: {err}"),
            _ => {}
        }
    }
    if params_failure.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Says why the flash stopped before anything was written.
fn stopped(target: IndividualAddress, stop: FlashStop, json: bool) -> anyhow::Result<ExitCode> {
    match stop {
        // The KNX Virtual IP-medium pattern and a silent Data Secure device
        // are named; any other failure is passed through with context.
        FlashStop::Descriptor {
            connected,
            secure,
            error,
        } => Err(
            match bussard_service::flash_flow::descriptor_read_message(
                target, connected, secure, &error,
            ) {
                Some(message) => anyhow::anyhow!(message),
                None => anyhow::Error::new(error).context("reading the device descriptor"),
            },
        ),
        FlashStop::Service(err) => Err(err.into()),
        FlashStop::Refused { check, reason } => {
            if let (Some(check), false) = (check, json) {
                eprintln!("{}", bussard_service::identity_line(target, &check));
            }
            eprintln!("cannot flash: {reason}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// `flash --dry-run`: the plan against the application's own mask, printed,
/// and (with `--dump-images`) the images it would stream. Opens no
/// connection and resolves no gateway.
fn dry_run(
    request: &flow::OfflineRequest<'_>,
    dump_images: Option<&std::path::Path>,
    json: bool,
    verbose: u8,
) -> anyhow::Result<ExitCode> {
    let (target, inputs) = (request.target, request.inputs);
    let offline = match flow::plan_offline(request) {
        Ok(offline) => offline,
        Err(flow::OfflineStop::Recorded(err)) => return Err(err.into()),
        Err(stop @ flow::OfflineStop::NoMask(_)) => {
            eprintln!("{stop}");
            return Ok(ExitCode::FAILURE);
        }
        Err(flow::OfflineStop::Refused(reason)) => {
            eprintln!("cannot flash: {reason}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if request.choices.parameters_only {
        return crate::flash_params::dry_run(target, &offline, json);
    }
    if let Some(recorded) = &offline.recorded {
        eprintln!(
            "dry run: the recorded device {}; load procedure {}",
            recorded.verdict,
            if recorded.par { "par" } else { "full" }
        );
        if !recorded.skipped.is_empty() {
            eprintln!(
                "dry run: object(s) {:?} skipped: the recorded MCB matches the image",
                recorded.skipped
            );
        }
    }
    if json {
        crate::output::report(&report::FlashPlanReport::new(
            target,
            offline.device_mask,
            &offline.plan,
            &offline.params,
            None,
        ))?;
    } else {
        print!(
            "{}",
            report::flash_plan_text(
                target,
                offline.device_mask,
                &offline.plan,
                inputs.overrides(),
                &offline.params,
                verbose,
            )
        );
    }
    if let Some(dir) = dump_images {
        bussard_service::program::dump::write_dump(
            dir,
            &target.to_string(),
            offline.device_mask,
            &offline.plan,
            inputs.table_images(),
        )?;
        eprintln!("dry run: images written to {}", dir.display());
    }
    eprintln!("dry run: no connection opened, nothing written.");
    Ok(ExitCode::SUCCESS)
}

/// Parses a `--bcu-key` value: a 32-bit access key in hex, with or without a
/// `0x` prefix (e.g. `FFFFFFFF`, `0x11223344`).
///
/// The key is presented with `A_Authorize_Request` on every management connect
/// (issue #52 finding #1). A malformed value is a hard error rather than a
/// silent fall back to free access, so a typo cannot flash a keyed device with
/// the wrong (unprivileged) key and get a confusing access-denied later.
fn parse_bcu_key(raw: &str) -> anyhow::Result<u32> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(hex, 16).with_context(|| {
        format!("parsing --bcu-key {raw:?} as a 32-bit hex access key (e.g. FFFFFFFF)")
    })
}
