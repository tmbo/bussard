//! The `bussard reconstruct` subcommand — read a device's tables back over the
//! bus and diff them against the model.
//!
//! Connects to a single device, reads its group-address and association tables,
//! resolves them to com-object → GA assignments, and diffs the result against the
//! links in the model's device file for that device. **System B** (mask `x7B0`) serves
//! those tables as interface-object properties (see [`bussard_mgmt::tables`]);
//! **System 7** (mask `0705` / `0701`) keeps them in absolute memory at `0x4000`
//! / `0x4201` and is read by [`bussard_download::tables_sys7`] (issue #91). The
//! report and the diff below are the same for both.
//!
//! The report and its diff are [`bussard_service::reconstruct::build_report`],
//! the function `knx_reconstruct_device` calls too (issue #717).
//!
//! The command is **read-only on the bus**: it only ever sends
//! `A_DeviceDescriptor_Read`, `A_Authorize_Request`, `A_PropertyValue_Read` and
//! (on the System 7 and System B fallback paths) `A_Memory_Read`.
//!
//! A KNX Data Secure-activated device answers the plain descriptor read with
//! mask `FFFF` and refuses the rest. With `--keyring` / `--tool-key` (issue
//! #170) the session is opened through [`bussard_service::BusService::with_l4`]
//! with the device's tool key, so every APDU above, the descriptor read
//! included, rides `A_SecureData` and the device reports its real mask.
//!
//! ## What the diff can and cannot see
//!
//! The address + association tables recover *which* GAs each com-object is
//! linked to, but not the transmit direction: the send/listen distinction lives
//! in the group object table's flags, which many devices do not expose readably.
//! The diff therefore compares **GA sets per object** — a model `send:` and a
//! model `listen:` entry are treated alike.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use bussard_model::IndividualAddress;
use bussard_model::schema::{
    BussardConfig, Connection as ModelConnection, Transport as ModelTransport,
};
use bussard_service::WritePolicy;
use bussard_service::reconstruct::{ReconstructReport, build_report};
use bussard_service::reconstruct_line::{
    LineSummary, OutDir, PER_ADDRESS_ESTIMATE, SweepObserver, build_summary, check_out_dir,
    discovery_timeouts, inject_reconstruct_banners, sweep_line, synthesize_model,
};
use bussard_transport::TransportKind;

use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, load_model_optional, load_model_required, open_service,
    resolve_config,
};
use crate::scan_cmd::parse_line;

/// Runs `bussard reconstruct`.
pub fn run(
    address: &str,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
    selection: crate::param_readback::Selection<'_>,
    no_parameters: bool,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    // A management command: a present-but-broken model is a hard error.
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // The product file the parameter read-back decodes with (issue #119).
    // `--no-parameters` (issue #215) wants the links and tables only: no
    // product is resolved or parsed, so no parameter memory is read.
    // A read-only command only warns about an override that contradicts the
    // lock (issue #228, item 4).
    if let Some(device) = model.as_ref().and_then(|m| m.devices.get(&target))
        && let Some(conflict) = crate::lock_pin::override_conflict(
            &device.device,
            selection.product,
            selection.application,
        )?
    {
        eprintln!("warning: {conflict}");
    }
    let product = if no_parameters {
        None
    } else {
        crate::param_readback::resolve(
            dir,
            selection,
            model.as_ref(),
            target,
            crate::param_readback::MissingProduct::Warn,
        )?
    };
    let model_ref = model.as_ref();
    let product_ref = product.as_ref();

    let facts = crate::device_facts::cache(dir, model.is_some(), overrides.refresh_facts);
    let (read_result, params, identity, _, _, _) = crate::plan_cmd::read_device(
        config,
        target,
        &overrides,
        tool_key_source,
        product_ref,
        model_ref,
        facts,
        &[],
        None,
        None,
    )?;
    let live = match read_result {
        crate::plan_cmd::LiveRead::Tables(live) => live,
        crate::plan_cmd::LiveRead::UnsupportedMask { address, mask } => {
            crate::plan_cmd::report_unsupported_mask("reconstruct", address, mask);
            return Ok(ExitCode::FAILURE);
        }
    };
    let read = live.tables();

    let mut report = build_report(target, read, model.as_ref());
    report.parameters = params.map(|p| p.readback);
    report.identity = identity.map(|reported| {
        bussard_model::identity::IdentityCheck::compare(
            model_ref
                .and_then(|m| m.devices.get(&target))
                .map(|d| &d.device),
            reported,
        )
    });
    if json {
        crate::output::print(crate::output::schema::RECONSTRUCT, &report)?;
    } else {
        print_text(&report);
        if let Some(identity) = &report.identity {
            println!("{}", crate::device_facts::identity_line(target, identity));
        }
        match &report.parameters {
            Some(params) => crate::param_readback::print_text(params, target),
            None if no_parameters => {}
            None => crate::param_readback::print_missing_product_note(model.as_ref(), target),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the human-readable report with the diff prominent.
fn print_text(report: &ReconstructReport) {
    println!(
        "device {} — mask {} ({})",
        report.address, report.mask, report.system_type
    );
    for (table, source) in &report.table_source {
        println!("  {table} table read via {source}");
    }
    for note in &report.notes {
        println!("  note: {note}");
    }
    println!(
        "\ninventory: {} group address(es), {} association(s), {} linked object(s)",
        report.addresses.len(),
        report.associations.len(),
        report.objects.len()
    );
    for (object, gas) in &report.objects {
        println!("  object {object:>4}: {}", gas.join(", "));
    }

    let Some(diff) = &report.diff else {
        println!("\nno model loaded — skipping the diff");
        return;
    };
    println!(
        "\ndiff against the model ({} match, {} only on device, {} only in model):",
        diff.matches.len(),
        diff.on_device_not_in_model.len(),
        diff.in_model_not_on_device.len()
    );
    if diff.on_device_not_in_model.is_empty() && diff.in_model_not_on_device.is_empty() {
        println!("  device tables and model links agree");
    }
    for pair in &diff.on_device_not_in_model {
        println!(
            "  + on device, not in model: object {:>4} → {}",
            pair.object, pair.ga
        );
    }
    for pair in &diff.in_model_not_on_device {
        println!(
            "  - in model, not on device: object {:>4} → {}",
            pair.object, pair.ga
        );
    }
    println!("  note: {}", diff.note);
}

// ===========================================================================
// Line mode: `bussard reconstruct --line 1.1 --out <fresh-dir>`
//
// Sweeps a whole line like `bussard scan` (short discovery timeouts, one
// connection at a time, progress on stderr), reads every System B device's
// tables, and synthesizes a fresh, ETS-less model into `--out`:
//
//   groups.toml            — every GA seen across all tables, placeholder names,
//                            no DPT (validation warns W011; that is honest).
//   devices/<ia>.toml      — object → GA sets. Direction is unrecoverable from
//                            the tables, so every GA is recorded as `listen`.
//   bussard.lock           — mask + best-effort product facts; a minimal
//                            com-object stub per linked object so the model
//                            validates (the flags/DPTs are placeholders).
//   bussard.toml           — the connection actually used for the sweep.
//
// Every synthesized hand-editable file carries a reconstruction banner
// injected after `Model::save` (the generated lock keeps its own) that says the
// model came from table read-back and that names, DPTs and directions still
// need human/monitor annotation.
// ===========================================================================

/// Runs `bussard reconstruct --line`.
pub fn run_line(
    line: &str,
    from: u8,
    to: u8,
    out: Option<&Path>,
    dir: &Path,
    json: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let (area, line_no) = parse_line(line)?;
    if from > to {
        return Err(anyhow!(
            "invalid range: --from {from} is greater than --to {to}"
        ));
    }
    let out = out.ok_or_else(|| {
        anyhow!(
            "--out <dir> is required in line mode (the fresh model directory to synthesize into)"
        )
    })?;
    ensure_empty_out(out)?;

    // The model dir here only supplies connection defaults; the synthesized
    // model is written to --out, never merged into it. A present-but-broken
    // model dir is still a hard error.
    let model = load_model_required(dir)?;
    crate::history_cmd::capture_external_edit(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;

    let count = to as u32 - from as u32 + 1;
    let estimate = PER_ADDRESS_ESTIMATE * count;
    eprintln!(
        "sweeping line {area}.{line_no}.{from}–{to} sequentially — estimated up to {}m{:02}s on TP1",
        estimate.as_secs() / 60,
        estimate.as_secs() % 60
    );

    // The sweep's runtime block consumes what it captures, but `overrides` is
    // still needed afterwards to seed the synthesized model's connection block.
    let conn = overrides.clone();
    let runtime = tokio::runtime::Runtime::new()?;
    let found = runtime.block_on(async move {
        let service = open_service(config, WritePolicy::ReadOnly).await?;
        let source = checked_source_or_close(&service, &conn).await?;
        let mut progress = Progress(crate::progress::SweepDisplay::new(
            "reconstructing",
            usize::from(to.saturating_sub(from)) + 1,
            json,
        ));
        let found = tokio::select! {
            found = sweep_line(
                &service,
                area,
                line_no,
                from,
                to,
                source,
                discovery_timeouts(),
                &mut progress,
            ) => {
                progress.0.finish();
                eprintln!(
                    "\rsweep complete: {} device(s) found            ",
                    found.len()
                );
                found
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Vec::new()
            }
        };
        service.close().await;
        anyhow::Ok(found)
    })?;

    let model = synthesize_model(&found, model_config(&overrides, dir));
    model
        .save(out)
        .with_context(|| format!("writing the reconstructed model to {}", out.display()))?;
    inject_reconstruct_banners(out)?;
    // `--out` must be empty, so there is no prior state to preserve; the
    // snapshot records the reconstructed model itself as the baseline the next
    // edit is measured against (issue #110).
    crate::history_cmd::snapshot(
        out,
        bussard_model::history::SnapshotReason::new("reconstruct")
            .with_args([line.to_string()])
            .with_result("the model reconstructed from the line sweep"),
    );

    let summary = build_summary(line, out, &found, &model);
    if json {
        crate::output::print(crate::output::schema::RECONSTRUCT_LINE, &summary)?;
    } else {
        print_line_summary(&summary);
    }
    Ok(ExitCode::SUCCESS)
}

/// Fails if `out` exists and is a non-empty directory (or a file). Reconstruction
/// must never merge into an existing model.
fn ensure_empty_out(out: &Path) -> anyhow::Result<()> {
    match check_out_dir(out)? {
        OutDir::Fresh => Ok(()),
        OutDir::File => Err(anyhow!(
            "--out {} is a file; expected a fresh (absent or empty) directory",
            out.display()
        )),
        OutDir::NotEmpty => Err(anyhow!(
            "--out {} is not empty; reconstruction never merges into an existing model \
             (choose a fresh directory)",
            out.display()
        )),
    }
}

/// The CLI's sweep progress: a line rewritten in place, or the live view on
/// an interactive terminal (issue #147).
struct Progress(crate::progress::SweepDisplay);

impl SweepObserver for Progress {
    fn probing(&mut self, addr: IndividualAddress, found: usize) {
        self.0.probing(addr, found);
    }

    fn advance(&mut self) {
        self.0.advance();
    }
}

/// Builds the `bussard.toml` config recording the connection actually used.
fn model_config(overrides: &ConnOverrides, dir: &Path) -> BussardConfig {
    // Reuse the resolved transport shape. Fall back to the input model's config
    // for the gateway/multicast text when no override was given.
    let base = load_model_optional(dir).map(|m| m.config.connection);
    let resolved = resolve_config(None, overrides);
    // The keyring setting is the operator's, not derived from the connection
    // used: carry it over from the input model.
    let keyring = base.as_ref().and_then(|c| c.keyring.clone());
    let admit_tunnel_senders = base.as_ref().is_some_and(|c| c.admit_tunnel_senders);

    let connection = match resolved {
        Ok(cfg) if cfg.transport == TransportKind::Routing => ModelConnection {
            transport: ModelTransport::Routing,
            gateway: None,
            multicast: Some(cfg.multicast.to_string()),
            keyring,
            admit_tunnel_senders,
        },
        Ok(cfg) => ModelConnection {
            transport: ModelTransport::Tunnel,
            gateway: cfg.gateway.map(|g| g.to_string()),
            multicast: None,
            keyring,
            admit_tunnel_senders,
        },
        // No override resolvable on its own (e.g. tunnel with no gateway flag):
        // fall back to whatever the input model had.
        Err(_) => base.unwrap_or_default(),
    };
    BussardConfig {
        connection,
        // Reconstruction infers nothing about project lint policy.
        lint: None,
        import: None,
        home_assistant: None,
        enroll: None,
    }
}

/// Prints the human-readable line-mode summary with next steps.
fn print_line_summary(s: &LineSummary) {
    println!("reconstructed line {} into {}", s.line, s.out);
    println!(
        "\n{} device(s) responded: {} read (System B), {} recorded as stubs",
        s.devices_found, s.devices_read, s.devices_skipped
    );
    for d in &s.device_details {
        match d.status {
            "read" => println!(
                "  {}  mask {} ({})  — {} GA(s), {} link(s)",
                d.address, d.mask, d.system_type, d.group_addresses, d.links
            ),
            _ => println!(
                "  {}  mask {} ({})  — stub: {}",
                d.address,
                d.mask,
                d.system_type,
                d.skip_reason.as_deref().unwrap_or("tables skipped")
            ),
        }
    }
    println!(
        "\nsynthesized {} group address(es) and {} link(s)",
        s.group_addresses, s.links
    );
    println!("\nnext steps:");
    println!(
        "  • names & DPTs are placeholders — run `bussard monitor --dir {}` to observe live",
        s.out
    );
    println!("    traffic and name what each GA does; add `dpt:` in groups.toml as you learn it.");
    println!(
        "  • send/listen direction is unknown (all GAs recorded as listen) — correct it as you"
    );
    println!("    observe which object transmits.");
    println!(
        "  • run `bussard validate --dir {}` — W011 (no DPT) warnings are expected and honest.",
        s.out
    );
}
