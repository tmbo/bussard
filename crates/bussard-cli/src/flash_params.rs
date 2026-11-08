//! `bussard flash --parameters-only`: rewrite only a device's parameter memory
//! (issue #119).
//!
//! The full `flash` pipeline builds the plan and runs the read-only pre-flight
//! probe; this module takes over from there:
//!
//! 1. **Refuse** unless the device runs the very application the product file
//!    describes (System B: `PID_PROGRAM_VERSION` matches; System 7, which has no
//!    readable application id: every load-state machine is `Loaded` and the
//!    application's code segments read back as the product's bytes).
//! 2. Read the parameter memory back and cut the full plan down to it
//!    (`FlashPlan::parameters_only`). Refuse when a parameter segment cannot
//!    be read, or when the new values would change the group-object table (a
//!    parameter that shows or hides a com-object needs the full flash). On
//!    System 7, also refuse when the model's links differ from the device's
//!    link tables: the table load-state machines are not reloaded (`apply`
//!    rewrites them).
//! 3. Show the plan: the parameters that change, the regions and octets.
//!    Nothing to change exits 0 without touching a load state.
//! 4. Confirm (a terminal, or `--yes`), snapshot the model history, and back up
//!    the parameter memory before the first write.
//! 5. Write only the changed octets, complete the load, restart, and verify by
//!    reading the parameter memory back.

use std::process::ExitCode;

use anyhow::Context as _;
use bussard_service::program::flash::{FlashRequest, Probed};
use bussard_service::program::params_only::{
    self, ParamsSession, ParamsWrite, ParamsWriteError, ParamsWritten,
};
use bussard_service::program::report;

/// Everything the parameter-only download needs from the `flash` pipeline.
pub(crate) struct Context<'a> {
    /// The command's runtime (one tunnel for the whole command).
    pub runtime: &'a tokio::runtime::Runtime,
    /// The flash request the pre-flight ran with.
    pub request: &'a FlashRequest<'a>,
    /// The resolved gateway, for the prompt and the history.
    pub gateway: String,
    /// `--yes`.
    pub yes: bool,
    /// `--json`.
    pub json: bool,
    /// What the pre-flight found (its kept connection already handed over).
    pub probed: Probed,
    /// The pre-flight's connection, kept under `--yes` for the write session
    /// (issue #213). It holds the bus lease, so it is released before any
    /// other session opens.
    pub handover: crate::flash_handover::Handover<'a>,
}

/// Runs the parameter-only download (module docs).
pub(crate) fn run(mut ctx: Context<'_>) -> anyhow::Result<ExitCode> {
    let req = ctx.request;
    let (target, app, plan) = (req.target, req.inputs.app(), &ctx.probed.plan);
    let refuse = |reason: String| {
        eprintln!("refusing the parameter-only download to {target}: {reason}");
        Ok(ExitCode::FAILURE)
    };
    if let Err(reason) = params_only::identity_gate(plan, ctx.probed.resident.as_ref()) {
        return refuse(reason);
    }
    let session = ParamsSession {
        service: req.service,
        target,
        bcu_key: req.bcu_key,
        tool_key: req.material.tool_key.clone(),
        high_water: req.high_water.clone(),
        max_apdu: ctx.probed.facts.max_apdu,
    };
    // The parameter memory (and, on System 7, the code segments that stand in
    // for the application id), read on the pre-flight connection (issue
    // #215), or over a read-only session of its own when the pre-flight did
    // not.
    let read = match ctx.probed.params.take() {
        Some(read) => read,
        None => {
            ctx.handover.release();
            ctx.runtime
                .block_on(params_only::read_parameters(&session, plan, app))
                .with_context(|| format!("connecting to {target} to read its parameters"))?
        }
    };
    let planned = match params_only::plan_parameters_only(target, req.inputs, plan, read) {
        Ok(planned) => planned,
        Err(reason) => return refuse(reason),
    };
    if ctx.json {
        crate::output::report(&report::ParamsPlanReport::new(target, &planned))?;
    } else {
        print!("{}", report::params_plan_text(target, &planned));
    }
    if planned.is_noop() {
        println!(
            "\nnothing to do: {target} already holds these parameter values (no load state touched)"
        );
        return Ok(ExitCode::SUCCESS);
    }
    let mut observer = crate::progress::Terminal::new(ctx.yes, ctx.json).snapshot(
        req.dir,
        bussard_model::history::SnapshotReason::new("flash --parameters-only")
            .with_args([target.to_string()])
            .with_gateway(Some(ctx.gateway.clone()))
            .with_result("before downloading the parameters"),
    );
    let write = ParamsWrite {
        question: planned.question(target, &ctx.gateway),
        session,
        source: req.source,
        dir: req.dir,
        plan,
        app,
        facts: ctx.probed.facts.clone(),
        handover: ctx.handover.take(),
    };
    let written = ctx.runtime.block_on(params_only::write_parameters_only(
        write,
        &planned,
        &mut observer,
    ));
    let (backup, outcome, verified) = match written {
        Ok(ParamsWritten::Ran {
            backup,
            outcome,
            verified,
        }) => (backup, outcome, verified),
        Ok(ParamsWritten::Declined) => {
            eprintln!("aborted: nothing written.");
            return Ok(ExitCode::FAILURE);
        }
        Err(ParamsWriteError::Backup(err)) => {
            return Err(anyhow::Error::new(err)
                .context("writing the parameter backup (refusing to write without a backup)"));
        }
        Err(ParamsWriteError::Refused(refusal)) => anyhow::bail!("{refusal}"),
        Err(ParamsWriteError::Session(err)) => {
            return Err(anyhow::Error::new(err)
                .context(format!("connecting to {target} to read its parameters")));
        }
    };
    let failed = |what: String| {
        eprintln!("\nERROR: {what}");
        recovery_notice(target, &backup);
        Ok(ExitCode::FAILURE)
    };
    match (&outcome, verified) {
        (Ok(done), Some(Ok(octets))) if done.ok() => {
            let props = match planned.properties.len() {
                0 => String::new(),
                n => format!(" and {n} property value(s)"),
            };
            println!(
                "\nparameters verified: {octets} changed octet(s){props} read back from {target}; \
                 the application is Loaded"
            );
            Ok(ExitCode::SUCCESS)
        }
        (Ok(done), Some(Err(reason))) if done.ok() => {
            failed(format!("the parameter read-back does not match: {reason}"))
        }
        (Ok(done), _) => failed(format!("the parameter download did not verify: {done:?}")),
        (Err(err), _) => failed(format!("the parameter download failed: {err}")),
    }
}

/// `flash --parameters-only --dry-run`: the op sequence the download would
/// send, planned offline (no connection).
pub(crate) fn dry_run(
    target: bussard_model::IndividualAddress,
    offline: &bussard_service::program::flash::Offline,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let partial = match params_only::dry_run(&offline.plan) {
        Ok(partial) => partial,
        Err(err) => {
            eprintln!("refusing the parameter-only download to {target}: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if json {
        crate::output::report(&report::ParamsPlanReport::dry_run(target, &partial))?;
    } else {
        print!("{}", report::params_dry_run_text(target, &partial));
    }
    eprintln!("dry run: no connection opened, nothing written.");
    Ok(ExitCode::SUCCESS)
}

/// Prints the recovery guidance after a failed parameter download.
fn recovery_notice(target: bussard_model::IndividualAddress, backup: &std::path::Path) {
    eprintln!(
        "\nThe device may be left with partly-written parameters or an application that is not\n\
         Loaded. The parameter memory before the download was saved to:\n    {}\n\
         If the application still reads Loaded, re-running `bussard flash --parameters-only\n\
         {target}` rewrites only the octets that still differ. If it is not Loaded (load state\n\
         Error or Loading), recover with a full `bussard flash --force {target}`, which\n\
         reloads every load-state machine. Do not assume the device works until a read-back\n\
         (`bussard plan {target}`) shows no parameter difference.",
        backup.display()
    );
}
