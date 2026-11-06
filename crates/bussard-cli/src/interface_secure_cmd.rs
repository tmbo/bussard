//! `bussard interface secure on|off <address>` (issue #398): KNXnet/IP Secure
//! commissioning of a KNX IP interface without ETS.
//!
//! The plan, the wire sequence, the read-back and the key store handling are
//! [`bussard_service::ip_secure`]'s, the same functions the MCP tool
//! `knx_interface_secure` calls. This module loads the model and the key
//! store, prints the plan, asks once, and reports.
//!
//! `--dry-run` opens no connection and writes nothing, not even the key
//! store; `--dump-images DIR` writes the plan's property writes to
//! `DIR/plan.json` (`system: "ip-secure"`) for `knxtrace imgdiff`, the
//! offline oracle against an ETS capture (`scripts/campaign/95-offline-oracle.sh`
//! rows with `run=secure-on` / `run=secure-off`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_project::KeyStore;
use bussard_service::ip_secure::{
    PlanRecordStep, Switch, SwitchContext, SwitchPlan, plan_off, plan_on, probe_gateway,
    run_switch, secured_through,
};
use bussard_service::secure::KEYRING_PASSWORD_ENV;

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{enforce_write_gate, gateway_display, resolve_config};

/// The `bussard interface` subcommands (issue #398).
#[derive(Debug, clap::Subcommand)]
pub(crate) enum InterfaceCommand {
    /// Switch KNXnet/IP Secure of a KNX IP interface on or off, the way ETS
    /// does.
    ///
    /// `on` takes a device in factory state over a plain tunnel: under its
    /// factory key the security mode and a tool key, then under the tool key the
    /// device authentication code, the password hashes of the management and
    /// tunnelling users, the tunnelling users and the secured service
    /// families, and a master reset. Credentials come from the key store
    /// (`bussard.keys`); missing ones are generated and saved there before
    /// the first write. `off` undoes it under the tool key, then again under
    /// the factory key. Both end with a read-back after the restart. The
    /// project files never hold a credential. See https://bussard.tmbo.dev/docs/explanation/safety/ for the recovery.
    // Issue #398.
    Secure(SecureArgs),
}

/// `bussard interface secure`.
#[derive(Debug, clap::Args)]
pub(crate) struct SecureArgs {
    /// `on` or `off`.
    #[arg(value_name = "on|off")]
    state: String,
    /// The interface's address, e.g. `1.1.200`.
    #[arg(value_name = "ADDRESS")]
    address: String,
    /// Print the steps and send nothing (no connection, the key store
    /// unchanged).
    #[arg(long)]
    dry_run: bool,
    /// With --dry-run: write the steps' property writes to DIR/plan.json
    /// for `knxtrace imgdiff` (key material as SHA-256 only).
    #[arg(long, value_name = "DIR", requires = "dry_run")]
    dump_images: Option<PathBuf>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    yes: bool,
    /// Switch the interface bussard tunnels through over a KNXnet/IP
    /// Secure session with that same interface (the session ends at the
    /// restart).
    #[arg(long)]
    allow_self_reconfigure: bool,
}

impl Run for InterfaceCommand {
    fn spec(&self) -> Spec {
        Spec::BUS.json().device_management()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        match self {
            InterfaceCommand::Secure(inputs) => run(&inputs, g),
        }
    }
}

/// The `plan.json` of `--dump-images`.
#[derive(Debug, serde::Serialize)]
struct DumpedPlan<'a> {
    /// Always `"ip-secure"`: knxtrace compares only the IP Secure properties.
    system: &'static str,
    /// The interface.
    device: String,
    /// `on` or `off`.
    switch: Switch,
    /// The steps with their property writes.
    steps: &'a [PlanRecordStep],
}

/// The `--json` output.
#[derive(Debug, serde::Serialize)]
struct SecureJson {
    /// The interface.
    device: String,
    /// `on` or `off`.
    switch: Switch,
    /// Whether this was a dry run (nothing sent, nothing saved).
    dry_run: bool,
    /// The steps, one line each.
    steps: Vec<String>,
    /// The credentials the plan generated (names only).
    generated: Vec<String>,
    /// Whether the switch was verified (absent on a dry run).
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    /// What the read-back found wrong.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mismatches: Vec<String>,
}

fn parse_switch(state: &str) -> anyhow::Result<Switch> {
    match state.trim().to_ascii_lowercase().as_str() {
        "on" => Ok(Switch::On),
        "off" => Ok(Switch::Off),
        other => bail!("expected `on` or `off`, got `{other}`"),
    }
}

/// Runs `bussard interface secure on|off <address>`.
fn run(inputs: &SecureArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (dir, overrides, json) = (g.dir(), &g.mgmt(), g.json);
    let switch = parse_switch(&inputs.state)?;
    let target: IndividualAddress = inputs
        .address
        .parse()
        .with_context(|| format!("not an individual address: {}", inputs.address))?;
    let Some(model) = crate::conn_cmd::load_model_required(dir)? else {
        bail!(
            "{}",
            crate::conn_cmd::no_model(
                dir,
                "`bussard interface secure` needs the interface's device file"
            )
        );
    };
    let Some(knxnet) = bussard_service::knxnet::interface_config(&model, target) else {
        bail!(
            "{target} is not planned as a KNX IP interface (devices/{target}.toml needs a [knxnet] \
             table and no links)"
        );
    };
    let password = bussard_model::dotenv::var(KEYRING_PASSWORD_ENV)
        .map_err(|_| bussard_service::secure::SecureKeyError::MissingPassword)?;
    let (store, keystore_loaded) = KeyStore::load_with_revision(dir, &password)
        .with_context(|| format!("loading the key store {}", KeyStore::path(dir).display()))?;
    let store = store.ok_or_else(|| {
        anyhow::anyhow!(
            "no key store at {}: the interface's factory key (FDSK) and credentials live \
                 there; create it with `bussard keys import <file.knxkeys>`",
            KeyStore::path(dir).display()
        )
    })?;
    let mut plan = match switch {
        Switch::On => plan_on(&store, target, &knxnet.tunnels)?,
        Switch::Off => plan_off(&store, target)?,
    };

    if inputs.dry_run {
        if let Some(out) = inputs.dump_images.as_deref() {
            dump(out, &plan)?;
        }
        report_plan(&plan, json, true)?;
        return Ok(ExitCode::SUCCESS);
    }

    let config = resolve_config(Some(&model), overrides)?;
    enforce_write_gate(&config, g.allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    let runtime = tokio::runtime::Runtime::new()?;
    let probed = runtime.block_on(probe_gateway(&config));
    let gateway_ia = probed.and_then(|(ia, _)| ia);
    // A device management connection (issue #523): asked for, or the
    // interface is the gateway and has no free tunnelling slot.
    let store_path = KeyStore::path(dir);
    let config = if config.transport == bussard_transport::TransportKind::DeviceManagement {
        crate::interface_session::device_management_config(
            &runtime,
            config,
            target,
            Some(&store_path),
        )?
    } else if gateway_ia == Some(target)
        && runtime.block_on(crate::interface_session::tunnel_slots_full(&config))
    {
        eprintln!(
            "note: the interface has no free tunnelling connection; switching {target} over a \
             KNXnet/IP device management connection instead of a tunnel"
        );
        crate::interface_session::device_management_config(
            &runtime,
            config,
            target,
            Some(&store_path),
        )?
    } else {
        config
    };
    if switch == Switch::On && gateway_ia == Some(target) && probed.is_some_and(|(_, s)| s) {
        eprintln!(
            "refusing: {target} already runs KNXnet/IP Secure (its tunnelling is secure-only). \
             Run `bussard interface secure off {target}` first, or factory-reset it."
        );
        return Ok(ExitCode::FAILURE);
    }
    if secured_through(&config, probed, target) && !inputs.allow_self_reconfigure {
        eprintln!(
            "refusing: bussard tunnels to {target} through a KNXnet/IP Secure session with {target} \
             itself; the switch restarts it and ends the session. Pass --allow-self-reconfigure \
             to do it anyway (the read-back then reconnects with the new credentials)."
        );
        return Ok(ExitCode::FAILURE);
    }
    if !json {
        print_plan(&plan);
    }
    if !crate::confirm::confirm(
        inputs.yes,
        &format!("switch KNXnet/IP Secure {switch} on {target} via {gateway}?"),
        &format!("interface secure {switch} {target} via {gateway}"),
    )? {
        eprintln!("aborted — nothing written.");
        return Ok(ExitCode::FAILURE);
    }
    let ctx = SwitchContext {
        config,
        policy: bussard_service::WritePolicy::transmit(g.allow_remote_gateway),
        skip_address_check: overrides.skip_address_check,
        dir,
        keystore_password: &password,
        keystore_loaded: &keystore_loaded,
        connect_wait: crate::conn_cmd::connect_wait(),
    };
    let mut progress = |line: &str| {
        if !json {
            println!("  -> {line}");
        }
    };
    let outcome = runtime.block_on(run_switch(&ctx, &mut plan, &store, &mut progress));
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!(
                "\nERROR: interface secure {switch} {target}: {err}\n{}",
                recovery(&plan)
            );
            return Ok(ExitCode::FAILURE);
        }
    };
    let verified = outcome.verified(switch);
    let mut mismatches = outcome.verification.mismatches();
    if let Some(secure) = outcome.gateway_secure_only
        && secure != (switch == Switch::On)
    {
        mismatches.push(format!(
            "the interface's description says tunnelling is {}",
            if secure { "secure-only" } else { "not secured" }
        ));
    }
    if json {
        crate::output::print(
            crate::output::schema::INTERFACE_SECURE,
            &SecureJson {
                device: target.to_string(),
                switch,
                dry_run: false,
                steps: plan.lines(),
                generated: plan.generated.clone(),
                verified: Some(verified),
                mismatches,
            },
        )?;
    } else if verified {
        println!(
            "\nKNXnet/IP Secure switched {switch} for {target}: verified (security mode{}{}).",
            match &outcome.verification.tunnel_users {
                Some(users) => format!(", {} tunnelling users read back", users.len()),
                None => String::new(),
            },
            match outcome.gateway_secure_only {
                Some(true) => ", secure tunnel with the key store's credentials",
                Some(false) => ", plain tunnel",
                None => "",
            }
        );
        if outcome.store_saved_after {
            println!("the key store no longer lists a tool key for {target} (it runs on its FDSK)");
        }
    } else {
        eprintln!("\nERROR: interface secure {switch} {target}: the read-back does not match:");
        for m in &mismatches {
            eprintln!("  - {m}");
        }
        eprintln!("{}", recovery(&plan));
    }
    Ok(if verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The recovery text after a failed switch.
fn recovery(plan: &SwitchPlan) -> String {
    format!(
        "Recovery: the key store holds the credentials the device was given (and its FDSK). \
         Retry the command, or factory-reset {} (the device's reset button; it returns to its \
         FDSK and plain tunnelling) and run `bussard interface secure on {}` again. The previous \
         key store is in bussard.keys.bak; an ETS keyring export restores it with `bussard keys \
         import`. See docs/explanation/safety.md.",
        plan.target, plan.target
    )
}

fn print_plan(plan: &SwitchPlan) {
    println!("KNXnet/IP Secure {} for {}:", plan.switch, plan.target);
    for line in plan.lines() {
        println!("  {line}");
    }
    if !plan.generated.is_empty() {
        println!(
            "the key store gains, before the first write: {}",
            plan.generated.join(", ")
        );
    }
}

fn report_plan(plan: &SwitchPlan, json: bool, dry_run: bool) -> anyhow::Result<()> {
    if json {
        crate::output::print(
            crate::output::schema::INTERFACE_SECURE,
            &SecureJson {
                device: plan.target.to_string(),
                switch: plan.switch,
                dry_run,
                steps: plan.lines(),
                generated: plan.generated.clone(),
                verified: None,
                mismatches: Vec::new(),
            },
        )?;
    } else {
        print_plan(plan);
        println!("\ndry run: nothing sent, the key store unchanged.");
    }
    Ok(())
}

/// Writes `DIR/plan.json` for `knxtrace imgdiff`.
fn dump(out: &Path, plan: &SwitchPlan) -> anyhow::Result<()> {
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let steps = plan.records();
    let body = DumpedPlan {
        system: "ip-secure",
        device: plan.target.to_string(),
        switch: plan.switch,
        steps: &steps,
    };
    let path = out.join("plan.json");
    std::fs::write(&path, serde_json::to_string_pretty(&body)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_switch_accepts_on_and_off() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_switch("on")?, Switch::On);
        assert_eq!(parse_switch(" OFF ")?, Switch::Off);
        assert!(parse_switch("maybe").is_err());
        Ok(())
    }
}
