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

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_project::KeyStore;
use bussard_service::ip_secure::{
    PlanRecordStep, Switch, SwitchContext, SwitchPlan, plan_off, plan_on, probe_gateway,
    run_switch, secured_through,
};
use bussard_service::secure::KEYRING_PASSWORD_ENV;

use crate::conn_cmd::{ConnOverrides, enforce_write_gate, gateway_display, resolve_config};

/// What `interface secure` takes besides the model directory.
#[derive(Debug, Clone)]
pub(crate) struct SecureInputs<'a> {
    /// `on` or `off`.
    pub state: &'a str,
    /// The interface's individual address.
    pub address: &'a str,
    /// `--dry-run`.
    pub dry_run: bool,
    /// `--dump-images DIR`.
    pub dump_images: Option<&'a Path>,
    /// `--yes`.
    pub yes: bool,
    /// `--allow-remote-gateway`.
    pub allow_remote_gateway: bool,
    /// `--allow-self-reconfigure`.
    pub allow_self_reconfigure: bool,
    /// `--json`.
    pub json: bool,
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
pub(crate) fn run(
    dir: &Path,
    inputs: SecureInputs<'_>,
    overrides: &ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let switch = parse_switch(inputs.state)?;
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
    let store = KeyStore::load(dir, &password)
        .with_context(|| format!("loading the key store {}", KeyStore::path(dir).display()))?
        .ok_or_else(|| {
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
        if let Some(out) = inputs.dump_images {
            dump(out, &plan)?;
        }
        report_plan(&plan, inputs.json, true)?;
        return Ok(ExitCode::SUCCESS);
    }

    let config = resolve_config(Some(&model), overrides)?;
    enforce_write_gate(&config, inputs.allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    let runtime = tokio::runtime::Runtime::new()?;
    let probed = runtime.block_on(probe_gateway(&config));
    let gateway_ia = probed.and_then(|(ia, _)| ia);
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
    if !inputs.json {
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
        policy: bussard_service::WritePolicy::transmit(inputs.allow_remote_gateway),
        skip_address_check: overrides.skip_address_check,
        dir,
        keystore_password: &password,
        connect_wait: crate::conn_cmd::connect_wait(),
    };
    let json = inputs.json;
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
    let mut mismatches = outcome.verification.mismatches.clone();
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
