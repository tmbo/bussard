//! The `bussard device <ADDRESS> [<CHANNEL>]` subcommand: what a device
//! offers, in its device file's words.
//!
//! Lists the device's channels; for one channel (or `device` for the
//! device-level scope) its parameters, with the choices, range and default the
//! product model gives, and its objects with what they send and listen on.
//! `--toml` prints the paste-ready device-file snippet instead. Files only: the
//! data comes from `bussard.lock` and `models/`. See
//! [`bussard_model::device_view`]. `--supported` lists bussard's list of
//! supported devices instead (issue #1089).

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::{IndividualAddress, Model, ProductModels};

use crate::cli::{Resolved, Run, Spec};

/// `bussard device`.
#[derive(Debug, clap::Args)]
pub(crate) struct DeviceArgs {
    /// The device, e.g. `1.1.47`.
    #[arg(value_name = "ADDRESS", required_unless_present = "supported")]
    address: Option<String>,
    /// The channel to list in detail: its handle (`a-1`), id or number, a
    /// page handle, or `device` for the device-level parameters and
    /// objects.
    #[arg(value_name = "CHANNEL")]
    channel: Option<String>,
    /// Print the paste-ready device-file TOML, with commented lines for
    /// what the file does not set yet.
    #[arg(long, conflicts_with = "json")]
    toml: bool,
    /// List the application programs bussard writes without
    /// `--allow-unsupported`, with the evidence for each, instead of a
    /// device.
    // Issue #1089.
    #[arg(long, conflicts_with_all = ["address", "channel", "toml"])]
    supported: bool,
}

impl Run for DeviceArgs {
    fn spec(&self) -> Spec {
        Spec::FILES.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        match &self.address {
            Some(address) if !self.supported => {
                run(address, self.channel.as_deref(), g.dir(), self.toml, g.json)
            }
            _ => list_supported(g.json),
        }
    }
}

/// `bussard device --supported`: the supported-device list (issue #1089).
fn list_supported(json: bool) -> anyhow::Result<ExitCode> {
    let list = bussard_service::support::SupportedList::embedded();
    if json {
        let entries: Vec<serde_json::Value> = list
            .entries()
            .iter()
            .map(|e| {
                serde_json::json!({
                    "application": e.application(),
                    "application_id": e.application_id,
                    "name": e.name,
                    "evidence": e.evidence,
                    "note": e.note,
                })
            })
            .collect();
        crate::output::print(1, &serde_json::json!({ "ok": true, "supported": entries }))?;
    } else {
        for e in list.entries() {
            println!(
                "{:<18} {:<10} {:<9} {}",
                e.application(),
                e.application_id,
                e.evidence,
                e.name
            );
        }
        println!(
            "\n{} application program(s). Any other is refused by flash, apply, restore and \
             replace on a real gateway unless you pass --allow-unsupported.",
            list.entries().len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs `bussard device`.
fn run(
    address: &str,
    channel: Option<&str>,
    dir: &Path,
    toml: bool,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;
    let model =
        Model::load(dir).with_context(|| format!("loading the project in {}", dir.display()))?;
    let app = model
        .devices
        .get(&target)
        .and_then(|d| d.device.product.as_ref())
        .and_then(|p| p.application_ref.clone());
    // A pinned archive whose model is missing gets it now, in the lock's
    // language, rather than the view reporting no product data (issue #255).
    if let Some(app) = &app {
        bussard_service::setup::products::complete_models(
            dir,
            Some(app),
            &mut crate::console::Console,
        );
    }
    let products = ProductModels::load_apps(dir, app.iter().map(String::as_str));
    let view = bussard_model::device_view::device_view(&model, &products, target, channel)?;
    // Whether bussard writes the device without the override (issue #1089).
    let support = bussard_service::support::verdict_at(Some(&model), target, None).view();
    if json {
        crate::output::report(&bussard_service::device_show::DeviceShow {
            support: Some(support),
            ..bussard_service::device_show::DeviceShow::of(view)
        })?;
    } else if toml {
        print!("{}", view.render_toml());
    } else {
        print!("{}", view.render_table());
        println!("{}", support.line());
    }
    Ok(ExitCode::SUCCESS)
}
