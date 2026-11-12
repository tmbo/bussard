//! The `bussard device <ADDRESS> [<CHANNEL>]` subcommand: what a device
//! offers, in its device file's words.
//!
//! Lists the device's channels; for one channel (or `device` for the
//! device-level scope) its parameters, with the choices, range and default the
//! product model gives, and its objects with what they send and listen on.
//! `--toml` prints the paste-ready device-file snippet instead. Files only: the
//! data comes from `bussard.lock` and `models/`. See
//! [`bussard_model::device_view`]. `--supported` lists bussard's device-support
//! list instead (issues #1089, #1097).

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
    /// List bussard's device-support list instead of a device: every
    /// application program with its category (proven, likely, or a known
    /// problem) and the evidence for it.
    // Issues #1089, #1097.
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

/// `bussard device --supported`: the device-support list (issues #1089,
/// #1097), every entry with its category.
fn list_supported(json: bool) -> anyhow::Result<ExitCode> {
    use bussard_service::support::Category;
    let list = bussard_service::support::SupportedList::embedded();
    if json {
        let entries: Vec<serde_json::Value> = list
            .entries()
            .iter()
            .map(|e| {
                let mut v = serde_json::to_value(e)?;
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("application".to_string(), e.application().into());
                }
                Ok(v)
            })
            .collect::<Result<_, serde_json::Error>>()?;
        crate::output::print(
            1,
            &serde_json::json!({
                "ok": true,
                "supported": entries,
                "rules": list.rules(),
                "families": list.families(),
                "source": list.source(),
            }),
        )?;
    } else {
        for e in list.entries() {
            let detail = match (e.problem(), &e.rule) {
                (Some(problem), _) => format!(" [{problem}]"),
                (None, Some(rule)) => format!(" [{rule}]"),
                (None, None) => String::new(),
            };
            println!(
                "{:<18} {:<11} {:<13} {:<4} {}{detail}",
                e.application(),
                e.category.as_str(),
                e.evidence.as_str(),
                e.masks.join(","),
                e.name
            );
        }
        let count = |c: Category| list.entries().iter().filter(|e| e.category == c).count();
        println!(
            "\n{} proven, {} likely (not confirmed on a real device), {} with a known problem. \
             flash, apply, restore and replace write proven and likely devices; any other is \
             refused on a real gateway unless you pass --allow-unsupported.",
            count(Category::Proven),
            count(Category::Likely),
            count(Category::Unsupported),
        );
        for rule in list.rules() {
            println!(
                "Rule {}: checked {}; not checked: {}.",
                rule.id,
                rule.checked.join(", "),
                rule.not_checked.join(", ")
            );
        }
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
