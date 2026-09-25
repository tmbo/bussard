//! The `bussard device <ADDRESS> [<CHANNEL>]` subcommand: what a device
//! offers, in its device file's words.
//!
//! Lists the device's channels; for one channel (or `device` for the
//! device-level scope) its parameters, with the choices, range and default the
//! product model gives, and its objects with what they send and listen on.
//! `--toml` prints the paste-ready device-file snippet instead. Files only: the
//! data comes from `bussard.lock` and `models/`. See
//! [`bussard_model::device_view`].

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::{IndividualAddress, Model, ProductModels};

/// Runs `bussard device`.
pub fn run(
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
        Model::load(dir).with_context(|| format!("loading the model in {}", dir.display()))?;
    let app = model
        .devices
        .get(&target)
        .and_then(|d| d.device.product.as_ref())
        .and_then(|p| p.application_ref.clone());
    let products = ProductModels::load_apps(dir, app.iter().map(String::as_str));
    let view = bussard_model::device_view::device_view(&model, &products, target, channel)?;
    if json {
        crate::output::print(crate::output::schema::DEVICE, &view)?;
    } else if toml {
        print!("{}", view.render_toml());
    } else {
        print!("{}", view.render_table());
    }
    Ok(ExitCode::SUCCESS)
}
