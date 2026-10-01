//! Parameter read-back for `bussard plan` and `bussard reconstruct` (issue #119).
//!
//! Both commands read the link tables. With the device's product file (the
//! explicit `--product`, or the archive in `<dir>/products/` the lock pins for
//! the device) they also read the parameter memory the application's load
//! procedure writes, decode it through the product's parameter types, and
//! report:
//!
//! - the parameters whose value differs from the vendor default, and
//! - the differences to the model's parameter values (what
//!   `bussard flash --parameters-only` would write), and
//! - the internal ETS values (`Access="None"`, never shown, e.g. a
//!   function-block selector) whose octets differ from the model's image,
//!   with both values (issue #285).
//!
//! The resolution, the read and the decoding live in
//! [`bussard_service::params`], shared with the MCP programming tier (issue
//! #274); this module prints them. Everything here is read-only on the bus.

use std::path::Path;

use bussard_model::{IndividualAddress, Model};

pub(crate) use bussard_service::params::{
    MissingProduct, ParamState, ProductSource, Readback, Selection, read_state,
};

/// Resolves the product file and application for `target`
/// ([`bussard_service::params::resolve_product`]), printing the warning a
/// [`MissingProduct::Warn`] lookup carries.
pub(crate) fn resolve(
    dir: &Path,
    selection: Selection<'_>,
    model: Option<&Model>,
    target: IndividualAddress,
    missing: MissingProduct,
) -> anyhow::Result<Option<ProductSource>> {
    let lookup = bussard_service::params::resolve_product(
        dir,
        selection,
        model,
        target,
        missing,
        Some(crate::product_cache::record_parse),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if let Some(warning) = lookup.warning {
        eprintln!("warning: {warning}; the parameters are not read back");
    }
    Ok(lookup.source)
}

/// Appends the unit, when there is one.
fn with_unit(value: &str, unit: &Option<String>) -> String {
    match unit {
        Some(u) if !u.is_empty() => format!("{value} {u}"),
        _ => value.to_string(),
    }
}

/// Prints the read-back section of a text report.
pub(crate) fn print_text(readback: &Readback, target: IndividualAddress) {
    println!("\nparameters (application {}):", readback.application);
    if let Some(note) = &readback.note {
        println!("  note: {note}");
    }
    if !readback.device_managed.is_empty() {
        println!("  device-managed (written by a download, owned by the application; no verdict):");
        for r in &readback.device_managed {
            println!("      {}: {}", r.name, with_unit(&r.value, &r.unit));
        }
    }
    if !readback.internal.is_empty() {
        println!(
            "  internal ETS values that differ from the model (never shown, written by a download):"
        );
        for run in &readback.internal {
            println!("      {}", run.sentence);
        }
        if let Some(explanation) = readback
            .internal
            .iter()
            .find_map(|r| r.explanation.as_deref())
        {
            println!("      {explanation}");
        }
    }
    if readback.non_default.is_empty() && readback.differences.is_empty() {
        if readback.note.is_none() {
            if readback.internal.is_empty() {
                println!("  every parameter holds its vendor default and matches the model");
            } else {
                println!("  every shown parameter holds its vendor default and matches the model");
            }
        }
        return;
    }
    println!(
        "  {} parameter(s) differ from the vendor default:",
        readback.non_default.len()
    );
    for r in &readback.non_default {
        println!(
            "      {}: {} (default {})",
            r.name,
            with_unit(&r.value, &r.unit),
            with_unit(&r.default, &r.unit)
        );
    }
    if readback.differences.is_empty() {
        println!("  the device matches the model's parameters: block");
        return;
    }
    println!(
        "  {} parameter(s) differ from the model:",
        readback.differences.len()
    );
    for d in &readback.differences {
        let device = d
            .device
            .as_deref()
            .map(|v| with_unit(v, &d.unit))
            .unwrap_or_else(|| "unreadable".to_string());
        println!(
            "      {}: device {device}, model {}",
            d.name,
            with_unit(&d.model, &d.unit)
        );
    }
    println!(
        "  run `bussard apply {target}` to write the model's values (a value that shows or \
         hides a com-object needs a full `bussard flash`)"
    );
}

/// The note printed when the model has parameters for a device but no product
/// file was found to decode them with.
pub(crate) fn print_missing_product_note(model: Option<&Model>, target: IndividualAddress) {
    let has_params = model
        .and_then(|m| m.devices.get(&target))
        .is_some_and(|d| !d.device.parameters.is_empty());
    if has_params {
        println!(
            "\nparameters: not read back (bussard.lock pins no product data for this device; pass \
             --product <FILE> or run `bussard import-product` to cache it)"
        );
    }
}
