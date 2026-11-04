//! The `bussard adopt` subcommand — the guided new-device flow (issue #26).
//!
//! The "I bought an MDT Taster 55 and wired it in" story, orchestrating the
//! existing pieces into one conversational wizard: get product data (import a
//! `.knxprod` or reuse a cached model), assign an individual address via
//! programming mode, verify the write against the product's order numbers, drop
//! a rich `devices/<address>.toml` plus its `bussard.lock` entry (product
//! identity and a com-object table lifted from the product model), and hand the
//! user a ready-to-paste device-file snippet plus the exact next commands.
//!
//! ## Conversational-first, LLM-drivable
//!
//! Every prompt is written to be clear both to a human at a TTY and to an LLM
//! driving over the CLI. The address write follows the one confirmation rule
//! of every write command (`crate::confirm`): `--yes` skips the prompt, and a
//! run without a terminal and without `--yes` is refused before it starts. The
//! target address is the optional `ADDRESS` argument, else the next free one,
//! exactly as for `assign`. Downloading product data is a separate consent,
//! `--yes-download`.
//!
//! ## A KNX Data Secure-activated device (issue #201, tier 1)
//!
//! When the keyring (the global `--keyring`, else `BUSSARD_KEYRING`, else
//! `connection.keyring` in `bussard.toml`; password in
//! `BUSSARD_KEYRING_PASSWORD`) holds a tool key for the device in programming
//! mode, adopt treats it as a device ETS has commissioned: it keeps the device
//! at its address (no address write), verifies it over `A_SecureData`, and
//! reads its link tables, parameters and security object (PID 61 group-object
//! security flags, PID 54 security individual address table) over the same
//! secured management path `reconstruct` uses. The device file records the
//! links, the parameters that differ from the vendor defaults and
//! `[security] activated = true, secure_commissioning = true`; the lock
//! records `secure_capable`, the keyring sequence and the sender table; the
//! device's secured objects and the keyed group addresses it is linked to are
//! marked `secure`. Nothing is written to a secured device: activation and
//! re-keying stay with ETS (tier 2 is out of scope).
//!
//! A device that hides its mask (`FFFF`, activated) but has no tool key in the
//! keyring fails with the resolver's "no tool key" message and a hint to
//! re-export the keyring; no device file is written.
//!
//! ## The flow lives in bussard-service (issue #749)
//!
//! The steps are [`bussard_service::assign`] (the programming-mode wait, the
//! address, the write and the read-back) and [`bussard_service::adopt::flow`]
//! (the product shaping, the device file, the secured read), the same
//! functions `knx_add_device` runs. This module keeps the wizard: the lines it
//! prints, the prompts, and the `--product` import.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_mgmt::system_type;
use bussard_model::schema::ComObject;
use bussard_model::{Flags, GroupAddress, IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData};
pub(crate) use bussard_service::adopt::flow::{
    SecureSummary, SecuredRead, SelectedProduct, build_device, object_placement, order_matches,
    shape_selected,
};
use bussard_service::identity::SecureStatus;
use bussard_service::secure::{SecureMaterial, ToolKeySource, ToolKeys};
use bussard_service::{BusService, WritePolicy};

use crate::assign_cmd::{
    Verified, VerifyKey, hex, load_model_optional, target_is_free, verify_assignment_with,
    wait_for_single_device_as, warn_if_still_in_programming_mode, write_device_file,
};
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display, open_service,
    resolve_config,
};
use crate::import_product_cmd::is_project_export;
use crate::style::Style;

/// What one `bussard adopt` run was asked to do.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdoptOptions<'a> {
    /// The target individual address (`ADDRESS`); `None` takes the next free
    /// one on the line, or keeps a Data Secure device's address.
    pub(crate) address: Option<&'a str>,
    /// `--product`: the vendor `.knxprod` for the new device.
    pub(crate) product: Option<&'a Path>,
    /// `--yes`: skip the confirmation prompt.
    pub(crate) yes: bool,
    /// `--force`: write the address although another device answers at it.
    pub(crate) force: bool,
    /// How the product-data download question is answered.
    pub(crate) consent: crate::product_fetch::Consent,
}

/// Runs `bussard adopt`.
pub(crate) fn run(
    options: AdoptOptions<'_>,
    dir: &Path,
    allow_remote_gateway: bool,
    keyring: Option<&Path>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let AdoptOptions {
        address: scripted_address,
        product,
        yes,
        force,
        consent,
    } = options;
    // A run without a terminal and without --yes was refused before this, by
    // `confirm::require_terminal_or_yes` in `main` (issue #74). Without a
    // terminal the wizard's choices take their documented defaults.
    let interactive = std::io::stdin().is_terminal();

    // History (issue #110): capture an edit made outside bussard before the
    // wizard starts writing device files.
    crate::history_cmd::capture_external_edit(dir);

    let style = Style::stdout();
    println!(
        "{} {}",
        style.bold("bussard adopt"),
        style.dim("guides a new device into your project")
    );
    step(1, "product data");

    // Step 1: resolve product data (import, pick a cached model, or product-less).
    let selected = resolve_product(product, dir, interactive)?;
    match &selected {
        Some(app) => println!(
            "  using application {} ({})",
            app.identity_id,
            app.display_name()
        ),
        None => println!(
            "  continuing without product data (stub-only adoption); no com-object table is \
             generated"
        ),
    }

    // Load the model (best effort) for address allocation and the device file.
    let have_explicit = scripted_address.is_some();
    let model = load_model_optional(
        dir,
        have_explicit,
        "adopt",
        "pass the target ADDRESS or run in a project directory",
    )?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    // The keyring's tool keys (issue #201): a device it lists is adopted as a
    // Data Secure device. Loaded before the bus is touched, so a wrong
    // password fails fast.
    let keys = ToolKeys::load(ToolKeySource {
        keyring,
        tool_key: None,
    })
    .context("loading the keyring for adopt")?;

    let adopt_keys = AdoptKeys {
        keys: &keys,
        keyring,
        product,
    };
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        // The service applies the same write gate again as it opens. Waiting
        // for the connect makes the tunnel-assigned source address available
        // (falling back to 0.0.255 on routing) — issue #30.
        let service = open_service(config, WritePolicy::transmit(allow_remote_gateway)).await?;
        let source = checked_source_or_close(&service, &overrides).await?;
        // Guard with Ctrl-C so an interrupt still closes the tunnel cleanly.
        let result = tokio::select! {
            result = adopt_flow(
                &service,
                source,
                dir,
                model.as_ref(),
                selected.as_ref(),
                scripted_address,
                AdoptRun { yes, force, gateway: &gateway },
                consent,
                &adopt_keys,
            ) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ninterrupted; closing the bus connection");
                Err(anyhow!("adopt interrupted by Ctrl-C"))
            }
        };
        service.close().await;
        result
    })
}

/// The key material and inputs of one adopt run that the bus flow needs.
struct AdoptKeys<'a> {
    /// The loaded keyring (or nothing).
    keys: &'a ToolKeys,
    /// The keyring's path, for messages.
    keyring: Option<&'a Path>,
    /// `--product`, for the parameter read-back of a secured device.
    product: Option<&'a Path>,
}

/// Step 1: resolve the product application.
///
/// With `--product`, run the import-product path (cache vendor + write models/)
/// then pick the sole/first application. Without it, list cached `models/` and
/// let a TTY user pick one, or proceed product-less with a warning.
fn resolve_product(
    product: Option<&Path>,
    dir: &Path,
    interactive: bool,
) -> anyhow::Result<Option<SelectedProduct>> {
    if let Some(file) = product {
        let data = import_product(file, dir)?;
        let app = choose_application(&data, interactive)?;
        return Ok(Some(shape_selected(&app, &data)));
    }

    // No product file: offer cached models.
    let models = cached_models(dir);
    if models.is_empty() {
        println!(
            "  no --product given and no cached product data under {}; continuing without \
             product data.",
            dir.join(bussard_model::param_model::MODELS_DIR).display()
        );
        return Ok(None);
    }

    if !interactive {
        // Reachable only via the scripted shape, which always passes --product;
        // guard anyway so a future caller does not silently pick model 0.
        println!(
            "  no --product given (non-interactive); continuing without product data. Pass \
             --product to attach product data."
        );
        return Ok(None);
    }

    println!(
        "  cached product models under {}:",
        dir.join(bussard_model::param_model::MODELS_DIR).display()
    );
    for (i, name) in models.iter().enumerate() {
        println!("    [{}] {name}", i + 1);
    }
    println!("    [0] none (product-less stub adoption)");
    let pick = prompt_index("  pick a model", models.len())?;
    if pick == 0 {
        return Ok(None);
    }
    // The cached model YAML is our own generated shape; but for the read-back
    // cross-check and com-object table we want the parsed application. We do not
    // keep the source .knxprod path here, so a cached-model pick attaches the
    // identity/order-number metadata we can recover from the model file name and
    // proceeds product-less for the com-object table with a note.
    println!(
        "  note: adopting from a cached model file carries product identity only; \
         re-run with --product <file.knxprod> to also generate the com-object table."
    );
    let id = models[pick - 1].trim_end_matches(".yaml").to_string();
    Ok(Some(SelectedProduct {
        manufacturer_ref: id.split('_').next().map(str::to_string),
        application_ref: id.clone(),
        app: vendor_application(dir, &id),
        identity_id: id,
        name: None,
        mask_version: None,
        order_numbers: Vec::new(),
        com_objects: std::collections::BTreeMap::new(),
    }))
}

/// Picks the application program to adopt from freshly-imported product data.
/// A single application is chosen silently; multiple are offered as a numbered
/// choice on a TTY, or the first is taken (with a note) non-interactively.
fn choose_application(data: &ProductData, interactive: bool) -> anyhow::Result<ApplicationProgram> {
    match data.applications.len() {
        0 => bail!("product data contained no application programs"),
        1 => Ok(data.applications[0].clone()),
        _ if !interactive => {
            let app = data.applications[0].clone();
            println!(
                "  {} applications in the product; taking the first ({}) non-interactively.",
                data.applications.len(),
                app.id
            );
            Ok(app)
        }
        _ => {
            println!("  the product contains several application programs:");
            for (i, app) in data.applications.iter().enumerate() {
                let name = app.name.as_deref().unwrap_or(&app.id);
                println!("    [{}] {name} ({})", i + 1, app.id);
            }
            let pick = prompt_index("  pick an application", data.applications.len())?;
            let idx = pick.max(1) - 1;
            Ok(data.applications[idx].clone())
        }
    }
}

// ---------------------------------------------------------------------------
// The bus-touching flow (steps 2–5)
// ---------------------------------------------------------------------------

/// The per-run choices `adopt_flow` needs besides the bus and the model.
#[derive(Clone, Copy)]
struct AdoptRun<'a> {
    /// `--yes`: skip the confirmation prompt.
    yes: bool,
    /// `--force`: write the address although another device answers at it.
    force: bool,
    /// The resolved gateway, for the prompt.
    gateway: &'a str,
}

/// The end-to-end adopt flow over the bus actor. Each broadcast and each
/// connected verify leases the bus for the duration of that step.
#[allow(clippy::too_many_arguments)]
async fn adopt_flow(
    service: &BusService,
    source: IndividualAddress,
    dir: &Path,
    model: Option<&Model>,
    selected: Option<&SelectedProduct>,
    scripted_address: Option<&str>,
    run: AdoptRun<'_>,
    fetch: crate::product_fetch::Consent,
    adopt_keys: &AdoptKeys<'_>,
) -> anyhow::Result<ExitCode> {
    let AdoptRun {
        yes,
        force,
        gateway,
    } = run;
    step(2, "assign an address");

    // Find exactly one device in programming mode.
    let current = match wait_for_single_device_as(service, source, "adopt").await? {
        Some(addr) => addr,
        None => return Ok(ExitCode::FAILURE),
    };
    eprintln!("device in programming mode: {current} (its current address)");

    // Decide the target address. A device the keyring lists is Data Secure
    // (issue #201): it stays at the address ETS gave it, since the keyring
    // looks its tool key up by that address.
    let keys = adopt_keys.keys;
    let secured = keys.lists(current);
    let target =
        bussard_service::adopt::flow::adopt_target(scripted_address, current, secured, model)?;
    // The key material for a secured device: its tool key, the keyring's group
    // keys and sequences (the rule `reconstruct` resolves with).
    let material = if secured {
        keys.material(current, true)?
    } else {
        SecureMaterial::default()
    };

    // NM_IndividualAddress_Write step 1 (Management Procedures 03_05_02
    // §2.3, issue #530): a new address must be free on the bus, not only in
    // the model. A device that keeps its address is the one answering there.
    if target != current && !target_is_free(service, source, target, force, "adopt").await {
        return Ok(ExitCode::FAILURE);
    }

    // Confirm.
    if !crate::confirm::confirm(
        yes,
        &format!("adopt {current} → {target} via {gateway}?"),
        &format!("adopt {current} → {target} via {gateway}"),
    )? {
        eprintln!("aborted; no address was written.");
        return Ok(ExitCode::FAILURE);
    }

    // Write, then verify. A device that already has the target address needs
    // no write (and a secured device gets none, issue #201).
    if target == current {
        eprintln!("{current} already has the address {target}; no address write; verifying…");
    } else {
        bussard_service::assign::write_address(service, source, target)
            .await
            .context("broadcasting the new individual address")?;
        eprintln!("wrote {target}; verifying…");
    }
    // adopt does not clear programming mode in the read-back; the broadcast
    // re-check below warns if the device is still in it. A keyring-listed
    // device is verified over A_SecureData with its tool key.
    let verify_key = VerifyKey {
        tool_key: material.tool_key.clone(),
        from_old_address: false,
    };
    let verified = verify_assignment_with(service, source, target, false, &verify_key).await?;
    if verified.secure == SecureStatus::ActivatedNoKey {
        return Err(activated_without_key(target, current, adopt_keys));
    }

    // Programming-mode persistence check: warn if the just-assigned device still
    // answers the programming-mode broadcast (KNX Virtual does not clear it; a
    // real device with a stuck button would not either). See the helper docs.
    // Without an address write the device had no reason to leave it: adopt
    // writes nothing more (a secured device gets no PID_PROGMODE write
    // either), so the button is the way out.
    if target == current {
        eprintln!(
            "note: {target} stays in programming mode (adopt wrote nothing to it); press its \
             programming button to leave it"
        );
    } else {
        warn_if_still_in_programming_mode(service, source, target).await;
    }

    // Product data fetches itself: without a product from step 1, the order
    // number the device reported is looked up in the vendor cache, then in the
    // pointer index (one question), downloaded and imported.
    let fetched = match (selected, verified.order.as_deref()) {
        (None, Some(order)) => fetch_product_for(order, dir, fetch),
        _ => None,
    };
    let selected = selected.or(fetched.as_ref());

    // Cross-check the read-back order number against the product's order numbers.
    let mut mismatch = false;
    if let (Some(sel), Some(read_order)) = (selected, verified.order.as_deref())
        && !sel.order_numbers.is_empty()
        && !order_matches(read_order, &sel.order_numbers)
    {
        mismatch = true;
        eprintln!();
        eprintln!(
            "{}",
            Style::stderr().warning_line(&format!(
                "the device reported order number {read_order:?}, which is not among the \
                 product's order numbers ({}). The product data may not match this hardware; \
                 check it before wiring links (continuing anyway).",
                sel.order_numbers.join(", ")
            ))
        );
    }

    // Step 3: write the rich device file.
    step(3, "write the device file");
    let device = build_device(target, &verified, selected);
    // A Data Secure device is commissioned: read what ETS programmed into it
    // (links, parameters, security object) over A_SecureData (issue #201).
    let (device, model_out, secure_summary) = if verified.secure == SecureStatus::Activated {
        let read = read_secured(
            service,
            source,
            target,
            dir,
            model,
            &device,
            selected,
            adopt_keys.product,
            &material,
        )
        .await?;
        let (device, model_out, summary) = bussard_service::adopt::flow::record_secured(
            model, device, target, selected, &read, &material, current,
        )?;
        (device, Some(model_out), Some(summary))
    } else {
        (device, None, None)
    };
    // A KNX IP interface (issue #391): its KNXnet/IP settings become the
    // device file's `[knxnet]` table, read from the device (the assignment
    // method, the static settings, the friendly name, the tunnel addresses).
    // A table the model already holds is the user's and stays.
    let mut device = device;
    let had_knxnet = device.knxnet.is_some()
        || model
            .and_then(|m| m.devices.get(&target))
            .is_some_and(|d| d.device.knxnet.is_some());
    if !had_knxnet {
        match bussard_service::adopt::flow::read_knxnet_settings(
            service, source, target, dir, &material,
        )
        .await
        {
            Ok(Some(knxnet)) => {
                let config = knxnet.as_config();
                println!(
                    "  KNXnet/IP: assignment {}, {} tunnel address(es){}",
                    config.assignment.label(),
                    config.tunnels.len(),
                    knxnet
                        .current_address
                        .map(|a| format!(", address in use {a}"))
                        .unwrap_or_default()
                );
                if knxnet.assignment_mode.is_none() {
                    println!(
                        "  note: {target} reports no IP assignment method the model spells; \
                         recorded as dhcp"
                    );
                }
                device.knxnet = Some(config);
            }
            Ok(None) => {}
            Err(err) => eprintln!(
                "note: the KNXnet/IP settings of {target} were not read ({err:#}); the device \
                 file has no [knxnet] table"
            ),
        }
    }
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("adopt")
            .with_args([target.to_string()])
            .with_result("before writing the adopted device file"),
    );
    // The lock records the serial the device reported (issue #752), and a
    // certificate entered for it before moves to it in the key store.
    let path = write_device_file(
        model_out.as_ref().or(model),
        dir,
        device.clone(),
        verified.serial.as_deref(),
        "device file",
    )?;
    println!("  wrote {}", path.display());
    if let Some(serial) = &verified.serial {
        crate::keys_cmd::attach_learned_serials(dir, &[(target, serial.clone())]).print(false);
    }

    // Step 4: links scaffolding (print only — the model stays untouched), or
    // the links a secured device already holds (recorded in the model).
    step(4, "wire the group objects");
    match &secure_summary {
        Some(summary) if summary.links > 0 => println!(
            "  recorded the {} link(s) the device holds in {}",
            summary.links,
            path.display()
        ),
        _ => print_links_snippet(target, &device, selected),
    }

    // Step 5: summary.
    step(5, "summary");
    print_summary(current, target, &verified, &path, selected, mismatch);
    if let Some(summary) = &secure_summary {
        print_secure_summary(target, summary);
    }

    Ok(ExitCode::SUCCESS)
}

/// The product data for the order number a device reported: the cached
/// archive under `<dir>/vendor/`, else the pointer index's download (asked
/// once), imported like `--product` would be. `None` (with the reason on the
/// console) continues product-less.
fn fetch_product_for(
    order: &str,
    dir: &Path,
    fetch: crate::product_fetch::Consent,
) -> Option<SelectedProduct> {
    let path = match crate::product_store::archive_for_order(dir, order) {
        Ok(Some(path)) => path,
        Ok(None) | Err(_) => {
            println!("  no product data cached for {order}; looking it up");
            let outcome =
                match crate::product_fetch::fetch_missing(dir, &[order.to_string()], fetch) {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        eprintln!("  product data for {order}: {err:#}");
                        return None;
                    }
                };
            match outcome.fetched.first() {
                Some((_, path)) => path.clone(),
                None => {
                    crate::product_fetch::print_missing(&outcome, dir);
                    println!("  continuing product-less for {order}");
                    return None;
                }
            }
        }
    };
    let data = match import_product(&path, dir) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("  product data for {order}: {err:#}; continuing product-less");
            return None;
        }
    };
    let app = crate::flash_cmd::resolve_by_order_number(&data, order)
        .ok()
        .cloned()
        .or_else(|| choose_application(&data, false).ok())?;
    println!(
        "  using application {} ({}) for {order}",
        app.id,
        app.name.as_deref().unwrap_or(&app.id)
    );
    Some(shape_selected(&app, &data))
}

/// The application program `app_ref` from an archive `bussard.lock` pins.
fn vendor_application(dir: &Path, app_ref: &str) -> Option<ApplicationProgram> {
    crate::product_store::pinned_application(dir, app_ref)
}

/// Prints a ready-to-paste device-file snippet: the device's most-useful com
/// objects (transmit-capable first), then an example link block. The snippet
/// goes to stdout only — the model itself is never modified here.
///
/// The object display text (button/sensor label) lives on the product shape
/// rather than the device row, so `selected` is consulted for names/suggestions.
fn print_links_snippet(
    address: IndividualAddress,
    device: &bussard_model::schema::Device,
    selected: Option<&SelectedProduct>,
) {
    if device.com_objects.is_empty() {
        println!(
            "  no com-object table (no product data); import the product later with \
             `bussard import-product` to generate one."
        );
        return;
    }

    // Order: transmit-capable first (most likely a sensor/button source), then
    // by number for stability.
    let mut objs: Vec<(&u16, &ComObject)> = device.com_objects.iter().collect();
    objs.sort_by_key(|(num, co)| (!co.flags.contains(Flags::TRANSMIT), **num));

    let text_for = |num: u16| -> Option<&str> {
        selected
            .and_then(|s| s.com_objects.get(&num))
            .and_then(|shape| shape.text.as_deref())
    };

    println!("  most-useful com objects (transmit-capable first):");
    for (num, co) in objs.iter().take(8) {
        let dpt = co
            .dpt
            .map(|d| d.to_string())
            .unwrap_or_else(|| "?".to_string());
        let label = text_for(**num).unwrap_or("");
        println!("    #{num:<3} dpt {dpt:<8} flags {:<6} {label}", co.flags);
    }

    // A paste-ready example wiring the first useful object.
    if let Some((num, co)) = objs.first() {
        let dpt = co
            .dpt
            .map(|d| d.to_string())
            .unwrap_or_else(|| "1.001".to_string());
        let name = text_for(**num).unwrap_or("New link");
        println!();
        println!("  ready-to-paste snippets (edit the group address to a free one):");
        let (table, key) = object_placement(device, **num);
        println!("    # ---8<--- groups.toml (inside `groups = [ … ]`)");
        println!("    {{ address = \"0/0/1\", name = \"{name}\", dpt = \"{dpt}\" }},");
        println!("    # ---8<--- devices/{address}.toml");
        println!("    {table}");
        // The direction follows the flags, as E025 requires: a reporting object
        // (T) sends, a command object listens.
        if co.flags.contains(Flags::TRANSMIT) {
            println!(
                "    {key}.send = \"0/0/1\"     # or `{key}.listen = [\"0/0/1\"]` for a receiving object"
            );
        } else {
            println!(
                "    {key}.listen = [\"0/0/1\"]     # or `{key}.send = \"0/0/1\"` for a reporting object"
            );
        }
        println!("    # --->8---");
    }
}

/// Prints the closing summary: what was created, what remains manual, and the
/// flash pointer for factory-fresh (Unloaded) devices.
fn print_summary(
    current: IndividualAddress,
    target: IndividualAddress,
    v: &Verified,
    path: &Path,
    selected: Option<&SelectedProduct>,
    mismatch: bool,
) {
    let style = Style::stdout();
    println!();
    println!(
        "{}",
        style.ok(&style.bold(&format!("adopted {current} → {target}")))
    );
    let secured = v.secure == SecureStatus::Activated;
    let label = |text: &str| style.dim(&format!("{text:<14}"));
    match v.mask {
        Some(mask) if secured => println!(
            "  {}mask {mask:#06x} ({}), read secured; KNX Data Secure is on",
            label("verified"),
            system_type(mask)
        ),
        Some(mask) => println!(
            "  {}mask {mask:#06x} ({})",
            label("verified"),
            system_type(mask)
        ),
        None => {}
    }
    if let Some(serial) = &v.serial {
        println!("  {}{}", label("serial number"), hex(serial).to_uppercase());
    }
    println!("  {}{}", label("device file"), path.display());
    match selected {
        Some(sel) if !sel.com_objects.is_empty() => {
            println!(
                "  {}{} ({} com objects)",
                label("product"),
                sel.display_name(),
                sel.com_objects.len()
            );
        }
        Some(sel) => println!(
            "  {}{} (identity only)",
            label("product"),
            sel.display_name()
        ),
        None => println!("  {}none (stub-only adoption)", label("product")),
    }
    if mismatch {
        println!(
            "  {}",
            style.warn("the order number check flagged a possible mismatch (see above)")
        );
    }

    let edit = format!("edit {}", path.display());
    let plan = format!("bussard plan {target}");
    let apply = format!("bussard apply {target}");
    let flash = format!("bussard flash {target}");
    let mut steps: Vec<(&str, &str)> = vec![(edit.as_str(), "set the device's name and room")];
    if secured {
        steps.push((
            plan.as_str(),
            "should report no change: your project now holds what the device holds",
        ));
    } else {
        steps[0].1 = "set the device's name and room, and wire its group objects (snippet above)";
        steps.push((plan.as_str(), "shows what writing the tables would change"));
        steps.push((apply.as_str(), "writes them to the device"));
        // A factory-fresh device needs its first application download before
        // links take effect; `bussard flash` (#43) is the path when product
        // data is in hand.
        if selected.is_some_and(|s| !s.com_objects.is_empty()) {
            steps.push((
                flash.as_str(),
                "only for a factory-fresh device: downloads the application first",
            ));
        }
    }
    println!();
    print!("{}", style.next_steps(&steps));
}

/// One step heading of the flow: `Step 2 of 5  assign an address`.
fn step(n: u8, what: &str) {
    let style = Style::stdout();
    println!("{} {what}", style.bold(&format!("Step {n} of 5")));
}

// ---------------------------------------------------------------------------
// A KNX Data Secure-activated device (issue #201, tier 1)
// ---------------------------------------------------------------------------

/// The failure for a device that hides its mask (Data Secure-activated) while
/// the keyring holds no tool key for it
/// ([`bussard_service::adopt::flow::activated_without_key`]).
fn activated_without_key(
    target: IndividualAddress,
    current: IndividualAddress,
    adopt_keys: &AdoptKeys<'_>,
) -> anyhow::Error {
    anyhow!(bussard_service::adopt::flow::activated_without_key(
        target,
        current,
        adopt_keys.keys,
        adopt_keys.keyring,
    ))
}

/// Reads an activated device's tables, security object and parameters in one
/// management session over `A_SecureData`
/// ([`bussard_service::adopt::flow::read_secured`]). Read-only.
#[allow(clippy::too_many_arguments)] // one call site; the inputs are the flow's state
async fn read_secured(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    dir: &Path,
    model: Option<&Model>,
    device: &bussard_model::schema::Device,
    selected: Option<&SelectedProduct>,
    product: Option<&Path>,
    material: &SecureMaterial,
) -> anyhow::Result<SecuredRead> {
    println!(
        "  reading the secured device over A_SecureData (tables, security object, parameters)"
    );
    // The product the parameter read-back decodes with, found through the
    // device file being written (its order number and application).
    let with_device = bussard_service::adopt::flow::with_device(model, device, target);
    let mut notes = Vec::new();
    let selection = crate::param_readback::Selection {
        product,
        application: selected.map(|s| s.application_ref.as_str()),
    };
    let product_source = match crate::param_readback::resolve(
        dir,
        selection,
        Some(&with_device),
        target,
        crate::param_readback::MissingProduct::Warn,
    ) {
        Ok(found) => found,
        Err(err) => {
            notes.push(format!("parameters not read: {err:#}"));
            None
        }
    };
    bussard_service::adopt::flow::read_secured(
        service,
        source,
        target,
        &with_device,
        product_source.as_ref(),
        material,
        notes,
    )
    .await
    .map_err(|err| {
        anyhow::Error::from(err).context(format!(
            "reading {target} over A_SecureData with its tool key"
        ))
    })
}

/// Prints the Data Secure part of the summary.
fn print_secure_summary(target: IndividualAddress, s: &SecureSummary) {
    let list = |items: &mut dyn Iterator<Item = String>| -> String {
        let v: Vec<String> = items.collect();
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(", ")
        }
    };
    println!();
    println!("Secure (read over A_SecureData with the device's tool key):");
    println!("  device file: [security] activated = true, secure_commissioning = true");
    println!(
        "  links: {}; parameters (non-default): {}",
        s.links, s.parameters
    );
    let source = if s.adoption.from_device_flags {
        "the device's object security flags (PID 61)"
    } else {
        "the group keys bussard has (PID 61 not read)"
    };
    println!(
        "  secure objects ({source}): {}",
        list(&mut s.adoption.secure_objects.iter().map(u16::to_string))
    );
    println!(
        "  secured group addresses (with a group key): {}",
        list(&mut s.adoption.secure_groups.iter().map(GroupAddress::to_string))
    );
    match &s.senders {
        Some(senders) => println!(
            "  secured senders (PID 54, saved to your project): {}",
            list(
                &mut senders
                    .iter()
                    .map(|e| format!("{} (sequence {})", e.address, e.sequence))
            )
        ),
        None => println!("  secured senders (PID 54): not read"),
    }
    if !s.adoption.flagged_without_key.is_empty() {
        let (noun, verb) = objects_are(s.adoption.flagged_without_key.len());
        let link = if s.adoption.flagged_without_key.len() == 1 {
            "links"
        } else {
            "link"
        };
        println!(
            "  NOTE: {noun} {} {verb} secured on the device but {link} no group address bussard \
             has a key for: the keys may be older than the device's last download",
            list(&mut s.adoption.flagged_without_key.iter().map(u16::to_string))
        );
    }
    if !s.adoption.keyed_not_flagged.is_empty() {
        let (noun, verb) = objects_are(s.adoption.keyed_not_flagged.len());
        let link = if s.adoption.keyed_not_flagged.len() == 1 {
            "links"
        } else {
            "link"
        };
        println!(
            "  NOTE: {noun} {} {link} a group address with a group key but {verb} not secured on \
             the device: the keys may be newer than the device's last download",
            list(&mut s.adoption.keyed_not_flagged.iter().map(u16::to_string))
        );
    }
    for note in &s.notes {
        println!("  note: {note}");
    }
    println!("  nothing was written to {target}; Secure and its keys stay with ETS");
}

/// "object … is" or "objects … are", by count.
fn objects_are(n: usize) -> (&'static str, &'static str) {
    if n == 1 {
        ("object", "is")
    } else {
        ("objects", "are")
    }
}

// ---------------------------------------------------------------------------
// Duplicated import-product helpers (private in `import_product_cmd`)
// ---------------------------------------------------------------------------

/// Imports a `.knxprod`: caches it under `<dir>/vendor/` and writes one
/// generated model YAML per application program under `<dir>/models/`, then
/// returns the parsed product data.
// DUP: mirrors the file-writing half of `import_product_cmd::run`. The model
// Product-model shaping (Identity/ComObjectModel/etc.) is NOT duplicated — adopt only
// needs the parsed `ProductData`, and re-serialising the full model would mean
// copying ~400 lines. We instead reuse `import_product_cmd::run` indirectly by
// re-reading, but keep it self-contained here per file-set discipline.
fn import_product(file: &Path, dir: &Path) -> anyhow::Result<ProductData> {
    if !file.exists() {
        bail!("product file not found: {}", file.display());
    }
    let product = bussard_prod::read_knxprod(file)
        .with_context(|| format!("reading product data from {}", file.display()))?;
    if product.applications.is_empty() {
        bail!(
            "no application programs found in {} (is it a valid .knxprod?)",
            file.display()
        );
    }

    // An ETS project export is stored the way `import-product` stores it:
    // every application program extracted once into products/ and pinned
    // (issue #228, item 4); the export itself is not copied.
    if is_project_export(file, &product) {
        let apps: Vec<String> = product
            .applications
            .iter()
            .filter(|a| !a.is_pei_program())
            .map(|a| a.id.clone())
            .collect();
        let entries = crate::lock_pin::extract_and_entries(dir, file, &product, &apps)?;
        println!(
            "  extracted {} application program(s) from the ETS project export {} into products/",
            entries.len(),
            file.display()
        );
        crate::lock_pin::pin(dir, &entries);
        crate::import_product_cmd::write_product_models(&product, dir)?;
        return Ok(product);
    }

    // Store the archive under <dir>/products/ (retained model data) and pin
    // it in bussard.lock (issue #228); the device save that follows links the
    // device to it. An archive already in the store was pinned when it was
    // stored.
    let stored = crate::product_store::store_file(dir, file)?;
    if stored != file {
        println!("  stored vendor file: {}", stored.display());
        let origin = bussard_model::schema::ProductOrigin::File {
            path: file.display().to_string(),
        };
        let entry = crate::lock_pin::archive_entry(&stored, dir, &product, origin)?;
        crate::lock_pin::pin(dir, &[entry]);
    }
    crate::import_product_cmd::write_product_models(&product, dir)?;

    Ok(product)
}

// ---------------------------------------------------------------------------
// Small local helpers
// ---------------------------------------------------------------------------

/// The cached model file names under `<dir>/models/`, sorted.
fn cached_models(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir.join(bussard_model::param_model::MODELS_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.ends_with(".yaml").then_some(name)
        })
        .collect();
    out.sort();
    out
}

/// Prompts for a numbered choice in `0..=max` (0 meaning "none"). Reads one line
/// from stdin; a blank line or parse failure re-prompts up to a few times.
fn prompt_index(label: &str, max: usize) -> anyhow::Result<usize> {
    for _ in 0..3 {
        eprint!("{label} [0-{max}]: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading choice")?;
        match line.trim().parse::<usize>() {
            Ok(n) if n <= max => return Ok(n),
            _ => eprintln!("  please enter a number between 0 and {max}."),
        }
    }
    bail!("no valid choice entered");
}
