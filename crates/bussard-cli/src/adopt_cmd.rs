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
//! ## Shared helpers
//!
//! The allocation, programming-mode wait, model load, read-back verification,
//! device-file write and hex helpers come from `assign_cmd`, and the
//! order-number lookup and vendor `.gitignore` from `import_product_cmd`
//! (issue #86 removed the copies). The few `// DUP:` blocks left differ from
//! their source in behaviour, not just wording (the com-object shaping feeds a
//! device file rather than a product model, the product import writes no model file), so they
//! stay local until the two flows converge.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_mgmt::{manufacturers, system_type, write_individual_address};
use bussard_model::schema::{ComObject, Device, Product, SecureSender};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData, ResolvedComObject};
use bussard_service::adopt::{SecureAdoption, SecureDeviceFacts};
use bussard_service::identity::SecureStatus;
use bussard_service::secure::{SecureKeyError, SecureMaterial, ToolKeySource, ToolKeys};
use bussard_service::{Authorize, BusService, L4Options, SourcePolicy, WritePolicy};

use crate::assign_cmd::{
    Verified, VerifyKey, allocate_address, hex, load_model_optional, validate_explicit_address,
    verify_assignment_with, wait_for_single_device_as, warn_if_still_in_programming_mode,
    write_device_file,
};
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display, open_service,
    resolve_config,
};
use crate::import_product_cmd::{is_project_export, order_numbers_for};

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
        consent,
    } = options;
    // A run without a terminal and without --yes was refused before this, by
    // `confirm::require_terminal_or_yes` in `main` (issue #74). Without a
    // terminal the wizard's choices take their documented defaults.
    let interactive = std::io::stdin().is_terminal();

    // History (issue #110): capture an edit made outside bussard before the
    // wizard starts writing device files.
    crate::history_cmd::capture_external_edit(dir);

    println!("bussard adopt — the guided new-device flow");
    println!("  step 1/5  product data");

    // Step 1: resolve product data (import, pick a cached model, or product-less).
    let selected = resolve_product(product, dir, interactive)?;
    match &selected {
        Some(app) => println!(
            "  using application {} ({})",
            app.identity_id,
            app.display_name()
        ),
        None => println!(
            "  proceeding product-less (stub-only adoption) — no com-object table will be generated"
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
                yes,
                &gateway,
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

/// A product application selected in step 1, flattened to just what later steps
/// need: identity, order numbers (for the read-back cross-check), and a
/// pre-shaped com-object table.
struct SelectedProduct {
    identity_id: String,
    name: Option<String>,
    manufacturer_ref: Option<String>,
    application_ref: String,
    mask_version: Option<String>,
    order_numbers: Vec<String>,
    com_objects: BTreeMap<u16, ComObjectShape>,
    /// The parsed program, when the product data is at hand: the lock facts
    /// (channel handles, object and parameter keys) are derived from it.
    app: Option<ApplicationProgram>,
}

impl SelectedProduct {
    fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.identity_id.clone())
    }
}

/// A com-object shaped the way the importer emits it (number → dpt/flags/size),
/// ready to fold into a device-file [`ComObject`].
// DUP: shaping mirrors `import_product_cmd::com_object_model`; the device-schema
// `ComObject` is the eventual home once the importer emits device rows directly.
struct ComObjectShape {
    text: Option<String>,
    dpt: Option<Dpt>,
    flags: Flags,
    size: Option<String>,
    ref_id: String,
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
            "  no --product given and no cached models under {} — continuing product-less.",
            dir.join(bussard_model::param_model::MODELS_DIR).display()
        );
        return Ok(None);
    }

    if !interactive {
        // Reachable only via the scripted shape, which always passes --product;
        // guard anyway so a future caller does not silently pick model 0.
        println!(
            "  no --product given (non-interactive) — continuing product-less; \
             pass --product to attach product data."
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
        com_objects: BTreeMap::new(),
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

/// Flattens an application + its product data into a [`SelectedProduct`].
fn shape_selected(app: &ApplicationProgram, data: &ProductData) -> SelectedProduct {
    SelectedProduct {
        identity_id: app.id.clone(),
        name: app.name.clone(),
        manufacturer_ref: app.id.split('_').next().map(str::to_string),
        application_ref: app.id.clone(),
        mask_version: app.mask_version.clone(),
        order_numbers: order_numbers_for(app, data),
        com_objects: shape_com_objects(app),
        app: Some(app.clone()),
    }
}

/// The resolved com-objects keyed by number, smallest-ref-id wins on collision.
// DUP: mirrors `import_product_cmd::com_objects_for` / `com_object_model`.
fn shape_com_objects(app: &ApplicationProgram) -> BTreeMap<u16, ComObjectShape> {
    let mut map: BTreeMap<u16, ComObjectShape> = BTreeMap::new();
    for rc in app.resolved_com_objects() {
        let number = rc.number();
        let candidate = shape_one(&rc);
        match map.get(&number) {
            Some(existing) if existing.ref_id <= candidate.ref_id => {}
            _ => {
                map.insert(number, candidate);
            }
        }
    }
    map
}

fn shape_one(rc: &ResolvedComObject<'_>) -> ComObjectShape {
    let dpt = rc.dpt();
    ComObjectShape {
        text: rc.text().map(str::to_string),
        dpt,
        flags: rc.flags(),
        // Carry size only when no DPT implies it, matching the device schema.
        size: if dpt.is_none() {
            rc.object_size().map(str::to_string)
        } else {
            None
        },
        ref_id: rc.cref.id.clone(),
    }
}

// ---------------------------------------------------------------------------
// The bus-touching flow (steps 2–5)
// ---------------------------------------------------------------------------

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
    yes: bool,
    gateway: &str,
    fetch: crate::product_fetch::Consent,
    adopt_keys: &AdoptKeys<'_>,
) -> anyhow::Result<ExitCode> {
    println!("  step 2/5  assign an address");

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
    let target = match scripted_address {
        Some(s) => validate_explicit_address(s, model)?,
        None if secured => validate_explicit_address(&current.to_string(), model)?,
        None => match allocate_address(model) {
            Some(addr) => addr,
            None => bail!(
                "could not allocate a free address automatically; re-run with a modelled line \
                 or pass the target ADDRESS"
            ),
        },
    };
    if secured && target != current {
        bail!(
            "{current} is KNX Data Secure-activated and the keyring holds its tool key under \
             {current}: adopt reads a secured device at the address ETS gave it and never \
             re-addresses it. Adopt it at {current} (`bussard adopt {current}`), or \
             re-address it first with `bussard assign {target} --keyring <file.knxkeys>` and \
             re-export the keyring from ETS. Nothing was written."
        );
    }
    // The key material for a secured device: its tool key, the keyring's group
    // keys and sequences (the rule `reconstruct` resolves with).
    let material = if secured {
        keys.material(current, true)?
    } else {
        SecureMaterial::default()
    };

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
        let write_channel = service.lease_channel().await?;
        write_individual_address(write_channel, source, target)
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
            "WARNING: the device reported order number {read_order:?}, which is not among the \
                 product's order numbers ({}).",
            sel.order_numbers.join(", ")
        );
        eprintln!(
            "         the product data may not match this hardware — double-check before \
                 wiring links. (continuing anyway)"
        );
    }

    // Step 3: write the rich device file.
    println!("  step 3/5  write the device file");
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
        let (device, model_out, summary) =
            record_secured(model, device, target, selected, &read, &material, current)?;
        (device, Some(model_out), Some(summary))
    } else {
        (device, None, None)
    };
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("adopt")
            .with_args([target.to_string()])
            .with_result("before writing the adopted device file"),
    );
    let path = write_device_file(
        model_out.as_ref().or(model),
        dir,
        device.clone(),
        "device file",
    )?;
    println!("  wrote {}", path.display());

    // Step 4: links scaffolding (print only — the model stays untouched), or
    // the links a secured device already holds (recorded in the model).
    println!("  step 4/5  wire the group objects");
    match &secure_summary {
        Some(summary) if summary.links > 0 => println!(
            "  recorded the {} link(s) the device holds in {}",
            summary.links,
            path.display()
        ),
        _ => print_links_snippet(target, &device, selected),
    }

    // Step 5: summary.
    println!("  step 5/5  summary");
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

/// Whether a read-back order number matches one of the product's order numbers.
/// Comparison is case-insensitive and tolerant of surrounding whitespace, and
/// also accepts a substring match either way (vendors abbreviate order strings).
fn order_matches(read: &str, candidates: &[String]) -> bool {
    let read = read.trim().to_ascii_uppercase();
    candidates.iter().any(|c| {
        let c = c.trim().to_ascii_uppercase();
        read == c || read.contains(&c) || c.contains(&read)
    })
}

/// Builds the rich device from the verified read-back and the selected product.
fn build_device(
    address: IndividualAddress,
    v: &Verified,
    selected: Option<&SelectedProduct>,
) -> Device {
    let name = selected
        .and_then(|s| s.name.clone())
        .unwrap_or_else(|| "New device (adopt)".to_string());

    let product = build_product(v, selected);
    let com_objects = selected
        .map(|s| {
            s.com_objects
                .iter()
                .map(|(num, shape)| {
                    (
                        *num,
                        ComObject {
                            dpt: shape.dpt,
                            size: shape.size.clone(),
                            flags: shape.flags,
                            reference: Some(shape.ref_id.clone()),
                            channel: None,
                            secure: false,
                            function: None,
                            key: None,
                            text: None,
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let mut device = Device {
        address,
        name,
        description: None,
        location: None,
        replaced: None,
        product,
        channels: Default::default(),
        parameters: Default::default(),
        module_bases: Default::default(),
        com_objects,
        // KNX Secure state is populated only by the knxproj importer (issue #71);
        // an adopted-from-bus device carries none.
        security: None,
        application_override: None,
        lock: Default::default(),
    };
    // The lock facts under the vendor defaults: the objects the program
    // shows, with channel handles and keys from day one.
    if let Some(app) = selected.and_then(|s| s.app.as_ref()) {
        let facts =
            bussard_project::facts::derive_facts(app, &BTreeMap::new(), &Default::default());
        device.com_objects.clear();
        bussard_project::facts::apply_facts(&mut device, app, &facts, &BTreeMap::new());
    }
    device
}

/// The application program `app_ref` from an archive `bussard.lock` pins.
fn vendor_application(dir: &Path, app_ref: &str) -> Option<ApplicationProgram> {
    crate::product_store::pinned_application(dir, app_ref)
}

/// The device's product block: identity from the matched application where we
/// have it, filled in from the bus read-back otherwise.
fn build_product(v: &Verified, selected: Option<&SelectedProduct>) -> Option<Product> {
    let manufacturer = v.manufacturer_id.map(manufacturers::display);
    let order_number = selected
        .and_then(|s| s.order_numbers.first().cloned())
        .or_else(|| v.order.clone());
    // Mask strings use the importer's bare-hex form ("07B0"), whether they come
    // from the product data or the live descriptor read-back.
    let mask = selected
        .and_then(|s| s.mask_version.clone())
        .or_else(|| v.mask.map(|m| format!("{m:04X}")));
    let manufacturer_ref = selected.and_then(|s| s.manufacturer_ref.clone());
    let application_ref = selected.map(|s| s.application_ref.clone());

    if manufacturer.is_none()
        && manufacturer_ref.is_none()
        && order_number.is_none()
        && application_ref.is_none()
        && mask.is_none()
    {
        return None;
    }
    Some(Product {
        manufacturer,
        manufacturer_ref,
        order_number,
        hardware_ref: None,
        application_ref,
        mask,
    })
}

/// The device-file table header and entry key for com object `num`:
/// `[channel.<handle>]` for a channel object, `[links]` otherwise, and the key
/// the lock assigns (else the number).
pub(crate) fn object_placement(device: &Device, num: u16) -> (String, String) {
    let co = device.com_objects.get(&num);
    let table = match co.and_then(|c| c.channel.as_deref()) {
        Some(id) => {
            let handle = device
                .channels
                .get(id)
                .and_then(|c| c.key.clone())
                .unwrap_or_else(|| id.to_string());
            format!("[channel.{handle}]")
        }
        None => "[links]".to_string(),
    };
    let key = co
        .and_then(|c| c.key.clone())
        .unwrap_or_else(|| num.to_string());
    (table, key)
}

/// Prints a ready-to-paste device-file snippet: the device's most-useful com
/// objects (transmit-capable first), then an example link block. The snippet
/// goes to stdout only — the model itself is never modified here.
///
/// The object display text (button/sensor label) lives on the product shape
/// rather than the device row, so `selected` is consulted for names/suggestions.
fn print_links_snippet(
    address: IndividualAddress,
    device: &Device,
    selected: Option<&SelectedProduct>,
) {
    if device.com_objects.is_empty() {
        println!(
            "  no com-object table (product-less) — import the product later with \
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
    println!();
    println!("adopted {current} → {target}");
    let secured = v.secure == SecureStatus::Activated;
    match v.mask {
        Some(mask) if secured => println!(
            "  verified (secured): mask {mask:#06x} ({}); Data Secure activated",
            system_type(mask)
        ),
        Some(mask) => println!("  verified: mask {mask:#06x} ({})", system_type(mask)),
        None => {}
    }
    if let Some(serial) = &v.serial {
        println!("  serial: {}", hex(serial));
    }
    println!("  device file: {}", path.display());
    match selected {
        Some(sel) if !sel.com_objects.is_empty() => {
            println!(
                "  product: {} ({} com objects)",
                sel.display_name(),
                sel.com_objects.len()
            );
        }
        Some(sel) => println!("  product: {} (identity only)", sel.display_name()),
        None => println!("  product: none (stub-only adoption)"),
    }
    if mismatch {
        println!("  NOTE: order-number cross-check flagged a possible mismatch (see above).");
    }

    println!();
    println!("what remains manual:");
    if secured {
        println!("  1. edit the name/room in {}", path.display());
        println!(
            "  2. `bussard plan {target}`   — should report no change (the model now holds what \
             the device holds; it uses the same keyring)"
        );
        return;
    }
    println!("  1. edit the name/room in {}", path.display());
    println!(
        "  2. wire the group objects: edit {} (snippet above)",
        path.display()
    );
    println!("  3. `bussard plan {target}`   — preview the tables");
    println!("  4. `bussard apply {target}`  — write them to the device");

    // Flash pointer for factory-fresh devices: with product data in hand and a
    // verified device, `bussard flash` (#43) is the path if it is still Unloaded.
    // A Data Secure device is commissioned already (ETS activated it).
    if !secured && selected.map(|s| !s.com_objects.is_empty()).unwrap_or(false) {
        println!();
        println!(
            "if this device is factory-fresh (never downloaded), it needs its first application \
             download before links take effect:"
        );
        println!("  - `bussard flash {target}`  — download the application (see issue #43)");
    }
}

// ---------------------------------------------------------------------------
// A KNX Data Secure-activated device (issue #201, tier 1)
// ---------------------------------------------------------------------------

/// The failure for a device that hides its mask (Data Secure-activated) while
/// the keyring holds no tool key for it: the resolver's "no tool key" message
/// plus what to do. No device file is written.
fn activated_without_key(
    target: IndividualAddress,
    current: IndividualAddress,
    adopt_keys: &AdoptKeys<'_>,
) -> anyhow::Error {
    let moved = if target == current {
        String::new()
    } else {
        format!(" The address {target} was written; the device answers there.")
    };
    match adopt_keys.keyring {
        Some(path) => {
            let no_entry = SecureKeyError::NoEntry {
                path: path.to_path_buf(),
                target,
                devices: adopt_keys.keys.listed().len(),
            };
            anyhow!(
                "{target} is KNX Data Secure-activated (it hides its mask from an unsecured read) \
                 and cannot be adopted: {no_entry} Re-export the keyring from ETS after the \
                 device's secure commissioning, so it lists {target}, and point \
                 --keyring (or connection.keyring in bussard.toml) at it. No device file was written.{moved}"
            )
        }
        None => anyhow!(
            "{target} is KNX Data Secure-activated (it hides its mask from an unsecured read) and \
             cannot be adopted without its tool key: {}. No device file was written.{moved}",
            bussard_service::guidance::tool_key_hint()
        ),
    }
}

/// What the secured session read from an activated device.
struct SecuredRead {
    /// The live tables, or `None` for a mask no table reader speaks.
    tables: Option<bussard_mgmt::tables::DeviceTables>,
    /// The security object read-back (PID 61, PID 54).
    security: bussard_download::SecurityReadback,
    /// The parameter read-back, when product data was at hand.
    params: Option<crate::param_readback::ParamState>,
    /// Why a part is missing.
    notes: Vec<String>,
}

/// Reads an activated device's tables, security object and parameters in one
/// management session over `A_SecureData`. Read-only: descriptor, property,
/// extended-property and memory reads (the `reconstruct` path plus the
/// security object's PID 61 and PID 54).
#[allow(clippy::too_many_arguments)] // one call site; the inputs are the flow's state
async fn read_secured(
    service: &BusService,
    source: IndividualAddress,
    target: IndividualAddress,
    dir: &Path,
    model: Option<&Model>,
    device: &Device,
    selected: Option<&SelectedProduct>,
    product: Option<&Path>,
    material: &SecureMaterial,
) -> anyhow::Result<SecuredRead> {
    println!(
        "  reading the Data Secure device over A_SecureData (tables, security object, parameters)"
    );
    // The product the parameter read-back decodes with, found through the
    // device file being written (its order number and application).
    let mut with_device = model
        .cloned()
        .unwrap_or_else(crate::assign_cmd::empty_model);
    with_device.devices.insert(
        target,
        bussard_model::LoadedDevice {
            device: device.clone(),
            file_stem: target.to_string(),
        },
    );
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
    let options = L4Options {
        source: SourcePolicy::Known(source),
        tool_key: material.tool_key.clone(),
        high_water: bussard_secure::SequenceHighWater::new(),
        authorize: Authorize::BestEffort(bussard_mgmt::apci::FREE_ACCESS_KEY),
        ..L4Options::default()
    };
    let with_device = &with_device;
    let product_source = product_source.as_ref();
    let read = service
        .with_l4(target, &options, async |l4| {
            // The APDU budget sizes the PID 61 chunks as ETS does.
            let _ = l4.negotiate_max_apdu().await;
            let tables = match bussard_download::read_live_tables(l4).await? {
                bussard_download::LiveRead::Tables(live) => Some(live),
                bussard_download::LiveRead::UnsupportedMask { mask, .. } => {
                    tracing::info!("{target}: no table reader for mask {mask:04X}");
                    None
                }
            };
            let security = bussard_download::read_security_object(l4).await?;
            let params = match (&tables, product_source) {
                (Some(live), Some(product)) => Some(
                    crate::param_readback::read_state(
                        l4,
                        product,
                        Some(with_device),
                        target,
                        live.tables().mask,
                    )
                    .await,
                ),
                _ => None,
            };
            Ok::<_, anyhow::Error>((tables.map(|t| t.tables().clone()), security, params))
        })
        .await
        .map_err(|err| {
            err.context(format!(
                "reading {target} over A_SecureData with its keyring tool key"
            ))
        })?;
    let (tables, security, params) = read;
    if tables.is_none() {
        notes.push(
            "the link tables were not read: bussard has no table reader for this mask".into(),
        );
    }
    if product_source.is_none() && notes.is_empty() {
        notes.push(
            "parameters not read: no product data (pass --product or cache the .knxprod)".into(),
        );
    }
    Ok(SecuredRead {
        tables,
        security,
        params,
        notes,
    })
}

/// What the secured adoption recorded, for the summary.
struct SecureSummary {
    /// Links recorded in the device file.
    links: usize,
    /// Parameters recorded (values that differ from the vendor defaults).
    parameters: usize,
    /// The Data Secure view.
    adoption: SecureAdoption,
    /// The PID 54 senders, or `None` when not read.
    senders: Option<Vec<SecureSender>>,
    /// Why a part is missing.
    notes: Vec<String>,
}

/// Records a secured read in a copy of the model: the device's parameters and
/// objects (lock facts under the values it holds), its links, the groups they
/// use, and the Data Secure state. Returns the device to write, the model to
/// write it into and the summary.
///
/// # Errors
///
/// Only an internal inconsistency (the device missing from its own copy).
fn record_secured(
    model: Option<&Model>,
    mut device: Device,
    target: IndividualAddress,
    selected: Option<&SelectedProduct>,
    read: &SecuredRead,
    material: &SecureMaterial,
    current: IndividualAddress,
) -> anyhow::Result<(Device, Model, SecureSummary)> {
    let mut notes = read.notes.clone();
    notes.extend(read.security.notes.iter().cloned());
    let mut parameters = 0;
    // The parameters the device holds: the lock facts (visible objects,
    // channels, keys) follow its values, and the file keeps the non-defaults.
    if let (Some(app), Some(state)) = (selected.and_then(|s| s.app.as_ref()), read.params.as_ref())
    {
        match &state.detail {
            Some(detail) => {
                let keys: std::collections::BTreeSet<&str> = detail
                    .decoded
                    .non_default
                    .iter()
                    .map(|r| r.key.as_str())
                    .collect();
                let stored: BTreeMap<String, String> = detail
                    .decoded
                    .values
                    .iter()
                    .filter(|(k, _)| keys.contains(k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                parameters = stored.len();
                let facts = bussard_project::facts::derive_facts(
                    app,
                    &detail.decoded.values,
                    &Default::default(),
                );
                device.com_objects.clear();
                bussard_project::facts::apply_facts(&mut device, app, &facts, &stored);
            }
            None => {
                if let Some(note) = &state.readback.note {
                    notes.push(format!("parameters: {note}"));
                }
            }
        }
    }

    // The links, sending on an object's first address when it transmits.
    let resolved: Vec<(u16, GroupAddress)> = read
        .tables
        .as_ref()
        .map(|t| t.resolved.iter().map(|l| (l.object, l.ga)).collect())
        .unwrap_or_default();
    let links = bussard_service::adopt::links_from_tables(&resolved, |object| {
        device.com_objects.get(&object).map(|co| co.flags)
    });
    for link in &links {
        device
            .com_objects
            .entry(link.object)
            .or_insert_with(|| bussard_service::adopt::placeholder_object(link));
    }

    let mut out = model
        .cloned()
        .unwrap_or_else(crate::assign_cmd::empty_model);
    let placeholder = |ga: GroupAddress| format!("GA {ga} (adopted from {target})");
    for link in &links {
        for ga in link.send.iter().chain(link.listen.iter()) {
            out.groups
                .groups
                .entry(*ga)
                .or_insert_with(|| bussard_model::schema::Group {
                    name: placeholder(*ga),
                    ..Default::default()
                });
        }
    }
    let empty = std::collections::HashMap::new();
    let group_keys = material.group_keys.as_ref().unwrap_or(&empty);
    let device_flags = read.security.secured_objects();
    let adoption =
        bussard_service::adopt::derive_secure_adoption(&links, group_keys, device_flags.as_ref());
    let senders: Option<Vec<SecureSender>> = read.security.senders.as_ref().map(|entries| {
        entries
            .iter()
            .map(|e| SecureSender {
                address: e.address,
                sequence: e.sequence,
            })
            .collect()
    });
    let facts = SecureDeviceFacts {
        sequence_number: material.device_sequences.get(&current).copied(),
        senders: senders.clone().unwrap_or_default(),
    };
    let link_count = links.len();
    if !links.is_empty() {
        out.links.links.insert(target, links);
    }
    out.devices.insert(
        target,
        bussard_model::LoadedDevice {
            device,
            file_stem: target.to_string(),
        },
    );
    bussard_service::adopt::apply_secure_adoption(&mut out, target, &adoption, &facts, placeholder);
    let device = out
        .devices
        .remove(&target)
        .map(|loaded| loaded.device)
        .context("the adopted device vanished from the model")?;
    let summary = SecureSummary {
        links: link_count,
        parameters,
        adoption,
        senders,
        notes,
    };
    Ok((device, out, summary))
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
    println!("KNX Data Secure (read over A_SecureData with the keyring's tool key):");
    println!("  device file: [security] activated = true, secure_commissioning = true");
    println!(
        "  links: {}; parameters (non-default): {}",
        s.links, s.parameters
    );
    let source = if s.adoption.from_device_flags {
        "the device's GO security flags (PID 61)"
    } else {
        "the keyring's group keys (PID 61 not read)"
    };
    println!(
        "  secure objects ({source}): {}",
        list(&mut s.adoption.secure_objects.iter().map(u16::to_string))
    );
    println!(
        "  secure groups (keyed in the keyring): {}",
        list(&mut s.adoption.secure_groups.iter().map(GroupAddress::to_string))
    );
    match &s.senders {
        Some(senders) => println!(
            "  secured senders (PID 54, kept in the lock): {}",
            list(
                &mut senders
                    .iter()
                    .map(|e| format!("{} (sequence {})", e.address, e.sequence))
            )
        ),
        None => println!("  secured senders (PID 54): not read"),
    }
    if !s.adoption.flagged_without_key.is_empty() {
        println!(
            "  NOTE: object(s) {} are secured on the device but link no group address the keyring \
             has a key for: the keyring may be older than the device's last download",
            list(&mut s.adoption.flagged_without_key.iter().map(u16::to_string))
        );
    }
    if !s.adoption.keyed_not_flagged.is_empty() {
        println!(
            "  NOTE: object(s) {} link a keyed group address but are not secured on the device: \
             the keyring may be newer than the device's last download",
            list(&mut s.adoption.keyed_not_flagged.iter().map(u16::to_string))
        );
    }
    for note in &s.notes {
        println!("  note: {note}");
    }
    println!("  nothing was written to {target}; activation and keys stay with ETS");
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

    // An ETS project export is the owner's project: read in place here.
    // `bussard import-product <export>` extracts its programs into products/.
    if is_project_export(file, &product) {
        println!(
            "  read the ETS project export in place: {} (run `bussard import-product` on it \
             to store its product data under products/)",
            file.display()
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn model_with(addrs: &[&str]) -> Model {
        let mut model = crate::assign_cmd::empty_model();
        for s in addrs {
            let addr: IndividualAddress = s.parse().expect("test fixture");
            model.devices.insert(
                addr,
                bussard_model::LoadedDevice {
                    device: Device {
                        address: addr,
                        name: "d".to_string(),
                        description: None,
                        location: None,
                        replaced: None,
                        product: None,
                        channels: Default::default(),
                        parameters: Default::default(),
                        module_bases: Default::default(),
                        com_objects: Default::default(),
                        security: None,
                        application_override: None,
                        lock: Default::default(),
                    },
                    file_stem: format!("{addr}-d"),
                },
            );
        }
        model
    }

    #[test]
    fn allocate_picks_lowest_free_on_dominant_line() -> Result<(), Box<dyn std::error::Error>> {
        let model = model_with(&["1.1.1", "1.1.2", "1.1.4"]);
        assert_eq!(allocate_address(Some(&model)), Some("1.1.3".parse()?));
        Ok(())
    }

    #[test]
    fn order_matches_is_case_and_substring_tolerant() {
        let cands = vec!["MDT-BE-04001.02".to_string()];
        assert!(order_matches("mdt-be-04001.02", &cands));
        assert!(order_matches("MDT-BE-04001.02 ", &cands));
        // Vendor abbreviations: read-back a prefix.
        assert!(order_matches("MDT-BE-04001", &cands));
        assert!(!order_matches("JUNG-4093TSM", &cands));
    }

    #[test]
    fn build_product_prefers_product_over_readback() -> Result<(), Box<dyn std::error::Error>> {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            serial: None,
            order: Some("READBACK-ORDER".to_string()),
            ..Verified::default()
        };
        let sel = SelectedProduct {
            identity_id: "M-0083_A-1234-11-ABCD".to_string(),
            name: Some("Taster".to_string()),
            manufacturer_ref: Some("M-0083".to_string()),
            application_ref: "M-0083_A-1234-11-ABCD".to_string(),
            mask_version: Some("07B0".to_string()),
            order_numbers: vec!["MDT-BE-04001.02".to_string()],
            com_objects: BTreeMap::new(),
            app: None,
        };
        let p = build_product(&v, Some(&sel)).ok_or("expected a value")?;
        assert_eq!(p.order_number.as_deref(), Some("MDT-BE-04001.02"));
        assert_eq!(p.application_ref.as_deref(), Some("M-0083_A-1234-11-ABCD"));
        assert_eq!(p.manufacturer_ref.as_deref(), Some("M-0083"));
        assert_eq!(p.mask.as_deref(), Some("07B0"));
        assert_eq!(p.manufacturer.as_deref(), Some("MDT"));
        Ok(())
    }

    #[test]
    fn build_product_falls_back_to_readback_without_product()
    -> Result<(), Box<dyn std::error::Error>> {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            serial: None,
            order: Some("MDT-JAL0410".to_string()),
            ..Verified::default()
        };
        let p = build_product(&v, None).ok_or("expected a value")?;
        assert_eq!(p.order_number.as_deref(), Some("MDT-JAL0410"));
        assert_eq!(p.mask.as_deref(), Some("07B0"));
        assert!(p.application_ref.is_none());
        Ok(())
    }

    #[test]
    fn build_device_carries_com_objects() -> Result<(), Box<dyn std::error::Error>> {
        let mut com = BTreeMap::new();
        com.insert(
            0u16,
            ComObjectShape {
                text: Some("Switch".to_string()),
                dpt: Some(Dpt::new(1, Some(1))),
                flags: "CWT".parse()?,
                size: None,
                ref_id: "R-1".to_string(),
            },
        );
        let sel = SelectedProduct {
            identity_id: "APP".to_string(),
            name: Some("Taster".to_string()),
            manufacturer_ref: None,
            application_ref: "APP".to_string(),
            mask_version: None,
            order_numbers: vec![],
            com_objects: com,
            app: None,
        };
        let v = Verified::default();
        let dev = build_device("1.1.7".parse()?, &v, Some(&sel));
        assert_eq!(dev.name, "Taster");
        assert_eq!(dev.com_objects.len(), 1);
        let co = dev.com_objects.get(&0).ok_or("expected a value")?;
        assert_eq!(co.dpt, Some(Dpt::new(1, Some(1))));
        assert_eq!(co.reference.as_deref(), Some("R-1"));
        Ok(())
    }
}
