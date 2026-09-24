//! The `bussard adopt` subcommand — the guided new-device flow (issue #26).
//!
//! The "I bought an MDT Taster 55 and wired it in" story, orchestrating the
//! existing pieces into one conversational wizard: get product data (import a
//! `.knxprod` or reuse a cached model), assign an individual address via
//! programming mode, verify the write against the product's order numbers, drop
//! a rich `devices/<ia>-<slug>.yaml` (product block + a com-object table lifted
//! from the product model), and hand the user a ready-to-paste `links.yaml`
//! snippet plus the exact next commands.
//!
//! ## Conversational-first, LLM-drivable
//!
//! Every prompt is written to be clear both to a human at a TTY and to an LLM
//! driving over the CLI. The bus writes are irreversible-ish, so the flow is
//! conservative: it refuses to run non-interactively *except* when both a
//! product file (`--product`) and an explicit target address (via the
//! documented [`ADOPT_ADDRESS_ENV`] test hook) are supplied. A wizard needs
//! inputs; without a terminal to gather them on we would otherwise be guessing.
//!
//! ## Shared helpers
//!
//! The allocation, programming-mode wait, model load, read-back verification,
//! device-file write, slug and hex helpers come from `assign_cmd`, and the
//! order-number lookup and vendor `.gitignore` from `import_product_cmd`
//! (issue #86 removed the copies). The few `// DUP:` blocks left differ from
//! their source in behaviour, not just wording (the confirmation has adopt's
//! own non-interactive gate, the com-object shaping feeds a device file rather
//! than a product model, the product import writes no model YAML), so they
//! stay local until the two flows converge.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_mgmt::{manufacturers, system_type, write_individual_address};
use bussard_model::schema::{ComObject, Device, Product};
use bussard_model::{Dpt, Flags, IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData, ResolvedComObject};
use bussard_service::{BusService, WritePolicy};

use crate::assign_cmd::{
    Verified, allocate_address, hex, load_model_optional, validate_explicit_address,
    verify_assignment_with, wait_for_single_device_as, warn_if_still_in_programming_mode,
    write_device_file,
};
use crate::conn_cmd::{
    ConnOverrides, checked_source_or_close, enforce_write_gate, gateway_display, open_service,
    resolve_config,
};
use crate::import_product_cmd::{VENDOR_GITIGNORE, is_project_export, order_numbers_for};

/// Documented test hook: a non-interactive `adopt` reads its target individual
/// address from this variable. `adopt` is a wizard, so it refuses to run without
/// a TTY unless both `--product` and this variable are supplied — the variable
/// stands in for the address the wizard would otherwise prompt for.
pub const ADOPT_ADDRESS_ENV: &str = "BUSSARD_ADOPT_ADDRESS";

/// Runs `bussard adopt`.
pub fn run(
    product: Option<&Path>,
    dir: &Path,
    yes: bool,
    allow_remote_gateway: bool,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let interactive = std::io::stdin().is_terminal();

    // Non-TTY gate: a wizard needs inputs. We allow exactly one scripted shape —
    // a product file plus an explicit address via the documented env hook, AND an
    // explicit `--yes` (issue #74: a re-address in a script must opt in, an
    // explicit address is not itself consent).
    let scripted_address = std::env::var(ADOPT_ADDRESS_ENV)
        .ok()
        .filter(|s| !s.is_empty());
    if !interactive && (product.is_none() || scripted_address.is_none()) {
        bail!(
            "`bussard adopt` is an interactive wizard and needs a terminal.\n\
             To drive it non-interactively (e.g. from a test or a script), supply BOTH a product \
             file (`--product <file.knxprod>`) and an explicit target address via the {ADOPT_ADDRESS_ENV} \
             environment variable."
        );
    }
    if !interactive && !yes {
        bail!(
            "refusing to adopt non-interactively without --yes: an explicit address is not \
             consent to write to the bus. Re-run with --yes to confirm."
        );
    }

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
        &format!("supply {ADOPT_ADDRESS_ENV} or run in a project directory"),
    )?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);

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
                scripted_address.as_deref(),
                interactive,
                &gateway,
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
            dir.join("models").display()
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
        dir.join("models").display()
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
    interactive: bool,
    gateway: &str,
) -> anyhow::Result<ExitCode> {
    println!("  step 2/5  assign an address");

    // Find exactly one device in programming mode.
    let current = match wait_for_single_device_as(service, source, "adopt").await? {
        Some(addr) => addr,
        None => return Ok(ExitCode::FAILURE),
    };
    eprintln!("device in programming mode: {current} (its current address)");

    // Decide the target address.
    let explicit = scripted_address.is_some();
    let target = match scripted_address {
        Some(s) => validate_explicit_address(s, model)?,
        None => match allocate_address(model) {
            Some(addr) => addr,
            None => bail!(
                "could not allocate a free address automatically; re-run with a modelled line \
                 or set {ADOPT_ADDRESS_ENV}"
            ),
        },
    };

    // Confirm.
    if !confirm_assignment(current, target, explicit, interactive, gateway)? {
        eprintln!("aborted; no address was written.");
        return Ok(ExitCode::FAILURE);
    }

    // Write, then verify.
    let write_channel = service.lease_channel().await?;
    write_individual_address(write_channel, source, target)
        .await
        .context("broadcasting the new individual address")?;
    eprintln!("wrote {target}; verifying…");
    // adopt does not clear programming mode in the read-back; the broadcast
    // re-check below warns if the device is still in it.
    let verified = verify_assignment_with(service, source, target, false).await?;

    // Programming-mode persistence check: warn if the just-assigned device still
    // answers the programming-mode broadcast (KNX Virtual does not clear it; a
    // real device with a stuck button would not either). See the helper docs.
    warn_if_still_in_programming_mode(service, source, target).await;

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
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("adopt")
            .with_args([target.to_string()])
            .with_result("before writing the adopted device file"),
    );
    let path = write_device_file(model, dir, device.clone(), "device file")?;
    println!("  wrote {}", path.display());

    // Step 4: links scaffolding (print only — the model stays untouched).
    println!("  step 4/5  wire the group objects");
    print_links_snippet(target, &device, selected);

    // Step 5: summary.
    println!("  step 5/5  summary");
    print_summary(current, target, &verified, &path, selected, mismatch);

    Ok(ExitCode::SUCCESS)
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
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    Device {
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
    }
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

/// Prints a ready-to-paste `links.yaml` snippet: the device's most-useful com
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

    // A paste-ready links.yaml example wiring the first useful object.
    if let Some((num, co)) = objs.first() {
        let dpt = co
            .dpt
            .map(|d| d.to_string())
            .unwrap_or_else(|| "1.001".to_string());
        let name = text_for(**num).unwrap_or("New link");
        println!();
        println!("  ready-to-paste snippets (edit the group address to a free one):");
        println!("    # ---8<--- groups.yaml (under `groups:`)");
        println!("    \"0/0/1\":");
        println!("      name: \"{name}\"");
        println!("      dpt: \"{dpt}\"");
        println!("    # ---8<--- links.yaml (under `links:`)");
        println!("    \"{address}\":");
        println!("      - object: {num}");
        println!("        name: \"{name}\"");
        println!("        send: \"0/0/1\"     # or `listen: [\"0/0/1\"]` for a receiving object");
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
    if let Some(mask) = v.mask {
        println!("  verified: mask {mask:#06x} ({})", system_type(mask));
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
    println!("  1. edit the name/room in {}", path.display());
    println!("  2. wire the group objects: edit links.yaml (snippet above)");
    println!("  3. `bussard plan {target}`   — preview the tables");
    println!("  4. `bussard apply {target}`  — write them to the device");

    // Flash pointer for factory-fresh devices: with product data in hand and a
    // verified device, `bussard flash` (#43) is the path if it is still Unloaded.
    if selected.map(|s| !s.com_objects.is_empty()).unwrap_or(false) {
        println!();
        println!(
            "if this device is factory-fresh (never downloaded), it needs its first application \
             download before links take effect:"
        );
        println!("  - `bussard flash {target}`  — download the application (see issue #43)");
    }
}

// ---------------------------------------------------------------------------
// Duplicated assign helpers (private in `assign_cmd`)
// ---------------------------------------------------------------------------

/// Confirms the assignment on a TTY (y/N). Under the scripted non-TTY shape the
/// address was explicit, so it is accepted without prompting.
// DUP: mirrors `assign_cmd::confirm_assignment`, adapted to the adopt gate.
fn confirm_assignment(
    current: IndividualAddress,
    target: IndividualAddress,
    explicit: bool,
    interactive: bool,
    gateway: &str,
) -> anyhow::Result<bool> {
    if !interactive {
        if explicit {
            // The run() gate already required --yes for this non-interactive path
            // (issue #74), so an explicit address here is genuinely confirmed.
            eprintln!(
                "non-interactive: adopting {current} → {target} via {gateway} (confirmed with --yes)."
            );
            return Ok(true);
        }
        // Unreachable given the run() gate, but fail loudly rather than guess.
        bail!(
            "refusing to adopt an automatically-chosen address ({target}) without a terminal; \
             set {ADOPT_ADDRESS_ENV}"
        );
    }

    crate::confirm::ask(&format!("adopt {current} → {target} via {gateway}?"))
}

// ---------------------------------------------------------------------------
// Duplicated import-product helpers (private in `import_product_cmd`)
// ---------------------------------------------------------------------------

/// Imports a `.knxprod`: caches it under `<dir>/vendor/` and writes one
/// generated model YAML per application program under `<dir>/models/`, then
/// returns the parsed product data.
// DUP: mirrors the file-writing half of `import_product_cmd::run`. The model
// YAML shaping (Identity/ComObjectModel/etc.) is NOT duplicated — adopt only
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

    // An ETS project export is the owner's project, not vendor product data:
    // read it in place and never copy it under vendor/.
    if is_project_export(file, &product) {
        println!(
            "  read the ETS project export in place (not cached under vendor/): {}",
            file.display()
        );
        let models_dir = dir.join("models");
        std::fs::create_dir_all(&models_dir)
            .with_context(|| format!("creating {}", models_dir.display()))?;
        return Ok(product);
    }

    // Cache the source file verbatim under <dir>/vendor/.
    let vendor_dir = dir.join("vendor");
    let vendor_created = !vendor_dir.exists();
    std::fs::create_dir_all(&vendor_dir)
        .with_context(|| format!("creating {}", vendor_dir.display()))?;
    if vendor_created {
        std::fs::write(vendor_dir.join(".gitignore"), VENDOR_GITIGNORE)
            .with_context(|| format!("writing {}", vendor_dir.join(".gitignore").display()))?;
    }
    let original_name = file
        .file_name()
        .context("product file has no file name")?
        .to_owned();
    let vendor_target = vendor_dir.join(&original_name);
    let src_bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let already = vendor_target.exists()
        && std::fs::read(&vendor_target)
            .map(|b| b == src_bytes)
            .unwrap_or(false);
    if !already {
        std::fs::write(&vendor_target, &src_bytes)
            .with_context(|| format!("writing {}", vendor_target.display()))?;
        println!("  cached vendor file: {}", vendor_target.display());
    } else {
        println!("  vendor file already cached: {}", vendor_target.display());
    }

    // Note: adopt writes the device file (step 3) rather than the generated
    // models/*.yaml. We still ensure models/ exists so `import-product` and
    // `adopt` present the same directory layout; a full model dump is left to
    // `bussard import-product` proper.
    let models_dir = dir.join("models");
    std::fs::create_dir_all(&models_dir)
        .with_context(|| format!("creating {}", models_dir.display()))?;

    Ok(product)
}

// ---------------------------------------------------------------------------
// Small local helpers
// ---------------------------------------------------------------------------

/// The cached model file names under `<dir>/models/`, sorted.
fn cached_models(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir.join("models"))
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
