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
//! ## File-set discipline
//!
//! This module deliberately duplicates a handful of small private helpers from
//! `assign_cmd` and `import_product_cmd` (allocation, slug, the vendor/model
//! write path, the com-object model shaping) rather than reaching into their
//! private internals. Each duplicate is flagged with a `// DUP:` comment noting
//! the source and that it should later be promoted to a shared helper.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bussard_bus::{Bus, BusHandle, ops};
use bussard_mgmt::apci::{PID_MANUFACTURER_ID, PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_mgmt::{
    DeviceConnection, LeaseChannel, broadcast, manufacturers, system_type, write_individual_address,
};
use bussard_model::schema::{ComObject, Device, Product};
use bussard_model::{Dpt, Flags, IndividualAddress, LoadedDevice, Model};
use bussard_prod::{ApplicationProgram, ProductData, ResolvedComObject};

use crate::conn_cmd::{ConnOverrides, enforce_write_gate, gateway_display, resolve_config};

/// The line to allocate on when the model has no devices to infer one from.
// DUP: mirrors `assign_cmd::FALLBACK_LINE`; promote to a shared allocation helper.
const FALLBACK_LINE: (u8, u8) = (1, 1);

/// Total time to wait for a device to enter programming mode before giving up.
// DUP: mirrors `assign_cmd::PROGRAMMING_WAIT_TOTAL`.
const PROGRAMMING_WAIT_TOTAL: Duration = Duration::from_secs(30);

/// Initial polling budget before we start nagging the user.
// DUP: mirrors `assign_cmd::INITIAL_POLL_TOTAL`.
const INITIAL_POLL_TOTAL: Duration = Duration::from_secs(3);

/// Environment variable that shortens the programming-mode wait windows, shared
/// with `assign` so the two flows stay in lockstep under the integration tests.
// DUP: mirrors `assign_cmd::WAIT_MS_ENV`.
const WAIT_MS_ENV: &str = "BUSSARD_ASSIGN_WAIT_MS";

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
    let model = load_model_for_adopt(dir, have_explicit)?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Safety envelope (issue #74): refuse a write to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        // Wait for the actor to connect so the tunnel-assigned source address is
        // available (falling back to 0.0.255 on routing) — issue #30.
        handle.wait_connected(Duration::from_secs(10)).await;
        let source = ops::group_source(&handle);
        // Guard with Ctrl-C so an interrupt still closes the tunnel cleanly.
        let result = tokio::select! {
            result = adopt_flow(
                &handle,
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
        let _ = handle.close().await;
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

/// The order numbers that map to this application program, sorted.
// DUP: mirrors `import_product_cmd::order_numbers_for`.
fn order_numbers_for(app: &ApplicationProgram, product: &ProductData) -> Vec<String> {
    let mut orders: Vec<String> = product
        .hardware
        .order_to_apps
        .iter()
        .filter(|(_, apps)| apps.iter().any(|a| a == &app.id))
        .map(|(order, _)| order.clone())
        .collect();
    orders.sort();
    orders.dedup();
    orders
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
    handle: &BusHandle,
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
    let current = match wait_for_single_device(handle, source).await? {
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
    let write_channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    write_individual_address(write_channel, source, target)
        .await
        .context("broadcasting the new individual address")?;
    eprintln!("wrote {target}; verifying…");
    let verified = verify_assignment(handle, source, target).await?;

    // Programming-mode persistence check: warn if the just-assigned device still
    // answers the programming-mode broadcast (KNX Virtual does not clear it; a
    // real device with a stuck button would not either). See the helper docs.
    warn_if_still_in_programming_mode(handle, source, target).await;

    // Cross-check the read-back order number against the product's order numbers.
    let mut mismatch = false;
    if let (Some(sel), Some(read_order)) = (selected, verified.order.as_deref()) {
        if !sel.order_numbers.is_empty() && !order_matches(read_order, &sel.order_numbers) {
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
    }

    // Step 3: write the rich device file.
    println!("  step 3/5  write the device file");
    let device = build_device(target, &verified, selected);
    let path = write_device_file(model, dir, device.clone())?;
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

/// Loads the model for an adopt run (optional under an explicit address).
///
/// An **absent** model directory is a fresh project (with an explicit address we
/// warn and continue); a directory **present but failing to parse** is a hard
/// error either way — adopt is a management command and must never proceed
/// against a broken model (issue #55).
// DUP: mirrors `assign_cmd::load_model_for_assign`.
fn load_model_for_adopt(dir: &Path, have_explicit_address: bool) -> anyhow::Result<Option<Model>> {
    if !dir.exists() {
        if have_explicit_address {
            eprintln!(
                "warning: model directory {} not found; continuing because an explicit address was given",
                dir.display()
            );
            return Ok(None);
        }
        return Err(anyhow!(
            "model directory {} not found\n\
             adopt needs the model to allocate a free address; supply {ADOPT_ADDRESS_ENV} \
             or run in a project directory",
            dir.display()
        ));
    }
    match Model::load(dir) {
        Ok(model) => Ok(Some(model)),
        Err(err) => Err(anyhow!(
            "could not load model from {}: {err}\n\
             refusing to run adopt against a model that failed to parse; fix the model files first",
            dir.display()
        )),
    }
}

/// Polls for devices in programming mode, nagging the user to press the button.
// DUP: mirrors `assign_cmd::wait_for_single_device`.
async fn wait_for_single_device(
    handle: &BusHandle,
    source: IndividualAddress,
) -> anyhow::Result<Option<IndividualAddress>> {
    let (initial, total) = wait_budgets();
    let start = tokio::time::Instant::now();
    let mut nagged = false;
    let window = collection_window();
    loop {
        let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
        let found = broadcast::devices_in_programming_mode_within(channel, source, window).await?;
        match found.len() {
            1 => return Ok(Some(found[0])),
            n if n > 1 => {
                eprintln!("{n} devices are in programming mode:");
                for addr in &found {
                    eprintln!("  {addr}");
                }
                eprintln!(
                    "adopt works on one device at a time — leave programming mode on all but \
                     the one you want, then re-run."
                );
                return Ok(None);
            }
            _ => {}
        }

        let elapsed = start.elapsed();
        if elapsed >= total {
            eprintln!();
            eprintln!(
                "no device entered programming mode within {}s.",
                total.as_secs()
            );
            eprintln!(
                "press the programming button on the new device (its LED usually lights up), \
                 then re-run `bussard adopt`."
            );
            return Ok(None);
        }

        if elapsed >= initial && !nagged {
            eprintln!(
                "no device in programming mode yet — press the programming button on the device, \
                 then keep waiting (or re-run)."
            );
            nagged = true;
        }

        if nagged {
            let remaining = total.saturating_sub(elapsed).as_secs();
            eprint!("\rwaiting for a device… {remaining}s left   ");
            let _ = std::io::stderr().flush();
        }
    }
}

/// Reads [`WAIT_MS_ENV`] as a millisecond budget, if set and parseable.
// DUP: mirrors `assign_cmd::wait_ms_override`.
fn wait_ms_override() -> Option<Duration> {
    std::env::var(WAIT_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// The (initial-nag, total) wait budgets, honouring [`WAIT_MS_ENV`].
// DUP: mirrors `assign_cmd::wait_budgets`.
fn wait_budgets() -> (Duration, Duration) {
    match wait_ms_override() {
        Some(total) => (total / 2, total),
        None => (INITIAL_POLL_TOTAL, PROGRAMMING_WAIT_TOTAL),
    }
}

/// The per-poll response-collection window, honouring [`WAIT_MS_ENV`].
// DUP: mirrors `assign_cmd::collection_window`.
fn collection_window() -> Duration {
    wait_ms_override().unwrap_or(bussard_mgmt::broadcast::PROGRAMMING_MODE_WINDOW)
}

/// Validates an explicit target address against the model.
// DUP: mirrors `assign_cmd::validate_explicit_address`.
fn validate_explicit_address(s: &str, model: Option<&Model>) -> anyhow::Result<IndividualAddress> {
    let addr: IndividualAddress = s.parse().with_context(|| {
        format!("invalid address {s:?}; expected area.line.device like \"1.1.47\"")
    })?;

    if let Some(model) = model {
        if model.devices.contains_key(&addr) {
            let name = model
                .devices
                .get(&addr)
                .map(|d| d.device.name.as_str())
                .unwrap_or("");
            bail!("address {addr} is already used in the model (\"{name}\"); pick a free one");
        }
        let lines = model_lines(model);
        if !lines.is_empty() && !lines.contains(&(addr.area(), addr.line())) {
            let known: Vec<String> = lines.iter().map(|(a, l)| format!("{a}.{l}")).collect();
            bail!(
                "address {addr} is on line {}.{}, which the model does not use (known lines: {}); \
                 double-check the address",
                addr.area(),
                addr.line(),
                known.join(", ")
            );
        }
    }
    Ok(addr)
}

/// Allocates the lowest free device number on the model's dominant line.
// DUP: mirrors `assign_cmd::allocate_address`.
fn allocate_address(model: Option<&Model>) -> Option<IndividualAddress> {
    let model = model?;
    let (area, line) = dominant_line(model).unwrap_or(FALLBACK_LINE);
    let used = used_devices_on_line(model, area, line);
    allocate_on_line(area, line, &used)
}

// DUP: mirrors `assign_cmd::allocate_on_line`.
fn allocate_on_line(area: u8, line: u8, used: &BTreeSet<u8>) -> Option<IndividualAddress> {
    (1u8..=255)
        .find(|d| !used.contains(d))
        .and_then(|d| IndividualAddress::new(area, line, d).ok())
}

// DUP: mirrors `assign_cmd::used_devices_on_line`.
fn used_devices_on_line(model: &Model, area: u8, line: u8) -> BTreeSet<u8> {
    model
        .devices
        .keys()
        .filter(|ia| ia.area() == area && ia.line() == line)
        .map(|ia| ia.device())
        .collect()
}

// DUP: mirrors `assign_cmd::dominant_line`.
fn dominant_line(model: &Model) -> Option<(u8, u8)> {
    let mut counts: BTreeMap<(u8, u8), usize> = BTreeMap::new();
    for ia in model.devices.keys() {
        *counts.entry((ia.area(), ia.line())).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|&(line, count)| (count, std::cmp::Reverse(line)))
        .map(|(line, _)| line)
}

// DUP: mirrors `assign_cmd::model_lines`.
fn model_lines(model: &Model) -> BTreeSet<(u8, u8)> {
    model
        .devices
        .keys()
        .map(|ia| (ia.area(), ia.line()))
        .collect()
}

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

    eprint!("adopt {current} → {target} via {gateway}? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// What the post-write verification read back from the device.
// DUP: mirrors `assign_cmd::Verified`.
#[derive(Default)]
struct Verified {
    mask: Option<u16>,
    manufacturer_id: Option<u16>,
    serial: Option<Vec<u8>>,
    order: Option<String>,
}

/// Verifies the write by connecting to `target` and reading its descriptor plus
/// best-effort manufacturer/serial/order properties.
// DUP: mirrors `assign_cmd::verify_assignment`.
async fn verify_assignment(
    handle: &BusHandle,
    source: IndividualAddress,
    target: IndividualAddress,
) -> anyhow::Result<Verified> {
    let channel = LeaseChannel::new(handle.lease().await.context("leasing the bus")?);
    let mut dev = DeviceConnection::connect(channel, target, source)
        .await
        .map_err(|err| {
            anyhow!(
                "wrote {target} but could not connect to it afterwards ({err}); the address may \
                 not have been applied — check the device and re-run"
            )
        })?;

    let mask = dev.device_descriptor().await.map_err(|err| {
        if matches!(err, bussard_mgmt::MgmtError::Disconnected { .. }) {
            anyhow!(
                "wrote {target} and connected, but the device disconnected on the first read: \
                 typical for devices whose management is gated on a loaded application or a \
                 different medium profile (e.g. KNX Virtual IP-medium `*.ip` devices, which \
                 disconnect on descriptor reads while their `*.tp` siblings answer). The address \
                 was written but could not be verified."
            )
        } else {
            anyhow!(
                "wrote {target} and connected, but the device did not answer a descriptor read \
                 ({err}); the assignment is unverified"
            )
        }
    })?;

    // Authorize the session (free access), as ETS does after the descriptor read
    // (issue #52 finding #1). Best-effort — the descriptor read already verified
    // the write; the property reads below are informational.
    if let Err(err) = dev.authorize(bussard_mgmt::apci::FREE_ACCESS_KEY).await {
        tracing::debug!("{target} authorize (free access) did not grant: {err}");
    }

    let manufacturer_id = match dev.read_device_property(PID_MANUFACTURER_ID).await {
        Ok(bytes) if bytes.len() >= 2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        _ => None,
    };
    let serial = dev
        .read_device_property(PID_SERIAL_NUMBER)
        .await
        .ok()
        .filter(|v| !v.is_empty());
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());

    let _ = dev.disconnect().await;
    Ok(Verified {
        mask: Some(mask),
        manufacturer_id,
        serial,
        order,
    })
}

/// Re-runs the programming-mode broadcast once, briefly, after write+verify and
/// warns if the just-assigned `target` still answers it.
// DUP: mirrors `assign_cmd::warn_if_still_in_programming_mode`.
///
/// A conformant device leaves programming mode when it applies its new address;
/// KNX Virtual devices do not, so the just-adopted device would be re-captured by
/// the next `assign`/`adopt`. On real hardware a persisting programming mode
/// usually means a stuck button. Best-effort and non-fatal.
async fn warn_if_still_in_programming_mode(
    handle: &BusHandle,
    source: IndividualAddress,
    target: IndividualAddress,
) {
    let window = collection_window();
    let Ok(lease) = handle.lease().await else {
        return;
    };
    let channel = LeaseChannel::new(lease);
    let found = match broadcast::devices_in_programming_mode_within(channel, source, window).await {
        Ok(found) => found,
        Err(_) => return,
    };
    if found.contains(&target) {
        eprintln!();
        eprintln!(
            "warning: {target} is still in programming mode after the assignment. A conformant \
             device leaves programming mode when it takes its new address; this one did not, so \
             the next `assign`/`adopt` would re-capture and re-address it."
        );
        eprintln!(
            "  - on KNX Virtual: toggle programming mode off for this device in the GUI.\n  \
             - on real hardware: this usually means a stuck programming button — release it."
        );
    }
}

/// Writes the device file (inserting into the model, saving without pruning).
// DUP: mirrors `assign_cmd::write_stub_device_file`.
fn write_device_file(model: Option<&Model>, dir: &Path, device: Device) -> anyhow::Result<PathBuf> {
    let address = device.address;
    let file_stem = device_file_stem(&device);

    let mut model = model.cloned().unwrap_or_else(empty_model);
    model.devices.insert(
        address,
        LoadedDevice {
            device,
            file_stem: file_stem.clone(),
        },
    );
    model
        .save(dir)
        .with_context(|| format!("saving the device file to {}", dir.display()))?;

    Ok(dir.join("devices").join(format!("{file_stem}.yaml")))
}

/// The `<address>-<slug>` file stem.
// DUP: mirrors `assign_cmd::device_file_stem`.
fn device_file_stem(device: &Device) -> String {
    format!("{}-{}", device.address, slugify(&device.name))
}

/// A minimal lower-kebab slug for filenames.
// DUP: mirrors `assign_cmd::slugify`.
fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// An empty model with default config.
// DUP: mirrors `assign_cmd::empty_model`.
fn empty_model() -> Model {
    Model {
        config: Default::default(),
        groups: Default::default(),
        links: Default::default(),
        devices: Default::default(),
    }
}

/// Formats a byte slice as lowercase hex.
// DUP: mirrors `assign_cmd::hex`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Cleans a raw property value to printable ASCII.
// DUP: mirrors `assign_cmd::clean_ascii`.
fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect();
    s.trim().to_string()
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

/// `vendor/.gitignore`: ignore everything (copyrighted vendor data).
// DUP: mirrors `import_product_cmd::VENDOR_GITIGNORE`.
const VENDOR_GITIGNORE: &str = "\
# Vendor `.knxprod` product data is copyrighted — never commit it. Each user
# supplies their own downloads; models under ../models/ are regenerated from them.
*
";

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
        let mut model = empty_model();
        for s in addrs {
            let addr: IndividualAddress = s.parse().unwrap();
            model.devices.insert(
                addr,
                LoadedDevice {
                    device: Device {
                        address: addr,
                        name: "d".to_string(),
                        description: None,
                        location: None,
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
    fn allocate_picks_lowest_free_on_dominant_line() {
        let model = model_with(&["1.1.1", "1.1.2", "1.1.4"]);
        assert_eq!(
            allocate_address(Some(&model)),
            Some("1.1.3".parse().unwrap())
        );
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
    fn build_product_prefers_product_over_readback() {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            serial: None,
            order: Some("READBACK-ORDER".to_string()),
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
        let p = build_product(&v, Some(&sel)).unwrap();
        assert_eq!(p.order_number.as_deref(), Some("MDT-BE-04001.02"));
        assert_eq!(p.application_ref.as_deref(), Some("M-0083_A-1234-11-ABCD"));
        assert_eq!(p.manufacturer_ref.as_deref(), Some("M-0083"));
        assert_eq!(p.mask.as_deref(), Some("07B0"));
        assert_eq!(p.manufacturer.as_deref(), Some("MDT"));
    }

    #[test]
    fn build_product_falls_back_to_readback_without_product() {
        let v = Verified {
            mask: Some(0x07B0),
            manufacturer_id: Some(0x0083),
            serial: None,
            order: Some("MDT-JAL0410".to_string()),
        };
        let p = build_product(&v, None).unwrap();
        assert_eq!(p.order_number.as_deref(), Some("MDT-JAL0410"));
        assert_eq!(p.mask.as_deref(), Some("07B0"));
        assert!(p.application_ref.is_none());
    }

    #[test]
    fn build_device_carries_com_objects() {
        let mut com = BTreeMap::new();
        com.insert(
            0u16,
            ComObjectShape {
                text: Some("Switch".to_string()),
                dpt: Some(Dpt::new(1, Some(1))),
                flags: "CWT".parse().unwrap(),
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
        let dev = build_device("1.1.7".parse().unwrap(), &v, Some(&sel));
        assert_eq!(dev.name, "Taster");
        assert_eq!(dev.com_objects.len(), 1);
        let co = dev.com_objects.get(&0).unwrap();
        assert_eq!(co.dpt, Some(Dpt::new(1, Some(1))));
        assert_eq!(co.reference.as_deref(), Some("R-1"));
    }

    #[test]
    fn slugify_makes_kebab() {
        assert_eq!(slugify("New device (adopt)"), "new-device-adopt");
    }
}
