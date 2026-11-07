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
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use bussard_mgmt::system_type;
use bussard_model::history::SnapshotReason;
use bussard_model::{Flags, GroupAddress, IndividualAddress, Model};
use bussard_product::{ApplicationProgram, ProductData};
use bussard_service::WritePolicy;
use bussard_service::adopt::flow::{SecureSummary, SelectedProduct, shape_selected};
use bussard_service::identity::SecureStatus;
use bussard_service::program::adopt;
use bussard_service::program::assign::AssignFlow;
use bussard_service::secure::{ToolKeySource, ToolKeys};

use crate::addressing::{question, stopped, warn_forced};
use crate::assign_cmd::{hex, load_model_optional};
use crate::cli::{Consent, Resolved, Run, Spec};
use crate::conn_cmd::{enforce_write_gate, gateway_display, open_checked, resolve_config};
use crate::progress::Terminal;
use crate::style::Style;

/// `bussard adopt`.
#[derive(Debug, clap::Args)]
pub(crate) struct AdoptArgs {
    /// The address to give the device, e.g. `1.1.47` (default: next free on
    /// the line; a KNX Data Secure device keeps the address ETS gave it).
    #[arg(value_name = "ADDRESS")]
    address: Option<String>,
    /// The vendor `.knxprod` for the new device (else the cached product model is used).
    #[arg(long, value_name = "FILE")]
    product: Option<PathBuf>,
    #[command(flatten)]
    consent: Consent,
    /// Download missing vendor product data without asking. Without a
    /// terminal and without this flag nothing is downloaded; the missing
    /// order numbers are listed.
    #[arg(long, conflicts_with = "no_download")]
    yes_download: bool,
    /// Do not download product data for the device's order number; adopt
    /// it without (identity and links by number) and say where to get it.
    #[arg(long)]
    no_download: bool,
    /// Write the address although another device already answers at it
    /// (the check is step 1 of the standard's address write).
    // Issue #530.
    #[arg(long)]
    force: bool,
}

impl Run for AdoptArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
    }

    fn early_consent(&self) -> Option<(bool, String)> {
        let action = match &self.address {
            Some(address) => format!("adopt the device in programming mode as {address}"),
            None => "adopt the device in programming mode".to_string(),
        };
        Some((self.consent.yes, action))
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(&self, g)
    }
}

/// Runs `bussard adopt`.
fn run(args: &AdoptArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (scripted_address, product) = (args.address.as_deref(), args.product.as_deref());
    let (yes, force) = (args.consent.yes, args.force);
    let consent = crate::confirm::Answers {
        yes_download: args.yes_download,
        no_download: args.no_download,
        ..Default::default()
    };
    let (dir, allow_remote_gateway, keyring, overrides) =
        (g.dir(), g.allow_remote_gateway, g.keyring(), g.mgmt());
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

    let keys = adopt::Keys {
        keys: &keys,
        keyring,
    };
    let run = AdoptRun {
        yes,
        force,
        gateway: &gateway,
        fetch: consent,
        product,
    };
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        // The service applies the same write gate again as it opens. Waiting
        // for the connect makes the tunnel-assigned source address available
        // (falling back to 0.0.255 on routing) — issue #30.
        let (service, source) = open_checked(
            config,
            WritePolicy::transmit(allow_remote_gateway),
            &overrides,
        )
        .await?;
        let flow = AssignFlow {
            service: &service,
            source,
        };
        // Guard with Ctrl-C so an interrupt still closes the tunnel cleanly.
        let result = tokio::select! {
            result = adopt_flow(
                flow, dir, model.as_ref(), selected.as_ref(), scripted_address, run, keys,
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
            dir.join(bussard_model::param_model::MODEL_CACHE_DIR)
                .display()
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
        dir.join(bussard_model::param_model::MODEL_CACHE_DIR)
            .display()
    );
    for (i, name) in models.iter().enumerate() {
        println!("    [{}] {name}", i + 1);
    }
    println!("    [0] none (product-less stub adoption)");
    let pick = prompt_index("  pick a model", models.len())?;
    if pick == 0 {
        return Ok(None);
    }
    // The cached product model is our own generated shape; but for the read-back
    // cross-check and com-object table we want the parsed application. We do not
    // keep the source .knxprod path here, so a cached-model pick attaches the
    // identity/order-number metadata we can recover from the model file name and
    // proceeds product-less for the com-object table with a note.
    println!(
        "  note: adopting from a cached model file carries product identity only; \
         re-run with --product <file.knxprod> to also generate the com-object table."
    );
    let id = models[pick - 1].trim_end_matches(".json").to_string();
    Ok(Some(SelectedProduct {
        manufacturer_ref: id.split('_').next().map(str::to_string),
        application_ref: id.clone(),
        app: crate::product_store::pinned_application(dir, &id),
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
    /// `--yes-download` / `--no-download`.
    fetch: crate::confirm::Answers,
    /// `--product`, for the parameter read-back of a secured device.
    product: Option<&'a Path>,
}

/// The end-to-end adopt flow ([`adopt::plan`] and [`adopt::run`]) with the
/// wizard's lines. Each broadcast and each connected verify leases the bus
/// for the duration of that step.
async fn adopt_flow(
    flow: AssignFlow<'_>,
    dir: &Path,
    model: Option<&Model>,
    selected: Option<&SelectedProduct>,
    scripted_address: Option<&str>,
    run: AdoptRun<'_>,
    keys: adopt::Keys<'_>,
) -> anyhow::Result<ExitCode> {
    step(2, "assign an address");
    let bench = &mut Terminal::new(run.yes, false).wizard();
    let planned = async {
        let current = flow.wait_for_one(bench).await?;
        let request = adopt::PlanRequest {
            address: scripted_address,
            model,
            keys,
            identify: false,
            force: run.force,
        };
        adopt::plan(&flow, current, request, bench).await
    };
    let planned = match planned.await {
        Ok(planned) => planned,
        Err(stop) => return stopped(stop, "adopt"),
    };
    let (current, target) = (planned.current, planned.target);
    if let Some(occupant) = &planned.forced {
        warn_forced(target, occupant);
    }
    // Product data fetches itself: without a product from step 1, the order
    // number the device reported is looked up in the store, then in the
    // pointer index (one question), downloaded and imported.
    let mut fetch = run.fetch;
    let mut product = |order: Option<&str>| match (selected, order) {
        (Some(selected), _) => Some(selected.clone()),
        (None, Some(order)) => fetch_product_for(order, dir, &mut fetch),
        (None, None) => None,
    };
    let request = adopt::RunRequest {
        dir,
        model,
        keys,
        question: &question("adopt", current, target, run.gateway),
        recheck_target: false,
        product: &mut product,
        product_file: run.product,
        on_parse: Some(crate::timing::record_product_parse),
        snapshot: SnapshotReason::new("adopt")
            .with_args([target.to_string()])
            .with_result("before writing the adopted device file"),
    };
    let adopted = match adopt::run(&flow, &planned, request, bench).await {
        Ok(adopted) => adopted,
        Err(stop) => return stopped(stop, "adopt"),
    };
    let verified = &adopted.assigned.verified;
    if let (Some(read), Some(selected)) = (&adopted.order_mismatch, &adopted.selected) {
        eprintln!(
            "\n{}",
            Style::stderr().warning_line(&format!(
                "the device reported order number {read:?}, which is not among the product's \
                 order numbers ({}). The product data may not match this hardware; check it \
                 before wiring links (continuing anyway).",
                selected.order_numbers.join(", ")
            ))
        );
    }
    match &adopted.knxnet {
        adopt::Knxnet::Read(knxnet) => {
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
        }
        adopt::Knxnet::Failed(err) => eprintln!(
            "note: the KNXnet/IP settings of {target} were not read ({err}); the device file \
             has no [knxnet] table"
        ),
        adopt::Knxnet::Kept | adopt::Knxnet::None => {}
    }
    let path = &adopted.path;
    println!("  wrote {}", path.display());
    // A certificate entered for the serial before moves to it (issue #728).
    if let Some(serial) = &verified.serial {
        crate::keys_cmd::attach_learned_serials(dir, &[(target, serial.clone())]).print(false);
    }

    // Step 4: links scaffolding (print only — the model stays untouched), or
    // the links a secured device already holds (recorded in the model).
    step(4, "wire the group objects");
    match &adopted.secure {
        Some(summary) if summary.links > 0 => println!(
            "  recorded the {} link(s) the device holds in {}",
            summary.links,
            path.display()
        ),
        _ => print_links_snippet(target, &adopted),
    }

    step(5, "summary");
    print_summary(current, &adopted);
    if let Some(summary) = &adopted.secure {
        print_secure_summary(target, summary);
    }
    Ok(ExitCode::SUCCESS)
}

/// The product data for the order number a device reported: the cached
/// archive in the store, else the pointer index's download (asked once),
/// imported like `--product` would be. `None` (with the reason on the
/// console) continues product-less.
fn fetch_product_for(
    order: &str,
    dir: &Path,
    fetch: &mut crate::confirm::Answers,
) -> Option<SelectedProduct> {
    let path = match bussard_service::params::archive_for_order(dir, order) {
        Ok(Some(path)) => path,
        Ok(None) | Err(_) => {
            println!("  no product data cached for {order}; looking it up");
            let outcome = match bussard_service::setup::products::fetch_missing(
                dir,
                &[order.to_string()],
                fetch,
                &mut crate::console::Console,
            ) {
                Ok(outcome) => outcome,
                Err(err) => {
                    eprintln!("  product data for {order}: {err:#}");
                    return None;
                }
            };
            match outcome.fetched.first() {
                Some((_, path)) => path.clone(),
                None => {
                    bussard_service::setup::products::report_missing(
                        &outcome,
                        dir,
                        &mut crate::console::Console,
                    );
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
    let app = bussard_service::adopt::flow::application_for_order(&data, order)?;
    println!(
        "  using application {} ({}) for {order}",
        app.id,
        app.name.as_deref().unwrap_or(&app.id)
    );
    Some(shape_selected(&app, &data))
}

/// Prints a ready-to-paste device-file snippet: the device's most-useful com
/// objects (transmit-capable first), then an example link block. The snippet
/// goes to stdout only — the model itself is never modified here.
fn print_links_snippet(address: IndividualAddress, adopted: &adopt::Adopted) {
    let objects =
        bussard_service::adopt::flow::useful_objects(&adopted.device, adopted.selected.as_ref());
    let Some(first) = objects.first() else {
        println!(
            "  no com-object table (no product data); import the product later with \
             `bussard import-product` to generate one."
        );
        return;
    };
    println!("  most-useful com objects (transmit-capable first):");
    for o in objects.iter().take(8) {
        let dpt = o.dpt.map_or_else(|| "?".to_string(), |d| d.to_string());
        let label = o.text.as_deref().unwrap_or("");
        println!(
            "    #{:<3} dpt {dpt:<8} flags {:<6} {label}",
            o.number, o.flags
        );
    }
    let dpt = first
        .dpt
        .map_or_else(|| "1.001".to_string(), |d| d.to_string());
    let name = first.text.as_deref().unwrap_or("New link");
    let (table, key) = (&first.table, &first.key);
    println!();
    println!("  ready-to-paste snippets (edit the group address to a free one):");
    println!("    # ---8<--- groups.toml (inside `groups = [ … ]`)");
    println!("    {{ address = \"0/0/1\", name = \"{name}\", dpt = \"{dpt}\" }},");
    println!("    # ---8<--- devices/{address}.toml");
    println!("    {table}");
    // The direction follows the flags, as E025 requires: a reporting object
    // (T) sends, a command object listens.
    if first.flags.contains(Flags::TRANSMIT) {
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

/// Prints the closing summary: what was created, what remains manual, and the
/// flash pointer for factory-fresh (Unloaded) devices.
fn print_summary(current: IndividualAddress, adopted: &adopt::Adopted) {
    let (target, v, path) = (
        adopted.assigned.target,
        &adopted.assigned.verified,
        adopted.path.display(),
    );
    let selected = adopted.selected.as_ref();
    let style = Style::stdout();
    println!();
    println!(
        "{}",
        style.ok(&style.bold(&format!("adopted {current} → {target}")))
    );
    let secured = v.secure == SecureStatus::Activated;
    let label = |text: &str| style.dim(&format!("{text:<14}"));
    if let Some(mask) = v.mask {
        let how = if secured {
            ", read secured; KNX Data Secure is on"
        } else {
            ""
        };
        println!(
            "  {}mask {mask:#06x} ({}){how}",
            label("verified"),
            system_type(mask)
        );
    }
    if let Some(serial) = &v.serial {
        println!("  {}{}", label("serial number"), hex(serial).to_uppercase());
    }
    println!("  {}{path}", label("device file"));
    let product = match selected {
        Some(sel) if !sel.com_objects.is_empty() => format!(
            "{} ({} com objects)",
            sel.display_name(),
            sel.com_objects.len()
        ),
        Some(sel) => format!("{} (identity only)", sel.display_name()),
        None => "none (stub-only adoption)".to_string(),
    };
    println!("  {}{product}", label("product"));
    if adopted.order_mismatch.is_some() {
        println!(
            "  {}",
            style.warn("the order number check flagged a possible mismatch (see above)")
        );
    }

    let edit = format!("edit {path}");
    let plan = format!("bussard plan {target}");
    let apply = format!("bussard apply {target}");
    let flash = format!("bussard flash {target}");
    let mut steps: Vec<(&str, &str)> = Vec::new();
    if secured {
        steps.push((edit.as_str(), "set the device's name and room"));
        steps.push((
            plan.as_str(),
            "should report no change: your project now holds what the device holds",
        ));
    } else {
        steps.push((
            edit.as_str(),
            "set the device's name and room, and wire its group objects (snippet above)",
        ));
        steps.push((plan.as_str(), "shows what writing the tables would change"));
        steps.push((apply.as_str(), "writes them to the device"));
        // A factory-fresh device needs its first application download before
        // links take effect (#43).
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
pub(crate) fn step(n: u8, what: &str) {
    let style = Style::stdout();
    println!("{} {what}", style.bold(&format!("Step {n} of 5")));
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
    let objects = |o: &[u16]| list(&mut o.iter().map(u16::to_string));
    // (objects, "is"/"are", "links"/"link") by count.
    let grammar = |n: usize| match n {
        1 => ("object", "is", "links"),
        _ => ("objects", "are", "link"),
    };
    let flagged = &s.adoption.flagged_without_key;
    if !flagged.is_empty() {
        let (noun, verb, link) = grammar(flagged.len());
        println!(
            "  NOTE: {noun} {} {verb} secured on the device but {link} no group address bussard \
             has a key for: the keys may be older than the device's last download",
            objects(flagged)
        );
    }
    let keyed = &s.adoption.keyed_not_flagged;
    if !keyed.is_empty() {
        let (noun, verb, link) = grammar(keyed.len());
        println!(
            "  NOTE: {noun} {} {link} a group address with a group key but {verb} not secured on \
             the device: the keys may be newer than the device's last download",
            objects(keyed)
        );
    }
    for note in &s.notes {
        println!("  note: {note}");
    }
    println!("  nothing was written to {target}; Secure and its keys stay with ETS");
}

/// Imports a `.knxprod` (or an ETS project export) into the product store
/// as `bussard import-product` does, and returns its product data.
fn import_product(file: &Path, dir: &Path) -> anyhow::Result<ProductData> {
    let mut said = bussard_service::observer::Collected::default();
    let imported =
        bussard_service::files::products::import_product_file(file, dir, None, &mut said)?;
    let archive = imported.archive.as_deref().unwrap_or(file);
    if archive != file {
        println!("  {}", imported.stored);
    }
    Ok(bussard_service::setup::products::read_in_model_language(
        archive, dir, None,
    )?)
}

// ---------------------------------------------------------------------------
// Small local helpers
// ---------------------------------------------------------------------------

/// The cached product model file names under `<dir>/.bussard/model-cache/`, sorted.
fn cached_models(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> =
        std::fs::read_dir(dir.join(bussard_model::param_model::MODEL_CACHE_DIR))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.ends_with(".json").then_some(name)
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
