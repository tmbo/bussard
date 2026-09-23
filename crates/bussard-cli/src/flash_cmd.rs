//! The `bussard flash` subcommand — first application download into a
//! factory-fresh device (phase 3).
//!
//! The flow mirrors `bussard apply`'s ladder, adapted for an application
//! download:
//! 1. Read the vendor `.knxprod`, select the application program (by `--application`
//!    id, or the sole candidate).
//! 2. Read the device descriptor (mask). Gate on System B (07B0); refuse others.
//! 3. Build a pre-flight [`FlashPlan`] — this also refuses a mask mismatch or any
//!    unsupported op — and show it. A refused plan exits non-zero before any write.
//! 4. Check the device is **factory-fresh** (issue #79): the read-only probe in
//!    step 2 read the load state of every object this flash would rewrite, plus
//!    the resident application id. A device carrying a *different* application is
//!    refused unless `--force`; an unreadable state is refused as unknown;
//!    re-flashing the *same* application is allowed (it is the documented
//!    recovery path) with a notice. Then state that **no backup is possible** and
//!    confirm on a TTY unless `--yes`.
//! 5. Execute with a progress line, then verify: the application object must be
//!    `Loaded`, and a sample of each written segment is read back.
//! 6. On any failure, print recovery guidance and exit non-zero.
//!
//! # Safety
//!
//! This is a device-mutating command. Per the phase-3 spec the first real flash
//! must happen against the thelsing virtual device or KNX Virtual, not the live
//! reference bus; the mask gate and the pre-flight validation are the guard-rails
//! that keep it from touching an unsupported or mismatched device.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, BusHandle, ops};
use bussard_download::{
    CurrentMemory, FlashPlan, FlashStep, Freshness, ParamPlan, ParamValue, Progress,
    assess_freshness, flash, param_plan, plan_flash, probe_resident_state,
    read_current_parameter_memory, select_application, trace,
};
use bussard_mgmt::load::WriteError;
use bussard_mgmt::{DeviceConnection, Layer4Connection, LeaseChannel, MgmtError, Timeouts};
use bussard_model::IndividualAddress;
use bussard_prod::{ApplicationProgram, ProductData, normalize_order_number};

use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, gateway_display, load_model_required, resolve_config,
};

/// Flashes an application program from vendor product data into a device.
///
/// The argument list mirrors the `flash` subcommand's flags 1:1; bundling them
/// would only obscure that mapping, so the clippy arity lint is allowed here.
#[allow(clippy::too_many_arguments)]
pub fn run(
    address: &str,
    product: &Path,
    application: Option<&str>,
    order_number: Option<&str>,
    dir: &Path,
    yes: bool,
    force: bool,
    allow_remote_gateway: bool,
    bcu_key: Option<&str>,
    tool_key_source: crate::secure_key::ToolKeySource<'_>,
    overrides: ConnOverrides,
    output: FlashOutput,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // KNX Data Secure (issue #71, spec §6.2): the target's tool key, from the
    // keyring (the real flow) or a raw `--tool-key` (test/bench). `None` is the
    // plain, byte-identical path. The key is never printed or logged (§2.3).
    let tool_key = crate::secure_key::resolve(target, tool_key_source)?;
    // One send-sequence high-water mark for the whole command (spec §5.9): the
    // pre-flight probe, the flash, and every mid-flash reconnect share it, so no
    // session ever replays a sequence the device already accepted.
    let secure_seq = bussard_secure::SequenceHighWater::new();

    // Parse the optional BCU access key (hex, e.g. `FFFFFFFF` or `0x11223344`).
    // Unset means present the free-access key on every management connect — the
    // capture used free access; keyed devices need the project BCU key here.
    let bcu_key = match bcu_key {
        Some(raw) => Some(parse_bcu_key(raw)?),
        None => None,
    };

    // Load the product data and pick the application program.
    let product_data = bussard_prod::read_knxprod(product)
        .with_context(|| format!("reading product data from {}", product.display()))?;

    // Resolve the application program. Three modes, in precedence order:
    //   --order-number : look the order number up in the hardware catalogue and
    //                    require exactly one matching application (clap already
    //                    rejects combining it with --application);
    //   --application  : an explicit application ref, looked up directly;
    //   neither        : the sole application in a single-app archive.
    let app = if let Some(order) = order_number {
        match resolve_by_order_number(&product_data, order) {
            Ok(app) => app,
            Err(err) => {
                eprintln!("{err}");
                return Ok(ExitCode::FAILURE);
            }
        }
    } else {
        let candidates: Vec<&ApplicationProgram> = product_data.applications.iter().collect();
        match select_application(&candidates, application) {
            Ok(app) => app,
            Err(err) => {
                eprintln!("cannot select an application program: {err}");
                return Ok(ExitCode::FAILURE);
            }
        }
    };

    // Parameter overrides come from the target device's `parameters:` block in
    // the model (`devices/*.yaml`), re-keyed to the app-relative ParameterRef id
    // the flash engine expects (the #46 contract: keys are `<slug>@<ref-id>`; the
    // part after `@` is the ETS-stable identity). The model is also the source of
    // the connection config.
    // A flash is a management command: a present-but-broken model is a hard
    // error (its parameter overrides drive what is written to the device).
    let model = load_model_required(dir)?;
    let config = resolve_config(model.as_ref(), &overrides)?;
    // Safety envelope (issue #74): refuse a flash to a real (non-loopback)
    // gateway unless the operator opted in.
    enforce_write_gate(&config, allow_remote_gateway)?;
    let gateway = gateway_display(&config);
    let overrides_map = collect_parameter_overrides(model.as_ref(), target);
    // Module-instance base offsets persisted by the importer (issue #48): the
    // keys are module-instance selectors, byte-identical to what
    // compute_parameter_image expects, so per-channel parameter overrides place
    // at their real per-instance offsets.
    let base_offsets = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| d.device.module_bases.clone())
        .unwrap_or_default();

    // Phase A (read-only): read the device descriptor and probe what is already
    // resident on the device (issue #79). Both run over one connection; neither
    // writes anything.
    let runtime = tokio::runtime::Runtime::new()?;
    let secure_probe = tool_key.is_some();
    let probe = {
        let config = config.clone();
        let probe_key = tool_key.clone();
        let probe_seq = secure_seq.clone();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
            if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
                eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
            }
            let source = ops::group_source(&handle);
            let lease = handle.lease().await.context("leasing the bus")?;
            let channel = LeaseChannel::new(lease);
            // Track whether the T_Connect established before the first read: a
            // connect-then-disconnect on the descriptor read is the diagnostic
            // pattern (see `descriptor_read_error`).
            // The descriptor read is a protected function on a security-
            // activated device (spec §6.4): probe it through the same secure
            // layer the flash will use, or plain when no tool key was given.
            let secure = crate::secure_key::layer(&probe_key, &probe_seq);
            let (connected, result, resident) = match DeviceConnection::connect_with_secure(
                channel,
                target,
                source,
                Timeouts::default(),
                secure,
            )
            .await
            {
                Ok(mut dev) => {
                    // Authorize the read-only descriptor probe too (best-effort):
                    // ETS authorizes every management session, so a keyed device
                    // that would otherwise drop the descriptor read is unlocked
                    // first. Tolerate a device that does not implement authorize.
                    let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
                    let r = match dev.authorize(key).await {
                        Ok(_) => dev.device_descriptor().await,
                        Err(err) => Err(err),
                    };
                    // The factory-freshness probe (issue #79): read the load
                    // state (and, on System B, the resident application id) of
                    // the objects this flash would unload and rewrite. Purely
                    // read-only, and only once the mask is known — it is the
                    // mask that decides System B objects vs System 7 LSMs. It
                    // rides the same (possibly secured) connection.
                    let resident = match &r {
                        Ok(mask) => Some(probe_resident_state(dev.l4_mut(), *mask, None).await),
                        Err(_) => None,
                    };
                    let _ = dev.disconnect().await;
                    (true, r, resident)
                }
                Err(err) => (false, Err(err), None),
            };
            let _ = handle.close().await;
            anyhow::Ok((connected, result, resident))
        })?
    };

    let (connected, device_mask, resident) = probe;
    let device_mask = match device_mask {
        Ok(mask) => mask,
        Err(err) => {
            return Err(descriptor_read_error(target, connected, secure_probe, err));
        }
    };

    // The master-template `Load` procedure for this app's mask, if the archive
    // shipped a `knx_master.xml`. A merged application (e.g. KNX Virtual DA.tp)
    // only carries its own app-segment blocks; the load-control ops for the
    // table objects (obj1/obj2/obj3) live in the template and are spliced in.
    let template_ops = app
        .mask_version
        .as_deref()
        .and_then(|mask| {
            product_data
                .master
                .as_ref()
                .and_then(|m| m.full_load_procedure(mask))
        })
        .map(|proc| proc.ops.clone());

    // The computed table images (obj1 address, obj2 association, obj3
    // group-object) this device requires, from its model links. A merged app's
    // template writes these objects; a self-contained (thelsing) app's does not,
    // so an empty map simply leaves the single-object flash untouched.
    let table_images = build_table_images(model.as_ref(), target, app);

    // Pre-flight: build and validate the plan (System B gate, mask match,
    // unsupported-op refusal all happen here).
    let plan = match plan_flash(
        app,
        address,
        device_mask,
        &overrides_map,
        &base_offsets,
        template_ops.as_deref(),
        &table_images,
    ) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("cannot flash: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };

    // The parameter-level plan (issue #109): what this flash changes in the
    // vendor's own words, before the memory-level plan. Reading the current
    // values back is only meaningful on a device that already carries an
    // application; a factory-fresh one has no segment to read, so every value is
    // reported as an unknown current value.
    let current_params = if resident
        .as_ref()
        .is_some_and(|r| r.has_loaded_application())
    {
        read_current_parameters(
            &runtime,
            config.clone(),
            target,
            &plan,
            bcu_key,
            tool_key.clone(),
            secure_seq.clone(),
        )
    } else {
        CurrentMemory::new()
    };
    let params = if plan.is_sys7() {
        // System 7 writes whole absolute memory regions rather than a parameter
        // image over an allocated segment, so the memory-level plan is the
        // authoritative one there.
        ParamPlan {
            note: Some(bussard_download::SYS7_NOTE.to_string()),
            ..Default::default()
        }
    } else {
        param_plan(app, &overrides_map, &base_offsets, &current_params)
    };

    if output.json {
        print_plan_json(target, device_mask, &plan, &params)?;
    } else {
        print_plan(
            target,
            device_mask,
            &plan,
            &overrides_map,
            &params,
            output.verbose,
        );
    }

    // The factory-freshness gate (issue #79): a flash takes no backup, so a
    // device that already carries a *different* application is refused unless
    // `--force`, and an unreadable state is refused too (unknown is not fresh).
    // A re-flash of the same application — the documented recovery path — goes
    // through with a notice.
    let freshness = match &resident {
        Some(state) => assess_freshness(state, &plan.identity),
        // Unreachable in practice: the descriptor read succeeded above, so the
        // probe ran. Treated as unknown rather than fresh all the same.
        None => Freshness::Unknown {
            reason: "the pre-flight probe did not run".to_string(),
        },
    };
    let decision = decide_freshness(target, &gateway, dir, force, &freshness);
    eprintln!("{}", decision.message);
    if !decision.proceed {
        return Ok(ExitCode::FAILURE);
    }

    // Confirm unless --yes.
    if !confirm(
        target,
        &gateway,
        yes,
        &plan,
        decision.prompt_note.as_deref(),
    )? {
        eprintln!("aborted — nothing written.");
        return Ok(ExitCode::FAILURE);
    }

    // Phase B (write): execute the flash with a progress line.
    let plan_ref = &plan;
    // Verify the flash *after* the terminal restart: a real device (KNX Virtual)
    // only holds the load if it survives the reboot, so bussard reconnects and
    // re-reads the load state once the device is back rather than trusting the
    // transient `Loaded` it reports before rebooting.
    let options = bussard_download::FlashOptions {
        bcu_key,
        verify_after_restart: true,
        ..Default::default()
    };
    let outcome = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let source = ops::group_source(&handle);
        let result = execute(
            &handle,
            target,
            source,
            plan_ref,
            options,
            tool_key,
            secure_seq,
        )
        .await;
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(verify) if verify.ok() => {
            println!(
                "\nflash verified: application program {} is {} on {target}",
                plan.identity.id, verify.load_state,
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(verify) => {
            eprintln!("\nERROR: flash did not verify: {verify:?}");
            recovery_notice(target);
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("\nERROR: flash failed: {err}");
            recovery_notice(target);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Collects the target device's parameter overrides from the model, re-keyed
/// from the device-file `<slug>@<ref-id>` form to the bare app-relative
/// `ParameterRef` id the flash engine consumes (the part after `@`).
///
/// The slug before `@` is a human aid and is dropped. A key with no `@` is
/// malformed for this contract and skipped with a warning (rather than fed to the
/// engine as a bogus ref id). Returns an empty map when the model is absent or
/// the device has no `parameters:` block.
fn collect_parameter_overrides(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(model) = model else { return out };
    let Some(loaded) = model.devices.get(&target) else {
        return out;
    };
    for (key, value) in &loaded.device.parameters {
        match key.split_once('@') {
            Some((_slug, ref_id)) if !ref_id.is_empty() => {
                out.insert(ref_id.to_string(), value.clone());
            }
            _ => {
                eprintln!(
                    "warning: ignoring parameter key {key:?} on {target}: it has no \
                     `<slug>@<ref-id>` form, so its ETS-stable identity is undetermined"
                );
            }
        }
    }
    out
}

/// Builds the loadable table images (obj1 address, obj2 association, obj3
/// group-object) a merged flash writes, keyed by device object index (1/2/3).
///
/// obj1 and obj2 come from the device's model links via
/// [`bussard_download::compute_tables`] (the same tables `bussard apply`
/// downloads); obj3 is the System B group-object descriptor table built from the
/// app's com-objects (its byte layout is verified byte-for-byte against the
/// ETS→KNX-Virtual DA.tp capture — see
/// [`bussard_download::compute::compute_group_object_table`]). Each image
/// includes its big-endian element-count word.
///
/// For a **module-based** application (the DA.tp shape), obj3 is
/// **channel-expanded**: the module's com-objects are instantiated once per
/// `<Module>` channel via
/// [`bussard_download::expand_group_object_descriptors`], so the table carries
/// every per-channel com-object instance ETS emits (73 entries for DA.tp), not
/// just the 7 module base objects. Each channel's Communication flag is set when
/// any of its com-objects is linked in the model, matching ETS (which registers a
/// linked instance with Communication set and an unlinked one with it cleared).
/// A non-module application keeps the flat per-com-object table.
///
/// Returns an empty map when the model is absent or the device has no links —
/// which leaves a self-contained (thelsing) single-object flash untouched.
fn build_table_images(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
    app: &ApplicationProgram,
) -> BTreeMap<u32, Vec<u8>> {
    use bussard_download::compute::{
        GroupObjectDescriptor, Priority, compute_group_object_table,
        descriptors_for_linked_objects, size_code_from_object_size, table_image_with_count,
    };

    let mut out = BTreeMap::new();

    // The device's model links, if any. A `--dir` model that has no entry for
    // this device (or an empty link list) is a *bare vendor-default* flash: the
    // device is programmed with the application's out-of-box group objects but no
    // group addresses (an empty address/association table), exactly as a
    // factory-fresh ETS download of an unassigned device would.
    let links: &[bussard_model::schema::Link] = model
        .and_then(|m| m.links.links.get(&target))
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    // obj1 (address table) + obj2 (association table) from the model links. With
    // no links these are the empty tables (count word 0), which a merged
    // template still allocates and writes on a bare flash.
    let desired = bussard_download::compute_tables(links);
    out.insert(
        1,
        table_image_with_count(desired.address_count(), &desired.address_elements()),
    );
    out.insert(
        2,
        table_image_with_count(desired.association_count(), &desired.association_elements()),
    );

    // obj3 (group-object table).
    let linked: std::collections::BTreeSet<u16> = links.iter().map(|l| l.object).collect();
    let obj3 = if !app.module_instances.is_empty() && app.channel_membership.is_some() {
        // Module-based application: instantiate the com-objects across channels.
        // Each channel is linked when any of the com-objects it carries appears
        // in the model links; `<choose>` selectors fall back to their parameter
        // defaults (the vendor-default channel objects on a bare flash).
        let descriptors = build_module_obj3_descriptors(app, &linked);
        compute_group_object_table(&descriptors)
    } else {
        // Non-module application: a flat per-com-object table. With links, ETS
        // registers a descriptor for each linked com-object (Communication set);
        // on a bare flash it emits every declared com-object with Communication
        // cleared.
        let com_objects = app.resolved_com_objects();
        if links.is_empty() {
            let descriptors: Vec<GroupObjectDescriptor> = com_objects
                .iter()
                .map(|c| GroupObjectDescriptor {
                    asap: c.number(),
                    // Communication cleared: an unlinked com-object on a bare flash.
                    flags: c.flags() - bussard_model::Flags::COMMUNICATION,
                    size_code: size_code_from_object_size(c.object_size()),
                    priority: Priority::default(),
                })
                .collect();
            compute_group_object_table(&descriptors)
        } else {
            let descriptors = descriptors_for_linked_objects(&com_objects, &linked);
            compute_group_object_table(&descriptors)
        }
    };
    if let Some(obj3) = obj3 {
        out.insert(3, obj3);
    }

    out
}

/// Builds the channel-expanded obj3 descriptors for a module-based application,
/// marking each channel linked when any of its instantiated com-objects is bound
/// to a group address in the model.
///
/// The channel's `<choose>` selectors use the parameters' declared defaults (the
/// vendor-default per-channel object set), which is what a bare flash of an
/// unconfigured device programs. Each channel's ASAPs are discovered by expanding
/// that channel alone; a channel is linked when any of those ASAPs is in
/// `linked`, and the full table is then expanded with those per-channel flags.
fn build_module_obj3_descriptors(
    app: &ApplicationProgram,
    linked: &std::collections::BTreeSet<u16>,
) -> Vec<bussard_download::compute::GroupObjectDescriptor> {
    use bussard_download::compute::{ChannelConfig, expand_group_object_descriptors};

    let channel_count = app.module_instances.len();
    let mut configs = vec![ChannelConfig::default(); channel_count];
    for (idx, config) in configs.iter_mut().enumerate() {
        // Expand this one channel alone (others contribute no descriptors only if
        // they too are default, but their ASAPs never collide — bases differ), so
        // its descriptors are exactly this channel's ASAPs.
        let mut solo = vec![ChannelConfig::default(); channel_count];
        // Give the other channels an out-of-band selector so they stay default;
        // the per-instance argObj bases already keep ASAP ranges disjoint, so we
        // can filter this channel's ASAPs by expanding only it.
        for (other_idx, other) in solo.iter_mut().enumerate() {
            other.linked = other_idx == idx;
        }
        let descs = expand_group_object_descriptors(app, &solo);
        // This channel's ASAPs are those whose descriptor has Communication set
        // (only this channel was marked linked).
        let channel_asaps: std::collections::BTreeSet<u16> = descs
            .iter()
            .filter(|d| d.flags.contains(bussard_model::Flags::COMMUNICATION))
            .map(|d| d.asap)
            .collect();
        config.linked = channel_asaps.iter().any(|a| linked.contains(a));
    }

    expand_group_object_descriptors(app, &configs)
}

/// Resolves an application program from a hardware order number, requiring
/// exactly one match.
///
/// Matching is index-style normalized (trim + upper-case, interior separators
/// preserved — the same rule the product pointer index uses), so `akk-0216.03 `
/// resolves to `AKK-0216.03`. Every order number in the archive's hardware
/// catalogue is normalized and compared; the applications the matching order
/// numbers map to are collected and de-duplicated by id.
///
/// - Exactly one distinct application → returned.
/// - Zero → an error naming the order number and (up to a few) known order
///   numbers as candidates.
/// - More than one → an error listing the candidate application ids so the user
///   can fall back to `--application`.
fn resolve_by_order_number<'a>(
    product: &'a ProductData,
    order_number: &str,
) -> anyhow::Result<&'a ApplicationProgram> {
    let want = normalize_order_number(order_number);

    // Every order-number key that normalizes to the wanted value, and the
    // application refs each maps to (joined, de-duplicated by ref).
    let mut app_refs: Vec<&str> = Vec::new();
    for (order, refs) in &product.hardware.order_to_apps {
        if normalize_order_number(order) == want {
            for r in refs {
                if !app_refs.contains(&r.as_str()) {
                    app_refs.push(r.as_str());
                }
            }
        }
    }

    // Resolve refs to the parsed applications present in the archive, keeping
    // them distinct by id (a ref may repeat across hardware rows).
    let mut apps: Vec<&ApplicationProgram> = Vec::new();
    for r in &app_refs {
        if let Some(app) = product.application_by_id(r) {
            if !apps.iter().any(|a| a.id == app.id) {
                apps.push(app);
            }
        }
    }

    match apps.as_slice() {
        [only] => Ok(only),
        [] => {
            let mut known: Vec<&str> = product
                .hardware
                .order_to_apps
                .keys()
                .map(String::as_str)
                .collect();
            known.sort_unstable();
            let candidates = if known.is_empty() {
                "the archive lists no order numbers".to_string()
            } else {
                let shown: Vec<&str> = known.iter().take(10).copied().collect();
                let suffix = if known.len() > shown.len() {
                    format!(", … ({} total)", known.len())
                } else {
                    String::new()
                };
                format!("known order numbers: {}{suffix}", shown.join(", "))
            };
            bail!(
                "no application matches order number {order_number:?} in {}; {candidates}. \
                 Pass --application <ref> to select by application id instead.",
                product_display(product),
            )
        }
        many => {
            let ids: Vec<&str> = many.iter().map(|a| a.id.as_str()).collect();
            bail!(
                "order number {order_number:?} maps to {} applications ({}); \
                 disambiguate with --application <ref>.",
                many.len(),
                ids.join(", "),
            )
        }
    }
}

/// Parses a `--bcu-key` value: a 32-bit access key in hex, with or without a
/// `0x` prefix (e.g. `FFFFFFFF`, `0x11223344`).
///
/// The key is presented with `A_Authorize_Request` on every management connect
/// (issue #52 finding #1). A malformed value is a hard error rather than a
/// silent fall back to free access, so a typo cannot flash a keyed device with
/// the wrong (unprivileged) key and get a confusing access-denied later.
fn parse_bcu_key(raw: &str) -> anyhow::Result<u32> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(hex, 16).with_context(|| {
        format!("parsing --bcu-key {raw:?} as a 32-bit hex access key (e.g. FFFFFFFF)")
    })
}

/// Turns a failed device-descriptor read into a helpful error.
///
/// The KNX Virtual IP-medium devices (order `*.ip`, e.g. a binary output at
/// `1.0.10`) accept the `T_Connect` but `T_Disconnect` on the very first
/// descriptor read, while their TP-medium siblings answer fully. When we see
/// exactly that shape — the connection established, then the first read
/// disconnected — name the pattern so the user gets guidance instead of a bare
/// "disconnected". Any other failure is passed through with context.
fn descriptor_read_error(
    target: IndividualAddress,
    connected: bool,
    secure: bool,
    err: MgmtError,
) -> anyhow::Error {
    // KNX Data Secure (issue #71, spec §6.4): an activated device silently drops
    // a management APDU it cannot accept — a wrong tool key fails the MAC, and a
    // plain (unwrapped) access to a protected function is refused outright. Both
    // reach bussard as "the device accepted the connection and then said
    // nothing", so the guidance has to name the secure cause before the
    // (identical-looking) IP-medium pattern below.
    if connected
        && matches!(
            err,
            MgmtError::Disconnected { .. } | MgmtError::NoResponse { .. }
        )
    {
        if secure {
            return anyhow::anyhow!(
                "{target} accepted the connection but never answered the SECURED management \
                 access. A KNX Data Secure device drops a frame it cannot authenticate, so \
                 either the tool key is not this device's key (the MAC does not verify), or the \
                 device is not security-activated at all and ignores A_SecureData — in which \
                 case flash it without --keyring/--tool-key. Nothing was written."
            );
        }
        if matches!(err, MgmtError::NoResponse { .. }) {
            return anyhow::anyhow!(
                "{target} accepted the connection but never answered the plain management \
                 access. If this device is KNX Data Secure-activated it refuses unsecured \
                 management: pass its tool key with --keyring <file.knxkeys> (password in \
                 BUSSARD_KEYRING_PASSWORD), or --tool-key <32 hex> for a test device. Nothing \
                 was written."
            );
        }
    }
    if connected && matches!(err, MgmtError::Disconnected { .. }) {
        return anyhow::anyhow!(
            "{target} accepted the connection but disconnected on the first read: typical for \
             devices whose management is gated on a loaded application or a different medium \
             profile (e.g. KNX Virtual IP-medium `*.ip` devices, which disconnect on descriptor \
             reads while their `*.tp` siblings answer). Flash targets the application download, \
             which this device is not accepting management for over this connection. It is also \
             what a KNX Data Secure-activated device does to unsecured management: if this \
             device is activated, pass its tool key with --keyring <file.knxkeys> (password in \
             BUSSARD_KEYRING_PASSWORD), or --tool-key <32 hex> for a test device."
        );
    }
    anyhow::Error::new(err).context("reading the device descriptor")
}

/// A short label for the product in an error message: its manufacturer id(s).
fn product_display(product: &ProductData) -> String {
    if product.manufacturers.is_empty() {
        "the product archive".to_string()
    } else {
        format!("the product archive ({})", product.manufacturers.join(", "))
    }
}

/// Opens the L4 connection to the flash target by leasing the bus.
///
/// The download ([`bussard_download::Session`]) runs over this single connection
/// for its whole duration, like ETS: the lease takes a [`bussard_bus::BusLease`]
/// and builds a [`LeaseChannel`] over it, so the flash observes the bus without
/// stealing frames from other subscribers.
struct LeaseConnector<'a> {
    handle: &'a BusHandle,
    target: IndividualAddress,
    source: IndividualAddress,
    /// The KNX Data Secure tool key for the target, when the device is
    /// security-activated (issue #71, spec §6.2). `None` is the plain,
    /// byte-identical path; `Some` wraps every management APDU behind
    /// A_SecureData. The key is cloned to build a fresh `DataSecureSession` on
    /// each (re)connect; the send sequence continues from `secure_seq` so a
    /// reconnect after a master reset never replays a sequence the device has
    /// already accepted.
    secure_tool_key: Option<bussard_secure::Key16>,
    /// The send-sequence high-water mark shared with every other session against
    /// this device (spec §5.9). A flash reconnects — on a master reset, on a
    /// dropped L4 — and an activated device refuses any sequence it has already
    /// accepted, so each reconnect must continue the counter, not reseed it from
    /// the clock.
    secure_seq: bussard_secure::SequenceHighWater,
}

/// Environment variable that overrides the flash's per-attempt L4 ACK/response
/// timeout (in milliseconds). Unset in normal use, so the standard 3 s budget
/// applies. It exists so a stress run against a device that drops the L4
/// connection extremely frequently (the local sim's tiny `KNX_SIM_L4_BUDGET`, or a
/// pathologically flaky tunnel) detects each drop in milliseconds instead of the
/// full 3 s ACK-retransmit wait — resume-on-drop then reconnects promptly. It does
/// not change what the flash does, only how long it waits before treating a silent
/// peer as a dropped connection.
const FLASH_L4_TIMEOUT_MS_ENV: &str = "BUSSARD_FLASH_L4_TIMEOUT_MS";

/// The L4 timeout budget for a flash connection, honouring [`FLASH_L4_TIMEOUT_MS_ENV`].
fn flash_l4_timeouts() -> Option<Timeouts> {
    std::env::var(FLASH_L4_TIMEOUT_MS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|ms| Timeouts {
            ack_timeout: std::time::Duration::from_millis(ms),
            max_repetitions: 1,
            response_timeout: std::time::Duration::from_millis(ms),
        })
}

impl bussard_download::Connector for LeaseConnector<'_> {
    type Channel = LeaseChannel;

    async fn connect(&mut self) -> Result<Layer4Connection<LeaseChannel>, WriteError> {
        let lease = self.handle.lease().await.map_err(|_| {
            // Leasing fails only if the bus actor is gone or the connection went
            // stale; either way the L4 session is unusable.
            WriteError::Mgmt(MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))
        })?;
        let channel = LeaseChannel::new(lease);
        // KNX Data Secure seam (spec §6.1/§6.2): a plain connection when no tool
        // key is set (byte-identical to today), or a wrapped one when the device
        // is security-activated.
        let secure = crate::secure_key::layer(&self.secure_tool_key, &self.secure_seq);
        let timeouts = flash_l4_timeouts().unwrap_or_default();
        Layer4Connection::connect_with_secure(channel, self.target, self.source, timeouts, secure)
            .await
            .map_err(WriteError::Mgmt)
    }
}

/// Runs the on-bus flash sequence with a progress line.
async fn execute(
    handle: &BusHandle,
    target: IndividualAddress,
    source: IndividualAddress,
    plan: &FlashPlan,
    options: bussard_download::FlashOptions,
    secure_tool_key: Option<bussard_secure::Key16>,
    secure_seq: bussard_secure::SequenceHighWater,
) -> Result<bussard_download::FlashOutcome, WriteError> {
    let connector = LeaseConnector {
        handle,
        target,
        source,
        secure_seq,
        // KNX Data Secure (issue #71, spec §6.2): `None` is the plain,
        // byte-identical path; `Some` wraps every management APDU behind
        // A_SecureData with the target's tool key (`--keyring` / `--tool-key`).
        secure_tool_key,
    };
    // Authorize the management connect with the project BCU key (or free access
    // when unset) — issue #52 finding #1.
    let mut session = bussard_download::Session::open_with_key(connector, options.bcu_key).await?;
    // The session owns the open connection; from here the flash body runs and its
    // result is captured, then the session is disconnected unconditionally below —
    // regardless of whether the flash succeeded or failed mid-procedure. `flash`
    // borrows the session (never consumes it), and there is no `?` between here and
    // the disconnect, so a mid-flash WriteError can never skip the T_Disconnect that
    // releases the L4 session. (finding 3: a stuck session after a failed flash
    // traces to a skipped disconnect; keeping the disconnect on every arm is the
    // guarantee.)
    let result = flash(&mut session, plan, options, |p| match p {
        Progress::Step {
            index,
            total,
            label,
        } => {
            eprintln!("  [{index}/{total}] {label}");
        }
        Progress::Bytes { written, total } => {
            eprint!("\r      {written}/{total} bytes");
            let _ = std::io::stderr().flush();
            if written == total {
                eprintln!();
            }
        }
    })
    .await;
    let _ = session.into_disconnect().await;
    result
}

/// Prints the pre-flight plan: application identity, mask compatibility, the
/// applied parameter overrides, and the ordered step list with byte counts and
/// time estimate.
/// How the flash pre-flight reports itself: the `--json` switch and the global
/// `-v` count that unfolds the memory-level plan.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlashOutput {
    /// Emit the pre-flight as JSON (including the `parameters` array) instead of
    /// the human report.
    pub json: bool,
    /// The global `-v` repeat count. One or more unfolds the memory-level plan
    /// (the step trace) under the parameter-level one.
    pub verbose: u8,
}

/// Reads the device's current parameter memory over a read-only management
/// session, so the parameter plan can name what the device holds today.
///
/// Best-effort: any failure yields an empty map and every parameter is then
/// reported with an unknown current value. Nothing here writes to the device.
#[allow(clippy::too_many_arguments)]
fn read_current_parameters(
    runtime: &tokio::runtime::Runtime,
    config: bussard_transport::ConnectionConfig,
    target: IndividualAddress,
    plan: &FlashPlan,
    bcu_key: Option<u32>,
    tool_key: Option<bussard_secure::Key16>,
    secure_seq: bussard_secure::SequenceHighWater,
) -> CurrentMemory {
    let result: anyhow::Result<CurrentMemory> = runtime.block_on(async {
        let (handle, _task) = Bus::connect(config);
        if !handle
            .wait_connected(std::time::Duration::from_secs(10))
            .await
        {
            return Ok(CurrentMemory::new());
        }
        let source = ops::group_source(&handle);
        let lease = handle.lease().await.context("leasing the bus")?;
        let channel = LeaseChannel::new(lease);
        let secure = crate::secure_key::layer(&tool_key, &secure_seq);
        let current = match DeviceConnection::connect_with_secure(
            channel,
            target,
            source,
            Timeouts::default(),
            secure,
        )
        .await
        {
            Ok(mut dev) => {
                let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
                let _ = dev.authorize(key).await;
                let current = read_current_parameter_memory(dev.l4_mut(), plan).await;
                let _ = dev.disconnect().await;
                current
            }
            Err(_) => CurrentMemory::new(),
        };
        let _ = handle.close().await;
        anyhow::Ok(current)
    });
    match result {
        Ok(current) => current,
        Err(err) => {
            tracing::debug!(%err, "the parameter read-back did not run; values stay unknown");
            CurrentMemory::new()
        }
    }
}

/// Prints the parameter-level plan: what changes, in the vendor's own words.
fn print_param_plan(params: &ParamPlan) {
    if let Some(note) = &params.note {
        println!("  note        : {note}");
    }
    if params.changes.is_empty() {
        println!("  parameters  : no parameter change");
        return;
    }
    println!(
        "  parameters  : {} change(s){}:",
        params.changes.len(),
        if params.unknown > 0 {
            format!(", {} without a readable current value", params.unknown)
        } else {
            String::new()
        }
    );
    for change in &params.changes {
        println!("      {}", change.line());
    }
}

/// Emits the pre-flight as JSON, including the `parameters` array (issue #109).
fn print_plan_json(
    target: IndividualAddress,
    device_mask: u16,
    plan: &FlashPlan,
    params: &ParamPlan,
) -> anyhow::Result<()> {
    let parameters: Vec<serde_json::Value> = params
        .changes
        .iter()
        .map(|c| {
            serde_json::json!({
                "key": c.key,
                "name": c.name,
                "old": match &c.old {
                    ParamValue::Known(v) => serde_json::Value::String(v.clone()),
                    ParamValue::Unknown => serde_json::Value::Null,
                },
                "new": match &c.new {
                    ParamValue::Known(v) => serde_json::Value::String(v.clone()),
                    ParamValue::Unknown => serde_json::Value::Null,
                },
                "unit": c.unit,
            })
        })
        .collect();
    let value = serde_json::json!({
        "device": target.to_string(),
        "device_mask": format!("{device_mask:04X}"),
        "application": {
            "id": plan.identity.id,
            "name": plan.identity.name,
            "number": plan.identity.application_number,
            "version": plan.identity.application_version,
            "mask": plan.identity.mask_version,
        },
        "parameters": parameters,
        "parameter_note": params.note,
        "memory": {
            "write_bytes": plan.total_write_bytes(),
            "steps": plan.steps.len(),
            "frames": plan.estimated_write_frames(),
            "estimated_seconds": plan.estimated_duration().as_secs_f64(),
        },
        "procedure": trace(plan),
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn print_plan(
    target: IndividualAddress,
    device_mask: u16,
    plan: &FlashPlan,
    overrides: &BTreeMap<String, String>,
    params: &ParamPlan,
    verbose: u8,
) {
    println!("Flash plan for {target}");
    println!(
        "  application : {} {}",
        plan.identity.id,
        plan.identity.name.as_deref().unwrap_or(""),
    );
    if let (Some(num), Some(ver)) = (
        plan.identity.application_number,
        plan.identity.application_version,
    ) {
        println!("  app number  : {num} (version {ver})");
    }
    println!(
        "  mask        : app {} vs device {device_mask:04X} — compatible",
        plan.identity.mask_version,
    );
    // The parameter-level plan first (issue #109): an owner reads "night setback:
    // 18 to 17 °C", not a byte offset. The model's own override keys follow only
    // when asked for, and the memory-level plan only under `-v`.
    print_param_plan(params);
    if verbose > 0 && !overrides.is_empty() {
        println!(
            "  overrides   : {} model value(s), keyed by the app-relative ParameterRef id:",
            overrides.len()
        );
        for (key, value) in overrides {
            println!("      {key} = {value}");
        }
    }
    println!(
        "  writes      : {} byte(s) across {} step(s), ~{} memory frame(s), est. {:.1}s on TP1",
        plan.total_write_bytes(),
        plan.steps.len(),
        plan.estimated_write_frames(),
        plan.estimated_duration().as_secs_f64(),
    );
    if verbose > 0 {
        println!("  procedure   :");
        for line in trace(plan) {
            println!("    {line}");
        }
    } else {
        println!(
            "  procedure   : {} step(s); re-run with -v for the memory-level plan",
            plan.steps.len()
        );
    }
}

/// What the factory-freshness gate decided: what to tell the operator, whether
/// the flash may go ahead, and the line the confirmation prompt carries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FreshnessDecision {
    /// The paragraph printed after the plan, before the confirmation.
    message: String,
    /// Whether the flash continues. `false` is a refusal: nothing is written.
    proceed: bool,
    /// The one-line warning folded into the confirmation prompt when the device
    /// is not factory-fresh, so a `y` is typed against what is being destroyed.
    prompt_note: Option<String>,
}

/// Applies the factory-freshness rule (issue #79) to a probed verdict.
///
/// - [`Freshness::Fresh`] — proceed, restating that a first flash takes no
///   backup (there is nothing to save).
/// - [`Freshness::SameApplication`] — proceed **without** `--force`: re-flashing
///   the same application is the documented recovery path for an interrupted
///   flash (see `docs/SAFETY.md`). The notice still says what a re-flash resets.
/// - [`Freshness::Resident`] — a *different* (or unidentifiable) application is
///   loaded. Refused unless `force`, because the flash would destroy it with no
///   backup; the message names the resident application and the two ways
///   forward.
/// - [`Freshness::Unknown`] — the state could not be read. Refused unless
///   `force`: "unreadable" is not evidence of an empty device, and a flash with
///   no backup must not be what finds out.
///
/// `force` proceeds in both refusal cases, printing a single loud line that
/// names the device, the gateway and what is being destroyed.
fn decide_freshness(
    target: IndividualAddress,
    gateway: &str,
    dir: &Path,
    force: bool,
    freshness: &Freshness,
) -> FreshnessDecision {
    let dir = dir.display();
    match freshness {
        Freshness::Fresh => FreshnessDecision {
            message: format!(
                "\npre-flight: no application is loaded on {target} — the device is \
                 factory-fresh.\n\n\
                 NOTE: a first flash assumes the device is factory-fresh; no backup is\n\
                 possible (there is no prior application to save). Recovery from a failed\n\
                 flash is re-running `bussard flash`."
            ),
            proceed: true,
            prompt_note: None,
        },
        Freshness::SameApplication { resident } => FreshnessDecision {
            message: format!(
                "\npre-flight: {target} already runs this application ({resident}).\n\n\
                 NOTE: re-flashing the SAME application is allowed without --force — it is\n\
                 the documented recovery path for an interrupted flash. It is still a full\n\
                 rewrite and takes no backup: the parameters are reset to the vendor\n\
                 defaults plus this model's `parameters:` overrides, and the address,\n\
                 association and group-object tables are rewritten from the model's links."
            ),
            proceed: true,
            prompt_note: Some(format!(
                "{target} currently has {resident} Loaded; re-flashing the same application \
                 resets its parameters and tables."
            )),
        },
        Freshness::Resident { resident, objects } => {
            let what = match resident {
                Some(id) => format!("application {id}"),
                None => "an application bussard could not identify (no readable \
                         PID_PROGRAM_VERSION)"
                    .to_string(),
            };
            let where_ = objects.join(", ");
            if force {
                return FreshnessDecision {
                    message: format!(
                        "\nWARNING: --force — {target} via {gateway} is NOT factory-fresh: it has \
                         {what} Loaded ({where_}); this flash DESTROYS it, its parameters and its \
                         links, and takes NO backup."
                    ),
                    proceed: true,
                    prompt_note: Some(format!(
                        "{target} currently has {what} Loaded; this flash DESTROYS it (no backup)."
                    )),
                };
            }
            FreshnessDecision {
                message: format!(
                    "\nREFUSING to flash {target}: it is not factory-fresh.\n\
                     \x20 resident : {what}\n\
                     \x20 loaded   : {where_}\n\
                     A flash unloads and rewrites the application wholesale and takes NO backup,\n\
                     so this would destroy the resident application, its parameters and its links.\n\
                    \n\
                     Two ways forward:\n\
                     \x20 1. Capture what is on the device first: `bussard reconstruct {target} \
                     --dir {dir}`\n\
                     \x20    writes its links into the model, and `bussard apply {target}` backs \
                     the tables\n\
                     \x20    up to {dir}/captures/backups/ before it writes.\n\
                     \x20 2. Re-run with --force to overwrite it anyway (destructive, no backup).\n\
                    \n\
                     Re-flashing the SAME application needs no --force; this device does not \
                     report it."
                ),
                proceed: false,
                prompt_note: None,
            }
        }
        Freshness::Unknown { reason } => {
            if force {
                return FreshnessDecision {
                    message: format!(
                        "\nWARNING: --force — bussard could not read whether {target} via \
                         {gateway} is factory-fresh ({reason}); flashing anyway DESTROYS any \
                         application it carries, and takes NO backup."
                    ),
                    proceed: true,
                    prompt_note: Some(format!(
                        "{target}'s load state is unreadable; if it carries an application this \
                         flash DESTROYS it (no backup)."
                    )),
                };
            }
            FreshnessDecision {
                message: format!(
                    "\nREFUSING to flash {target}: its load state is unreadable, so bussard \
                     cannot tell\n\
                     whether the device is factory-fresh ({reason}).\n\
                     The device did NOT report an application as Loaded — the state is simply \
                     unknown,\n\
                     and a flash that takes no backup must not be what finds out.\n\
                     Re-run once the device answers reliably, or with --force to flash anyway \
                     (destructive\n\
                     if it carries an application)."
                ),
                proceed: false,
                prompt_note: None,
            }
        }
    }
}

/// Confirms on a TTY (y/N), naming the resolved gateway (issue #74) and, when
/// the device is not factory-fresh, what this flash destroys (issue #79).
/// Non-interactive without `--yes` is refused.
fn confirm(
    target: IndividualAddress,
    gateway: &str,
    yes: bool,
    plan: &FlashPlan,
    prompt_note: Option<&str>,
) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!(
            "refusing to flash {target} without a terminal to confirm on; \
             pass --yes to flash non-interactively"
        );
    }
    let writes = plan
        .steps
        .iter()
        .filter(|s| {
            matches!(
                s,
                FlashStep::WriteRelMem { .. } | FlashStep::WriteMem { .. }
            )
        })
        .count();
    if let Some(note) = prompt_note {
        eprintln!("{note}");
    }
    eprint!(
        "flash {} ({writes} memory write(s)) to {target} via {gateway}? [y/N] ",
        plan.identity.id
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Prints loud recovery guidance on any flash failure.
fn recovery_notice(target: IndividualAddress) {
    eprintln!(
        "\nThe device may be left with a partially-written or unloaded application.\n\
         Because this was a first flash there is no prior state to restore.\n\
         Recover by re-running `bussard flash {target}` (the download is idempotent —\n\
         it re-unloads and rewrites the application wholesale), or by downloading the\n\
         device with ETS. Do not assume the device is functional until a re-flash\n\
         reports the application is Loaded and verified.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::parse_application_program;

    /// Builds a one-device model whose device at `addr` carries `params`.
    fn model_with_params(addr: &str, params: &[(&str, &str)]) -> bussard_model::Model {
        use bussard_model::schema::Device;
        let address: IndividualAddress = addr.parse().unwrap();
        let device = Device {
            address,
            name: "test".to_string(),
            description: None,
            location: None,
            product: None,
            channels: Default::default(),
            parameters: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            module_bases: Default::default(),
            com_objects: Default::default(),
            security: None,
        };
        let mut devices = std::collections::BTreeMap::new();
        devices.insert(
            address,
            bussard_model::loader::LoadedDevice {
                device,
                file_stem: "test".to_string(),
            },
        );
        bussard_model::Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices,
        }
    }

    #[test]
    fn parameter_overrides_are_rekeyed_to_ref_id() {
        // A device file keys parameters `<slug>@<ref-id>`; collection drops the
        // slug and keys by the ETS-stable ref id (the part after @).
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        let model = model_with_params(
            "1.1.4",
            &[
                ("windalarm-1@MD-1_M-3_MI-1_P-3_R-45", "1"),
                ("nachtabsenkung@P-1312_R-2140", "18"),
            ],
        );
        let out = collect_parameter_overrides(Some(&model), target);
        assert_eq!(
            out.get("MD-1_M-3_MI-1_P-3_R-45").map(String::as_str),
            Some("1")
        );
        assert_eq!(out.get("P-1312_R-2140").map(String::as_str), Some("18"));
        // The human slug is gone from the key entirely.
        assert!(!out.keys().any(|k| k.contains('@')));
    }

    #[test]
    fn malformed_parameter_key_without_at_is_skipped() {
        // A key with no `@` has no determinable ref-id identity; it is skipped
        // rather than fed to the engine as a bogus ref id.
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        let model = model_with_params("1.1.4", &[("bogus_no_at_sign", "5")]);
        let out = collect_parameter_overrides(Some(&model), target);
        assert!(out.is_empty());
    }

    #[test]
    fn no_model_or_unknown_device_yields_no_overrides() {
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        assert!(collect_parameter_overrides(None, target).is_empty());
        // A model that has no device at the target address contributes nothing.
        let model = model_with_params("1.1.9", &[("x@P-1_R-1", "1")]);
        assert!(collect_parameter_overrides(Some(&model), target).is_empty());
    }

    /// A minimal parseable single-segment System B application under id `id`.
    fn app(id: &str) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
             <ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1"
                MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
              <Static>
               <Code>
                <RelativeSegment Id="{id}_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
               </Code>
               <LoadProcedures>
                <LoadProcedure><LdCtrlConnect /><LdCtrlDisconnect /></LoadProcedure>
               </LoadProcedures>
              </Static>
             </ApplicationProgram></KNX>"#
        );
        parse_application_program(id, xml.as_bytes()).unwrap()
    }

    /// Builds a [`ProductData`] from `(order_number, [app_ref…])` rows and the
    /// application ids present in the archive.
    fn product(rows: &[(&str, &[&str])], app_ids: &[&str]) -> ProductData {
        let mut data = ProductData {
            manufacturers: vec!["M-0083".to_string()],
            ..ProductData::default()
        };
        for id in app_ids {
            data.applications.push(app(id));
        }
        for (order, refs) in rows {
            data.hardware.order_to_apps.insert(
                order.to_string(),
                refs.iter().map(|r| r.to_string()).collect(),
            );
        }
        data
    }

    #[test]
    fn resolves_exactly_one_match() {
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-000D-23-5BFD"])],
            &["M-0083_A-000D-23-5BFD"],
        );
        let app = resolve_by_order_number(&data, "AKK-0216.03").unwrap();
        assert_eq!(app.id, "M-0083_A-000D-23-5BFD");
    }

    #[test]
    fn resolution_normalizes_case_and_whitespace() {
        // Index-style normalization: trim + upper-case, interior separators kept.
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-000D-23-5BFD"])],
            &["M-0083_A-000D-23-5BFD"],
        );
        let app = resolve_by_order_number(&data, "  akk-0216.03 ").unwrap();
        assert_eq!(app.id, "M-0083_A-000D-23-5BFD");
    }

    #[test]
    fn zero_matches_lists_known_order_numbers() {
        let data = product(
            &[
                ("AKK-0216.03", &["M-0083_A-1"]),
                ("AKK-0416.03", &["M-0083_A-1"]),
            ],
            &["M-0083_A-1"],
        );
        let err = resolve_by_order_number(&data, "NOPE-9").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no application matches order number"), "{msg}");
        assert!(
            msg.contains("AKK-0216.03"),
            "should list known order numbers: {msg}"
        );
        assert!(
            msg.contains("--application"),
            "should point at the fallback: {msg}"
        );
    }

    #[test]
    fn multiple_matches_lists_candidate_ids() {
        // One order number mapping to two distinct applications is ambiguous.
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-1", "M-0083_A-2"])],
            &["M-0083_A-1", "M-0083_A-2"],
        );
        let err = resolve_by_order_number(&data, "AKK-0216.03").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("maps to 2 applications"), "{msg}");
        assert!(
            msg.contains("M-0083_A-1") && msg.contains("M-0083_A-2"),
            "{msg}"
        );
        assert!(msg.contains("--application"), "{msg}");
    }

    #[test]
    fn descriptor_disconnect_after_connect_names_the_pattern() {
        let target: IndividualAddress = "1.0.10".parse().unwrap();
        let err = descriptor_read_error(
            target,
            true, // the T_Connect established before the read
            false,
            MgmtError::Disconnected { address: target },
        );
        let msg = err.to_string();
        assert!(
            msg.contains("accepted the connection but disconnected on the first read"),
            "{msg}"
        );
        assert!(msg.contains("*.ip") && msg.contains("*.tp"), "{msg}");
    }

    #[test]
    fn descriptor_disconnect_without_connect_is_passed_through() {
        // A disconnect that happened before the connection established is not the
        // IP-medium pattern; it passes through with the generic context.
        let target: IndividualAddress = "1.0.10".parse().unwrap();
        let err = descriptor_read_error(
            target,
            false,
            false,
            MgmtError::Disconnected { address: target },
        );
        let msg = err.to_string();
        assert!(msg.contains("reading the device descriptor"), "{msg}");
        assert!(
            !msg.contains("accepted the connection but disconnected"),
            "{msg}"
        );
    }

    #[test]
    fn descriptor_other_error_is_passed_through() {
        let target: IndividualAddress = "1.0.10".parse().unwrap();
        let err = descriptor_read_error(target, true, false, MgmtError::Nak { address: target });
        let msg = err.to_string();
        assert!(msg.contains("reading the device descriptor"), "{msg}");
    }

    /// A silent activated device (wrong tool key, or a plain device ignoring the
    /// wrapper) names the KNX Data Secure cause, not the IP-medium pattern.
    #[test]
    fn descriptor_silence_on_a_secure_connection_names_the_tool_key() {
        let target: IndividualAddress = "1.1.2".parse().unwrap();
        for err in [
            MgmtError::Disconnected { address: target },
            MgmtError::NoResponse { address: target },
        ] {
            let msg = descriptor_read_error(target, true, true, err).to_string();
            assert!(msg.contains("SECURED management access"), "{msg}");
            assert!(msg.contains("tool key"), "{msg}");
            assert!(msg.contains("Nothing was written"), "{msg}");
            assert!(
                !msg.contains("*.ip"),
                "the IP-medium guidance is wrong here: {msg}"
            );
        }
    }

    /// A silent PLAIN connection points at the keyring: an activated device
    /// refuses unsecured management (spec §6.4).
    #[test]
    fn descriptor_silence_on_a_plain_connection_suggests_the_keyring() {
        let target: IndividualAddress = "1.1.2".parse().unwrap();
        for err in [
            MgmtError::NoResponse { address: target },
            MgmtError::Disconnected { address: target },
        ] {
            let msg = descriptor_read_error(target, true, false, err).to_string();
            assert!(msg.contains("--keyring"), "{msg}");
            assert!(msg.contains("KNX Data Secure"), "{msg}");
        }
    }

    #[test]
    fn duplicate_refs_across_rows_collapse_to_one() {
        // Two order-number rows pointing at the same application resolve cleanly.
        let data = product(
            &[
                ("AKK-0216.03", &["M-0083_A-1"]),
                ("AKK-0216.03 ", &["M-0083_A-1"]),
            ],
            &["M-0083_A-1"],
        );
        let app = resolve_by_order_number(&data, "AKK-0216.03").unwrap();
        assert_eq!(app.id, "M-0083_A-1");
    }

    // --- The factory-freshness gate (issue #79) -----------------------------

    /// A target, gateway and model dir for the gate messages.
    fn gate(force: bool, freshness: &Freshness) -> FreshnessDecision {
        let target: IndividualAddress = "1.0.2".parse().unwrap();
        decide_freshness(target, "127.0.0.1:3671", Path::new("knx"), force, freshness)
    }

    fn resident_other() -> Freshness {
        Freshness::Resident {
            resident: Some("M-0083 A-0007 v35".to_string()),
            objects: vec!["object 3 (application program)".to_string()],
        }
    }

    #[test]
    fn test_decide_freshness_fresh_device_proceeds_with_the_no_backup_note() {
        let decision = gate(false, &Freshness::Fresh);
        assert!(decision.proceed);
        assert!(decision.prompt_note.is_none());
        assert!(
            decision
                .message
                .contains("no application is loaded on 1.0.2"),
            "{}",
            decision.message
        );
        // The long-standing no-backup note is still stated before the write.
        assert!(
            decision.message.contains("no backup is"),
            "{}",
            decision.message
        );
    }

    #[test]
    fn test_decide_freshness_same_application_proceeds_without_force() {
        let decision = gate(
            false,
            &Freshness::SameApplication {
                resident: "M-00FA A-2500 v16".to_string(),
            },
        );
        assert!(
            decision.proceed,
            "a re-flash of the same app needs no --force"
        );
        assert!(
            decision
                .message
                .contains("1.0.2 already runs this application (M-00FA A-2500 v16)"),
            "{}",
            decision.message
        );
        // It says what a re-flash resets, so "allowed" is not read as "harmless".
        assert!(
            decision.message.contains("reset to the vendor"),
            "{}",
            decision.message
        );
        let note = decision.prompt_note.expect("the prompt names the re-flash");
        assert!(note.contains("M-00FA A-2500 v16"), "{note}");
        assert!(note.contains("Loaded"), "{note}");
    }

    #[test]
    fn test_decide_freshness_other_application_is_refused_without_force() {
        let decision = gate(false, &resident_other());
        assert!(
            !decision.proceed,
            "a different resident app must be refused"
        );
        let msg = &decision.message;
        assert!(msg.contains("REFUSING to flash 1.0.2"), "{msg}");
        // Names the resident application and where it is loaded.
        assert!(msg.contains("M-0083 A-0007 v35"), "{msg}");
        assert!(msg.contains("object 3 (application program)"), "{msg}");
        // Names both ways forward.
        assert!(msg.contains("--force"), "{msg}");
        assert!(msg.contains("bussard reconstruct 1.0.2 --dir knx"), "{msg}");
        assert!(msg.contains("bussard apply 1.0.2"), "{msg}");
        // States the same-application rule explicitly.
        assert!(msg.contains("Re-flashing the SAME application"), "{msg}");
    }

    #[test]
    fn test_decide_freshness_force_proceeds_with_a_loud_warning() {
        let decision = gate(true, &resident_other());
        assert!(decision.proceed);
        let msg = &decision.message;
        assert!(msg.contains("WARNING: --force"), "{msg}");
        // The warning names the device, the gateway and what is destroyed.
        assert!(msg.contains("1.0.2"), "{msg}");
        assert!(msg.contains("127.0.0.1:3671"), "{msg}");
        assert!(msg.contains("M-0083 A-0007 v35"), "{msg}");
        assert!(msg.contains("DESTROYS"), "{msg}");
        let note = decision.prompt_note.expect("the prompt warns too");
        assert!(note.contains("Loaded"), "{note}");
        assert!(note.contains("DESTROYS it"), "{note}");
    }

    #[test]
    fn test_decide_freshness_unidentified_resident_application_is_refused() {
        let decision = gate(
            false,
            &Freshness::Resident {
                resident: None,
                objects: vec!["LSM 3".to_string()],
            },
        );
        assert!(!decision.proceed);
        assert!(
            decision.message.contains("could not identify"),
            "{}",
            decision.message
        );
        assert!(decision.message.contains("LSM 3"), "{}", decision.message);
    }

    #[test]
    fn test_decide_freshness_unreadable_state_is_refused_as_unknown() {
        let decision = gate(
            false,
            &Freshness::Unknown {
                reason: "no object reported a load state".to_string(),
            },
        );
        assert!(
            !decision.proceed,
            "unknown is refused, not treated as fresh"
        );
        let msg = &decision.message;
        assert!(msg.contains("load state is unreadable"), "{msg}");
        assert!(msg.contains("no object reported a load state"), "{msg}");
        // The message must not leave the operator thinking the device reported
        // an application as Loaded.
        assert!(
            msg.contains("did NOT report an application as Loaded"),
            "{msg}"
        );
        assert!(msg.contains("--force"), "{msg}");
    }

    #[test]
    fn test_decide_freshness_unknown_with_force_proceeds() {
        let decision = gate(
            true,
            &Freshness::Unknown {
                reason: "device refused the read".to_string(),
            },
        );
        assert!(decision.proceed);
        assert!(
            decision.message.contains("WARNING: --force"),
            "{}",
            decision.message
        );
        assert!(
            decision.message.contains("127.0.0.1:3671"),
            "{}",
            decision.message
        );
        assert!(decision.prompt_note.is_some());
    }
}
