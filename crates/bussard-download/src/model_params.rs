//! The model's parameter half of a device write, shared by `bussard flash`,
//! `bussard apply` and the MCP programming tier (issue #274).
//!
//! Everything here is offline or read-only on the bus: the parameter inputs
//! and table images the flash planner takes from the model, the full plan a
//! parameter read-back locates the memory with, the resident-application
//! gate a parameter-only download needs, and the read-back verification and
//! backup of the parameter memory. One implementation, so the image the MCP
//! tier writes is byte-identical to the CLI's.

use std::collections::BTreeMap;
use std::path::Path;

use bussard_mgmt::memory::read_memory_range;
use bussard_model::IndividualAddress;
use bussard_prod::{ApplicationProgram, ProductData, normalize_order_number};

use crate::backup::{
    ParameterBackup, ParameterMemory, encode_hex, parameter_backups_dir, rfc3339_utc, unix_seconds,
    write_parameter_backup,
};
use crate::flash::{FlashPlan, FlashStep, plan_flash_with_object_flags};
use crate::param_plan::ParamRegions;
use crate::preflight::{Freshness, ResidentState, assess_freshness};

/// Why an order number selects no single application program.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OrderNumberError(pub String);

/// The master-template `Load` procedure for `app`'s mask, if the archive
/// shipped a `knx_master.xml`. A merged application (e.g. KNX Virtual DA.tp)
/// only carries its own app-segment blocks; the load-control ops for the table
/// objects (obj1/obj2/obj3) live in the template and are spliced in.
pub fn template_ops_for(
    product_data: &ProductData,
    app: &ApplicationProgram,
) -> Option<Vec<bussard_prod::application::LoadOp>> {
    app.mask_version
        .as_deref()
        .and_then(|mask| {
            product_data
                .master
                .as_ref()
                .and_then(|m| m.full_load_procedure(mask))
        })
        .map(|proc| proc.ops.clone())
}

/// The model's parameter inputs for `target`: the parameter overrides
/// re-keyed to app-relative ParameterRef ids, and the module-instance bases.
pub fn model_parameters(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
) -> (BTreeMap<String, String>, BTreeMap<String, u32>) {
    let overrides = collect_parameter_overrides(model, target);
    let bases = model
        .and_then(|m| m.devices.get(&target))
        .map(|d| d.device.module_bases.clone())
        .unwrap_or_default();
    (overrides, bases)
}

/// The full flash plan for `target` against `device_mask`, built offline the
/// way `flash` builds it. `plan` and `reconstruct` use it to locate the
/// parameter memory they read back (issue #119).
pub fn plan_for_readback(
    product_data: &ProductData,
    app: &ApplicationProgram,
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
    device_mask: u16,
) -> Result<FlashPlan, crate::PlanError> {
    let (overrides, bases) = model_parameters(model, target);
    let template_ops = template_ops_for(product_data, app);
    let table_images = build_table_images(model, target, app, &overrides);
    let object_flags = linked_object_flags(model, target);
    plan_flash_with_object_flags(
        app,
        &target.to_string(),
        device_mask,
        &overrides,
        &bases,
        template_ops.as_deref(),
        &table_images,
        &object_flags,
    )
}

/// Collects the target device's parameter overrides from the model, re-keyed
/// from the device-file `<slug>@<ref-id>` form to the bare app-relative
/// `ParameterRef` id the flash engine consumes (the part after `@`).
///
/// The slug before `@` is a human aid and is dropped. A key with no `@` is
/// malformed for this contract and skipped with a warning (rather than fed to the
/// engine as a bogus ref id). Returns an empty map when the model is absent or
/// the device has no parameter values; the second half lists the warnings
/// for malformed keys.
pub fn parameter_overrides(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut malformed = Vec::new();
    let Some(model) = model else {
        return (out, malformed);
    };
    let Some(loaded) = model.devices.get(&target) else {
        return (out, malformed);
    };
    for (key, value) in &loaded.device.parameters {
        match key.split_once('@') {
            Some((_slug, ref_id)) if !ref_id.is_empty() => {
                out.insert(ref_id.to_string(), value.clone());
            }
            _ => malformed.push(malformed_parameter_warning(key, target)),
        }
    }
    (out, malformed)
}

/// The warning for a parameter key without the `<slug>@<ref-id>` form.
pub fn malformed_parameter_warning(key: &str, target: IndividualAddress) -> String {
    format!(
        "warning: ignoring parameter key {key:?} on {target}: it has no `<slug>@<ref-id>` \
         form, so its ETS-stable identity is undetermined"
    )
}

/// [`parameter_overrides`], logging each malformed key at `warn` (the CLI
/// prints them itself).
fn collect_parameter_overrides(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
) -> BTreeMap<String, String> {
    let (out, malformed) = parameter_overrides(model, target);
    for warning in malformed {
        tracing::warn!("{warning}");
    }
    out
}

/// The model's flags of every com-object the device links, keyed by object
/// number. A System 7 plan writes them into the linked descriptors; the System B
/// group-object table image cannot carry object 0 (issue #126, 1.1.1).
pub fn linked_object_flags(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
) -> BTreeMap<u16, bussard_model::Flags> {
    let Some(model) = model else {
        return BTreeMap::new();
    };
    let linked: std::collections::BTreeSet<u16> = model
        .links
        .links
        .get(&target)
        .map(|links| links.iter().map(|l| l.object).collect())
        .unwrap_or_default();
    model
        .devices
        .get(&target)
        .map(|loaded| {
            loaded
                .device
                .com_objects
                .iter()
                .filter(|(number, _)| linked.contains(number))
                .map(|(number, co)| (*number, co.flags))
                .collect()
        })
        .unwrap_or_default()
}
/// Builds the loadable table images (obj1 address, obj2 association, obj3
/// group-object) a merged flash writes, keyed by device object index (1/2/3).
///
/// obj1 and obj2 come from the device's model links via
/// [`crate::compute_tables`] (the same tables `bussard apply`
/// downloads); obj3 is the System B group-object descriptor table built from the
/// app's com-objects (its byte layout is verified byte-for-byte against the
/// ETS→KNX-Virtual DA.tp capture — see
/// [`crate::compute::compute_group_object_table`]). Each image
/// includes its big-endian element-count word.
///
/// For a **module-based** application (the DA.tp shape), obj3 is
/// **channel-expanded**: the module's com-objects are instantiated once per
/// `<Module>` channel via
/// [`crate::expand_group_object_descriptors`], so the table carries
/// every per-channel com-object instance ETS emits (73 entries for DA.tp), not
/// just the 7 module base objects. Each channel's Communication flag is set when
/// any of its com-objects is linked in the model, matching ETS (which registers a
/// linked instance with Communication set and an unlinked one with it cleared).
/// A non-module application keeps the flat per-com-object table.
///
/// An application with a Dynamic section (every real product; issue #123) is
/// evaluated like ETS does instead: the device's parameter `overrides` decide
/// which modules and com-objects the configuration shows, only those get
/// descriptors (Communication set when linked, the model's per-object flags
/// for a linked one), at ASAP `Number` + the module instance's `BaseNumber`
/// argument, and the table is counted up to the application's highest own
/// com-object number ([`crate::dynamic_group_object_table`]). The
/// two paths below remain for applications without one.
///
/// Returns an empty map when the model is absent or the device has no links —
/// which leaves a self-contained (thelsing) single-object flash untouched.
pub fn build_table_images(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> BTreeMap<u32, Vec<u8>> {
    use crate::compute::{
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
    let desired = crate::compute_tables(links);
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
    // The flags ETS writes for a linked object are the project's, not the
    // product's defaults: the model's `com_objects` carry them (1.1.46 in the
    // campaign: object 7 is CRT in the model and ETS wrote T R C, the product
    // default lacks T). Applied to every descriptor set below.
    let model_flags: std::collections::BTreeMap<u16, bussard_model::Flags> = model
        .and_then(|m| m.devices.get(&target))
        .map(|loaded| {
            loaded
                .device
                .com_objects
                .iter()
                .map(|(number, co)| (*number, co.flags))
                .collect()
        })
        .unwrap_or_default();
    let with_model_flags = |mut descriptors: Vec<GroupObjectDescriptor>| {
        for d in &mut descriptors {
            if linked.contains(&d.asap)
                && let Some(flags) = model_flags.get(&d.asap)
            {
                d.flags = *flags;
            }
        }
        descriptors
    };
    let obj3 = if bussard_prod::uses_dynamic_image(app) {
        let model_objects = model
            .and_then(|m| m.devices.get(&target))
            .map(|d| &d.device.com_objects);
        let linked_objects: BTreeMap<u16, crate::LinkedObject> = linked
            .iter()
            .map(|&object| {
                let info = model_objects.and_then(|objects| objects.get(&object));
                let entry = crate::LinkedObject {
                    com_object_ref: info.and_then(|c| c.reference.clone()),
                    flags: info.map(|c| c.flags),
                };
                (object, entry)
            })
            .collect();
        crate::dynamic_group_object_table(app, overrides, &linked_objects)
    } else if !app.module_instances.is_empty() && app.channel_membership.is_some() {
        // Module-based application: instantiate the com-objects across channels.
        // Each channel is linked when any of the com-objects it carries appears
        // in the model links; `<choose>` selectors fall back to their parameter
        // defaults (the vendor-default channel objects on a bare flash).
        let descriptors = with_model_flags(build_module_obj3_descriptors(app, &linked));
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
            let descriptors =
                with_model_flags(descriptors_for_linked_objects(&com_objects, &linked));
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
pub fn build_module_obj3_descriptors(
    app: &ApplicationProgram,
    linked: &std::collections::BTreeSet<u16>,
) -> Vec<crate::compute::GroupObjectDescriptor> {
    use crate::compute::{ChannelConfig, expand_group_object_descriptors};

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
pub fn resolve_by_order_number<'a>(
    product: &'a ProductData,
    order_number: &str,
) -> Result<&'a ApplicationProgram, OrderNumberError> {
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
        if let Some(app) = product.application_by_id(r)
            && !apps.iter().any(|a| a.id == app.id)
        {
            apps.push(app);
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
            Err(OrderNumberError(format!(
                "no application matches order number {order_number:?} in {}; {candidates}. \
                 Pass --application <ref> to select by application id instead.",
                product_display(product),
            )))
        }
        many => {
            let ids: Vec<&str> = many.iter().map(|a| a.id.as_str()).collect();
            Err(OrderNumberError(format!(
                "order number {order_number:?} maps to {} applications ({}); \
                 disambiguate with --application <ref>.",
                many.len(),
                ids.join(", "),
            )))
        }
    }
}

/// A short label for the product in an error message: its manufacturer id(s).
pub fn product_display(product: &ProductData) -> String {
    if product.manufacturers.is_empty() {
        "the product archive".to_string()
    } else {
        format!("the product archive ({})", product.manufacturers.join(", "))
    }
}

/// The resident-application rule: the device must run the application the
/// product file describes, and it must be `Loaded`.
///
/// One rule for every caller that trusts the resident parameter layout (the
/// parameter-only download and the `plan`/`reconstruct` read-back, issue
/// #142). System B compares `PID_PROGRAM_VERSION` (manufacturer, application
/// number and version: a product build with another hash is the same
/// program). System 7 has no readable id: every load-state machine the
/// application's procedure drives must be `Loaded`, and the caller samples the
/// code segments with [`sys7_code_mismatch`].
pub fn identity_gate(plan: &FlashPlan, resident: Option<&ResidentState>) -> Result<(), String> {
    let Some(state) = resident else {
        return Err(
            "the pre-flight probe did not run, so the resident application is unknown".into(),
        );
    };
    let expected = &plan.identity.id;
    match assess_freshness(state, &plan.identity) {
        Freshness::SameApplication { .. } => Ok(()),
        Freshness::Fresh => Err(format!(
            "the device holds no loaded application (it is not Loaded); a parameter-only \
             download needs {expected} in place. Run a full `bussard flash` first."
        )),
        Freshness::Unknown { reason } => Err(format!(
            "the device's load state could not be read ({reason})"
        )),
        Freshness::Resident {
            resident: Some(id), ..
        } => Err(format!(
            "the device runs application {id}, not {expected}; its parameter memory does not \
             have this application's layout. Run a full `bussard flash` to replace it."
        )),
        Freshness::Resident { resident: None, .. } if plan.is_sys7() => {
            // System 7 exposes no application id. Every load-state machine must
            // be Loaded; the code-segment comparison in `read_device` stands in
            // for the id.
            let driven: std::collections::BTreeSet<u32> = plan
                .steps
                .iter()
                .filter_map(|step| match step {
                    FlashStep::Sys7StartLoading { lsm } => Some(*lsm),
                    _ => None,
                })
                .collect();
            let unloaded: Vec<String> = state
                .objects
                .iter()
                // An LSM the application's procedure never loads (the probe
                // reads every one the mask defines) says nothing about it.
                .filter(|o| driven.is_empty() || driven.contains(&u32::from(o.index)))
                .filter(|o| o.state != bussard_mgmt::load::LoadState::Loaded)
                .map(|o| format!("{} is {}", o.label(), o.state))
                .collect();
            if unloaded.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "the device is not fully Loaded ({}); run a full `bussard flash`",
                    unloaded.join(", ")
                ))
            }
        }
        Freshness::Resident { resident: None, .. } => Err(format!(
            "the device runs an application whose id (PID_PROGRAM_VERSION) cannot be read, so \
             it cannot be confirmed to be {expected}"
        )),
    }
}

/// How many leading octets of each System 7 code segment are compared.
const CODE_SAMPLE: usize = 32;

/// Compares the leading octets of every System 7 code segment (a data-bearing
/// segment no parameter targets) against the product's bytes. System 7 has no
/// readable application id, so resident code that differs is the evidence of a
/// different application. `None` when every sampled segment matches, or when
/// there is none to sample.
pub async fn sys7_code_mismatch<Ch: bussard_mgmt::L4Channel>(
    l4: &mut bussard_mgmt::Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> Option<String> {
    for step in &plan.steps {
        let FlashStep::Sys7AbsSegment {
            address,
            image: Some(image),
            checksum_ctrl,
            ..
        } = step
        else {
            continue;
        };
        // Parameter segments are what changes; runtime-writable segments are
        // rewritten by the running application; table segments are the links.
        let carries_params = plan
            .param_images
            .get(&image.segment_id)
            .is_some_and(|b| !b.is_empty());
        if carries_params || *checksum_ctrl == 0 || image.kind == crate::ImageKind::Table {
            continue;
        }
        let Some(expected) = plan.image_bytes(&image.segment_id) else {
            continue;
        };
        let len = expected.len().min(CODE_SAMPLE);
        let Ok(got) = read_memory_range(l4, *address, len).await else {
            continue;
        };
        let mask = plan.segment_mask(&image.segment_id);
        let differs = (0..len)
            .any(|i| mask.is_none_or(|m| m.get(i) == Some(&0xFF)) && got.get(i) != expected.get(i));
        if differs {
            return Some(format!(
                "the code at {address:#06X} ({}) does not match {}; the device runs another \
                 application or version. Run a full `bussard flash` to replace it.",
                image.segment_id, plan.identity.id
            ));
        }
    }
    None
}

/// Names what a group-object change shows and hides.
pub fn describe_group_object_change(change: &crate::GroupObjectChange) -> String {
    let list = |v: &[u16]| v.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
    let mut parts = Vec::new();
    if !change.shown.is_empty() {
        parts.push(format!("shows object(s) {}", list(&change.shown)));
    }
    if !change.hidden.is_empty() {
        parts.push(format!("hides object(s) {}", list(&change.hidden)));
    }
    if parts.is_empty() {
        parts.push("changes an object's size or flags".to_string());
    }
    parts.join(", ")
}

/// The memory regions the download writes: `(segment, address, octets, changed)`.
pub fn region_rows(
    partial: &FlashPlan,
    regions: &ParamRegions,
) -> Vec<(String, u32, usize, usize)> {
    regions
        .values()
        .filter_map(|r| {
            let current = partial.baseline(&r.segment_id)?;
            let desired = partial.image_bytes(&r.segment_id)?;
            let mask = partial.segment_mask(&r.segment_id);
            let changed = desired
                .iter()
                .enumerate()
                .filter(|(i, b)| {
                    mask.is_none_or(|m| m.get(*i) == Some(&0xFF)) && current.get(*i) != Some(*b)
                })
                .count();
            Some((r.segment_id.clone(), r.address, desired.len(), changed))
        })
        .collect()
}

/// Writes the pre-download parameter memory to
/// `<dir>/captures/backups/parameters/<ia>-<ts>.json`.
pub fn write_parameter_memory_backup(
    dir: &Path,
    target: IndividualAddress,
    plan: &FlashPlan,
    regions: &ParamRegions,
) -> Result<std::path::PathBuf, crate::BackupError> {
    let now = std::time::SystemTime::now();
    let backup = ParameterBackup {
        address: target.to_string(),
        mask: format!("{:04X}", plan.device_mask),
        application: plan.identity.id.clone(),
        unix_timestamp: unix_seconds(now),
        read_time: rfc3339_utc(now),
        regions: regions
            .values()
            .map(|r| ParameterMemory {
                base: r.address,
                length: r.bytes.len(),
                bytes: encode_hex(&r.bytes),
                source: format!("parameter segment {}", r.segment_id),
            })
            .collect(),
    };
    write_parameter_backup(&parameter_backups_dir(dir), &backup)
}

/// The System 7 segments the running application rewrites after the restart
/// (`checksum_ctrl == 0`, the Jung `0x4916` region, issue #89): their
/// read-back proves nothing, so the verify skips them.
pub fn runtime_segments(plan: &FlashPlan) -> std::collections::BTreeSet<String> {
    plan.steps
        .iter()
        .filter_map(|step| match step {
            FlashStep::Sys7AbsSegment {
                checksum_ctrl: 0,
                image: Some(image),
                ..
            } => Some(image.segment_id.clone()),
            _ => None,
        })
        .collect()
}

/// Compares the read-back against every octet the download meant to change,
/// except in the segments the application rewrites at run time (`skip`).
/// Returns how many octets were checked.
pub fn verify_readback(
    partial: &FlashPlan,
    after: &ParamRegions,
    skip: &std::collections::BTreeSet<String>,
) -> Result<usize, String> {
    let mut checked = 0usize;
    for (segment, _, _, _) in region_rows(partial, after) {
        if skip.contains(&segment) {
            continue;
        }
        let (Some(current), Some(desired)) =
            (partial.baseline(&segment), partial.image_bytes(&segment))
        else {
            continue;
        };
        let read = after
            .get(&segment)
            .map(|r| r.bytes.as_slice())
            .ok_or_else(|| format!("segment {segment} could not be read back"))?;
        let mask = partial.segment_mask(&segment);
        for (i, want) in desired.iter().enumerate() {
            let writable = mask.is_none_or(|m| m.get(i) == Some(&0xFF));
            if !writable || current.get(i) == Some(want) {
                continue;
            }
            checked += 1;
            if read.get(i) != Some(want) {
                return Err(format!(
                    "segment {segment} octet {i} reads {:?}, expected {want:#04X}",
                    read.get(i)
                ));
            }
        }
    }
    if after.is_empty() {
        return Err("the parameter memory could not be read back".to_string());
    }
    Ok(checked)
}
