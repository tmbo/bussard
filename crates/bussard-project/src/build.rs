//! Assembles a [`Model`] from the parsed project and manufacturer data.
//!
//! This is where the resolution chain lives: com-object instances are resolved
//! through the manufacturer XML's refs and bases to effective DPT / flags /
//! size / name, links are split into send (first) and listen (rest), and group
//! addresses without an explicit DPT inherit one from a linked com-object.

use std::collections::{BTreeMap, HashMap};

use bussard_model::loader::{LoadedDevice, Model};
use bussard_model::schema::{
    BussardConfig, Channel, ComObject, Device, Group, Groups, Link, Links, Location, Product, Range,
};
use bussard_model::{Dpt, Flags, GroupAddress, IndividualAddress};

use crate::container::Container;
use crate::error::Result;
use crate::hardware::Hardware;
use crate::knx_master;
use crate::manufacturer::{ApplicationProgram, parse_application_program};
use crate::project::{RawComObjectInstance, RawDevice, RawProject};

/// A fully-resolved com object on a device.
struct ResolvedComObject {
    number: u16,
    /// Informational name; lives only in `links.yaml` (issue #19).
    name: String,
    dpt: Option<Dpt>,
    size: Option<String>,
    flags: Flags,
    /// The owning channel *key* (a raw module-instance channel ref, e.g.
    /// `MD-1_M-1_MI-1_CH-13`); the human label is resolved separately (#11).
    channel: Option<String>,
    reference: String,
    /// GA references (suffixes) in link order; first is the sending GA.
    link_suffixes: Vec<String>,
    /// The instance's ETS `Security` setting (absent = the `Auto` default).
    security: Option<crate::project::SecuritySetting>,
}

/// Normalizes an ETS `ObjectSize` string (e.g. `"1 Bit"`, `"2 Bytes"`) to the
/// lowercase `"1 bit"` / `"2 bytes"` style used across bussard (issue #17).
fn normalize_size(size: &str) -> String {
    size.trim().to_ascii_lowercase()
}

/// Resolves the `{{…}}` placeholders in a manufacturer `Text`.
///
/// Two placeholder families appear in the ETS product data (issue #11):
///
/// * `{{ArgName}}` — a module argument reference (e.g. `{{ArgBeschriftung}}`).
///   It is resolved against the owning module instance's argument values: the
///   application program maps the argument `Name` to its app-relative id (e.g.
///   `ArgBeschriftung` → `MD-1_A-3`) and the module instance holds that id's
///   value (e.g. `"1/2"`). When the value is missing or empty the placeholder is
///   dropped.
/// * `{{N:...}}` — a numbered format token ETS substitutes at display time
///   (e.g. `{{0:...}}`). We have no value for it, so it is stripped cleanly.
///
/// After substitution the result is whitespace-normalized (runs collapsed,
/// ends trimmed) and any now-empty parenthetical left behind by a stripped
/// token (e.g. `" ()"`) is removed. Returns `None` if nothing readable remains.
fn resolve_placeholders(
    text: &str,
    app: &ApplicationProgram,
    module_instance_id: Option<&str>,
    module_instances: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    if !text.contains("{{") {
        return non_empty_label(text);
    }

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            // Unterminated placeholder: keep the remainder verbatim.
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let token = &after[..close];
        // A numbered format token like `0:...` — no value available, strip it.
        let is_numbered = token
            .split_once(':')
            .map(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or(false);
        if !is_numbered {
            // Treat as an argument-name reference.
            if let Some(value) = module_instance_id
                .and_then(|mi| lookup_argument(app, token, mi, module_instances))
                .filter(|v| !v.is_empty())
            {
                out.push_str(&value);
            }
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);

    // Drop parentheticals emptied by a stripped token, then normalize.
    let cleaned = out.replace("()", " ");
    non_empty_label(&cleaned)
}

/// Resolves placeholders in a com-object `Text` when an application program is
/// available, else strips any `{{…}}` tokens and normalizes whitespace so a raw
/// placeholder never reaches the model. Returns `None` if nothing readable
/// remains (the caller then falls back to `Name`).
fn resolve_text(
    text: &str,
    app: Option<&ApplicationProgram>,
    module_instance_id: Option<&str>,
    module_instances: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    match app {
        Some(app) => resolve_placeholders(text, app, module_instance_id, module_instances),
        None => {
            // No program to resolve argument names against: strip every token.
            let empty = HashMap::new();
            let stub = ApplicationProgram::default();
            resolve_placeholders(text, &stub, module_instance_id, &empty)
        }
    }
}

/// Resolves an argument `Name` (e.g. `ArgBeschriftung`) to its value for a given
/// module instance, via the application program's name → id map.
fn lookup_argument(
    app: &ApplicationProgram,
    arg_name: &str,
    module_instance_id: &str,
    module_instances: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    let arg_id = app.argument_id(arg_name)?;
    module_instances
        .get(module_instance_id)
        .and_then(|args| args.get(arg_id))
        .cloned()
}

/// Collapses internal whitespace and trims ends, returning `None` when nothing
/// printable remains.
fn non_empty_label(s: &str) -> Option<String> {
    let joined = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// The app-relative channel id for a com-object channel ref, plus the owning
/// module-instance id. Mirrors [`normalize_ref`] for channel refs.
///
/// * `"MD-1_M-1_MI-1_CH-13"` → (`"MD-1_CH-13"`, `Some("MD-1_M-1_MI-1")`).
/// * `"CH-2"` (a non-module channel) → (`"CH-2"`, `None`).
fn normalize_channel_ref(channel_ref: &str) -> (String, Option<String>) {
    if channel_ref.starts_with("MD-")
        && let Some(md_end) = channel_ref.find("_M-")
    {
        let after = &channel_ref[md_end + 1..]; // "M-1_MI-1_CH-13"
        if let Some(mi_pos) = after.find("_MI-") {
            let rest = &after[mi_pos + "_MI-".len()..]; // "1_CH-13"
            if let Some(obj_pos) = rest.find('_') {
                let module_selector = &after[..mi_pos + "_MI-".len() + obj_pos]; // "M-1_MI-1"
                let channel_part = &rest[obj_pos + 1..]; // "CH-13"
                let module_def = &channel_ref[..md_end]; // "MD-1"
                let mi_id = format!("{module_def}_{module_selector}");
                let app_channel = format!("{module_def}_{channel_part}");
                return (app_channel, Some(mi_id));
            }
        }
    }
    (channel_ref.to_string(), None)
}

/// Resolves a human channel label for a com-object channel ref, if one distinct
/// from the raw ref can be derived from the manufacturer data.
///
/// Prefers the channel `Text` (with `{{Arg…}}` placeholders resolved from the
/// module instance and `{{N:…}}` tokens stripped) over the channel `Name`. When
/// no manufacturer channel definition matches, falls back to a cleaned generic
/// label built from the channel number (e.g. `CH-13` → `"Kanal 13"`) so a raw
/// ref is never surfaced as a label. Returns `None` only if even that is
/// impossible (an unparseable ref).
fn resolve_channel_label(
    channel_ref: &str,
    apps: &[&ApplicationProgram],
    module_instances: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    let (app_channel_id, mi_id) = normalize_channel_ref(channel_ref);

    for app in apps {
        if let Some(ch) = app.channel(&app_channel_id) {
            if let Some(text) = &ch.text
                && let Some(label) =
                    resolve_placeholders(text, app, mi_id.as_deref(), module_instances)
            {
                return Some(label);
            }
            if let Some(name) = ch.name.as_deref().and_then(non_empty_label) {
                return Some(name);
            }
        }
    }

    // Fallback: a clean generic label from the channel number.
    generic_channel_label(&app_channel_id)
}

/// Builds a generic `"Kanal N"` label from an app-relative channel id whose
/// trailing segment is `CH-<n>`; `None` if no channel number can be read.
fn generic_channel_label(app_channel_id: &str) -> Option<String> {
    let ch = app_channel_id.rsplit('_').next().unwrap_or(app_channel_id);
    let num = ch.strip_prefix("CH-")?;
    if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
        Some(format!("Kanal {num}"))
    } else {
        None
    }
}

/// Builds the model from a parsed project, reading manufacturer XML from the
/// container as devices require it.
pub fn build_model(project: RawProject, container: &mut Container) -> Result<Model> {
    // Manufacturer id -> name (best-effort; absent master is not fatal).
    let manufacturers = match container.knx_master_xml() {
        Ok(xml) => knx_master::parse_manufacturers(&xml)?,
        Err(_) => HashMap::new(),
    };

    // GA suffix (`GA-213`) -> its address, for resolving links.
    let mut ga_by_suffix: HashMap<String, GroupAddress> = HashMap::new();
    // The group addresses ETS runs with Data Secure (issue #156).
    let mut secure_gas: std::collections::HashSet<GroupAddress> = std::collections::HashSet::new();
    for ga in &project.group_addresses {
        ga_by_suffix.insert(ga.ref_suffix.clone(), ga.address);
        if ga.secure {
            secure_gas.insert(ga.address);
        }
    }

    // Cache of parsed application programs (by app id) and per-manufacturer
    // parsed `Hardware.xml` (by manufacturer id).
    let mut hw_cache: HashMap<String, Hardware> = HashMap::new();

    // Phase 1: resolve each device's ordered application-program ids (this also
    // fills `hw_cache`, which requires `&mut container`), remembering them so the
    // device loop below does not resolve them a second time.
    let mut app_ids_by_device: Vec<Vec<String>> = Vec::with_capacity(project.devices.len());
    for raw_dev in &project.devices {
        app_ids_by_device.push(app_ids_for(raw_dev, container, &mut hw_cache)?);
    }

    // The distinct referenced application-program ids, in first-seen order (kept
    // only for a stable serial read; the cache is a keyed lookup so emission
    // order downstream is independent of it).
    let app_cache = parse_applications(container, &project.devices, &app_ids_by_device)?;

    // Accumulate: links per device, com_objects per device, and (GA -> inferred
    // DPT) from linked com-objects for GAs lacking an explicit DPT.
    let mut links: BTreeMap<IndividualAddress, Vec<Link>> = BTreeMap::new();
    let mut devices: BTreeMap<IndividualAddress, LoadedDevice> = BTreeMap::new();
    let mut inferred_ga_dpt: HashMap<GroupAddress, Dpt> = HashMap::new();

    for (raw_dev, app_ids) in project.devices.iter().zip(&app_ids_by_device) {
        let apps: Vec<&ApplicationProgram> =
            app_ids.iter().filter_map(|id| app_cache.get(id)).collect();
        let primary_app = apps.first().copied();

        // Resolve each com-object instance against any of the device's apps.
        let mut resolved: Vec<ResolvedComObject> = Vec::new();
        for ci in &raw_dev.com_objects {
            if let Some(r) = resolve_com_object(ci, &apps, &raw_dev.module_instances) {
                resolved.push(r);
            }
        }

        // Build the device's link entries and record GA-DPT inference.
        let mut dev_links: Vec<Link> = Vec::new();
        let mut com_objects: BTreeMap<u16, ComObject> = BTreeMap::new();
        let mut channels: BTreeMap<String, Channel> = BTreeMap::new();

        for r in &resolved {
            // Map link suffixes to GAs.
            let mut gas: Vec<GroupAddress> = Vec::new();
            for suffix in &r.link_suffixes {
                if let Some(ga) = ga_by_suffix.get(suffix) {
                    gas.push(*ga);
                }
            }

            // Record com object. The size is derived from the DPT on demand, so
            // it is only stored when there is no DPT at all (issue #17); when
            // stored, its casing is normalized to the lowercase "1 bit" style.
            let size = match r.dpt {
                Some(_) => None,
                None => r.size.as_deref().map(normalize_size),
            };
            com_objects.insert(
                r.number,
                ComObject {
                    dpt: r.dpt,
                    size,
                    flags: r.flags,
                    reference: Some(r.reference.clone()),
                    channel: r.channel.clone(),
                    // `On` secures the object; `Auto` (also the meaning of an
                    // absent attribute) follows its linked group addresses.
                    // CONFIRMED (issue #156): the post-activation export carries
                    // no `Security` attribute on any ComObjectInstanceRef, yet
                    // ETS wrote flag 0x03 for group object 1289, the one linked
                    // to the keyed GA 0/3/47.
                    secure: match r.security {
                        Some(crate::project::SecuritySetting::On) => true,
                        Some(crate::project::SecuritySetting::Off) => false,
                        Some(crate::project::SecuritySetting::Auto) | None => {
                            gas.iter().any(|ga| secure_gas.contains(ga))
                        }
                    },
                    function: None,
                    key: None,
                    text: None,
                },
            );
            // Channel labels (issue #11): the com-object keeps its raw channel
            // *ref* as the key (it stays the stable cluster handle bussard-ha
            // groups by), and the `channels:` block carries the resolved human
            // label. The label comes from the manufacturer's `<Channel>` Text
            // (with `{{Arg…}}` placeholders resolved from the module instance and
            // `{{N:…}}` tokens stripped), falling back to a clean generic
            // "Kanal N". We only emit an entry when the label is distinct from
            // the key, so name==key noise is never surfaced.
            if let Some(ch) = &r.channel {
                let label = resolve_channel_label(ch, &apps, &raw_dev.module_instances);
                if let Some(label) = label.filter(|l| l != ch) {
                    channels.entry(ch.clone()).or_insert_with(|| Channel {
                        name: label,
                        key: None,
                        number: None,
                        text: None,
                    });
                }
            }

            // Infer DPTs for linked GAs that will end up without an explicit one.
            if let Some(dpt) = r.dpt {
                for ga in &gas {
                    inferred_ga_dpt.entry(*ga).or_insert(dpt);
                }
            }

            // Split into send + listen. ETS lists the sending GA first, but an
            // object only actually sends if it has the T (transmit) flag; a
            // listen-only object keeps all its GAs as `listen` (mirroring KNX
            // association semantics and keeping `send` consistent with the T
            // flag, per validation rule E007).
            if !gas.is_empty() {
                let (send, listen) = if r.flags.contains(Flags::TRANSMIT) {
                    (Some(gas[0]), gas[1..].to_vec())
                } else {
                    (None, gas.clone())
                };
                dev_links.push(Link {
                    object: r.number,
                    name: Some(r.name.clone()),
                    send,
                    listen,
                });
            }
        }

        if !dev_links.is_empty() {
            dev_links.sort_by_key(|l| l.object);
            links.insert(raw_dev.address, dev_links);
        }

        // Per-device parameter values (issue #46): resolve each configured
        // ParameterInstanceRef to its stable key + value, keeping the ones whose
        // value differs from the vendor default (display-only ones included).
        let parameters = resolve_parameters(raw_dev, &apps);

        // Per-module-instance memory base offsets (issue #48): resolve each of
        // the device's module instances' `BaseOffset` argument values so a module
        // parameter override can be placed at `declared_offset + instance_base`.
        let module_bases = resolve_module_bases(raw_dev, &apps);

        // Product identity (and the hardware name, used as a naming fallback).
        let (product, hardware_name) =
            build_product(raw_dev, primary_app, &manufacturers, &hw_cache);
        let name = device_name(raw_dev, hardware_name.as_deref());

        let location = project
            .locations
            .get(&raw_dev.id)
            .map(|l| Location {
                floor: l.floor.clone(),
                room: l.room.clone(),
            })
            .filter(|l| l.floor.is_some() || l.room.is_some());

        // KNX Secure status (issue #71, spec §11): flags + seqnum state ONLY.
        // No key material ever reaches the committed YAML model (spec §2.2).
        let secure_capable = primary_app.map(|a| a.is_secure_enabled).unwrap_or(false);
        let security = if secure_capable
            || raw_dev.has_device_certificate
            || raw_dev.secure_sequence_number.is_some()
            || raw_dev.has_tool_key
            || raw_dev.has_loaded_tool_key
        {
            Some(bussard_model::schema::DeviceSecurity {
                secure_capable,
                // CONFIRMED activation signal (issue #156, the export ETS made
                // after activating 1.1.12, `…_20260923_2.knxproj`): the device's
                // `<Security>` child gains `ToolKey` and `LoadedToolKey`. The
                // sequence number is no signal: every secure-capable device
                // carries one before activation too. `ToolKey` alone (1.1.10 in
                // the same export) is secure commissioning configured but not
                // yet downloaded.
                activated: raw_dev.has_loaded_tool_key,
                secure_commissioning: raw_dev.has_tool_key,
                has_fdsk_certificate: raw_dev.has_device_certificate,
                sequence_number: raw_dev.secure_sequence_number,
            })
        } else {
            None
        };

        let device = Device {
            address: raw_dev.address,
            name,
            description: raw_dev.description.clone(),
            location,
            // An ETS import knows nothing about bus history, so a freshly built
            // device carries no replacement date; the merge keeps ours (#98).
            replaced: None,
            product,
            channels,
            parameters,
            module_bases,
            com_objects,
            security,
            application_override: None,
            lock: Default::default(),
        };

        let file_stem = format!("{}-{}", raw_dev.address, slugify(&device.name));
        devices.insert(raw_dev.address, LoadedDevice { device, file_stem });
    }

    // Build the groups map, applying DPT inference for GAs without explicit DPT.
    let mut group_map: BTreeMap<GroupAddress, Group> = BTreeMap::new();
    for ga in &project.group_addresses {
        let dpt = ga.dpt.or_else(|| inferred_ga_dpt.get(&ga.address).copied());
        group_map.insert(
            ga.address,
            Group {
                name: ga.name.clone(),
                dpt,
                description: ga.description.clone(),
                secure: ga.secure,
                ..Default::default()
            },
        );
    }

    let mut ranges: BTreeMap<String, Range> = BTreeMap::new();
    for r in &project.ranges {
        ranges.insert(
            r.key.clone(),
            Range {
                name: r.name.clone(),
            },
        );
    }

    let groups = Groups {
        project: project.project_name.clone(),
        imported_from: None,
        ranges,
        groups: group_map,
    };

    Ok(Model {
        config: BussardConfig::default(),
        groups,
        links: Links { links },
        devices,
    })
}

/// Returns the ordered application-program ids for a device.
///
/// Resolution goes through the manufacturer's `Hardware.xml`: the device's
/// `Hardware2ProgramRefId` keys a `Hardware2Program` whose `ApplicationProgramRef`
/// list (first = primary) gives the app ids. When `Hardware.xml` is unavailable
/// we fall back to the `HP-…` → `A-…` shorthand, which is correct for
/// single-application devices.
/// Reads and parses every distinct referenced application-program XML.
///
/// The parse of these (up to ~28 MB) manufacturer files dominates import wall
/// time, so it is data-parallel: the raw entries are inflated *serially* from
/// the shared `ZipArchive` (inflate is a small fraction of the cost, and reading
/// serially sidesteps `&mut` aliasing on the archive), then the CPU-bound parses
/// run across a rayon pool into the returned cache.
///
/// Determinism: the returned map is a keyed lookup, so downstream emission order
/// is unchanged regardless of parse completion order. On a parse error the
/// lowest app-id error wins (results are sorted by id before the first error is
/// reported), so the surfaced failure is stable across runs and thread counts.
fn parse_applications(
    container: &mut Container,
    devices: &[RawDevice],
    app_ids_by_device: &[Vec<String>],
) -> Result<HashMap<String, ApplicationProgram>> {
    use rayon::prelude::*;

    // The distinct referenced app ids, each paired with a device address for
    // error context (any referencing device suffices; first-seen is stable).
    let mut raw: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen: HashMap<&str, ()> = HashMap::new();
    for (raw_dev, app_ids) in devices.iter().zip(app_ids_by_device) {
        for app_id in app_ids {
            if seen.insert(app_id.as_str(), ()).is_none() {
                // Serial read from the shared archive (inflate only).
                let bytes = container.application_raw(app_id, &raw_dev.address.to_string())?;
                raw.push((app_id.clone(), bytes));
            }
        }
    }

    // Parallel parse. Each result carries its app id so a failure can be
    // attributed deterministically (lowest id wins). The closure yields the
    // parser's own `EtsError` result; it converts to `ImportError` via `?` at
    // the unwrap below.
    let mut parsed: Vec<(String, bussard_ets::Result<ApplicationProgram>)> = raw
        .into_par_iter()
        .map(|(id, bytes)| {
            let app = parse_application_program(&id, &bytes);
            (id, app)
        })
        .collect();

    // First error wins deterministically: sort by app id, then surface the
    // first Err (if any) before assembling the cache.
    parsed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut cache: HashMap<String, ApplicationProgram> = HashMap::with_capacity(parsed.len());
    for (id, result) in parsed {
        cache.insert(id, result?);
    }
    Ok(cache)
}

fn app_ids_for(
    raw_dev: &RawDevice,
    container: &mut Container,
    hw_cache: &mut HashMap<String, Hardware>,
) -> Result<Vec<String>> {
    let h2p_ref = match raw_dev.hardware2program_ref_id.as_deref() {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let mfr = h2p_ref.split('_').next().unwrap_or(h2p_ref);
    if let Some(hw) = ensure_hardware(mfr, container, hw_cache)
        && let Some(ids) = hw.hardware2program.get(h2p_ref)
        && !ids.is_empty()
    {
        return Ok(ids.clone());
    }
    // Fallback: `<mfr>_H-…_HP-<rest>` → `<mfr>_A-<rest>`.
    Ok(fallback_app_id(h2p_ref).into_iter().collect())
}

/// The single-application shorthand: `<mfr>_H-…_HP-<rest>` → `<mfr>_A-<rest>`.
fn fallback_app_id(h2p_ref: &str) -> Option<String> {
    let mfr = h2p_ref.split('_').next()?;
    let hp_pos = h2p_ref.find("_HP-")?;
    let rest = &h2p_ref[hp_pos + "_HP-".len()..];
    Some(format!("{mfr}_A-{rest}"))
}

/// Resolves a com-object instance to its effective values, trying each of the
/// device's application programs in order until one resolves the ref.
///
/// Handles both plain refs (`O-0_R-1`) and module refs
/// (`MD-1_M-6_MI-1_O-2-1_R-37`). For a module ref, the object number is the sum
/// of the module com-object's declared `Number` and the value of the module
/// instance's base-number argument.
fn resolve_com_object(
    ci: &RawComObjectInstance,
    apps: &[&ApplicationProgram],
    module_instances: &HashMap<String, HashMap<String, String>>,
) -> Option<ResolvedComObject> {
    // The ref id relative to the application program, and (for module refs) the
    // owning module-instance id.
    let (app_ref_suffix, module_instance_id) = normalize_ref(&ci.ref_id);

    let (base, cor) = apps.iter().find_map(|app| app.resolve(&app_ref_suffix))?;

    // Effective object number. For a module com-object, add the module
    // instance's base-number argument value to the declared number.
    let number = match (&module_instance_id, &base.base_number_ref) {
        (Some(mi_id), Some(base_ref)) => {
            let arg_key = strip_app_prefix(base_ref);
            let base_value = module_instances
                .get(mi_id)
                .and_then(|args| args.get(arg_key))
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            (base_value + u32::from(base.number)) as u16
        }
        _ => base.number,
    };

    // Effective flags: base < ref < instance.
    let flags = base.flags.merge(cor.flags).merge(ci.flags).to_flags();

    // Effective size: instance > ref > base.
    let size = ci
        .object_size
        .clone()
        .or_else(|| cor.object_size.clone())
        .or_else(|| base.object_size.clone());

    // Effective DPT: instance > ref > base; if none is declared, fall back to
    // one derived from the object size (as ETS/xknxproject does), so every
    // com-object carries at least a main DPT.
    let dpt = ci.dpt.or(cor.dpt).or(base.dpt).or_else(|| {
        size.as_deref()
            .and_then(crate::dpt_map::dpt_from_object_size)
    });

    // Effective display name: prefer the ref/base Text (the human label ETS
    // shows), falling back to Name. Texts may carry `{{Arg…}}` / `{{N:…}}`
    // placeholders (issue #11); resolve them against the owning module instance
    // (using the first app that carries the argument definitions).
    let resolve_app = apps.first().copied();
    let name = cor
        .text
        .clone()
        .filter(|s| !s.is_empty())
        .and_then(|t| {
            resolve_text(
                &t,
                resolve_app,
                module_instance_id.as_deref(),
                module_instances,
            )
        })
        .or_else(|| {
            base.text.clone().filter(|s| !s.is_empty()).and_then(|t| {
                resolve_text(
                    &t,
                    resolve_app,
                    module_instance_id.as_deref(),
                    module_instances,
                )
            })
        })
        .or_else(|| cor.name.clone().filter(|s| !s.is_empty()))
        .or_else(|| base.name.clone().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| format!("Object {number}"));

    Some(ResolvedComObject {
        number,
        name,
        dpt,
        size,
        flags,
        channel: ci.channel.clone(),
        reference: ci.ref_id.clone(),
        link_suffixes: ci.links.clone(),
        security: ci.security,
    })
}

/// Resolves a device's configured `ParameterInstanceRef`s into the per-device
/// `parameters:` map (issue #46).
///
/// For each `(ref_id, value)` the ref is resolved against the device's
/// application programs to its `ParameterRef` → `Parameter`, which supplies the
/// vendor default (the resolved ref/parameter `Value`), the display name (for
/// the human key prefix) and the memory location. A value is emitted when it
/// **differs from the vendor default** (diff-friendly: only real deltas land in
/// the file). Every kind of parameter counts, because each one reaches the
/// download (issue #123):
///
/// * a **display-only** parameter (no `<Memory>`) decides, through the Dynamic
///   section's `<choose>`s, which modules, com-objects and parameters the device
///   carries (the Jung F50's button/rocker concept is one);
/// * a **`<Union>` member** has no memory of its own but is written at the
///   union's location;
/// * a parameter with **several refs whose defaults differ** is emitted even
///   when its value equals the default of the ref it was stored under: the value
///   belongs to the parameter, and which ref's default applies depends on which
///   ref the configuration shows, so leaving it out would let another ref's
///   default take over.
///
/// The key is `<name-slug>@<app-relative-ref-id>`, where the app-relative ref id
/// preserves the module-instance selector (`MD-2_M-20_MI-1_P-15_R-17`), the
/// unique+stable handle; the slug is a human aid. See the `parameters:` field
/// rustdoc on [`bussard_model::schema::Device`] for the full rationale.
fn resolve_parameters(
    raw_dev: &RawDevice,
    apps: &[&ApplicationProgram],
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (ref_id, value) in &raw_dev.parameters {
        // App-relative ref id, module-instance selector preserved (the key body).
        let Some(app_rel) = app_relative_param_ref(ref_id, apps) else {
            continue;
        };
        // The app-model ref id has the `_M-<m>_MI-<n>` selector removed; the
        // app model keys `parameter_refs` by the *full* (app-prefixed) id.
        let (model_ref_rel, _mi) = normalize_ref(&app_rel);

        // Resolve against whichever app defines the ref.
        let Some((app, resolved)) = apps.iter().find_map(|app| {
            let full = format!("{}_{model_ref_rel}", app.id);
            app.resolved_parameter(&full).map(|r| (*app, r))
        }) else {
            continue;
        };

        // Diff against the vendor default (ref Value override, else param
        // Value), unless the parameter's refs disagree on the default.
        let vendor_default = resolved.value().unwrap_or("");
        if value == vendor_default && !has_ambiguous_default(app, &resolved.param.id) {
            continue;
        }

        let name = resolved.param.name.as_deref().unwrap_or("");
        let key = format!("{}@{app_rel}", param_name_slug(name));
        // Determinism: an app-relative ref id is unique per device, so keys do
        // not collide; the first write wins if a malformed file repeats one.
        out.entry(key).or_insert_with(|| value.clone());
    }
    out
}

/// Whether the refs of parameter `param_id` (a full id) declare different
/// defaults (a ref's `Value`, else the parameter's own), so a value equal to one
/// of them is still a real setting.
fn has_ambiguous_default(app: &ApplicationProgram, param_id: &str) -> bool {
    let own = app
        .parameters
        .get(param_id)
        .and_then(|p| p.default.as_deref());
    let mut defaults = app
        .parameter_refs
        .values()
        .filter(|r| r.ref_id == param_id)
        .map(|r| r.value.as_deref().or(own));
    match defaults.next() {
        Some(first) => defaults.any(|d| d != first),
        None => false,
    }
}

/// Resolves a device's per-module-instance **memory base offsets** into the
/// generated `module_bases:` map (issue #48).
///
/// A module parameter's `<Memory>` carries a `BaseOffset` naming a module
/// `<Argument>` (e.g. `ParamOffsBase` → app-relative `MD-1_A-1`); each channel's
/// instance places its value at `declared Offset + instance_base`, where
/// `instance_base` is that argument's value for the channel. The per-instance
/// argument values live in the project's `ModuleInstance` data; this reads them
/// out and keys them by the module-instance selector (`MD-<d>_M-<m>_MI-<n>`) —
/// exactly the key `bussard-prod`'s `compute_parameter_image` looks up in its
/// `base_offsets`, and the key the parameter-key body reduces to once
/// `_P-<p>_R-<r>` is stripped.
///
/// For each module instance, the base-offset argument is determined from the
/// application program: the module def's parameters that carry a `BaseOffset` all
/// name the same per-module argument (verified in real data — every `MD-1`
/// parameter references `MD-1_A-1`), so the module-def → arg mapping is read once
/// per app. An instance whose argument value is absent or non-numeric is skipped
/// (nothing to place against), keeping the emitted map to real, resolvable bases.
fn resolve_module_bases(
    raw_dev: &RawDevice,
    apps: &[&ApplicationProgram],
) -> BTreeMap<String, u32> {
    // Module-def prefix (e.g. `MD-1`) -> app-relative base-offset argument id
    // (e.g. `MD-1_A-1`), read from each app's memory-bearing module parameters.
    let base_arg_by_module = base_offset_args(apps);

    let mut out = BTreeMap::new();
    for (mi_id, args) in &raw_dev.module_instances {
        // The module-def prefix of this instance (`MD-1_M-3_MI-1` -> `MD-1`).
        let Some(module_def) = mi_id.split_once("_M-").map(|(head, _)| head) else {
            continue;
        };
        let Some(arg_rel) = base_arg_by_module.get(module_def) else {
            // This module def defines no BaseOffset-bearing parameter (nothing to
            // place against an instance base), so no base is needed.
            continue;
        };
        // The instance's value for that argument -> the base byte offset.
        let Some(base) = args.get(arg_rel).and_then(|v| v.trim().parse::<u32>().ok()) else {
            continue;
        };
        out.insert(mi_id.clone(), base);
    }
    out
}

/// Builds the module-def → app-relative base-offset argument id map for a device's
/// application programs.
///
/// Scans every memory-bearing parameter carrying a `BaseOffset` and records, per
/// module def (`MD-<d>`), the app-relative argument id its `BaseOffset` names
/// (`<app>_MD-1_A-1` → `MD-1_A-1`). The first argument seen per module wins; in
/// real data a module def's parameters all reference a single base-offset argument
/// (`MD-1` → `MD-1_A-1`), matching the single-base-per-instance shape the flasher's
/// `base_offsets` map (keyed only by module-instance selector) can represent.
fn base_offset_args(apps: &[&ApplicationProgram]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for app in apps {
        for param in app.parameters.values() {
            let Some(base_ref) = param.memory.as_ref().and_then(|m| m.base_offset.as_deref())
            else {
                continue;
            };
            // App-relative argument id, e.g. `MD-1_A-1`.
            let arg_rel = strip_app_prefix(base_ref);
            let Some(module_def) = arg_rel.split_once("_A-").map(|(head, _)| head) else {
                continue;
            };
            out.entry(module_def.to_string())
                .or_insert_with(|| arg_rel.to_string());
        }
    }
    out
}

/// Strips the application-program prefix from a fully-qualified
/// `ParameterInstanceRef` `RefId`, returning the app-relative remainder (with
/// the module-instance selector preserved). Tries each of the device's apps so
/// the correct prefix is removed; falls back to the last `_A-…`-anchored split
/// when no app matches (defensive — should not happen for real data).
fn app_relative_param_ref(ref_id: &str, apps: &[&ApplicationProgram]) -> Option<String> {
    for app in apps {
        if let Some(rest) = ref_id
            .strip_prefix(app.id.as_str())
            .and_then(|r| r.strip_prefix('_'))
        {
            return Some(rest.to_string());
        }
    }
    None
}

/// A short, filesystem/diff-friendly slug of a parameter `Name` for the human
/// prefix of a parameter key. Lowercases, keeps ASCII alphanumerics, collapses
/// every other run to a single `-`, trims leading manufacturer prefixes like
/// `_va_`/`_re_`, and caps the length so keys stay scannable. Empty names slug
/// to `param`.
fn param_name_slug(name: &str) -> String {
    let base = crate::build::slugify(name);
    // Drop a leading manufacturer scope token (e.g. "va-", "re-", "ha-", "xja-")
    // left by names like `_VA_Verhalten…`; keep it only if nothing else remains.
    let trimmed = match base.split_once('-') {
        Some((head, rest)) if head.len() <= 4 && !rest.is_empty() => rest,
        _ => base.as_str(),
    };
    let capped: String = trimmed.chars().take(40).collect();
    let capped = capped.trim_matches('-').to_string();
    if capped.is_empty() {
        "param".to_string()
    } else {
        capped
    }
}

/// Normalizes a com-object instance `RefId` into the ref id relative to the
/// application program, plus the owning module-instance id for module refs.
///
/// * Plain ref `"O-0_R-1"` → (`"O-0_R-1"`, `None`).
/// * Module ref `"MD-1_M-6_MI-1_O-2-1_R-37"` →
///   (`"MD-1_O-2-1_R-37"`, `Some("MD-1_M-6_MI-1")`) — the `_M-<m>_MI-<mi>`
///   instance selector is removed from the app-relative ref.
fn normalize_ref(ref_id: &str) -> (String, Option<String>) {
    // Locate the `_M-<m>_MI-<mi>_` module-instance selector, if present.
    if let Some(md_end) = ref_id.find("_M-")
        && ref_id.starts_with("MD-")
    {
        // The selector runs from `_M-` up to the segment after `_MI-<n>`.
        let after = &ref_id[md_end + 1..]; // e.g. "M-6_MI-1_O-2-1_R-37"
        // Split off the object part after `MI-<n>_`.
        if let Some(mi_pos) = after.find("_MI-") {
            let rest = &after[mi_pos + "_MI-".len()..]; // "1_O-2-1_R-37"
            if let Some(obj_pos) = rest.find('_') {
                let module_selector = &after[..mi_pos + "_MI-".len() + obj_pos]; // "M-6_MI-1"
                let object_part = &rest[obj_pos + 1..]; // "O-2-1_R-37"
                let module_def = &ref_id[..md_end]; // "MD-1"
                let mi_id = format!("{module_def}_{module_selector}");
                let app_ref = format!("{module_def}_{object_part}");
                return (app_ref, Some(mi_id));
            }
        }
    }
    (ref_id.to_string(), None)
}

/// Strips the application-program prefix from an argument reference id,
/// returning the module-local part (e.g. `<app>_MD-1_A-2` → `MD-1_A-2`).
fn strip_app_prefix(base_ref: &str) -> &str {
    match base_ref.find("_MD-") {
        Some(pos) => &base_ref[pos + 1..],
        None => base_ref,
    }
}

/// Builds the [`Product`] identity for a device, returning it together with the
/// hardware name (used as a device-name fallback).
fn build_product(
    raw_dev: &RawDevice,
    app: Option<&ApplicationProgram>,
    manufacturers: &HashMap<String, String>,
    hw_cache: &HashMap<String, Hardware>,
) -> (Option<Product>, Option<String>) {
    let manufacturer_ref = raw_dev
        .product_ref_id
        .as_deref()
        .and_then(|p| p.split('_').next())
        .map(str::to_string);

    let manufacturer = manufacturer_ref
        .as_deref()
        .and_then(|id| manufacturers.get(id).cloned());

    let application_ref = app.map(|a| a.id.clone());
    let mask = app.and_then(|a| a.mask_version.clone());

    // Order number and hardware name from the already-parsed Hardware.xml.
    let mut order_number = None;
    let mut hardware_name = None;
    if let (Some(product_ref), Some(mfr)) = (
        raw_dev.product_ref_id.as_deref(),
        manufacturer_ref.as_deref(),
    ) && let Some(hw) = hw_cache.get(mfr)
        && let Some(info) = hw.products.get(product_ref)
    {
        order_number = info.order_number.clone();
        hardware_name = info.hardware_name.clone();
    }

    let product = Product {
        manufacturer,
        manufacturer_ref,
        order_number,
        hardware_ref: None,
        application_ref,
        mask,
    };

    let product = if product.manufacturer.is_none()
        && product.manufacturer_ref.is_none()
        && product.order_number.is_none()
        && product.application_ref.is_none()
        && product.mask.is_none()
    {
        None
    } else {
        Some(product)
    };
    (product, hardware_name)
}

/// Loads (and caches) a manufacturer's parsed `Hardware.xml`.
fn ensure_hardware<'a>(
    mfr: &str,
    container: &mut Container,
    cache: &'a mut HashMap<String, Hardware>,
) -> Option<&'a Hardware> {
    if !cache.contains_key(mfr) {
        let entry = format!("{mfr}/Hardware.xml");
        let parsed = container
            .raw_entry(&entry)
            .ok()
            .flatten()
            .and_then(|xml| crate::hardware::parse_hardware(&xml).ok())
            .unwrap_or_default();
        cache.insert(mfr.to_string(), parsed);
    }
    cache.get(mfr)
}

/// Determines the device display name: prefer the explicit `Name`, else the
/// hardware name, else the address.
fn device_name(raw_dev: &RawDevice, hardware_name: Option<&str>) -> String {
    if !raw_dev.name.is_empty() {
        raw_dev.name.clone()
    } else if let Some(hw) = hardware_name {
        hw.to_string()
    } else {
        raw_dev.address.to_string()
    }
}

/// Produces a filesystem-safe slug from a device name: lowercase, ASCII
/// alphanumerics and hyphens only, collapsing runs of other characters into a
/// single hyphen.
pub(crate) fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut last_hyphen = false;
    for ch in name.chars() {
        let mapped = match ch {
            'a'..='z' | '0'..='9' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            'ä' | 'Ä' => {
                out.push_str("ae");
                last_hyphen = false;
                continue;
            }
            'ö' | 'Ö' => {
                out.push_str("oe");
                last_hyphen = false;
                continue;
            }
            'ü' | 'Ü' => {
                out.push_str("ue");
                last_hyphen = false;
                continue;
            }
            'ß' => {
                out.push_str("ss");
                last_hyphen = false;
                continue;
            }
            _ => None,
        };
        match mapped {
            Some(c) => {
                out.push(c);
                last_hyphen = false;
            }
            None => {
                if !last_hyphen && !out.is_empty() {
                    out.push('-');
                    last_hyphen = true;
                }
            }
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "device".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_basic() {
        assert_eq!(slugify("Jalousieaktor Wohnen"), "jalousieaktor-wohnen");
        assert_eq!(slugify("Küche EG"), "kueche-eg");
        assert_eq!(slugify("A/B  C"), "a-b-c");
        assert_eq!(slugify("   "), "device");
        assert_eq!(slugify("Süd"), "sued");
    }

    #[test]
    fn fallback_app_id_derivation() {
        assert_eq!(
            fallback_app_id("M-0004_H-4.20.2F.2F.202116REG-1-O000A_HP-7066-11-7A9E-O000A")
                .as_deref(),
            Some("M-0004_A-7066-11-7A9E-O000A")
        );
    }

    #[test]
    fn normalize_plain_ref() {
        let (app_ref, mi) = normalize_ref("O-0_R-1");
        assert_eq!(app_ref, "O-0_R-1");
        assert_eq!(mi, None);
    }

    #[test]
    fn normalize_module_ref() {
        let (app_ref, mi) = normalize_ref("MD-1_M-6_MI-1_O-2-1_R-37");
        assert_eq!(app_ref, "MD-1_O-2-1_R-37");
        assert_eq!(mi.as_deref(), Some("MD-1_M-6_MI-1"));
    }

    #[test]
    fn normalize_channel_ref_module_and_plain() {
        let (app_ch, mi) = normalize_channel_ref("MD-1_M-1_MI-1_CH-13");
        assert_eq!(app_ch, "MD-1_CH-13");
        assert_eq!(mi.as_deref(), Some("MD-1_M-1_MI-1"));

        let (app_ch, mi) = normalize_channel_ref("CH-2");
        assert_eq!(app_ch, "CH-2");
        assert_eq!(mi, None);
    }

    #[test]
    fn generic_channel_label_from_number() {
        assert_eq!(
            generic_channel_label("MD-1_CH-13").as_deref(),
            Some("Kanal 13")
        );
        assert_eq!(generic_channel_label("CH-2").as_deref(), Some("Kanal 2"));
        assert_eq!(generic_channel_label("MD-1_X-1"), None);
    }

    /// Builds an [`ApplicationProgram`] with one module argument and one channel
    /// for the placeholder tests.
    fn app_with_channel() -> ApplicationProgram {
        use crate::manufacturer::ChannelDef;
        let mut app = ApplicationProgram {
            id: "M-0004_A-1".to_string(),
            ..Default::default()
        };
        app.argument_ids
            .insert("ArgBeschriftung".to_string(), "MD-1_A-3".to_string());
        app.argument_ids
            .insert("ArgBeschriftungRelais".to_string(), "MD-1_A-5".to_string());
        app.channels.insert(
            "MD-1_CH-13".to_string(),
            ChannelDef {
                name: Some("Relaisausgänge".to_string()),
                text: Some("{{ArgBeschriftungRelais}} {{ArgBeschriftung}} ({{0:...}})".to_string()),
            },
        );
        app
    }

    fn module_instances_fixture() -> HashMap<String, HashMap<String, String>> {
        let mut mi = HashMap::new();
        let mut args = HashMap::new();
        args.insert("MD-1_A-3".to_string(), "1/2".to_string());
        args.insert("MD-1_A-5".to_string(), "Relaisausgänge".to_string());
        mi.insert("MD-1_M-1_MI-1".to_string(), args);
        mi
    }

    #[test]
    fn resolves_channel_label_with_arguments() {
        let app = app_with_channel();
        let mis = module_instances_fixture();
        let label = resolve_channel_label("MD-1_M-1_MI-1_CH-13", &[&app], &mis);
        assert_eq!(label.as_deref(), Some("Relaisausgänge 1/2"));
    }

    #[test]
    fn resolves_com_object_text_strips_numbered_token() {
        let app = app_with_channel();
        let mis = module_instances_fixture();
        let out = resolve_text(
            "Venetian blind {{ArgBeschriftung}} ({{0:...}}) - Input",
            Some(&app),
            Some("MD-1_M-1_MI-1"),
            &mis,
        );
        assert_eq!(out.as_deref(), Some("Venetian blind 1/2 - Input"));
    }

    #[test]
    fn missing_argument_strips_placeholder_cleanly() {
        // No module instance value → the `{{ArgBeschriftung}}` token is dropped
        // and the `{{0:...}}` token stripped, leaving a clean label.
        let app = app_with_channel();
        let empty = HashMap::new();
        let out = resolve_text(
            "Venetian blind {{ArgBeschriftung}} ({{0:...}}) - Input",
            Some(&app),
            Some("MD-1_M-1_MI-1"),
            &empty,
        );
        assert_eq!(out.as_deref(), Some("Venetian blind - Input"));
    }

    #[test]
    fn channel_label_falls_back_to_generic_without_def() {
        let app = ApplicationProgram {
            id: "M-0004_A-1".to_string(),
            ..Default::default()
        };
        let empty = HashMap::new();
        let label = resolve_channel_label("MD-1_M-1_MI-1_CH-13", &[&app], &empty);
        assert_eq!(label.as_deref(), Some("Kanal 13"));
    }

    #[test]
    fn strip_app_prefix_from_base_ref() {
        assert_eq!(
            strip_app_prefix("M-0004_A-20D7-26-053C-O000A_MD-1_A-2"),
            "MD-1_A-2"
        );
        assert_eq!(strip_app_prefix("MD-1_A-2"), "MD-1_A-2");
    }

    // ---- issue #123: parameters that steer the Dynamic section ----------

    #[test]
    fn test_resolve_parameters_keeps_display_only_union_and_multi_ref_values()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/21">
         <ApplicationProgram Id="M-0004_A-1" Name="x"><Static>
          <ParameterTypes><ParameterType Id="M-0004_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters>
           <Parameter Id="M-0004_A-1_P-1" Name="concept" ParameterType="M-0004_A-1_PT-0" Value="0" />
           <Parameter Id="M-0004_A-1_P-2" Name="inst" ParameterType="M-0004_A-1_PT-0" Value="0">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="0" BitOffset="0" />
           </Parameter>
           <Union SizeInBit="8">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="1" BitOffset="0" />
            <Parameter Id="M-0004_A-1_UP-3" Name="led" ParameterType="M-0004_A-1_PT-0" Value="2" Offset="0" BitOffset="0" />
           </Union>
           <Parameter Id="M-0004_A-1_P-4" Name="plain" ParameterType="M-0004_A-1_PT-0" Value="5">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="2" BitOffset="0" />
           </Parameter>
          </Parameters>
          <ParameterRefs>
           <ParameterRef Id="M-0004_A-1_P-1_R-1" RefId="M-0004_A-1_P-1" />
           <ParameterRef Id="M-0004_A-1_P-2_R-2" RefId="M-0004_A-1_P-2" />
           <ParameterRef Id="M-0004_A-1_P-2_R-3" RefId="M-0004_A-1_P-2" Value="46" />
           <ParameterRef Id="M-0004_A-1_UP-3_R-4" RefId="M-0004_A-1_UP-3" />
           <ParameterRef Id="M-0004_A-1_P-4_R-5" RefId="M-0004_A-1_P-4" />
          </ParameterRefs>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0004_A-1", xml.as_bytes())?;
        let mut raw = raw_dev_with_module_instances(&[]);
        raw.parameters = [
            ("M-0004_A-1_P-1_R-1", "1"),  // display-only, changed
            ("M-0004_A-1_P-2_R-2", "0"),  // equals R-2's default, but R-3 says 46
            ("M-0004_A-1_UP-3_R-4", "4"), // union member, changed
            ("M-0004_A-1_P-4_R-5", "5"),  // single default, unchanged
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let params = resolve_parameters(&raw, &[&app]);
        let keys: Vec<&str> = params
            .keys()
            .filter_map(|k| k.split_once('@').map(|(_, r)| r))
            .collect();
        assert_eq!(keys, ["P-1_R-1", "P-2_R-2", "UP-3_R-4"]);
        Ok(())
    }

    // ---- issue #48: module-instance memory base offsets ------------------

    /// An app whose module `MD-1` has one parameter carrying a `BaseOffset`
    /// naming `MD-1_A-1`, plus a plain (non-module) parameter that must not
    /// contribute any base. Mirrors the Jung 23024 shape.
    fn app_with_base_offset() -> ApplicationProgram {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0004_A-1" Name="Jung"><Static>
          <ParameterTypes><ParameterType Id="M-0004_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters>
           <Parameter Id="M-0004_A-1_MD-1_P-3" Name="chanparam" ParameterType="M-0004_A-1_PT-0" Value="0">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="1" BitOffset="0" BaseOffset="M-0004_A-1_MD-1_A-1" />
           </Parameter>
           <Parameter Id="M-0004_A-1_P-9" Name="plain" ParameterType="M-0004_A-1_PT-0" Value="0">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="7" BitOffset="0" />
           </Parameter>
          </Parameters>
         </Static></ApplicationProgram></KNX>"#;
        parse_application_program("M-0004_A-1", xml.as_bytes()).unwrap()
    }

    fn raw_dev_with_module_instances(instances: &[(&str, &[(&str, &str)])]) -> RawDevice {
        let mut module_instances: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (mi_id, args) in instances {
            let map = args
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            module_instances.insert(mi_id.to_string(), map);
        }
        RawDevice {
            id: "P-1_DI-1".to_string(),
            address: "1.1.4".parse().unwrap(),
            name: "dev".to_string(),
            description: None,
            product_ref_id: None,
            hardware2program_ref_id: None,
            com_objects: Vec::new(),
            module_instances,
            parameters: Vec::new(),
            secure_sequence_number: None,
            has_device_certificate: false,
            has_tool_key: false,
            has_loaded_tool_key: false,
        }
    }

    #[test]
    fn base_offset_args_maps_module_to_its_argument() {
        let app = app_with_base_offset();
        let map = base_offset_args(&[&app]);
        assert_eq!(map.get("MD-1").map(String::as_str), Some("MD-1_A-1"));
        // The plain parameter contributes no module entry.
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn resolve_module_bases_reads_instance_values() {
        // Two channels of MD-1 with distinct ParamOffsBase (MD-1_A-1) values, and
        // an unrelated argument that must be ignored.
        let app = app_with_base_offset();
        let raw = raw_dev_with_module_instances(&[
            ("MD-1_M-1_MI-1", &[("MD-1_A-1", "805"), ("MD-1_A-6", "1")]),
            ("MD-1_M-3_MI-1", &[("MD-1_A-1", "1797"), ("MD-1_A-6", "3")]),
        ]);
        let bases = resolve_module_bases(&raw, &[&app]);
        assert_eq!(bases.get("MD-1_M-1_MI-1").copied(), Some(805));
        assert_eq!(bases.get("MD-1_M-3_MI-1").copied(), Some(1797));
        assert_eq!(bases.len(), 2);
    }

    #[test]
    fn resolve_module_bases_skips_absent_or_non_numeric() {
        let app = app_with_base_offset();
        let raw = raw_dev_with_module_instances(&[
            // Missing the base argument entirely -> skipped.
            ("MD-1_M-1_MI-1", &[("MD-1_A-6", "1")]),
            // Non-numeric base value -> skipped (never guessed).
            ("MD-1_M-2_MI-1", &[("MD-1_A-1", "n/a")]),
            // Good one -> kept.
            ("MD-1_M-3_MI-1", &[("MD-1_A-1", "1797")]),
        ]);
        let bases = resolve_module_bases(&raw, &[&app]);
        assert_eq!(bases.keys().collect::<Vec<_>>(), vec!["MD-1_M-3_MI-1"]);
    }

    #[test]
    fn resolve_module_bases_empty_without_base_offset_params() {
        // An app with no BaseOffset-bearing parameter yields no bases even when the
        // device has module instances.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0004_A-1" Name="x"><Static>
          <ParameterTypes><ParameterType Id="M-0004_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-0004_A-1_P-1" Name="p" ParameterType="M-0004_A-1_PT-0" Value="0"><Memory CodeSegment="M-0004_A-1_RS-1" Offset="0" BitOffset="0" /></Parameter></Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0004_A-1", xml.as_bytes()).unwrap();
        let raw = raw_dev_with_module_instances(&[("MD-1_M-1_MI-1", &[("MD-1_A-1", "805")])]);
        assert!(resolve_module_bases(&raw, &[&app]).is_empty());
    }

    #[test]
    fn resolve_module_bases_is_deterministic() {
        // Re-resolving the same inputs yields byte-identical maps (BTreeMap key
        // order is stable), so a re-import is idempotent.
        let app = app_with_base_offset();
        let raw = raw_dev_with_module_instances(&[
            ("MD-1_M-3_MI-1", &[("MD-1_A-1", "1797")]),
            ("MD-1_M-1_MI-1", &[("MD-1_A-1", "805")]),
            ("MD-1_M-2_MI-1", &[("MD-1_A-1", "1301")]),
        ]);
        let a = resolve_module_bases(&raw, &[&app]);
        let b = resolve_module_bases(&raw, &[&app]);
        assert_eq!(a, b);
        assert_eq!(
            a.keys().cloned().collect::<Vec<_>>(),
            vec!["MD-1_M-1_MI-1", "MD-1_M-2_MI-1", "MD-1_M-3_MI-1"]
        );
    }
}
