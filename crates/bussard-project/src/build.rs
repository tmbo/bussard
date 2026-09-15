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
use crate::manufacturer::{parse_application_program, ApplicationProgram};
use crate::project::{RawComObjectInstance, RawDevice, RawProject};

/// A fully-resolved com object on a device.
struct ResolvedComObject {
    number: u16,
    name: String,
    dpt: Option<Dpt>,
    size: Option<String>,
    flags: Flags,
    channel: Option<String>,
    reference: String,
    /// GA references (suffixes) in link order; first is the sending GA.
    link_suffixes: Vec<String>,
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
    for ga in &project.group_addresses {
        ga_by_suffix.insert(ga.ref_suffix.clone(), ga.address);
    }

    // Cache of parsed application programs (by app id) and per-manufacturer
    // parsed `Hardware.xml` (by manufacturer id).
    let mut app_cache: HashMap<String, ApplicationProgram> = HashMap::new();
    let mut hw_cache: HashMap<String, Hardware> = HashMap::new();

    // Accumulate: links per device, com_objects per device, and (GA -> inferred
    // DPT) from linked com-objects for GAs lacking an explicit DPT.
    let mut links: BTreeMap<IndividualAddress, Vec<Link>> = BTreeMap::new();
    let mut devices: BTreeMap<IndividualAddress, LoadedDevice> = BTreeMap::new();
    let mut inferred_ga_dpt: HashMap<GroupAddress, Dpt> = HashMap::new();

    for raw_dev in &project.devices {
        // The ordered application-program ids for this device (usually one; a
        // multi-application device lists several, the first being primary).
        let app_ids = app_ids_for(raw_dev, container, &mut hw_cache)?;
        for app_id in &app_ids {
            if !app_cache.contains_key(app_id) {
                let xml = container.application_xml(app_id, &raw_dev.address.to_string())?;
                let app = parse_application_program(app_id, &xml)?;
                app_cache.insert(app_id.clone(), app);
            }
        }
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

            // Record com object.
            com_objects.insert(
                r.number,
                ComObject {
                    name: r.name.clone(),
                    dpt: r.dpt,
                    size: r.size.clone(),
                    flags: r.flags,
                    reference: Some(r.reference.clone()),
                    channel: r.channel.clone(),
                },
            );
            if let Some(ch) = &r.channel {
                channels
                    .entry(ch.clone())
                    .or_insert_with(|| Channel { name: ch.clone() });
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

        let device = Device {
            address: raw_dev.address,
            name,
            description: raw_dev.description.clone(),
            location,
            product,
            channels,
            com_objects,
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
    if let Some(hw) = ensure_hardware(mfr, container, hw_cache) {
        if let Some(ids) = hw.hardware2program.get(h2p_ref) {
            if !ids.is_empty() {
                return Ok(ids.clone());
            }
        }
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
    // shows), falling back to Name.
    let name = cor
        .text
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| base.text.clone().filter(|s| !s.is_empty()))
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
    })
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
    if let Some(md_end) = ref_id.find("_M-") {
        if ref_id.starts_with("MD-") {
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
    ) {
        if let Some(hw) = hw_cache.get(mfr) {
            if let Some(info) = hw.products.get(product_ref) {
                order_number = info.order_number.clone();
                hardware_name = info.hardware_name.clone();
            }
        }
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
    fn strip_app_prefix_from_base_ref() {
        assert_eq!(
            strip_app_prefix("M-0004_A-20D7-26-053C-O000A_MD-1_A-2"),
            "MD-1_A-2"
        );
        assert_eq!(strip_app_prefix("MD-1_A-2"), "MD-1_A-2");
    }
}
