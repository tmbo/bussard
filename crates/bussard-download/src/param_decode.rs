//! Decoding a device's parameter memory back into parameter values (issues
//! #119, #142).
//!
//! The decoder is the exact inverse of the image builder in `bussard_prod`: it
//! walks the same list of placements the encoder writes
//! ([`bussard_prod::dynamic_parameter_slots`] for an application with a
//! Dynamic section, the vendor-default placement otherwise) and decodes each
//! value with [`bussard_prod::decode_parameter_value`], the inverse of the
//! encoder's own value encoding. So a value is read from exactly the byte, bit
//! offset, union member, module instance and ref the encoder wrote it for, and
//! a device holding the image the encoder built from a model decodes back to
//! that model with no difference.
//!
//! Three things follow from walking the encoder's placements rather than the
//! application's parameter list:
//!
//! - Only the refs the configuration shows are read. A parameter behind a
//!   `<choose>` branch that is not taken, a union member that is not shown, a
//!   ref of a parameter whose shown ref is another one: none of them holds a
//!   value of its own in the image, so none is decoded or reported.
//! - A hidden parameter the application downloads at its default (see
//!   [`bussard_prod::ApplicationProgram::downloads_invisible_parameters`]) is
//!   never reported as non-default: its bytes hold the default by construction.
//! - A value is compared as the octets it writes: the desired value is encoded
//!   and decoded back ([`bussard_prod::canonical_parameter_value`]), so DPT 9
//!   rounding, leading zeros or text padding never show up as a difference.
//!
//! Which refs are shown depends on the values the device holds, so the
//! device's own configuration is found by iteration: evaluate the Dynamic
//! section with the model's values, decode every shown ref, feed what differs
//! back in, and repeat until the shown set settles.

use std::collections::{BTreeMap, HashMap};

use bussard_prod::application::{ApplicationProgram, Parameter, ParameterType};
use bussard_prod::dynamic::{evaluate_dynamic, split_selector};

use crate::param_plan::{CurrentMemory, ParamChange, ParamReading, ParamValue};

/// How often the device's configuration is re-evaluated with the decoded
/// values before the decoder settles for what it has.
const MAX_PASSES: usize = 8;

/// A device's parameter memory, decoded (issue #142).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedParameters {
    /// The values the device holds, keyed like the model's `parameters:`
    /// block (app-relative `ParameterRef` id, module-instance selector where
    /// the ref belongs to a module). Starts from the model's values and
    /// replaces every value the memory answers for; a display-only parameter
    /// (no memory) keeps the model's value.
    pub values: BTreeMap<String, String>,
    /// The shown parameters whose value differs from the vendor default,
    /// sorted by key.
    pub non_default: Vec<ParamReading>,
    /// The shown parameters whose value differs from the model's, sorted by
    /// key: what a parameter download of the model would change.
    pub differences: Vec<ParamChange>,
    /// The shown parameters the application owns at runtime (`Access="None"`,
    /// e.g. a "download flag" ETS writes and the application resets after the
    /// restart), with the value the device holds. They are part of the image
    /// a download writes, but what the device holds says nothing about the
    /// model, so they carry no verdict: never in `non_default` or
    /// `differences`, and never fed into `values`.
    pub device_managed: Vec<ParamReading>,
    /// How many of the model's overrides could not be read back.
    pub unknown: usize,
}

/// Decodes `current` (the parameter segments read off a device, keyed by
/// code-segment id) against the model's `overrides` (keyed like
/// [`bussard_prod::compute_parameter_image`] takes them) and module-instance
/// `base_offsets`.
pub fn decode_parameters(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    current: &CurrentMemory,
) -> DecodedParameters {
    let keys = KeyForms::new(overrides);
    let placements = |values: &BTreeMap<String, String>| -> Vec<Placed<'_>> {
        if bussard_prod::uses_dynamic_image(app) {
            dynamic_placements(app, values, &keys)
        } else {
            static_placements(app, values, base_offsets)
        }
    };

    // The device's configuration: iterate until the decoded values settle.
    let mut values = overrides.clone();
    let mut device = placements(&values);
    for _ in 0..MAX_PASSES {
        let mut changed = false;
        for p in device.iter().filter(|p| p.reported(app)) {
            let Some(held) = p.decode(app, current) else {
                continue;
            };
            if p.desired.as_deref() != Some(held.as_str()) {
                values.insert(p.key.clone(), held);
                changed = true;
            }
        }
        if !changed {
            break;
        }
        device = placements(&values);
    }

    let mut non_default = Vec::new();
    let mut device_managed = Vec::new();
    for p in device.iter().filter(|p| p.user_value) {
        let Some(held) = p.decode(app, current) else {
            continue;
        };
        let managed = p.device_managed(app);
        if !managed && p.default.as_deref() == Some(held.as_str()) {
            continue;
        }
        let ptype = parameter_type(app, p.param);
        let list = if managed {
            &mut device_managed
        } else {
            &mut non_default
        };
        list.push(ParamReading {
            key: p.key.clone(),
            name: display_name(p.param),
            value: render(&held, ptype),
            default: p
                .default
                .as_deref()
                .map(|d| render(d, ptype))
                .unwrap_or_default(),
            unit: p.param.suffix_text.clone(),
        });
    }
    non_default.sort_by(|a, b| a.key.cmp(&b.key));
    device_managed.sort_by(|a, b| a.key.cmp(&b.key));
    device_managed.dedup_by(|a, b| a.key == b.key);

    let mut differences = Vec::new();
    let mut unknown = 0usize;
    for p in placements(overrides).iter().filter(|p| p.reported(app)) {
        let ptype = parameter_type(app, p.param);
        let Some(desired) = p.desired.as_deref() else {
            continue;
        };
        let old = match p.decode(app, current) {
            Some(held) if held == desired => continue,
            Some(held) => ParamValue::Known(render(&held, ptype)),
            // Unreadable: named only when the model asks for the value.
            None if overrides.contains_key(&p.key) => {
                unknown += 1;
                ParamValue::Unknown
            }
            None => continue,
        };
        differences.push(ParamChange {
            key: p.key.clone(),
            name: display_name(p.param),
            old,
            new: ParamValue::Known(render(desired, ptype)),
            unit: p.param.suffix_text.clone(),
        });
    }
    differences.sort_by(|a, b| a.key.cmp(&b.key));
    differences.dedup_by(|a, b| a.key == b.key);

    DecodedParameters {
        values,
        non_default,
        differences,
        device_managed,
        unknown,
    }
}

/// One value the encoder writes, with what the configuration wants there.
struct Placed<'a> {
    /// The device-file key of the ref.
    key: String,
    /// The parameter written.
    param: &'a Parameter,
    /// Where: segment, byte offset, bit offset.
    segment: &'a str,
    offset: usize,
    bit_offset: u8,
    /// Whether the value is the user's (a shown ref that no `<Assign>` sets).
    /// A hidden parameter written at its default, or an assigned target, is
    /// placed but never reported.
    user_value: bool,
    /// The value the configuration writes, canonical.
    desired: Option<String>,
    /// The vendor default of the ref, canonical.
    default: Option<String>,
    /// The bit ranges of the field (absolute bit positions in the segment)
    /// that a later placement overwrites. Those bits hold the later value, so
    /// they are read as the desired value's bits: only the rest is compared.
    shadowed: Vec<(usize, usize)>,
}

impl Placed<'_> {
    /// Whether the value is the user's and not the application's own
    /// (see [`DecodedParameters::device_managed`]).
    fn reported(&self, app: &ApplicationProgram) -> bool {
        self.user_value && !self.device_managed(app)
    }

    /// Whether the parameter is runtime-owned: its effective `Access` (the
    /// ref's, else the parameter's) is `None`.
    fn device_managed(&self, app: &ApplicationProgram) -> bool {
        let pref = app
            .parameter_refs
            .get(&format!("{}_{}", app.id, split_selector(&self.key).1));
        pref.and_then(|r| r.access.as_deref())
            .or(self.param.access.as_deref())
            .is_some_and(|a| a.trim().eq_ignore_ascii_case("none"))
    }

    /// The value the device holds here, `None` when the segment was not read
    /// or the field lies past what was.
    fn decode(&self, app: &ApplicationProgram, current: &CurrentMemory) -> Option<String> {
        let bytes = current.get(self.segment)?;
        if self.shadowed.is_empty() {
            return bussard_prod::decode_parameter_value(
                app,
                self.param,
                bytes,
                self.offset,
                self.bit_offset,
            );
        }
        // Read the overwritten bits as the desired value's own.
        let mut desired = bytes.clone();
        bussard_prod::write_parameter_value(
            app,
            self.param,
            self.desired.as_deref(),
            &mut desired,
            self.offset,
            self.bit_offset,
        )
        .ok()?;
        let mut held = bytes.clone();
        for &(start, end) in &self.shadowed {
            for pos in start..end {
                let (byte, mask) = (pos / 8, 0x80u8 >> (pos % 8));
                let (Some(h), Some(d)) = (held.get_mut(byte), desired.get(byte)) else {
                    return None;
                };
                *h = (*h & !mask) | (d & mask);
            }
        }
        bussard_prod::decode_parameter_value(app, self.param, &held, self.offset, self.bit_offset)
    }

    /// The bit range the value occupies, when its width is fixed by its type.
    fn bits(&self, app: &ApplicationProgram) -> (usize, usize) {
        let start = self.offset * 8 + usize::from(self.bit_offset);
        let width = bit_width(parameter_type(app, self.param)).unwrap_or(1);
        (start, start + width as usize)
    }
}

/// The device-file keys of a module ref: the model's own spelling where it
/// has one (its `_MI-<n>` instance number), else `_MI-1`.
struct KeyForms {
    known: HashMap<(String, String), String>,
}

impl KeyForms {
    fn new(overrides: &BTreeMap<String, String>) -> Self {
        let known = overrides
            .keys()
            .filter_map(|key| match split_selector(key) {
                (Some(instance), param_ref) => Some(((instance, param_ref), key.clone())),
                (None, _) => None,
            })
            .collect();
        KeyForms { known }
    }

    /// The key of `param_ref` (app-relative) in module instance `instance`
    /// (e.g. `MD-15_M-26`), or of an application ref when `instance` is `None`.
    fn key(&self, instance: Option<&str>, param_ref: &str) -> String {
        let Some(instance) = instance else {
            return param_ref.to_string();
        };
        if let Some(key) = self
            .known
            .get(&(instance.to_string(), param_ref.to_string()))
        {
            return key.clone();
        }
        let module_def = instance.split_once("_M-").map_or(instance, |(md, _)| md);
        let rest = param_ref
            .strip_prefix(&format!("{module_def}_"))
            .unwrap_or(param_ref);
        format!("{instance}_MI-1_{rest}")
    }
}

/// The placements of an application built through its Dynamic section: the
/// encoder's own slot list for the configuration `values` yield.
fn dynamic_placements<'a>(
    app: &'a ApplicationProgram,
    values: &BTreeMap<String, String>,
    keys: &KeyForms,
) -> Vec<Placed<'a>> {
    let config = evaluate_dynamic(app, values);
    let Ok(slots) = bussard_prod::dynamic_parameter_slots(app, &config) else {
        return Vec::new();
    };
    let placed = slots
        .into_iter()
        .map(|slot| {
            let canonical = |v: Option<String>| {
                bussard_prod::canonical_parameter_value(app, slot.parameter, v.as_deref())
            };
            let (key, user_value, desired, default) = match slot.param_ref_id.as_deref() {
                Some(ref_id) => (
                    keys.key(config.module_instance_id(slot.module), ref_id),
                    !config.is_assigned(slot.module, ref_id),
                    canonical(config.value(app, slot.module, ref_id)),
                    canonical(config.vendor_default(app, slot.module, ref_id)),
                ),
                None => {
                    let d = canonical(slot.parameter.default.clone());
                    (relative_id(app, &slot.parameter.id), false, d.clone(), d)
                }
            };
            Placed {
                key,
                param: slot.parameter,
                segment: slot.segment,
                offset: slot.offset,
                bit_offset: slot.bit_offset,
                user_value,
                desired,
                default,
                shadowed: Vec::new(),
            }
        })
        .collect();
    drop_shadowed(app, placed)
}

/// Marks the bits of each placement that a later one overwrites, and drops a
/// placement overwritten entirely: its bits no longer hold its value, so they
/// say nothing about it.
fn drop_shadowed<'a>(app: &ApplicationProgram, placed: Vec<Placed<'a>>) -> Vec<Placed<'a>> {
    // Walk from the last write back; `covered` holds the disjoint bit ranges
    // per segment (start -> end) written later than the placement at hand.
    let mut covered: HashMap<&str, BTreeMap<usize, usize>> = HashMap::new();
    let mut keep = vec![true; placed.len()];
    let mut shadows: Vec<Vec<(usize, usize)>> = vec![Vec::new(); placed.len()];
    for (i, p) in placed.iter().enumerate().rev() {
        let (start, end) = p.bits(app);
        let ranges = covered.entry(p.segment).or_default();
        let overlapping: Vec<(usize, usize)> = ranges
            .range(..end)
            .filter(|(_, e)| **e > start)
            .map(|(s, e)| (*s, *e))
            .collect();
        let pieces: Vec<(usize, usize)> = overlapping
            .iter()
            .map(|&(s, e)| (s.max(start), e.min(end)))
            .collect();
        let shadowed_bits: usize = pieces.iter().map(|(s, e)| e - s).sum();
        keep[i] = shadowed_bits < end - start;
        shadows[i] = pieces;
        // Merge the placement into the covered ranges.
        let (mut lo, mut hi) = (start, end);
        let touching: Vec<usize> = ranges
            .range(..=end)
            .filter(|(_, e)| **e >= start)
            .map(|(s, _)| *s)
            .collect();
        for s in touching {
            if let Some(e) = ranges.remove(&s) {
                lo = lo.min(s);
                hi = hi.max(e);
            }
        }
        ranges.insert(lo, hi);
    }
    placed
        .into_iter()
        .zip(keep.into_iter().zip(shadows))
        .filter_map(|(mut p, (k, shadowed))| {
            p.shadowed = shadowed;
            k.then_some(p)
        })
        .collect()
}

/// The placements of an application without a Dynamic section, in the order
/// [`bussard_prod::compute_parameter_image`] writes them: every parameter's
/// vendor default (module parameters once per module instance), the default
/// member of every union, then the overrides.
fn static_placements<'a>(
    app: &'a ApplicationProgram,
    values: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
) -> Vec<Placed<'a>> {
    let canonical =
        |param: &Parameter, v: Option<&str>| bussard_prod::canonical_parameter_value(app, param, v);
    // The first ref (by id) of each parameter, and its value: the vendor
    // default the encoder writes.
    let mut refs: Vec<_> = app.parameter_refs.values().collect();
    refs.sort_by(|a, b| a.id.cmp(&b.id));
    let mut first_ref: BTreeMap<&str, &str> = BTreeMap::new();
    let mut ref_value: BTreeMap<&str, &str> = BTreeMap::new();
    for r in &refs {
        first_ref.entry(r.ref_id.as_str()).or_insert(r.id.as_str());
        if let Some(v) = r.value.as_deref() {
            ref_value.entry(r.ref_id.as_str()).or_insert(v);
        }
    }
    let default_of = |param: &Parameter| -> Option<String> {
        ref_value
            .get(param.id.as_str())
            .map(|s| s.to_string())
            .or_else(|| param.default.clone())
    };
    let mut placed = Vec::new();

    let mut params: Vec<&Parameter> = app.parameters.values().collect();
    params.sort_by(|a, b| a.id.cmp(&b.id));
    for param in params {
        let Some(mem) = param.memory.as_ref() else {
            continue;
        };
        let (Some(segment), Some(offset)) = (mem.code_segment.as_deref(), mem.offset) else {
            continue;
        };
        // A module parameter's instances: only overrides place them (the
        // encoder's default expansion across instances carries no ref key).
        if mem.base_offset.is_some() {
            continue;
        }
        let key = relative_id(
            app,
            first_ref
                .get(param.id.as_str())
                .unwrap_or(&param.id.as_str()),
        );
        let default = canonical(param, default_of(param).as_deref());
        placed.push(Placed {
            key,
            param,
            segment,
            offset: offset as usize,
            bit_offset: mem.bit_offset.unwrap_or(0),
            user_value: true,
            desired: default.clone(),
            default,
            shadowed: Vec::new(),
        });
    }

    for union in &app.unions {
        let Some(mem) = union.memory.as_ref() else {
            continue;
        };
        let (Some(segment), Some(base)) = (mem.code_segment.as_deref(), mem.offset) else {
            continue;
        };
        let Some(member) = union
            .members
            .iter()
            .find(|m| m.is_default)
            .or_else(|| union.members.first())
        else {
            continue;
        };
        let Some(param) = app.parameters.get(&member.parameter) else {
            continue;
        };
        let key = relative_id(
            app,
            first_ref
                .get(param.id.as_str())
                .unwrap_or(&param.id.as_str()),
        );
        let bits =
            u32::from(mem.bit_offset.unwrap_or(0)) + u32::from(member.bit_offset.unwrap_or(0));
        let offset = base + member.offset.unwrap_or(0) + bits / 8;
        let default = canonical(param, default_of(param).as_deref());
        placed.push(Placed {
            key,
            param,
            segment,
            offset: offset as usize,
            bit_offset: (bits % 8) as u8,
            user_value: true,
            desired: default.clone(),
            default,
            shadowed: Vec::new(),
        });
    }

    for (key, value) in values {
        let Some((param, instance)) = resolve_key(app, key) else {
            continue;
        };
        let Some((segment, offset, bit_offset)) =
            static_location(app, param, instance.as_deref(), base_offsets)
        else {
            continue;
        };
        let pref = app
            .parameter_refs
            .get(&format!("{}_{}", app.id, split_selector(key).1));
        let default = pref
            .and_then(|r| r.value.clone())
            .or_else(|| default_of(param));
        placed.push(Placed {
            key: key.clone(),
            param,
            segment,
            offset,
            bit_offset,
            user_value: true,
            desired: canonical(param, Some(value)),
            default: canonical(param, default.as_deref()),
            shadowed: Vec::new(),
        });
    }
    drop_shadowed(app, placed)
}

/// Where the static encoder writes an override of `param`: its own memory, or
/// its union's plus the member offset, module base added.
fn static_location<'a>(
    app: &'a ApplicationProgram,
    param: &'a Parameter,
    instance: Option<&str>,
    base_offsets: &BTreeMap<String, u32>,
) -> Option<(&'a str, usize, u8)> {
    let (segment, offset, bit_offset, module_relative) = match param.memory.as_ref() {
        Some(mem) => (
            mem.code_segment.as_deref()?,
            mem.offset?,
            mem.bit_offset.unwrap_or(0),
            mem.base_offset.is_some(),
        ),
        None => {
            let (union, member) = app.unions.iter().find_map(|u| {
                u.members
                    .iter()
                    .find(|m| m.parameter == param.id)
                    .map(|m| (u, m))
            })?;
            let mem = union.memory.as_ref()?;
            let bits =
                u32::from(mem.bit_offset.unwrap_or(0)) + u32::from(member.bit_offset.unwrap_or(0));
            (
                mem.code_segment.as_deref()?,
                mem.offset? + member.offset.unwrap_or(0) + bits / 8,
                (bits % 8) as u8,
                mem.base_offset.is_some(),
            )
        }
    };
    let offset = if module_relative {
        offset.checked_add(*base_offsets.get(instance?)?)?
    } else {
        offset
    };
    Some((segment, offset as usize, bit_offset))
}

/// Resolves a device-file key to its parameter and, for a module ref, the
/// `MD-<d>_M-<m>_MI-<n>` selector the model's `module_bases` are keyed by.
pub(crate) fn resolve_key<'a>(
    app: &'a ApplicationProgram,
    key: &str,
) -> Option<(&'a Parameter, Option<String>)> {
    let (instance, param_ref) = split_selector(key);
    // The ref's parameter; for a key naming no declared ref, the parameter the
    // key spells (its `_R-<r>` suffix dropped), as the image builder does.
    let param = match app.parameter_refs.get(&format!("{}_{param_ref}", app.id)) {
        Some(pref) => app.parameters.get(&pref.ref_id)?,
        None => {
            let rel = param_ref.rsplit_once("_R-")?.0;
            app.parameters
                .get(&format!("{}_{rel}", app.id))
                .or_else(|| app.parameters.get(rel))?
        }
    };
    // The selector is the key up to the instance number.
    let selector = instance.and_then(|inst| {
        let rest = key.strip_prefix(&format!("{inst}_MI-"))?;
        let n = rest.split('_').next()?;
        Some(format!("{inst}_MI-{n}"))
    });
    Some((param, selector))
}

/// The width in bits of a value of `ptype`, `None` when it depends on the
/// value (raw data) or the type carries no memory.
fn bit_width(ptype: Option<&ParameterType>) -> Option<u32> {
    match ptype? {
        ParameterType::Int { size_bits, .. } => Some(size_bits.unwrap_or(8)),
        ParameterType::Enum { size_bits, .. } => Some(size_bits.unwrap_or(8)),
        ParameterType::Text { size_bits } => size_bits.filter(|b| *b > 0),
        ParameterType::Float { encoding, .. } => Some(
            match encoding
                .as_deref()
                .map(|e| e.trim().to_ascii_lowercase())
                .as_deref()
            {
                Some("ieee-754 single")
                | Some("ieee 754 single")
                | Some("dpt 14")
                | Some("dpt14") => 32,
                Some("ieee-754 double") | Some("ieee 754 double") => 64,
                _ => 16,
            },
        ),
        ParameterType::None => None,
        ParameterType::Other { kind, .. } if kind == "TypeRawData" => None,
        ParameterType::Other { size_bits, .. } => size_bits.filter(|b| *b > 0),
    }
}

/// The declared type of `param`.
pub(crate) fn parameter_type<'a>(
    app: &'a ApplicationProgram,
    param: &Parameter,
) -> Option<&'a ParameterType> {
    param
        .parameter_type
        .as_deref()
        .and_then(|id| app.parameter_types.get(id))
        .map(|decl| &decl.kind)
}

/// The human name for a parameter: its display `Text`, else its `Name`, else
/// its id.
pub(crate) fn display_name(param: &Parameter) -> String {
    param
        .text
        .clone()
        .filter(|t| !t.trim().is_empty())
        .or_else(|| param.name.clone().filter(|n| !n.trim().is_empty()))
        .unwrap_or_else(|| param.id.clone())
}

/// Strips the application prefix from a fully-qualified id.
pub(crate) fn relative_id(app: &ApplicationProgram, id: &str) -> String {
    id.strip_prefix(&format!("{}_", app.id))
        .unwrap_or(id)
        .to_string()
}

/// Renders a raw value for a human: an enumeration shows the vendor's own text
/// for the member, everything else shows the value as written.
pub(crate) fn render(raw: &str, ptype: Option<&ParameterType>) -> String {
    if let Some(ParameterType::Enum { values, .. }) = ptype
        && let Ok(n) = raw.trim().parse::<i64>()
        && let Some(member) = values.iter().find(|v| v.value == n)
        && !member.text.trim().is_empty()
    {
        return member.text.clone();
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::application::parse_application_program;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The synthetic application of `tests/fixtures/param-readback/app.xml`.
    fn app() -> Result<ApplicationProgram, Box<dyn std::error::Error>> {
        let xml = include_str!("../tests/fixtures/param-readback/app.xml");
        Ok(parse_application_program("A", xml.as_bytes())?)
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// What a device holds after a download of `values`: the encoder's image.
    fn device(
        app: &ApplicationProgram,
        values: &BTreeMap<String, String>,
    ) -> Result<CurrentMemory, Box<dyn std::error::Error>> {
        Ok(bussard_prod::compute_parameter_image(
            app,
            values,
            &BTreeMap::new(),
        )?)
    }

    fn keys(readings: &[ParamReading]) -> Vec<&str> {
        readings.iter().map(|r| r.key.as_str()).collect()
    }

    #[test]
    fn test_decode_parameters_round_trips_every_placement() -> TestResult {
        let app = app()?;
        // Concept 1 shows the union's `level` member and `hidden`; instance
        // M-2 shows App-ID ref R-5 (its intcomm is 0 + argument 4).
        let model = map(&[
            ("P-1_R-1", "1"),
            ("P-10_R-10", "12"),
            ("UP-4_R-4", "9"),
            ("P-2_R-2", "5"),
            ("P-7_R-7", "1"),
            ("P-5_R-5", "17.5"),
            ("P-6_R-6", "90"),
            ("MD-1_M-2_MI-1_P-2_R-5", "70"),
            ("MD-1_M-1_MI-1_P-3_R-6", "8"),
        ]);
        let current = device(&app, &model)?;
        assert_eq!(
            current["A_RS-1"],
            [
                12, 9, 5, 0x10, 66, 8, 70, 5, 0x06, 0xD6, 30, 1, 0, 1, 0xAA, 0
            ]
        );
        let decoded = decode_parameters(&app, &model, &BTreeMap::new(), &current);
        assert!(decoded.differences.is_empty(), "{:?}", decoded.differences);
        // Every value but the display-only concept, which has no memory.
        assert_eq!(
            keys(&decoded.non_default),
            [
                "MD-1_M-1_MI-1_P-3_R-6",
                "MD-1_M-2_MI-1_P-2_R-5",
                "P-10_R-10",
                "P-2_R-2",
                "P-5_R-5",
                "P-6_R-6",
                "P-7_R-7",
                "UP-4_R-4",
            ]
        );
        let setpoint = decoded
            .non_default
            .iter()
            .find(|r| r.key == "P-5_R-5")
            .ok_or("no setpoint")?;
        assert_eq!(setpoint.line(), "Setpoint: 17.5 °C (default 21 °C)");
        let flag = decoded
            .non_default
            .iter()
            .find(|r| r.key == "P-7_R-7")
            .ok_or("no flag")?;
        assert_eq!(flag.line(), "Flag: Yes (default No)");
        // The decoded values are the model's.
        for (key, value) in &model {
            assert_eq!(decoded.values.get(key), Some(value), "{key}");
        }
        Ok(())
    }

    #[test]
    fn test_decode_parameters_skips_hidden_and_unshown_refs() -> TestResult {
        let app = app()?;
        // Concept 0: `hidden` is written at its default 7 whatever the model
        // says, the union holds `mode`, and instance M-1's App-ID is its
        // default 66 through ref R-4 (R-5's default 68 is not what is there).
        let model = map(&[("P-1_R-1", "0"), ("P-2_R-2", "5"), ("UP-3_R-3", "2")]);
        let current = device(&app, &model)?;
        assert_eq!(current["A_RS-1"][..3], [10, 0x20, 7]);
        let decoded = decode_parameters(&app, &model, &BTreeMap::new(), &current);
        assert!(decoded.differences.is_empty(), "{:?}", decoded.differences);
        assert_eq!(keys(&decoded.non_default), ["UP-3_R-3"]);
        assert_eq!(decoded.non_default[0].line(), "Mode: On (default Auto)");

        // A factory image of the same configuration holds only defaults.
        let defaults = device(&app, &BTreeMap::new())?;
        let decoded = decode_parameters(&app, &BTreeMap::new(), &BTreeMap::new(), &defaults);
        assert!(decoded.non_default.is_empty(), "{:?}", decoded.non_default);
        assert!(decoded.differences.is_empty());
        Ok(())
    }

    #[test]
    fn test_decode_parameters_reports_drift_per_ref() -> TestResult {
        let app = app()?;
        let model = map(&[("P-1_R-1", "1"), ("P-5_R-5", "17.5")]);
        let mut current = device(&app, &model)?;
        let segment = current.get_mut("A_RS-1").ok_or("no segment")?;
        segment[8..10].copy_from_slice(&[0x07, 0x08]); // 18 °C
        segment[10..13].copy_from_slice(&[0, 2, 0]); // 120 s
        segment[7] = 9; // instance M-2's debounce
        let decoded = decode_parameters(&app, &model, &BTreeMap::new(), &current);
        let lines: Vec<String> = decoded.differences.iter().map(ParamChange::line).collect();
        assert_eq!(
            lines,
            [
                "Debounce: 9 to 5",
                "Setpoint: 18 °C to 17.5 °C",
                "Switch-off delay: 120 s to 300 s",
            ]
        );
        assert_eq!(decoded.differences[0].key, "MD-1_M-2_MI-1_P-3_R-6");
        assert_eq!(
            decoded
                .values
                .get("MD-1_M-2_MI-1_P-3_R-6")
                .map(String::as_str),
            Some("9")
        );
        Ok(())
    }

    #[test]
    fn test_decode_parameters_reports_access_none_without_verdict() -> TestResult {
        let app = app()?;
        let model = map(&[("P-1_R-1", "1"), ("P-10_R-10", "12")]);
        let mut current = device(&app, &model)?;
        // The download writes the flag's 1; the application resets it.
        let segment = current.get_mut("A_RS-1").ok_or("no segment")?;
        assert_eq!(segment[13], 1);
        segment[13] = 0;
        let decoded = decode_parameters(&app, &model, &BTreeMap::new(), &current);
        assert!(decoded.differences.is_empty(), "{:?}", decoded.differences);
        assert_eq!(keys(&decoded.non_default), ["P-10_R-10"]);
        assert_eq!(keys(&decoded.device_managed), ["P-8_R-8"]);
        assert_eq!(decoded.device_managed[0].value, "0");
        // The device's reset value is not taken for a user value.
        assert!(!decoded.values.contains_key("P-8_R-8"));
        Ok(())
    }

    #[test]
    fn test_decode_parameters_compares_dpt9_as_written() -> TestResult {
        let app = app()?;
        // 999.7 is written as 999.68 (mantissa 1562, exponent 6): the device
        // holding that image matches the model.
        let model = map(&[("P-5_R-5", "999.7")]);
        let current = device(&app, &model)?;
        assert_eq!(current["A_RS-1"][8..10], [0x36, 0x1A]);
        let decoded = decode_parameters(&app, &model, &BTreeMap::new(), &current);
        assert!(decoded.differences.is_empty(), "{:?}", decoded.differences);
        assert_eq!(decoded.non_default[0].value, "999.68");
        Ok(())
    }
}
