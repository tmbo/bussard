//! The parameter-level flash plan (issue #109).
//!
//! `bussard flash` used to show only the memory-level plan: byte counts, load
//! steps, segment offsets. An owner changing a night setback wants to read
//! "night setback: 18 to 17 °C", not an offset. This module produces that line.
//!
//! It is a **pure** diff between two things bussard already has:
//!
//! * the **desired** value of every parameter, from the device file's
//!   `parameters:` block resolved through the application program (the same
//!   override chain [`bussard_prod::compute_parameter_image`] encodes), and
//! * the **current** value, decoded out of the bytes the device holds today.
//!
//! The current bytes are read back by the caller, per code segment, and passed
//! in. When they are absent — a factory-fresh device has no segment to read, and
//! an unreadable one must not be guessed at — the parameter is reported with an
//! unknown current value rather than silently compared against the vendor
//! default.
//!
//! Decoding reuses the product data's own parameter type tables
//! ([`ParameterType`]): there is no second parser here, only the inverse of the
//! placement [`bussard_prod`] performs (MSB-first bit fields, big-endian
//! integers, the three declared float encodings).
//!
//! # System 7
//!
//! System 7 (mask 0705/0701) places parameters in absolute memory regions rather
//! than allocated relative segments, and its flash writes whole regions. The
//! plan therefore carries a [`ParamPlan::note`] saying the memory-level plan is
//! the authoritative one there, and lists the desired values without a current
//! value to compare against.

use std::collections::{BTreeMap, BTreeSet};

use bussard_mgmt::load::read_table_reference;
use bussard_mgmt::memory::read_memory_range;
use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_prod::application::{ApplicationProgram, Parameter, ParameterType};

use crate::flash::{FlashPlan, FlashStep, ImageKind};

/// Interface-object type 3: the application-program object.
const OT_APPLICATION_PROGRAM: u16 = 3;

/// A parameter value as the plan shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    /// A value, already rendered for a human (an enumeration shows its text).
    Known(String),
    /// The value could not be read back from the device.
    Unknown,
}

impl std::fmt::Display for ParamValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamValue::Known(v) => write!(f, "{v}"),
            ParamValue::Unknown => write!(f, "unknown current value"),
        }
    }
}

/// One parameter the flash would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamChange {
    /// The app-relative `ParameterRef` id that identifies the parameter (the
    /// part after `@` in a device-file parameter key).
    pub key: String,
    /// The human name: the parameter's `Text` from the `.knxprod`, falling back
    /// to its `Name` and then its id.
    pub name: String,
    /// What the device holds now.
    pub old: ParamValue,
    /// What the flash would write.
    pub new: ParamValue,
    /// The unit the vendor shows after the value (`SuffixText`), when declared.
    pub unit: Option<String>,
}

impl ParamChange {
    /// The one-line rendering used by the CLI pre-flight and the `--json`
    /// fallback text: `night setback: 18 to 17 °C`.
    pub fn line(&self) -> String {
        let unit = match &self.unit {
            Some(u) if !u.is_empty() => format!(" {u}"),
            _ => String::new(),
        };
        match (&self.old, &self.new) {
            (ParamValue::Unknown, new) => {
                format!("{}: unknown current value, will be {new}{unit}", self.name)
            }
            (old, new) => format!("{}: {old}{unit} to {new}{unit}", self.name),
        }
    }
}

/// The parameter-level plan: what the flash changes, in the vendor's own words.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParamPlan {
    /// The changes, sorted by parameter key so two runs agree.
    pub changes: Vec<ParamChange>,
    /// How many parameters the plan could not read back from the device.
    pub unknown: usize,
    /// A note explaining a degraded plan (System 7, or no readback at all).
    pub note: Option<String>,
}

impl ParamPlan {
    /// Whether the plan changes no parameter.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// The current bytes of each code segment, as read back from the device, keyed
/// by code-segment id. An empty map means nothing could be read.
pub type CurrentMemory = BTreeMap<String, Vec<u8>>;

/// Builds the parameter-level plan.
///
/// `overrides` is the device file's `parameters:` block re-keyed to bare
/// app-relative `ParameterRef` ids (exactly what [`crate::plan_flash`] takes),
/// `base_offsets` the per-module-instance memory bases, and `current` the bytes
/// read back from the device per code segment.
///
/// A parameter is listed when the value the flash would write differs from the
/// value the device holds. A parameter the caller overrode is listed even when
/// the current value is unreadable, because the operator asked for that change
/// and needs to see it named; a parameter left at its vendor default with an
/// unreadable current value is not listed, because nothing is known about it.
pub fn param_plan(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    current: &CurrentMemory,
) -> ParamPlan {
    let mut changes = Vec::new();
    let mut unknown = 0usize;
    let mut overridden_params: BTreeSet<String> = BTreeSet::new();

    // 1. Every explicit override, in key order.
    for (ref_id, desired_raw) in overrides {
        let Some((param, module_instance)) = resolve(app, ref_id) else {
            continue;
        };
        overridden_params.insert(param.id.clone());
        let Some(location) = location(param, module_instance.as_deref(), base_offsets) else {
            continue;
        };
        let ptype = parameter_type(app, param);
        let old_raw = decode(current, &location, ptype);
        if old_raw.as_deref() == Some(desired_raw.trim()) {
            continue;
        }
        if old_raw.is_none() {
            unknown += 1;
        }
        changes.push(ParamChange {
            key: ref_id.clone(),
            name: display_name(param),
            old: match &old_raw {
                Some(raw) => ParamValue::Known(render(raw, ptype)),
                None => ParamValue::Unknown,
            },
            new: ParamValue::Known(render(desired_raw.trim(), ptype)),
            unit: param.suffix_text.clone(),
        });
    }

    // 2. Every other memory-bearing parameter whose current value is readable and
    //    differs from the vendor default the flash would restore. These are the
    //    changes the operator did not ask for but the flash performs anyway
    //    (a device configured by ETS being brought back to the model's truth).
    if !current.is_empty() {
        let mut params: Vec<&Parameter> = app.parameters.values().collect();
        params.sort_by(|a, b| a.id.cmp(&b.id));
        for param in params {
            if overridden_params.contains(&param.id) {
                continue;
            }
            // A module parameter has one instance per channel and no single
            // location; its values are only ever reported through an explicit
            // override key, which names the instance.
            if param
                .memory
                .as_ref()
                .is_some_and(|m| m.base_offset.is_some())
            {
                continue;
            }
            let Some(location) = location(param, None, base_offsets) else {
                continue;
            };
            let ptype = parameter_type(app, param);
            let Some(old_raw) = decode(current, &location, ptype) else {
                continue;
            };
            let desired_raw = default_value(app, param).unwrap_or_else(|| "0".to_string());
            if old_raw == desired_raw.trim() {
                continue;
            }
            changes.push(ParamChange {
                key: relative_id(app, &param.id),
                name: display_name(param),
                old: ParamValue::Known(render(&old_raw, ptype)),
                new: ParamValue::Known(render(desired_raw.trim(), ptype)),
                unit: param.suffix_text.clone(),
            });
        }
    }

    changes.sort_by(|a, b| a.key.cmp(&b.key));
    let note = if current.is_empty() && !changes.is_empty() {
        Some(
            "the device's current parameter memory could not be read, so every value \
             below is shown as an unknown current value"
                .to_string(),
        )
    } else {
        None
    };
    ParamPlan {
        changes,
        unknown,
        note,
    }
}

/// The note a System 7 flash prints instead of a parameter diff.
///
/// System 7 writes whole absolute memory regions rather than a parameter image
/// over an allocated segment, so the memory-level plan is what actually
/// describes the download there.
pub const SYS7_NOTE: &str = "System 7 device: parameters are written as whole absolute memory regions, so \
     the memory-level plan below is the authoritative one";

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Where a parameter's value sits in a code segment.
struct Location {
    segment: String,
    offset: usize,
    bit_offset: u8,
}

/// Resolves an app-relative `ParameterRef` id to its `Parameter` and, for a
/// module parameter, the `MD-<d>_M-<m>_MI-<n>` instance selector.
///
/// Mirrors `bussard_prod`'s own override-key resolution; it is reimplemented
/// here (a dozen lines) rather than exposed, so the image builder's contract
/// stays private to the encoder.
fn resolve<'a>(
    app: &'a ApplicationProgram,
    ref_id: &str,
) -> Option<(&'a Parameter, Option<String>)> {
    let param_ref = ref_id.rsplit_once("_R-").map(|(head, _)| head)?;
    let (param_rel, module_instance) = split_module_instance(param_ref);
    let full = format!("{}_{param_rel}", app.id);
    let param = app
        .parameters
        .get(&full)
        .or_else(|| app.parameters.get(param_rel.as_str()))?;
    Some((param, module_instance))
}

/// Splits an app-relative parameter ref into `(param_rel, module_instance)`.
fn split_module_instance(param_ref: &str) -> (String, Option<String>) {
    if !param_ref.starts_with("MD-") {
        return (param_ref.to_string(), None);
    }
    let Some(m_pos) = param_ref.find("_M-") else {
        return (param_ref.to_string(), None);
    };
    let module_def = &param_ref[..m_pos];
    let after = &param_ref[m_pos + 1..];
    let Some(mi_pos) = after.find("_MI-") else {
        return (param_ref.to_string(), None);
    };
    let rest = &after[mi_pos + "_MI-".len()..];
    let Some(obj_pos) = rest.find('_') else {
        return (param_ref.to_string(), None);
    };
    let selector = format!("{module_def}_{}", &after[..mi_pos + "_MI-".len() + obj_pos]);
    (
        format!("{module_def}_{}", &rest[obj_pos + 1..]),
        Some(selector),
    )
}

/// The parameter's effective location, applying the per-instance base offset a
/// module parameter needs. `None` when the parameter carries no placeable
/// memory (a display-only parameter, or a module instance with no known base).
fn location(
    param: &Parameter,
    module_instance: Option<&str>,
    base_offsets: &BTreeMap<String, u32>,
) -> Option<Location> {
    let mem = param.memory.as_ref()?;
    let segment = mem.code_segment.clone()?;
    let declared = mem.offset?;
    let offset = if mem.base_offset.is_some() {
        let base = base_offsets.get(module_instance?)?;
        declared.checked_add(*base)?
    } else {
        declared
    };
    Some(Location {
        segment,
        offset: usize::try_from(offset).ok()?,
        bit_offset: mem.bit_offset.unwrap_or(0),
    })
}

fn parameter_type<'a>(app: &'a ApplicationProgram, param: &Parameter) -> Option<&'a ParameterType> {
    param
        .parameter_type
        .as_deref()
        .and_then(|id| app.parameter_types.get(id))
        .map(|decl| &decl.kind)
}

/// The vendor default for a parameter: the first `ParameterRef` value pointing
/// at it (refs are the per-channel instances), else the parameter's own `Value`.
/// Mirrors steps 1-3 of the image builder's override chain.
fn default_value(app: &ApplicationProgram, param: &Parameter) -> Option<String> {
    let mut refs: Vec<_> = app
        .parameter_refs
        .values()
        .filter(|r| r.ref_id == param.id)
        .collect();
    refs.sort_by(|a, b| a.id.cmp(&b.id));
    refs.iter()
        .find_map(|r| r.value.clone())
        .or_else(|| param.default.clone())
}

/// The human name for a parameter: its display `Text`, else its `Name`, else its
/// app-relative id.
fn display_name(param: &Parameter) -> String {
    param
        .text
        .clone()
        .filter(|t| !t.trim().is_empty())
        .or_else(|| param.name.clone().filter(|n| !n.trim().is_empty()))
        .unwrap_or_else(|| param.id.clone())
}

/// Strips the application prefix from a fully-qualified id.
fn relative_id(app: &ApplicationProgram, id: &str) -> String {
    id.strip_prefix(&format!("{}_", app.id))
        .unwrap_or(id)
        .to_string()
}

// ---------------------------------------------------------------------------
// Decoding: the inverse of the image builder's placement
// ---------------------------------------------------------------------------

/// Decodes the current raw value at `location` out of the read-back memory.
///
/// Returns `None` when the segment was not read back, the field lies past the
/// bytes that were read, or the type carries no memory.
fn decode(
    current: &CurrentMemory,
    location: &Location,
    ptype: Option<&ParameterType>,
) -> Option<String> {
    let bytes = current.get(&location.segment)?;
    match ptype? {
        ParameterType::Int {
            size_bits, signed, ..
        } => {
            let bits = (*size_bits)?;
            let raw = read_bits(bytes, location.offset, location.bit_offset, bits)?;
            Some(if *signed {
                sign_extend(raw, bits).to_string()
            } else {
                raw.to_string()
            })
        }
        ParameterType::Enum { size_bits, .. } => {
            let bits = size_bits.unwrap_or(8);
            let raw = read_bits(bytes, location.offset, location.bit_offset, bits)?;
            Some(raw.to_string())
        }
        ParameterType::Text { size_bits } => {
            let len = (size_bits.unwrap_or(0) / 8) as usize;
            let end = location.offset.checked_add(len)?;
            let slice = bytes.get(location.offset..end)?;
            let text: String = String::from_utf8_lossy(slice)
                .trim_end_matches('\0')
                .to_string();
            Some(text)
        }
        ParameterType::Float { encoding, .. } => {
            let slice = |len: usize| -> Option<&[u8]> {
                let end = location.offset.checked_add(len)?;
                bytes.get(location.offset..end)
            };
            match float_width(encoding.as_deref()) {
                FloatWidth::Dpt9 => {
                    let b = slice(2)?;
                    Some(format_float(f64::from(decode_float16(b[0], b[1]))))
                }
                FloatWidth::Single => {
                    let b = slice(4)?;
                    let v = f32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                    Some(format_float(f64::from(v)))
                }
                FloatWidth::Double => {
                    let b = slice(8)?;
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    Some(format_float(f64::from_be_bytes(arr)))
                }
            }
        }
        ParameterType::None => None,
        ParameterType::Other { size_bits, .. } => {
            let bits = (*size_bits).filter(|b| *b > 0 && *b <= 64 && b % 8 == 0)?;
            let raw = read_bits(bytes, location.offset, location.bit_offset, bits)?;
            Some(raw.to_string())
        }
    }
}

/// Reads an MSB-first bit field of `bits` width starting at
/// `offset * 8 + bit_offset`, the exact inverse of the image builder's
/// placement. `None` when the field runs past the bytes that were read, or when
/// it is wider than a `u64`.
fn read_bits(bytes: &[u8], offset: usize, bit_offset: u8, bits: u32) -> Option<u64> {
    if bits == 0 || bits > 64 {
        return None;
    }
    let start = offset
        .checked_mul(8)?
        .checked_add(usize::from(bit_offset))?;
    let end = start.checked_add(bits as usize)?;
    if end.div_ceil(8) > bytes.len() {
        return None;
    }
    let mut value: u64 = 0;
    for i in 0..bits as usize {
        let pos = start + i;
        let bit = (bytes[pos / 8] >> (7 - (pos % 8))) & 1;
        value = (value << 1) | u64::from(bit);
    }
    Some(value)
}

/// Interprets an unsigned bit pattern of `bits` width as two's complement.
fn sign_extend(raw: u64, bits: u32) -> i64 {
    if bits >= 64 {
        return raw as i64;
    }
    let sign = 1u64 << (bits - 1);
    if raw & sign != 0 {
        (raw as i64) - (1i64 << bits)
    } else {
        raw as i64
    }
}

/// The three float encodings ETS product data uses.
enum FloatWidth {
    /// The KNX 2-byte float (`"DPT 9"`), and the fallback for an absent encoding.
    Dpt9,
    /// A 4-byte big-endian IEEE-754 single.
    Single,
    /// An 8-byte big-endian IEEE-754 double.
    Double,
}

fn float_width(encoding: Option<&str>) -> FloatWidth {
    match encoding.map(|e| e.trim().to_ascii_lowercase()).as_deref() {
        Some("ieee-754 single") | Some("ieee 754 single") | Some("dpt 14") | Some("dpt14") => {
            FloatWidth::Single
        }
        Some("ieee-754 double") | Some("ieee 754 double") => FloatWidth::Double,
        _ => FloatWidth::Dpt9,
    }
}

/// Decodes the KNX 2-octet float (DPT 9) through the workspace's one DPT codec.
fn decode_float16(hi: u8, lo: u8) -> f32 {
    match bussard_model::decode(&bussard_model::Dpt::new(9, None), &[hi, lo]) {
        bussard_model::TypedValue::Float { value, .. } => value,
        _ => f32::NAN,
    }
}

/// Renders a float without a trailing `.0` on a whole number, so a temperature
/// reads `18` and `17.5` rather than `18.0000001`.
fn format_float(value: f64) -> String {
    let rounded = (value * 1000.0).round() / 1000.0;
    if rounded.fract() == 0.0 {
        format!("{}", rounded as i64)
    } else {
        format!("{rounded}")
    }
}

/// Renders a raw value for a human: an enumeration shows the vendor's own text
/// for the member, everything else shows the value as written.
fn render(raw: &str, ptype: Option<&ParameterType>) -> String {
    if let Some(ParameterType::Enum { values, .. }) = ptype {
        if let Ok(n) = raw.trim().parse::<i64>() {
            if let Some(member) = values.iter().find(|v| v.value == n) {
                if !member.text.trim().is_empty() {
                    return member.text.clone();
                }
            }
        }
    }
    raw.to_string()
}

// ---------------------------------------------------------------------------
// Reading the current parameter memory off a device
// ---------------------------------------------------------------------------

/// Reads back the parameter memory a [`FlashPlan`] would overwrite, so
/// [`param_plan`] can name the values the device holds today.
///
/// **Read-only and best-effort.** For every parameter image the plan streams, it
/// resolves the target object's segment base through `PID_TABLE_REFERENCE` and
/// reads the image's own length from `base + offset`. Any failure — an object
/// that reports no base (the `0` an `Unloaded` object returns), a refused read, a
/// device that does not expose the property — drops that segment from the result
/// rather than failing the caller: an unreadable value is reported as unknown,
/// never guessed at.
///
/// Returns an empty map for a System 7 plan, whose parameters are written as
/// whole absolute regions rather than a segment image (see [`SYS7_NOTE`]).
pub async fn read_current_parameter_memory<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> CurrentMemory {
    let mut out = CurrentMemory::new();
    if plan.is_sys7() {
        return out;
    }
    // The same resolution the download engine applies: an op's index names a
    // device object when the device exposes it, else the application object.
    let table = match bussard_mgmt::probe_object_types(l4).await {
        Ok(table) => table,
        Err(err) => {
            tracing::debug!(%err, "object table unreadable; skipping the parameter read-back");
            return out;
        }
    };
    let Some(app_object) = table
        .iter()
        .find(|(_, object_type)| *object_type == OT_APPLICATION_PROGRAM)
        .map(|(index, _)| *index)
    else {
        tracing::debug!("no application object found; skipping the parameter read-back");
        return out;
    };
    let resolve_object = |target: &Option<u32>| -> u8 {
        target
            .and_then(|t| u8::try_from(t).ok())
            .filter(|t| *t != 0 && table.iter().any(|(i, _)| i == t))
            .unwrap_or(app_object)
    };

    // An object's `PID_TABLE_REFERENCE` names only the segment allocated on it
    // *last*. A parameter image written after an earlier allocation on the same
    // object sits at a base the device no longer reports, so reading it would
    // decode the wrong bytes; such an image is left unread (its values stay
    // unknown) rather than guessed at.
    let mut last_allocation: BTreeMap<u8, usize> = BTreeMap::new();
    for (i, step) in plan.steps.iter().enumerate() {
        if let FlashStep::AllocateSegment { target, .. } = step {
            last_allocation.insert(resolve_object(target), i);
        }
    }

    // Segment bases are per object; read each one once.
    let mut bases: BTreeMap<u8, Option<u32>> = BTreeMap::new();
    let mut preceding_allocation: Option<(u8, usize)> = None;
    for (i, step) in plan.steps.iter().enumerate() {
        if let FlashStep::AllocateSegment { target, .. } = step {
            preceding_allocation = Some((resolve_object(target), i));
            continue;
        }
        let FlashStep::WriteRelMem {
            offset,
            image,
            target,
        } = step
        else {
            continue;
        };
        if image.kind != ImageKind::Parameters || out.contains_key(&image.segment_id) {
            continue;
        }
        let object = resolve_object(target);
        let readable = match preceding_allocation {
            Some((alloc_object, at)) => {
                alloc_object == object && last_allocation.get(&object) == Some(&at)
            }
            // No allocation in this plan: the object's current segment is the
            // one the write targets.
            None => !last_allocation.contains_key(&object),
        };
        if !readable {
            tracing::debug!(
                segment = %image.segment_id,
                "parameter segment is not the object's last allocation; its values stay unknown"
            );
            continue;
        }
        let base = match bases.get(&object) {
            Some(base) => *base,
            None => {
                let read = read_table_reference(l4, object)
                    .await
                    .ok()
                    .filter(|b| *b != 0);
                bases.insert(object, read);
                read
            }
        };
        let Some(base) = base else { continue };
        let Some(addr) = base.checked_add(*offset) else {
            continue;
        };
        match read_memory_range(l4, addr, image.len).await {
            Ok(bytes) => {
                out.insert(image.segment_id.clone(), bytes);
            }
            Err(err) => {
                tracing::debug!(
                    segment = %image.segment_id,
                    %err,
                    "parameter segment could not be read back; its values stay unknown"
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::application::parse_application_program;

    /// A two-parameter System B application: an 8-bit setback temperature in °C
    /// and a 2-bit enumeration, both in one parameter segment.
    fn app() -> ApplicationProgram {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" ApplicationNumber="1" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>
            <RelativeSegment Id="M-1_A-1_RS-2" Size="4" LoadStateMachine="4" Offset="0"><Data>AAAAAA==</Data></RelativeSegment>
           </Code>
           <ParameterTypes>
            <ParameterType Id="M-1_A-1_PT-0" Name="temp"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="5" maxInclusive="30" /></ParameterType>
            <ParameterType Id="M-1_A-1_PT-1" Name="mode"><TypeRestriction Base="Value" SizeInBit="2">
              <Enumeration Text="Off" Value="0" /><Enumeration Text="Automatic" Value="1" /><Enumeration Text="Always on" Value="2" />
            </TypeRestriction></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-1_A-1_P-0" Name="Nachtabsenkung" Text="Night setback" SuffixText="°C" ParameterType="M-1_A-1_PT-0" Value="18"><Memory CodeSegment="M-1_A-1_RS-2" Offset="0" BitOffset="0" /></Parameter>
            <Parameter Id="M-1_A-1_P-1" Name="Betriebsart" Text="Operating mode" ParameterType="M-1_A-1_PT-1" Value="1"><Memory CodeSegment="M-1_A-1_RS-2" Offset="1" BitOffset="0" /></Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-1_A-1_P-0_R-1" RefId="M-1_A-1_P-0" />
            <ParameterRef Id="M-1_A-1_P-1_R-2" RefId="M-1_A-1_P-1" />
           </ParameterRefs>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlConnect />
             <LdCtrlLoad LsmIdx="4" />
             <LdCtrlRelSegment LsmIdx="4" Size="4" AppliesTo="par" />
             <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="4" AppliesTo="par" />
             <LdCtrlLoadCompleted LsmIdx="4" />
             <LdCtrlDisconnect />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        parse_application_program("M-1_A-1", xml.as_bytes()).expect("the fixture parses")
    }

    /// The device memory holding the vendor defaults: 18 °C, mode 1 (`0b01` in
    /// the top two bits of byte 1).
    fn current_defaults() -> CurrentMemory {
        BTreeMap::from([("M-1_A-1_RS-2".to_string(), vec![18, 0b0100_0000, 0, 0])])
    }

    #[test]
    fn test_param_plan_one_changed_parameter() {
        let app = app();
        let overrides = BTreeMap::from([("P-0_R-1".to_string(), "17".to_string())]);
        let plan = param_plan(&app, &overrides, &BTreeMap::new(), &current_defaults());
        assert_eq!(plan.changes.len(), 1, "changes: {:?}", plan.changes);
        let change = &plan.changes[0];
        assert_eq!(change.name, "Night setback");
        assert_eq!(change.old, ParamValue::Known("18".to_string()));
        assert_eq!(change.new, ParamValue::Known("17".to_string()));
        assert_eq!(change.unit.as_deref(), Some("°C"));
        assert_eq!(change.line(), "Night setback: 18 °C to 17 °C");
        assert_eq!(plan.unknown, 0);
    }

    #[test]
    fn test_param_plan_unchanged_override_is_not_listed() {
        let app = app();
        let overrides = BTreeMap::from([("P-0_R-1".to_string(), "18".to_string())]);
        let plan = param_plan(&app, &overrides, &BTreeMap::new(), &current_defaults());
        assert!(plan.is_empty(), "changes: {:?}", plan.changes);
    }

    #[test]
    fn test_param_plan_enum_renders_vendor_text() {
        let app = app();
        let overrides = BTreeMap::from([("P-1_R-2".to_string(), "2".to_string())]);
        let plan = param_plan(&app, &overrides, &BTreeMap::new(), &current_defaults());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(
            plan.changes[0].old,
            ParamValue::Known("Automatic".to_string())
        );
        assert_eq!(
            plan.changes[0].new,
            ParamValue::Known("Always on".to_string())
        );
        assert_eq!(
            plan.changes[0].line(),
            "Operating mode: Automatic to Always on"
        );
    }

    #[test]
    fn test_param_plan_without_readback_is_unknown() {
        let app = app();
        let overrides = BTreeMap::from([("P-0_R-1".to_string(), "17".to_string())]);
        let plan = param_plan(&app, &overrides, &BTreeMap::new(), &CurrentMemory::new());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].old, ParamValue::Unknown);
        assert_eq!(plan.unknown, 1);
        assert!(plan.note.is_some());
        assert_eq!(
            plan.changes[0].line(),
            "Night setback: unknown current value, will be 17 °C"
        );
    }

    #[test]
    fn test_param_plan_reports_drift_the_flash_would_undo() {
        // The device holds 21 °C but nothing overrides the parameter: the flash
        // restores the vendor default 18, which is a change worth naming.
        let app = app();
        let current = BTreeMap::from([("M-1_A-1_RS-2".to_string(), vec![21, 0b0100_0000, 0, 0])]);
        let plan = param_plan(&app, &BTreeMap::new(), &BTreeMap::new(), &current);
        assert_eq!(plan.changes.len(), 1, "changes: {:?}", plan.changes);
        assert_eq!(plan.changes[0].key, "P-0");
        assert_eq!(plan.changes[0].old, ParamValue::Known("21".to_string()));
        assert_eq!(plan.changes[0].new, ParamValue::Known("18".to_string()));
    }

    #[test]
    fn test_read_bits_msb_first_across_a_byte_boundary() {
        // A 4-bit field at bit offset 6 spans bytes 0 and 1: 0b??00_1101 → 0b1101.
        let bytes = [0b0000_0011u8, 0b0100_0000];
        assert_eq!(read_bits(&bytes, 0, 6, 4), Some(0b1101));
        // Past the end of what was read.
        assert_eq!(read_bits(&bytes, 4, 0, 8), None);
    }

    #[test]
    fn test_sign_extend_two_s_complement() {
        assert_eq!(sign_extend(0b1111_1111, 8), -1);
        assert_eq!(sign_extend(0b0111_1111, 8), 127);
        assert_eq!(sign_extend(0b11, 2), -1);
    }

    #[test]
    fn test_decode_float16_matches_knx_vectors() {
        // DPT 9 reference: 0x0C 0x1A is 21.00, 0x8A 0x24 is -30.00.
        assert!((decode_float16(0x0C, 0x1A) - 21.0).abs() < 0.01);
        assert!((decode_float16(0x8A, 0x24) + 30.0).abs() < 0.01);
    }

    #[test]
    fn test_split_module_instance_recovers_the_selector() {
        let (param, selector) = split_module_instance("MD-1_M-3_MI-1_P-3");
        assert_eq!(param, "MD-1_P-3");
        assert_eq!(selector.as_deref(), Some("MD-1_M-3_MI-1"));
        let (param, selector) = split_module_instance("P-1312");
        assert_eq!(param, "P-1312");
        assert_eq!(selector, None);
    }
}
