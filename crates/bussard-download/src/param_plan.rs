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
use bussard_prod::application::ApplicationProgram;

use crate::param_decode::{decode_parameters, display_name, parameter_type, render, resolve_key};

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
    if !current.is_empty() {
        let decoded = decode_parameters(app, overrides, base_offsets, current);
        return ParamPlan {
            changes: decoded.differences,
            unknown: decoded.unknown,
            note: None,
        };
    }
    // Nothing was read: every override that lands in memory is a change to an
    // unknown current value.
    let mut changes = Vec::new();
    for (key, desired) in overrides {
        let Some((param, _)) = resolve_key(app, key) else {
            continue;
        };
        let in_union = app
            .unions
            .iter()
            .any(|u| u.members.iter().any(|m| m.parameter == param.id));
        if param.memory.is_none() && !in_union {
            continue;
        }
        let ptype = parameter_type(app, param);
        changes.push(ParamChange {
            key: key.clone(),
            name: display_name(param),
            old: ParamValue::Unknown,
            new: ParamValue::Known(render(desired.trim(), ptype)),
            unit: param.suffix_text.clone(),
        });
    }
    let note = (!changes.is_empty()).then(|| {
        "the device's current parameter memory could not be read, so every value \
         below is shown as an unknown current value"
            .to_string()
    });
    ParamPlan {
        unknown: changes.len(),
        changes,
        note,
    }
}

/// One parameter value decoded out of a device's parameter memory, next to the
/// vendor default (issue #119, `reconstruct` / `plan` read-back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamReading {
    /// The app-relative parameter id (`P-…`).
    pub key: String,
    /// The human name (see [`ParamChange::name`]).
    pub name: String,
    /// The value the device holds, rendered.
    pub value: String,
    /// The vendor default, rendered.
    pub default: String,
    /// The unit the vendor shows after the value, when declared.
    pub unit: Option<String>,
}

impl ParamReading {
    /// `night setback: 17 °C (default 18 °C)`.
    pub fn line(&self) -> String {
        let unit = match &self.unit {
            Some(u) if !u.is_empty() => format!(" {u}"),
            _ => String::new(),
        };
        format!(
            "{}: {}{unit} (default {}{unit})",
            self.name, self.value, self.default
        )
    }
}

/// The shown parameters whose value in `current` differs from the vendor
/// default, sorted by key: what a device carries beyond a fresh download.
///
/// `overrides` (the model's values) steer which refs are shown where the
/// memory cannot (display-only parameters); see
/// [`crate::param_decode::decode_parameters`].
pub fn non_default_parameters(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    current: &CurrentMemory,
) -> Vec<ParamReading> {
    decode_parameters(app, overrides, base_offsets, current).non_default
}

/// The raw values the device holds, keyed like a device file's
/// `parameters:` block: the override shape
/// [`bussard_prod::dynamic::evaluate_dynamic`] takes.
///
/// Starts from `overrides` (the model's values) and replaces every value the
/// device memory in `current` answers for. A parameter with no memory (a
/// display-only selector) keeps the model's value, since the device does not
/// hold one.
pub fn current_parameter_values(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
    current: &CurrentMemory,
) -> BTreeMap<String, String> {
    decode_parameters(app, overrides, base_offsets, current).values
}

/// How a parameter change would reshape the group-object table (issue #119).
///
/// A parameter that shows or hides a com-object, or changes its size or flags,
/// changes the group-object table the full flash writes. A parameter-only
/// download does not touch that table, so it must refuse such a change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupObjectChange {
    /// Com-object numbers the new parameters show that the current ones hide.
    pub shown: Vec<u16>,
    /// Com-object numbers the new parameters hide that the current ones show.
    pub hidden: Vec<u16>,
    /// Whether the table image differs at all (a size or flag change on an
    /// object shown both before and after counts too).
    pub table_differs: bool,
}

impl GroupObjectChange {
    /// Whether the group-object table stays exactly the same.
    pub fn is_empty(&self) -> bool {
        !self.table_differs && self.shown.is_empty() && self.hidden.is_empty()
    }
}

/// Compares the group-object table the application's Dynamic section yields for
/// the `before` and `after` parameter values (both keyed like
/// [`current_parameter_values`] returns them).
pub fn group_object_change(
    app: &ApplicationProgram,
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> GroupObjectChange {
    let linked = BTreeMap::new();
    let asaps = |values: &BTreeMap<String, String>| -> BTreeSet<u16> {
        let config = bussard_prod::dynamic::evaluate_dynamic(app, values);
        crate::compute::dynamic_group_object_descriptors(app, &config, &linked)
            .iter()
            .map(|d| d.asap)
            .collect()
    };
    let (old, new) = (asaps(before), asaps(after));
    GroupObjectChange {
        shown: new.difference(&old).copied().collect(),
        hidden: old.difference(&new).copied().collect(),
        table_differs: crate::compute::dynamic_group_object_table(app, before, &linked)
            != crate::compute::dynamic_group_object_table(app, after, &linked),
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
    if plan.is_sys7() {
        return CurrentMemory::new();
    }
    read_parameter_regions(l4, plan)
        .await
        .into_iter()
        .map(|(segment, region)| (segment, region.bytes))
        .collect()
}

/// One parameter-bearing memory region read back off a device: where it sits
/// and the octets it holds (issue #119).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamRegion {
    /// The code-segment id the region belongs to.
    pub segment_id: String,
    /// The absolute device address the region starts at (the segment base from
    /// `PID_TABLE_REFERENCE` plus the write offset on System B, the
    /// `AbsSegment` address on System 7).
    pub address: u32,
    /// The octets the device holds, as long as the image the plan streams.
    pub bytes: Vec<u8>,
}

/// The parameter regions of one device, keyed by code-segment id.
pub type ParamRegions = BTreeMap<String, ParamRegion>;

/// The bytes of each region, in the shape [`param_plan`] decodes.
pub fn regions_memory(regions: &ParamRegions) -> CurrentMemory {
    regions
        .iter()
        .map(|(segment, region)| (segment.clone(), region.bytes.clone()))
        .collect()
}

/// The parameter regions [`read_parameter_regions`] reads off a device, as
/// they read once `plan` has run: the same segments, each holding the bytes
/// the plan streams into it. The offline half of the read-back round trip
/// (issue #142): decoding these must give back the parameters the plan was
/// built from.
///
/// The selection mirrors [`read_parameter_regions`]: on System 7 every
/// `AbsSegment` whose image carries parameters, at its absolute address; on
/// System B every parameter `WriteRelMem` that writes into its object's last
/// allocation, with the write offset as its address (the segment base is the
/// device's to choose, so it is not known offline).
pub fn planned_parameter_regions(plan: &FlashPlan) -> ParamRegions {
    let mut out = ParamRegions::new();
    let mut add = |segment: &str, address: u32, len: usize| {
        if out.contains_key(segment) {
            return;
        }
        if let Some(bytes) = plan.image_bytes(segment) {
            out.insert(
                segment.to_string(),
                ParamRegion {
                    segment_id: segment.to_string(),
                    address,
                    bytes: bytes[..len.min(bytes.len())].to_vec(),
                },
            );
        }
    };
    if plan.is_sys7() {
        for step in &plan.steps {
            if let FlashStep::Sys7AbsSegment {
                address,
                image: Some(image),
                ..
            } = step
                && plan
                    .param_images
                    .get(&image.segment_id)
                    .is_some_and(|b| !b.is_empty())
            {
                add(&image.segment_id, *address, image.len);
            }
        }
        return out;
    }
    // Object indices as the plan names them; `None`/`0` is the application
    // object.
    let object = |target: &Option<u32>| target.filter(|t| *t != 0);
    let mut last_allocation: BTreeMap<Option<u32>, usize> = BTreeMap::new();
    for (i, step) in plan.steps.iter().enumerate() {
        if let FlashStep::AllocateSegment { target, .. } = step {
            last_allocation.insert(object(target), i);
        }
    }
    let mut allocated: BTreeMap<Option<u32>, usize> = BTreeMap::new();
    for (i, step) in plan.steps.iter().enumerate() {
        match step {
            FlashStep::AllocateSegment { target, .. } => {
                allocated.insert(object(target), i);
            }
            FlashStep::WriteRelMem {
                offset,
                image,
                target,
            } if image.kind == ImageKind::Parameters => {
                let obj = object(target);
                let readable = match allocated.get(&obj) {
                    Some(at) => last_allocation.get(&obj) == Some(at),
                    None => !last_allocation.contains_key(&obj),
                };
                if readable {
                    add(&image.segment_id, *offset, image.len);
                }
            }
            _ => {}
        }
    }
    out
}

/// Reads back every parameter-bearing region a [`FlashPlan`] writes, with the
/// absolute address each one sits at.
///
/// **Read-only and best-effort**, like [`read_current_parameter_memory`]: a
/// region that cannot be addressed or read is left out, never guessed at.
///
/// - **System B**: every `WriteRelMem` that streams a parameter image is read at
///   its object's `PID_TABLE_REFERENCE` base plus the write offset. An image
///   written after an earlier allocation on the same object is left out, since
///   the object only reports the base of its last allocation.
/// - **System 7**: every `AbsSegment` whose image carries parameters is read at
///   the segment's absolute address.
pub async fn read_parameter_regions<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> ParamRegions {
    let mut out = ParamRegions::new();
    if plan.is_sys7() {
        for step in &plan.steps {
            let FlashStep::Sys7AbsSegment {
                address,
                image: Some(image),
                ..
            } = step
            else {
                continue;
            };
            let carries_params = plan
                .param_images
                .get(&image.segment_id)
                .is_some_and(|b| !b.is_empty());
            if !carries_params || out.contains_key(&image.segment_id) {
                continue;
            }
            match read_memory_range(l4, *address, image.len).await {
                Ok(bytes) => {
                    out.insert(
                        image.segment_id.clone(),
                        ParamRegion {
                            segment_id: image.segment_id.clone(),
                            address: *address,
                            bytes,
                        },
                    );
                }
                Err(err) => {
                    tracing::debug!(
                        segment = %image.segment_id,
                        %err,
                        "System 7 parameter segment could not be read back"
                    );
                }
            }
        }
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
    // The allocation each object received most recently, as the steps run: a
    // write streams into its own object's segment (the executor keeps one base
    // per object), even when other objects were allocated in between, as the
    // master template does (obj4, obj3, obj1, obj2 allocated, then written).
    let mut allocated: BTreeMap<u8, usize> = BTreeMap::new();
    for (i, step) in plan.steps.iter().enumerate() {
        if let FlashStep::AllocateSegment { target, .. } = step {
            allocated.insert(resolve_object(target), i);
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
        let readable = match allocated.get(&object) {
            Some(at) => last_allocation.get(&object) == Some(at),
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
                out.insert(
                    image.segment_id.clone(),
                    ParamRegion {
                        segment_id: image.segment_id.clone(),
                        address: addr,
                        bytes,
                    },
                );
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
        assert_eq!(plan.changes[0].key, "P-0_R-1");
        assert_eq!(plan.changes[0].old, ParamValue::Known("21".to_string()));
        assert_eq!(plan.changes[0].new, ParamValue::Known("18".to_string()));
    }

    /// A one-segment app whose 1-bit parameter `P-1` shows com-object 2.
    fn gated_app() -> ApplicationProgram {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-2" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="Gate" LoadProcedureStyle="ProductDefault">
          <Static>
           <Code>
            <RelativeSegment Id="M-1_A-2_RS-1" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
           </Code>
           <ParameterTypes>
            <ParameterType Id="M-1_A-2_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
            <ParameterType Id="M-1_A-2_PT-1" Name="onoff"><TypeRestriction Base="Value" SizeInBit="1">
              <Enumeration Text="Off" Value="0" /><Enumeration Text="On" Value="1" />
            </TypeRestriction></ParameterType>
           </ParameterTypes>
           <Parameters>
            <Parameter Id="M-1_A-2_P-0" Name="thr" Text="Threshold" ParameterType="M-1_A-2_PT-0" Value="7"><Memory CodeSegment="M-1_A-2_RS-1" Offset="0" BitOffset="0" /></Parameter>
            <Parameter Id="M-1_A-2_P-1" Name="obj2" Text="Object 2" ParameterType="M-1_A-2_PT-1" Value="0"><Memory CodeSegment="M-1_A-2_RS-1" Offset="1" BitOffset="0" /></Parameter>
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="M-1_A-2_P-0_R-1" RefId="M-1_A-2_P-0" />
            <ParameterRef Id="M-1_A-2_P-1_R-2" RefId="M-1_A-2_P-1" />
           </ParameterRefs>
           <ComObjects>
            <ComObject Id="M-1_A-2_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
            <ComObject Id="M-1_A-2_O-2" Number="2" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
           </ComObjects>
           <ComObjectRefs>
            <ComObjectRef Id="M-1_A-2_O-1_R-1" RefId="M-1_A-2_O-1" />
            <ComObjectRef Id="M-1_A-2_O-2_R-2" RefId="M-1_A-2_O-2" />
           </ComObjectRefs>
          </Static>
          <Dynamic>
           <ChannelIndependentBlock>
            <ParameterBlock Id="M-1_A-2_PB-1" Name="main">
             <ParameterRefRef RefId="M-1_A-2_P-0_R-1" />
             <ParameterRefRef RefId="M-1_A-2_P-1_R-2" />
             <ComObjectRefRef RefId="M-1_A-2_O-1_R-1" />
             <choose ParamRefId="M-1_A-2_P-1_R-2">
              <when test="1"><ComObjectRefRef RefId="M-1_A-2_O-2_R-2" /></when>
             </choose>
            </ParameterBlock>
           </ChannelIndependentBlock>
          </Dynamic>
         </ApplicationProgram></KNX>"#;
        parse_application_program("M-1_A-2", xml.as_bytes()).expect("the fixture parses")
    }

    #[test]
    fn test_current_parameter_values_decodes_every_ref() {
        let app = gated_app();
        let current = BTreeMap::from([("M-1_A-2_RS-1".to_string(), vec![9, 0b1000_0000])]);
        let values = current_parameter_values(&app, &BTreeMap::new(), &BTreeMap::new(), &current);
        assert_eq!(values.get("P-0_R-1").map(String::as_str), Some("9"));
        assert_eq!(values.get("P-1_R-2").map(String::as_str), Some("1"));
    }

    #[test]
    fn test_group_object_change_detects_a_shown_object() {
        let app = gated_app();
        let off = BTreeMap::from([("P-1_R-2".to_string(), "0".to_string())]);
        let on = BTreeMap::from([("P-1_R-2".to_string(), "1".to_string())]);
        let change = group_object_change(&app, &off, &on);
        assert_eq!(change.shown, vec![2]);
        assert!(change.hidden.is_empty());
        assert!(!change.is_empty());
        assert_eq!(group_object_change(&app, &on, &off).hidden, vec![2]);
        // A threshold change leaves the table alone.
        let thr = BTreeMap::from([("P-0_R-1".to_string(), "12".to_string())]);
        assert!(group_object_change(&app, &off, &thr).is_empty());
    }

    #[test]
    fn test_non_default_parameters_lists_only_changed_values() {
        let app = gated_app();
        let current = BTreeMap::from([("M-1_A-2_RS-1".to_string(), vec![7, 0b1000_0000])]);
        let readings = non_default_parameters(&app, &BTreeMap::new(), &BTreeMap::new(), &current);
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].line(), "Object 2: On (default Off)");
    }
}
