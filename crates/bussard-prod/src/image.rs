//! The parameter memory image builder: turn an [`ApplicationProgram`]'s
//! parameters (their declared defaults, `ParameterRef` overrides, and a
//! caller-supplied override map) into the per-segment byte images ETS would
//! download into a device.
//!
//! # What this computes
//!
//! Every [`Parameter`] with a `<Memory>` location contributes its value to a
//! byte image keyed by the memory's `CodeSegment` id. [`compute_parameter_image`]
//! resolves each parameter's effective value through the override chain, encodes
//! it to bytes at the declared `Offset`/`BitOffset` with the width its
//! `ParameterType` implies, and returns one `Vec<u8>` per segment that any
//! parameter targets.
//!
//! # Bit-offset semantics (established from real ETS data)
//!
//! ETS lays parameter fields into a byte **most-significant-bit first**: a field
//! of width `w` at `BitOffset b` occupies bits `[b, b+w)` counting from the MSB
//! (bit 0 = the byte's high bit `0x80`, bit 7 = the low bit `0x01`). Evidence
//! from `home_test.knxproj`:
//!
//! * Consecutive sub-byte fields pack left to right with `BitOffset` equal to
//!   the cumulative width so far: four 2-bit fields sharing a byte carry
//!   `BitOffset` 0, 2, 4, 6; four 1-bit fields carry 4, 5, 6, 7; a 1-bit field
//!   at 0 is followed by a 3-bit field at 1.
//! * Where a shipped `<Data>` image happened to hold a parameter's non-zero
//!   default, decoding MSB-first reproduced the default (e.g. a 2-bit field with
//!   default 3 at `BitOffset 6` sat in byte `0b0000_0111`).
//!
//! Multi-byte integers are stored **big-endian** (default 500 appeared as
//! `01 F4`, 2000 as `07 D0`, 10 as `00 0A`).
//!
//! # Base image
//!
//! A parameter segment is usually a separate `RelativeSegment` whose `<Data>` is
//! a mostly-zero placeholder that ETS overwrites with parameter values on
//! download. If the target segment carries a `<Data>` payload bussard uses it as
//! the base image and lays parameters over it (so bytes no parameter touches
//! keep the vendor's bytes); otherwise the image starts as all-`0x00`, sized to
//! hold every parameter that targets it.

use std::collections::BTreeMap;

use bussard_ets::application::{ApplicationProgram, ParameterType};

use crate::error::{ProdError, Result};

/// The largest parameter-memory image bussard will ever build for a single
/// segment when the segment declares no `Size`. A segment's image is a base
/// image plus parameters placed by byte offset; both the offset and the payload
/// length originate in untrusted vendor XML (a `<Memory Offset>` is a raw `u32`,
/// so `0xFFFF_FFFF` would otherwise force a ~4 GiB `Vec` allocation at flash
/// pre-flight). Real System B application segments are tens of KiB; 1 MiB is a
/// generous ceiling that no legitimate segment reaches, so exceeding it is
/// treated as corrupt/hostile input and refused rather than allocated.
const MAX_SEGMENT_IMAGE: u64 = 1024 * 1024;

/// Builds the per-segment parameter memory images for `app`, applying
/// caller-supplied overrides keyed by **app-relative `ParameterRef` id** (the
/// `#46` model-agent contract — see [`Device::parameters`]).
///
/// [`Device::parameters`]: bussard_model::schema::Device::parameters
///
/// For every parameter carrying a `<Memory>` location, the effective value is
/// resolved through the override chain (lowest to highest precedence):
///
/// 1. the `ParameterType` default (`0`/empty when the parameter has no `Value`),
/// 2. the parameter's own `Value`,
/// 3. the value of the *first* `ParameterRef` pointing at the parameter that
///    carries a `Value` (refs are the per-channel instances; a single-instance
///    parameter has one ref),
/// 4. `overrides[ref-id]`, the caller's explicit choice, keyed by the
///    app-relative `ParameterRef` id (e.g. `MD-1_M-3_MI-1_P-3_R-45` or
///    `P-1312_R-2140`) — **not** the parameter name, which is provably
///    non-unique (module repetition and multi-ref parameters).
///
/// The resolved value is encoded MSB-first big-endian into the byte image keyed
/// by the memory's `CodeSegment`. Returns a map from segment id to its image.
///
/// # Module-instance offsets
///
/// A module parameter (id `MD-<d>_..._P-<p>`, whose `<Memory>` carries a
/// [`BaseOffset`](bussard_ets::application::Memory::base_offset)) is instantiated
/// once per channel; each instance places its value at
/// `declared_offset + instance_base`, where `instance_base` is the module
/// instance's value for the argument the `BaseOffset` names. That per-instance
/// value lives in the **project** (`ModuleInstance` data), not in the
/// application program, so a caller that knows it passes it in `base_offsets`,
/// keyed by the module-instance selector (`MD-<d>_M-<m>_MI-<n>`). A module
/// override whose selector is absent from `base_offsets` **cannot be placed**
/// without guessing its address, so it is refused (see Errors) rather than
/// written to the wrong byte. Plain (non-module) parameters ignore `base_offsets`
/// entirely — their declared offset is absolute within the segment.
///
/// # Errors
///
/// Returns [`ProdError::ParameterImage`] naming the offending parameter/key if a
/// value cannot be parsed for its type, exceeds the field's declared width, its
/// memory location is incomplete, or a module-instance override cannot be placed
/// because its per-instance base offset was not supplied in `base_offsets`.
pub fn compute_parameter_image(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
    base_offsets: &BTreeMap<String, u32>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    // Pre-index the first ParameterRef Value override per parameter id, in a
    // deterministic order (sorted by ref id) so a fixed ref wins reproducibly.
    let mut ref_value: BTreeMap<&str, &str> = BTreeMap::new();
    {
        let mut refs: Vec<_> = app.parameter_refs.values().collect();
        refs.sort_by(|a, b| a.id.cmp(&b.id));
        for r in refs {
            if let Some(v) = r.value.as_deref() {
                ref_value.entry(r.ref_id.as_str()).or_insert(v);
            }
        }
    }

    // Validate every segment's decoded `<Data>`/`<Mask>` against its declared
    // `Size` before building any image. Both payloads are base64 decoded from
    // vendor XML; a payload longer than the segment claims (or, when `Size` is
    // absent, longer than the sane cap) means corrupt/hostile product data, and
    // is refused rather than seeding an oversized base image.
    let mut seg_ids: Vec<&String> = app.code_segments.keys().collect();
    seg_ids.sort();
    for seg_id in seg_ids {
        let seg = &app.code_segments[seg_id];
        let limit = match seg.size {
            Some(sz) => u64::from(sz),
            None => MAX_SEGMENT_IMAGE,
        };
        for (what, payload) in [("<Data>", &seg.data), ("<Mask>", &seg.mask)] {
            if let Some(bytes) = payload {
                if bytes.len() as u64 > limit {
                    return Err(param_err(
                        app,
                        seg_id,
                        &format!(
                            "segment {what} is {} bytes but the segment declares Size {} \
                             (refusing an over-sized segment image)",
                            bytes.len(),
                            seg.size.map(|s| s.to_string()).unwrap_or_else(|| format!(
                                "absent, capped at {MAX_SEGMENT_IMAGE}"
                            )),
                        ),
                    ));
                }
            }
        }
    }

    // Seed each targeted segment's image from its `<Data>` base (if any), else
    // empty; grow lazily as parameters are placed.
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // The set of application `Parameter` ids a channel's parameter block
    // references (via `<ParameterRefRef>`), for a module-based application. ETS
    // only writes a module parameter that a channel actually references; a module
    // parameter with a `<Memory>` that no channel references (e.g. a `color`
    // parameter on the DA.tp app) is never written to the image. `None` for a
    // non-module application, where every parameter is placed as before.
    let referenced_module_params: Option<std::collections::BTreeSet<String>> =
        module_referenced_params(app);

    // First, lay every parameter's default/ref value at its declared position
    // (the vendor-default image). A **module** parameter (its `<Memory>` carries a
    // `BaseOffset`) is instantiated once per `<Module>` channel, so each instance
    // is placed at `declared_offset + instance[base_offset]` — the full
    // channel-expanded default image ETS downloads. A module parameter no channel
    // references is skipped entirely. Non-module parameters are placed once at
    // their declared offset; overrides then re-place per-instance below.
    let mut params: Vec<_> = app.parameters.values().collect();
    params.sort_by(|a, b| a.id.cmp(&b.id));

    for param in params {
        let Some(mem) = param.memory.as_ref() else {
            continue;
        };
        let Some(seg_id) = mem.code_segment.as_deref() else {
            // A memory block with no segment: nothing to place it into.
            continue;
        };

        let pname = param.name.as_deref().unwrap_or(&param.id);

        // Resolve the effective *default* value (chain steps 1-3); explicit
        // ref-id overrides (step 4) are applied in a second pass so a module
        // parameter's default lands at its declared offset while each overridden
        // instance lands at its own instance offset.
        let value: Option<String> = ref_value
            .get(param.id.as_str())
            .map(|s| s.to_string())
            .or_else(|| param.default.clone());

        let ptype = param
            .parameter_type
            .as_deref()
            .and_then(|id| app.parameter_types.get(id))
            .map(|d| &d.kind);

        let Some(offset) = mem.offset else {
            return Err(param_err(app, pname, "memory block is missing its Offset"));
        };
        let bit_offset = mem.bit_offset.unwrap_or(0);

        let placement = encode_value(app, pname, ptype, value.as_deref())?;

        let seg_size = app.code_segments.get(seg_id).and_then(|s| s.size);

        // The per-instance byte offsets this parameter's default occupies. For a
        // module parameter that a channel references, one offset per module
        // instance (`declared + instance[base_offset]`); for a plain parameter,
        // just its declared offset.
        let instance_offsets: Vec<usize> = match (
            mem.base_offset.as_deref(),
            referenced_module_params.as_ref(),
        ) {
            (Some(base_arg), Some(referenced)) => {
                // A module parameter: skip it entirely if no channel references it
                // (ETS never writes it), else place one instance per channel.
                if !referenced.contains(&param.id) {
                    continue;
                }
                let rel_arg = base_arg
                    .strip_prefix(&format!("{}_", app.id))
                    .unwrap_or(base_arg);
                let mut offsets = Vec::new();
                for instance in &app.module_instances {
                    let base = instance.arg_values.get(rel_arg).copied().unwrap_or(0);
                    let effective = i64::from(offset).checked_add(base).and_then(|v| {
                        if v >= 0 {
                            usize::try_from(v).ok()
                        } else {
                            None
                        }
                    });
                    let Some(effective) = effective else {
                        return Err(param_err(
                            app,
                            pname,
                            "module-instance base offset places the parameter at an \
                             out-of-range address",
                        ));
                    };
                    offsets.push(effective);
                }
                offsets
            }
            // A plain parameter, or a module parameter in a non-module app: place
            // once at the declared offset.
            _ => vec![offset as usize],
        };

        let image = images
            .entry(seg_id.to_string())
            .or_insert_with(|| base_image(app, seg_id));

        for inst_offset in instance_offsets {
            place_checked(
                app,
                pname,
                image,
                inst_offset,
                bit_offset,
                &placement,
                seg_size,
            )?;
        }
    }

    // Second pass: apply the caller's explicit overrides, keyed by app-relative
    // ParameterRef id. Each key resolves to its application `Parameter` (dropping
    // the module-instance selector and the `_R-<r>` suffix) and, for a module
    // parameter, to the module-instance selector that picks its per-instance base
    // offset.
    for (ref_id, raw_value) in overrides {
        let resolved = resolve_override_key(app, ref_id)?;
        let param = resolved.param;
        let pname = param.name.as_deref().unwrap_or(&param.id);

        let Some(mem) = param.memory.as_ref() else {
            // A display-only parameter (no <Memory>) never reaches an image; an
            // override targeting one is a caller error worth surfacing.
            return Err(param_err(
                app,
                ref_id,
                "parameter has no <Memory> location, so it cannot be flashed",
            ));
        };
        let Some(seg_id) = mem.code_segment.as_deref() else {
            return Err(param_err(app, ref_id, "memory block names no CodeSegment"));
        };
        let Some(declared) = mem.offset else {
            return Err(param_err(app, ref_id, "memory block is missing its Offset"));
        };
        let bit_offset = mem.bit_offset.unwrap_or(0);

        // Resolve the effective byte offset. A module parameter's declared offset
        // is instance-relative: add the per-instance base the caller supplied for
        // this module-instance selector. Refuse rather than misplace when the
        // base is needed but absent.
        let offset = if mem.base_offset.is_some() {
            match resolved.module_instance.as_deref() {
                Some(selector) => {
                    let base = base_offsets.get(selector).copied().ok_or_else(|| {
                        param_err(
                            app,
                            ref_id,
                            &format!(
                                "is a module-instance parameter whose per-instance base offset \
                                 (selector {selector}) was not supplied; cannot place it without \
                                 guessing its address"
                            ),
                        )
                    })?;
                    // Both operands are untrusted vendor/project u32s; a wrapping
                    // add would silently place the parameter at a bogus address.
                    declared.checked_add(base).ok_or_else(|| {
                        param_err(
                            app,
                            ref_id,
                            &format!(
                                "declared offset {declared} plus per-instance base {base} \
                                 overflows a 32-bit segment offset"
                            ),
                        )
                    })?
                }
                None => {
                    // A BaseOffset with no module-instance selector on the key:
                    // the parameter is module-relative but the override did not
                    // name an instance, so its address is undetermined.
                    return Err(param_err(
                        app,
                        ref_id,
                        "is a module parameter but its key carries no _M-<m>_MI-<n> \
                         instance selector; cannot determine its per-instance offset",
                    ));
                }
            }
        } else {
            declared
        };

        let ptype = param
            .parameter_type
            .as_deref()
            .and_then(|id| app.parameter_types.get(id))
            .map(|d| &d.kind);

        let placement = encode_value(app, pname, ptype, Some(raw_value))?;

        let seg_size = app.code_segments.get(seg_id).and_then(|s| s.size);
        let image = images
            .entry(seg_id.to_string())
            .or_insert_with(|| base_image(app, seg_id));

        place_checked(
            app,
            pname,
            image,
            offset as usize,
            bit_offset,
            &placement,
            seg_size,
        )?;
    }

    Ok(images)
}

/// The set of application `Parameter` ids a module application's channel
/// parameter block references, or `None` when the application is not
/// module-based (no module instances or no captured channel membership).
///
/// A module application instantiates its parameters once per `<Module>` channel;
/// its channel `<ParameterBlock>` lists which parameter refs each channel shows
/// (`<ParameterRefRef>`). ETS only writes the parameters a channel references, so
/// this set drives which module parameters
/// [`compute_parameter_image`] expands across instances (a module parameter
/// absent from it — e.g. a `color` parameter with a `<Memory>` no channel
/// references — is never written). The referenced ids are resolved from the
/// membership's parameter-ref ids (app-relative) through
/// [`ApplicationProgram::parameter_refs`] to the underlying `Parameter` id.
fn module_referenced_params(
    app: &ApplicationProgram,
) -> Option<std::collections::BTreeSet<String>> {
    if app.module_instances.is_empty() {
        return None;
    }
    let membership = app.channel_membership.as_ref()?;
    let mut out = std::collections::BTreeSet::new();
    for rel_ref_id in &membership.parameter_refs {
        let full_ref = format!("{}_{rel_ref_id}", app.id);
        if let Some(pref) = app.parameter_refs.get(&full_ref) {
            out.insert(pref.ref_id.clone());
        }
    }
    Some(out)
}

/// A resolved override key: the application `Parameter` it names and, for a
/// module parameter, the module-instance selector (`MD-<d>_M-<m>_MI-<n>`) that
/// picks its per-instance base offset.
struct ResolvedOverride<'a> {
    param: &'a bussard_ets::application::Parameter,
    /// The `MD-<d>_M-<m>_MI-<n>` selector for a module parameter, else `None`.
    module_instance: Option<String>,
}

/// Resolves an app-relative `ParameterRef` id (the part after `@` in a device
/// parameter key) to its application `Parameter` and module-instance selector.
///
/// The ref id preserves the module-instance selector and ends in `_R-<r>`; the
/// application parameter id is the ref id with the `_R-<r>` suffix and the
/// `_M-<m>_MI-<n>` selector removed (mirroring the model's `key_to_param_id`).
/// Both the app-relative id (e.g. `MD-1_P-3`) and the fully-qualified id
/// (`<app>_MD-1_P-3`) are tried, so the map can be keyed either way.
fn resolve_override_key<'a>(
    app: &'a ApplicationProgram,
    ref_id: &str,
) -> Result<ResolvedOverride<'a>> {
    // Strip the trailing `_R-<r>` ref suffix to get the parameter ref.
    let param_ref = ref_id
        .rsplit_once("_R-")
        .map(|(head, _)| head)
        .ok_or_else(|| {
            param_err(
                app,
                ref_id,
                "is not a valid parameter key (no _R-<r> ref suffix)",
            )
        })?;

    // Strip a module-instance selector, if present, recording it.
    let (param_rel, module_instance) = split_module_instance(param_ref);

    // Look the parameter up by its full id (app-prefixed) or its app-relative id.
    let full = format!("{}_{param_rel}", app.id);
    let param = app
        .parameters
        .get(&full)
        .or_else(|| app.parameters.get(param_rel.as_str()))
        .ok_or_else(|| {
            param_err(
                app,
                ref_id,
                &format!("names parameter {param_rel}, which this application does not define"),
            )
        })?;

    Ok(ResolvedOverride {
        param,
        module_instance,
    })
}

/// Splits an app-relative parameter ref into `(param_rel, module_instance)`.
///
/// For a module ref `MD-<d>_M-<m>_MI-<n>_<param>` returns
/// (`MD-<d>_<param>`, `Some("MD-<d>_M-<m>_MI-<n>")`); for a plain ref returns
/// the ref unchanged and `None`. Mirrors the model's `strip_module_instance`.
fn split_module_instance(param_ref: &str) -> (String, Option<String>) {
    if !param_ref.starts_with("MD-") {
        return (param_ref.to_string(), None);
    }
    let Some(m_pos) = param_ref.find("_M-") else {
        return (param_ref.to_string(), None);
    };
    let module_def = &param_ref[..m_pos]; // "MD-1"
    let after = &param_ref[m_pos + 1..]; // "M-3_MI-1_P-3"
    let Some(mi_pos) = after.find("_MI-") else {
        return (param_ref.to_string(), None);
    };
    let rest = &after[mi_pos + "_MI-".len()..]; // "1_P-3"
    let Some(obj_pos) = rest.find('_') else {
        return (param_ref.to_string(), None);
    };
    let instance = &rest[..obj_pos]; // "1"
    let param_part = &rest[obj_pos + 1..]; // "P-3"
    let selector = format!("{module_def}_{}_MI-{instance}", &after[..mi_pos]);
    (format!("{module_def}_{param_part}"), Some(selector))
}

/// The base image for a segment: its decoded `<Data>` if present, else empty.
fn base_image(app: &ApplicationProgram, seg_id: &str) -> Vec<u8> {
    app.code_segments
        .get(seg_id)
        .and_then(|s| s.data.clone())
        .unwrap_or_default()
}

/// An encoded parameter value ready to place.
enum Placement {
    /// One or more whole bytes, laid down starting at the byte offset. Used for
    /// byte-aligned payloads (text, float, byte-multiple ints at bit offset 0).
    Bytes(Vec<u8>),
    /// A bit field up to 64 bits wide, holding the unsigned `value`, placed
    /// MSB-first from `bit_offset` and allowed to span byte boundaries.
    Field { bits: u32, value: u64 },
    /// A no-op (e.g. a `TypeNone` marker) that occupies no memory.
    Empty,
}

/// Resolves the width/encoding of a value from its parameter type.
fn encode_value(
    app: &ApplicationProgram,
    pname: &str,
    ptype: Option<&ParameterType>,
    value: Option<&str>,
) -> Result<Placement> {
    match ptype {
        Some(ParameterType::Int {
            size_bits,
            signed,
            min,
            max,
        }) => encode_int(app, pname, *size_bits, *signed, *min, *max, value),
        Some(ParameterType::Enum { size_bits, values }) => {
            // Enum default is the raw numeric value; validate it is a declared
            // member when it parses, but always encode the number.
            let raw = value.unwrap_or("0");
            let n: i64 = raw.trim().parse().map_err(|_| {
                param_err(app, pname, &format!("enum value `{raw}` is not an integer"))
            })?;
            if !values.is_empty() && !values.iter().any(|e| e.value == n) {
                return Err(param_err(
                    app,
                    pname,
                    &format!("value `{n}` is not a declared enumeration member"),
                ));
            }
            encode_int_bits(app, pname, size_bits.unwrap_or(8), false, n)
        }
        Some(ParameterType::Text { size_bits }) => {
            let len = (size_bits.unwrap_or(0) / 8) as usize;
            let s = value.unwrap_or("");
            let bytes = s.as_bytes();
            if bytes.len() > len {
                return Err(param_err(
                    app,
                    pname,
                    &format!(
                        "text `{s}` is {} bytes but the field holds {len}",
                        bytes.len()
                    ),
                ));
            }
            let mut buf = vec![0u8; len];
            buf[..bytes.len()].copy_from_slice(bytes);
            Ok(Placement::Bytes(buf))
        }
        Some(ParameterType::Float { .. }) => {
            let raw = value.unwrap_or("0");
            let f: f32 = raw.trim().parse().map_err(|_| {
                param_err(app, pname, &format!("float value `{raw}` is not a number"))
            })?;
            let enc = encode_float16(f).map_err(|_| {
                param_err(
                    app,
                    pname,
                    &format!("float value `{f}` is out of DPT-9 range"),
                )
            })?;
            Ok(Placement::Bytes(enc.to_vec()))
        }
        Some(ParameterType::None) | None => Ok(Placement::Empty),
        Some(ParameterType::Other { size_bits, kind }) => {
            // Unknown shape: if it declares a byte-multiple width and the value
            // is a plain integer, place it big-endian; else refuse rather than
            // guess.
            match (size_bits, value) {
                (Some(bits), Some(v)) if bits % 8 == 0 => {
                    let n: i64 = v.trim().parse().map_err(|_| {
                        param_err(app, pname, &format!("{kind} value `{v}` is not an integer"))
                    })?;
                    encode_int_bits(app, pname, *bits, false, n)
                }
                _ => Ok(Placement::Empty),
            }
        }
    }
}

/// Encodes a `<TypeNumber>` value, honouring declared min/max and signedness.
fn encode_int(
    app: &ApplicationProgram,
    pname: &str,
    size_bits: Option<u32>,
    signed: bool,
    min: Option<i64>,
    max: Option<i64>,
    value: Option<&str>,
) -> Result<Placement> {
    let raw = value.unwrap_or("0");
    let n: i64 = raw.trim().parse().map_err(|_| {
        param_err(
            app,
            pname,
            &format!("integer value `{raw}` is not an integer"),
        )
    })?;
    if let Some(lo) = min {
        if n < lo {
            return Err(param_err(
                app,
                pname,
                &format!("value {n} is below the declared minimum {lo}"),
            ));
        }
    }
    if let Some(hi) = max {
        if n > hi {
            return Err(param_err(
                app,
                pname,
                &format!("value {n} is above the declared maximum {hi}"),
            ));
        }
    }
    encode_int_bits(app, pname, size_bits.unwrap_or(8), signed, n)
}

/// Encodes an integer into a [`Placement`] of `bits` width, checking that the
/// value fits. Signed values are two's-complement within the width.
fn encode_int_bits(
    app: &ApplicationProgram,
    pname: &str,
    bits: u32,
    signed: bool,
    n: i64,
) -> Result<Placement> {
    if bits == 0 {
        return Ok(Placement::Empty);
    }
    // Represent the value as an unsigned bit pattern of `bits` width.
    let unsigned: u64 = if signed {
        let lo = -(1i64 << (bits - 1));
        let hi = (1i64 << (bits - 1)) - 1;
        if n < lo || n > hi {
            return Err(param_err(
                app,
                pname,
                &format!("value {n} does not fit in {bits} signed bits ({lo}..={hi})"),
            ));
        }
        // Two's-complement truncated to `bits`.
        (n as i128 as u128 & ((1u128 << bits) - 1)) as u64
    } else {
        if n < 0 {
            return Err(param_err(
                app,
                pname,
                &format!("negative value {n} in an unsigned {bits}-bit field"),
            ));
        }
        let max = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        if (n as u64) > max {
            return Err(param_err(
                app,
                pname,
                &format!("value {n} does not fit in {bits} unsigned bits (max {max})"),
            ));
        }
        n as u64
    };

    if bits > 64 {
        // Integers wider than 64 bits do not occur in ETS parameter memory.
        return Err(param_err(
            app,
            pname,
            &format!("unsupported integer field width of {bits} bits"),
        ));
    }
    // A general MSB-first bit field: `place` writes it into the byte image at
    // the parameter's `BitOffset`, spanning byte boundaries where needed (ETS
    // uses e.g. 15-bit fields at bit offset 1).
    Ok(Placement::Field {
        bits,
        value: unsigned,
    })
}

/// Bounds a placement before it grows an image, then delegates to [`place`].
///
/// The parameter's byte `offset` and its payload length both originate in
/// untrusted vendor XML, so their sum (the image end this placement forces) is
/// checked against the segment's declared `Size` when present, and against
/// [`MAX_SEGMENT_IMAGE`] when it is absent. A parameter whose end runs past that
/// bound is refused by name rather than resizing the image to an absurd length
/// (guarding the `image.resize(offset + bytes.len(), 0)` allocation in `place`).
fn place_checked(
    app: &ApplicationProgram,
    pname: &str,
    image: &mut Vec<u8>,
    offset: usize,
    bit_offset: u8,
    placement: &Placement,
    seg_size: Option<u32>,
) -> Result<()> {
    // The exclusive byte end this placement writes up to (bit fields round up).
    let end: u64 = match placement {
        Placement::Empty => offset as u64,
        Placement::Bytes(bytes) => (offset as u64).saturating_add(bytes.len() as u64),
        Placement::Field { bits, .. } => {
            let start_bit = (offset as u64)
                .saturating_mul(8)
                .saturating_add(u64::from(bit_offset));
            start_bit.saturating_add(u64::from(*bits)).div_ceil(8)
        }
    };
    let limit = match seg_size {
        Some(sz) => u64::from(sz),
        None => MAX_SEGMENT_IMAGE,
    };
    if end > limit {
        return Err(param_err(
            app,
            pname,
            &format!(
                "places bytes ending at offset {end} but the segment {} — refusing to \
                 grow the image past its bounds",
                seg_size
                    .map(|s| format!("declares Size {s}"))
                    .unwrap_or_else(|| format!("declares no Size (capped at {MAX_SEGMENT_IMAGE})")),
            ),
        ));
    }
    place(image, offset, bit_offset, placement);
    Ok(())
}

/// Places an encoded value into `image` at the byte offset (and bit offset for
/// bit fields), growing the image with zeros as needed. MSB-first throughout.
fn place(image: &mut Vec<u8>, offset: usize, bit_offset: u8, placement: &Placement) {
    match placement {
        Placement::Empty => {}
        Placement::Bytes(bytes) => {
            let end = offset + bytes.len();
            if image.len() < end {
                image.resize(end, 0);
            }
            image[offset..end].copy_from_slice(bytes);
        }
        Placement::Field { bits, value } => {
            let bits = *bits;
            // MSB-first bit stream: the field occupies bits
            // [start, start+bits) where `start = offset*8 + bit_offset`,
            // counting from the high bit of each byte. Fields may span byte
            // boundaries (ETS uses 15-bit fields at bit offset 1). We write the
            // value's bits from most to least significant, clearing then setting
            // each target bit so adjacent fields compose over a base image.
            let start = offset * 8 + bit_offset as usize;
            let end_byte = (start + bits as usize).div_ceil(8);
            if image.len() < end_byte {
                image.resize(end_byte, 0);
            }
            for i in 0..bits as usize {
                // Bit i of the field, MSB-first (i=0 is the value's high bit).
                let bit_val = (*value >> (bits as usize - 1 - i)) & 1;
                let pos = start + i;
                let byte = pos / 8;
                let shift = 7 - (pos % 8); // MSB-first within the byte.
                image[byte] &= !(1u8 << shift);
                image[byte] |= (bit_val as u8) << shift;
            }
        }
    }
}

/// Builds a [`ProdError::ParameterImage`] naming the parameter and reason.
fn param_err(_app: &ApplicationProgram, pname: &str, reason: &str) -> ProdError {
    ProdError::ParameterImage {
        parameter: pname.to_string(),
        reason: reason.to_string(),
    }
}

// ---------------------------------------------------------------------------
// KNX 2-byte float (DPT 9) encoding, self-contained for the clean-room boundary.
// ---------------------------------------------------------------------------

const FLOAT16_MIN: f32 = 0.01 * -2048.0 * 32768.0;
const FLOAT16_MAX: f32 = 0.01 * 2047.0 * 32768.0;

/// Encodes a value into a KNX 2-byte float (DPT 9.x), big-endian.
fn encode_float16(value: f32) -> std::result::Result<[u8; 2], ()> {
    if !value.is_finite() || !(FLOAT16_MIN..=FLOAT16_MAX).contains(&value) {
        return Err(());
    }
    let mut mantissa = (value * 100.0).round() as i32;
    let mut exponent = 0i32;
    while !(-2048..=2047).contains(&mantissa) {
        if exponent >= 15 {
            return Err(());
        }
        mantissa = if mantissa >= 0 {
            (mantissa + 1) / 2
        } else {
            (mantissa - 1) / 2
        };
        exponent += 1;
    }
    let (sign, mant_bits) = if mantissa < 0 {
        (0x8000u16, (mantissa + 2048) as u16)
    } else {
        (0u16, mantissa as u16)
    };
    let raw = sign | ((exponent as u16) << 11) | (mant_bits & 0x07ff);
    Ok([(raw >> 8) as u8, (raw & 0xff) as u8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_ets::application::parse_application_program;

    fn no_overrides() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn no_bases() -> BTreeMap<String, u32> {
        BTreeMap::new()
    }

    /// Builds a one-segment app whose parameters are described inline. `params`
    /// is a list of `(name, type_xml, value_attr, offset, bit_offset)`; the type
    /// xml is the `<Type…/>` element for a `<ParameterType>`.
    fn app_with(params: &[(&str, &str, Option<&str>, u32, u8)]) -> ApplicationProgram {
        let mut pts = String::new();
        let mut ps = String::new();
        for (i, (name, ty, val, off, bit)) in params.iter().enumerate() {
            let ptid = format!("M-1_A-1_PT-{i}");
            pts.push_str(&format!(
                "<ParameterType Id=\"{ptid}\" Name=\"{name}t\">{ty}</ParameterType>"
            ));
            let value = val.map(|v| format!(" Value=\"{v}\"")).unwrap_or_default();
            ps.push_str(&format!(
                "<Parameter Id=\"M-1_A-1_P-{i}\" Name=\"{name}\" ParameterType=\"{ptid}\"{value}>\
                 <Memory CodeSegment=\"M-1_A-1_RS-1\" Offset=\"{off}\" BitOffset=\"{bit}\" /></Parameter>"
            ));
        }
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
             <ApplicationProgram Id="M-1_A-1" Name="t">
              <Static>
               <Code><RelativeSegment Id="M-1_A-1_RS-1" Size="64" LoadStateMachine="4" Offset="0" /></Code>
               <ParameterTypes>{pts}</ParameterTypes>
               <Parameters>{ps}</Parameters>
              </Static>
             </ApplicationProgram></KNX>"#
        );
        parse_application_program("M-1_A-1", xml.as_bytes()).unwrap()
    }

    fn image_of(app: &ApplicationProgram) -> Vec<u8> {
        let m = compute_parameter_image(app, &no_overrides(), &no_bases()).unwrap();
        m.get("M-1_A-1_RS-1").cloned().unwrap_or_default()
    }

    #[test]
    fn packs_full_byte_int() {
        let app = app_with(&[(
            "x",
            r#"<TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" />"#,
            Some("83"),
            0,
            0,
        )]);
        assert_eq!(image_of(&app)[0], 83);
    }

    #[test]
    fn packs_big_endian_16bit() {
        // Default 500 must appear as 0x01 0xF4 (big-endian), confirmed against
        // real ETS segment images.
        let app = app_with(&[(
            "x",
            r#"<TypeNumber SizeInBit="16" Type="unsignedInt" maxInclusive="65535" />"#,
            Some("500"),
            2,
            0,
        )]);
        let img = image_of(&app);
        assert_eq!(&img[2..4], &[0x01, 0xF4]);
    }

    #[test]
    fn packs_32bit_big_endian() {
        let app = app_with(&[(
            "x",
            r#"<TypeNumber SizeInBit="32" Type="unsignedInt" />"#,
            Some("66051"),
            0,
            0,
        )]);
        let img = image_of(&app);
        assert_eq!(&img[0..4], &[0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn adjacent_sub_byte_fields_compose_msb_first() {
        // Four 2-bit fields sharing byte 0 at bit offsets 0,2,4,6 with values
        // 3,2,1,0 -> MSB-first that is 11 10 01 00 = 0b1110_0100 = 0xE4.
        let ty = r#"<TypeNumber SizeInBit="2" Type="unsignedInt" maxInclusive="3" />"#;
        let app = app_with(&[
            ("a", ty, Some("3"), 0, 0),
            ("b", ty, Some("2"), 0, 2),
            ("c", ty, Some("1"), 0, 4),
            ("d", ty, Some("0"), 0, 6),
        ]);
        assert_eq!(image_of(&app)[0], 0b1110_0100);
    }

    #[test]
    fn one_bit_fields_pack_high_to_low() {
        // 1-bit fields at bit offsets 4,5,6,7 set to 1 -> 0b0000_1111 = 0x0F.
        let ty = r#"<TypeNumber SizeInBit="1" Type="unsignedInt" maxInclusive="1" />"#;
        let app = app_with(&[
            ("a", ty, Some("1"), 0, 4),
            ("b", ty, Some("1"), 0, 5),
            ("c", ty, Some("1"), 0, 6),
            ("d", ty, Some("1"), 0, 7),
        ]);
        assert_eq!(image_of(&app)[0], 0x0F);
    }

    #[test]
    fn one_bit_then_three_bit_field() {
        // 1-bit at offset 0 (=1) then 3-bit at offset 1 (=5=0b101).
        // MSB-first: 1 101 0000 = 0b1101_0000 = 0xD0.
        let app = app_with(&[
            (
                "a",
                r#"<TypeNumber SizeInBit="1" Type="unsignedInt" maxInclusive="1" />"#,
                Some("1"),
                0,
                0,
            ),
            (
                "b",
                r#"<TypeNumber SizeInBit="3" Type="unsignedInt" maxInclusive="7" />"#,
                Some("5"),
                0,
                1,
            ),
        ]);
        assert_eq!(image_of(&app)[0], 0b1101_0000);
    }

    #[test]
    fn enum_encodes_by_value() {
        let app = app_with(&[(
            "mode",
            r#"<TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="e0"/><Enumeration Text="On" Value="7" Id="e1"/></TypeRestriction>"#,
            Some("7"),
            0,
            0,
        )]);
        assert_eq!(image_of(&app)[0], 7);
    }

    #[test]
    fn enum_rejects_undeclared_value() {
        let app = app_with(&[(
            "mode",
            r#"<TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="e0"/></TypeRestriction>"#,
            Some("9"),
            0,
            0,
        )]);
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        assert!(err.to_string().contains("mode"), "{err}");
    }

    #[test]
    fn text_is_padded_with_zeros() {
        // 6-byte (48-bit) text "Hi" -> "Hi\0\0\0\0".
        let app = app_with(&[("label", r#"<TypeText SizeInBit="48" />"#, Some("Hi"), 0, 0)]);
        let img = image_of(&app);
        assert_eq!(&img[0..6], b"Hi\0\0\0\0");
    }

    #[test]
    fn text_too_long_errors() {
        let app = app_with(&[(
            "label",
            r#"<TypeText SizeInBit="16" />"#,
            Some("toolong"),
            0,
            0,
        )]);
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        assert!(err.to_string().contains("label"), "{err}");
    }

    #[test]
    fn signed_int_two_complement() {
        // -5 in an 8-bit signed field = 0xFB.
        let app = app_with(&[(
            "x",
            r#"<TypeNumber SizeInBit="8" Type="signedInt" minInclusive="-128" maxInclusive="127" />"#,
            Some("-5"),
            0,
            0,
        )]);
        assert_eq!(image_of(&app)[0], 0xFB);
    }

    #[test]
    fn value_exceeding_width_errors_naming_param() {
        let app = app_with(&[(
            "level",
            r#"<TypeNumber SizeInBit="2" Type="unsignedInt" />"#,
            Some("9"),
            0,
            0,
        )]);
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("level"), "{s}");
        assert!(s.contains("fit") || s.contains("maximum"), "{s}");
    }

    #[test]
    fn min_max_enforced() {
        let app = app_with(&[(
            "t",
            r#"<TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="10" maxInclusive="20" />"#,
            Some("5"),
            0,
            0,
        )]);
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        assert!(err.to_string().contains("minimum"), "{err}");
    }

    #[test]
    fn float_dpt9_encoding() {
        // 21.0 -> DPT9: mantissa 2100 -> halve to 1050 (exp 1) -> 0x0C1A? verify
        // by decoding is out of scope; just assert two bytes are written and the
        // top bit region is sane (non-zero).
        let app = app_with(&[(
            "temp",
            r#"<TypeFloat Encoding="DPT 9" minInclusive="-273" maxInclusive="670760" />"#,
            Some("21"),
            0,
            0,
        )]);
        let img = image_of(&app);
        // 21.0: mantissa=2100 needs exp=1 (1050), raw = (1<<11)|1050 = 0x0C1A.
        assert_eq!(&img[0..2], &[0x0C, 0x1A]);
    }

    #[test]
    fn user_override_beats_ref_and_default() {
        // Default 50, ParameterRef Value 75, user override 90 -> 90 wins.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="t"><Static>
          <Code><RelativeSegment Id="M-1_A-1_RS-1" Size="8" LoadStateMachine="4" Offset="0" /></Code>
          <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-1_A-1_P-0" Name="thr" ParameterType="M-1_A-1_PT-0" Value="50"><Memory CodeSegment="M-1_A-1_RS-1" Offset="0" BitOffset="0" /></Parameter></Parameters>
          <ParameterRefs><ParameterRef Id="M-1_A-1_P-0_R-1" RefId="M-1_A-1_P-0" Value="75" /></ParameterRefs>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-1", xml.as_bytes()).unwrap();

        // No override: ref Value 75 wins over default 50.
        let img = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 75);

        // User override 90 beats the ref. The override is keyed by the
        // app-relative ParameterRef id (P-0_R-1), NOT the parameter name.
        let mut ov = BTreeMap::new();
        ov.insert("P-0_R-1".to_string(), "90".to_string());
        let img = compute_parameter_image(&app, &ov, &no_bases()).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 90);

        // The fully-qualified ref id (app-prefixed) resolves identically.
        let mut ov = BTreeMap::new();
        ov.insert("M-1_A-1_P-0_R-1".to_string(), "13".to_string());
        let img = compute_parameter_image(&app, &ov, &no_bases()).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 13);
    }

    #[test]
    fn override_by_name_no_longer_applies() {
        // The old (broken) behaviour keyed overrides by parameter NAME. A name
        // key must now be a no-op resolution failure — proving the contract flip
        // to ref-id keying. A name is not a valid `..._R-<r>` ref id, so it is
        // rejected with the key named.
        let app = app_with(&[(
            "thr",
            r#"<TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" />"#,
            Some("50"),
            0,
            0,
        )]);
        let mut ov = BTreeMap::new();
        ov.insert("thr".to_string(), "90".to_string());
        let err = compute_parameter_image(&app, &ov, &no_bases()).unwrap_err();
        assert!(err.to_string().contains("thr"), "{err}");
        assert!(err.to_string().contains("ref suffix"), "{err}");
    }

    #[test]
    fn module_instances_land_at_distinct_offsets() {
        // One module parameter (MD-1_P-3, declared Offset 1, BaseOffset naming
        // MDA_P_Base) instantiated as two channels. Two overrides, keyed by their
        // distinct module-instance ref ids, must land at distinct effective
        // offsets = declared 1 + the per-instance base the caller supplies.
        // Evidence-anchored: the Jung MD-1 bases 310 (M-1_MI-1) and 442 (M-3_MI-1)
        // put P-3 at 311 and 443.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0004_A-1" Name="Jung"><Static>
          <Code><RelativeSegment Id="M-0004_A-1_RS-1" Size="512" LoadStateMachine="4" Offset="0" /></Code>
          <ParameterTypes><ParameterType Id="M-0004_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters>
           <Parameter Id="M-0004_A-1_MD-1_P-3" Name="_VA_Label" ParameterType="M-0004_A-1_PT-0" Value="0">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="1" BitOffset="0" BaseOffset="M-0004_A-1_MD-1_A-1" />
           </Parameter>
          </Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0004_A-1", xml.as_bytes()).unwrap();

        let mut ov = BTreeMap::new();
        ov.insert("MD-1_M-1_MI-1_P-3_R-45".to_string(), "17".to_string());
        ov.insert("MD-1_M-3_MI-1_P-3_R-45".to_string(), "42".to_string());

        let mut bases = BTreeMap::new();
        bases.insert("MD-1_M-1_MI-1".to_string(), 310u32);
        bases.insert("MD-1_M-3_MI-1".to_string(), 442u32);

        let img = compute_parameter_image(&app, &ov, &bases).unwrap();
        let seg = &img["M-0004_A-1_RS-1"];
        // Instance 1 at 1 + 310 = 311 holds 17; instance 3 at 1 + 442 = 443 holds
        // 42. The two values do NOT collide — the old name-keyed builder would
        // have collapsed both onto the single declared offset 1.
        assert_eq!(seg[311], 17, "instance M-1_MI-1 at offset 311");
        assert_eq!(seg[443], 42, "instance M-3_MI-1 at offset 443");
        // The declared offset 1 keeps the default (0), untouched by either.
        assert_eq!(seg[1], 0);
    }

    #[test]
    fn module_override_without_base_offset_is_refused() {
        // A module-instance override whose per-instance base offset was not
        // supplied cannot be placed; it must error (never misplace a byte),
        // naming the offending key.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-0004_A-1" Name="Jung"><Static>
          <Code><RelativeSegment Id="M-0004_A-1_RS-1" Size="512" LoadStateMachine="4" Offset="0" /></Code>
          <ParameterTypes><ParameterType Id="M-0004_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters>
           <Parameter Id="M-0004_A-1_MD-1_P-3" Name="_VA_Label" ParameterType="M-0004_A-1_PT-0" Value="0">
            <Memory CodeSegment="M-0004_A-1_RS-1" Offset="1" BitOffset="0" BaseOffset="M-0004_A-1_MD-1_A-1" />
           </Parameter>
          </Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-0004_A-1", xml.as_bytes()).unwrap();

        let mut ov = BTreeMap::new();
        ov.insert("MD-1_M-3_MI-1_P-3_R-45".to_string(), "42".to_string());

        // No base offsets supplied: the module override cannot be placed.
        let err = compute_parameter_image(&app, &ov, &no_bases()).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("MD-1_M-3_MI-1_P-3_R-45"), "{s}");
        assert!(s.contains("base offset") || s.contains("MI-1"), "{s}");
    }

    #[test]
    fn unknown_ref_id_override_is_refused() {
        // An override naming a parameter this application does not define is a
        // pre-flight error naming the key.
        let app = app_with(&[(
            "thr",
            r#"<TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" />"#,
            Some("50"),
            0,
            0,
        )]);
        let mut ov = BTreeMap::new();
        ov.insert("P-999_R-1".to_string(), "1".to_string());
        let err = compute_parameter_image(&app, &ov, &no_bases()).unwrap_err();
        assert!(err.to_string().contains("P-999"), "{err}");
    }

    #[test]
    fn param_value_beats_type_default_when_no_ref() {
        // Parameter Value present, no ref -> parameter Value used.
        let app = app_with(&[(
            "x",
            r#"<TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" />"#,
            Some("42"),
            0,
            0,
        )]);
        assert_eq!(image_of(&app)[0], 42);
    }

    #[test]
    fn params_laid_over_segment_base_data() {
        // Segment carries a base <Data> image; a parameter overwrites its byte
        // while bytes it does not touch keep the vendor's data.
        // Base image = [0xAA, 0xBB, 0xCC, 0xDD] (base64 "qrvM3Q==").
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="t"><Static>
          <Code><RelativeSegment Id="M-1_A-1_RS-1" Size="4" LoadStateMachine="4" Offset="0"><Data>qrvM3Q==</Data></RelativeSegment></Code>
          <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-1_A-1_P-0" Name="x" ParameterType="M-1_A-1_PT-0" Value="1"><Memory CodeSegment="M-1_A-1_RS-1" Offset="2" BitOffset="0" /></Parameter></Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-1", xml.as_bytes()).unwrap();
        let img = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap();
        // Byte 2 overwritten to 1; the rest keep the base image.
        assert_eq!(img["M-1_A-1_RS-1"], vec![0xAA, 0xBB, 0x01, 0xDD]);
    }

    #[test]
    fn sub_byte_over_base_data_preserves_other_bits() {
        // Base byte 0xFF; a 2-bit field at bit offset 0 set to 0b01 must clear
        // only its two high bits: 0b01_111111 = 0x7F.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="t"><Static>
          <Code><RelativeSegment Id="M-1_A-1_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>/w==</Data></RelativeSegment></Code>
          <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="2" Type="unsignedInt" maxInclusive="3" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-1_A-1_P-0" Name="x" ParameterType="M-1_A-1_PT-0" Value="1"><Memory CodeSegment="M-1_A-1_RS-1" Offset="0" BitOffset="0" /></Parameter></Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-1", xml.as_bytes()).unwrap();
        let img = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 0b0111_1111);
    }

    #[test]
    fn type_none_occupies_no_memory() {
        let app = app_with(&[("marker", r#"<TypeNone />"#, None, 0, 0)]);
        // No bytes placed -> empty image (segment had no base data).
        let img = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap();
        assert!(img["M-1_A-1_RS-1"].is_empty());
    }

    // ---------------------------------------------------------------------
    // Issue #53: bounds on parameter placement and segment payloads.
    // ---------------------------------------------------------------------

    #[test]
    fn parameter_offset_beyond_segment_size_errors_naming_it() {
        // The `app_with` segment declares Size=64. A byte parameter placed at
        // offset 100 ends at 101, past the segment; refuse and name the parameter
        // rather than resizing the image to an arbitrary length.
        let app = app_with(&[(
            "toofar",
            r#"<TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" />"#,
            Some("1"),
            100,
            0,
        )]);
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        match err {
            ProdError::ParameterImage { parameter, reason } => {
                assert_eq!(parameter, "toofar");
                assert!(reason.contains("Size"), "reason names the bound: {reason}");
            }
            other => panic!("expected ParameterImage, got {other:?}"),
        }
    }

    #[test]
    fn segment_data_longer_than_declared_size_errors() {
        // A <Data> payload longer than the segment's declared Size is corrupt
        // product data; refuse rather than seeding an over-sized base image.
        // Size=2 but the base64 `AAECAw==` decodes to 4 bytes.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="t"><Static>
          <Code><RelativeSegment Id="M-1_A-1_RS-1" Size="2" LoadStateMachine="4" Offset="0"><Data>AAECAw==</Data></RelativeSegment></Code>
          <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-1_A-1_P-0" Name="x" ParameterType="M-1_A-1_PT-0" Value="1"><Memory CodeSegment="M-1_A-1_RS-1" Offset="0" BitOffset="0" /></Parameter></Parameters>
         </Static></ApplicationProgram></KNX>"#;
        let app = parse_application_program("M-1_A-1", xml.as_bytes()).unwrap();
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        match err {
            ProdError::ParameterImage { reason, .. } => {
                assert!(reason.contains("Size"), "reason names Size: {reason}");
            }
            other => panic!("expected ParameterImage, got {other:?}"),
        }
    }

    #[test]
    fn parameter_end_past_cap_errors_when_segment_declares_no_size() {
        // With no declared Size, a parameter whose end exceeds the 1 MiB cap is
        // refused — no allocation of that size ever happens (a huge offset from
        // untrusted vendor XML would otherwise force a multi-MiB resize).
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram Id="M-1_A-1" Name="t"><Static>
          <Code><RelativeSegment Id="M-1_A-1_RS-1" LoadStateMachine="4" Offset="0" /></Code>
          <ParameterTypes><ParameterType Id="M-1_A-1_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType></ParameterTypes>
          <Parameters><Parameter Id="M-1_A-1_P-0" Name="huge" ParameterType="M-1_A-1_PT-0" Value="1"><Memory CodeSegment="M-1_A-1_RS-1" Offset="{}" BitOffset="0" /></Parameter></Parameters>
         </Static></ApplicationProgram></KNX>"#,
            MAX_SEGMENT_IMAGE + 10
        );
        let app = parse_application_program("M-1_A-1", xml.as_bytes()).unwrap();
        let err = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap_err();
        assert!(
            matches!(err, ProdError::ParameterImage { .. }),
            "expected ParameterImage, got {err:?}"
        );
    }

    /// A self-contained ApplicationProgram XML reproducing the DA.tp module
    /// parameter structure: a 256-byte `<Data>`-of-0xFF segment; three module
    /// parameters (speed off0 default5, steps off1 default4, color off2 default1),
    /// all with `BaseOffset=argPar`; 8 module instances (argPar 0,16,…,112); and a
    /// channel parameter block that references only speed and steps (not color).
    fn da_tp_param_app() -> ApplicationProgram {
        // base64 of 256 bytes of 0xFF (the segment's `<Data>` base image).
        let ff256 = concat!(
            "////////////////////////////////////////////////////////////////////////////////",
            "////////////////////////////////////////////////////////////////////////////////",
            "////////////////////////////////////////////////////////////////////////////////",
            "////////////////////////////////////////////////////////////////////////////////",
            "/////////////////////w==",
        );
        let bases = [
            (1, 0),
            (2, 16),
            (3, 32),
            (4, 48),
            (5, 64),
            (6, 80),
            (7, 96),
            (8, 112),
        ];
        let mut modules = String::new();
        for (ch, par) in bases {
            modules.push_str(&format!(
                r#"<Module Id="APP_MD-1_M-{ch}" RefId="APP_MD-1">
                     <Arguments>
                       <NumericArg RefId="APP_MD-1_A-1" Value="{ch}" />
                       <NumericArg RefId="APP_MD-1_A-3" Value="{par}" />
                     </Arguments>
                   </Module>"#
            ));
        }
        let enum8 = |name: &str| {
            format!(
                "<ParameterType Id=\"APP_PT-{name}\" Name=\"{name}\">\
                 <TypeRestriction Base=\"Value\" SizeInBit=\"8\">\
                 <Enumeration Text=\"a\" Value=\"1\" />\
                 <Enumeration Text=\"b\" Value=\"4\" />\
                 <Enumeration Text=\"c\" Value=\"5\" /></TypeRestriction></ParameterType>"
            )
        };
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
             <ApplicationProgram Id="APP" ApplicationNumber="9472" ApplicationVersion="16"
                MaskVersion="MV-07B0" Name="Dimming" LoadProcedureStyle="MergedProcedure">
              <Static>
               <Code><RelativeSegment Id="APP_RS-04" Size="256" LoadStateMachine="4" Offset="0"><Data>{ff256}</Data></RelativeSegment></Code>
               <ParameterTypes>{speed_ty}{steps_ty}{color_ty}</ParameterTypes>
               <Parameters>
                <Parameter Id="APP_MD-1_P-1" Name="speed" ParameterType="APP_PT-speed" Value="5"><Memory CodeSegment="APP_RS-04" Offset="0" BitOffset="0" BaseOffset="APP_MD-1_A-3" /></Parameter>
                <Parameter Id="APP_MD-1_P-2" Name="steps" ParameterType="APP_PT-steps" Value="4"><Memory CodeSegment="APP_RS-04" Offset="1" BitOffset="0" BaseOffset="APP_MD-1_A-3" /></Parameter>
                <Parameter Id="APP_MD-1_P-3" Name="color" ParameterType="APP_PT-color" Value="1"><Memory CodeSegment="APP_RS-04" Offset="2" BitOffset="0" BaseOffset="APP_MD-1_A-3" /></Parameter>
               </Parameters>
               <ParameterRefs>
                <ParameterRef Id="APP_MD-1_P-1_R-1" RefId="APP_MD-1_P-1" />
                <ParameterRef Id="APP_MD-1_P-2_R-2" RefId="APP_MD-1_P-2" />
               </ParameterRefs>
              </Static>
              <Dynamic>
               <Channel Id="APP_MD-1_CH-argCH" Number="argCH">
                <ParameterBlock Id="APP_MD-1_PB-1" Name="config">
                 <ParameterRefRef RefId="APP_MD-1_P-1_R-1" />
                 <ParameterRefRef RefId="APP_MD-1_P-2_R-2" />
                </ParameterBlock>
               </Channel>
               {modules}
              </Dynamic>
             </ApplicationProgram></KNX>"#,
            speed_ty = enum8("speed"),
            steps_ty = enum8("steps"),
            color_ty = enum8("color"),
        );
        parse_application_program("APP", xml.as_bytes()).expect("da_tp param app parses")
    }

    /// The default parameter image for the DA.tp module app: a 256-byte 0xFF base
    /// with speed=5 and steps=4 written per channel at `argPar+0`/`argPar+1`.
    /// `color` is never written (no channel references it), so its byte stays
    /// 0xFF.
    ///
    /// This is the *pure product-default* image. The real ETS→KNX-Virtual capture
    /// differs only in channel 1's `steps` byte (offset 1 = `05` instead of `04`),
    /// which is that live **project**'s "16 steps" override — project data, not
    /// product data. See [`obj4_matches_ets_capture_with_ch1_override`].
    #[test]
    fn obj4_default_expansion_writes_speed_and_steps_per_channel() {
        let app = da_tp_param_app();
        let images = compute_parameter_image(&app, &no_overrides(), &no_bases()).unwrap();
        let image = images.get("APP_RS-04").expect("segment image present");
        assert_eq!(image.len(), 256);

        // Every non-0xFF byte and its value.
        let non_ff: Vec<(usize, u8)> = image
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b != 0xFF)
            .map(|(i, &b)| (i, b))
            .collect();
        let expected: Vec<(usize, u8)> = (0..8)
            .flat_map(|ch| {
                let par = ch * 16;
                [(par, 5u8), (par + 1, 4u8)]
            })
            .collect();
        assert_eq!(non_ff, expected);
    }

    /// With channel 1's `steps` overridden to 5 ("16 steps"), the image matches
    /// ETS's exact 256-byte obj4 capture byte-for-byte: `05 05` on channel 1 and
    /// `05 04` on channels 2-8, everything else 0xFF.
    #[test]
    fn obj4_matches_ets_capture_with_ch1_override() {
        let app = da_tp_param_app();

        // The channel-1 `steps` override (project "16 steps" = enum value 5),
        // keyed by app-relative ParameterRef id with the module-instance selector
        // the override contract expects. The per-instance base offset for channel
        // 1 is argPar=0.
        let mut overrides = BTreeMap::new();
        overrides.insert("MD-1_M-1_MI-1_P-2_R-2".to_string(), "5".to_string());
        let mut base_offsets = BTreeMap::new();
        base_offsets.insert("MD-1_M-1_MI-1".to_string(), 0u32);

        let images = compute_parameter_image(&app, &overrides, &base_offsets).unwrap();
        let image = images.get("APP_RS-04").expect("segment image present");

        // Reconstruct ETS's exact 256-byte obj4: 0xFF base, ch1 = 05 05, ch2-8 =
        // 05 04, at argPar bases 0,16,…,112.
        let mut ets = vec![0xFFu8; 256];
        for ch in 0..8 {
            let par = ch * 16;
            ets[par] = 0x05; // speed = 5 (default) everywhere
            ets[par + 1] = if ch == 0 { 0x05 } else { 0x04 }; // steps: ch1=5, else 4
        }
        assert_eq!(image, &ets);
    }
}
