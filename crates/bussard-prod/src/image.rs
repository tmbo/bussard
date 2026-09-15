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

/// Builds the per-segment parameter memory images for `app`.
///
/// For every parameter carrying a `<Memory>` location, the effective value is
/// resolved through the override chain (lowest to highest precedence):
///
/// 1. the `ParameterType` default (`0`/empty when the parameter has no `Value`),
/// 2. the parameter's own `Value`,
/// 3. the value of the *first* `ParameterRef` pointing at the parameter that
///    carries a `Value` (refs are the per-channel instances; a single-instance
///    parameter has one ref),
/// 4. `overrides[parameter name]`, the caller's explicit choice.
///
/// The resolved value is encoded MSB-first big-endian into the byte image keyed
/// by the memory's `CodeSegment`. Returns a map from segment id to its image.
///
/// # Errors
///
/// Returns [`ProdError::ParameterImage`] naming the offending parameter if a
/// value cannot be parsed for its type, exceeds the field's declared width, or
/// the parameter's memory location is incomplete.
pub fn compute_parameter_image(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
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

    // Seed each targeted segment's image from its `<Data>` base (if any), else
    // empty; grow lazily as parameters are placed.
    let mut images: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    // Deterministic parameter order: by parameter id.
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

        // Resolve the effective value through the precedence chain.
        let value: Option<String> = param
            .name
            .as_deref()
            .and_then(|n| overrides.get(n))
            .cloned()
            .or_else(|| ref_value.get(param.id.as_str()).map(|s| s.to_string()))
            .or_else(|| param.default.clone());

        // The parameter type governs width and encoding.
        let ptype = param
            .parameter_type
            .as_deref()
            .and_then(|id| app.parameter_types.get(id))
            .map(|d| &d.kind);

        let Some(offset) = mem.offset else {
            return Err(param_err(app, pname, "memory block is missing its Offset"));
        };
        let bit_offset = mem.bit_offset.unwrap_or(0);

        // Encode the value into bytes plus a bit-width for sub-byte placement.
        let placement = encode_value(app, pname, ptype, value.as_deref())?;

        // Ensure the segment image exists and is large enough.
        let image = images
            .entry(seg_id.to_string())
            .or_insert_with(|| base_image(app, seg_id));

        place(image, offset as usize, bit_offset, &placement);
    }

    Ok(images)
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
        parse_application_program("M-1_A-1", &xml).unwrap()
    }

    fn image_of(app: &ApplicationProgram) -> Vec<u8> {
        let m = compute_parameter_image(app, &no_overrides()).unwrap();
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
        let err = compute_parameter_image(&app, &no_overrides()).unwrap_err();
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
        let err = compute_parameter_image(&app, &no_overrides()).unwrap_err();
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
        let err = compute_parameter_image(&app, &no_overrides()).unwrap_err();
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
        let err = compute_parameter_image(&app, &no_overrides()).unwrap_err();
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
        let app = parse_application_program("M-1_A-1", xml).unwrap();

        // No override: ref Value 75 wins over default 50.
        let img = compute_parameter_image(&app, &no_overrides()).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 75);

        // User override 90 beats the ref.
        let mut ov = BTreeMap::new();
        ov.insert("thr".to_string(), "90".to_string());
        let img = compute_parameter_image(&app, &ov).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 90);
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
        let app = parse_application_program("M-1_A-1", xml).unwrap();
        let img = compute_parameter_image(&app, &no_overrides()).unwrap();
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
        let app = parse_application_program("M-1_A-1", xml).unwrap();
        let img = compute_parameter_image(&app, &no_overrides()).unwrap();
        assert_eq!(img["M-1_A-1_RS-1"][0], 0b0111_1111);
    }

    #[test]
    fn type_none_occupies_no_memory() {
        let app = app_with(&[("marker", r#"<TypeNone />"#, None, 0, 0)]);
        // No bytes placed -> empty image (segment had no base data).
        let img = compute_parameter_image(&app, &no_overrides()).unwrap();
        assert!(img["M-1_A-1_RS-1"].is_empty());
    }
}
