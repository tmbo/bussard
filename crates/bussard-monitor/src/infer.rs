//! Inferring a datapoint type and a name for a group address from live traffic
//! (issue #95).
//!
//! A house without a project file has hundreds of group addresses with
//! placeholder names and no DPT. The only evidence available is what appears on
//! the bus: a payload of a certain length and value range, sent by a device the
//! model may already know. This module turns that evidence into ranked
//! [`DptCandidate`]s and a proposed name, as pure functions:
//!
//! - [`infer_dpt`] ranks the DPTs a payload could carry. It never claims
//!   [`Confidence::High`] for an ambiguous length; only a DPT declared by the
//!   sending com object earns that, and then it is ranked first.
//! - [`refine`] narrows a candidate set with further observations of the same
//!   group address.
//! - [`sending_object`] resolves the com object behind a `(sender, GA)` pair.
//! - [`propose_name`] builds a human name from the device's location, the
//!   channel name and the com-object function.
//!
//! Nothing here touches the bus or the filesystem, so every rule is unit
//! testable against a hand-built payload and an in-code model.

use bussard_model::codec::{TypedValue, decode};
use bussard_model::{ApduSize, Dpt, Flags, GroupAddress, IndividualAddress, Model};

/// How sure an inference is about one candidate.
///
/// [`Confidence::High`] is reserved for a DPT the sending com object declares
/// in the model; payload shape alone never earns it, because most KNX payload
/// lengths are shared by several datapoint types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// The payload merely permits this DPT.
    Low,
    /// The payload's length and value range fit this DPT well.
    Medium,
    /// The sending com object declares this DPT in the model.
    High,
}

impl Confidence {
    /// A short, stable lowercase tag for JSON output and display.
    pub fn tag(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }

    /// The next confidence up, saturating below [`Confidence::High`].
    ///
    /// Narrowing by observation can raise `Low` to `Medium` but never reaches
    /// `High`: only a declared DPT does.
    fn promoted(self) -> Confidence {
        match self {
            Confidence::Low => Confidence::Medium,
            other => other,
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

/// One candidate datapoint type for an observed payload, with the reasoning
/// that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DptCandidate {
    /// The candidate datapoint type.
    pub dpt: Dpt,
    /// How sure the inference is.
    pub confidence: Confidence,
    /// A human sentence explaining why this DPT is a candidate. Shown verbatim
    /// by `bussard learn` and returned by the `knx_infer_group` MCP tool.
    pub reason: String,
}

impl DptCandidate {
    /// Builds a candidate. `dpt` is parsed from a literal the callers control,
    /// so an unparsable one is dropped rather than panicking (there is no
    /// sensible fallback and a bad literal is a programming error caught by the
    /// unit tests below).
    fn new(dpt: &str, confidence: Confidence, reason: impl Into<String>) -> Option<DptCandidate> {
        Some(DptCandidate {
            dpt: dpt.parse().ok()?,
            confidence,
            reason: reason.into(),
        })
    }
}

/// Whether a payload of `len` bytes is the width `dpt` declares.
///
/// A sub-byte DPT (main 1/2/3) occupies a single small-APDU octet on the wire,
/// so it matches a one-byte payload.
fn size_fits(dpt: Dpt, len: usize) -> bool {
    match dpt.expected_size() {
        Some(ApduSize::Bits(_)) => len == 1,
        Some(ApduSize::Bytes(n)) => len == n as usize,
        // A DPT whose width bussard does not model cannot be contradicted.
        None => true,
    }
}

/// Ranks the datapoint types an observed payload could carry, best first.
///
/// `declared` is the DPT the *sending com object* declares in the model, if the
/// model knows it. When it is present and its width matches the payload it is
/// returned first with [`Confidence::High`] — that is the only way a candidate
/// reaches `High`. A declared DPT whose width contradicts the payload is still
/// reported, but last and with [`Confidence::Low`], naming the disagreement.
///
/// An empty payload (a `GroupValueRead`) yields no candidates.
///
/// ```
/// use bussard_monitor::infer::{infer_dpt, Confidence};
///
/// // A one-bit switch telegram.
/// let candidates = infer_dpt(&[0x01], None);
/// assert_eq!(candidates[0].dpt.to_string(), "1.001");
/// // Shape alone never claims certainty.
/// assert_eq!(candidates[0].confidence, Confidence::Medium);
/// ```
pub fn infer_dpt(payload: &[u8], declared: Option<Dpt>) -> Vec<DptCandidate> {
    let mut out: Vec<DptCandidate> = Vec::new();

    let declared_fits = declared
        .map(|d| size_fits(d, payload.len()))
        .unwrap_or(false);
    if let Some(dpt) = declared
        && declared_fits
    {
        out.extend(DptCandidate::new(
            &dpt.to_string(),
            Confidence::High,
            format!("the sending com object declares DPT {dpt} in the model"),
        ));
    }

    out.extend(by_shape(payload));

    // Drop duplicates, keeping the highest-ranked occurrence.
    let mut seen: Vec<Dpt> = Vec::with_capacity(out.len());
    out.retain(|c| {
        if seen.contains(&c.dpt) {
            false
        } else {
            seen.push(c.dpt);
            true
        }
    });

    // A declared DPT that contradicts the wire is reported last: the model may
    // be wrong, or the device may be sending something else on this GA.
    if let Some(dpt) = declared
        && !declared_fits
        && !payload.is_empty()
    {
        let expected = dpt
            .expected_size()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "an unmodelled width".to_string());
        out.extend(DptCandidate::new(
            &dpt.to_string(),
            Confidence::Low,
            format!(
                "the sending com object declares DPT {dpt} ({expected}), but the payload is \
                     {} byte(s); the model and the wire disagree",
                payload.len()
            ),
        ));
    }

    out
}

/// The shape-only candidates for a payload, best first.
fn by_shape(payload: &[u8]) -> Vec<DptCandidate> {
    match payload.len() {
        0 => Vec::new(),
        1 => one_byte(payload[0]),
        2 => two_bytes(payload),
        3 => three_bytes(payload),
        4 => four_bytes(payload),
        6 => vec![DptCandidate::new(
            "251.600",
            Confidence::Low,
            "a 6-byte payload is the width of an RGBW colour value (251.600)",
        )]
        .into_iter()
        .flatten()
        .collect(),
        8 => vec![DptCandidate::new(
            "19.001",
            Confidence::Low,
            "an 8-byte payload is the width of the combined date and time (19.001)",
        )]
        .into_iter()
        .flatten()
        .collect(),
        14 => fourteen_bytes(payload),
        _ => Vec::new(),
    }
}

/// Candidates for a single payload octet.
///
/// A 1-bit DPT is packed into the APDU's low six bits and reaches the decoder as
/// one octet, so a value of 0 or 1 is read as a switching object first; a larger
/// value can only be a byte-wide DPT.
fn one_byte(value: u8) -> Vec<DptCandidate> {
    let mut out = Vec::new();
    if value <= 1 {
        out.push(DptCandidate::new(
            "1.001",
            Confidence::Medium,
            format!(
                "a 1-bit payload (value {value}); switching (1.001) is the most common 1-bit object"
            ),
        ));
        for (dpt, what) in [
            ("1.002", "boolean"),
            ("1.008", "up/down"),
            ("1.009", "open/closed"),
            ("1.005", "alarm"),
        ] {
            out.push(DptCandidate::new(
                dpt,
                Confidence::Low,
                format!("a 1-bit payload also fits {dpt} ({what})"),
            ));
        }
        out.push(DptCandidate::new(
            "5.001",
            Confidence::Low,
            "a byte-wide DPT such as 5.001 can carry this value too; only the sending com \
             object's declared width settles it",
        ));
        return out.into_iter().flatten().collect();
    }

    if value <= 100 {
        out.push(DptCandidate::new(
            "5.001",
            Confidence::Medium,
            format!(
                "a 1-byte payload in 0..=100 (value {value}); a percentage (5.001) is the most \
                 common byte-wide object"
            ),
        ));
        out.push(DptCandidate::new(
            "5.010",
            Confidence::Low,
            format!("an unscaled 1-byte counter (5.010) would read {value}"),
        ));
        if value <= 63 {
            out.push(DptCandidate::new(
                "17.001",
                Confidence::Low,
                format!("a scene number (17.001) is 0..=63, so {value} fits"),
            ));
        }
    } else {
        out.push(DptCandidate::new(
            "5.010",
            Confidence::Medium,
            format!(
                "a 1-byte payload above 100 (value {value}); an unscaled counter (5.010) fits, a \
                 percentage would have to be scaled"
            ),
        ));
        out.push(DptCandidate::new(
            "5.001",
            Confidence::Low,
            format!(
                "a percentage (5.001) is scaled 0..=255 to 0..=100 %, so {value} would read \
                 {:.0} %",
                value as f32 * 100.0 / 255.0
            ),
        ));
    }
    out.into_iter().flatten().collect()
}

/// Plausible ranges for the common 2-byte float quantities.
const TEMPERATURE_RANGE: std::ops::RangeInclusive<f32> = -30.0..=60.0;
/// Relative humidity, in percent.
const HUMIDITY_RANGE: std::ops::RangeInclusive<f32> = 0.0..=100.0;
/// Illuminance, in lux.
const LUX_RANGE: std::ops::RangeInclusive<f32> = 0.0..=100_000.0;

/// Candidates for a two-octet payload.
///
/// Two octets are shared by the 2-byte float (9.xxx) and the 2-byte unsigned
/// integer (7.xxx). The float is decoded and its value is matched against the
/// plausible ranges for the quantities a house actually puts on the bus.
fn two_bytes(payload: &[u8]) -> Vec<DptCandidate> {
    let mut out = Vec::new();
    let float = float16_value(payload);
    let raw = u16::from_be_bytes([payload[0], payload[1]]);

    if let Some(f) = float {
        let temperature = TEMPERATURE_RANGE.contains(&f);
        let humidity = HUMIDITY_RANGE.contains(&f);
        let lux = LUX_RANGE.contains(&f);
        if temperature {
            out.push(DptCandidate::new(
                "9.001",
                Confidence::Medium,
                format!("a 2-byte float reading {f:.2}, inside the plausible temperature range"),
            ));
        }
        if humidity {
            out.push(DptCandidate::new(
                "9.007",
                if temperature {
                    Confidence::Low
                } else {
                    Confidence::Medium
                },
                format!("a 2-byte float reading {f:.2}, which also fits humidity in percent"),
            ));
        }
        if lux {
            out.push(DptCandidate::new(
                "9.004",
                if temperature || humidity {
                    Confidence::Low
                } else {
                    Confidence::Medium
                },
                format!("a 2-byte float reading {f:.2}, which also fits illuminance in lux"),
            ));
        }
        if !temperature && !humidity && !lux {
            out.push(DptCandidate::new(
                "9.001",
                Confidence::Low,
                format!(
                    "a 2-byte float reading {f:.2}; outside every common quantity's plausible \
                     range, so the 9.xxx subtype is a guess"
                ),
            ));
        }
    }

    out.push(DptCandidate::new(
        "7.001",
        Confidence::Low,
        format!("a 2-byte unsigned integer (7.xxx) would read {raw}"),
    ));
    out.into_iter().flatten().collect()
}

/// Candidates for a three-octet payload: time of day and calendar date, each
/// admitted only when every field is in range.
fn three_bytes(payload: &[u8]) -> Vec<DptCandidate> {
    let mut out = Vec::new();

    let weekday = payload[0] >> 5;
    let hour = payload[0] & 0x1f;
    let minute = payload[1] & 0x3f;
    let second = payload[2] & 0x3f;
    if hour <= 23 && minute <= 59 && second <= 59 && payload[1] <= 59 && payload[2] <= 59 {
        out.push(DptCandidate::new(
            "10.001",
            Confidence::Medium,
            format!(
                "a 3-byte payload whose fields are a valid time of day \
                 (weekday {weekday}, {hour:02}:{minute:02}:{second:02})"
            ),
        ));
    }

    let day = payload[0] & 0x1f;
    let month = payload[1] & 0x0f;
    let year = payload[2] & 0x7f;
    if (1..=31).contains(&day) && (1..=12).contains(&month) && year <= 99 {
        out.push(DptCandidate::new(
            "11.001",
            Confidence::Medium,
            format!("a 3-byte payload whose fields are a valid date (day {day}, month {month})"),
        ));
    }

    out.push(DptCandidate::new(
        "232.600",
        Confidence::Low,
        "a 3-byte payload is also the width of an RGB colour value (232.600)",
    ));
    out.into_iter().flatten().collect()
}

/// Candidates for a four-octet payload: the 4-byte float and the 4-byte
/// integers.
fn four_bytes(payload: &[u8]) -> Vec<DptCandidate> {
    let bits = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let float = f32::from_bits(bits);
    let mut out = Vec::new();
    if float.is_finite() {
        out.push(DptCandidate::new(
            "14",
            Confidence::Medium,
            format!(
                "a 4-byte payload decoding as the IEEE-754 float {float}; pick the 14.xxx subtype \
                 that names the quantity"
            ),
        ));
    }
    out.push(DptCandidate::new(
        "12.001",
        Confidence::Low,
        format!("a 4-byte unsigned counter (12.001) would read {bits}"),
    ));
    out.push(DptCandidate::new(
        "13.001",
        Confidence::Low,
        format!(
            "a 4-byte signed counter (13.001) would read {}",
            bits as i32
        ),
    ));
    out.into_iter().flatten().collect()
}

/// Candidates for the 14-octet string payload.
fn fourteen_bytes(payload: &[u8]) -> Vec<DptCandidate> {
    let ascii = payload.iter().all(|b| *b == 0 || (0x20..0x7f).contains(b));
    let mut out = vec![DptCandidate::new(
        "16.001",
        Confidence::Medium,
        if ascii {
            "a 14-byte payload of printable characters: a text string (16.001)".to_string()
        } else {
            "a 14-byte payload: the width of a text string (16.001), though some bytes are not \
             printable ASCII"
                .to_string()
        },
    )];
    out.push(DptCandidate::new(
        "16.000",
        Confidence::Low,
        "16.000 is the ASCII-only variant of the same 14-byte string",
    ));
    out.into_iter().flatten().collect()
}

/// Decodes a two-octet payload as a DPT 9 float, if the codec can.
fn float16_value(payload: &[u8]) -> Option<f32> {
    let dpt = Dpt::new(9, Some(1));
    match decode(&dpt, payload) {
        TypedValue::Float { value, .. } => Some(value),
        _ => None,
    }
}

/// Narrows a candidate set with further payloads seen on the same group
/// address.
///
/// Every additional observation must also be explainable by a candidate for it
/// to survive. A [`Confidence::High`] candidate (one the sending com object
/// declares) is never dropped. When the extra observations narrow the set to a
/// single shape-derived candidate, that candidate is promoted one step, but
/// never to `High`.
///
/// If the observations cannot be reconciled at all — payloads of different
/// widths on one GA, which usually means two objects share the address — the
/// latest observation's candidates are returned at [`Confidence::Low`], with
/// the disagreement named in the reason.
///
/// ```
/// use bussard_monitor::infer::{infer_dpt, refine};
///
/// // First sighting: a single 0/1 octet, which reads as a switching object.
/// let first = infer_dpt(&[1], None);
/// assert_eq!(first[0].dpt.to_string(), "1.001");
/// // A later sighting of 200 on the same GA rules every 1-bit reading out.
/// let narrowed = refine(first, &[vec![200]]);
/// assert_eq!(narrowed.len(), 1);
/// assert_eq!(narrowed[0].dpt.to_string(), "5.001");
/// ```
pub fn refine(candidates: Vec<DptCandidate>, payloads: &[Vec<u8>]) -> Vec<DptCandidate> {
    let mut current = candidates;
    for payload in payloads {
        let observed = by_shape(payload);
        let before = current.len();
        let mut kept: Vec<DptCandidate> = current
            .into_iter()
            .filter(|c| c.confidence == Confidence::High || observed.iter().any(|o| o.dpt == c.dpt))
            .collect();

        if kept.is_empty() {
            current = observed
                .into_iter()
                .map(|mut c| {
                    c.confidence = Confidence::Low;
                    c.reason = format!(
                        "observations of this group address disagree (a {}-byte payload arrived \
                         after payloads of another width); {}",
                        payload.len(),
                        c.reason
                    );
                    c
                })
                .collect();
            continue;
        }

        // A single survivor out of several is real evidence: promote it once.
        if kept.len() == 1 && before > 1 {
            let only = &mut kept[0];
            if only.confidence != Confidence::High {
                only.confidence = only.confidence.promoted();
                only.reason = format!("{} (narrowed by a further observation)", only.reason);
            }
        }
        current = kept;
    }
    current
}

/// The com object behind a `(sender, group address)` pair, as the model knows
/// it.
///
/// Resolved from `links.yaml` (which owns the informational object name) plus
/// the sending device's generated com-object table (which owns the declared DPT,
/// the flags and the owning channel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendingObject {
    /// The ETS com-object number, the stable handle used by `links.yaml`.
    pub index: u16,
    /// The informational com-object name from `links.yaml`, if any.
    pub name: Option<String>,
    /// The DPT the device file declares for this object, if any.
    pub declared_dpt: Option<Dpt>,
    /// The object's communication flags, if the device file has the object.
    pub flags: Option<Flags>,
    /// The owning channel's key in the device file, if any.
    pub channel_key: Option<String>,
    /// The owning channel's display name, if the device file names it.
    pub channel_name: Option<String>,
}

/// Resolves the com object on `sender` whose sending group address is `ga`.
///
/// Returns `None` when the model has no link from that device to that GA, which
/// is the normal case while learning a house that was never imported from a
/// project file.
pub fn sending_object(
    model: &Model,
    sender: IndividualAddress,
    ga: GroupAddress,
) -> Option<SendingObject> {
    let links = model.links.links.get(&sender)?;
    let link = links.iter().find(|l| l.send == Some(ga))?;
    let device = model.devices.get(&sender).map(|d| &d.device);
    let com = device.and_then(|d| d.com_objects.get(&link.object));
    let channel_key = com.and_then(|c| c.channel.clone());
    let channel_name = channel_key
        .as_ref()
        .and_then(|key| device.and_then(|d| d.channels.get(key)))
        .map(|c| c.name.clone());

    Some(SendingObject {
        index: link.object,
        name: link.name.clone(),
        declared_dpt: com.and_then(|c| c.dpt),
        flags: com.map(|c| c.flags),
        channel_key,
        channel_name,
    })
}

/// Proposes a human name for a group address from the sending device's
/// location, channel and com-object function.
///
/// The shape is `"<place> <thing>, <function>"`, e.g.
/// `"Kitchen ceiling light, switch"`: the room from the device's `location`, the
/// thing from the owning channel's name (or the device's own name when the
/// object has no channel), and the function from the com-object name in
/// `links.yaml`. Parts the model does not know are left out; a room already
/// named in the channel or device name is not repeated.
///
/// Returns `None` when the model does not know the sending device at all, so a
/// caller can fall back to asking the human.
pub fn propose_name(
    model: &Model,
    sender_ia: IndividualAddress,
    com_object_index: u16,
) -> Option<String> {
    let loaded = model.devices.get(&sender_ia)?;
    let device = &loaded.device;

    let room = device
        .location
        .as_ref()
        .and_then(|l| l.room.clone().or_else(|| l.floor.clone()))
        .filter(|r| !r.trim().is_empty());

    let channel = device
        .com_objects
        .get(&com_object_index)
        .and_then(|c| c.channel.as_ref())
        .and_then(|key| device.channels.get(key))
        .map(|c| c.name.clone())
        .filter(|n| !n.trim().is_empty());

    let thing = channel.unwrap_or_else(|| device.name.clone());
    let thing = thing.trim().to_string();

    let head = match room {
        Some(room) if !contains_word(&thing, &room) => {
            format!("{room} {}", lowercase_lead(&thing))
        }
        _ => thing,
    };
    if head.trim().is_empty() {
        return None;
    }

    let function = model
        .links
        .links
        .get(&sender_ia)
        .and_then(|links| links.iter().find(|l| l.object == com_object_index))
        .and_then(|l| l.name.clone())
        .map(|n| short_function(&n))
        .filter(|f| !f.is_empty() && !contains_word(&head, f));

    Some(match function {
        Some(function) => format!("{head}, {}", lowercase_lead(&function)),
        None => head,
    })
}

/// Shortens a com-object name to its function.
///
/// ETS object names are often prefixed with the channel ("Kanal A - Schalten",
/// "Ausgang 1: Status"); the part after the last separator is the function.
fn short_function(name: &str) -> String {
    let mut best = name.trim();
    for sep in [" - ", ": ", " – ", " | "] {
        if let Some((_, tail)) = best.rsplit_once(sep) {
            best = tail.trim();
        }
    }
    best.to_string()
}

/// Whether `haystack` already contains `needle` as a case-insensitive substring.
fn contains_word(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Lowercases the first character of `s`, unless its first word looks like an
/// acronym (all uppercase, more than one character), so "Ceiling light" becomes
/// "ceiling light" while "EG Flur" is left alone.
fn lowercase_lead(s: &str) -> String {
    let first_word = s.split_whitespace().next().unwrap_or("");
    let acronym = first_word.len() > 1
        && first_word
            .chars()
            .all(|c| !c.is_alphabetic() || c.is_uppercase());
    if acronym {
        return s.to_string();
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::error::Error;

    use bussard_model::LoadedDevice;
    use bussard_model::schema::{
        BussardConfig, Channel, ComObject, Device, Groups, Link, Links, Location,
    };

    type R = Result<(), Box<dyn Error>>;

    fn dpts(candidates: &[DptCandidate]) -> Vec<String> {
        candidates.iter().map(|c| c.dpt.to_string()).collect()
    }

    #[test]
    fn test_infer_dpt_one_bit_ranks_switching_first() -> R {
        for byte in [0u8, 1] {
            let out = infer_dpt(&[byte], None);
            assert_eq!(out[0].dpt, "1.001".parse()?, "byte {byte}");
            assert_eq!(out[0].confidence, Confidence::Medium);
            // The 1.xxx alternatives are offered, never as certainties.
            let names = dpts(&out);
            for alt in ["1.002", "1.008", "1.009"] {
                assert!(
                    names.iter().any(|d| d == alt),
                    "{alt} missing from {names:?}"
                );
            }
            assert!(
                out.iter().all(|c| c.confidence < Confidence::High),
                "shape alone must never claim high confidence"
            );
            assert!(out.iter().all(|c| !c.reason.is_empty()));
        }
        Ok(())
    }

    #[test]
    fn test_infer_dpt_one_byte_percent_before_counter() -> R {
        let out = infer_dpt(&[50], None);
        assert_eq!(out[0].dpt, "5.001".parse()?);
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert_eq!(out[1].dpt, "5.010".parse()?);
        Ok(())
    }

    #[test]
    fn test_infer_dpt_one_byte_above_hundred_prefers_counter() -> R {
        let out = infer_dpt(&[200], None);
        assert_eq!(out[0].dpt, "5.010".parse()?);
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert!(dpts(&out).contains(&"5.001".to_string()));
        Ok(())
    }

    #[test]
    fn test_infer_dpt_two_byte_temperature() -> R {
        // DPT 9 encoding of 21.5 °C.
        let payload = bussard_model::encode_float16(21.5)?;
        let out = infer_dpt(&payload, None);
        assert_eq!(out[0].dpt, "9.001".parse()?);
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert!(out[0].reason.contains("21.50"), "reason: {}", out[0].reason);
        // The 2-byte unsigned reading is offered as a lower-ranked alternative.
        assert!(dpts(&out).contains(&"7.001".to_string()));
        Ok(())
    }

    #[test]
    fn test_infer_dpt_two_byte_humidity_and_lux() -> R {
        // 85 % is outside the temperature range, so humidity leads.
        let humid = bussard_model::encode_float16(85.0)?;
        let out = infer_dpt(&humid, None);
        assert_eq!(out[0].dpt, "9.007".parse()?);
        assert_eq!(out[0].confidence, Confidence::Medium);

        // 12000 lux is outside both, so illuminance leads.
        let lux = bussard_model::encode_float16(12000.0)?;
        let out = infer_dpt(&lux, None);
        assert_eq!(out[0].dpt, "9.004".parse()?);
        assert_eq!(out[0].confidence, Confidence::Medium);
        Ok(())
    }

    #[test]
    fn test_infer_dpt_four_byte_float() -> R {
        let payload = 42.5f32.to_bits().to_be_bytes();
        let out = infer_dpt(&payload, None);
        assert_eq!(out[0].dpt.main, 14);
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert!(dpts(&out).contains(&"12.001".to_string()));
        assert!(dpts(&out).contains(&"13.001".to_string()));
        Ok(())
    }

    #[test]
    fn test_infer_dpt_three_byte_time_and_date() -> R {
        // Wednesday 14:30:05 — a valid time, not a valid date (month 30).
        let time = [(3u8 << 5) | 14, 30, 5];
        let out = infer_dpt(&time, None);
        assert_eq!(out[0].dpt, "10.001".parse()?);
        assert!(!dpts(&out).contains(&"11.001".to_string()));

        // 24 December 2026 — a valid date; hour 24 makes it an invalid time.
        let date = [24u8, 12, 26];
        let out = infer_dpt(&date, None);
        assert_eq!(out[0].dpt, "11.001".parse()?);
        assert!(!dpts(&out).contains(&"10.001".to_string()));
        Ok(())
    }

    #[test]
    fn test_infer_dpt_fourteen_byte_string() -> R {
        let mut payload = [0u8; 14];
        payload[..5].copy_from_slice(b"Hallo");
        let out = infer_dpt(&payload, None);
        assert_eq!(out[0].dpt, "16.001".parse()?);
        assert_eq!(out[0].confidence, Confidence::Medium);
        Ok(())
    }

    #[test]
    fn test_infer_dpt_two_byte_unsigned_alternative_present() -> R {
        let out = infer_dpt(&[0x00, 0x2a], None);
        assert!(dpts(&out).contains(&"7.001".to_string()));
        assert!(out.iter().all(|c| c.confidence < Confidence::High));
        Ok(())
    }

    #[test]
    fn test_infer_dpt_declared_wins_and_is_high() -> R {
        let declared: Dpt = "1.008".parse()?;
        let out = infer_dpt(&[1], Some(declared));
        assert_eq!(out[0].dpt, declared);
        assert_eq!(out[0].confidence, Confidence::High);
        // The declared DPT appears once, not twice.
        assert_eq!(out.iter().filter(|c| c.dpt == declared).count(), 1);
        Ok(())
    }

    #[test]
    fn test_infer_dpt_declared_of_wrong_width_is_demoted_and_last() -> R {
        let declared: Dpt = "9.001".parse()?;
        let out = infer_dpt(&[1], Some(declared));
        assert_ne!(
            out[0].dpt, declared,
            "a contradicted declaration cannot lead"
        );
        let last = out.last().expect("candidates");
        assert_eq!(last.dpt, declared);
        assert_eq!(last.confidence, Confidence::Low);
        assert!(last.reason.contains("disagree"), "reason: {}", last.reason);
        Ok(())
    }

    #[test]
    fn test_infer_dpt_empty_payload_has_no_candidates() {
        assert!(infer_dpt(&[], None).is_empty());
        assert!(infer_dpt(&[], "1.001".parse().ok()).is_empty());
    }

    #[test]
    fn test_refine_narrows_to_a_single_candidate() -> R {
        // A 0/1 octet looks like a switch; a later 200 on the same GA can only
        // be a byte-wide DPT, so exactly one candidate survives.
        let first = infer_dpt(&[1], None);
        assert!(first.len() > 1);
        let narrowed = refine(first, &[vec![200]]);
        assert_eq!(narrowed.len(), 1);
        assert_eq!(narrowed[0].dpt, "5.001".parse()?);
        // Narrowing raises confidence but never to `High`.
        assert_eq!(narrowed[0].confidence, Confidence::Medium);
        assert!(narrowed[0].reason.contains("narrowed"));
        Ok(())
    }

    #[test]
    fn test_refine_keeps_a_declared_candidate() -> R {
        let declared: Dpt = "5.001".parse()?;
        let first = infer_dpt(&[50], Some(declared));
        // A later two-byte payload contradicts the shape, but the declaration
        // survives.
        let out = refine(first, &[vec![0x0c, 0x1a]]);
        assert!(
            out.iter()
                .any(|c| c.dpt == declared && c.confidence == Confidence::High)
        );
        Ok(())
    }

    #[test]
    fn test_refine_reports_disagreeing_observations() -> R {
        let first = infer_dpt(&[1], None);
        let out = refine(first, &[vec![0x0c, 0x1a]]);
        assert!(!out.is_empty());
        assert!(
            out.iter().all(|c| c.confidence == Confidence::Low),
            "a contradiction must not leave a confident candidate"
        );
        assert!(
            out[0].reason.contains("disagree"),
            "reason: {}",
            out[0].reason
        );
        Ok(())
    }

    // --- model-derived proposals ---------------------------------------------

    fn model() -> Result<Model, Box<dyn Error>> {
        let mut channels = BTreeMap::new();
        channels.insert(
            "A".to_string(),
            Channel {
                name: "Ceiling light".to_string(),
                key: None,
                number: None,
                text: None,
            },
        );
        let mut com_objects = BTreeMap::new();
        com_objects.insert(
            3u16,
            ComObject {
                dpt: Some("1.001".parse()?),
                size: None,
                flags: Flags::COMMUNICATION | Flags::TRANSMIT,
                reference: None,
                channel: Some("A".to_string()),
                secure: false,
                function: None,
                key: None,
                text: None,
            },
        );
        let device = Device {
            address: "1.1.30".parse()?,
            name: "Schaltaktor".to_string(),
            description: None,
            location: Some(Location {
                floor: Some("EG".to_string()),
                room: Some("Kitchen".to_string()),
            }),
            product: None,
            channels,
            parameters: BTreeMap::new(),
            module_bases: BTreeMap::new(),
            com_objects,
            security: None,
            replaced: None,
            application_override: None,
            lock: Default::default(),
        };
        let mut devices = BTreeMap::new();
        devices.insert(
            device.address,
            LoadedDevice {
                device,
                file_stem: "1.1.30-schaltaktor".to_string(),
            },
        );
        let mut links = BTreeMap::new();
        links.insert(
            "1.1.30".parse()?,
            vec![Link {
                object: 3,
                name: Some("Kanal A - Schalten".to_string()),
                send: Some("1/0/1".parse()?),
                listen: Vec::new(),
            }],
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups::default(),
            links: Links { links },
            devices,
        })
    }

    #[test]
    fn test_sending_object_resolves_channel_and_declared_dpt() -> R {
        let m = model()?;
        let obj = sending_object(&m, "1.1.30".parse()?, "1/0/1".parse()?)
            .ok_or("the link should resolve")?;
        assert_eq!(obj.index, 3);
        assert_eq!(obj.name.as_deref(), Some("Kanal A - Schalten"));
        assert_eq!(obj.declared_dpt, Some("1.001".parse()?));
        assert_eq!(obj.channel_name.as_deref(), Some("Ceiling light"));
        assert!(obj.flags.is_some_and(|f| f.contains(Flags::TRANSMIT)));
        Ok(())
    }

    #[test]
    fn test_sending_object_none_for_unlinked_ga() -> R {
        let m = model()?;
        assert!(sending_object(&m, "1.1.30".parse()?, "1/0/9".parse()?).is_none());
        assert!(sending_object(&m, "1.1.99".parse()?, "1/0/1".parse()?).is_none());
        Ok(())
    }

    #[test]
    fn test_propose_name_from_room_channel_and_function() -> R {
        let m = model()?;
        let name = propose_name(&m, "1.1.30".parse()?, 3).ok_or("a name should be proposed")?;
        assert_eq!(name, "Kitchen ceiling light, schalten");
        Ok(())
    }

    #[test]
    fn test_propose_name_falls_back_to_device_name() -> R {
        let mut m = model()?;
        // An object with no channel: the device name carries the thing.
        let dev = m
            .devices
            .get_mut(&"1.1.30".parse()?)
            .ok_or("device present")?;
        dev.device.com_objects.clear();
        let name = propose_name(&m, "1.1.30".parse()?, 3).ok_or("a name should be proposed")?;
        assert!(name.starts_with("Kitchen schaltaktor"), "got {name}");
        Ok(())
    }

    #[test]
    fn test_propose_name_none_for_unknown_device() -> R {
        let m = model()?;
        assert!(propose_name(&m, "1.1.99".parse()?, 3).is_none());
        Ok(())
    }

    #[test]
    fn test_propose_name_does_not_repeat_the_room() -> R {
        let mut m = model()?;
        let dev = m
            .devices
            .get_mut(&"1.1.30".parse()?)
            .ok_or("device present")?;
        dev.device.channels.insert(
            "A".to_string(),
            Channel {
                name: "Kitchen ceiling light".to_string(),
                key: None,
                number: None,
                text: None,
            },
        );
        let name = propose_name(&m, "1.1.30".parse()?, 3).ok_or("a name should be proposed")?;
        assert_eq!(name, "Kitchen ceiling light, schalten");
        Ok(())
    }

    #[test]
    fn test_short_function_strips_the_channel_prefix() {
        assert_eq!(short_function("Kanal A - Schalten"), "Schalten");
        assert_eq!(short_function("Ausgang 1: Status"), "Status");
        assert_eq!(short_function("Schalten"), "Schalten");
    }
}
