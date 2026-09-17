//! Formatters for decoded telegrams: a coloured pretty line and JSON Lines.
//!
//! The pretty formatter is aligned and coloured by APCI kind, honouring
//! `NO_COLOR` and non-TTY output. The JSON formatter emits one object per line
//! with stable field names — this is what LLM tooling consumes, so the field
//! set is deliberately fixed.

use std::time::SystemTime;

use owo_colors::{OwoColorize, Style};
use serde_json::json;

use crate::decode::{ApciKind, DecodedTelegram, DestinationRef};
use crate::timefmt;

/// Formats the `HH:MM:SS.mmm` UTC wall-clock portion of a timestamp.
fn format_clock(ts: SystemTime) -> String {
    timefmt::to_clock(ts)
}

/// Formats the full RFC3339 UTC timestamp used in JSON output.
fn format_rfc3339(ts: SystemTime) -> String {
    timefmt::to_rfc3339(ts)
}

/// Renders `addr name` when a name is known, or just the address otherwise.
fn labelled(addr: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!("{addr} {n}"),
        None => addr.to_string(),
    }
}

/// A pretty, aligned, coloured one-line rendering of a telegram.
///
/// With `color` false (or under `NO_COLOR` / a pipe) no escape codes are
/// emitted, so the output is stable for snapshot tests. Unknown group addresses
/// (no name in the model) are dimmed; the line is tinted by APCI kind.
pub fn pretty_line(t: &DecodedTelegram, color: bool) -> String {
    let clock = format_clock(t.timestamp);

    let source = labelled(&t.source.to_string(), t.source_name.as_deref());
    let dest_addr = t.destination.to_string();
    let dest = labelled(&dest_addr, t.destination_name.as_deref());

    // The value section: "= <value>" for writes/responses, nothing for reads.
    let mut trailer = String::new();
    if let Some(value) = &t.value {
        trailer.push_str(&format!("= {value}"));
    }
    // Annotate with the DPT and sending object where known.
    let mut annotations: Vec<String> = Vec::new();
    if let Some(dpt) = &t.dpt {
        annotations.push(dpt.to_string());
    }
    if let Some(obj) = &t.object_name {
        annotations.push(format!("obj {obj:?}"));
    }
    if !annotations.is_empty() {
        trailer.push_str(&format!(" ({})", annotations.join(", ")));
    }

    // The base, uncoloured line with sensible column alignment.
    let arrow = t.apci.arrow();
    let mut line = format!("{clock}  {source:<24} {arrow} {dest:<24} {trailer}");
    // Trim trailing spaces produced by an empty trailer.
    let trimmed_len = line.trim_end().len();
    line.truncate(trimmed_len);

    if let Some(note) = &t.decode_note {
        line.push_str(&format!("  [{note}]"));
    }

    if !color {
        return line;
    }

    // Coloured rendering: rebuild with per-segment styles.
    let apci_style = apci_style(t.apci);
    let source_styled = style_addr(&source, t.source_name.is_some());
    let dest_styled = style_addr(&dest, t.destination_name.is_some());
    let arrow_styled = arrow.style(apci_style).to_string();

    let mut out = format!(
        "{}  {:<width_src$} {} {:<width_dst$} ",
        clock.dimmed(),
        source_styled,
        arrow_styled,
        dest_styled,
        // Pad using the *uncoloured* widths so alignment survives the escapes.
        width_src = pad_to(&source, 24),
        width_dst = pad_to(&dest, 24),
    );
    if let Some(value) = &t.value {
        out.push_str(&format!("= {}", value.style(apci_style).bold()));
    }
    if !annotations.is_empty() {
        out.push_str(&format!(
            " {}",
            format!("({})", annotations.join(", ")).dimmed()
        ));
    }
    let out = out.trim_end().to_string();
    if let Some(note) = &t.decode_note {
        format!("{out}  {}", format!("[{note}]").yellow())
    } else {
        out
    }
}

/// The padding width for a coloured segment: the field width, but never less
/// than the string's own length (so long names are not truncated).
fn pad_to(s: &str, width: usize) -> usize {
    width.max(s.len())
}

/// Styles an address+name segment; unknown (unnamed) addresses are dimmed.
fn style_addr(s: &str, known: bool) -> String {
    if known {
        s.to_string()
    } else {
        s.dimmed().to_string()
    }
}

/// The colour used for a given APCI kind.
fn apci_style(apci: ApciKind) -> Style {
    match apci {
        ApciKind::Write => Style::new().green(),
        ApciKind::Read => Style::new().blue(),
        ApciKind::Response => Style::new().cyan(),
        ApciKind::Other(_) => Style::new().magenta(),
    }
}

/// A single JSON [`Value`](serde_json::Value) for a telegram, with stable field
/// names.
///
/// Fields: `ts_utc` (RFC3339 UTC — matches the SQLite capture column),
/// `source`, `source_name`, `destination`, `destination_name`, `dest_type`
/// (`group`|`individual`), `apci`, `payload` (hex), `value` (display string),
/// `dpt`, `object_name` (the sending com-object's informational name), `note`.
/// Absent fields are `null` so the schema is uniform.
///
/// This is the shared projection: [`json_line`] serializes it to one JSON Lines
/// record, and the viz server extends it with a `seq` field before streaming.
/// Keep the field set here identical between both callers.
pub fn json_value(t: &DecodedTelegram) -> serde_json::Value {
    let dest_type = match t.destination {
        DestinationRef::Group(_) => "group",
        DestinationRef::Individual(_) => "individual",
    };
    let mut payload_hex = String::with_capacity(t.payload.len() * 2);
    for b in &t.payload {
        use std::fmt::Write;
        let _ = write!(payload_hex, "{b:02x}");
    }

    json!({
        "ts_utc": format_rfc3339(t.timestamp),
        "source": t.source.to_string(),
        "source_name": t.source_name,
        "destination": t.destination.to_string(),
        "destination_name": t.destination_name,
        "dest_type": dest_type,
        "apci": t.apci.tag(),
        "payload": payload_hex,
        "value": t.value.as_ref().map(|v| v.to_string()),
        "dpt": t.dpt.map(|d| d.to_string()),
        "object_name": t.object_name,
        "note": t.decode_note,
    })
}

/// A single JSON Lines record for a telegram, with stable field names.
///
/// A thin wrapper over [`json_value`] that serializes it to a one-line string.
/// The field set is documented on [`json_value`]; this is what LLM tooling
/// consumes.
pub fn json_line(t: &DecodedTelegram) -> String {
    // serde_json::Value serialization is infallible for a well-formed value.
    json_value(t).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    use bussard_model::codec::TypedValue;
    use bussard_model::{GroupAddress, IndividualAddress};

    fn ia(s: &str) -> IndividualAddress {
        s.parse().unwrap()
    }
    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    /// A fully-resolved write at t=1.5s past the epoch.
    fn sample() -> DecodedTelegram {
        DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(1_500),
            source: ia("1.1.30"),
            source_name: Some("Meteodata".to_string()),
            destination: DestinationRef::Group(ga("3/2/0")),
            destination_name: Some("Windalarm".to_string()),
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(TypedValue::Bool {
                value: true,
                label: "Alarm",
            }),
            dpt: Some("1.005".parse().unwrap()),
            object_name: Some("Windalarm 1".to_string()),
            decode_note: None,
        }
    }

    #[test]
    fn pretty_no_color_exact() {
        let line = pretty_line(&sample(), false);
        assert_eq!(
            line,
            "00:00:01.500  1.1.30 Meteodata         → 3/2/0 Windalarm          = Alarm (1.005, obj \"Windalarm 1\")"
        );
    }

    #[test]
    fn pretty_no_color_has_no_escapes() {
        let line = pretty_line(&sample(), false);
        assert!(!line.contains('\u{1b}'), "should have no ANSI escapes");
    }

    #[test]
    fn pretty_read_has_no_value_section() {
        let mut t = sample();
        t.apci = ApciKind::Read;
        t.value = None;
        t.payload = vec![];
        let line = pretty_line(&t, false);
        assert!(line.contains("?→"));
        assert!(!line.contains('='), "read has no value: {line:?}");
    }

    #[test]
    fn pretty_note_is_appended() {
        let mut t = sample();
        t.decode_note = Some("payload is 1 byte, but DPT 9.001 expects 2 bytes".to_string());
        let line = pretty_line(&t, false);
        assert!(line.ends_with("[payload is 1 byte, but DPT 9.001 expects 2 bytes]"));
    }

    #[test]
    fn json_line_stable_fields() {
        let line = json_line(&sample());
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["ts_utc"], "1970-01-01T00:00:01.500Z");
        assert_eq!(v["source"], "1.1.30");
        assert_eq!(v["source_name"], "Meteodata");
        assert_eq!(v["destination"], "3/2/0");
        assert_eq!(v["destination_name"], "Windalarm");
        assert_eq!(v["dest_type"], "group");
        assert_eq!(v["apci"], "write");
        assert_eq!(v["payload"], "01");
        assert_eq!(v["value"], "Alarm");
        assert_eq!(v["dpt"], "1.005");
        assert_eq!(v["object_name"], "Windalarm 1");
        assert_eq!(v["note"], serde_json::Value::Null);
    }

    #[test]
    fn json_value_field_set_is_exact() {
        // The viz server extends this object with `seq`; if the field set drifts,
        // the frontend contract and the JSON Lines schema both break. Pin it.
        let v = json_value(&sample());
        let obj = v.as_object().expect("json_value is an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "apci",
                "dest_type",
                "destination",
                "destination_name",
                "dpt",
                "note",
                "object_name",
                "payload",
                "source",
                "source_name",
                "ts_utc",
                "value",
            ]
        );
    }

    #[test]
    fn json_line_matches_json_value() {
        // The line form must be exactly the serialized value form.
        let t = sample();
        assert_eq!(json_line(&t), json_value(&t).to_string());
    }

    #[test]
    fn json_line_nulls_when_unknown() {
        let t = DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH,
            source: ia("1.1.1"),
            source_name: None,
            destination: DestinationRef::Group(ga("9/1/9")),
            destination_name: None,
            apci: ApciKind::Read,
            payload: vec![],
            value: None,
            dpt: None,
            object_name: None,
            decode_note: None,
        };
        let v: serde_json::Value = serde_json::from_str(&json_line(&t)).unwrap();
        assert_eq!(v["source_name"], serde_json::Value::Null);
        assert_eq!(v["value"], serde_json::Value::Null);
        assert_eq!(v["payload"], "");
        assert_eq!(v["apci"], "read");
    }

    #[test]
    fn unknown_ga_pretty_dims_when_colored() {
        // With color on, an unknown destination should include a dim escape.
        let mut t = sample();
        t.destination_name = None;
        t.dpt = None;
        t.object_name = None;
        let line = pretty_line(&t, true);
        assert!(
            line.contains('\u{1b}'),
            "colored output should have escapes"
        );
        // Sanity: the raw address is still present.
        assert!(line.contains("3/2/0"));
        // And a no-color render of the same telegram omits the (now unknown) name.
        let plain = pretty_line(&t, false);
        assert!(
            !plain.contains("Windalarm"),
            "unknown dest has no name: {plain:?}"
        );
        let _ = BTreeMap::<u8, u8>::new();
    }
}
