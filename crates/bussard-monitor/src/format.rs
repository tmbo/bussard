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
use crate::secure::SecureStatus;
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
    let secure = secure_tag(t);
    if let Some(tag) = &secure {
        line.push_str(&format!("  [{tag}]"));
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
    let mut out = out.trim_end().to_string();
    if let Some(note) = &t.decode_note {
        out = format!("{out}  {}", format!("[{note}]").yellow());
    }
    match (&secure, &t.secure) {
        (Some(tag), Some(info)) if info.verified() && info.warning.is_none() => {
            format!("{out}  {}", format!("[{tag}]").green())
        }
        (Some(tag), _) => format!("{out}  {}", format!("[{tag}]").red()),
        _ => out,
    }
}

/// The short KNX Data Secure marker of a telegram decoded with a keyring:
/// `secured`, `secured (MAC failed) …` or `secured (no group key) …` with the
/// sequence and the raw ASDU, plus any freshness warning. `None` for plain
/// traffic.
fn secure_tag(t: &DecodedTelegram) -> Option<String> {
    let info = t.secure.as_ref()?;
    let mut tag = match info.status {
        SecureStatus::Verified => {
            let alg = crate::secure::algorithm_label(info.scf);
            if alg == "auth" {
                "secured, auth only".to_string()
            } else {
                "secured".to_string()
            }
        }
        SecureStatus::MacFailed => format!("secured (MAC failed) seq={}", info.sequence),
        SecureStatus::NoKey => format!("secured (no group key) seq={}", info.sequence),
    };
    if let Some(raw) = &info.raw_asdu {
        tag.push_str(&format!(" raw={}", hex(raw)));
    }
    if let Some(warning) = &info.warning {
        tag.push_str(&format!("; warning: {warning}"));
    }
    Some(tag)
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
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
/// A KNX Data Secure group telegram decoded with a keyring (issue #172) adds
/// `secured` (`true` when the MAC verified), `secure_status` (`ok`,
/// `mac_failed`, `no_key`), `secure_seq` (the sender's sequence number),
/// `secure_raw` (the raw ASDU hex when it did not verify, else `null`) and
/// `secure_warning` (an advisory freshness warning or `null`). Plain telegrams
/// carry none of these, so their records are unchanged.
///
/// This is the shared projection: [`json_line`] serializes it to one JSON Lines
/// record, and the viz server extends it with a `seq` field before streaming.
/// Keep the field set here identical between both callers.
pub fn json_value(t: &DecodedTelegram) -> serde_json::Value {
    let dest_type = match t.destination {
        DestinationRef::Group(_) => "group",
        DestinationRef::Individual(_) => "individual",
    };
    let payload_hex = hex(&t.payload);

    let mut value = json!({
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
    });
    if let (Some(info), Some(obj)) = (&t.secure, value.as_object_mut()) {
        obj.insert("secured".into(), json!(info.verified()));
        obj.insert("secure_status".into(), json!(info.status.tag()));
        obj.insert("secure_seq".into(), json!(info.sequence));
        obj.insert(
            "secure_raw".into(),
            json!(info.raw_asdu.as_deref().map(hex)),
        );
        obj.insert("secure_warning".into(), json!(info.warning));
    }
    value
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
    use bussard_testkit::{TestResult, ga, ia};
    use std::collections::BTreeMap;
    use std::time::Duration;

    use bussard_model::codec::TypedValue;

    /// A fully-resolved write at t=1.5s past the epoch.
    fn sample() -> TestResult<DecodedTelegram> {
        Ok(DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(1_500),
            source: ia("1.1.30")?,
            source_name: Some("Meteodata".to_string()),
            destination: DestinationRef::Group(ga("3/2/0")?),
            destination_name: Some("Windalarm".to_string()),
            apci: ApciKind::Write,
            payload: vec![1],
            value: Some(TypedValue::Bool {
                value: true,
                label: "Alarm",
            }),
            dpt: Some("1.005".parse()?),
            object_name: Some("Windalarm 1".to_string()),
            decode_note: None,
            secure: None,
        })
    }

    #[test]
    fn pretty_no_color_exact() -> TestResult {
        let line = pretty_line(&sample()?, false);
        assert_eq!(
            line,
            "00:00:01.500  1.1.30 Meteodata         → 3/2/0 Windalarm          = Alarm (1.005, obj \"Windalarm 1\")"
        );
        Ok(())
    }

    #[test]
    fn pretty_no_color_has_no_escapes() -> TestResult {
        let line = pretty_line(&sample()?, false);
        assert!(!line.contains('\u{1b}'), "should have no ANSI escapes");
        Ok(())
    }

    #[test]
    fn pretty_read_has_no_value_section() -> TestResult {
        let mut t = sample()?;
        t.apci = ApciKind::Read;
        t.value = None;
        t.payload = vec![];
        let line = pretty_line(&t, false);
        assert!(line.contains("?→"));
        assert!(!line.contains('='), "read has no value: {line:?}");
        Ok(())
    }

    #[test]
    fn pretty_note_is_appended() -> TestResult {
        let mut t = sample()?;
        t.decode_note = Some("payload is 1 byte, but DPT 9.001 expects 2 bytes".to_string());
        let line = pretty_line(&t, false);
        assert!(line.ends_with("[payload is 1 byte, but DPT 9.001 expects 2 bytes]"));
        Ok(())
    }

    #[test]
    fn json_line_stable_fields() -> TestResult {
        let line = json_line(&sample()?);
        let v: serde_json::Value = serde_json::from_str(&line)?;
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
        Ok(())
    }

    #[test]
    fn json_value_field_set_is_exact() -> TestResult {
        // The viz server extends this object with `seq`; if the field set drifts,
        // the frontend contract and the JSON Lines schema both break. Pin it.
        let v = json_value(&sample()?);
        let obj = v.as_object().ok_or("json_value is an object")?;
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
        Ok(())
    }

    #[test]
    fn json_line_matches_json_value() -> TestResult {
        // The line form must be exactly the serialized value form.
        let t = sample()?;
        assert_eq!(json_line(&t), json_value(&t).to_string());
        Ok(())
    }

    #[test]
    fn json_line_nulls_when_unknown() -> TestResult {
        let t = DecodedTelegram {
            timestamp: SystemTime::UNIX_EPOCH,
            source: ia("1.1.1")?,
            source_name: None,
            destination: DestinationRef::Group(ga("9/1/9")?),
            destination_name: None,
            apci: ApciKind::Read,
            payload: vec![],
            value: None,
            dpt: None,
            object_name: None,
            decode_note: None,
            secure: None,
        };
        let v: serde_json::Value = serde_json::from_str(&json_line(&t))?;
        assert_eq!(v["source_name"], serde_json::Value::Null);
        assert_eq!(v["value"], serde_json::Value::Null);
        assert_eq!(v["payload"], "");
        assert_eq!(v["apci"], "read");
        Ok(())
    }

    #[test]
    fn unknown_ga_pretty_dims_when_colored() -> TestResult {
        // With color on, an unknown destination should include a dim escape.
        let mut t = sample()?;
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
        Ok(())
    }

    fn secured(status: SecureStatus, warning: Option<&str>) -> TestResult<DecodedTelegram> {
        let mut t = sample()?;
        t.secure = Some(crate::secure::SecureInfo {
            status,
            scf: 0x10,
            sequence: 275_080_000_001,
            raw_asdu: (status != SecureStatus::Verified).then(|| vec![0x10, 0xAB]),
            warning: warning.map(str::to_string),
        });
        Ok(t)
    }

    #[test]
    fn test_pretty_line_marks_a_verified_secured_telegram() -> TestResult {
        let line = pretty_line(&secured(SecureStatus::Verified, None)?, false);
        assert!(
            line.ends_with("= Alarm (1.005, obj \"Windalarm 1\")  [secured]"),
            "{line}"
        );
        Ok(())
    }

    #[test]
    fn test_pretty_line_mac_failure_shows_raw_bytes() -> TestResult {
        let line = pretty_line(&secured(SecureStatus::MacFailed, None)?, false);
        assert!(
            line.ends_with("[secured (MAC failed) seq=275080000001 raw=10ab]"),
            "{line}"
        );
        Ok(())
    }

    #[test]
    fn test_pretty_line_carries_the_freshness_warning() -> TestResult {
        let line = pretty_line(&secured(SecureStatus::Verified, Some("stale"))?, false);
        assert!(line.ends_with("[secured; warning: stale]"), "{line}");
        Ok(())
    }

    #[test]
    fn test_json_value_secure_fields() -> TestResult {
        let v = json_value(&secured(SecureStatus::Verified, None)?);
        assert_eq!(v["secured"], true);
        assert_eq!(v["secure_status"], "ok");
        assert_eq!(v["secure_seq"], 275_080_000_001u64);
        assert_eq!(v["secure_raw"], serde_json::Value::Null);
        assert_eq!(v["secure_warning"], serde_json::Value::Null);
        let v = json_value(&secured(SecureStatus::MacFailed, None)?);
        assert_eq!(v["secured"], false);
        assert_eq!(v["secure_status"], "mac_failed");
        assert_eq!(v["secure_raw"], "10ab");
        // A plain telegram carries none of the secure fields.
        let plain = json_value(&sample()?);
        assert!(plain.get("secured").is_none());
        Ok(())
    }
}
