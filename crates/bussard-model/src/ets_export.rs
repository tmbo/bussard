//! Group-address export in the two formats ETS imports (issue #104).
//!
//! Import is otherwise one-way: names and DPTs curated in bussard (or generated
//! by [`crate::scaffold`]) cannot reach ETS except by retyping. ETS's
//! *Group Addresses -> Import* accepts two shapes, and this module writes both.
//!
//! # CSV
//!
//! The three-level CSV ETS itself exports: UTF-8 **with a BOM**, semicolon
//! separated, every field quoted, and one header row:
//!
//! ```text
//! "Main";"Middle";"Sub";"Address";"Central";"Unfiltered";"Description";"DatapointType";"Security"
//! ```
//!
//! A main group, a middle group and an address each get their own row; the name
//! sits in the column for its level and the other two stay empty. Addresses use
//! the `-` placeholder for the levels below them (`1/-/-`, `1/0/-`).
//!
//! # XML
//!
//! The `GroupAddress-Export` document (namespace
//! `http://knx.org/xml/ga-export/01`): nested `GroupRange` elements for the main
//! and middle levels, `GroupAddress` leaves carrying `Name`, `Address`,
//! `Description`, `DPTs` and `Security`. It is written by hand (no serializer
//! dependency) with full attribute escaping.
//!
//! # What is preserved
//!
//! Names and descriptions go across verbatim. DPTs are rendered in ETS notation
//! (`DPST-1-1` with a sub number, `DPT-1` without). ETS has no concept of
//! bussard's `protected:` flag, so it is carried into the description as a
//! leading `[protected]` marker, which survives a round trip back through an
//! import.

use std::collections::BTreeMap;

use crate::address::GroupAddress;
use crate::dpt::Dpt;
use crate::schema::{Group, Groups};

/// The marker a `protected: true` group address carries in its ETS description.
pub const PROTECTED_MARKER: &str = "[protected]";

/// The CSV header row ETS's group-address import expects.
const CSV_HEADER: &str = "\"Main\";\"Middle\";\"Sub\";\"Address\";\"Central\";\"Unfiltered\";\"Description\";\
     \"DatapointType\";\"Security\"";

/// The XML namespace of the ETS group-address export document.
pub const GA_EXPORT_NS: &str = "http://knx.org/xml/ga-export/01";

/// A DPT in ETS notation: `DPST-1-1` with a sub number, `DPT-1` without.
fn ets_dpt(dpt: Dpt) -> String {
    match dpt.sub {
        Some(sub) => format!("DPST-{}-{}", dpt.main, sub),
        None => format!("DPT-{}", dpt.main),
    }
}

/// The description ETS sees: the model description, prefixed with the
/// `[protected]` marker when the address is guarded.
fn ets_description(group: &Group) -> String {
    let body = group.description.as_deref().unwrap_or("");
    match (group.protected, body.is_empty()) {
        (false, _) => body.to_string(),
        (true, true) => PROTECTED_MARKER.to_string(),
        (true, false) => format!("{PROTECTED_MARKER} {body}"),
    }
}

/// The name of a main group: the declared range name, else a generated one.
fn main_name(groups: &Groups, main: u8) -> String {
    groups
        .ranges
        .get(&main.to_string())
        .map(|r| r.name.clone())
        .unwrap_or_else(|| format!("Main group {main}"))
}

/// The name of a middle group: the declared range name, else a generated one.
fn middle_name(groups: &Groups, main: u8, middle: u8) -> String {
    groups
        .ranges
        .get(&format!("{main}/{middle}"))
        .map(|r| r.name.clone())
        .unwrap_or_else(|| format!("Middle group {main}/{middle}"))
}

/// The addresses of one middle group, in address order.
type MiddleRange<'a> = Vec<(GroupAddress, &'a Group)>;

/// The addresses grouped by main, then middle.
type RangeTree<'a> = BTreeMap<u8, BTreeMap<u8, MiddleRange<'a>>>;

/// The addresses grouped by main, then middle, in address order.
fn by_range(groups: &Groups) -> RangeTree<'_> {
    let mut out: RangeTree<'_> = BTreeMap::new();
    for (ga, group) in &groups.groups {
        out.entry(ga.main())
            .or_default()
            .entry(ga.middle())
            .or_default()
            .push((*ga, group));
    }
    out
}

/// Quotes one CSV field: wrapped in `"` with inner quotes doubled.
fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Joins one CSV row from already-plain field values.
fn csv_row(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(";")
}

/// Renders the group-address plan as the CSV ETS imports.
///
/// The result starts with a UTF-8 BOM, as ETS's own export does, and uses CRLF
/// line endings so the file opens unchanged in ETS and in Excel.
pub fn to_ets_csv(groups: &Groups) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str(CSV_HEADER);
    out.push_str("\r\n");

    for (main, middles) in by_range(groups) {
        out.push_str(&csv_row(&[
            &main_name(groups, main),
            "",
            "",
            &format!("{main}/-/-"),
            "",
            "",
            "",
            "",
            "Auto",
        ]));
        out.push_str("\r\n");
        for (middle, addresses) in middles {
            out.push_str(&csv_row(&[
                "",
                &middle_name(groups, main, middle),
                "",
                &format!("{main}/{middle}/-"),
                "",
                "",
                "",
                "",
                "Auto",
            ]));
            out.push_str("\r\n");
            for (ga, group) in addresses {
                let dpt = group.dpt.map(ets_dpt).unwrap_or_default();
                out.push_str(&csv_row(&[
                    "",
                    "",
                    &group.name,
                    &ga.to_string(),
                    "",
                    "",
                    &ets_description(group),
                    &dpt,
                    "Auto",
                ]));
                out.push_str("\r\n");
            }
        }
    }
    out
}

/// Escapes text for use inside an XML attribute value.
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Renders the group-address plan as an ETS `GroupAddress-Export` document.
///
/// `RangeStart`/`RangeEnd` are the raw 16-bit bounds of each level, which is
/// what ETS writes and what its importer uses to place a range.
pub fn to_ets_xml(groups: &Groups) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    out.push_str(&format!("<GroupAddress-Export xmlns=\"{GA_EXPORT_NS}\">\n"));

    for (main, middles) in by_range(groups) {
        let main_start = u16::from(main) << 11;
        out.push_str(&format!(
            "  <GroupRange Name=\"{}\" RangeStart=\"{}\" RangeEnd=\"{}\">\n",
            xml_escape(&main_name(groups, main)),
            main_start,
            main_start + 2047
        ));
        for (middle, addresses) in middles {
            let middle_start = main_start | (u16::from(middle) << 8);
            out.push_str(&format!(
                "    <GroupRange Name=\"{}\" RangeStart=\"{}\" RangeEnd=\"{}\">\n",
                xml_escape(&middle_name(groups, main, middle)),
                middle_start,
                middle_start + 255
            ));
            for (ga, group) in addresses {
                let dpt = group.dpt.map(ets_dpt).unwrap_or_default();
                out.push_str(&format!(
                    "      <GroupAddress Name=\"{}\" Address=\"{}\" Description=\"{}\" \
                     DPTs=\"{}\" Security=\"Auto\" />\n",
                    xml_escape(&group.name),
                    ga,
                    xml_escape(&ets_description(group)),
                    xml_escape(&dpt),
                ));
            }
            out.push_str("    </GroupRange>\n");
        }
        out.push_str("  </GroupRange>\n");
    }

    out.push_str("</GroupAddress-Export>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Range;

    fn sample() -> Groups {
        let mut groups = Groups::default();
        groups.ranges.insert(
            "1".to_string(),
            Range {
                name: "Light".to_string(),
            },
        );
        groups.ranges.insert(
            "1/0".to_string(),
            Range {
                name: "Ground floor".to_string(),
            },
        );
        groups.groups.insert(
            "1/0/0".parse().expect("GA parses"),
            Group {
                name: "Ground floor Kitchen Light Switch".to_string(),
                dpt: Some(Dpt::new(1, Some(1))),
                description: None,
                protected: false,
                secure: false,
            },
        );
        groups.groups.insert(
            "1/0/3".parse().expect("GA parses"),
            Group {
                name: "Wind alarm \"north\" & roof".to_string(),
                dpt: Some(Dpt::new(1, Some(5))),
                description: Some("guarded".to_string()),
                protected: true,
                secure: false,
            },
        );
        groups
    }

    #[test]
    fn test_ets_dpt_notation() {
        assert_eq!(ets_dpt(Dpt::new(1, Some(1))), "DPST-1-1");
        assert_eq!(ets_dpt(Dpt::new(20, Some(102))), "DPST-20-102");
        assert_eq!(ets_dpt(Dpt::new(9, None)), "DPT-9");
    }

    #[test]
    fn test_csv_has_bom_header_and_levels() {
        let csv = to_ets_csv(&sample());
        assert!(csv.starts_with('\u{feff}'), "the file must carry a BOM");
        let lines: Vec<&str> = csv.trim_start_matches('\u{feff}').split("\r\n").collect();
        assert_eq!(lines[0], CSV_HEADER);
        assert!(
            lines[1].starts_with("\"Light\";\"\";\"\";\"1/-/-\""),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].starts_with("\"\";\"Ground floor\";\"\";\"1/0/-\""),
            "{}",
            lines[2]
        );
        assert!(lines[3].contains("\"1/0/0\""), "{}", lines[3]);
        assert!(lines[3].contains("\"DPST-1-1\""), "{}", lines[3]);
    }

    #[test]
    fn test_csv_quotes_are_doubled_and_protected_is_marked() {
        let csv = to_ets_csv(&sample());
        assert!(
            csv.contains("\"Wind alarm \"\"north\"\" & roof\""),
            "inner quotes must be doubled: {csv}"
        );
        assert!(csv.contains("\"[protected] guarded\""), "{csv}");
    }

    #[test]
    fn test_xml_escapes_and_nests() {
        let xml = to_ets_xml(&sample());
        assert!(
            xml.contains("xmlns=\"http://knx.org/xml/ga-export/01\""),
            "{xml}"
        );
        assert!(
            xml.contains("RangeStart=\"2048\" RangeEnd=\"4095\""),
            "{xml}"
        );
        assert!(
            xml.contains("RangeStart=\"2048\" RangeEnd=\"2303\""),
            "{xml}"
        );
        assert!(xml.contains("&quot;north&quot; &amp; roof"), "{xml}");
        assert!(xml.contains("Description=\"[protected] guarded\""), "{xml}");
    }

    #[test]
    fn test_empty_plan_still_produces_a_valid_document() {
        let csv = to_ets_csv(&Groups::default());
        assert_eq!(csv.lines().count(), 1);
        let xml = to_ets_xml(&Groups::default());
        assert!(xml.contains("<GroupAddress-Export"), "{xml}");
        assert!(xml.contains("</GroupAddress-Export>"), "{xml}");
    }
}
