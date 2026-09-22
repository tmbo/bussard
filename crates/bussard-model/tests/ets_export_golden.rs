//! Golden tests for the ETS group-address export (issue #104).
//!
//! The CSV and XML are compared byte-for-byte against committed goldens, the XML
//! is parsed back with `quick-xml` to prove it is well-formed, and the CSV is
//! read back through a small reader that mirrors what an importer does.

use std::error::Error;
use std::path::{Path, PathBuf};

use bussard_model::loader::load_groups;
use bussard_model::{to_ets_csv, to_ets_xml};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

/// The export fixture directory.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ets_export")
}

#[test]
fn test_csv_matches_the_golden_file() -> Result<(), Box<dyn Error>> {
    let groups = load_groups(&fixtures().join("groups.yaml"))?;
    let actual = to_ets_csv(&groups);
    let expected = std::fs::read_to_string(fixtures().join("expected.csv"))?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn test_xml_matches_the_golden_file() -> Result<(), Box<dyn Error>> {
    let groups = load_groups(&fixtures().join("groups.yaml"))?;
    let actual = to_ets_xml(&groups);
    let expected = std::fs::read_to_string(fixtures().join("expected.xml"))?;
    assert_eq!(actual, expected);
    Ok(())
}

/// Reads one CSV line into its quoted fields, undoubling inner quotes. Enough
/// for the export's shape: every field is quoted and may contain a `;`.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => fields.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    fields.push(current);
    fields
}

#[test]
fn test_csv_round_trips_through_a_reader() -> Result<(), Box<dyn Error>> {
    let groups = load_groups(&fixtures().join("groups.yaml"))?;
    let csv = to_ets_csv(&groups);
    let body = csv.trim_start_matches('\u{feff}');
    let lines: Vec<&str> = body.split("\r\n").filter(|l| !l.is_empty()).collect();

    let header = csv_fields(lines[0]);
    assert_eq!(header[0], "Main");
    assert_eq!(header[3], "Address");
    assert_eq!(header[7], "DatapointType");

    // Every address row (the ones with a Sub name) must carry its name, address
    // and DPT back unchanged, with `protected` visible in the description.
    let mut seen = 0usize;
    for line in &lines[1..] {
        let f = csv_fields(line);
        assert_eq!(f.len(), 9, "row has nine columns: {line}");
        if f[2].is_empty() {
            continue;
        }
        seen += 1;
        let address = f[3].parse()?;
        let Some(group) = groups.groups.get(&address) else {
            panic!("{} is not in the source plan", f[3]);
        };
        assert_eq!(f[2], group.name);
        match group.dpt {
            Some(dpt) => assert_eq!(f[7], format!("DPST-{}-{}", dpt.main, dpt.sub.unwrap_or(0))),
            None => assert!(f[7].is_empty(), "an untyped GA exports an empty DPT"),
        }
        if group.protected {
            assert!(f[6].starts_with("[protected]"), "{}", f[6]);
        }
    }
    assert_eq!(seen, groups.groups.len(), "every address must be exported");
    Ok(())
}

#[test]
fn test_xml_is_well_formed_and_carries_every_address() -> Result<(), Box<dyn Error>> {
    let groups = load_groups(&fixtures().join("groups.yaml"))?;
    let xml = to_ets_xml(&groups);

    let mut reader = Reader::from_str(&xml);
    let mut addresses = Vec::new();
    let mut ranges = 0usize;
    loop {
        match reader.read_event()? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"GroupRange" => ranges += 1,
                b"GroupAddress" => {
                    let mut address = None;
                    for attr in e.attributes() {
                        let attr = attr?;
                        if attr.key.local_name().as_ref() == b"Address" {
                            address =
                                Some(attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned());
                        }
                    }
                    let Some(address) = address else {
                        panic!("a GroupAddress element without an Address attribute");
                    };
                    addresses.push(address);
                }
                _ => {}
            },
            _ => {}
        }
    }

    assert_eq!(ranges, 4, "two main ranges, each with one middle range");
    let expected: Vec<String> = groups.groups.keys().map(|ga| ga.to_string()).collect();
    assert_eq!(addresses, expected);
    Ok(())
}

#[test]
fn test_xml_unescapes_back_to_the_original_text() -> Result<(), Box<dyn Error>> {
    let groups = load_groups(&fixtures().join("groups.yaml"))?;
    let xml = to_ets_xml(&groups);
    let mut reader = Reader::from_str(&xml);
    let mut found = false;
    loop {
        match reader.read_event()? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"GroupAddress" => {
                for attr in e.attributes() {
                    let attr = attr?;
                    if attr.key.local_name().as_ref() == b"Description" {
                        let value = attr.normalized_value(XmlVersion::Implicit1_0)?;
                        if value.contains("Roof") {
                            assert_eq!(value, "[protected] Roof & facade");
                            found = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    assert!(found, "the escaped description must survive a round trip");
    Ok(())
}
