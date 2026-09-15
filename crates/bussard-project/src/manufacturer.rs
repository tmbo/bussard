//! Streaming parser for a manufacturer ApplicationProgram XML file.
//!
//! These files can be 20–28 MB, so we never build a DOM: `quick-xml` pulls
//! events and we keep only what phase 0 needs — the application's
//! `MaskVersion`, name and version, plus the `ComObject` (base) and
//! `ComObjectRef` tables. Everything else (`ParameterTypes`, `Parameters`,
//! `LoadProcedures`, …) is skipped.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::dpt_map::parse_ets_dpt;
use crate::error::{ImportError, Result};
use crate::flag_map::{parse_flag_value, FlagSet};
use bussard_model::Dpt;

/// A base `<ComObject>` from the application program.
#[derive(Debug, Clone, Default)]
pub struct ComObjectBase {
    /// The com-object number (the stable, user-visible handle).
    pub number: u16,
    /// Object `Name`.
    pub name: Option<String>,
    /// Object `Text`.
    pub text: Option<String>,
    /// Declared `ObjectSize`, e.g. `"1 Bit"`.
    pub object_size: Option<String>,
    /// Effective DPT (base rarely carries one, but honour it if present).
    pub dpt: Option<Dpt>,
    /// Flags declared on the base object.
    pub flags: FlagSet,
    /// For a module com-object: the argument id whose value is added to
    /// `number` to compute the instance's effective object number.
    pub base_number_ref: Option<String>,
}

/// A `<ComObjectRef>` from the application program.
#[derive(Debug, Clone, Default)]
pub struct ComObjectRef {
    /// The base `<ComObject>` id this ref points at.
    pub ref_id: String,
    /// Optional `Name` override.
    pub name: Option<String>,
    /// Optional `Text` override.
    pub text: Option<String>,
    /// Optional `ObjectSize` override.
    pub object_size: Option<String>,
    /// Optional DPT override.
    pub dpt: Option<Dpt>,
    /// Flags declared on the ref (override the base's).
    pub flags: FlagSet,
}

/// The parsed pieces of one ApplicationProgram file.
#[derive(Debug, Clone, Default)]
pub struct ApplicationProgram {
    /// The application program id (e.g. `M-0004_A-7066-11-7A9E-O000A`).
    pub id: String,
    /// The mask version with the `MV-` prefix stripped, e.g. `"0705"`.
    pub mask_version: Option<String>,
    /// Application program display name.
    pub name: Option<String>,
    /// Application version string.
    pub version: Option<String>,
    /// Base com-objects, keyed by their full `Id`.
    pub com_objects: HashMap<String, ComObjectBase>,
    /// Com-object refs, keyed by their full `Id`.
    pub com_object_refs: HashMap<String, ComObjectRef>,
}

impl ApplicationProgram {
    /// Resolves a `ComObjectInstanceRef` `RefId` (relative to this program) to
    /// its effective base + ref, if both resolve.
    ///
    /// The `RefId` on an instance is relative (e.g. `O-0_R-1`); the full ref id
    /// is `<program-id>_<RefId>` and the base id is the ref's `RefId`.
    pub fn resolve(&self, instance_ref_id: &str) -> Option<(&ComObjectBase, &ComObjectRef)> {
        let full_ref_id = format!("{}_{instance_ref_id}", self.id);
        let cor = self.com_object_refs.get(&full_ref_id)?;
        let base = self.com_objects.get(&cor.ref_id)?;
        Some((base, cor))
    }
}

/// Attribute helper: extracts the (unescaped, UTF-8) value of an attribute.
fn attr_value(
    e: &quick_xml::events::BytesStart,
    key: &[u8],
    context: &str,
) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr = attr.map_err(|source| ImportError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        if attr.key.as_ref() == key {
            let cow = attr.unescape_value().map_err(|source| ImportError::Xml {
                context: context.to_string(),
                source,
            })?;
            return Ok(Some(cow.into_owned()));
        }
    }
    Ok(None)
}

/// Parses all attributes of a start tag into a map for convenient lookup.
fn attrs_map(e: &quick_xml::events::BytesStart, context: &str) -> Result<HashMap<Vec<u8>, String>> {
    let mut map = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|source| ImportError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        let value = attr
            .unescape_value()
            .map_err(|source| ImportError::Xml {
                context: context.to_string(),
                source,
            })?
            .into_owned();
        map.insert(attr.key.as_ref().to_vec(), value);
    }
    Ok(map)
}

fn get<'a>(map: &'a HashMap<Vec<u8>, String>, key: &[u8]) -> Option<&'a str> {
    map.get(key).map(String::as_str)
}

fn flagset_from(map: &HashMap<Vec<u8>, String>) -> FlagSet {
    FlagSet {
        communication: get(map, b"CommunicationFlag").and_then(parse_flag_value),
        read: get(map, b"ReadFlag").and_then(parse_flag_value),
        write: get(map, b"WriteFlag").and_then(parse_flag_value),
        transmit: get(map, b"TransmitFlag").and_then(parse_flag_value),
        update: get(map, b"UpdateFlag").and_then(parse_flag_value),
        read_on_init: get(map, b"ReadOnInitFlag").and_then(parse_flag_value),
    }
}

/// Parses an ApplicationProgram XML string, extracting only what phase 0 needs.
///
/// `id` is the application-program id (used for context in errors and as the
/// returned id).
pub fn parse_application_program(id: &str, xml: &str) -> Result<ApplicationProgram> {
    let context = format!("application program {id}");
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut app = ApplicationProgram {
        id: id.to_string(),
        ..Default::default()
    };

    loop {
        match reader.read_event().map_err(|source| ImportError::Xml {
            context: context.clone(),
            source,
        })? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"ApplicationProgram" => {
                    if let Some(mv) = attr_value(&e, b"MaskVersion", &context)? {
                        app.mask_version = Some(mv.strip_prefix("MV-").unwrap_or(&mv).to_string());
                    }
                    app.name = attr_value(&e, b"Name", &context)?;
                    app.version = attr_value(&e, b"ApplicationVersion", &context)?;
                }
                b"ComObject" => {
                    let m = attrs_map(&e, &context)?;
                    let id = match get(&m, b"Id") {
                        Some(v) => v.to_string(),
                        None => continue,
                    };
                    let number = get(&m, b"Number")
                        .and_then(|n| n.parse::<u16>().ok())
                        .unwrap_or(0);
                    let base = ComObjectBase {
                        number,
                        name: get(&m, b"Name").map(str::to_string),
                        text: get(&m, b"Text").map(str::to_string),
                        object_size: get(&m, b"ObjectSize").map(str::to_string),
                        dpt: get(&m, b"DatapointType").and_then(parse_ets_dpt),
                        flags: flagset_from(&m),
                        base_number_ref: get(&m, b"BaseNumber").map(str::to_string),
                    };
                    app.com_objects.insert(id, base);
                }
                b"ComObjectRef" => {
                    let m = attrs_map(&e, &context)?;
                    let id = match get(&m, b"Id") {
                        Some(v) => v.to_string(),
                        None => continue,
                    };
                    let ref_id = match get(&m, b"RefId") {
                        Some(v) => v.to_string(),
                        None => continue,
                    };
                    let cor = ComObjectRef {
                        ref_id,
                        name: get(&m, b"Name").map(str::to_string),
                        text: get(&m, b"Text").map(str::to_string),
                        object_size: get(&m, b"ObjectSize").map(str::to_string),
                        dpt: get(&m, b"DatapointType").and_then(parse_ets_dpt),
                        flags: flagset_from(&m),
                    };
                    app.com_object_refs.insert(id, cor);
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ApplicationProgram Id="M-0001_A-1234-1-0000" MaskVersion="MV-07B0" Name="Demo" ApplicationVersion="3">
    <ComObjects>
      <ComObject Id="M-0001_A-1234-1-0000_O-0" Number="0" Name="Base" Text="Schalten"
        ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled"
        TransmitFlag="Enabled" ReadFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
    </ComObjects>
    <ComObjectRefs>
      <ComObjectRef Id="M-0001_A-1234-1-0000_O-0_R-1" RefId="M-0001_A-1234-1-0000_O-0"
        FunctionText="Onoff" DatapointType="DPST-1-1" ReadFlag="Enabled" />
    </ComObjectRefs>
  </ApplicationProgram>
</KNX>"#;

    #[test]
    fn parses_mask_and_objects() {
        let app = parse_application_program("M-0001_A-1234-1-0000", SAMPLE).unwrap();
        assert_eq!(app.mask_version.as_deref(), Some("07B0"));
        assert_eq!(app.name.as_deref(), Some("Demo"));
        assert_eq!(app.com_objects.len(), 1);
        assert_eq!(app.com_object_refs.len(), 1);

        let (base, cor) = app.resolve("O-0_R-1").unwrap();
        assert_eq!(base.number, 0);
        // Effective DPT comes from the ref.
        assert_eq!(cor.dpt, Some(Dpt::new(1, Some(1))));
        // Effective flags: base C W T + ref R (ref adds Read).
        let flags = base.flags.merge(cor.flags).to_flags();
        assert_eq!(flags.to_string(), "CRWT");
    }
}
