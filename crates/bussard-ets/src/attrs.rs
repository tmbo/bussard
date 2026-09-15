//! Attribute helpers shared by every ETS-XML parser.
//!
//! ETS XML is attribute-heavy, so parsers repeatedly need to pull the
//! (unescaped, UTF-8) value of one or more attributes off a start/empty tag.
//! These helpers centralize that, plus the flag-attribute extraction and the
//! UTF-8 BOM stripping every entry reader wants.

use std::collections::HashMap;

use quick_xml::events::BytesStart;

use crate::error::{EtsError, Result};
use crate::flags::{FlagSet, parse_flag_value};

/// Parses all attributes of a start/empty tag into a map keyed by attribute
/// name (the raw, namespace-unqualified key bytes).
pub fn attrs_map(e: &BytesStart, context: &str) -> Result<HashMap<Vec<u8>, String>> {
    let mut map = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|source| EtsError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        // quick-xml 0.41 deprecates unescape_value in favor of normalized_value,
        // which also applies XML attribute-value normalization (whitespace
        // folding). ETS emission is held to byte-equal output, so keep the
        // plain-unescape semantics deliberately.
        #[allow(deprecated)]
        let value = attr
            .unescape_value()
            .map_err(|source| EtsError::Xml {
                context: context.to_string(),
                source,
            })?
            .into_owned();
        map.insert(attr.key.as_ref().to_vec(), value);
    }
    Ok(map)
}

/// Looks up an attribute value in a parsed [`attrs_map`], as a `&str`.
pub fn get<'a>(map: &'a HashMap<Vec<u8>, String>, key: &[u8]) -> Option<&'a str> {
    map.get(key).map(String::as_str)
}

/// Extracts the (unescaped, UTF-8) value of a single attribute directly off a
/// tag, without building a full map. Returns `None` if the attribute is absent.
pub fn attr_value(e: &BytesStart, key: &[u8], context: &str) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr = attr.map_err(|source| EtsError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        if attr.key.as_ref() == key {
            #[allow(deprecated)] // see attrs_map: plain unescape is deliberate
            let cow = attr.unescape_value().map_err(|source| EtsError::Xml {
                context: context.to_string(),
                source,
            })?;
            return Ok(Some(cow.into_owned()));
        }
    }
    Ok(None)
}

/// Builds a [`FlagSet`] from the six ETS flag attributes on a com-object tag.
pub fn flagset_from(map: &HashMap<Vec<u8>, String>) -> FlagSet {
    FlagSet {
        communication: get(map, b"CommunicationFlag").and_then(parse_flag_value),
        read: get(map, b"ReadFlag").and_then(parse_flag_value),
        write: get(map, b"WriteFlag").and_then(parse_flag_value),
        transmit: get(map, b"TransmitFlag").and_then(parse_flag_value),
        update: get(map, b"UpdateFlag").and_then(parse_flag_value),
        read_on_init: get(map, b"ReadOnInitFlag").and_then(parse_flag_value),
    }
}

/// Converts bytes to a `String`, dropping a leading UTF-8 BOM if present.
pub fn strip_bom(bytes: Vec<u8>) -> String {
    let s = String::from_utf8_lossy(&bytes).into_owned();
    s.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"<KNX/>");
        assert_eq!(strip_bom(bytes), "<KNX/>");
        assert_eq!(strip_bom(b"plain".to_vec()), "plain");
    }
}
