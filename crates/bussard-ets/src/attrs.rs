//! Attribute helpers shared by every ETS-XML parser.
//!
//! ETS XML is attribute-heavy, so parsers repeatedly need to pull the
//! (unescaped, UTF-8) value of one or more attributes off a start/empty tag.
//! These helpers centralize that, plus the flag-attribute extraction and the
//! UTF-8 BOM stripping every entry reader wants.

use quick_xml::events::BytesStart;

use crate::error::{EtsError, Result};
use crate::flags::{FlagSet, parse_flag_value};

/// The parsed attributes of a single start/empty tag.
///
/// ETS elements carry only a handful of attributes, so this stores them as a
/// flat `(key, value)` list and answers [`Attrs::get`] with a linear scan. That
/// is faster than a `HashMap` at these sizes and, crucially, its backing
/// allocations can be **reused across elements** via [`Attrs::parse_into`],
/// which is the whole point on the multi-megabyte manufacturer-XML hot path: a
/// fresh `HashMap` per element (plus a `Vec<u8>` key and `String` value per
/// attribute) was the dominant per-element allocation churn.
#[derive(Debug, Default, Clone)]
pub struct Attrs {
    /// `(key-bytes, unescaped-value)` pairs in document order.
    pairs: Vec<(Vec<u8>, String)>,
    /// The current number of live pairs. Slots at `[len..pairs.len()]` are
    /// retained (with their heap buffers) for reuse by the next parse.
    len: usize,
}

impl Attrs {
    /// Creates an empty attribute set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-parses all attributes of `e` into `self`, reusing the existing key
    /// and value allocations rather than freeing and reallocating them.
    ///
    /// The plain (non-normalizing) unescape is deliberate: quick-xml 0.41
    /// deprecates `unescape_value` in favour of `normalized_value`, which also
    /// applies XML attribute-value whitespace folding. ETS emission is held to
    /// byte-equal output, so the plain-unescape semantics are kept.
    pub fn parse_into(&mut self, e: &BytesStart, context: &str) -> Result<()> {
        self.len = 0;
        for attr in e.attributes() {
            let attr = attr.map_err(|source| EtsError::XmlAttr {
                context: context.to_string(),
                source,
            })?;
            #[allow(deprecated)] // plain unescape is deliberate; see the doc comment.
            let value = attr.unescape_value().map_err(|source| EtsError::Xml {
                context: context.to_string(),
                source,
            })?;
            let key = attr.key.as_ref();

            // Reuse a retained slot's buffers if one is available, else grow.
            if let Some((k, v)) = self.pairs.get_mut(self.len) {
                k.clear();
                k.extend_from_slice(key);
                v.clear();
                v.push_str(&value);
            } else {
                self.pairs.push((key.to_vec(), value.into_owned()));
            }
            self.len += 1;
        }
        Ok(())
    }

    /// Looks up an attribute value by key, as a `&str`. Linear scan.
    pub fn get(&self, key: &[u8]) -> Option<&str> {
        self.pairs[..self.len]
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_str())
    }

    /// Iterates the live `(key-bytes, value)` pairs in document order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &str)> {
        self.pairs[..self.len]
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_str()))
    }
}

/// Parses all attributes of a start/empty tag into a fresh [`Attrs`].
///
/// Convenience for callers that do not maintain a reusable [`Attrs`] scratch
/// buffer (e.g. one-shot parses). The streaming hot path uses
/// [`Attrs::parse_into`] on a shared buffer instead.
pub fn attrs_map(e: &BytesStart, context: &str) -> Result<Attrs> {
    let mut attrs = Attrs::new();
    attrs.parse_into(e, context)?;
    Ok(attrs)
}

/// Looks up an attribute value in a parsed [`Attrs`], as a `&str`.
pub fn get<'a>(map: &'a Attrs, key: &[u8]) -> Option<&'a str> {
    map.get(key)
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
pub fn flagset_from(map: &Attrs) -> FlagSet {
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

    /// Parses the attributes of the single tag in `xml` into `attrs`.
    fn parse_one(attrs: &mut Attrs, xml: &str) -> Result<()> {
        use quick_xml::Reader;
        use quick_xml::events::Event;
        let mut reader = Reader::from_str(xml);
        loop {
            match reader.read_event().map_err(|source| EtsError::Xml {
                context: "test".to_string(),
                source,
            })? {
                Event::Start(e) | Event::Empty(e) => {
                    attrs.parse_into(&e, "test")?;
                    return Ok(());
                }
                Event::Eof => return Ok(()),
                _ => {}
            }
        }
    }

    #[test]
    fn attrs_get_returns_values_and_none() -> Result<()> {
        let mut attrs = Attrs::new();
        parse_one(&mut attrs, r#"<E Id="O-1" Name="Light &amp; Fan" />"#)?;
        assert_eq!(attrs.get(b"Id"), Some("O-1"));
        // Entity unescaping is applied (plain, non-normalizing).
        assert_eq!(attrs.get(b"Name"), Some("Light & Fan"));
        assert_eq!(attrs.get(b"Missing"), None);
        Ok(())
    }

    #[test]
    fn attrs_parse_into_reuses_buffer_without_stale_pairs() -> Result<()> {
        // Reusing one Attrs across elements must not leak attributes from a
        // previous (longer) element into a later (shorter) one.
        let mut attrs = Attrs::new();
        parse_one(&mut attrs, r#"<E A="1" B="2" C="3" />"#)?;
        assert_eq!(attrs.iter().count(), 3);
        assert_eq!(attrs.get(b"C"), Some("3"));

        parse_one(&mut attrs, r#"<E A="9" />"#)?;
        assert_eq!(
            attrs.iter().count(),
            1,
            "stale pairs must not survive reuse"
        );
        assert_eq!(attrs.get(b"A"), Some("9"));
        assert_eq!(attrs.get(b"B"), None, "B belonged to the previous element");
        assert_eq!(attrs.get(b"C"), None);
        Ok(())
    }

    #[test]
    fn attrs_map_matches_attrs_parse_into() -> Result<()> {
        // The convenience one-shot builder agrees with the reusable path.
        let mut reused = Attrs::new();
        parse_one(&mut reused, r#"<E X="a" Y="b" />"#)?;
        let fresh = {
            use quick_xml::Reader;
            use quick_xml::events::Event;
            let mut reader = Reader::from_str(r#"<E X="a" Y="b" />"#);
            loop {
                if let Event::Empty(e) = reader.read_event().map_err(|source| EtsError::Xml {
                    context: "test".to_string(),
                    source,
                })? {
                    break attrs_map(&e, "test")?;
                }
            }
        };
        assert_eq!(fresh.get(b"X"), reused.get(b"X"));
        assert_eq!(fresh.get(b"Y"), reused.get(b"Y"));
        Ok(())
    }
}
