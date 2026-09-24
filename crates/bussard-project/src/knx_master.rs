//! Minimal parser for `knx_master.xml` — only the manufacturer id → name map.

use std::collections::HashMap;

use bussard_ets::attrs::attrs_map;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{ImportError, Result};

/// Parses the manufacturer id → display name map from `knx_master.xml`.
pub fn parse_manufacturers(xml: &str) -> Result<HashMap<String, String>> {
    let context = "knx_master.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut map = HashMap::new();
    loop {
        match reader.read_event().map_err(|source| ImportError::Xml {
            context: context.to_string(),
            source,
        })? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Manufacturer" => {
                // Plain (non-normalizing) unescape via the shared helper keeps
                // import output byte-stable.
                let attrs = attrs_map(&e, context)?;
                let id = attrs.get(b"Id").map(str::to_string);
                let name = attrs.get(b"Name").map(str::to_string);
                if let (Some(id), Some(name)) = (id, name) {
                    map.insert(id, name);
                }
            }
            _ => {}
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names() -> Result<()> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <MasterData>
            <Manufacturers>
              <Manufacturer Id="M-0004" Name="Albrecht Jung" />
              <Manufacturer Id="M-0001" Name="Siemens" />
            </Manufacturers>
          </MasterData>
        </KNX>"#;
        let m = parse_manufacturers(xml)?;
        assert_eq!(m.get("M-0004").map(String::as_str), Some("Albrecht Jung"));
        assert_eq!(m.get("M-0001").map(String::as_str), Some("Siemens"));
        Ok(())
    }
}
