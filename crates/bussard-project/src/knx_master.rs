//! Minimal parser for `knx_master.xml` — only the manufacturer id → name map.

use std::collections::HashMap;

use crate::error::Result;

/// Parses the manufacturer id → display name map from `knx_master.xml`, with
/// the parser `bussard-ets` shares with the product store (issue #788).
pub fn parse_manufacturers(xml: &str) -> Result<HashMap<String, String>> {
    Ok(
        bussard_ets::master::parse_manufacturer_names(xml.as_bytes(), "knx_master.xml")?
            .into_iter()
            .collect(),
    )
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
