//! Parser for a manufacturer `Hardware.xml`, resolving order numbers to the
//! application programs that a device carries.
//!
//! The chain is `Product(OrderNumber)` → its enclosing `Hardware2Program` →
//! `ApplicationProgramRef(RefId)`. The `RefId` is the same application-program
//! ref that the `.knxproj` importer writes into `devices/*.yaml` as
//! `application_ref`, so order number is the join key from a physical catalogue
//! part to an [`crate::ApplicationProgram`].
//!
//! This adapts the shape of `bussard-project::hardware`; see the crate `lib.rs`
//! dedup note.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{ProdError, Result};

/// The order-number → application-program mapping parsed from a `Hardware.xml`.
#[derive(Debug, Clone, Default)]
pub struct HardwareCatalog {
    /// Order number (e.g. `"230241SR"`) → the ordered application-program ids
    /// its hardware can be programmed with (first is primary).
    pub order_to_apps: HashMap<String, Vec<String>>,
}

impl HardwareCatalog {
    /// Merges another catalog into this one (for multi-manufacturer archives).
    pub fn extend(&mut self, other: HardwareCatalog) {
        for (order, apps) in other.order_to_apps {
            self.order_to_apps.entry(order).or_default().extend(apps);
        }
    }
}

/// Parses a `Hardware.xml`, returning order number → application-program refs.
///
/// A `<Hardware>` groups its `<Product>`s (which carry `OrderNumber`) with its
/// `<Hardware2Program>`s (which list `ApplicationProgramRef`s). Every product in
/// a hardware block is mapped to every application program that block declares.
pub fn parse_hardware(xml: &str) -> Result<HardwareCatalog> {
    let context = "Hardware.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut catalog = HardwareCatalog::default();
    // Order numbers and app refs collected within the current <Hardware> block.
    let mut block_orders: Vec<String> = Vec::new();
    let mut block_apps: Vec<String> = Vec::new();

    loop {
        match reader.read_event().map_err(|source| ProdError::Xml {
            context: context.to_string(),
            source,
        })? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"Hardware" => {
                    // A new hardware block: flush any prior one, then reset.
                    flush_block(&mut catalog, &mut block_orders, &mut block_apps);
                }
                b"Product" => {
                    if let Some(order) = attr(&e, b"OrderNumber", context)? {
                        if !order.is_empty() {
                            block_orders.push(order);
                        }
                    }
                }
                b"ApplicationProgramRef" => {
                    if let Some(ref_id) = attr(&e, b"RefId", context)? {
                        block_apps.push(ref_id);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    // Flush the final block.
    flush_block(&mut catalog, &mut block_orders, &mut block_apps);

    Ok(catalog)
}

/// Maps every collected order number in the block to every collected app ref,
/// then clears the block buffers for the next `<Hardware>`.
fn flush_block(catalog: &mut HardwareCatalog, orders: &mut Vec<String>, apps: &mut Vec<String>) {
    if !orders.is_empty() && !apps.is_empty() {
        for order in orders.iter() {
            catalog
                .order_to_apps
                .entry(order.clone())
                .or_default()
                .extend(apps.iter().cloned());
        }
    }
    orders.clear();
    apps.clear();
}

/// Reads a single attribute's unescaped value from a start/empty tag.
fn attr(e: &quick_xml::events::BytesStart, key: &[u8], context: &str) -> Result<Option<String>> {
    for a in e.attributes() {
        let a = a.map_err(|source| ProdError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        if a.key.as_ref() == key {
            let v = a.unescape_value().map_err(|source| ProdError::Xml {
                context: context.to_string(),
                source,
            })?;
            return Ok(Some(v.into_owned()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_order_number_to_app_refs() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="hw">
            <Products>
              <Product Id="H-1_P-1" OrderNumber="2116REG" />
            </Products>
            <Hardware2Programs>
              <Hardware2Program Id="H-1_HP-1">
                <ApplicationProgramRef RefId="M-0004_A-20D7-26-053C-O000A" />
              </Hardware2Program>
            </Hardware2Programs>
          </Hardware>
        </KNX>"#;
        let cat = parse_hardware(xml).unwrap();
        assert_eq!(
            cat.order_to_apps.get("2116REG").map(Vec::as_slice),
            Some(["M-0004_A-20D7-26-053C-O000A".to_string()].as_slice())
        );
    }

    #[test]
    fn separates_hardware_blocks() {
        let xml = r#"<KNX>
          <Hardware Id="H-1">
            <Products><Product OrderNumber="AAA" /></Products>
            <Hardware2Programs><Hardware2Program>
              <ApplicationProgramRef RefId="M-1_A-1" />
            </Hardware2Program></Hardware2Programs>
          </Hardware>
          <Hardware Id="H-2">
            <Products><Product OrderNumber="BBB" /></Products>
            <Hardware2Programs><Hardware2Program>
              <ApplicationProgramRef RefId="M-1_A-2" />
            </Hardware2Program></Hardware2Programs>
          </Hardware>
        </KNX>"#;
        let cat = parse_hardware(xml).unwrap();
        assert_eq!(cat.order_to_apps.get("AAA").unwrap(), &["M-1_A-1"]);
        assert_eq!(cat.order_to_apps.get("BBB").unwrap(), &["M-1_A-2"]);
    }
}
