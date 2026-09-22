//! One streaming parser for a manufacturer `Hardware.xml`.
//!
//! The file groups, per `<Hardware>` block, the physical `<Product>`s (each
//! carrying an `OrderNumber`) with the `<Hardware2Program>`s that say which
//! application programs that hardware can run. The chain is:
//!
//! ```text
//! Hardware
//!   Product(OrderNumber, Id)          ← the catalogue part
//!   Hardware2Program(Id)              ← a programmable variant
//!     ApplicationProgramRef(RefId)    ← the application it runs
//! ```
//!
//! Two consumers key this differently:
//!
//! * `.knxproj` import keys by `Hardware2Program` id: a device records its
//!   `Hardware2ProgramRefId`, and that id resolves directly to its app refs.
//! * `.knxprod` reading keys by order number: it has no device, so it joins a
//!   catalogue order number to the application programs its hardware declares.
//!
//! Both keyings are derived from the same parse. Crucially the order-number
//! join stays **per Hardware2Program within the enclosing `<Hardware>` block**:
//! it never cross-products every order number in a block against every app ref
//! in that block (which could attribute the wrong application to a part when a
//! block carries several distinct programs).

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::attrs::attr_value;
use crate::error::{EtsError, Result};
use crate::translation::TranslationCollector;

/// Product identity looked up from `Hardware.xml`.
#[derive(Debug, Clone, Default)]
pub struct ProductInfo {
    /// The catalogue order number, e.g. `"2116REG"`.
    pub order_number: Option<String>,
    /// The hardware display name, e.g. `"Beispielaktor 4fach"` (en-US resolved).
    pub hardware_name: Option<String>,
}

/// The parsed pieces of a `Hardware.xml`.
#[derive(Debug, Clone, Default)]
pub struct Hardware {
    /// Product id → identity.
    pub products: HashMap<String, ProductInfo>,
    /// `Hardware2Program` id → its ordered list of application-program ids.
    ///
    /// Multi-application devices (a single hardware programmed with several
    /// application programs) list more than one; the first is the primary.
    pub hardware2program: HashMap<String, Vec<String>>,
    /// Order number → the bus current the hardware draws, in mA, from the
    /// `<Hardware BusCurrent=…>` attribute.
    ///
    /// Read by the `L002` topology lint (via the generated `models/*.yaml`) to
    /// total a line's draw against its power supply. Vendors declare it per
    /// `<Hardware>` block, so every order number in a block shares the value.
    pub order_to_bus_current: HashMap<String, u32>,
    /// Order number → ordered application-program ids, joined per Hardware block
    /// through that block's own `Hardware2Program`s (not cross-producted).
    ///
    /// This is what the order-number consumer (`.knxprod`) uses. Within a block,
    /// every product's order number maps to every app ref that block's
    /// `Hardware2Program`s declare, in document order.
    pub order_to_apps: HashMap<String, Vec<String>>,
}

impl Hardware {
    /// Merges another parsed `Hardware` into this one (multi-manufacturer or
    /// multi-file archives). Product and Hardware2Program ids are globally
    /// unique, so those maps just absorb the other's entries; order numbers can
    /// recur across manufacturers, so their app lists are appended.
    pub fn extend(&mut self, other: Hardware) {
        self.products.extend(other.products);
        self.hardware2program.extend(other.hardware2program);
        self.order_to_bus_current.extend(other.order_to_bus_current);
        for (order, apps) in other.order_to_apps {
            self.order_to_apps.entry(order).or_default().extend(apps);
        }
    }
}

/// Parses a `Hardware.xml`.
///
/// A `<Product>` inherits its name from the enclosing `<Hardware Name=…>`, or
/// its own `Text` attribute (preferred) when present; the order number comes
/// from the product's own `OrderNumber`. en-US product-name translations from
/// the `<Languages>` section override the raw `Text`.
pub fn parse_hardware(xml: &str) -> Result<Hardware> {
    let context = "Hardware.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut products: HashMap<String, ProductInfo> = HashMap::new();
    let mut h2p: HashMap<String, Vec<String>> = HashMap::new();
    let mut order_to_apps: HashMap<String, Vec<String>> = HashMap::new();
    let mut order_to_bus_current: HashMap<String, u32> = HashMap::new();

    let mut current_h2p_id: Option<String> = None;
    let mut current_hw_name: Option<String> = None;

    // Order numbers and app refs collected within the current <Hardware> block,
    // for the order-number join. Kept separate from the h2p-id keying above.
    let mut block_orders: Vec<String> = Vec::new();
    let mut block_apps: Vec<String> = Vec::new();
    let mut block_bus_current: Option<u32> = None;

    // Translation state for the `<Languages>` section: product `Text` → en-US.
    let mut translations = TranslationCollector::new();

    loop {
        match reader.read_event().map_err(|source| EtsError::Xml {
            context: context.to_string(),
            source,
        })? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"Hardware" => {
                    // A new hardware block: flush the prior block's order join.
                    flush_block(
                        &mut order_to_apps,
                        &mut order_to_bus_current,
                        &mut block_orders,
                        &mut block_apps,
                        &mut block_bus_current,
                    );
                    current_hw_name = attr_value(&e, b"Name", context)?;
                    block_bus_current =
                        attr_value(&e, b"BusCurrent", context)?.and_then(|v| parse_bus_current(&v));
                }
                b"Product" => {
                    let order = attr_value(&e, b"OrderNumber", context)?;
                    // The order-number join collects every order number in the
                    // block, regardless of whether the product carries an `Id`.
                    if let Some(o) = order.as_deref().filter(|s| !s.is_empty()) {
                        block_orders.push(o.to_string());
                    }
                    if let Some(id) = attr_value(&e, b"Id", context)? {
                        // Prefer the product's own `Text` as the display name,
                        // falling back to the enclosing hardware `Name`.
                        let name = attr_value(&e, b"Text", context)?
                            .filter(|s| !s.is_empty())
                            .or_else(|| current_hw_name.clone());
                        products.insert(
                            id,
                            ProductInfo {
                                order_number: order,
                                hardware_name: name,
                            },
                        );
                    }
                }
                b"Hardware2Program" => {
                    current_h2p_id = attr_value(&e, b"Id", context)?;
                    if let Some(id) = &current_h2p_id {
                        h2p.entry(id.clone()).or_default();
                    }
                }
                b"ApplicationProgramRef" => {
                    if let Some(ref_id) = attr_value(&e, b"RefId", context)? {
                        if let Some(h2p_id) = &current_h2p_id {
                            h2p.entry(h2p_id.clone()).or_default().push(ref_id.clone());
                        }
                        block_apps.push(ref_id);
                    }
                }
                b"Language" => {
                    translations.enter_language(attr_value(&e, b"Identifier", context)?.as_deref());
                }
                b"TranslationElement" => {
                    translations.enter_element(attr_value(&e, b"RefId", context)?.as_deref());
                }
                b"Translation" => {
                    // Hardware.xml keys the product `Text` translation directly
                    // on the TranslationUnit RefId (the product id), not a nested
                    // TranslationElement. Capture from whichever is current.
                    let m = crate::attrs::attrs_map(&e, context)?;
                    translations.record(&m, &["Text"]);
                }
                b"TranslationUnit" => {
                    // Fall back to the unit's RefId as the element key when no
                    // TranslationElement wraps the Translation.
                    translations.enter_element(attr_value(&e, b"RefId", context)?.as_deref());
                }
                _ => {}
            },
            Event::End(e) => match e.local_name().as_ref() {
                b"Hardware" => current_hw_name = None,
                b"Hardware2Program" => current_h2p_id = None,
                b"Language" => translations.exit_language(),
                b"TranslationElement" => translations.exit_element(),
                b"TranslationUnit" => translations.exit_element(),
                _ => {}
            },
            _ => {}
        }
    }
    // Flush the final block.
    flush_block(
        &mut order_to_apps,
        &mut order_to_bus_current,
        &mut block_orders,
        &mut block_apps,
        &mut block_bus_current,
    );

    // Apply en-US product-name translations, keyed by product id.
    if !translations.is_empty() {
        for (id, info) in products.iter_mut() {
            if let Some(text) = translations.get(id, "Text") {
                info.hardware_name = Some(text.to_string());
            }
        }
    }

    Ok(Hardware {
        products,
        hardware2program: h2p,
        order_to_bus_current,
        order_to_apps,
    })
}

/// Maps every collected order number in the block to every collected app ref
/// (and to the block's declared bus current), then clears the block buffers for
/// the next `<Hardware>`.
fn flush_block(
    order_to_apps: &mut HashMap<String, Vec<String>>,
    order_to_bus_current: &mut HashMap<String, u32>,
    orders: &mut Vec<String>,
    apps: &mut Vec<String>,
    bus_current: &mut Option<u32>,
) {
    if !orders.is_empty() && !apps.is_empty() {
        for order in orders.iter() {
            order_to_apps
                .entry(order.clone())
                .or_default()
                .extend(apps.iter().cloned());
        }
    }
    if let Some(ma) = *bus_current {
        for order in orders.iter() {
            order_to_bus_current.insert(order.clone(), ma);
        }
    }
    orders.clear();
    apps.clear();
    *bus_current = None;
}

/// Parses a `BusCurrent` attribute (mA). Vendors write it as an integer, but a
/// decimal shows up too; a fractional value rounds up so a lint never
/// under-reports a line's draw.
fn parse_bus_current(raw: &str) -> Option<u32> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(value) = text.parse::<u32>() {
        return Some(value);
    }
    let value = text.parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    Some(value.ceil() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hardware_reads_bus_current_per_block() -> Result<()> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="Actuator" BusCurrent="10">
            <Products><Product Id="H-1_P-A" OrderNumber="A-1" /></Products>
          </Hardware>
          <Hardware Id="H-2" Name="Sensor" BusCurrent="7.5">
            <Products><Product Id="H-2_P-B" OrderNumber="B-1" /></Products>
          </Hardware>
          <Hardware Id="H-3" Name="Passive">
            <Products><Product Id="H-3_P-C" OrderNumber="C-1" /></Products>
          </Hardware>
        </KNX>"#;
        let hw = parse_hardware(xml)?;
        assert_eq!(hw.order_to_bus_current.get("A-1"), Some(&10));
        // A fractional value rounds up so the lint never under-reports.
        assert_eq!(hw.order_to_bus_current.get("B-1"), Some(&8));
        assert_eq!(hw.order_to_bus_current.get("C-1"), None);
        Ok(())
    }

    #[test]
    fn product_prefers_text_over_hardware_name() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="Hardware name">
            <Products>
              <Product Id="H-1_P-2116REG" OrderNumber="2116REG" Text="Beispielaktor 4fach" />
            </Products>
          </Hardware>
        </KNX>"#;
        let hw = parse_hardware(xml).unwrap();
        let p = hw.products.get("H-1_P-2116REG").unwrap();
        assert_eq!(p.order_number.as_deref(), Some("2116REG"));
        assert_eq!(p.hardware_name.as_deref(), Some("Beispielaktor 4fach"));
    }

    #[test]
    fn product_falls_back_to_hardware_name_without_text() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="Hardware name">
            <Products>
              <Product Id="H-1_P-1" OrderNumber="1" />
            </Products>
          </Hardware>
        </KNX>"#;
        let hw = parse_hardware(xml).unwrap();
        assert_eq!(
            hw.products.get("H-1_P-1").unwrap().hardware_name.as_deref(),
            Some("Hardware name")
        );
    }

    #[test]
    fn en_us_translation_overrides_text() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="hw">
            <Products>
              <Product Id="H-1_P-1" OrderNumber="1" Text="Schaltaktor" />
            </Products>
          </Hardware>
          <Languages>
            <Language Identifier="en-US">
              <TranslationUnit RefId="H-1_P-1">
                <TranslationElement RefId="H-1_P-1">
                  <Translation AttributeName="Text" Text="Switch actuator" />
                </TranslationElement>
              </TranslationUnit>
            </Language>
            <Language Identifier="fr-FR">
              <TranslationUnit RefId="H-1_P-1">
                <TranslationElement RefId="H-1_P-1">
                  <Translation AttributeName="Text" Text="Actionneur" />
                </TranslationElement>
              </TranslationUnit>
            </Language>
          </Languages>
        </KNX>"#;
        let hw = parse_hardware(xml).unwrap();
        assert_eq!(
            hw.products.get("H-1_P-1").unwrap().hardware_name.as_deref(),
            Some("Switch actuator")
        );
    }

    #[test]
    fn parses_hardware2program_app_refs() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="hw">
            <Hardware2Programs>
              <Hardware2Program Id="H-1_HP-1">
                <ApplicationProgramRef RefId="M-0007_A-6179-82-036E" />
                <ApplicationProgramRef RefId="M-0007_A-6179-83-A008" />
              </Hardware2Program>
            </Hardware2Programs>
          </Hardware>
        </KNX>"#;
        let hw = parse_hardware(xml).unwrap();
        assert_eq!(
            hw.hardware2program.get("H-1_HP-1").map(Vec::as_slice),
            Some(
                [
                    "M-0007_A-6179-82-036E".to_string(),
                    "M-0007_A-6179-83-A008".to_string()
                ]
                .as_slice()
            )
        );
    }

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
        let hw = parse_hardware(xml).unwrap();
        assert_eq!(
            hw.order_to_apps.get("2116REG").map(Vec::as_slice),
            Some(["M-0004_A-20D7-26-053C-O000A".to_string()].as_slice())
        );
    }

    #[test]
    fn separates_hardware_blocks() {
        let xml = r#"<KNX>
          <Hardware Id="H-1">
            <Products><Product Id="H-1_P-1" OrderNumber="AAA" /></Products>
            <Hardware2Programs><Hardware2Program Id="H-1_HP-1">
              <ApplicationProgramRef RefId="M-1_A-1" />
            </Hardware2Program></Hardware2Programs>
          </Hardware>
          <Hardware Id="H-2">
            <Products><Product Id="H-2_P-1" OrderNumber="BBB" /></Products>
            <Hardware2Programs><Hardware2Program Id="H-2_HP-1">
              <ApplicationProgramRef RefId="M-1_A-2" />
            </Hardware2Program></Hardware2Programs>
          </Hardware>
        </KNX>"#;
        let hw = parse_hardware(xml).unwrap();
        assert_eq!(hw.order_to_apps.get("AAA").unwrap(), &["M-1_A-1"]);
        assert_eq!(hw.order_to_apps.get("BBB").unwrap(), &["M-1_A-2"]);
    }
}
