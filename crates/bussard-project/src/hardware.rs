//! Minimal parser for a manufacturer `Hardware.xml`: maps a product id to its
//! order number and hardware name, for enriching device identity.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{ImportError, Result};

/// Product identity looked up from `Hardware.xml`.
#[derive(Debug, Clone, Default)]
pub struct ProductInfo {
    /// The catalogue order number, e.g. `"2116REG"`.
    pub order_number: Option<String>,
    /// The hardware display name, e.g. `"Binäreingang 6fach"`.
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
}

/// Parses `Hardware.xml`, returning products and Hardware2Program → app refs.
///
/// A `<Product>` inherits its name from the enclosing `<Hardware Name=…>`; the
/// order number comes from the product's own `OrderNumber` attribute.
pub fn parse_hardware(xml: &str) -> Result<Hardware> {
    let context = "Hardware.xml";
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut map: HashMap<String, ProductInfo> = HashMap::new();
    let mut h2p: HashMap<String, Vec<String>> = HashMap::new();
    let mut current_h2p_id: Option<String> = None;
    let mut current_hw_name: Option<String> = None;

    // Translation state for the `<Languages>` section. We collect the product
    // `Text` attribute translated to en-US (preferred) or de-DE, keyed by
    // product id, then apply them after parsing.
    let mut current_lang: Option<String> = None;
    let mut current_tu: Option<String> = None;
    // (language, product id) -> translated Text.
    let mut translations: HashMap<(String, String), String> = HashMap::new();

    loop {
        match reader.read_event().map_err(|source| ImportError::Xml {
            context: context.to_string(),
            source,
        })? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"Hardware" => {
                    current_hw_name = attr(&e, b"Name", context)?;
                }
                b"Product" => {
                    if let Some(id) = attr(&e, b"Id", context)? {
                        // Prefer the product's own `Text` as the display name,
                        // falling back to the enclosing hardware `Name`.
                        let name = attr(&e, b"Text", context)?
                            .filter(|s| !s.is_empty())
                            .or_else(|| current_hw_name.clone());
                        map.insert(
                            id,
                            ProductInfo {
                                order_number: attr(&e, b"OrderNumber", context)?,
                                hardware_name: name,
                            },
                        );
                    }
                }
                b"Hardware2Program" => {
                    current_h2p_id = attr(&e, b"Id", context)?;
                    if let Some(id) = &current_h2p_id {
                        h2p.entry(id.clone()).or_default();
                    }
                }
                b"ApplicationProgramRef" => {
                    if let (Some(h2p_id), Some(ref_id)) =
                        (&current_h2p_id, attr(&e, b"RefId", context)?)
                    {
                        h2p.entry(h2p_id.clone()).or_default().push(ref_id);
                    }
                }
                b"Language" => {
                    current_lang = attr(&e, b"Identifier", context)?;
                }
                b"TranslationElement" => {
                    current_tu = attr(&e, b"RefId", context)?;
                }
                b"Translation" => {
                    if let (Some(lang), Some(tu)) = (&current_lang, &current_tu) {
                        if attr(&e, b"AttributeName", context)?.as_deref() == Some("Text") {
                            if let Some(text) = attr(&e, b"Text", context)? {
                                translations.insert((lang.clone(), tu.clone()), text);
                            }
                        }
                    }
                }
                _ => {}
            },
            Event::End(e) => match e.local_name().as_ref() {
                b"Hardware" => current_hw_name = None,
                b"Hardware2Program" => current_h2p_id = None,
                b"Language" => current_lang = None,
                b"TranslationElement" => current_tu = None,
                _ => {}
            },
            _ => {}
        }
    }

    // Apply the en-US translation to product names when present; otherwise keep
    // the raw `Text` attribute (which is in the product's DefaultLanguage). This
    // mirrors ETS/xknxproject resolving to en-US by default and falling back to
    // the untranslated attribute rather than to another language.
    for (id, info) in map.iter_mut() {
        if let Some(text) = translations.get(&("en-US".to_string(), id.clone())) {
            info.hardware_name = Some(text.clone());
        }
    }

    Ok(Hardware {
        products: map,
        hardware2program: h2p,
    })
}

/// Reads a single attribute's unescaped value from a start/empty tag.
fn attr(e: &quick_xml::events::BytesStart, key: &[u8], context: &str) -> Result<Option<String>> {
    for a in e.attributes() {
        let a = a.map_err(|source| ImportError::XmlAttr {
            context: context.to_string(),
            source,
        })?;
        if a.key.as_ref() == key {
            let v = a.unescape_value().map_err(|source| ImportError::Xml {
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
    fn product_prefers_text_over_hardware_name() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
          <Hardware Id="H-1" Name="Hardware name">
            <Products>
              <Product Id="H-1_P-2116REG" OrderNumber="2116REG" Text="Binäreingang 6fach" />
            </Products>
          </Hardware>
        </KNX>"#;
        let hw = parse_hardware(xml).unwrap();
        let p = hw.products.get("H-1_P-2116REG").unwrap();
        assert_eq!(p.order_number.as_deref(), Some("2116REG"));
        assert_eq!(p.hardware_name.as_deref(), Some("Binäreingang 6fach"));
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
}
