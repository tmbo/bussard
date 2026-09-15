//! en-US translation resolution for ETS XML.
//!
//! ETS stores non-default-language strings in a `<Languages>` section:
//!
//! ```xml
//! <Languages>
//!   <Language Identifier="en-US">
//!     <TranslationUnit RefId="…">
//!       <TranslationElement RefId="<element-id>">
//!         <Translation AttributeName="Text" Text="Switch" />
//!       </TranslationElement>
//!     </TranslationUnit>
//!   </Language>
//! </Languages>
//! ```
//!
//! ETS/xknxproject resolve display strings to en-US by default, falling back to
//! the untranslated attribute (the element's `DefaultLanguage`) rather than to
//! some other language. This collector applies that rule: it keeps only en-US
//! `<Translation>` values, keyed by `(element id, attribute name)`, and the
//! parser applies them after the main pass.

use std::collections::HashMap;

use crate::attrs::get;

/// Collects en-US translations while streaming an ETS XML file.
///
/// The parser feeds it `Language`, `TranslationElement`, and `Translation`
/// events; it retains only the en-US layer.
#[derive(Debug, Default)]
pub struct TranslationCollector {
    cur_lang: Option<String>,
    cur_element: Option<String>,
    /// `(element id, attribute name)` → en-US text.
    translations: HashMap<(String, String), String>,
}

impl TranslationCollector {
    /// Creates an empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the enclosing `<Language Identifier=…>`.
    pub fn enter_language(&mut self, identifier: Option<&str>) {
        self.cur_lang = identifier.map(str::to_string);
    }

    /// Clears the current language (on `</Language>`).
    pub fn exit_language(&mut self) {
        self.cur_lang = None;
    }

    /// Records the current `<TranslationElement RefId=…>` (or `<TranslationUnit>`
    /// where a parser keys on that instead).
    pub fn enter_element(&mut self, ref_id: Option<&str>) {
        self.cur_element = ref_id.map(str::to_string);
    }

    /// Clears the current translation element.
    pub fn exit_element(&mut self) {
        self.cur_element = None;
    }

    /// Records a `<Translation AttributeName=… Text=…>` if the enclosing
    /// language is en-US and it targets one of `wanted_attrs`.
    ///
    /// `m` is the parsed attribute map of the `<Translation>` tag.
    pub fn record(&mut self, m: &HashMap<Vec<u8>, String>, wanted_attrs: &[&str]) {
        if self.cur_lang.as_deref() != Some("en-US") {
            return;
        }
        let (Some(element), Some(attr_name), Some(text)) = (
            self.cur_element.as_deref(),
            get(m, b"AttributeName"),
            get(m, b"Text"),
        ) else {
            return;
        };
        if wanted_attrs.contains(&attr_name) {
            self.translations.insert(
                (element.to_string(), attr_name.to_string()),
                text.to_string(),
            );
        }
    }

    /// The en-US text for `(element id, attribute)`, if collected.
    pub fn get(&self, element_id: &str, attribute: &str) -> Option<&str> {
        self.translations
            .get(&(element_id.to_string(), attribute.to_string()))
            .map(String::as_str)
    }

    /// Whether nothing was collected (lets the parser skip the apply pass).
    pub fn is_empty(&self) -> bool {
        self.translations.is_empty()
    }
}
