//! Translation resolution for ETS XML.
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
//! A collector keeps the `<Translation>` values of one language, keyed by
//! `(element id, attribute name)`, and the parser applies them after the main
//! pass. An attribute without a translation keeps its untranslated text (the
//! program's `DefaultLanguage`) rather than falling back to some other
//! language. [`TranslationCollector::new`] collects en-US, the language
//! ETS/xknxproject resolve to by default; `bussard import` picks the
//! project's language instead (see [`TranslationCollector::for_language`]).

use std::collections::{BTreeMap, HashMap};

use crate::attrs::{Attrs, get};

/// The language [`TranslationCollector::new`] collects.
pub const DEFAULT_LANGUAGE: &str = "en-US";

/// Collects the translations of one language while streaming an ETS XML file.
///
/// The parser feeds it `Language`, `TranslationElement`, and `Translation`
/// events; it retains only the layer of its language.
#[derive(Debug)]
pub struct TranslationCollector {
    /// The language kept, e.g. `de-DE`.
    language: String,
    cur_lang: Option<String>,
    cur_element: Option<String>,
    /// `(element id, attribute name)` → translated text.
    translations: HashMap<(String, String), String>,
    /// Enumeration element id → language → translated `Text`, in every
    /// language the file carries (see [`TranslationCollector::enum_labels`]).
    enum_labels: HashMap<String, BTreeMap<String, String>>,
}

impl Default for TranslationCollector {
    fn default() -> Self {
        Self::for_language(DEFAULT_LANGUAGE)
    }
}

impl TranslationCollector {
    /// Creates an empty collector for en-US.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty collector for `language` (an ETS identifier such as
    /// `de-DE`, compared without regard to case).
    pub fn for_language(language: &str) -> Self {
        Self {
            language: language.to_string(),
            cur_lang: None,
            cur_element: None,
            translations: HashMap::new(),
            enum_labels: HashMap::new(),
        }
    }

    /// The language this collector keeps.
    pub fn language(&self) -> &str {
        &self.language
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
    /// language is the collector's and it targets one of `wanted_attrs`.
    ///
    /// `m` is the parsed attribute map of the `<Translation>` tag.
    ///
    /// Independently of the language, the `Text` of an enumeration member
    /// (an element id carrying the schema's `_EN-` member suffix) is kept in
    /// every language, so a label written in another language still names
    /// its member (see [`TranslationCollector::enum_labels`]).
    pub fn record(&mut self, m: &Attrs, wanted_attrs: &[&str]) {
        if let (Some(lang), Some(element), Some("Text"), Some(text)) = (
            self.cur_lang.as_deref(),
            self.cur_element.as_deref(),
            get(m, b"AttributeName"),
            get(m, b"Text"),
        ) && element.contains("_EN-")
        {
            self.enum_labels
                .entry(element.to_string())
                .or_default()
                .insert(lang.to_string(), text.to_string());
        }
        if !self
            .cur_lang
            .as_deref()
            .is_some_and(|l| l.eq_ignore_ascii_case(&self.language))
        {
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

    /// The translated text for `(element id, attribute)`, if collected.
    pub fn get(&self, element_id: &str, attribute: &str) -> Option<&str> {
        self.translations
            .get(&(element_id.to_string(), attribute.to_string()))
            .map(String::as_str)
    }

    /// The translated `Text` of enumeration member `element_id` in every
    /// language the file carries, keyed by language identifier, if any.
    pub fn enum_labels(&self, element_id: &str) -> Option<&BTreeMap<String, String>> {
        self.enum_labels.get(element_id)
    }

    /// Whether nothing was collected (lets the parser skip the apply pass).
    pub fn is_empty(&self) -> bool {
        self.translations.is_empty() && self.enum_labels.is_empty()
    }
}
