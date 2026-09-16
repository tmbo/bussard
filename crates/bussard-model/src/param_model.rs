//! Reading the generated product model YAML (`models/<application_ref>.yaml`)
//! for parameter validation.
//!
//! The product models are written by `bussard import-product` from vendor
//! `.knxprod` data; they are the derived, human-readable description of one
//! application program's parameters (id, type, default, memory). They are the
//! *only* on-disk source of the parameter definitions the validator needs to
//! check a device's `parameters:` block against, so validation parses them back
//! here — lazily, and only for validation. Nothing else in the model depends on
//! them, and their absence is not an error (validation degrades to an info note).
//!
//! Only the fields the validator uses are deserialized. The file carries more
//! (com-objects, load procedure, identity); `#[serde(default)]` and an untagged
//! catch-all keep parsing tolerant of everything else.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// One parsed product model file: its parameter definitions, indexed for lookup.
#[derive(Debug, Clone, Default)]
pub struct ProductModel {
    /// Parameter definitions keyed by their **application-relative** id
    /// (the full id with the `<application_ref>_` prefix stripped, e.g.
    /// `MD-1_P-3` or `P-1312`). A device parameter key resolves to this id by
    /// dropping its `_M-<m>_MI-<n>` module-instance selector and `_R-<r>`
    /// suffix; indexing app-relative lets the lookup ignore the app prefix.
    pub parameters: BTreeMap<String, ParamDef>,
}

/// A single parameter definition, reduced to what validation needs.
#[derive(Debug, Clone)]
pub struct ParamDef {
    /// The parameter type/shape.
    pub kind: ParamKind,
    /// The vendor default value, if any.
    pub default: Option<String>,
}

/// A parameter's type, mirroring the `type:` tag in the model YAML.
#[derive(Debug, Clone)]
pub enum ParamKind {
    /// A bounded integer (`int`).
    Int {
        /// Inclusive minimum, if declared.
        min: Option<i64>,
        /// Inclusive maximum, if declared.
        max: Option<i64>,
        /// Whether the encoding is signed.
        signed: bool,
    },
    /// An enumeration (`enum`) of declared numeric values.
    Enum {
        /// The declared member values.
        values: Vec<i64>,
    },
    /// A fixed-length text field (`text`); `size` is the byte length.
    Text {
        /// The field length in bytes, if declared (`size_bits / 8`).
        len: Option<usize>,
    },
    /// A float (`float`).
    Float,
    /// A marker with no memory (`none`).
    None,
    /// Any other shape (`other`), not range-checked.
    Other,
}

// ---------------------------------------------------------------------------
// Deserialization shapes (mirror the emitter in `import_product_cmd`).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawModel {
    #[serde(default)]
    parameters: Vec<RawParam>,
}

#[derive(Debug, Deserialize)]
struct RawParam {
    id: String,
    #[serde(rename = "type")]
    param_type: RawType,
    #[serde(default)]
    default: Option<String>,
}

// Some fields exist only to consume the YAML shape faithfully; the validator
// reads a subset. `allow(dead_code)` keeps the full shape without warnings.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum RawType {
    Int {
        #[serde(default)]
        min: Option<i64>,
        #[serde(default)]
        max: Option<i64>,
        #[serde(default)]
        size: Option<u32>,
        #[serde(default)]
        signed: bool,
    },
    Enum {
        #[serde(default)]
        values: Vec<RawEnumValue>,
    },
    Text {
        #[serde(default)]
        size: Option<u32>,
    },
    Float {
        #[serde(default)]
        encoding: Option<String>,
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
    },
    None,
    Other {
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        size: Option<u32>,
    },
}

#[derive(Debug, Deserialize)]
struct RawEnumValue {
    value: i64,
    #[serde(default)]
    #[allow(dead_code)]
    text: Option<String>,
}

impl ProductModel {
    /// Parses a product model from YAML text (the emitter's banner is a comment
    /// and is ignored). `app_ref` is the application id, used to strip the
    /// prefix from each parameter id so lookups are app-relative.
    pub fn from_yaml(text: &str, app_ref: &str) -> Result<Self, serde_norway::Error> {
        let raw: RawModel = serde_norway::from_str(text)?;
        let mut parameters = BTreeMap::new();
        let prefix = format!("{app_ref}_");
        for p in raw.parameters {
            let rel = p.id.strip_prefix(&prefix).unwrap_or(&p.id).to_string();
            parameters.insert(
                rel,
                ParamDef {
                    kind: p.param_type.into_kind(),
                    default: p.default,
                },
            );
        }
        Ok(ProductModel { parameters })
    }
}

impl RawType {
    fn into_kind(self) -> ParamKind {
        match self {
            RawType::Int {
                min, max, signed, ..
            } => ParamKind::Int { min, max, signed },
            RawType::Enum { values } => ParamKind::Enum {
                values: values.into_iter().map(|v| v.value).collect(),
            },
            RawType::Text { size } => ParamKind::Text {
                len: size.map(|b| (b / 8) as usize),
            },
            RawType::Float { .. } => ParamKind::Float,
            RawType::None => ParamKind::None,
            RawType::Other { .. } => ParamKind::Other,
        }
    }
}

/// The product models available for validation, keyed by application ref, loaded
/// lazily from `<dir>/models/*.yaml`.
///
/// Missing or unparsable files are simply absent from the map (a missing model
/// is an info-level note during validation, never a hard error). The `models/`
/// directory is local-only vendor-derived data, so it is often absent entirely.
#[derive(Debug, Clone, Default)]
pub struct ProductModels {
    /// Parsed models keyed by application ref (the file stem).
    pub by_app_ref: BTreeMap<String, ProductModel>,
}

impl ProductModels {
    /// Loads every `models/*.yaml` under `dir` (best-effort). Returns an empty
    /// set when the directory is absent. Individual files that fail to parse are
    /// skipped (their app then reads as "no model", an info-level note).
    pub fn load(dir: &Path) -> Self {
        let models_dir = dir.join("models");
        let mut by_app_ref = BTreeMap::new();
        let Ok(entries) = std::fs::read_dir(&models_dir) else {
            return Self::default();
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml");
            if !is_yaml {
                continue;
            }
            let Some(app_ref) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Ok(model) = ProductModel::from_yaml(&text, app_ref) {
                by_app_ref.insert(app_ref.to_string(), model);
            }
        }
        Self { by_app_ref }
    }

    /// Looks up the model for an application ref, if loaded.
    pub fn get(&self, app_ref: &str) -> Option<&ProductModel> {
        self.by_app_ref.get(app_ref)
    }
}

/// Reduces a device parameter **key** to the application-relative parameter id
/// it names, so it can be looked up in a [`ProductModel`].
///
/// The key is `<name-slug>@<app-relative-ref-id>`; the ref id preserves the
/// module-instance selector and ends in `_R-<r>`. Dropping the slug, the
/// `_M-<m>_MI-<n>` selector and the `_R-<r>` suffix yields the parameter id:
///
/// * `windalarm-1@MD-1_M-3_MI-1_P-3_R-45` → `MD-1_P-3`
/// * `nachtabsenkung@P-1312_R-2140` → `P-1312`
///
/// Returns `None` if the key has no `@` or no `_R-` ref suffix (malformed).
pub fn key_to_param_id(key: &str) -> Option<String> {
    let ref_id = key.split_once('@').map(|(_, r)| r)?;
    // Strip the trailing `_R-<r>` ref suffix.
    let param_ref = ref_id.rsplit_once("_R-")?.0;
    // Strip a `_M-<m>_MI-<n>` module-instance selector, if present. The
    // remaining id is `MD-<d>_<param>` or a plain `<param>`.
    Some(strip_module_instance(param_ref))
}

/// Removes the `_M-<m>_MI-<n>` module-instance selector from an app-relative
/// parameter ref, leaving the module-definition-relative parameter id. Mirrors
/// the importer's `normalize_ref` for the parameter case.
fn strip_module_instance(param_ref: &str) -> String {
    // Only module refs (`MD-…_M-…_MI-…_P-…`) carry the selector.
    if !param_ref.starts_with("MD-") {
        return param_ref.to_string();
    }
    let Some(m_pos) = param_ref.find("_M-") else {
        return param_ref.to_string();
    };
    let module_def = &param_ref[..m_pos]; // "MD-1"
    let after = &param_ref[m_pos + 1..]; // "M-3_MI-1_P-3"
    let Some(mi_pos) = after.find("_MI-") else {
        return param_ref.to_string();
    };
    let rest = &after[mi_pos + "_MI-".len()..]; // "1_P-3"
    let Some(obj_pos) = rest.find('_') else {
        return param_ref.to_string();
    };
    let param_part = &rest[obj_pos + 1..]; // "P-3"
    format!("{module_def}_{param_part}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_reduces_to_param_id_module_and_plain() {
        assert_eq!(
            key_to_param_id("windalarm-1@MD-1_M-3_MI-1_P-3_R-45").as_deref(),
            Some("MD-1_P-3")
        );
        assert_eq!(
            key_to_param_id("nachtabsenkung@P-1312_R-2140").as_deref(),
            Some("P-1312")
        );
        // Missing `@` or `_R-` is malformed.
        assert_eq!(key_to_param_id("noatsign_R-1"), None);
        assert_eq!(key_to_param_id("slug@P-1"), None);
    }

    #[test]
    fn parses_model_yaml_indexed_app_relative() {
        let app = "M-00FA_A-1";
        let yaml = "\
identity:
  id: M-00FA_A-1
parameters:
  - id: M-00FA_A-1_MD-1_P-3
    name: _xJA_Windalarm
    type: !int
      min: 0
      max: 3
      size: 2
    default: '0'
  - id: M-00FA_A-1_P-9
    type: !enum
      values:
        - value: 0
          text: Off
        - value: 7
          text: On
    default: '0'
";
        let m = ProductModel::from_yaml(yaml, app).unwrap();
        assert!(m.parameters.contains_key("MD-1_P-3"));
        let p = &m.parameters["MD-1_P-3"];
        assert!(matches!(
            p.kind,
            ParamKind::Int {
                min: Some(0),
                max: Some(3),
                ..
            }
        ));
        assert_eq!(p.default.as_deref(), Some("0"));
        match &m.parameters["P-9"].kind {
            ParamKind::Enum { values } => assert_eq!(values, &[0, 7]),
            other => panic!("expected enum, got {other:?}"),
        }
    }
}
