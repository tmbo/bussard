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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

/// One parsed product model file: its parameter definitions, indexed for lookup.
#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
pub struct ProductModel {
    /// The bus current this product draws, in mA, as declared by the vendor's
    /// `Hardware.xml` (`BusCurrent`). Used by the `L002` topology lint to total
    /// a line's draw against its power supply. `None` when the cached model
    /// predates the field or the vendor omitted it.
    pub bus_current_ma: Option<u32>,
    /// Parameter definitions keyed by their **application-relative** id
    /// (the full id with the `<application_ref>_` prefix stripped, e.g.
    /// `MD-1_P-3` or `P-1312`). A device parameter key resolves to this id by
    /// dropping its `_M-<m>_MI-<n>` module-instance selector and `_R-<r>`
    /// suffix; indexing app-relative lets the lookup ignore the app prefix.
    pub parameters: BTreeMap<String, ParamDef>,
    /// The com-objects by number: the vendor's text, function and DPT.
    pub com_objects: BTreeMap<u16, ObjectDef>,
    /// The com-object refs of the application's Dynamic section that
    /// [`Self::com_objects`] describes through another ref of the same
    /// number, keyed by app-relative ref id (`O-32_R-454`).
    pub com_object_refs: BTreeMap<String, ObjectDef>,
    /// The application program id (`M-0002_A-A0ED-10-9B4E`), the prefix the
    /// app-relative ids drop.
    pub program_id: String,
    /// The Data Secure table capacities of a Data-Secure-capable application
    /// (`data_secure:`, format 9, issue #537); `None` for an application that
    /// does not declare `IsSecureEnabled`.
    pub data_secure: Option<DataSecureCapacity>,
    /// The application's own Dynamic section (`dynamic:`, format 5, issue
    /// #345), app-relative ids throughout: what [`crate::dynamic::evaluate_dynamic`]
    /// walks through this model's [`crate::dynamic::DynamicSource`] impl.
    #[serde(with = "crate::dynamic_compact::nodes")]
    pub dynamic: Vec<crate::dynamic::DynamicNode>,
    /// The Dynamic section of every module definition, keyed by app-relative
    /// module definition id (`MD-1`) (`module_dynamics:`, format 5).
    #[serde(with = "crate::dynamic_compact::module_nodes")]
    pub module_dynamics: BTreeMap<String, Vec<crate::dynamic::DynamicNode>>,
    /// The application's `<Union>`s, in document order, each with its size
    /// and its members' app-relative parameter ids and positions (`unions:`,
    /// format 5).
    #[serde(with = "crate::dynamic_compact::unions")]
    pub unions: Vec<crate::dynamic::Union>,
    /// Every parameter ref of the application, keyed by app-relative ref id:
    /// its parameter, its `Value` where it matters and whether it is internal
    /// (the `refs:` of each parameter, format 5).
    pub parameter_refs: BTreeMap<String, RefDef>,
    /// The application's and the module definitions' `<Allocator>`s, keyed
    /// by app-relative id (`L-2`, `MD-1_L-1`) (`allocators:`, format 10,
    /// issue #449).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allocators: BTreeMap<String, crate::dynamic::Allocator>,
    /// The `Allocates` of every module `<Argument>` that declares one, keyed
    /// by app-relative argument id (`argument_allocates:`, format 10).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub argument_allocates: BTreeMap<String, i64>,
    /// The ETS parameter pages and channels, derived from [`Self::dynamic`]
    /// on first use ([`Self::blocks`]).
    #[serde(skip)]
    pages: std::sync::OnceLock<Vec<crate::blocks::BlockDef>>,
}

/// The Data Secure table capacities a product declares (the application's
/// `MaxSecurity*` attributes, issue #537): how many entries the group key
/// table (PID 53), the security individual address table (PID 54) and the
/// point-to-point key table hold. `None` where the product gives no figure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct DataSecureCapacity {
    /// `MaxSecurityGroupKeyTableEntries`.
    #[serde(
        default,
        rename = "max_group_key_table_entries",
        skip_serializing_if = "Option::is_none"
    )]
    pub group_key_table_entries: Option<u32>,
    /// `MaxSecurityIndividualAddressEntries`.
    #[serde(
        default,
        rename = "max_individual_address_entries",
        skip_serializing_if = "Option::is_none"
    )]
    pub individual_address_entries: Option<u32>,
    /// `MaxSecurityP2PKeyTableEntries`.
    #[serde(
        default,
        rename = "max_p2p_key_table_entries",
        skip_serializing_if = "Option::is_none"
    )]
    pub p2p_key_table_entries: Option<u32>,
}

/// One `ParameterRef` of a product model (an entry of a parameter's `refs:`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct RefDef {
    /// The app-relative id of the parameter it points at.
    pub parameter: String,
    /// The ref's `Value`, where the model's parameter `default` does not give
    /// it already: the value the ref has when nothing is stored.
    pub value: Option<String>,
    /// Whether the ref's effective `Access` is `None`: ETS keeps the value
    /// to itself and never shows it.
    pub internal: bool,
    /// The ref's own `Text`, where it differs from its parameter's: what
    /// titles a page whose `ParamRefId` names the ref.
    pub text: Option<String>,
}

/// One com-object of a product model, reduced to what a view shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct ObjectDef {
    /// The vendor's object text.
    pub text: Option<String>,
    /// The vendor's function text.
    pub function: Option<String>,
    /// The datapoint type, as written.
    pub dpt: Option<String>,
    /// The communication flags, as written.
    pub flags: Option<String>,
    /// The transmission priority the product declares, where it is not Low
    /// (format 8, issue #541).
    pub priority: Option<crate::flags::Priority>,
}

/// The product-model format this build writes: `model_format:` at the top of
/// the file. A model of an older format regenerates from its archive
/// (format 2 adds `blocks:`, issue #298; format 3 the conditions inside a
/// block, `parameter_when:`, issue #315; format 4 the `ParameterRef` values,
/// `ref_values:`, issue #326; format 5 the Dynamic tree, `dynamic:`,
/// `module_dynamics:`, `unions:` and each parameter's `refs:`, `base_value`
/// and integer width, issue #345; format 6 drops `blocks:`,
/// `parameter_when:` and `ref_values:`, which the tree gives, and writes a
/// parameter's own default, issue #345; format 7 a text type's
/// `encoding:`, issue #401; format 8 a com-object's `priority:` where it is
/// not Low, issue #541; format 9 a Data-Secure-capable application's table
/// capacities, `data_secure:`, issue #537; format 10 `<Repeat>` nodes, a
/// module's computed arguments, `allocators:` and `argument_allocates:`,
/// issue #449).
pub const MODEL_FORMAT: u32 = 10;

/// Whether the model file at `path` is of the current [`MODEL_FORMAT`]. Reads
/// only the head of the file, where the emitter puts the key.
pub fn model_is_current(path: &Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut bytes = Vec::with_capacity(4096);
    if file.take(4096).read_to_end(&mut bytes).is_err() {
        return false;
    }
    let head = String::from_utf8_lossy(&bytes);
    let wanted = format!("model_format: {MODEL_FORMAT}");
    head.lines().any(|l| l.trim_end() == wanted)
}

/// A single parameter definition, reduced to what validation needs.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct ParamDef {
    /// The parameter type/shape.
    pub kind: ParamKind,
    /// The vendor default value, if any.
    pub default: Option<String>,
    /// The parameter's human-readable text as ETS shows it (e.g. "Night
    /// setback"), when the product model carries one.
    pub text: Option<String>,
    /// For an enumeration, its `(code, text)` pairs in document order: the
    /// labels a device file may write instead of the code (see
    /// [`enum_label`] and [`enum_code`]). Empty for other kinds.
    pub labels: Vec<(i64, String)>,
    /// The parameter's `Name`, when the product model carries one.
    pub name: Option<String>,
    /// The parameter refs that point at this parameter, app-relative
    /// (`MD-1_P-3_R-45` without the module-instance selector), when the
    /// product model lists them (`refs:`). A device-file key the lock does not
    /// list resolves through them (see [`ProductModel::resolve_key`]).
    pub refs: Vec<String>,
    /// The `BaseValue` argument id: a module parameter whose default has the
    /// instance's value of this argument added to it (issue #126).
    pub base_value: Option<String>,
    /// Width in bits and signedness of an integer or plain enumeration
    /// parameter (`bits:`, `signed:`), `None` for any other type: what a
    /// shared `<Union>` memory is read back with.
    pub integer_width: Option<(u32, bool)>,
    /// For an enumeration, its members (code and label): what an override
    /// written as a label is matched against. Empty for other kinds.
    pub enum_values: Vec<crate::dynamic::EnumValue>,
}

/// A parameter's type, mirroring the `type:` tag in the model YAML.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
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
        /// The program's `TextParameterEncoding`, the code page the text is
        /// written in (issue #401); `None` when undeclared.
        #[serde(default)]
        encoding: Option<String>,
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
    bus_current_ma: Option<u32>,
    #[serde(default)]
    parameters: Vec<RawParam>,
    #[serde(default)]
    com_objects: BTreeMap<u16, RawComObject>,
    #[serde(default)]
    com_object_refs: BTreeMap<String, RawComObject>,
    #[serde(default, with = "crate::dynamic_compact::nodes")]
    dynamic: Vec<crate::dynamic::DynamicNode>,
    #[serde(default, with = "crate::dynamic_compact::module_nodes")]
    module_dynamics: BTreeMap<String, Vec<crate::dynamic::DynamicNode>>,
    #[serde(default, with = "crate::dynamic_compact::unions")]
    unions: Vec<crate::dynamic::Union>,
    #[serde(default)]
    data_secure: Option<DataSecureCapacity>,
    #[serde(default)]
    allocators: BTreeMap<String, crate::dynamic::Allocator>,
    #[serde(default)]
    argument_allocates: BTreeMap<String, i64>,
}

#[derive(Debug, Deserialize)]
struct RawComObject {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    function_text: Option<String>,
    #[serde(default)]
    dpt: Option<String>,
    #[serde(default)]
    flags: Option<String>,
    #[serde(default)]
    priority: Option<crate::flags::Priority>,
}

#[derive(Debug, Deserialize)]
struct RawParam {
    id: String,
    #[serde(rename = "type")]
    param_type: RawType,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    refs: BTreeMap<String, Option<RawRef>>,
    #[serde(default)]
    base_value: Option<String>,
    #[serde(default)]
    bits: Option<u32>,
    #[serde(default)]
    signed: bool,
}

#[derive(Debug, Default, Deserialize)]
struct RawRef {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    internal: bool,
    #[serde(default)]
    text: Option<String>,
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
        #[serde(default)]
        encoding: Option<String>,
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
    text: Option<String>,
}

impl ProductModel {
    /// The vendor's description of com-object ref `reference` (app-relative):
    /// its own entry when the ref is not the one `com_objects` describes, else
    /// that of its number.
    pub fn object_def(&self, reference: &str) -> Option<&ObjectDef> {
        self.com_object_refs.get(reference).or_else(|| {
            crate::blocks::object_number(reference).and_then(|n| self.com_objects.get(&n))
        })
    }

    /// Parses a product model from YAML text (the emitter's banner is a comment
    /// and is ignored). `app_ref` is the application id, used to strip the
    /// prefix from each parameter id so lookups are app-relative.
    pub fn from_yaml(text: &str, app_ref: &str) -> Result<Self, serde_norway::Error> {
        let raw: RawModel = serde_norway::from_str(text)?;
        let mut parameters = BTreeMap::new();
        let mut parameter_refs = BTreeMap::new();
        let prefix = format!("{app_ref}_");
        let relative = |id: &str| id.strip_prefix(&prefix).unwrap_or(id).to_string();
        for p in raw.parameters {
            let rel = relative(&p.id);
            let (labels, enum_values) = match &p.param_type {
                RawType::Enum { values } => (
                    values
                        .iter()
                        .filter_map(|v| v.text.clone().map(|t| (v.value, t)))
                        .collect(),
                    values
                        .iter()
                        .map(|v| {
                            let text = v.text.clone().unwrap_or_default();
                            crate::dynamic::EnumValue {
                                value: v.value,
                                default_text: text.clone(),
                                text,
                                translations: BTreeMap::new(),
                                id: None,
                                binary_value: None,
                            }
                        })
                        .collect(),
                ),
                _ => (Vec::new(), Vec::new()),
            };
            let mut refs = Vec::with_capacity(p.refs.len());
            for (reference, def) in p.refs {
                let def = def.unwrap_or_default();
                let reference = relative(&reference);
                refs.push(reference.clone());
                parameter_refs.insert(
                    reference,
                    RefDef {
                        parameter: rel.clone(),
                        value: def.value,
                        internal: def.internal,
                        text: def.text,
                    },
                );
            }
            parameters.insert(
                rel,
                ParamDef {
                    labels,
                    kind: p.param_type.into_kind(),
                    default: p.default,
                    text: p.text.filter(|t| !t.trim().is_empty()),
                    name: p.name.filter(|n| !n.trim().is_empty()),
                    refs,
                    base_value: p.base_value,
                    integer_width: p.bits.map(|bits| (bits, p.signed)),
                    enum_values,
                },
            );
        }
        let object = |o: RawComObject| ObjectDef {
            text: o.text,
            function: o.function_text,
            dpt: o.dpt,
            flags: o.flags,
            priority: o.priority,
        };
        let com_objects = raw
            .com_objects
            .into_iter()
            .map(|(n, o)| (n, object(o)))
            .collect();
        let com_object_refs = raw
            .com_object_refs
            .into_iter()
            .map(|(r, o)| (r, object(o)))
            .collect();
        Ok(ProductModel {
            bus_current_ma: raw.bus_current_ma,
            parameters,
            com_objects,
            com_object_refs,
            program_id: app_ref.to_string(),
            data_secure: raw.data_secure,
            dynamic: raw.dynamic,
            module_dynamics: raw.module_dynamics,
            unions: raw.unions,
            parameter_refs,
            allocators: raw.allocators,
            argument_allocates: raw.argument_allocates,
            pages: std::sync::OnceLock::new(),
        })
    }

    /// The ETS parameter pages and channels of the application's own
    /// Dynamic section, in document order, derived from the tree once
    /// ([`crate::blocks::pages_of`]).
    pub fn blocks(&self) -> &[crate::blocks::BlockDef] {
        self.pages.get_or_init(|| crate::blocks::pages_of(self))
    }

    /// The vendor default of app-relative parameter ref `reference`: the
    /// ref's own `Value` when the model records one, else the parameter's
    /// default. This is the value ETS shows, and a download writes, when
    /// nothing is stored (issue #326).
    pub fn ref_default(&self, reference: &str) -> Option<&str> {
        match self.parameter_refs.get(reference) {
            Some(r) => r
                .value
                .as_deref()
                .or_else(|| self.parameters.get(&r.parameter)?.default.as_deref()),
            None => self
                .parameters
                .get(crate::blocks::ref_param_id(reference))
                .and_then(|d| d.default.as_deref()),
        }
    }

    /// Resolves a device-file parameter key the lock does not list, in the
    /// scope of module instance `selector` (`MD-3_M-18_MI-1`, `None` for an
    /// application channel or the device level), to a device-form parameter
    /// ref (`MD-3_M-18_MI-1_P-14_R-14`).
    ///
    /// The key's last `.`-separated part must equal the slug of exactly one
    /// parameter's text (else its name) among the parameters of that scope
    /// (the module definition's, or the application's own), and that
    /// parameter must have exactly one ref. `None` otherwise: the model lacks
    /// the refs, the key is unknown, or it is ambiguous.
    pub fn resolve_key(&self, selector: Option<&str>, key: &str) -> Option<String> {
        let wanted = key.rsplit('.').next().unwrap_or(key);
        let module_def = selector.and_then(|s| s.split_once('_').map(|(md, _)| md));
        let mut hits = self.parameters.iter().filter(|(id, def)| {
            let in_scope = match module_def {
                Some(md) => id.strip_prefix(md).is_some_and(|r| r.starts_with('_')),
                None => !id.starts_with("MD-"),
            };
            in_scope
                && def
                    .text
                    .as_deref()
                    .or(def.name.as_deref())
                    .is_some_and(|t| crate::slug(t) == wanted)
        });
        let (_, def) = hits.next()?;
        if hits.next().is_some() {
            return None;
        }
        let [reference] = def.refs.as_slice() else {
            return None;
        };
        match (selector, module_def) {
            (Some(sel), Some(md)) => {
                let rest = reference.strip_prefix(md)?;
                Some(format!("{sel}{rest}"))
            }
            _ => Some(reference.clone()),
        }
    }
}

/// The product model as the Dynamic evaluator's input (issue #345): the same
/// walk as over the application XML, from the tree, refs and unions the
/// model carries. Parameter ids are app-relative.
impl crate::dynamic::DynamicSource for ProductModel {
    fn program_id(&self) -> &str {
        &self.program_id
    }

    fn dynamic(&self) -> &[crate::dynamic::DynamicNode] {
        &self.dynamic
    }

    fn module_dynamic(&self, module_def: &str) -> Option<&[crate::dynamic::DynamicNode]> {
        self.module_dynamics.get(module_def).map(Vec::as_slice)
    }

    fn module_dynamics(
        &self,
    ) -> Box<dyn Iterator<Item = (&str, &[crate::dynamic::DynamicNode])> + '_> {
        Box::new(
            self.module_dynamics
                .iter()
                .map(|(def, body)| (def.as_str(), body.as_slice())),
        )
    }

    fn parameter_ref(&self, ref_id: &str) -> Option<(&str, Option<&str>)> {
        self.parameter_refs
            .get(ref_id)
            .map(|r| (r.parameter.as_str(), r.value.as_deref()))
    }

    fn parameter_refs(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(
            self.parameter_refs
                .iter()
                .map(|(r, def)| (r.as_str(), def.parameter.as_str())),
        )
    }

    fn parameter(&self, param_id: &str) -> Option<(Option<&str>, Option<&str>)> {
        self.parameters
            .get(param_id)
            .map(|p| (p.default.as_deref(), p.base_value.as_deref()))
    }

    fn integer_width(&self, param_id: &str) -> Option<(u32, bool)> {
        self.parameters.get(param_id)?.integer_width
    }

    fn enum_members(&self, param_id: &str) -> Option<&[crate::dynamic::EnumValue]> {
        let def = self.parameters.get(param_id)?;
        match def.kind {
            ParamKind::Enum { .. } => Some(def.enum_values.as_slice()),
            _ => None,
        }
    }

    fn unions(&self) -> &[crate::dynamic::Union] {
        &self.unions
    }

    fn allocator(&self, allocator_id: &str) -> Option<crate::dynamic::Allocator> {
        self.allocators.get(allocator_id).copied()
    }

    fn argument_allocates(&self, arg_id: &str) -> Option<i64> {
        self.argument_allocates.get(arg_id).copied()
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
            RawType::Text { size, encoding } => ParamKind::Text {
                len: size.map(|b| (b / 8) as usize),
                encoding,
            },
            RawType::Float { .. } => ParamKind::Float,
            RawType::None => ParamKind::None,
            RawType::Other { .. } => ParamKind::Other,
        }
    }
}

/// Where the product models live under a model directory: regenerated data
/// under `.bussard/` (issue #228), derived from the archives in `products/`.
pub const MODELS_DIR: &str = ".bussard/models";

/// The product-model directories of `dir`, in lookup order. The location
/// earlier versions used (`<dir>/models/`) is not read: those models
/// regenerate from `products/`.
pub fn models_dirs(dir: &Path) -> [std::path::PathBuf; 1] {
    [dir.join(MODELS_DIR)]
}

/// The product models available for validation, keyed by application ref, loaded
/// lazily from `<dir>/models/*.yaml`.
///
/// Missing or unparsable files are simply absent from the map (a missing model
/// is an info-level note during validation, never a hard error). The `models/`
/// directory is local-only vendor-derived data, so it is often absent entirely.
///
/// Each model is shared ([`Arc`]): a load is served from a process-wide memo
/// and the JSON cache under [`MODEL_CACHE_DIR`] (issue #339), so a model file
/// is parsed at most once per process and per change.
#[derive(Debug, Clone, Default)]
pub struct ProductModels {
    /// Parsed models keyed by application ref (the file stem).
    pub by_app_ref: BTreeMap<String, Arc<ProductModel>>,
}

impl ProductModels {
    /// Loads every `models/*.yaml` under `dir` (best-effort). Returns an empty
    /// set when the directory is absent. Individual files that fail to parse are
    /// skipped (their app then reads as "no model", an info-level note).
    pub fn load(dir: &Path) -> Self {
        let mut by_app_ref = BTreeMap::new();
        let entries = models_dirs(dir)
            .into_iter()
            .filter_map(|d| std::fs::read_dir(d).ok())
            .flat_map(|rd| rd.flatten());
        for entry in entries {
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
            if by_app_ref.contains_key(app_ref) {
                continue;
            }
            if let Some(model) = cache::load(dir, &path, app_ref) {
                by_app_ref.insert(app_ref.to_string(), model);
            }
        }
        Self { by_app_ref }
    }

    /// Loads only `models/<app_ref>.yaml` for each of `app_refs` (best-effort,
    /// like [`ProductModels::load`]): what a model load or save needs to
    /// translate enum labels, without parsing every cached model.
    pub fn load_apps<'a>(dir: &Path, app_refs: impl IntoIterator<Item = &'a str>) -> Self {
        let dirs = models_dirs(dir);
        let mut by_app_ref = BTreeMap::new();
        for app_ref in app_refs {
            if by_app_ref.contains_key(app_ref) || app_ref.contains(['/', '\\']) {
                continue;
            }
            let model = dirs
                .iter()
                .find_map(|d| cache::load(dir, &d.join(format!("{app_ref}.yaml")), app_ref));
            if let Some(model) = model {
                by_app_ref.insert(app_ref.to_string(), model);
            }
        }
        Self { by_app_ref }
    }

    /// Adds (or replaces) the model of `app_ref`.
    pub fn insert(&mut self, app_ref: impl Into<String>, model: ProductModel) {
        self.by_app_ref.insert(app_ref.into(), Arc::new(model));
    }

    /// Looks up the model for an application ref, if loaded.
    pub fn get(&self, app_ref: &str) -> Option<&ProductModel> {
        self.by_app_ref.get(app_ref).map(|m| &**m)
    }

    /// The definition of the parameter an in-memory key (`<slug>@<ref>`) names
    /// in application `app_ref`, if that model is loaded.
    pub fn param_def(&self, app_ref: &str, key: &str) -> Option<&ParamDef> {
        let id = key_to_param_id(key)?;
        self.get(app_ref)?.parameters.get(&id)
    }

    /// How many product-model files this process has parsed from YAML (a
    /// memo and JSON-cache miss) and read from the JSON cache: what
    /// `--timing` reports.
    pub fn load_counts() -> (usize, usize) {
        cache::counts()
    }
}

/// Where the converted product models are cached as JSON under a model
/// directory (issue #339), next to [`MODELS_DIR`] rather than inside it: the
/// model loader fingerprints `models/`, and a cache written there would
/// invalidate its memo. `.bussard/` is disposable, so a missing cache only
/// costs a parse.
pub const MODEL_CACHE_DIR: &str = ".bussard/model-cache";

/// The JSON cache file of application `app_ref` under model directory `dir`.
pub fn model_cache_path(dir: &Path, app_ref: &str) -> PathBuf {
    dir.join(MODEL_CACHE_DIR).join(format!("{app_ref}.json"))
}

/// Converts the product model YAML `yaml`, just written to
/// `<dir>/.bussard/models/<app_ref>.yaml`, and stores the result in the JSON
/// cache and the process memo, so the first command after an import does not
/// parse it. The conversion is [`ProductModel::from_yaml`], the same as a
/// load's. Best effort: a text that does not parse or does not match the file
/// on disk, or a cache that cannot be written, is skipped.
pub fn cache_written_model(dir: &Path, app_ref: &str, yaml: &str) {
    if app_ref.contains(['/', '\\']) {
        return;
    }
    let path = dir.join(MODELS_DIR).join(format!("{app_ref}.yaml"));
    cache::store_written(dir, &path, app_ref, yaml);
}

/// The model the JSON cache holds for `app_ref` under model directory `dir`,
/// when its header matches `.bussard/models/<app_ref>.yaml` on disk and this
/// build; `None` when it is missing, stale or unreadable. Bypasses the memo:
/// what a test or a diagnostic checks the cache with.
pub fn cached_product_model(dir: &Path, app_ref: &str) -> Option<ProductModel> {
    if app_ref.contains(['/', '\\']) {
        return None;
    }
    let path = dir.join(MODELS_DIR).join(format!("{app_ref}.yaml"));
    cache::read_cache(dir, app_ref, cache::Stamp::of(&path)?)
}

/// The process-wide memo and the JSON cache behind [`ProductModels`] (issue
/// #339): a product model is parsed from YAML once per process and change,
/// and across processes only when its JSON cache is missing or stale.
mod cache {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Serialize};

    use super::{MODEL_FORMAT, ProductModel, model_cache_path};

    /// The cache file layout; a cache of another one is ignored and rewritten.
    pub(super) const CACHE_SCHEMA: u32 = 1;

    /// YAML parses so far (memo and cache misses).
    static YAML_PARSES: AtomicUsize = AtomicUsize::new(0);
    /// JSON cache reads so far.
    static CACHE_READS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    thread_local! {
        /// This thread's (YAML parses, cache reads): what a unit test counts,
        /// unaffected by tests running in parallel threads.
        pub(super) static THREAD_COUNTS: std::cell::Cell<(usize, usize)> =
            const { std::cell::Cell::new((0, 0)) };
    }

    /// Counts one YAML parse.
    fn count_parse() {
        YAML_PARSES.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        THREAD_COUNTS.with(|c| c.set((c.get().0 + 1, c.get().1)));
    }

    /// Counts one cache read.
    fn count_cache_read() {
        CACHE_READS.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        THREAD_COUNTS.with(|c| c.set((c.get().0, c.get().1 + 1)));
    }

    /// Drops the memo entry of `path`, so the next load goes to the cache.
    #[cfg(test)]
    pub(super) fn forget(path: &Path) {
        if let Ok(mut memo) = MEMO.lock()
            && let Some(map) = memo.as_mut()
        {
            map.remove(path);
        }
    }

    /// The identity of a model file on disk: its length and modification
    /// time. A rewrite changes at least one of them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Stamp {
        len: u64,
        mtime: SystemTime,
    }

    impl Stamp {
        /// The stamp of the file at `path`, if it exists and has a time.
        pub(super) fn of(path: &Path) -> Option<Self> {
            let meta = std::fs::metadata(path).ok()?;
            Some(Self {
                len: meta.len(),
                mtime: meta.modified().ok()?,
            })
        }

        /// The modification time as (seconds, nanoseconds) since the epoch,
        /// which round-trips a `SystemTime` exactly. `None` before the epoch.
        fn mtime_parts(self) -> Option<(u64, u32)> {
            let d = self.mtime.duration_since(UNIX_EPOCH).ok()?;
            Some((d.as_secs(), d.subsec_nanos()))
        }
    }

    /// One memoized model: the stamp it was parsed at and the model.
    type MemoEntry = (Stamp, Arc<ProductModel>);

    /// The memo, keyed by the model file's path.
    static MEMO: Mutex<Option<HashMap<PathBuf, MemoEntry>>> = Mutex::new(None);

    /// The cache file's header: everything that must match the YAML on disk
    /// and this build for the cached model to stand for it.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Header {
        schema: u32,
        model_format: u32,
        application: String,
        yaml_len: u64,
        yaml_mtime_secs: u64,
        yaml_mtime_nanos: u32,
    }

    impl Header {
        /// The header a cache of `app_ref` at `stamp` must carry.
        fn expected(app_ref: &str, stamp: Stamp) -> Option<Self> {
            let (secs, nanos) = stamp.mtime_parts()?;
            Some(Self {
                schema: CACHE_SCHEMA,
                model_format: MODEL_FORMAT,
                application: app_ref.to_string(),
                yaml_len: stamp.len,
                yaml_mtime_secs: secs,
                yaml_mtime_nanos: nanos,
            })
        }
    }

    /// A cache file as read: the header, then the model.
    #[derive(Deserialize)]
    struct CacheFileIn {
        header: Header,
        model: ProductModel,
    }

    /// A cache file as written.
    #[derive(Serialize)]
    struct CacheFileOut<'a> {
        header: &'a Header,
        model: &'a ProductModel,
    }

    /// (YAML parses, JSON cache reads) so far.
    pub(super) fn counts() -> (usize, usize) {
        (
            YAML_PARSES.load(Ordering::Relaxed),
            CACHE_READS.load(Ordering::Relaxed),
        )
    }

    /// The memoized model of `path`, if memoized at `stamp`.
    fn memo_get(path: &Path, stamp: Stamp) -> Option<Arc<ProductModel>> {
        let memo = MEMO.lock().ok()?;
        let (at, model) = memo.as_ref()?.get(path)?;
        (*at == stamp).then(|| Arc::clone(model))
    }

    /// Memoizes `model` as the content of `path` at `stamp`.
    fn memo_put(path: &Path, stamp: Stamp, model: &Arc<ProductModel>) {
        if let Ok(mut memo) = MEMO.lock() {
            memo.get_or_insert_with(HashMap::new)
                .insert(path.to_path_buf(), (stamp, Arc::clone(model)));
        }
    }

    /// The model the JSON cache holds for `app_ref`, if its header matches.
    pub(super) fn read_cache(dir: &Path, app_ref: &str, stamp: Stamp) -> Option<ProductModel> {
        let expected = Header::expected(app_ref, stamp)?;
        let bytes = std::fs::read(model_cache_path(dir, app_ref)).ok()?;
        let file: CacheFileIn = serde_json::from_slice(&bytes).ok()?;
        (file.header == expected).then_some(file.model)
    }

    /// Writes the JSON cache of `app_ref` atomically (temp file and rename).
    /// Errors are ignored: the cache is an optimization.
    fn write_cache(dir: &Path, app_ref: &str, stamp: Stamp, model: &ProductModel) {
        let Some(header) = Header::expected(app_ref, stamp) else {
            return;
        };
        let cache = model_cache_path(dir, app_ref);
        let Ok(json) = serde_json::to_vec(&CacheFileOut {
            header: &header,
            model,
        }) else {
            return;
        };
        let Some(parent) = cache.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let tmp = cache.with_extension(format!("json.{}.tmp", std::process::id()));
        if std::fs::write(&tmp, json).is_err() || std::fs::rename(&tmp, &cache).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// The product model in file `path` (application `app_ref`, under model
    /// directory `dir`): from the memo, else the JSON cache, else parsed from
    /// the YAML (and cached). `None` when the file is missing or unparsable.
    pub(super) fn load(dir: &Path, path: &Path, app_ref: &str) -> Option<Arc<ProductModel>> {
        let stamp = Stamp::of(path)?;
        if let Some(model) = memo_get(path, stamp) {
            return Some(model);
        }
        if let Some(model) = read_cache(dir, app_ref, stamp) {
            count_cache_read();
            let model = Arc::new(model);
            memo_put(path, stamp, &model);
            return Some(model);
        }
        let text = std::fs::read_to_string(path).ok()?;
        count_parse();
        let model = Arc::new(ProductModel::from_yaml(&text, app_ref).ok()?);
        // Remember it only when the file did not change under the read.
        if Stamp::of(path) == Some(stamp) {
            write_cache(dir, app_ref, stamp, &model);
            memo_put(path, stamp, &model);
        }
        Some(model)
    }

    /// Converts `yaml`, the text just written to `path`, and caches it.
    pub(super) fn store_written(dir: &Path, path: &Path, app_ref: &str, yaml: &str) {
        let Some(stamp) = Stamp::of(path) else {
            return;
        };
        if stamp.len != yaml.len() as u64 {
            return;
        }
        let Ok(model) = ProductModel::from_yaml(yaml, app_ref) else {
            return;
        };
        write_cache(dir, app_ref, stamp, &model);
        memo_put(path, stamp, &Arc::new(model));
    }
}

/// The label a device file writes for enum `code`: the enumeration text of
/// that code, when it has one that reads back as this code and nothing else.
///
/// `None` when `code` is not an integer, has no text, the text is blank, is
/// shared with another code, or itself parses as an integer (a text `"1"` for
/// code 0 would read back as code 1). The file then keeps the code.
pub fn enum_label<'a>(labels: &'a [(i64, String)], code: &str) -> Option<&'a str> {
    let code: i64 = code.trim().parse().ok()?;
    let text = labels.iter().find(|(c, _)| *c == code)?.1.as_str();
    let usable = !text.trim().is_empty()
        && text.trim().parse::<i64>().is_err()
        && labels.iter().filter(|(_, t)| t == text).count() == 1;
    usable.then_some(text)
}

/// The enum code a device-file label stands for: the code of the one
/// enumeration entry whose text is exactly `text`. `None` for an integer
/// (already a code), an unknown text, or a text two codes share.
pub fn enum_code(labels: &[(i64, String)], text: &str) -> Option<i64> {
    if text.trim().parse::<i64>().is_ok() {
        return None;
    }
    let mut hits = labels.iter().filter(|(_, t)| t == text);
    let (code, _) = hits.next()?;
    hits.next().is_none().then_some(*code)
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

/// Maps a device-file parameter key to the app-relative ref id the product
/// model lists in [`ProductModel::parameter_refs`]: the key's ref without
/// its module-instance selector.
///
/// * `windalarm-1@MD-1_M-3_MI-1_P-3_R-45` → `MD-1_P-3_R-45`
/// * `nachtabsenkung@P-1312_R-2140` → `P-1312_R-2140`
pub fn key_to_model_ref(key: &str) -> Option<String> {
    let ref_id = key.split_once('@').map(|(_, r)| r)?;
    let (param_ref, r) = ref_id.rsplit_once("_R-")?;
    Some(format!("{}_R-{r}", strip_module_instance(param_ref)))
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

    const REFS_YAML: &str = "\
parameters:
  - id: M-1_A-1_MD-3_P-14
    text: Betriebsart
    type: !int
      min: 0
    refs: {M-1_A-1_MD-3_P-14_R-14: {}}
  - id: M-1_A-1_P-19
    text: Regenalarm
    type: !int
      min: 0
    refs: {M-1_A-1_P-19_R-38: {}}
  - id: M-1_A-1_P-20
    text: Zwei Refs
    type: !int
      min: 0
    refs: {M-1_A-1_P-20_R-1: {}, M-1_A-1_P-20_R-2: {}}
  - id: M-1_A-1_P-21
    name: OhneRefs
    type: !int
      min: 0
";

    #[test]
    fn test_resolve_key_through_text_and_refs() -> Result<(), serde_norway::Error> {
        let model = ProductModel::from_yaml(REFS_YAML, "M-1_A-1")?;
        assert_eq!(
            model
                .resolve_key(Some("MD-3_M-18_MI-1"), "betriebsart")
                .as_deref(),
            Some("MD-3_M-18_MI-1_P-14_R-14")
        );
        assert_eq!(
            model.resolve_key(None, "regenalarm").as_deref(),
            Some("P-19_R-38")
        );
        // A page-qualified key resolves by its last part.
        assert_eq!(
            model.resolve_key(None, "allgemein.regenalarm").as_deref(),
            Some("P-19_R-38")
        );
        // Out of scope, ambiguous refs, no refs, unknown.
        assert_eq!(model.resolve_key(None, "betriebsart"), None);
        assert_eq!(model.resolve_key(None, "zwei-refs"), None);
        assert_eq!(model.resolve_key(None, "ohnerefs"), None);
        assert_eq!(model.resolve_key(None, "unbekannt"), None);
        Ok(())
    }

    #[test]
    fn parses_model_yaml_indexed_app_relative() -> Result<(), Box<dyn std::error::Error>> {
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
        let m = ProductModel::from_yaml(yaml, app)?;
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
        assert_eq!(
            m.parameters["P-9"].labels,
            vec![(0, "Off".to_string()), (7, "On".to_string())]
        );
        Ok(())
    }

    fn labels(pairs: &[(i64, &str)]) -> Vec<(i64, String)> {
        pairs.iter().map(|(c, t)| (*c, t.to_string())).collect()
    }

    #[test]
    fn test_enum_label_needs_a_unique_non_numeric_text() {
        let l = labels(&[(0, "Aus"), (1, "Ein"), (2, "Ein"), (3, "5"), (4, " ")]);
        assert_eq!(enum_label(&l, "0"), Some("Aus"));
        assert_eq!(enum_label(&l, "1"), None, "shared text");
        assert_eq!(enum_label(&l, "3"), None, "numeric text");
        assert_eq!(enum_label(&l, "4"), None, "blank text");
        assert_eq!(enum_label(&l, "9"), None, "no text");
        assert_eq!(enum_label(&l, "Aus"), None, "not a code");
    }

    #[test]
    fn test_enum_code_translates_exact_unique_texts() {
        let l = labels(&[(0, "Aus"), (1, "Ein"), (2, "Ein")]);
        assert_eq!(enum_code(&l, "Aus"), Some(0));
        assert_eq!(enum_code(&l, "Ein"), None, "ambiguous");
        assert_eq!(enum_code(&l, "aus"), None, "exact match only");
        assert_eq!(enum_code(&l, "0"), None, "already a code");
    }

    type TestErr = Box<dyn std::error::Error>;
    /// (YAML parses, cache reads) a load cost.
    type Cost = (usize, usize);
    /// One way to break the cache file.
    type Breaker = Box<dyn Fn(&CacheScratch) -> Result<(), TestErr>>;

    /// A scratch model directory holding `.bussard/models/<app>.yaml`.
    struct CacheScratch {
        dir: PathBuf,
        yaml: PathBuf,
    }

    impl CacheScratch {
        const APP: &'static str = "M-1_A-1";

        fn new(tag: &str) -> Result<Self, Box<dyn std::error::Error>> {
            // Only portable file-name characters: a Debug-formatted
            // SystemTime holds braces and colons, which Windows rejects.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let dir = std::env::temp_dir().join(format!(
                "bussard-model-cache-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(dir.join(MODELS_DIR))?;
            let yaml = dir.join(MODELS_DIR).join(format!("{}.yaml", Self::APP));
            std::fs::write(&yaml, REFS_YAML)?;
            Ok(Self { dir, yaml })
        }

        /// Loads the model; returns it with the (parses, cache reads) it cost.
        fn load(&self) -> Result<(Arc<ProductModel>, Cost), TestErr> {
            let before = cache::THREAD_COUNTS.with(std::cell::Cell::get);
            let models = ProductModels::load_apps(&self.dir, [Self::APP]);
            let after = cache::THREAD_COUNTS.with(std::cell::Cell::get);
            let model = models
                .by_app_ref
                .get(Self::APP)
                .cloned()
                .ok_or("the model loads")?;
            Ok((model, (after.0 - before.0, after.1 - before.1)))
        }

        fn cache(&self) -> PathBuf {
            model_cache_path(&self.dir, Self::APP)
        }

        /// Rewrites one field of the cache file's header.
        fn edit_header(
            &self,
            field: &str,
            value: serde_json::Value,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(self.cache())?)?;
            json["header"][field] = value;
            std::fs::write(self.cache(), serde_json::to_vec(&json)?)?;
            Ok(())
        }

        /// Sets the YAML's modification time `secs` seconds into the future.
        fn touch(&self, secs: u64) -> Result<(), Box<dyn std::error::Error>> {
            let at = std::time::SystemTime::now() + std::time::Duration::from_secs(secs);
            std::fs::File::options()
                .write(true)
                .open(&self.yaml)?
                .set_modified(at)?;
            Ok(())
        }
    }

    impl Drop for CacheScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_load_apps_memo_hit_and_miss() -> Result<(), Box<dyn std::error::Error>> {
        let s = CacheScratch::new("memo")?;
        let (first, cost) = s.load()?;
        assert_eq!(cost, (1, 0), "a cold load parses the YAML");
        assert!(s.cache().is_file(), "and writes the cache");
        let (again, cost) = s.load()?;
        assert_eq!(cost, (0, 0), "a second load is a memo hit");
        assert!(Arc::ptr_eq(&first, &again), "sharing the parsed model");
        let all = ProductModels::load(&s.dir);
        assert!(Arc::ptr_eq(&first, &all.by_app_ref[CacheScratch::APP]));

        // A rewrite of another length is parsed again.
        std::fs::write(&s.yaml, REFS_YAML.replace("Regenalarm", "Regenalarm2"))?;
        let (changed, cost) = s.load()?;
        assert_eq!(cost, (1, 0));
        assert!(
            changed
                .parameters
                .values()
                .any(|p| p.text.as_deref() == Some("Regenalarm2"))
        );

        // A rewrite of the same length is parsed again by its new mtime.
        std::fs::write(&s.yaml, REFS_YAML.replace("Regenalarm", "Regenalarx"))?;
        s.touch(5)?;
        let (changed, cost) = s.load()?;
        assert_eq!(cost, (1, 0));
        assert!(
            changed
                .parameters
                .values()
                .any(|p| p.text.as_deref() == Some("Regenalarx"))
        );
        Ok(())
    }

    #[test]
    fn test_load_apps_reads_a_matching_cache() -> Result<(), Box<dyn std::error::Error>> {
        let s = CacheScratch::new("hit")?;
        let (parsed, _) = s.load()?;
        cache::forget(&s.yaml);
        let (cached, cost) = s.load()?;
        assert_eq!(cost, (0, 1), "a new process reads the JSON cache");
        assert_eq!(format!("{parsed:?}"), format!("{cached:?}"));
        Ok(())
    }

    /// Every header mismatch and a corrupt file fall back to the YAML and
    /// rewrite the cache.
    #[test]
    fn test_load_apps_rejects_a_stale_cache() -> Result<(), Box<dyn std::error::Error>> {
        let s = CacheScratch::new("stale")?;
        s.load()?;
        let breaks: [(&str, Breaker); 6] = [
            ("len", Box::new(|s| s.edit_header("yaml_len", 1.into()))),
            (
                "mtime secs",
                Box::new(|s| s.edit_header("yaml_mtime_secs", 1.into())),
            ),
            (
                "mtime nanos",
                Box::new(|s| s.edit_header("yaml_mtime_nanos", 7.into())),
            ),
            (
                "schema",
                Box::new(|s| s.edit_header("schema", (cache::CACHE_SCHEMA + 1).into())),
            ),
            (
                "model format",
                Box::new(|s| s.edit_header("model_format", (MODEL_FORMAT - 1).into())),
            ),
            (
                "corrupt",
                Box::new(|s| Ok(std::fs::write(s.cache(), b"{\"header\": nope")?)),
            ),
        ];
        for (what, break_it) in breaks {
            break_it(&s)?;
            assert!(
                cached_product_model(&s.dir, CacheScratch::APP).is_none(),
                "{what}"
            );
            cache::forget(&s.yaml);
            let (_, cost) = s.load()?;
            assert_eq!(cost, (1, 0), "{what}: parsed from YAML");
            assert!(
                cached_product_model(&s.dir, CacheScratch::APP).is_some(),
                "{what}: rewritten"
            );
        }

        // A YAML touched after the cache was written makes it stale too.
        s.touch(10)?;
        assert!(cached_product_model(&s.dir, CacheScratch::APP).is_none());
        cache::forget(&s.yaml);
        let (_, cost) = s.load()?;
        assert_eq!(cost, (1, 0));
        Ok(())
    }

    #[test]
    fn test_cache_written_model_seeds_the_cache() -> Result<(), Box<dyn std::error::Error>> {
        let s = CacheScratch::new("written")?;
        cache_written_model(&s.dir, CacheScratch::APP, REFS_YAML);
        assert!(cached_product_model(&s.dir, CacheScratch::APP).is_some());
        let (_, cost) = s.load()?;
        assert_eq!(cost, (0, 0), "the write seeded the memo");
        cache::forget(&s.yaml);
        let (_, cost) = s.load()?;
        assert_eq!(cost, (0, 1), "and the cache");
        Ok(())
    }
}
