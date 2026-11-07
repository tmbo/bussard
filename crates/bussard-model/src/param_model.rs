//! The product model: one application program's parameters, com-objects
//! and Dynamic section, reduced to what the views, the validator and the
//! Dynamic evaluator read ([`ProductModel`]).
//!
//! `bussard-prod` builds it from the parsed application program and stores it
//! as JSON under `<model dir>/.bussard/model-cache/<application_ref>.json`
//! ([`write_product_model`]). Commands read it back here ([`ProductModels`]),
//! at most once per process and file change. The directory is regenerated
//! data: a missing or outdated file is rebuilt from the archive `bussard.lock`
//! pins, and its absence is not an error (validation degrades to an info
//! note).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;

/// One parsed product model file: its parameter definitions, indexed for lookup.
#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
#[serde(default)]
pub struct ProductModel {
    /// The bus current this product draws, in mA, as declared by the vendor's
    /// `Hardware.xml` (`BusCurrent`). Used by the `L002` topology lint to total
    /// a line's draw against its power supply. `None` when the cached model
    /// predates the field or the vendor omitted it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bus_current_ma: Option<u32>,
    /// Parameter definitions keyed by their **application-relative** id
    /// (the full id with the `<application_ref>_` prefix stripped, e.g.
    /// `MD-1_P-3` or `P-1312`). A device parameter key resolves to this id by
    /// dropping its `_M-<m>_MI-<n>` module-instance selector and `_R-<r>`
    /// suffix; indexing app-relative lets the lookup ignore the app prefix.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, ParamDef>,
    /// The com-objects by number: the vendor's text, function and DPT.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub com_objects: BTreeMap<u16, ObjectDef>,
    /// The com-object refs of the application's Dynamic section that
    /// [`Self::com_objects`] describes through another ref of the same
    /// number, keyed by app-relative ref id (`O-32_R-454`).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub com_object_refs: BTreeMap<String, ObjectDef>,
    /// The application program id (`M-0002_A-A0ED-10-9B4E`), the prefix the
    /// app-relative ids drop.
    pub program_id: String,
    /// The Data Secure table capacities of a Data-Secure-capable application
    /// (`data_secure:`, format 9, issue #537); `None` for an application that
    /// does not declare `IsSecureEnabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_secure: Option<DataSecureCapacity>,
    /// The application's own Dynamic section (`dynamic:`, format 5, issue
    /// #345), app-relative ids throughout: what [`crate::dynamic::evaluate_dynamic`]
    /// walks through this model's [`crate::dynamic::DynamicSource`] impl.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dynamic: Vec<crate::dynamic::DynamicNode>,
    /// The Dynamic section of every module definition, keyed by app-relative
    /// module definition id (`MD-1`) (`module_dynamics:`, format 5).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub module_dynamics: BTreeMap<String, Vec<crate::dynamic::DynamicNode>>,
    /// The application's `<Union>`s, in document order, each with its size
    /// and its members' app-relative parameter ids and positions (`unions:`,
    /// format 5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unions: Vec<crate::dynamic::Union>,
    /// Every parameter ref of the application, keyed by app-relative ref id:
    /// its parameter, its `Value` where it matters and whether it is internal
    /// (the `refs:` of each parameter, format 5).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub parameter_refs: BTreeMap<String, RefDef>,
    /// The application's and the module definitions' `<Allocator>`s, keyed
    /// by app-relative id (`L-2`, `MD-1_L-1`) (`allocators:`, format 10,
    /// issue #449).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub allocators: BTreeMap<String, crate::dynamic::Allocator>,
    /// The `Allocates` of every module `<Argument>` that declares one, keyed
    /// by app-relative argument id (`argument_allocates:`, format 10).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub argument_allocates: BTreeMap<String, i64>,
    /// Whether the application is a System B one: its
    /// `identity.mask_version` is `xxB0` (issue #474).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub system_b: bool,
    /// The application's `<ParameterCalculation>`s, in document order, ids
    /// and refs app-relative (`calculations:`, format 13, issue #712): what
    /// the Dynamic evaluation runs through this model's
    /// [`crate::dynamic::DynamicSource`] impl, so the views show the value a
    /// download computes and writes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calculations: Vec<crate::dynamic::ParameterCalculation>,
    /// The ETS parameter pages and channels, derived from [`Self::dynamic`]
    /// on first use ([`Self::blocks`]).
    #[serde(skip)]
    pages: std::sync::OnceLock<Vec<crate::blocks::BlockDef>>,
    /// [`Self::blocks`] followed by the channels of the module instances
    /// ([`Self::blocks_with_module_channels`]).
    #[serde(skip)]
    pages_with_modules: std::sync::OnceLock<Vec<crate::blocks::BlockDef>>,
    /// The conditions in front of every ref ([`Self::ref_index`]).
    #[serde(skip)]
    ref_index: std::sync::OnceLock<crate::dynamic::RefIndex>,
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
#[serde(default)]
pub struct RefDef {
    /// The app-relative id of the parameter it points at.
    pub parameter: String,
    /// The ref's `Value`, where the model's parameter `default` does not give
    /// it already: the value the ref has when nothing is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Whether the ref's effective `Access` is `None`: ETS keeps the value
    /// to itself and never shows it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub internal: bool,
    /// The ref's own `Text`, where it differs from its parameter's: what
    /// titles a page whose `ParamRefId` names the ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// One com-object of a product model, reduced to what a view shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(default)]
pub struct ObjectDef {
    /// The vendor's object text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The vendor's function text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The datapoint type, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpt: Option<String>,
    /// The communication flags, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    /// The transmission priority the product declares, where it is not Low
    /// (format 8, issue #541).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<crate::flags::Priority>,
}

/// The product-model format this build writes, in the header of each
/// model file: a file of another format is rebuilt from its archive. Format
/// 14 is the first JSON one (issue #906); formats 1 to 13 were YAML files
/// under `.bussard/models/`.
pub const MODEL_FORMAT: u32 = 14;

/// A single parameter definition, reduced to what validation needs.
#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
#[serde(default)]
pub struct ParamDef {
    /// The parameter type/shape.
    pub kind: ParamKind,
    /// The vendor default value, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// The parameter's human-readable text as ETS shows it (e.g. "Night
    /// setback"), when the product model carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// For an enumeration, its `(code, text)` pairs in document order: the
    /// labels a device file may write instead of the code (see
    /// [`enum_label`] and [`enum_code`]). Empty for other kinds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(i64, String)>,
    /// The parameter's `Name`, when the product model carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The parameter refs that point at this parameter, app-relative
    /// (`MD-1_P-3_R-45` without the module-instance selector), when the
    /// product model lists them (`refs:`). A device-file key the lock does not
    /// list resolves through them (see [`ProductModel::resolve_key`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    /// The `BaseValue` argument id: a module parameter whose default has the
    /// instance's value of this argument added to it (issue #126).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_value: Option<String>,
    /// Width in bits and signedness of an integer or plain enumeration
    /// parameter (`bits:`, `signed:`), `None` for any other type: what a
    /// shared `<Union>` memory is read back with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integer_width: Option<(u32, bool)>,
    /// For an enumeration, its members (code and label): what an override
    /// written as a label is matched against. Empty for other kinds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<crate::dynamic::EnumValue>,
    /// A text parameter's `InitialValue` in the model's language
    /// (`initial_value:`, format 10, issue #473): the value a new device
    /// starts with, which wins over the `Value`s as the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<String>,
    /// Whether the parameter is virtual: no memory, no property and no
    /// union place, so it only ever has its value (`virtual: true`, format
    /// 12, issue #474).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_virtual: bool,
}

/// A parameter's type.
#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
pub enum ParamKind {
    /// A bounded integer (`int`).
    Int {
        /// Inclusive minimum, if declared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
        /// Inclusive maximum, if declared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<i64>,
        /// Whether the encoding is signed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        len: Option<usize>,
        /// The program's `TextParameterEncoding`, the code page the text is
        /// written in (issue #401); `None` when undeclared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encoding: Option<String>,
    },
    /// A float (`float`).
    Float,
    /// A marker with no memory (`none`).
    None,
    /// A colour (`color`) of the declared space, written `#RRGGBB` (issue
    /// #616).
    Color {
        /// The `<TypeColor>` `Space`.
        space: crate::color_codec::ColorSpace,
    },
    /// Any other shape (`other`), not range-checked.
    #[default]
    Other,
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

    /// The ETS parameter pages and channels of the application's own
    /// Dynamic section, in document order, derived from the tree once
    /// ([`crate::blocks::pages_of`]).
    pub fn blocks(&self) -> &[crate::blocks::BlockDef] {
        self.pages.get_or_init(|| crate::blocks::pages_of(self))
    }

    /// The value-free index of the conditions in front of every parameter
    /// and com-object ref ([`crate::dynamic::RefIndex`]), built once: every
    /// device view of the application reads it (issue #302).
    pub fn ref_index(&self) -> &crate::dynamic::RefIndex {
        self.ref_index
            .get_or_init(|| crate::dynamic::RefIndex::new(self))
    }

    /// [`Self::blocks`] followed by the `<Channel>`s of the module instances
    /// the Dynamic section places ([`crate::blocks::module_channels_of`],
    /// issue #302), derived once. The first `blocks().len()` entries are
    /// [`Self::blocks`], so an index into either means the same block.
    pub fn blocks_with_module_channels(&self) -> &[crate::blocks::BlockDef] {
        self.pages_with_modules.get_or_init(|| {
            let mut all = self.blocks().to_vec();
            all.extend(crate::blocks::module_channels_of(self));
            all
        })
    }

    /// The `<ParameterCalculation>` that writes app-relative ref `reference`
    /// (`P-3_R-3`, `MD-3_P-14_R-14`) as one of its outputs, if any: ETS shows
    /// such a parameter read-only, and a download writes what the
    /// calculation computes (issue #712).
    pub fn calculation_writing(
        &self,
        reference: &str,
    ) -> Option<&crate::dynamic::ParameterCalculation> {
        self.calculations
            .iter()
            .find(|c| c.outputs.iter().any(|o| o.param_ref == reference))
    }

    /// The vendor default of app-relative parameter ref `reference`: a text
    /// parameter's `InitialValue` (issue #473), else the ref's own `Value`
    /// when the model records one, else the parameter's default. This is the
    /// value ETS shows, and a download writes, when nothing is stored (issue
    /// #326).
    pub fn ref_default(&self, reference: &str) -> Option<&str> {
        match self.parameter_refs.get(reference) {
            Some(r) => {
                let def = self.parameters.get(&r.parameter);
                // A text parameter's `InitialValue` comes first (issue #473).
                def.and_then(|d| d.initial_value.as_deref())
                    .or(r.value.as_deref())
                    .or_else(|| def?.default.as_deref())
            }
            None => self
                .parameters
                .get(crate::blocks::ref_param_id(reference))
                .and_then(|d| d.initial_value.as_deref().or(d.default.as_deref())),
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

    fn initial_value(&self, param_id: &str) -> Option<&str> {
        self.parameters.get(param_id)?.initial_value.as_deref()
    }

    fn is_virtual(&self, param_id: &str) -> bool {
        self.parameters.get(param_id).is_some_and(|p| p.is_virtual)
    }

    fn is_system_b(&self) -> bool {
        self.system_b
    }

    fn calculations(&self) -> &[crate::dynamic::ParameterCalculation] {
        &self.calculations
    }

    fn parameter_name(&self, param_id: &str) -> Option<&str> {
        self.parameters.get(param_id)?.name.as_deref()
    }

    fn parameter_is_text(&self, param_id: &str) -> Option<bool> {
        match self.parameters.get(param_id)?.kind {
            ParamKind::Text { .. } => Some(true),
            ParamKind::Int { .. } | ParamKind::Enum { .. } | ParamKind::Float => Some(false),
            _ => None,
        }
    }
}

/// Whether a `MaskVersion` (`07B0`, `MV-07B0`) is a System B one (`xxB0`).
pub fn is_system_b_mask(mask: &str) -> bool {
    let mask = mask.trim();
    let digits = mask.strip_prefix("MV-").unwrap_or(mask);
    u16::from_str_radix(digits, 16).is_ok_and(|m| m & 0x0FFF == 0x07B0)
}

/// Where the product models live under a model directory: regenerated data
/// under `.bussard/` (issue #228), one JSON file per application program,
/// built from the archives in `products/` (issue #906).
pub const MODEL_CACHE_DIR: &str = ".bussard/model-cache";

/// The model file of application `app_ref` under model directory `dir`.
pub fn model_cache_path(dir: &Path, app_ref: &str) -> PathBuf {
    dir.join(MODEL_CACHE_DIR).join(format!("{app_ref}.json"))
}

/// Whether an application ref can name a file (no path separator).
fn plain_app_ref(app_ref: &str) -> bool {
    !app_ref.is_empty() && !app_ref.contains(['/', '\\'])
}

/// Whether `dir` holds the model of `app_ref` in the current
/// [`MODEL_FORMAT`]. Reads only the head of the file, where the header is.
pub fn product_model_is_current(dir: &Path, app_ref: &str) -> bool {
    use std::io::Read;
    if !plain_app_ref(app_ref) {
        return false;
    }
    let Some(wanted) = cache::header_prefix(app_ref) else {
        return false;
    };
    let Ok(file) = std::fs::File::open(model_cache_path(dir, app_ref)) else {
        return false;
    };
    let mut head = Vec::with_capacity(wanted.len());
    file.take(wanted.len() as u64)
        .read_to_end(&mut head)
        .is_ok()
        && head == wanted.as_bytes()
}

/// Stores `model` as the model of its application (`program_id`) under
/// model directory `dir`, atomically (a temporary file and a rename), and
/// memoizes it so the command that wrote it does not read it back.
///
/// # Errors
///
/// The program id cannot name a file, or the file cannot be written.
pub fn write_product_model(dir: &Path, model: ProductModel) -> std::io::Result<()> {
    if !plain_app_ref(&model.program_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("no file name for application {:?}", model.program_id),
        ));
    }
    cache::store(&model_cache_path(dir, &model.program_id), model)
}

/// The model `dir` holds for `app_ref`, when the file is of this build's
/// format; `None` when it is missing, outdated or unreadable. Bypasses the
/// memo: what a test or a diagnostic checks the file with.
pub fn cached_product_model(dir: &Path, app_ref: &str) -> Option<ProductModel> {
    if !plain_app_ref(app_ref) {
        return None;
    }
    cache::read(&model_cache_path(dir, app_ref), app_ref)
}

/// The product models available for validation and the views, keyed by
/// application ref, loaded lazily from `<dir>/.bussard/model-cache/*.json`.
///
/// Missing, outdated or unparsable files are simply absent from the map (a
/// missing model is an info-level note during validation, never a hard
/// error). The directory is regenerated data, so it is often absent entirely.
///
/// Each model is shared ([`Arc`]) and served from a process-wide memo (issue
/// #339), so a model file is read at most once per process and per change.
#[derive(Debug, Clone, Default)]
pub struct ProductModels {
    /// Parsed models keyed by application ref (the file stem).
    pub by_app_ref: BTreeMap<String, Arc<ProductModel>>,
}

impl ProductModels {
    /// Loads every model under `dir` (best-effort). Returns an empty set when
    /// the directory is absent. Individual files that fail to load are
    /// skipped (their app then reads as "no model", an info-level note).
    pub fn load(dir: &Path) -> Self {
        let mut by_app_ref = BTreeMap::new();
        let Ok(entries) = std::fs::read_dir(dir.join(MODEL_CACHE_DIR)) else {
            return Self { by_app_ref };
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(app_ref) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if let Some(model) = cache::load(&path, app_ref) {
                by_app_ref.insert(app_ref.to_string(), model);
            }
        }
        Self { by_app_ref }
    }

    /// Loads only the models of `app_refs` (best-effort, like
    /// [`ProductModels::load`]): what a model load or save needs to translate
    /// enum labels, without reading every stored model.
    pub fn load_apps<'a>(dir: &Path, app_refs: impl IntoIterator<Item = &'a str>) -> Self {
        let mut by_app_ref = BTreeMap::new();
        for app_ref in app_refs {
            if by_app_ref.contains_key(app_ref) || !plain_app_ref(app_ref) {
                continue;
            }
            if let Some(model) = cache::load(&model_cache_path(dir, app_ref), app_ref) {
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

    /// How many product-model files this process has read (memo misses):
    /// what `--timing` reports.
    pub fn load_count() -> usize {
        cache::reads()
    }
}

/// The process-wide memo behind [`ProductModels`] (issue #339) and the file
/// layout: a header, then the model.
mod cache {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    use serde::{Deserialize, Serialize};

    use super::{MODEL_FORMAT, ProductModel};

    /// The file layout; a file of another one is ignored and rebuilt.
    pub(super) const SCHEMA: u32 = 2;

    /// Model files read so far (memo misses).
    static READS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    thread_local! {
        /// This thread's reads: what a unit test counts, unaffected by tests
        /// running in parallel threads.
        pub(super) static THREAD_READS: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    /// Counts one read.
    fn count_read() {
        READS.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        THREAD_READS.with(|c| c.set(c.get() + 1));
    }

    /// Model files read so far.
    pub(super) fn reads() -> usize {
        READS.load(Ordering::Relaxed)
    }

    /// Drops the memo entry of `path`, so the next load reads the file.
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
    struct Stamp {
        len: u64,
        mtime: SystemTime,
    }

    impl Stamp {
        /// The stamp of the file at `path`, if it exists and has a time.
        fn of(path: &Path) -> Option<Self> {
            let meta = std::fs::metadata(path).ok()?;
            Some(Self {
                len: meta.len(),
                mtime: meta.modified().ok()?,
            })
        }
    }

    /// One memoized model: the stamp it was read at and the model.
    type MemoEntry = (Stamp, Arc<ProductModel>);

    /// The memo, keyed by the model file's path.
    static MEMO: Mutex<Option<HashMap<PathBuf, MemoEntry>>> = Mutex::new(None);

    /// A model file's header: what must match this build and the file name
    /// for the model to be used.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Header {
        schema: u32,
        model_format: u32,
        application: String,
    }

    impl Header {
        /// The header a model file of `app_ref` must carry.
        fn expected(app_ref: &str) -> Self {
            Self {
                schema: SCHEMA,
                model_format: MODEL_FORMAT,
                application: app_ref.to_string(),
            }
        }
    }

    /// A model file as read: the header, then the model.
    #[derive(Deserialize)]
    struct FileIn {
        header: Header,
        model: ProductModel,
    }

    /// A model file as written.
    #[derive(Serialize)]
    struct FileOut<'a> {
        header: &'a Header,
        model: &'a ProductModel,
    }

    /// The bytes a current model file of `app_ref` starts with.
    pub(super) fn header_prefix(app_ref: &str) -> Option<String> {
        let header = serde_json::to_string(&Header::expected(app_ref)).ok()?;
        Some(format!("{{\"header\":{header}"))
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

    /// The model the file at `path` holds for `app_ref`, if its header
    /// matches.
    pub(super) fn read(path: &Path, app_ref: &str) -> Option<ProductModel> {
        let bytes = std::fs::read(path).ok()?;
        let file: FileIn = serde_json::from_slice(&bytes).ok()?;
        (file.header == Header::expected(app_ref)).then_some(file.model)
    }

    /// Writes `model` to `path` through a temporary file, and memoizes it.
    pub(super) fn store(path: &Path, model: ProductModel) -> std::io::Result<()> {
        let header = Header::expected(&model.program_id);
        let json = serde_json::to_vec(&FileOut {
            header: &header,
            model: &model,
        })
        .map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
        if let Err(err) = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
        if let Some(stamp) = Stamp::of(path) {
            memo_put(path, stamp, &Arc::new(model));
        }
        Ok(())
    }

    /// The product model in file `path` (application `app_ref`): from the
    /// memo, else read. `None` when the file is missing, outdated or
    /// unparsable.
    pub(super) fn load(path: &Path, app_ref: &str) -> Option<Arc<ProductModel>> {
        let stamp = Stamp::of(path)?;
        if let Some(model) = memo_get(path, stamp) {
            return Some(model);
        }
        let model = Arc::new(read(path, app_ref)?);
        count_read();
        // Remember it only when the file did not change under the read.
        if Stamp::of(path) == Some(stamp) {
            memo_put(path, stamp, &model);
        }
        Some(model)
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

/// Renders a stored or default code as the file writes it: the enum label
/// when there is a usable one, else the value as is.
pub fn display_value(def: Option<&ParamDef>, value: &str) -> String {
    match def {
        Some(d) if !d.labels.is_empty() => enum_label(&d.labels, value)
            .map(str::to_string)
            .unwrap_or_else(|| value.to_string()),
        _ => value.to_string(),
    }
}

/// Whether two renderings of a value mean the same (a label and its code).
pub fn same_value(def: Option<&ParamDef>, a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    if a == b {
        return true;
    }
    let Some(d) = def else { return false };
    let code = |v: &str| v.parse::<i64>().ok().or_else(|| enum_code(&d.labels, v));
    matches!((code(a), code(b)), (Some(x), Some(y)) if x == y)
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

    /// A model with four parameters: one of a module, two with refs, one
    /// with two refs and one without.
    fn refs_model() -> ProductModel {
        let mut model = ProductModel {
            program_id: "M-1_A-1".to_string(),
            ..ProductModel::default()
        };
        for (id, text, refs) in [
            ("MD-3_P-14", Some("Betriebsart"), &["MD-3_P-14_R-14"][..]),
            ("P-19", Some("Regenalarm"), &["P-19_R-38"][..]),
            ("P-20", Some("Zwei Refs"), &["P-20_R-1", "P-20_R-2"][..]),
            ("P-21", None, &[][..]),
        ] {
            let def = ParamDef {
                kind: ParamKind::Int {
                    min: Some(0),
                    max: None,
                    signed: false,
                },
                text: text.map(str::to_string),
                name: text.is_none().then(|| "OhneRefs".to_string()),
                refs: refs.iter().map(|r| r.to_string()).collect(),
                ..ParamDef::default()
            };
            model.parameters.insert(id.to_string(), def);
        }
        model
    }

    #[test]
    fn test_resolve_key_through_text_and_refs() {
        let model = refs_model();
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

    /// A scratch model directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        const APP: &'static str = "M-1_A-1";

        fn new(tag: &str) -> Result<Self, TestErr> {
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
            std::fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn file(&self) -> PathBuf {
            model_cache_path(&self.0, Self::APP)
        }

        /// Loads the model; returns it with the file reads it cost.
        fn load(&self) -> Result<(Arc<ProductModel>, usize), TestErr> {
            let before = cache::THREAD_READS.with(std::cell::Cell::get);
            let models = ProductModels::load_apps(&self.0, [Self::APP]);
            let after = cache::THREAD_READS.with(std::cell::Cell::get);
            let model = models
                .by_app_ref
                .get(Self::APP)
                .cloned()
                .ok_or("the model loads")?;
            Ok((model, after - before))
        }

        /// Rewrites one field of the file's header.
        fn edit_header(&self, field: &str, value: serde_json::Value) -> Result<(), TestErr> {
            let mut json: serde_json::Value = serde_json::from_slice(&std::fs::read(self.file())?)?;
            json["header"][field] = value;
            std::fs::write(self.file(), serde_json::to_vec(&json)?)?;
            Ok(())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_load_apps_memo_hit_and_miss() -> Result<(), TestErr> {
        let s = Scratch::new("memo")?;
        write_product_model(&s.0, refs_model())?;
        assert!(product_model_is_current(&s.0, Scratch::APP));
        let (first, reads) = s.load()?;
        assert_eq!(reads, 0, "the write memoized the model");
        cache::forget(&s.file());
        let (again, reads) = s.load()?;
        assert_eq!(reads, 1, "a new process reads the file");
        assert_eq!(format!("{first:?}"), format!("{again:?}"));
        let (third, reads) = s.load()?;
        assert_eq!(reads, 0, "a second load is a memo hit");
        assert!(Arc::ptr_eq(&again, &third), "sharing the parsed model");
        let all = ProductModels::load(&s.0);
        assert!(Arc::ptr_eq(&again, &all.by_app_ref[Scratch::APP]));

        // A rewrite by another process is read again.
        let mut changed = refs_model();
        changed.system_b = true;
        let json = std::fs::read_to_string(s.file())?;
        std::fs::write(
            s.file(),
            json.replacen("\"program_id\"", "\"system_b\":true,\"program_id\"", 1),
        )?;
        let (reread, reads) = s.load()?;
        assert_eq!(reads, 1);
        assert!(reread.system_b);
        Ok(())
    }

    /// Every header mismatch and a corrupt file make the file unusable.
    #[test]
    fn test_load_apps_rejects_an_outdated_file() -> Result<(), TestErr> {
        let s = Scratch::new("stale")?;
        let breaks: [(&str, &str, serde_json::Value); 3] = [
            ("schema", "schema", (cache::SCHEMA + 1).into()),
            ("model format", "model_format", (MODEL_FORMAT - 1).into()),
            ("application", "application", "M-2_A-2".into()),
        ];
        for (what, field, value) in breaks {
            write_product_model(&s.0, refs_model())?;
            s.edit_header(field, value)?;
            assert!(!product_model_is_current(&s.0, Scratch::APP), "{what}");
            assert!(cached_product_model(&s.0, Scratch::APP).is_none(), "{what}");
            cache::forget(&s.file());
            assert!(s.load().is_err(), "{what}");
        }
        std::fs::write(s.file(), b"{\"header\": nope")?;
        assert!(cached_product_model(&s.0, Scratch::APP).is_none());
        write_product_model(&s.0, refs_model())?;
        assert!(cached_product_model(&s.0, Scratch::APP).is_some());
        Ok(())
    }
}
