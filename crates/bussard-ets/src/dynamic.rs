//! Evaluation of an application program's Dynamic section against a device's
//! parameter values.
//!
//! ETS decides what a device carries by walking the Dynamic section: a
//! `<choose ParamRefId>` takes the `<when>` branches whose test matches the
//! parameter's current value, a `<Module>` reached this way instantiates its
//! `<ModuleDef>` (evaluated again with the instance's argument values), and every
//! `<ParameterRefRef>` / `<ComObjectRefRef>` reached is part of the device's
//! configuration. Only those parameters are written into the parameter image
//! and only those com-objects get a group-object descriptor; everything behind a
//! branch that is not taken is left out.
//!
//! [`evaluate_dynamic`] performs that walk and returns a [`DynamicConfig`]: the
//! reached module instances, parameter refs and com-object refs, and the
//! resolved parameter values (overrides, `<Assign>` results, then the vendor
//! defaults).
//!
//! `<Channel>` and `<ParameterBlock>` containers are transparent to the walk,
//! but it records where each reached item sits: its channel, its block path
//! and the module instance (with its ordinal) whose body contains it, in
//! [`DynamicConfig::parameter_placements`] and
//! [`DynamicConfig::com_object_placements`]. [`visible_parameter_refs`] picks
//! one ref per parameter from the result, and [`DynamicConfig::label`] reads a
//! `TextParameterRefId` label for [`crate::label::substitute_label`].
//!
//! A `<choose>` whose controlling parameter is itself inactive selects no
//! branch at all, not even a `<when default="true">` one (issue #159). ETS
//! decides activity by the same walk: a parameter is active while one of its
//! `<ParameterRefRef>`s is reached, i.e. its enclosing channel, parameter
//! block, `<when>` branch and module instance are all shown under the current
//! values. In the ETS schema a `<Channel>` or `<ParameterBlock>` is never
//! gated by an attribute of its own (its `Number`/`Text` only label it); it is
//! shown or hidden by the `<choose>`/`<when>` it sits in, and a module
//! instance is shown when its `<Module>` element is reached. So the reached
//! set of this walk is exactly the active set. Two cases stay active without
//! a reached `<ParameterRefRef>`: a parameter the Dynamic section never shows
//! anywhere (a pure steering parameter, which only ever has its value), and an
//! unreached `<Union>` member whose union has a reached member (its shared
//! memory is live, see [`SharedUnions`]). The target of a reached `<Assign>`
//! counts as active too: ETS writes it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use crate::application::{ApplicationProgram, DynamicNode, ParameterType, WhenTest};
pub use crate::application::{BlockRef, ChannelRef};

/// How deep `<Module>` instantiations may nest before the walk stops (real
/// products nest at most one level; the bound only guards a malformed file).
const MAX_MODULE_DEPTH: usize = 8;

/// How many times the walk is repeated to settle `<Assign>` results that feed
/// back into `<choose>` decisions.
const MAX_ASSIGN_PASSES: usize = 16;

/// One module instance the walk reached.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveModule {
    /// The module instance id, app-relative (e.g. `MD-13_M-44`).
    pub id: String,
    /// The module definition it instantiates (e.g. `MD-13`).
    pub module_def: String,
    /// The instance's argument values, keyed by app-relative argument id.
    pub args: HashMap<String, i64>,
    /// The instance's 1-based ordinal among all instances of the same module
    /// definition, in `M-<m>` order (by the numeric `m`). Counted over every
    /// `<Module>` element of the application, reached or not, so it is stable
    /// under parameter changes.
    pub ordinal: u32,
}

/// Where an active parameter or com-object sits in the Dynamic section.
///
/// [`DynamicConfig::parameter_placements`] and
/// [`DynamicConfig::com_object_placements`] hold one per entry of
/// [`DynamicConfig::parameters`] and [`DynamicConfig::com_objects`], at the
/// same index. The placement is that of the first reach of the entry in walk
/// (document) order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Placement {
    /// The enclosing `<Channel>`, if any.
    pub channel: Option<ChannelRef>,
    /// The enclosing `<ParameterBlock>`s, outermost first.
    pub blocks: Vec<BlockRef>,
    /// Index into [`DynamicConfig::modules`] of the module instance whose
    /// Dynamic body contains the element, `None` at the application level.
    /// This is where the element sits, which can differ from the scope of an
    /// application ref reached inside a module body (see
    /// [`ActiveParameter::module`]).
    pub module: Option<usize>,
    /// The id of that module instance (e.g. `MD-1_M-3`).
    pub module_instance: Option<String>,
    /// That instance's ordinal ([`ActiveModule::ordinal`]).
    pub module_ordinal: Option<u32>,
    /// Whether the entry was reached through a `<ParameterRefRef>` or
    /// `<ComObjectRefRef>` (shown in ETS). `false` for a parameter that is
    /// only the target or source of a reached `<Assign>`; its channel and
    /// blocks are then those of the `<Assign>` element.
    pub shown: bool,
}

/// The location context while walking: the enclosing channel and block path.
#[derive(Debug, Default)]
struct Context {
    channel: Option<ChannelRef>,
    blocks: Vec<BlockRef>,
}

/// Where a walk reached an item: the shared context plus the enclosing module.
#[derive(Debug, Clone, Default)]
struct Place {
    ctx: Rc<Context>,
    module: Option<usize>,
}

/// A parameter ref the walk reached (shown in ETS, so written to memory).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveParameter {
    /// Index into [`DynamicConfig::modules`] of the module instance the ref
    /// belongs to; `None` for a parameter of the application itself.
    pub module: Option<usize>,
    /// The app-relative `ParameterRef` id (e.g. `MD-3_P-3_R-6`).
    pub param_ref_id: String,
}

/// A com-object ref the walk reached (instantiated on the device).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveComObject {
    /// Index into [`DynamicConfig::modules`] of the module instance; `None`
    /// for a com-object of the application itself.
    pub module: Option<usize>,
    /// The app-relative `ComObjectRef` id (e.g. `MD-3_O-2-0_R-1`).
    pub com_object_ref_id: String,
}

/// The result of evaluating an application's Dynamic section.
#[derive(Debug, Clone, Default)]
pub struct DynamicConfig {
    /// The module instances reached, in walk order.
    pub modules: Vec<ActiveModule>,
    /// The parameter refs reached, in walk order and without duplicates:
    /// every `<ParameterRefRef>` plus the target and source of every reached
    /// `<Assign>` (ETS writes both).
    pub parameters: Vec<ActiveParameter>,
    /// The com-object refs reached, in walk order and without duplicates.
    pub com_objects: Vec<ActiveComObject>,
    /// Where each entry of [`Self::parameters`] sits, at the same index.
    pub parameter_placements: Vec<Placement>,
    /// Where each entry of [`Self::com_objects`] sits, at the same index.
    pub com_object_placements: Vec<Placement>,
    /// Override keys that name no `ParameterRef` of this application.
    pub unresolved_overrides: Vec<String>,
    /// Resolved values keyed by (module instance id or `""`, app-relative
    /// `ParameterRef` id): the overrides and the `<Assign>` results.
    values: HashMap<(String, String), String>,
    /// The keys of `values` that came from a caller override (not an assign).
    overridden: HashSet<(String, String)>,
}

impl DynamicConfig {
    /// The argument values of the module instance `module` (empty for the
    /// application itself).
    pub fn module_args(&self, module: Option<usize>) -> Option<&HashMap<String, i64>> {
        module.and_then(|i| self.modules.get(i)).map(|m| &m.args)
    }

    /// The effective value of `param_ref_id` (app-relative) in the context of
    /// `module`: an override or `<Assign>` result for this ref, else the ref's
    /// `Value`, else the parameter's own `Value`.
    pub fn value(
        &self,
        app: &ApplicationProgram,
        module: Option<usize>,
        param_ref_id: &str,
    ) -> Option<String> {
        value_of(
            app,
            &self.values,
            self.instance_id(module),
            self.module_args(module),
            param_ref_id,
        )
    }

    /// Whether the value of `param_ref_id` in `module` came from a caller
    /// override (as opposed to a vendor default or an `<Assign>`).
    pub fn is_override(
        &self,
        app: &ApplicationProgram,
        module: Option<usize>,
        param_ref_id: &str,
    ) -> bool {
        parameter_id(app, param_ref_id).is_some()
            && self.overridden.contains(&(
                self.instance_id(module).to_string(),
                param_ref_id.to_string(),
            ))
    }

    /// The vendor default of `param_ref_id` (app-relative) in the context of
    /// `module`, ignoring every override and `<Assign>`: the ref's `Value`,
    /// else the parameter's own `Value`, plus the instance's `BaseValue`
    /// argument where the parameter declares one (see [`DynamicConfig::value`]).
    pub fn vendor_default(
        &self,
        app: &ApplicationProgram,
        module: Option<usize>,
        param_ref_id: &str,
    ) -> Option<String> {
        value_of(
            app,
            &HashMap::new(),
            self.instance_id(module),
            self.module_args(module),
            param_ref_id,
        )
    }

    /// Whether the value of `param_ref_id` in `module` was set by a reached
    /// `<Assign>` (and so is not the user's to choose).
    pub fn is_assigned(&self, module: Option<usize>, param_ref_id: &str) -> bool {
        let key = (
            self.instance_id(module).to_string(),
            param_ref_id.to_string(),
        );
        self.values.contains_key(&key) && !self.overridden.contains(&key)
    }

    /// The module instance id (e.g. `MD-15_M-26`) of `module`, `None` for the
    /// application itself.
    pub fn module_instance_id(&self, module: Option<usize>) -> Option<&str> {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
    }

    /// The label a `TextParameterRefId` gives, read in the context of the
    /// module instance `module` the labelled element sits in (a module's own
    /// ref resolves in that instance, an application ref at the application
    /// level, as in the walk).
    ///
    /// The value is the effective one ([`DynamicConfig::value`]); for an
    /// enumeration parameter it is the matching enumeration text. Returns
    /// `None` when the ref is unknown or the value is empty after trimming.
    /// Feed the result to [`crate::label::substitute_label`].
    pub fn label(
        &self,
        app: &ApplicationProgram,
        module: Option<usize>,
        text_parameter_ref: &str,
    ) -> Option<String> {
        let scope = scope_of(&self.modules, module, text_parameter_ref);
        let raw = self.value(app, scope, text_parameter_ref)?;
        let kind = app
            .parameter_ref(text_parameter_ref)
            .and_then(|r| app.parameters.get(&r.ref_id))
            .and_then(|p| p.parameter_type.as_deref())
            .and_then(|t| app.parameter_types.get(t))
            .map(|d| &d.kind);
        let text = match kind {
            Some(ParameterType::Enum { values, .. }) => raw
                .trim()
                .parse::<i64>()
                .ok()
                .and_then(|v| values.iter().find(|e| e.value == v))
                .map(|e| e.text.clone())
                .unwrap_or(raw),
            _ => raw,
        };
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_string())
    }

    /// `text` with its `{{0}}`/`{{0:…}}` placeholder filled from
    /// `text_parameter_ref` in the context of `module` (see
    /// [`DynamicConfig::label`] and [`crate::label::substitute_label`]).
    /// Without a ref or a label the text is returned unchanged.
    pub fn labelled_text(
        &self,
        app: &ApplicationProgram,
        module: Option<usize>,
        text: &str,
        text_parameter_ref: Option<&str>,
    ) -> String {
        let label = text_parameter_ref.and_then(|r| self.label(app, module, r));
        crate::label::substitute_label(text, label.as_deref())
    }

    /// The instance id used as the value key for `module`.
    fn instance_id(&self, module: Option<usize>) -> &str {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
            .unwrap_or("")
    }
}

/// Evaluates `app`'s Dynamic section with the given parameter overrides.
///
/// `overrides` is keyed by app-relative `ParameterRef` id, optionally carrying
/// a project module-instance selector (`MD-<d>_M-<m>_MI-<n>_<param>_R-<r>`, the
/// device-file key form); a value applies to that ref, within that module
/// instance. A value is a ref's, not a parameter's, as in an ETS project
/// (`ParameterInstanceRef` is keyed by ref): when a configuration shows a
/// different ref of the same parameter, ETS writes that ref's own value (issue
/// #117: a Jung 3361-1MWW set to application type 1 shows other refs of its
/// send-delay parameters, and ETS writes their defaults, not the values set
/// through the refs of type 0). Keys that name no ref of this application are
/// listed in [`DynamicConfig::unresolved_overrides`].
///
/// `<Assign>` elements reached by the walk set their target to the source's
/// value (or the literal) and win over an override of the target, as in ETS
/// where an assigned parameter is not user-editable. The walk is repeated until
/// the assigned values settle.
///
/// Returns an empty configuration when the application has no Dynamic section.
pub fn evaluate_dynamic(
    app: &ApplicationProgram,
    overrides: &BTreeMap<String, String>,
) -> DynamicConfig {
    let mut values: HashMap<(String, String), String> = HashMap::new();
    let mut overridden = HashSet::new();
    let mut unresolved = Vec::new();
    for (key, value) in overrides {
        let (instance, param_ref) = split_selector(key);
        match parameter_id(app, &param_ref) {
            Some(_) => {
                let k = (instance.unwrap_or_default(), param_ref);
                overridden.insert(k.clone());
                values.insert(k, value.clone());
            }
            None => unresolved.push(key.clone()),
        }
    }

    let unions = UnionIndex::new(app);
    let placed = Rc::new(placed_parameters(app));
    let mut shared = SharedUnions::default();
    // The active parameters start empty and grow pass by pass (the least
    // fixpoint): a choose whose parameter is shown only later in document
    // order, or only through another gated choose, is taken once a pass has
    // reached that parameter.
    let mut active = HashSet::new();
    let mut walk = Walk::default();
    for _ in 0..MAX_ASSIGN_PASSES {
        walk = Walk {
            shared: std::mem::take(&mut shared),
            placed: Rc::clone(&placed),
            active_before: std::mem::take(&mut active),
            ..Walk::default()
        };
        walk.run(app, &values, &app.dynamic, None, 0);
        let next = unions.shared_memory(app, &values, &walk);
        let mut changed = next.images != walk.shared.images;
        shared = next;
        let now = walk.active_set(app);
        changed |= now != walk.active_before;
        active = now;
        for assign in &walk.assigns {
            let instance = walk.instance_id(assign.target_module).to_string();
            let new = match (&assign.value, &assign.source) {
                (Some(v), _) => Some(v.clone()),
                (None, Some(src)) => value_of(
                    app,
                    &values,
                    walk.instance_id(assign.source_module),
                    walk.module_args(assign.source_module),
                    src,
                ),
                (None, None) => None,
            };
            let Some(new) = new else {
                continue;
            };
            if parameter_id(app, &assign.target).is_none() {
                continue;
            }
            let key = (instance, assign.target.clone());
            if values.get(&key) != Some(&new) {
                overridden.remove(&key);
                values.insert(key, new);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // The written parameters: every reached ParameterRefRef plus the target
    // and source of every reached Assign, without duplicates.
    let ordinals = module_ordinals(app);
    for m in &mut walk.modules {
        m.ordinal = ordinals.get(&m.id).copied().unwrap_or(0);
    }
    let modules = walk.modules;
    let placement = |place: &Place, shown: bool| {
        let active = place.module.and_then(|i| modules.get(i));
        Placement {
            channel: place.ctx.channel.clone(),
            blocks: place.ctx.blocks.clone(),
            module: place.module,
            module_instance: active.map(|m| m.id.clone()),
            module_ordinal: active.map(|m| m.ordinal),
            shown,
        }
    };
    let mut seen = HashSet::new();
    let mut parameters = Vec::new();
    let mut parameter_placements = Vec::new();
    let assigned = walk.assigns.iter().flat_map(|a| {
        std::iter::once((
            ActiveParameter {
                module: a.target_module,
                param_ref_id: a.target.clone(),
            },
            &a.place,
        ))
        .chain(a.source.iter().map(|s| {
            (
                ActiveParameter {
                    module: a.source_module,
                    param_ref_id: s.clone(),
                },
                &a.place,
            )
        }))
    });
    let reached = walk
        .parameters
        .iter()
        .cloned()
        .zip(walk.parameter_places.iter())
        .map(|(p, place)| (p, place, true));
    for (p, place, shown) in reached.chain(assigned.map(|(p, place)| (p, place, false))) {
        if seen.insert(p.clone()) {
            parameters.push(p);
            parameter_placements.push(placement(place, shown));
        }
    }
    let mut seen = HashSet::new();
    let mut com_objects = Vec::new();
    let mut com_object_placements = Vec::new();
    for (c, place) in walk.com_objects.into_iter().zip(&walk.com_object_places) {
        if seen.insert(c.clone()) {
            com_objects.push(c);
            com_object_placements.push(placement(place, true));
        }
    }

    DynamicConfig {
        modules,
        parameters,
        com_objects,
        parameter_placements,
        com_object_placements,
        unresolved_overrides: unresolved,
        values,
        overridden,
    }
}

/// Splits a device-file parameter key into its module instance id and the
/// app-relative `ParameterRef` id: `MD-15_M-26_MI-1_UP-22_R-27` becomes
/// (`Some("MD-15_M-26")`, `MD-15_UP-22_R-27`); a key without a selector is
/// returned unchanged with `None`.
pub fn split_selector(key: &str) -> (Option<String>, String) {
    let parsed = (|| {
        let (md, after) = key.split_once("_M-")?;
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !md.strip_prefix("MD-").is_some_and(digits) {
            return None;
        }
        let (m, after) = after.split_once("_MI-")?;
        let (n, param) = after.split_once('_')?;
        if !digits(m) || !digits(n) {
            return None;
        }
        Some((format!("{md}_M-{m}"), format!("{md}_{param}")))
    })();
    match parsed {
        Some((instance, param_ref)) => (Some(instance), param_ref),
        None => (None, key.to_string()),
    }
}

/// The `Parameter` ids (full) the Dynamic section shows somewhere: every
/// parameter with a `<ParameterRefRef>` in the application's Dynamic section
/// or in any `<ModuleDef>`'s, in any branch. A `<choose>` on a parameter
/// outside this set is never gated by activity (see the module docs).
fn placed_parameters(app: &ApplicationProgram) -> HashSet<String> {
    fn visit(app: &ApplicationProgram, nodes: &[DynamicNode], out: &mut HashSet<String>) {
        for node in nodes {
            match node {
                DynamicNode::ParameterRefRef(r) => {
                    if let Some(id) = parameter_id(app, r) {
                        out.insert(id.to_string());
                    }
                }
                DynamicNode::Choose { whens, .. } => {
                    for w in whens {
                        visit(app, &w.children, out);
                    }
                }
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. } => visit(app, children, out),
                DynamicNode::ComObjectRefRef(_)
                | DynamicNode::Module { .. }
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    let mut out = HashSet::new();
    visit(app, &app.dynamic, &mut out);
    for body in app.module_dynamics.values() {
        visit(app, body, &mut out);
    }
    out
}

/// The scope a ref reached inside `module` belongs to (see [`Walk::scope`]).
fn scope_of(modules: &[ActiveModule], module: Option<usize>, ref_id: &str) -> Option<usize> {
    let m = modules.get(module?)?;
    let own = ref_id
        .strip_prefix(m.module_def.as_str())
        .is_some_and(|rest| rest.starts_with('_'));
    if own || ref_id.starts_with("MD-") {
        module
    } else {
        None
    }
}

/// The device-file key of an app-relative id in a module instance: the id
/// itself at the application level (`instance` `None`), else the id with the
/// project module-instance selector inserted after its module definition
/// (`MD-1_M-3` and `MD-1_P-3_R-5` give `MD-1_M-3_MI-1_P-3_R-5`). This is the
/// key form device files use for parameters (and the inverse of
/// [`split_selector`]); it applies to parameter ids (`MD-1_P-3`), refs and
/// channel ids alike.
pub fn selector_key(instance: Option<&str>, app_relative_id: &str) -> String {
    let Some(instance) = instance else {
        return app_relative_id.to_string();
    };
    let module_def = instance.split_once("_M-").map_or(instance, |(md, _)| md);
    let rest = app_relative_id
        .strip_prefix(module_def)
        .and_then(|r| r.strip_prefix('_'))
        .unwrap_or(app_relative_id);
    format!("{instance}_MI-1_{rest}")
}

/// The one ref through which a parameter (one memory cell) is stored: see
/// [`visible_parameter_refs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleParameter {
    /// The parameter's key: its app-relative id with the module-instance
    /// selector (`P-12`, `MD-1_M-3_MI-1_P-3`; see [`selector_key`]).
    pub key: String,
    /// The app-relative `Parameter` id (`P-12`, `MD-1_P-3`).
    pub parameter_id: String,
    /// The scope of the parameter: index into [`DynamicConfig::modules`], as
    /// in [`ActiveParameter::module`].
    pub module: Option<usize>,
    /// The chosen app-relative `ParameterRef` id (`MD-1_P-3_R-5`).
    pub param_ref_id: String,
    /// The chosen ref in device-key form (`MD-1_M-3_MI-1_P-3_R-5`).
    pub ref_key: String,
    /// Index of the chosen ref in [`DynamicConfig::parameters`] (and
    /// [`DynamicConfig::parameter_placements`]).
    pub index: usize,
    /// The other active refs of the same parameter in the same scope,
    /// app-relative, in walk order.
    pub alternatives: Vec<String>,
}

/// Picks one active `ParameterRef` per parameter (per module instance), so a
/// parameter is stored once per memory cell.
///
/// The rule: among the entries of [`DynamicConfig::parameters`] that point at
/// the same `Parameter` in the same scope, take the first one that is shown
/// (reached through a `<ParameterRefRef>`, [`Placement::shown`]) in walk
/// order, which is document order with each reached module body expanded in
/// place; when none is shown (the parameter is only touched by an
/// `<Assign>`), take the first entry. Every other active ref of that
/// parameter is listed in [`VisibleParameter::alternatives`]. Refs that
/// resolve to no parameter are skipped. The result is ordered by the chosen
/// entry's index.
pub fn visible_parameter_refs(
    app: &ApplicationProgram,
    config: &DynamicConfig,
) -> Vec<VisibleParameter> {
    let prefix = format!("{}_", app.id);
    // (instance, parameter id) -> indices into config.parameters, walk order.
    type Key = (Option<usize>, String);
    let mut groups: Vec<(Key, Vec<usize>)> = Vec::new();
    let mut slot: HashMap<Key, usize> = HashMap::new();
    for (i, p) in config.parameters.iter().enumerate() {
        let Some(pid) = parameter_id(app, &p.param_ref_id) else {
            continue;
        };
        let rel = pid.strip_prefix(&prefix).unwrap_or(pid).to_string();
        let key = (p.module, rel);
        match slot.get(&key) {
            Some(&g) => groups[g].1.push(i),
            None => {
                slot.insert(key.clone(), groups.len());
                groups.push((key, vec![i]));
            }
        }
    }
    let shown = |i: usize| config.parameter_placements.get(i).is_some_and(|p| p.shown);
    let mut out: Vec<VisibleParameter> = groups
        .into_iter()
        .filter_map(|((module, parameter_id), indices)| {
            let chosen = indices
                .iter()
                .copied()
                .find(|&i| shown(i))
                .or_else(|| indices.first().copied())?;
            let param_ref_id = config.parameters.get(chosen)?.param_ref_id.clone();
            let mut alternatives: Vec<String> = Vec::new();
            for &i in &indices {
                let r = &config.parameters[i].param_ref_id;
                if *r != param_ref_id && !alternatives.contains(r) {
                    alternatives.push(r.clone());
                }
            }
            let instance = config.module_instance_id(module);
            Some(VisibleParameter {
                key: selector_key(instance, &parameter_id),
                ref_key: selector_key(instance, &param_ref_id),
                parameter_id,
                module,
                param_ref_id,
                index: chosen,
                alternatives,
            })
        })
        .collect();
    out.sort_by_key(|v| v.index);
    out
}

/// The 1-based ordinal of every module instance id among the instances of
/// its module definition, in `M-<m>` order (numeric `m`), counted over every
/// `<Module>` in the application's and the module definitions' Dynamic
/// sections, in any branch.
fn module_ordinals(app: &ApplicationProgram) -> HashMap<String, u32> {
    fn visit(nodes: &[DynamicNode], out: &mut BTreeMap<String, Vec<String>>) {
        for node in nodes {
            match node {
                DynamicNode::Module { id, module_def, .. } => {
                    out.entry(module_def.clone()).or_default().push(id.clone());
                }
                DynamicNode::Choose { whens, .. } => {
                    for w in whens {
                        visit(&w.children, out);
                    }
                }
                DynamicNode::Channel { children, .. }
                | DynamicNode::ParameterBlock { children, .. } => visit(children, out),
                DynamicNode::ParameterRefRef(_)
                | DynamicNode::ComObjectRefRef(_)
                | DynamicNode::Assign { .. } => {}
            }
        }
    }
    let mut by_def = BTreeMap::new();
    visit(&app.dynamic, &mut by_def);
    for body in app.module_dynamics.values() {
        visit(body, &mut by_def);
    }
    let m_number = |id: &str| -> Option<u64> { id.rsplit_once("_M-")?.1.parse().ok() };
    let mut out = HashMap::new();
    for mut ids in by_def.into_values() {
        ids.sort_by(|a, b| m_number(a).cmp(&m_number(b)).then_with(|| a.cmp(b)));
        ids.dedup();
        for (i, id) in ids.into_iter().enumerate() {
            out.insert(id, u32::try_from(i + 1).unwrap_or(u32::MAX));
        }
    }
    out
}

/// The full `Parameter` id an app-relative `ParameterRef` id points at.
fn parameter_id<'a>(app: &'a ApplicationProgram, param_ref_id: &str) -> Option<&'a str> {
    app.parameter_refs
        .get(&format!("{}_{param_ref_id}", app.id))
        .map(|r| r.ref_id.as_str())
}

/// The effective value of an app-relative `ParameterRef` in one instance: an
/// override or `<Assign>` result, else the ref's `Value`, else the parameter's
/// `Value`. A default of a parameter with a `BaseValue` argument has that
/// argument's value in the instance (`args`) added to it, as ETS does (issue
/// #126: the Jung 230021SU input module's "internal group communication"
/// parameter is `Value="0" BaseValue="MD-1_A-19"`, 4 in one instance and 5 in
/// another, and its `<choose>` selects the instance's App-ID and debounce refs).
fn value_of(
    app: &ApplicationProgram,
    values: &HashMap<(String, String), String>,
    instance: &str,
    args: Option<&HashMap<String, i64>>,
    param_ref_id: &str,
) -> Option<String> {
    let pref = app
        .parameter_refs
        .get(&format!("{}_{param_ref_id}", app.id))?;
    if let Some(v) = values.get(&(instance.to_string(), param_ref_id.to_string())) {
        return Some(v.clone());
    }
    let param = app.parameters.get(&pref.ref_id);
    let default = pref
        .value
        .clone()
        .or_else(|| param.and_then(|p| p.default.clone()));
    let base = param
        .and_then(|p| p.base_value.as_deref())
        .map(|arg| arg.strip_prefix(&format!("{}_", app.id)).unwrap_or(arg))
        .and_then(|arg| args?.get(arg).copied());
    match base {
        Some(base) => {
            let own = match default.as_deref().map(str::trim) {
                None | Some("") => 0,
                Some(v) => match v.parse::<i64>() {
                    Ok(n) => n,
                    // A non-integer default takes no base.
                    Err(_) => return default,
                },
            };
            Some(own.saturating_add(base).to_string())
        }
        None => default,
    }
}

/// Whether a `<when>` test (other than `default`) matches a value.
fn when_matches(test: &WhenTest, value: Option<f64>) -> bool {
    let Some(v) = value else { return false };
    match test {
        // Exact values compare as integers; a fractional value matches none.
        WhenTest::Values(vs) => v.fract() == 0.0 && vs.iter().any(|&x| x as f64 == v),
        WhenTest::Compare { op, value } => {
            use crate::application::CompareOp;
            let x = *value as f64;
            match op {
                CompareOp::Ne => v != x,
                CompareOp::Lt => v < x,
                CompareOp::Le => v <= x,
                CompareOp::Gt => v > x,
                CompareOp::Ge => v >= x,
            }
        }
        WhenTest::Default | WhenTest::Unknown(_) => false,
    }
}

/// A reached `<Assign>`.
#[derive(Debug, Clone)]
struct ReachedAssign {
    /// The scope of `target` (see [`Walk::scope`]).
    target_module: Option<usize>,
    target: String,
    /// The scope of `source`.
    source_module: Option<usize>,
    source: Option<String>,
    value: Option<String>,
    /// Where the `<Assign>` element sits.
    place: Place,
}

/// One pass over the Dynamic tree.
#[derive(Debug, Default)]
struct Walk {
    modules: Vec<ActiveModule>,
    parameters: Vec<ActiveParameter>,
    com_objects: Vec<ActiveComObject>,
    /// Where each entry of `parameters` was reached, same index.
    parameter_places: Vec<Place>,
    /// Where each entry of `com_objects` was reached, same index.
    com_object_places: Vec<Place>,
    /// The channel and block path at the current point of the walk.
    ctx: Rc<Context>,
    assigns: Vec<ReachedAssign>,
    /// What the previous pass left in the unions' shared memory.
    shared: SharedUnions,
    /// The parameters the Dynamic section shows somewhere
    /// ([`placed_parameters`]).
    placed: Rc<HashSet<String>>,
    /// The active parameters the previous pass reached, keyed by (module
    /// instance id or `""`, full `Parameter` id).
    active_before: HashSet<(String, String)>,
    /// The parameters this pass has reached so far, same keys.
    active_now: HashSet<(String, String)>,
}

/// The shared memory of every union a pass reached a member of, and the values
/// the members it did not reach read from it.
///
/// Union members overlay one memory region, so in ETS a member that is not
/// shown has whatever value the shown member left in those bits, not its own
/// default. A `<choose>` on such a member branches on that value (the ABB
/// BE/S16's template channel: `Par_Operation_11` defaults to 3, but its union
/// sibling `Par_Operation_2` is the one shown, with 2, so the `when test="3"`
/// block with `Par_Operation_5` is not shown and ETS writes `Par_Operation_4`).
#[derive(Debug, Default)]
struct SharedUnions {
    /// Keyed by (module instance id or `""`, union index): the region's bits.
    images: BTreeMap<(String, usize), Vec<u8>>,
    /// Keyed by (module instance id or `""`, app-relative `ParameterRef` id):
    /// the value an unreached member reads.
    values: HashMap<(String, String), String>,
}

/// Where each union member parameter sits: parameter id to (union index,
/// member bit position relative to the union, member width in bits, signed).
struct UnionIndex {
    members: HashMap<String, (usize, u32, u32, bool)>,
}

impl UnionIndex {
    fn new(app: &ApplicationProgram) -> Self {
        let mut members = HashMap::new();
        for (ui, union) in app.unions.iter().enumerate() {
            for member in &union.members {
                let Some((bits, signed)) = integer_width(app, &member.parameter) else {
                    continue;
                };
                let pos =
                    member.offset.unwrap_or(0) * 8 + u32::from(member.bit_offset.unwrap_or(0));
                members.insert(member.parameter.clone(), (ui, pos, bits, signed));
            }
        }
        Self { members }
    }

    /// Lays the reached members' values into their unions' memory, then reads
    /// every other ref of a member of those unions back out of it.
    fn shared_memory(
        &self,
        app: &ApplicationProgram,
        values: &HashMap<(String, String), String>,
        walk: &Walk,
    ) -> SharedUnions {
        let mut out = SharedUnions::default();
        if self.members.is_empty() {
            return out;
        }
        let mut reached: HashSet<(String, String)> = HashSet::new();
        for p in &walk.parameters {
            let instance = walk.instance_id(p.module).to_string();
            reached.insert((instance.clone(), p.param_ref_id.clone()));
            let Some(&(ui, pos, bits, _)) =
                parameter_id(app, &p.param_ref_id).and_then(|id| self.members.get(id))
            else {
                continue;
            };
            let Some(v) = value_of(
                app,
                values,
                &instance,
                walk.module_args(p.module),
                &p.param_ref_id,
            )
            .and_then(|v| v.trim().parse::<i64>().ok()) else {
                continue;
            };
            let size = app.unions[ui].size_bits.unwrap_or(0).max(pos + bits);
            let image = out
                .images
                .entry((instance, ui))
                .or_insert_with(|| vec![0; size.div_ceil(8) as usize]);
            put_bits(image, pos, bits, v as u64);
        }
        let mut by_union: HashMap<usize, Vec<(&String, &Vec<u8>)>> = HashMap::new();
        for ((instance, ui), image) in &out.images {
            by_union.entry(*ui).or_default().push((instance, image));
        }
        let prefix = format!("{}_", app.id);
        let mut read = HashMap::new();
        for pref in app.parameter_refs.values() {
            let Some(&(ui, pos, bits, signed)) = self.members.get(&pref.ref_id) else {
                continue;
            };
            let (Some(rel), Some(images)) = (pref.id.strip_prefix(&prefix), by_union.get(&ui))
            else {
                continue;
            };
            for (instance, image) in images {
                let key = ((*instance).clone(), rel.to_string());
                if reached.contains(&key) {
                    continue;
                }
                let raw = get_bits(image, pos, bits);
                let v = if signed && bits > 0 && bits < 64 && raw >> (bits - 1) & 1 == 1 {
                    (raw as i64) - (1i64 << bits)
                } else {
                    raw as i64
                };
                read.insert(key, v.to_string());
            }
        }
        out.values = read;
        out
    }
}

/// The width and signedness of an integer or enumeration parameter, `None` for
/// any other type (text, float, …), whose shared bits are not read back.
fn integer_width(app: &ApplicationProgram, parameter: &str) -> Option<(u32, bool)> {
    let ptype = app.parameters.get(parameter)?.parameter_type.as_deref()?;
    match &app.parameter_types.get(ptype)?.kind {
        ParameterType::Int {
            size_bits, signed, ..
        } => Some(((*size_bits)?, *signed)),
        ParameterType::Enum { size_bits, values } => {
            // A `BinaryValue` enumeration's memory is not its `Value`.
            if values.iter().any(|v| v.binary_value.is_some()) {
                return None;
            }
            Some(((*size_bits)?, false))
        }
        _ => None,
    }
    .filter(|(bits, _)| (1..=64).contains(bits))
}

/// Writes the low `bits` of `value` MSB-first at bit `pos` of `image`.
fn put_bits(image: &mut [u8], pos: u32, bits: u32, value: u64) {
    for i in 0..bits {
        let bit = (value >> (bits - 1 - i)) & 1;
        let at = (pos + i) as usize;
        let Some(byte) = image.get_mut(at / 8) else {
            return;
        };
        let mask = 0x80u8 >> (at % 8);
        if bit == 1 {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
}

/// Reads `bits` MSB-first from bit `pos` of `image` (missing bits read 0).
fn get_bits(image: &[u8], pos: u32, bits: u32) -> u64 {
    (0..bits).fold(0u64, |acc, i| {
        let at = (pos + i) as usize;
        let bit = image.get(at / 8).map_or(0, |b| (b >> (7 - at % 8)) & 1);
        (acc << 1) | u64::from(bit)
    })
}

impl Walk {
    /// The active parameters this pass reached: every reached
    /// `<ParameterRefRef>` and every reached `<Assign>` target.
    fn active_set(&self, app: &ApplicationProgram) -> HashSet<(String, String)> {
        let mut out = self.active_now.clone();
        for a in &self.assigns {
            if let Some(id) = parameter_id(app, &a.target) {
                out.insert((
                    self.instance_id(a.target_module).to_string(),
                    id.to_string(),
                ));
            }
        }
        out
    }

    /// Whether the parameter of `param_ref_id` in `instance` is active, so a
    /// `<choose>` on it may select a branch (issue #159, see the module docs).
    fn is_active(&self, app: &ApplicationProgram, instance: &str, param_ref_id: &str) -> bool {
        let Some(id) = parameter_id(app, param_ref_id) else {
            return true;
        };
        if !self.placed.contains(id) {
            return true;
        }
        let key = (instance.to_string(), id.to_string());
        self.active_now.contains(&key) || self.active_before.contains(&key)
    }

    fn module_args(&self, module: Option<usize>) -> Option<&HashMap<String, i64>> {
        module.and_then(|i| self.modules.get(i)).map(|m| &m.args)
    }

    fn instance_id(&self, module: Option<usize>) -> &str {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
            .unwrap_or("")
    }

    /// The current location, inside the module instance `module`.
    fn place(&self, module: Option<usize>) -> Place {
        Place {
            ctx: Rc::clone(&self.ctx),
            module,
        }
    }

    /// The scope a ref reached inside `module` belongs to: the module instance
    /// for a ref of its own `ModuleDef` (`MD-3_P-3_R-3` inside an `MD-3`
    /// instance), the application for an application ref (`P-15_R-16`).
    ///
    /// A module's Dynamic body may test and assign application parameters:
    /// the Jung 230021SU blind module chooses on the application's "safety
    /// release" `P-15_R-16` and assigns the application's alarm parameters to
    /// its own. Those resolve to the application's values, never to a
    /// per-instance copy (issue #126).
    fn scope(&self, module: Option<usize>, ref_id: &str) -> Option<usize> {
        scope_of(&self.modules, module, ref_id)
    }

    fn run(
        &mut self,
        app: &ApplicationProgram,
        values: &HashMap<(String, String), String>,
        nodes: &[DynamicNode],
        module: Option<usize>,
        depth: usize,
    ) {
        for node in nodes {
            match node {
                DynamicNode::ParameterRefRef(r) => {
                    let scope = self.scope(module, r);
                    if let Some(id) = parameter_id(app, r) {
                        self.active_now
                            .insert((self.instance_id(scope).to_string(), id.to_string()));
                    }
                    self.parameters.push(ActiveParameter {
                        module: scope,
                        param_ref_id: r.clone(),
                    });
                    self.parameter_places.push(self.place(module));
                }
                DynamicNode::ComObjectRefRef(r) => {
                    self.com_objects.push(ActiveComObject {
                        module: self.scope(module, r),
                        com_object_ref_id: r.clone(),
                    });
                    self.com_object_places.push(self.place(module));
                }
                DynamicNode::Channel { children, .. } => {
                    let outer = Rc::clone(&self.ctx);
                    self.ctx = Rc::new(Context {
                        channel: node.channel_ref(),
                        blocks: outer.blocks.clone(),
                    });
                    self.run(app, values, children, module, depth);
                    self.ctx = outer;
                }
                DynamicNode::ParameterBlock { children, .. } => {
                    let outer = Rc::clone(&self.ctx);
                    let mut blocks = outer.blocks.clone();
                    blocks.extend(node.block_ref());
                    self.ctx = Rc::new(Context {
                        channel: outer.channel.clone(),
                        blocks,
                    });
                    self.run(app, values, children, module, depth);
                    self.ctx = outer;
                }
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    let scope = self.scope(module, param_ref_id);
                    let instance = self.instance_id(scope);
                    let key = (instance.to_string(), param_ref_id.clone());
                    let shared = (!values.contains_key(&key))
                        .then(|| self.shared.values.get(&key).cloned())
                        .flatten();
                    // An inactive controlling parameter selects no branch, not
                    // even the default one; a union member reading live shared
                    // memory is active.
                    if shared.is_none() && !self.is_active(app, instance, param_ref_id) {
                        continue;
                    }
                    let value = shared
                        .or_else(|| {
                            value_of(app, values, instance, self.module_args(scope), param_ref_id)
                        })
                        .and_then(|v| v.trim().parse::<f64>().ok());
                    let hits: Vec<_> = whens
                        .iter()
                        .filter(|w| when_matches(&w.test, value))
                        .collect();
                    let taken: Vec<_> = if hits.is_empty() {
                        whens
                            .iter()
                            .filter(|w| w.test == WhenTest::Default)
                            .collect()
                    } else {
                        hits
                    };
                    for w in taken {
                        self.run(app, values, &w.children, module, depth);
                    }
                }
                DynamicNode::Module {
                    id,
                    module_def,
                    args,
                } => {
                    if depth >= MAX_MODULE_DEPTH {
                        continue;
                    }
                    let Some(body) = app.module_dynamics.get(module_def) else {
                        continue;
                    };
                    let idx = self.modules.len();
                    self.modules.push(ActiveModule {
                        id: id.clone(),
                        module_def: module_def.clone(),
                        args: args.clone(),
                        ordinal: 0,
                    });
                    self.run(app, values, body, Some(idx), depth + 1);
                }
                DynamicNode::Assign {
                    target,
                    source,
                    value,
                } => self.assigns.push(ReachedAssign {
                    target_module: self.scope(module, target),
                    target: target.clone(),
                    source_module: source.as_deref().and_then(|s| self.scope(module, s)),
                    source: source.clone(),
                    value: value.clone(),
                    place: self.place(module),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::parse_application_program_str;

    /// A two-module app: a selector picks which module instance is reached; the
    /// module shows an object unconditionally and a second one behind its own
    /// parameter; an `<Assign>` copies one module parameter into another.
    const XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="A" MaskVersion="MV-07B0" Name="t">
      <Static>
       <Parameters>
        <Parameter Id="A_P-1" Name="sel" Value="0" />
       </Parameters>
       <ParameterRefs><ParameterRef Id="A_P-1_R-1" RefId="A_P-1" /></ParameterRefs>
       <ComObjects><ComObject Id="A_O-7" Number="7" /></ComObjects>
       <ComObjectRefs><ComObjectRef Id="A_O-7_R-1" RefId="A_O-7" /></ComObjectRefs>
      </Static>
      <ModuleDefs>
       <ModuleDef Id="A_MD-1" Name="m">
        <Arguments><Argument Id="A_MD-1_A-1" Name="obj" /></Arguments>
        <Static>
         <Parameters>
          <Parameter Id="A_MD-1_P-1" Name="fb" Value="0" />
          <Parameter Id="A_MD-1_P-2" Name="copy" Value="0" />
         </Parameters>
         <ParameterRefs>
          <ParameterRef Id="A_MD-1_P-1_R-1" RefId="A_MD-1_P-1" />
          <ParameterRef Id="A_MD-1_P-2_R-2" RefId="A_MD-1_P-2" />
         </ParameterRefs>
         <ComObjects>
          <ComObject Id="A_MD-1_O-1" Number="0" BaseNumber="A_MD-1_A-1" />
          <ComObject Id="A_MD-1_O-2" Number="1" BaseNumber="A_MD-1_A-1" />
         </ComObjects>
         <ComObjectRefs>
          <ComObjectRef Id="A_MD-1_O-1_R-1" RefId="A_MD-1_O-1" />
          <ComObjectRef Id="A_MD-1_O-2_R-2" RefId="A_MD-1_O-2" />
         </ComObjectRefs>
        </Static>
        <Dynamic>
         <ParameterBlock Id="A_MD-1_PB-1">
          <ParameterRefRef RefId="A_MD-1_P-1_R-1" />
          <ComObjectRefRef RefId="A_MD-1_O-1_R-1" />
          <choose ParamRefId="A_MD-1_P-1_R-1">
           <when test="0" />
           <when test="1"><ComObjectRefRef RefId="A_MD-1_O-2_R-2" /></when>
          </choose>
          <Assign TargetParamRefRef="A_MD-1_P-2_R-2" SourceParamRefRef="A_MD-1_P-1_R-1" />
         </ParameterBlock>
        </Dynamic>
       </ModuleDef>
      </ModuleDefs>
      <Dynamic>
       <ChannelIndependentBlock>
        <ParameterBlock Id="A_PB-1">
         <ParameterRefRef RefId="A_P-1_R-1" />
        </ParameterBlock>
       </ChannelIndependentBlock>
       <choose ParamRefId="A_P-1_R-1">
        <when test="0">
         <Module Id="A_MD-1_M-1" RefId="A_MD-1"><NumericArg RefId="A_MD-1_A-1" Value="10" /></Module>
        </when>
        <when default="true">
         <Module Id="A_MD-1_M-2" RefId="A_MD-1"><NumericArg RefId="A_MD-1_A-1" Value="20" /></Module>
         <ComObjectRefRef RefId="A_O-7_R-1" />
        </when>
       </choose>
      </Dynamic>
     </ApplicationProgram></KNX>"#;

    #[test]
    fn test_evaluate_dynamic_defaults_reach_the_first_module()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("A", XML)?;
        assert_eq!(app.module_dynamics.len(), 1);
        let cfg = evaluate_dynamic(&app, &BTreeMap::new());
        assert_eq!(cfg.modules.len(), 1);
        assert_eq!(cfg.modules[0].id, "MD-1_M-1");
        assert_eq!(cfg.modules[0].args.get("MD-1_A-1"), Some(&10));
        let cos: Vec<_> = cfg
            .com_objects
            .iter()
            .map(|c| c.com_object_ref_id.as_str())
            .collect();
        assert_eq!(cos, ["MD-1_O-1_R-1"]);
        Ok(())
    }

    #[test]
    fn test_evaluate_dynamic_overrides_select_branches_and_assign_copies()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("A", XML)?;
        let mut overrides = BTreeMap::new();
        overrides.insert("P-1_R-1".to_string(), "5".to_string());
        overrides.insert("MD-1_M-2_MI-1_P-1_R-1".to_string(), "1".to_string());
        overrides.insert("P-99_R-1".to_string(), "1".to_string());
        let cfg = evaluate_dynamic(&app, &overrides);
        // The default branch: module 2 plus the static object 7.
        assert_eq!(cfg.modules.len(), 1);
        assert_eq!(cfg.modules[0].id, "MD-1_M-2");
        let cos: Vec<_> = cfg
            .com_objects
            .iter()
            .map(|c| (c.module, c.com_object_ref_id.as_str()))
            .collect();
        assert_eq!(
            cos,
            [
                (Some(0), "MD-1_O-1_R-1"),
                (Some(0), "MD-1_O-2_R-2"),
                (None, "O-7_R-1")
            ]
        );
        // The assign copied the instance's feedback value into `copy`, and both
        // assign ends count as written parameters.
        assert_eq!(
            cfg.value(&app, Some(0), "MD-1_P-2_R-2").as_deref(),
            Some("1")
        );
        assert!(cfg.is_override(&app, Some(0), "MD-1_P-1_R-1"));
        assert!(!cfg.is_override(&app, Some(0), "MD-1_P-2_R-2"));
        assert!(
            cfg.parameters
                .iter()
                .any(|p| p.param_ref_id == "MD-1_P-2_R-2")
        );
        assert_eq!(cfg.unresolved_overrides, ["P-99_R-1"]);
        Ok(())
    }

    /// The Jung 230021SU shape (issue #126): the module's `intcomm` default
    /// is its `BaseValue` argument, and its switching object is shown only
    /// while that value is 0; the module body shows and tests the
    /// application's `release` and assigns from the application's `alarm`.
    const MODULE_APP_REFS_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="A" MaskVersion="MV-07B0" Name="t">
      <Static>
       <Parameters>
        <Parameter Id="A_P-1" Name="release" Value="0" />
        <Parameter Id="A_P-2" Name="alarm" Value="0" />
       </Parameters>
       <ParameterRefs>
        <ParameterRef Id="A_P-1_R-1" RefId="A_P-1" />
        <ParameterRef Id="A_P-2_R-2" RefId="A_P-2" />
       </ParameterRefs>
      </Static>
      <ModuleDefs>
       <ModuleDef Id="A_MD-1" Name="m">
        <Arguments><Argument Id="A_MD-1_A-1" Name="obj" /><Argument Id="A_MD-1_A-2" Name="intcomm" /></Arguments>
        <Static>
         <Parameters>
          <Parameter Id="A_MD-1_P-1" Name="intcomm" Value="0" BaseValue="A_MD-1_A-2" />
          <Parameter Id="A_MD-1_P-2" Name="copy" Value="0" />
         </Parameters>
         <ParameterRefs>
          <ParameterRef Id="A_MD-1_P-1_R-1" RefId="A_MD-1_P-1" />
          <ParameterRef Id="A_MD-1_P-2_R-2" RefId="A_MD-1_P-2" />
         </ParameterRefs>
         <ComObjects><ComObject Id="A_MD-1_O-1" Number="0" BaseNumber="A_MD-1_A-1" /></ComObjects>
         <ComObjectRefs><ComObjectRef Id="A_MD-1_O-1_R-1" RefId="A_MD-1_O-1" /></ComObjectRefs>
        </Static>
        <Dynamic>
         <ParameterBlock Id="A_MD-1_PB-1">
          <choose ParamRefId="A_MD-1_P-1_R-1">
           <when test="0"><ComObjectRefRef RefId="A_MD-1_O-1_R-1" /></when>
          </choose>
          <ParameterRefRef RefId="A_P-1_R-1" />
          <choose ParamRefId="A_P-1_R-1">
           <when test="1"><Assign TargetParamRefRef="A_MD-1_P-2_R-2" SourceParamRefRef="A_P-2_R-2" /></when>
          </choose>
         </ParameterBlock>
        </Dynamic>
       </ModuleDef>
      </ModuleDefs>
      <Dynamic>
       <Module Id="A_MD-1_M-1" RefId="A_MD-1"><NumericArg RefId="A_MD-1_A-1" Value="10" /><NumericArg RefId="A_MD-1_A-2" Value="0" /></Module>
       <Module Id="A_MD-1_M-2" RefId="A_MD-1"><NumericArg RefId="A_MD-1_A-1" Value="20" /><NumericArg RefId="A_MD-1_A-2" Value="4" /></Module>
      </Dynamic>
     </ApplicationProgram></KNX>"#;

    #[test]
    fn test_evaluate_dynamic_base_value_takes_the_instance_argument()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("A", MODULE_APP_REFS_XML)?;
        let cfg = evaluate_dynamic(&app, &BTreeMap::new());
        assert_eq!(cfg.modules.len(), 2);
        assert_eq!(
            cfg.value(&app, Some(0), "MD-1_P-1_R-1").as_deref(),
            Some("0")
        );
        assert_eq!(
            cfg.value(&app, Some(1), "MD-1_P-1_R-1").as_deref(),
            Some("4")
        );
        // Only the instance whose argument is 0 shows its switching object.
        let cos: Vec<_> = cfg
            .com_objects
            .iter()
            .map(|c| (c.module, c.com_object_ref_id.as_str()))
            .collect();
        assert_eq!(cos, [(Some(0), "MD-1_O-1_R-1")]);
        Ok(())
    }

    #[test]
    fn test_evaluate_dynamic_application_refs_in_a_module_resolve_to_the_application()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("A", MODULE_APP_REFS_XML)?;
        let mut overrides = BTreeMap::new();
        overrides.insert("P-1_R-1".to_string(), "1".to_string());
        overrides.insert("P-2_R-2".to_string(), "3".to_string());
        let cfg = evaluate_dynamic(&app, &overrides);
        // The application's override steers the module's choose, and the
        // assign copies the application's value into each instance.
        assert_eq!(
            cfg.value(&app, Some(0), "MD-1_P-2_R-2").as_deref(),
            Some("3")
        );
        assert_eq!(
            cfg.value(&app, Some(1), "MD-1_P-2_R-2").as_deref(),
            Some("3")
        );
        // Application refs reached inside the module are the application's.
        let app_level: Vec<_> = cfg
            .parameters
            .iter()
            .filter(|p| !p.param_ref_id.starts_with("MD-"))
            .map(|p| (p.module, p.param_ref_id.as_str()))
            .collect();
        assert_eq!(app_level, [(None, "P-1_R-1"), (None, "P-2_R-2")]);
        Ok(())
    }

    #[test]
    fn test_split_selector_module_and_plain_keys() {
        assert_eq!(
            split_selector("MD-15_M-26_MI-1_UP-22_R-27"),
            (
                Some("MD-15_M-26".to_string()),
                "MD-15_UP-22_R-27".to_string()
            )
        );
        assert_eq!(
            split_selector("P-1313_R-191"),
            (None, "P-1313_R-191".to_string())
        );
        assert_eq!(
            split_selector("MD-3_P-3_R-6"),
            (None, "MD-3_P-3_R-6".to_string())
        );
    }

    /// A value belongs to a ref: `P-2` has a ref in each branch of `P-1`; a
    /// value set through `R-20` does not carry over to `R-21` when the other
    /// branch shows it (the Jung 3361-1MWW send delays, issue #117).
    #[test]
    fn test_evaluate_dynamic_value_is_per_ref() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
         <ApplicationProgram Id="A" MaskVersion="MV-0705" Name="t">
          <Static>
           <Parameters>
            <Parameter Id="A_P-1" Name="type" Value="0" />
            <Parameter Id="A_P-2" Name="delay" Value="30" />
           </Parameters>
           <ParameterRefs>
            <ParameterRef Id="A_P-1_R-1" RefId="A_P-1" />
            <ParameterRef Id="A_P-2_R-20" RefId="A_P-2" />
            <ParameterRef Id="A_P-2_R-21" RefId="A_P-2" />
           </ParameterRefs>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="A_PB-1">
           <ParameterRefRef RefId="A_P-1_R-1" />
           <choose ParamRefId="A_P-1_R-1">
            <when test="0"><ParameterRefRef RefId="A_P-2_R-20" /></when>
            <when test="1"><ParameterRefRef RefId="A_P-2_R-21" /></when>
           </choose>
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
         </ApplicationProgram></KNX>"#;
        let app = parse_application_program_str("A", xml)?;
        let overrides: BTreeMap<String, String> = [
            ("P-1_R-1".to_string(), "1".to_string()),
            ("P-2_R-20".to_string(), "0".to_string()),
        ]
        .into();
        let config = evaluate_dynamic(&app, &overrides);
        let reached: Vec<&str> = config
            .parameters
            .iter()
            .map(|p| p.param_ref_id.as_str())
            .collect();
        assert_eq!(reached, ["P-1_R-1", "P-2_R-21"]);
        assert_eq!(config.value(&app, None, "P-2_R-21").as_deref(), Some("30"));
        assert!(!config.is_override(&app, None, "P-2_R-21"));
        assert_eq!(config.value(&app, None, "P-2_R-20").as_deref(), Some("0"));
        assert!(config.is_override(&app, None, "P-2_R-20"));
        Ok(())
    }

    /// Issue #159 (the 1.1.12 F50 Secure module's extension channel): `ext`
    /// is shown only inside a channel gated by `en`; chooses on it (one with a
    /// `default` branch, one placed before the channel in document order) show
    /// `inst` refs. `steer` is never shown anywhere and keeps steering.
    const INACTIVE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/20">
     <ApplicationProgram Id="A" MaskVersion="MV-07B0" Name="t">
      <Static>
       <Parameters>
        <Parameter Id="A_P-1" Name="en" Value="0" />
        <Parameter Id="A_P-2" Name="ext" Value="1" />
        <Parameter Id="A_P-3" Name="inst" Value="0" />
        <Parameter Id="A_P-4" Name="steer" Value="1" />
       </Parameters>
       <ParameterRefs>
        <ParameterRef Id="A_P-1_R-1" RefId="A_P-1" />
        <ParameterRef Id="A_P-2_R-2" RefId="A_P-2" />
        <ParameterRef Id="A_P-3_R-30" RefId="A_P-3" />
        <ParameterRef Id="A_P-3_R-31" RefId="A_P-3" Value="46" />
        <ParameterRef Id="A_P-3_R-32" RefId="A_P-3" />
        <ParameterRef Id="A_P-3_R-33" RefId="A_P-3" />
        <ParameterRef Id="A_P-4_R-4" RefId="A_P-4" />
       </ParameterRefs>
      </Static>
      <Dynamic>
       <ChannelIndependentBlock><ParameterBlock Id="A_PB-1">
        <ParameterRefRef RefId="A_P-1_R-1" />
        <choose ParamRefId="A_P-2_R-2">
         <when test="1"><ParameterRefRef RefId="A_P-3_R-32" /></when>
        </choose>
       </ParameterBlock></ChannelIndependentBlock>
       <choose ParamRefId="A_P-1_R-1">
        <when test="1 2">
         <Channel Id="A_CH-1" Number="1" Text="ext"><ParameterBlock Id="A_PB-2">
          <ParameterRefRef RefId="A_P-2_R-2" />
         </ParameterBlock></Channel>
        </when>
       </choose>
       <Channel Id="A_CH-2" Number="2" Text="main"><ParameterBlock Id="A_PB-3">
        <choose ParamRefId="A_P-2_R-2">
         <when test="0"><ParameterRefRef RefId="A_P-3_R-30" /></when>
         <when default="true"><ParameterRefRef RefId="A_P-3_R-31" /></when>
        </choose>
        <choose ParamRefId="A_P-4_R-4">
         <when test="1"><ParameterRefRef RefId="A_P-3_R-33" /></when>
        </choose>
       </ParameterBlock></Channel>
      </Dynamic>
     </ApplicationProgram></KNX>"#;

    fn reached_refs(cfg: &DynamicConfig) -> Vec<&str> {
        cfg.parameters
            .iter()
            .map(|p| p.param_ref_id.as_str())
            .collect()
    }

    #[test]
    fn test_evaluate_dynamic_inactive_controlling_parameter_selects_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = parse_application_program_str("A", INACTIVE_XML)?;
        // `en` = 0: `ext` is not shown, so neither choose on it selects a
        // branch (not even the default one); the never-shown `steer` still
        // steers.
        let cfg = evaluate_dynamic(&app, &BTreeMap::new());
        assert_eq!(reached_refs(&cfg), ["P-1_R-1", "P-3_R-33"]);

        // `en` = 1: `ext` is shown with its default 1, which takes the
        // default branch and (on a later pass) the choose placed before it.
        let on: BTreeMap<String, String> = [("P-1_R-1".to_string(), "1".to_string())].into();
        let cfg = evaluate_dynamic(&app, &on);
        assert_eq!(
            reached_refs(&cfg),
            ["P-1_R-1", "P-3_R-32", "P-2_R-2", "P-3_R-31", "P-3_R-33"]
        );

        // An explicit test value of an active parameter behaves as before.
        let mut zero = on.clone();
        zero.insert("P-2_R-2".to_string(), "0".to_string());
        let cfg = evaluate_dynamic(&app, &zero);
        assert_eq!(
            reached_refs(&cfg),
            ["P-1_R-1", "P-2_R-2", "P-3_R-30", "P-3_R-33"]
        );
        Ok(())
    }
}
