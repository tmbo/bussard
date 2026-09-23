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

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::application::{ApplicationProgram, DynamicNode, WhenTest};

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

    let mut walk = Walk::default();
    for _ in 0..MAX_ASSIGN_PASSES {
        walk = Walk::default();
        walk.run(app, &values, &app.dynamic, None, 0);
        let mut changed = false;
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
    let mut seen = HashSet::new();
    let mut parameters = Vec::new();
    let assigned = walk.assigns.iter().flat_map(|a| {
        std::iter::once(ActiveParameter {
            module: a.target_module,
            param_ref_id: a.target.clone(),
        })
        .chain(a.source.iter().map(|s| ActiveParameter {
            module: a.source_module,
            param_ref_id: s.clone(),
        }))
    });
    for p in walk.parameters.iter().cloned().chain(assigned) {
        if seen.insert(p.clone()) {
            parameters.push(p);
        }
    }
    let mut seen = HashSet::new();
    let com_objects = walk
        .com_objects
        .into_iter()
        .filter(|c| seen.insert(c.clone()))
        .collect();

    DynamicConfig {
        modules: walk.modules,
        parameters,
        com_objects,
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
}

/// One pass over the Dynamic tree.
#[derive(Debug, Default)]
struct Walk {
    modules: Vec<ActiveModule>,
    parameters: Vec<ActiveParameter>,
    com_objects: Vec<ActiveComObject>,
    assigns: Vec<ReachedAssign>,
}

impl Walk {
    fn module_args(&self, module: Option<usize>) -> Option<&HashMap<String, i64>> {
        module.and_then(|i| self.modules.get(i)).map(|m| &m.args)
    }

    fn instance_id(&self, module: Option<usize>) -> &str {
        module
            .and_then(|i| self.modules.get(i))
            .map(|m| m.id.as_str())
            .unwrap_or("")
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
        let m = self.modules.get(module?)?;
        let own = ref_id
            .strip_prefix(m.module_def.as_str())
            .is_some_and(|rest| rest.starts_with('_'));
        if own || ref_id.starts_with("MD-") {
            module
        } else {
            None
        }
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
                DynamicNode::ParameterRefRef(r) => self.parameters.push(ActiveParameter {
                    module: self.scope(module, r),
                    param_ref_id: r.clone(),
                }),
                DynamicNode::ComObjectRefRef(r) => self.com_objects.push(ActiveComObject {
                    module: self.scope(module, r),
                    com_object_ref_id: r.clone(),
                }),
                DynamicNode::Choose {
                    param_ref_id,
                    whens,
                } => {
                    let scope = self.scope(module, param_ref_id);
                    let value = value_of(
                        app,
                        values,
                        self.instance_id(scope),
                        self.module_args(scope),
                        param_ref_id,
                    )
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
}
