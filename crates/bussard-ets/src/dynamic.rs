//! Evaluation of an application program's Dynamic section against a device's
//! parameter values.
//!
//! The evaluator lives in [`bussard_model::dynamic`] behind the
//! [`DynamicSource`] trait (issue #345), so the product model can feed the
//! same walk. This module re-exports it unchanged for the download-side
//! callers and implements [`DynamicSource`] for [`ApplicationProgram`].

// The facade re-export keeps every `bussard_ets::dynamic::…` path working.
pub use bussard_model::dynamic::*;

use crate::application::{ApplicationProgram, ParameterType};

impl DynamicSource for ApplicationProgram {
    fn program_id(&self) -> &str {
        &self.id
    }

    fn dynamic(&self) -> &[DynamicNode] {
        &self.dynamic
    }

    fn module_dynamic(&self, module_def: &str) -> Option<&[DynamicNode]> {
        self.module_dynamics.get(module_def).map(Vec::as_slice)
    }

    fn module_dynamics(&self) -> Box<dyn Iterator<Item = (&str, &[DynamicNode])> + '_> {
        Box::new(
            self.module_dynamics
                .iter()
                .map(|(def, body)| (def.as_str(), body.as_slice())),
        )
    }

    fn parameter_ref(&self, ref_id: &str) -> Option<(&str, Option<&str>)> {
        ApplicationProgram::parameter_ref(self, ref_id)
            .map(|r| (r.ref_id.as_str(), r.value.as_deref()))
    }

    fn parameter_refs(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        let prefix = format!("{}_", self.id);
        Box::new(
            self.parameter_refs.values().filter_map(move |r| {
                Some((r.id.strip_prefix(prefix.as_str())?, r.ref_id.as_str()))
            }),
        )
    }

    fn parameter(&self, param_id: &str) -> Option<(Option<&str>, Option<&str>)> {
        self.parameters
            .get(param_id)
            .map(|p| (p.default.as_deref(), p.base_value.as_deref()))
    }

    fn integer_width(&self, param_id: &str) -> Option<(u32, bool)> {
        let ptype = self.parameters.get(param_id)?.parameter_type.as_deref()?;
        match &self.parameter_types.get(ptype)?.kind {
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

    fn enum_members(&self, param_id: &str) -> Option<&[EnumValue]> {
        let ptype = self.parameters.get(param_id)?.parameter_type.as_deref()?;
        match &self.parameter_types.get(ptype)?.kind {
            ParameterType::Enum { values, .. } => Some(values.as_slice()),
            _ => None,
        }
    }

    fn unions(&self) -> &[Union] {
        &self.unions
    }

    fn allocator(&self, allocator_id: &str) -> Option<Allocator> {
        self.allocators.get(allocator_id).copied()
    }

    fn argument_allocates(&self, arg_id: &str) -> Option<i64> {
        self.argument_allocates.get(arg_id).copied()
    }

    fn steers_only(&self, param_id: &str) -> bool {
        self.parameters
            .get(param_id)
            .is_some_and(|p| p.memory.is_none() && p.property.is_none())
            && !self
                .unions
                .iter()
                .any(|u| u.members.iter().any(|m| m.parameter == param_id))
    }

    fn is_type_none(&self, param_id: &str) -> bool {
        // A parameter without a known type is `!none` in the product model
        // too, so both sources answer alike.
        self.parameters.get(param_id).is_some_and(|p| {
            p.parameter_type
                .as_deref()
                .and_then(|t| self.parameter_types.get(t))
                .is_none_or(|d| matches!(d.kind, ParameterType::None))
        })
    }

    fn initial_value(&self, param_id: &str) -> Option<&str> {
        self.parameters.get(param_id)?.initial_value.as_deref()
    }

    fn ref_access_none(&self, param_ref_id: &str) -> bool {
        let Some(pref) = ApplicationProgram::parameter_ref(self, param_ref_id) else {
            return false;
        };
        let param = self.parameters.get(&pref.ref_id);
        pref.access
            .as_deref()
            .or(param.and_then(|p| p.access.as_deref()))
            == Some("None")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::parse_application_program_str;
    use std::collections::BTreeMap;

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
