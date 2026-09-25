//! One streaming parser for the `knx_master.xml` load-procedure templates.
//!
//! A `.knxprod` (and every ETS installation) ships a `knx_master.xml` that,
//! among much else, declares — per `<MaskVersion>` — the full `<Procedure
//! ProcedureType="Load" …>` templates a management tool follows to download a
//! device of that mask. These templates carry the per-object load-control ops
//! (Unload / Load / RelSegment / WriteRelMem / LoadCompleted for the address,
//! association, group-object and application objects) that a **merged**
//! application program does *not* carry itself: the app supplies only its own
//! `<LoadProcedure MergeId="N">` blocks, which ETS splices into the template at
//! the matching `<LdCtrlMerge MergeId="N"/>` markers.
//!
//! bussard needs the template so `bussard flash` of a merged app programs all
//! four objects the way ETS does, not just the app segment. This parser extracts
//! just the `Load` procedures per mask (the only thing the flash engine needs);
//! everything else in the multi-megabyte master file is skipped. The op parsing
//! reuses the same [`crate::application::push_load_op`] logic as the application
//! parser, so the two never diverge on how an `LdCtrl*` element maps to a
//! [`LoadOp`].
//!
//! # What is captured
//!
//! For each `<MaskVersion Id="MV-XXXX">` the parser records every `<Procedure
//! ProcedureType="Load" ProcedureSubType="…">` as a [`MaskLoadProcedure`]
//! (its sub-type plus the ordered [`LoadOp`]s, `LdCtrlMerge` markers included as
//! [`LoadOp::Merge`]). The flash engine later picks the right sub-type (the full
//! `all` download, falling back to `ap1`) and splices the app's blocks in.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::application::push_load_op;
use crate::attrs::{Attrs, get};
use crate::error::{EtsError, Result};
use crate::{LoadOp, LoadProcedure};

/// One `<Procedure ProcedureType="Load">` template from a mask block.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MaskLoadProcedure {
    /// The `ProcedureSubType`, e.g. `"all"`, `"ap1"`, `"grp"`, `"par"`. Absent
    /// on the rare untyped procedure.
    pub sub_type: Option<String>,
    /// The ordered load ops, `LdCtrlMerge` markers preserved as
    /// [`LoadOp::Merge`].
    pub ops: Vec<LoadOp>,
}

/// One `<Resource>` entry from a mask's `HawkConfigurationData`: a named device
/// resource (LSM control/status, a table location, …) with its memory location.
///
/// System 7 (mask 0705/0701) resolves its LSM realisation and table addresses
/// from these rather than from hardcoded Rust constants (`[system7-spec §2.4]`).
/// The Jung MV-0705 block confirms the corpus defaults: `GroupAddressTableLoadControl`
/// at `StandardMemory` `StartAddress=260` (`0x0104`), `Length=12`,
/// `Flavour="LoadControl_M112"`, and the per-table load-status bytes at
/// `0xB6EA`, `0xB6EB`, `0xB6EC` (one per LSM).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HawkResource {
    /// The resource name, e.g. `"GroupAddressTableLoadControl"`.
    pub name: String,
    /// The `<Location>` `AddressSpace` (e.g. `"StandardMemory"`, `"SystemProperty"`,
    /// `"Constant"`, `"None"`).
    pub address_space: Option<String>,
    /// The `<Location>` `StartAddress`, when the address space carries one.
    pub start_address: Option<u32>,
    /// The `<ResourceType>` `Length` in octets.
    pub length: Option<u32>,
    /// The `<ResourceType>` `Flavour`, e.g. `"LoadControl_M112"`.
    pub flavour: Option<String>,
}

/// The `HawkConfigurationData` resource records extracted for one mask.
///
/// Keyed by resource name. Parsed from a `.knxprod`'s `knx_master.xml`
/// (`[system7-spec §2.4]`); [`HawkConfig::resource`] looks one up by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HawkConfig {
    /// Resource name → its parsed record.
    pub resources: HashMap<String, HawkResource>,
    /// The block's `<Features>`: feature name → its `Value` attribute (e.g.
    /// `"VerifyMode"` → `"1"`, `"PropertyMappedLsms"` → `"0"`).
    pub features: HashMap<String, String>,
}

impl HawkConfig {
    /// The resource with the given name, if present.
    pub fn resource(&self, name: &str) -> Option<&HawkResource> {
        self.resources.get(name)
    }

    /// The `Value` of the named `<Feature>`, if the block declares it.
    pub fn feature(&self, name: &str) -> Option<&str> {
        self.features.get(name).map(String::as_str)
    }

    /// The `VerifyMode` feature as a number, or `None` when the mask declares
    /// none (MV-0701) or its value is not numeric. MV-0705 declares `1`.
    pub fn verify_mode(&self) -> Option<u8> {
        self.feature("VerifyMode")
            .and_then(|v| v.trim().parse().ok())
    }
}

/// The load-procedure templates extracted from a `knx_master.xml`, keyed by the
/// **`MV-`-stripped** mask id (e.g. `"07B0"`) to match
/// [`crate::ApplicationProgram::mask_version`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MasterTemplate {
    /// Mask id (`"07B0"`) → the mask's `Load` procedure templates, in document
    /// order.
    pub masks: HashMap<String, Vec<MaskLoadProcedure>>,
    /// Mask id (`"0705"`) → its `HawkConfigurationData` resources, when the mask
    /// block carried one. Empty for masks without a Hawk block.
    pub hawk: HashMap<String, HawkConfig>,
}

impl MasterTemplate {
    /// The best full-download `Load` template for a mask, or `None` if the mask
    /// is absent or declares no usable template.
    ///
    /// Preference order matches what ETS drives for a first full download:
    /// `ProcedureSubType="all"` (unload + reload every object), then `"ap1"`
    /// (the application-plus-tables variant), then any other `Load` procedure
    /// that actually carries ops. `mask` is the `MV-`-stripped id (`"07B0"`).
    pub fn full_load_procedure(&self, mask: &str) -> Option<&MaskLoadProcedure> {
        let procs = self.masks.get(mask)?;
        let pick = |want: &str| {
            procs
                .iter()
                .find(|p| p.sub_type.as_deref() == Some(want) && !p.ops.is_empty())
        };
        pick("all")
            .or_else(|| pick("ap1"))
            .or_else(|| procs.iter().find(|p| !p.ops.is_empty()))
    }

    /// The parsed `HawkConfigurationData` for a mask, or `None` if the mask
    /// declared none. `mask` is the `MV-`-stripped id (`"0705"`).
    pub fn hawk_config(&self, mask: &str) -> Option<&HawkConfig> {
        self.hawk.get(mask)
    }
}

/// Parses a `knx_master.xml` document into its per-mask `Load` procedure
/// templates.
///
/// Streaming (the file reaches ~1 MB+ and lives in a much larger install), it
/// only materialises the `Load` procedures under each `<MaskVersion>`; all other
/// content is skipped. `context` names the source for error messages.
pub fn parse_master_template(xml: &[u8], context: &str) -> Result<MasterTemplate> {
    // Strip a leading UTF-8 BOM so the reader starts on `<`.
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut out = MasterTemplate::default();
    let mut attrs = Attrs::new();

    // The mask id (MV-stripped) currently being parsed, if inside a MaskVersion.
    let mut cur_mask: Option<String> = None;
    // The Load procedure currently being accumulated (reusing LoadProcedure as
    // the op sink for `push_load_op`), plus its sub-type. `None` unless inside a
    // `<Procedure ProcedureType="Load">`.
    let mut cur_proc: Option<LoadProcedure> = None;
    let mut cur_sub_type: Option<String> = None;

    // The `HawkConfigurationData` resource currently being accumulated, if inside
    // a `<Resource>` element within the current mask's Hawk block.
    let mut cur_resource: Option<HawkResource> = None;
    // Whether the reader is inside the current mask's `HawkConfigurationData`.
    let mut in_hawk = false;

    loop {
        let event = reader.read_event().map_err(|source| EtsError::Xml {
            context: context.to_string(),
            source,
        })?;
        match event {
            Event::Eof => break,
            Event::Start(e) => {
                let local = e.local_name();
                match local.as_ref() {
                    b"MaskVersion" => {
                        attrs.parse_into(&e, context)?;
                        cur_mask = get(&attrs, b"Id")
                            .map(|id| id.strip_prefix("MV-").unwrap_or(id).to_string());
                    }
                    b"Procedure" => {
                        attrs.parse_into(&e, context)?;
                        if cur_mask.is_some() && get(&attrs, b"ProcedureType") == Some("Load") {
                            cur_sub_type = get(&attrs, b"ProcedureSubType").map(str::to_string);
                            cur_proc = Some(LoadProcedure::default());
                        }
                    }
                    // An `LdCtrl*` with children (e.g. LdCtrlCompareProp) inside a
                    // Load procedure: parse the same way the application parser
                    // does, so the master's ops match the app's exactly.
                    name if name.starts_with(b"LdCtrl") && cur_proc.is_some() => {
                        attrs.parse_into(&e, context)?;
                        push_load_op(&mut cur_proc, &e, &attrs);
                    }
                    // A `HawkConfigurationData` `<Resource>` (has child <Location>
                    // / <ResourceType>): start accumulating it.
                    b"HawkConfigurationData" if cur_mask.is_some() => in_hawk = true,
                    b"Resource" if cur_mask.is_some() => {
                        attrs.parse_into(&e, context)?;
                        cur_resource = Some(HawkResource {
                            name: get(&attrs, b"Name").unwrap_or_default().to_string(),
                            ..HawkResource::default()
                        });
                    }
                    _ => {}
                }
            }
            Event::Empty(e) => {
                let local = e.local_name();
                match local.as_ref() {
                    name if name.starts_with(b"LdCtrl") && cur_proc.is_some() => {
                        attrs.parse_into(&e, context)?;
                        push_load_op(&mut cur_proc, &e, &attrs);
                    }
                    // `<Location .../>` and `<ResourceType .../>` fill the current
                    // resource (both are self-closing empty elements).
                    b"Location" if cur_resource.is_some() => {
                        attrs.parse_into(&e, context)?;
                        if let Some(r) = cur_resource.as_mut() {
                            r.address_space = get(&attrs, b"AddressSpace").map(str::to_string);
                            r.start_address =
                                get(&attrs, b"StartAddress").and_then(|s| s.trim().parse().ok());
                        }
                    }
                    // `<Feature Name=".." Value=".."/>` inside the Hawk block.
                    b"Feature" if in_hawk => {
                        attrs.parse_into(&e, context)?;
                        if let (Some(mask), Some(name)) = (cur_mask.clone(), get(&attrs, b"Name")) {
                            let value = get(&attrs, b"Value").unwrap_or_default().to_string();
                            out.hawk
                                .entry(mask)
                                .or_default()
                                .features
                                .insert(name.to_string(), value);
                        }
                    }
                    b"ResourceType" if cur_resource.is_some() => {
                        attrs.parse_into(&e, context)?;
                        if let Some(r) = cur_resource.as_mut() {
                            r.length = get(&attrs, b"Length").and_then(|s| s.trim().parse().ok());
                            r.flavour = get(&attrs, b"Flavour").map(str::to_string);
                        }
                    }
                    _ => {}
                }
            }
            Event::End(e) => match e.local_name().as_ref() {
                b"Procedure" => {
                    if let (Some(mask), Some(proc)) = (cur_mask.clone(), cur_proc.take()) {
                        out.masks.entry(mask).or_default().push(MaskLoadProcedure {
                            sub_type: cur_sub_type.take(),
                            ops: proc.ops,
                        });
                    }
                    cur_sub_type = None;
                }
                b"Resource" => {
                    if let (Some(mask), Some(resource)) = (cur_mask.clone(), cur_resource.take())
                        && !resource.name.is_empty()
                    {
                        out.hawk
                            .entry(mask)
                            .or_default()
                            .resources
                            .insert(resource.name.clone(), resource);
                    }
                }
                b"HawkConfigurationData" => in_hawk = false,
                b"MaskVersion" => {
                    cur_mask = None;
                    in_hawk = false;
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny master file with one 07B0 mask carrying an `all` Load procedure
    /// with two merge markers, plus an `ap1` variant and an unrelated mask.
    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <MasterData>
  <MaskVersions>
   <MaskVersion Id="MV-0705" Name="System 7">
    <Procedures>
     <Procedure ProcedureType="Load" ProcedureSubType="all">
      <LdCtrlConnect />
      <LdCtrlRestart />
     </Procedure>
    </Procedures>
   </MaskVersion>
   <MaskVersion Id="MV-07B0" Name="System B">
    <Procedures>
     <Procedure ProcedureType="Load" ProcedureSubType="ap1">
      <LdCtrlConnect />
      <LdCtrlLoad LsmIdx="4" />
      <LdCtrlMerge MergeId="2" />
      <LdCtrlRestart />
     </Procedure>
     <Procedure ProcedureType="Load" ProcedureSubType="all">
      <LdCtrlConnect />
      <LdCtrlUnload LsmIdx="4" />
      <LdCtrlLoad LsmIdx="4" />
      <LdCtrlMerge MergeId="2" />
      <LdCtrlLoad LsmIdx="3" />
      <LdCtrlRelSegment LsmIdx="3" Size="2" />
      <LdCtrlMerge MergeId="4" />
      <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="1048576" />
      <LdCtrlLoadCompleted LsmIdx="4" />
      <LdCtrlLoadCompleted LsmIdx="3" />
      <LdCtrlRestart />
     </Procedure>
     <Procedure ProcedureType="Unload" ProcedureSubType="all">
      <LdCtrlConnect />
      <LdCtrlUnload LsmIdx="4" />
     </Procedure>
    </Procedures>
   </MaskVersion>
  </MaskVersions>
 </MasterData>
</KNX>"#;

    #[test]
    fn test_parse_master_template_extracts_load_procedures()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let t = parse_master_template(SAMPLE.as_bytes(), "test")?;
        // Both masks present, keyed MV-stripped.
        assert!(t.masks.contains_key("0705"));
        assert!(t.masks.contains_key("07B0"));
        // 07B0 has two Load procedures (Unload is not captured).
        assert_eq!(t.masks["07B0"].len(), 2);
        // The full-download pick prefers `all` over `ap1`.
        let full = t.full_load_procedure("07B0").ok_or("an all procedure")?;
        assert_eq!(full.sub_type.as_deref(), Some("all"));
        Ok(())
    }

    #[test]
    fn test_parse_master_template_preserves_merge_markers()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let t = parse_master_template(SAMPLE.as_bytes(), "test")?;
        let full = t
            .full_load_procedure("07B0")
            .ok_or("t.full_load_procedure(\"07B0\") missing")?;
        let merge_ids: Vec<&str> = full
            .ops
            .iter()
            .filter_map(|op| match op {
                LoadOp::Merge { merge_id } => merge_id.as_deref(),
                _ => None,
            })
            .collect();
        assert_eq!(merge_ids, vec!["2", "4"]);
        Ok(())
    }

    #[test]
    fn test_full_load_procedure_falls_back_to_ap1()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A mask with only an `ap1` Load procedure still resolves.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <MaskVersion Id="MV-07B0">
          <Procedure ProcedureType="Load" ProcedureSubType="ap1">
           <LdCtrlConnect /><LdCtrlRestart />
          </Procedure>
         </MaskVersion></KNX>"#;
        let t = parse_master_template(xml.as_bytes(), "test")?;
        let full = t
            .full_load_procedure("07B0")
            .ok_or("t.full_load_procedure(\"07B0\") missing")?;
        assert_eq!(full.sub_type.as_deref(), Some("ap1"));
        Ok(())
    }

    #[test]
    fn test_absent_mask_has_no_template() -> Result<()> {
        let t = parse_master_template(SAMPLE.as_bytes(), "test")?;
        assert!(t.full_load_procedure("2705").is_none());
        Ok(())
    }

    /// A MV-0705 mask carrying a `HawkConfigurationData` block with the
    /// LoadControl/LoadStatus resources the real Jung 3361-1M declares.
    const HAWK_SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <MasterData><MaskVersions>
  <MaskVersion Id="MV-0705" Name="System 7">
   <HawkConfigurationData>
    <Features>
     <Feature Name="PropertyMappedLsms" Value="1" />
     <Feature Name="VerifyMode" Value="1" />
    </Features>
    <Resources>
     <Resource Name="ManagementStyle" Access="remote">
      <Location AddressSpace="Constant" StartAddress="2" />
      <ResourceType Length="1" />
     </Resource>
     <Resource Name="GroupAddressTableLoadControl" Access="remote">
      <Location AddressSpace="StandardMemory" StartAddress="260" />
      <ResourceType Length="12" Flavour="LoadControl_M112" />
     </Resource>
     <Resource Name="GroupAddressTableLoadStatus" Access="remote">
      <Location AddressSpace="StandardMemory" StartAddress="46826" />
      <ResourceType Length="1" Flavour="LoadControl_M112" />
     </Resource>
     <Resource Name="GroupAssociationTableLoadStatus" Access="remote">
      <Location AddressSpace="StandardMemory" StartAddress="46827" />
      <ResourceType Length="1" Flavour="LoadControl_M112" />
     </Resource>
    </Resources>
   </HawkConfigurationData>
  </MaskVersion>
 </MaskVersions></MasterData>
</KNX>"#;

    #[test]
    fn test_parse_hawk_configuration_data_for_system7()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let t = parse_master_template(HAWK_SAMPLE.as_bytes(), "test")?;
        let hawk = t.hawk_config("0705").ok_or("a Hawk config for 0705")?;

        // The LoadControl is the 12-octet record at StandardMemory 260 = 0x0104,
        // Flavour LoadControl_M112 — the memory-mapped LSM control the spec §5
        // default names.
        let ctrl = hawk
            .resource("GroupAddressTableLoadControl")
            .ok_or("a LoadControl resource")?;
        assert_eq!(ctrl.address_space.as_deref(), Some("StandardMemory"));
        assert_eq!(ctrl.start_address, Some(260)); // 0x0104
        assert_eq!(ctrl.length, Some(12));
        assert_eq!(ctrl.flavour.as_deref(), Some("LoadControl_M112"));

        // The per-table load-status bytes sit at 0xB6EA, 0xB6EB (one per LSM).
        assert_eq!(
            hawk.resource("GroupAddressTableLoadStatus")
                .and_then(|r| r.start_address),
            Some(46826) // 0xB6EA
        );
        assert_eq!(
            hawk.resource("GroupAssociationTableLoadStatus")
                .and_then(|r| r.start_address),
            Some(46827) // 0xB6EB
        );
        // The <Features> block: VerifyMode=1 selects the blind write (#133).
        assert_eq!(hawk.feature("PropertyMappedLsms"), Some("1"));
        assert_eq!(hawk.verify_mode(), Some(1));
        Ok(())
    }

    #[test]
    fn test_mask_without_hawk_block_has_no_config() -> Result<()> {
        let t = parse_master_template(SAMPLE.as_bytes(), "test")?;
        // The SAMPLE masks declare no HawkConfigurationData.
        assert!(t.hawk_config("0705").is_none());
        assert!(t.hawk_config("07B0").is_none());
        Ok(())
    }
}
