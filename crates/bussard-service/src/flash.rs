//! The image a full application download writes, built once for both entry
//! points (issue #303): `bussard flash` and the MCP tier's
//! `knx_apply_device` when its plan says `method: flash`.
//!
//! Both build the plan with [`FlashInputs`] from the same inputs (the
//! product data the lock pins, the model's parameter values, links and
//! module bases for the device, the mask the device reports, the
//! factory-freshness verdict of the read-only probe and the Data Secure
//! material), shape it with [`FlashInputs::finish`] and choose the download
//! options with [`flash_options`]. The plan is then run by
//! [`crate::download::flash_session`]. What the device receives is therefore
//! the same octets in the same order from both, which keeps the offline
//! oracle (`scripts/campaign/95-offline-oracle.sh`) covering the MCP flash.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bussard_download::{
    FlashOptions, FlashPlan, Freshness, PlanError, ResidentState, SecureSenderEntry,
    SecurityPlanError,
};
use bussard_model::{Flags, IndividualAddress, Model};
use bussard_prod::application::LoadOp;
use bussard_prod::{ApplicationProgram, ProductData};

use crate::secure::SecureMaterial;

/// How long a device is offline while a full download restarts it, in
/// seconds, as a range: the campaign rows of the reference installation
/// measured 30 to 50 s from the first unload to the verified restart.
pub const DEVICE_OFFLINE_SECONDS: (u32, u32) = (30, 50);

/// Everything a full download of `app` into one device is planned from that
/// does not depend on the device: the model's parameter values and module
/// bases, the master-template load procedure, the table images computed
/// from the model's links, and the flags of the linked objects.
pub struct FlashInputs<'a> {
    /// The application program to download.
    app: &'a ApplicationProgram,
    /// The device as named in a plan error (the CLI keeps the operator's
    /// spelling).
    device: String,
    /// The parameter overrides, keyed by app-relative `ParameterRef` id.
    overrides: BTreeMap<String, String>,
    /// The module-instance base offsets the importer recorded.
    base_offsets: BTreeMap<String, u32>,
    /// The master-template `Load` procedure for the app's mask, if any.
    template_ops: Option<Vec<LoadOp>>,
    /// The computed table images (obj1 address, obj2 association, obj3
    /// group objects), keyed by object index.
    table_images: BTreeMap<u32, Vec<u8>>,
    /// The project flags of the linked objects.
    object_flags: BTreeMap<u16, Flags>,
    /// The device file's `[knxnet]` table: the KNXnet/IP parameters a full
    /// download into a device with a KNX IP interface built in writes (issue
    /// #455).
    knxnet: Option<bussard_model::knxnet::KnxnetConfig>,
    /// The device being downloaded into.
    target: IndividualAddress,
}

impl<'a> FlashInputs<'a> {
    /// The inputs for downloading `app` (from `product`) into `target`, from
    /// the model. `device` names the device in a plan error. The second
    /// half lists one warning per malformed parameter key, which is skipped.
    pub fn from_model(
        product: &ProductData,
        app: &'a ApplicationProgram,
        device: &str,
        model: Option<&Model>,
        target: IndividualAddress,
    ) -> (FlashInputs<'a>, Vec<String>) {
        let (overrides, malformed) = bussard_download::parameter_overrides(model, target);
        let base_offsets = model
            .and_then(|m| m.devices.get(&target))
            .map(|d| d.device.module_bases.clone())
            .unwrap_or_default();
        let template_ops = bussard_download::template_ops_for(product, app);
        let table_images = bussard_download::build_table_images(model, target, app, &overrides);
        let object_flags = bussard_download::linked_object_flags(model, target);
        let knxnet = model
            .and_then(|m| m.devices.get(&target))
            .and_then(|d| d.device.knxnet.clone());
        (
            FlashInputs {
                app,
                device: device.to_string(),
                overrides,
                base_offsets,
                template_ops,
                table_images,
                object_flags,
                knxnet,
                target,
            },
            malformed,
        )
    }

    /// The application program.
    pub fn app(&self) -> &'a ApplicationProgram {
        self.app
    }

    /// The parameter overrides, keyed by app-relative `ParameterRef` id.
    pub fn overrides(&self) -> &BTreeMap<String, String> {
        &self.overrides
    }

    /// The module-instance base offsets.
    pub fn base_offsets(&self) -> &BTreeMap<String, u32> {
        &self.base_offsets
    }

    /// The computed table images, keyed by object index (1 address, 2
    /// association, 3 group objects); empty for an application whose own
    /// load procedure carries no table objects.
    pub fn table_images(&self) -> &BTreeMap<u32, Vec<u8>> {
        &self.table_images
    }

    /// The mask the application declares, which is what a matching device
    /// reports. `None` when it declares no usable one.
    pub fn declared_mask(&self) -> Option<u16> {
        self.app
            .mask_version
            .as_deref()
            .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
    }

    /// The pre-flight plan against `mask`: the System B gate, the mask
    /// match and the unsupported-op refusal all happen here. A device with a
    /// KNX IP interface built in also gets its KNXnet/IP parameter writes
    /// from the `[knxnet]` table (issue #455).
    ///
    /// # Errors
    ///
    /// The plan is refused (another mask, an unsupported device or op, a
    /// KNXnet/IP parameter without a value in `[knxnet]`).
    pub fn plan(&self, mask: u16) -> Result<FlashPlan, PlanError> {
        let mut plan = bussard_download::plan_flash_with_object_flags(
            self.app,
            &self.device,
            mask,
            &self.overrides,
            &self.base_offsets,
            self.template_ops.as_deref(),
            &self.table_images,
            &self.object_flags,
        )?;
        // A property-only procedure (an IP interface, issue #390) writes the
        // object itself; `apply` keeps its `[knxnet]` table (issue #391).
        if !plan.is_property_only()
            && let Some(program) = bussard_download::knxnet_ip_program(
                self.app,
                mask,
                self.target,
                self.knxnet.as_ref(),
            )
            .map_err(PlanError::KnxnetIpUnsourced)?
        {
            plan.add_knxnet_ip(program);
        }
        Ok(plan)
    }

    /// Shapes a pre-flight plan into what is downloaded: the factory reset
    /// or the `par` load procedure the freshness verdict asks for
    /// ([`apply_freshness`], `resident` is the probe's state), then the Data
    /// Secure security object ([`FlashInputs::add_security_steps`]). Returns
    /// the security individual address table the download writes, when it
    /// writes one, so a verified flash can record it in the lock.
    ///
    /// # Errors
    ///
    /// The security program cannot be built (a group key is missing).
    #[allow(clippy::too_many_arguments)] // the shaping inputs, passed through 1:1
    pub fn finish(
        &self,
        plan: &mut FlashPlan,
        freshness: Option<&Freshness>,
        resident: Option<&ResidentState>,
        no_factory_reset: bool,
        model: Option<&Model>,
        target: IndividualAddress,
        material: &SecureMaterial,
        extra_senders: &[IndividualAddress],
    ) -> Result<Option<Vec<SecureSenderEntry>>, SecurityPlanError> {
        apply_freshness(plan, freshness, resident, no_factory_reset);
        self.add_security_steps(plan, model, target, material, extra_senders)
    }

    /// Adds the KNX Data Secure security-object steps to a full flash over a
    /// secured connection (issue #156): the group key table from the
    /// keyring's keys for the GAs in the address table this flash writes, the
    /// group-object security flags sized to the group-object table it
    /// writes, and the security individual address table entries of the
    /// secured senders it receives from (issue #181; `extra_senders` adds
    /// `--secure-sender` and the tunnelling addresses `admit_tunnel_senders`
    /// admits, issue #297). A plain flash (no tool key) is left untouched.
    ///
    /// # Errors
    ///
    /// The security program cannot be built.
    pub fn add_security_steps(
        &self,
        plan: &mut FlashPlan,
        model: Option<&Model>,
        target: IndividualAddress,
        material: &SecureMaterial,
        extra_senders: &[IndividualAddress],
    ) -> Result<Option<Vec<SecureSenderEntry>>, SecurityPlanError> {
        if material.tool_key.is_none() || plan.is_sys7() || plan.has_security_program() {
            return Ok(None);
        }
        let empty = HashMap::new();
        let group_keys = material.group_keys.as_ref().unwrap_or(&empty);
        let links: &[bussard_model::schema::Link] = model
            .and_then(|m| m.links.links.get(&target))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let addresses = bussard_download::compute_tables(links).addresses;
        // The group-object count is the count word of the obj3 image this
        // flash writes (1333 for the 1.1.12 reference download, matching
        // ETS's PID 61 element count); without one, the highest group object
        // the model knows.
        let go_count = self
            .table_images
            .get(&3)
            .and_then(|img| img.get(..2))
            .map(|w| u16::from_be_bytes([w[0], w[1]]))
            .or_else(|| {
                model
                    .and_then(|m| m.devices.get(&target))
                    .and_then(|d| d.device.com_objects.keys().max().copied())
            })
            .unwrap_or(0);
        let view = bussard_download::device_security_view(model, target, group_keys);
        let mut program = bussard_download::build_security_program(
            target,
            &addresses,
            go_count,
            &view.secure_objects,
            &view.secure_gas,
            group_keys,
        )?;
        program.senders = bussard_download::secured_senders(
            model,
            target,
            group_keys,
            &material.device_sequences,
            extra_senders,
        );
        // The table capacities the product declares (issue #537): a program
        // that does not fit is refused here, at plan time; the executor reads
        // the ones the product leaves out from the device before any step.
        let capacity = bussard_download::TableCapacity::from_product(&self.app.security_capacity);
        capacity.check(target, &program)?;
        let senders = program.senders.clone();
        plan.add_security_program(program);
        plan.set_security_capacity(capacity);
        Ok(Some(senders))
    }

    /// The com-objects the device shows with `values` (keyed like the
    /// overrides), as the application's Dynamic section yields them.
    pub fn visible_objects(&self, values: &BTreeMap<String, String>) -> BTreeSet<u16> {
        visible_objects(self.app, values)
    }
}

/// The com-objects `app` shows with the parameter `values` (keyed by
/// app-relative `ParameterRef` id).
pub fn visible_objects(
    app: &ApplicationProgram,
    values: &BTreeMap<String, String>,
) -> BTreeSet<u16> {
    let config = bussard_prod::dynamic::evaluate_dynamic(app, values);
    bussard_download::dynamic_group_object_descriptors(app, &config, &BTreeMap::new())
        .iter()
        .map(|d| d.asap)
        .collect()
}

/// The text and DPT of com-object `number` in `app`: the reference's words
/// when it has them, else the object's.
pub fn com_object_words(app: &ApplicationProgram, number: u16) -> (Option<String>, Option<String>) {
    let mut found: Vec<_> = app
        .com_objects
        .values()
        .filter(|o| o.number == number)
        .collect();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    let Some(object) = found.first() else {
        return (None, None);
    };
    let mut refs: Vec<_> = app
        .com_object_refs
        .values()
        .filter(|r| r.ref_id == object.id)
        .collect();
    refs.sort_by(|a, b| a.id.cmp(&b.id));
    let reference = refs.first();
    let text = reference
        .and_then(|r| r.text.clone())
        .or_else(|| object.text.clone())
        .or_else(|| object.name.clone());
    let dpt = reference
        .and_then(|r| r.dpt.as_ref())
        .or(object.dpt.as_ref())
        .map(ToString::to_string);
    (text, dpt)
}

/// The factory reset of a full download (issues #79, #117): a device that
/// carries another application, or whose state could not be read, is reset
/// before the download, on top of the reset the planner adds for a sparse,
/// filled-segment download. `freshness` is `None` offline (a dry run), where
/// only the planner's own reset shows. `no_factory_reset` waives it.
///
/// A System 7 device whose every load-state machine the probe read answers
/// `Unloaded` gets no pre-download unload-and-restart pass, as ETS gives none
/// to a factory-fresh device (issue #488, [`FlashPlan::fit_sys7_prelude`]);
/// without a probed state, a [`Freshness::Fresh`] verdict does the same. A
/// device with an LSM Loaded or Loading, or a resident application id, keeps
/// it; offline without a recorded state the plan keeps it too.
///
/// A System B device that already holds this application
/// ([`Freshness::SameApplication`]) gets the product's `AppliesTo="par"`
/// load procedure, as ETS runs it there (issue #490,
/// [`FlashPlan::use_par_procedure`]); `resident` is the probe's state, whose
/// object load states decide which unloads that procedure leaves out.
pub fn apply_freshness(
    plan: &mut FlashPlan,
    freshness: Option<&Freshness>,
    resident: Option<&ResidentState>,
    no_factory_reset: bool,
) {
    if matches!(
        freshness,
        Some(Freshness::Resident { .. } | Freshness::Unknown { .. })
    ) {
        plan.require_factory_reset();
    }
    // The System 7 pre-download pass follows the probed LSM states when there
    // are any (issue #488): a Loading LSM is `Fresh` to the gate but keeps the
    // pass. Without a probed state only the verdict can tell.
    match resident {
        Some(state) => plan.fit_sys7_prelude(state),
        None if matches!(freshness, Some(Freshness::Fresh)) => plan.skip_sys7_prelude(),
        None => {}
    }
    if matches!(freshness, Some(Freshness::SameApplication { .. })) {
        plan.use_par_procedure(resident);
    }
    if no_factory_reset {
        plan.skip_factory_reset();
    }
}

/// Whether the download skips an object whose resident image already
/// matches (the ETS group-B differential download): only when the device
/// carries no application or the same one, never with `full`, and never
/// after a factory reset (which leaves nothing resident to match).
pub fn skip_unchanged(full: bool, plan: &FlashPlan, freshness: &Freshness) -> bool {
    !full
        && !plan.has_factory_reset()
        && matches!(
            freshness,
            Freshness::Fresh | Freshness::SameApplication { .. }
        )
}

/// The download options of a full flash: the BCU key (free access when
/// `None`), the verification after the terminal restart, and the
/// differential download of [`skip_unchanged`].
pub fn flash_options(
    bcu_key: Option<u32>,
    full: bool,
    plan: &FlashPlan,
    freshness: &Freshness,
) -> FlashOptions {
    FlashOptions {
        bcu_key,
        verify_after_restart: true,
        skip_matching_mcb: skip_unchanged(full, plan, freshness),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small System B application (bussard's own work, no vendor data):
    /// a code segment and a two-octet parameter segment whose bit 1.0
    /// shows com-object 2.
    const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData>
    <Manufacturer RefId="M-00FA">
      <ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0002" ApplicationNumber="2" ApplicationVersion="1"
            MaskVersion="MV-07B0" Name="bussard flash test app" LoadProcedureStyle="ProductDefault">
          <Static>
            <Code>
              <RelativeSegment Id="M-00FA_A-0002_RS-1" Size="6" LoadStateMachine="4" Offset="0"><Data>AAECAwQF</Data></RelativeSegment>
              <RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data></RelativeSegment>
            </Code>
            <ParameterTypes>
              <ParameterType Id="M-00FA_A-0002_PT-0" Name="n"><TypeNumber SizeInBit="8" Type="unsignedInt" maxInclusive="255" /></ParameterType>
              <ParameterType Id="M-00FA_A-0002_PT-1" Name="onoff"><TypeRestriction Base="Value" SizeInBit="1">
                <Enumeration Text="Off" Value="0" /><Enumeration Text="On" Value="1" />
              </TypeRestriction></ParameterType>
            </ParameterTypes>
            <Parameters>
              <Parameter Id="M-00FA_A-0002_P-0" Name="thr" Text="Threshold" ParameterType="M-00FA_A-0002_PT-0" Value="7"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="0" BitOffset="0" /></Parameter>
              <Parameter Id="M-00FA_A-0002_P-1" Name="obj2" Text="Object 2" ParameterType="M-00FA_A-0002_PT-1" Value="0"><Memory CodeSegment="M-00FA_A-0002_RS-2" Offset="1" BitOffset="0" /></Parameter>
            </Parameters>
            <ParameterRefs>
              <ParameterRef Id="M-00FA_A-0002_P-0_R-1" RefId="M-00FA_A-0002_P-0" />
              <ParameterRef Id="M-00FA_A-0002_P-1_R-2" RefId="M-00FA_A-0002_P-1" />
            </ParameterRefs>
            <ComObjects>
              <ComObject Id="M-00FA_A-0002_O-1" Number="1" ObjectSize="1 Bit" CommunicationFlag="Enabled" WriteFlag="Enabled" />
              <ComObject Id="M-00FA_A-0002_O-2" Number="2" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
            </ComObjects>
            <ComObjectRefs>
              <ComObjectRef Id="M-00FA_A-0002_O-1_R-1" RefId="M-00FA_A-0002_O-1" />
              <ComObjectRef Id="M-00FA_A-0002_O-2_R-2" RefId="M-00FA_A-0002_O-2" />
            </ComObjectRefs>
            <LoadProcedures>
              <LoadProcedure>
                <LdCtrlConnect />
                <LdCtrlUnload LsmIdx="4" />
                <LdCtrlLoad LsmIdx="4" />
                <LdCtrlRelSegment LsmIdx="4" Size="6" AppliesTo="full" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="6" AppliesTo="full" />
                <LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="par" />
                <LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="par" />
                <LdCtrlLoadCompleted LsmIdx="4" />
                <LdCtrlRestart />
                <LdCtrlDisconnect />
              </LoadProcedure>
            </LoadProcedures>
          </Static>
          <Dynamic>
            <ChannelIndependentBlock>
              <ParameterBlock Id="M-00FA_A-0002_PB-1" Name="main">
                <ParameterRefRef RefId="M-00FA_A-0002_P-0_R-1" />
                <ParameterRefRef RefId="M-00FA_A-0002_P-1_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-0002_O-1_R-1" />
                <choose ParamRefId="M-00FA_A-0002_P-1_R-2">
                  <when test="1"><ComObjectRefRef RefId="M-00FA_A-0002_O-2_R-2" /></when>
                </choose>
              </ParameterBlock>
            </ChannelIndependentBlock>
          </Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms>
    </Manufacturer>
  </ManufacturerData>
</KNX>
"#;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The fixture device's model: 1.1.4 runs the app, with object 2 shown
    /// and a threshold of 9, and one link.
    fn fixture(tag: &str) -> Result<(std::path::PathBuf, Model), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "bussard-service-flash-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("devices"))?;
        std::fs::write(
            dir.join("devices").join("1.1.4.toml"),
            "address = \"1.1.4\"\nname = \"Flash test\"\n\n[parameters]\n\
             \"thr@P-0_R-1\" = \"9\"\n\"obj2@P-1_R-2\" = \"1\"\n\n[links]\n\
             1.listen = [\"1/2/0\"]\n2.send = \"1/2/1\"\n",
        )?;
        let model = Model::load(&dir)?;
        Ok((dir, model))
    }

    fn product() -> Result<ProductData, Box<dyn std::error::Error>> {
        let app = bussard_prod::parse_application_program("M-00FA_A-0002", APP_XML.as_bytes())?;
        Ok(ProductData {
            applications: vec![app],
            ..ProductData::default()
        })
    }

    /// The image `bussard flash` built before issue #303 moved its shaping
    /// here, from the planner's own primitives.
    fn primitive_plan(
        product: &ProductData,
        app: &ApplicationProgram,
        model: &Model,
        target: IndividualAddress,
        freshness: &Freshness,
    ) -> Result<FlashPlan, Box<dyn std::error::Error>> {
        let (overrides, _) = bussard_download::parameter_overrides(Some(model), target);
        let bases = model
            .devices
            .get(&target)
            .map(|d| d.device.module_bases.clone())
            .unwrap_or_default();
        let template = bussard_download::template_ops_for(product, app);
        let images = bussard_download::build_table_images(Some(model), target, app, &overrides);
        let flags = bussard_download::linked_object_flags(Some(model), target);
        let mut plan = bussard_download::plan_flash_with_object_flags(
            app,
            &target.to_string(),
            0x07B0,
            &overrides,
            &bases,
            template.as_deref(),
            &images,
            &flags,
        )?;
        if matches!(
            freshness,
            Freshness::Resident { .. } | Freshness::Unknown { .. }
        ) {
            plan.require_factory_reset();
        }
        if matches!(freshness, Freshness::SameApplication { .. }) {
            plan.use_par_procedure(None);
        }
        Ok(plan)
    }

    #[test]
    fn test_flash_inputs_cli_and_mcp_build_the_same_image() -> TestResult {
        let (dir, model) = fixture("same-image")?;
        let product = product()?;
        let app = product
            .applications
            .first()
            .ok_or("the fixture product has no application")?;
        let target: IndividualAddress = "1.1.4".parse()?;
        let plain = SecureMaterial::default();
        for freshness in [
            Freshness::Fresh,
            Freshness::SameApplication {
                resident: "00FA000201".to_string(),
            },
            Freshness::Unknown {
                reason: "unreadable".to_string(),
            },
        ] {
            // `bussard flash`: the operator's spelling names the device, the
            // pre-flight plan is built for the declared mask, then shaped.
            let (cli_inputs, _) =
                FlashInputs::from_model(&product, app, "1.1.4", Some(&model), target);
            let mask = cli_inputs.declared_mask().ok_or("no declared mask")?;
            let mut cli = cli_inputs.plan(mask)?;
            cli_inputs.finish(
                &mut cli,
                Some(&freshness),
                None,
                false,
                Some(&model),
                target,
                &plain,
                &[],
            )?;
            // `knx_apply_device` with `method: flash`: the reported mask.
            let (mcp_inputs, _) =
                FlashInputs::from_model(&product, app, &target.to_string(), Some(&model), target);
            let mut mcp = mcp_inputs.plan(0x07B0)?;
            mcp_inputs.finish(
                &mut mcp,
                Some(&freshness),
                None,
                false,
                Some(&model),
                target,
                &plain,
                &[],
            )?;
            let primitive = primitive_plan(&product, app, &model, target, &freshness)?;
            assert_eq!(format!("{cli:?}"), format!("{mcp:?}"), "{freshness:?}");
            assert_eq!(
                format!("{cli:?}"),
                format!("{primitive:?}"),
                "{freshness:?}"
            );
            // The model's parameter values are in the image: threshold 9,
            // object 2 on (bit offset 0 is the octet's most significant bit).
            let params = cli
                .param_images
                .values()
                .next()
                .ok_or("no parameter image")?;
            assert_eq!(params.as_slice(), [9, 0x80], "{params:?}");
            assert_eq!(
                flash_options(None, false, &cli, &freshness).skip_matching_mcb,
                skip_unchanged(false, &mcp, &freshness)
            );
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_apply_freshness_resets_another_application_unless_waived() -> TestResult {
        let (dir, model) = fixture("freshness")?;
        let product = product()?;
        let plain_app = product.applications.first().ok_or("no application")?;
        let target: IndividualAddress = "1.1.4".parse()?;
        let resident = Freshness::Resident {
            resident: Some("0001000101".to_string()),
            objects: Vec::new(),
            reason: None,
        };
        // Issue #452: an application that is not secure-capable is never
        // sent a master reset, another application resident or not.
        let (plain, _) =
            FlashInputs::from_model(&product, plain_app, "1.1.4", Some(&model), target);
        let mut plain_plan = plain.plan(0x07B0)?;
        apply_freshness(&mut plain_plan, Some(&resident), None, false);
        assert!(!plain_plan.has_factory_reset());
        let mut secure_app = plain_app.clone();
        secure_app.is_secure_enabled = true;
        let app = &secure_app;
        let (inputs, _) = FlashInputs::from_model(&product, app, "1.1.4", Some(&model), target);
        let mut plan = inputs.plan(0x07B0)?;
        apply_freshness(&mut plan, Some(&resident), None, false);
        assert!(plan.has_factory_reset());
        assert!(!skip_unchanged(false, &plan, &resident));
        let mut waived = inputs.plan(0x07B0)?;
        apply_freshness(&mut waived, Some(&resident), None, true);
        assert!(!waived.has_factory_reset());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn test_visible_objects_follows_the_dynamic_section() -> TestResult {
        let product = product()?;
        let app = product.applications.first().ok_or("no application")?;
        let off = BTreeMap::from([("P-1_R-2".to_string(), "0".to_string())]);
        let on = BTreeMap::from([("P-1_R-2".to_string(), "1".to_string())]);
        assert_eq!(visible_objects(app, &off), BTreeSet::from([1]));
        assert_eq!(visible_objects(app, &on), BTreeSet::from([1, 2]));
        Ok(())
    }

    /// Issue #455: an application with tunnelling addresses gets the
    /// KNXnet/IP parameter writes from `[knxnet]`, read back by type 11; a
    /// device file without the table is refused at plan time.
    #[test]
    fn test_flash_inputs_plan_writes_knxnet_ip_from_the_device_file() -> TestResult {
        let (dir, model) = fixture("knxnet-ip")?;
        let mut product = product()?;
        let app = product
            .applications
            .first_mut()
            .ok_or("the fixture product has no application")?;
        app.additional_addresses_count = Some(2);
        let app = product.applications[0].clone();
        let target: IndividualAddress = "1.1.4".parse()?;
        let (inputs, _) = FlashInputs::from_model(&product, &app, "1.1.4", Some(&model), target);
        let refused = inputs.plan(0x07B0).err().ok_or("no [knxnet] table")?;
        assert!(
            matches!(&refused, PlanError::KnxnetIpUnsourced(why) if why.contains("[knxnet]")),
            "{refused}"
        );
        let file = dir.join("devices").join("1.1.4.toml");
        let mut toml = std::fs::read_to_string(&file)?;
        toml.push_str(
            "\n[knxnet]\nassignment = \"dhcp\"\nfriendly_name = \"Flash test\"\n\
             tunnels = [\"1.1.250\", \"1.1.251\"]\n",
        );
        std::fs::write(&file, toml)?;
        let model = Model::load(&dir)?;
        let (inputs, _) = FlashInputs::from_model(&product, &app, "1.1.4", Some(&model), target);
        let plan = inputs.plan(0x07B0)?;
        let program = plan
            .knxnet_ip()
            .ok_or("the plan writes the KNXnet/IP object")?;
        assert_eq!(program.object, bussard_download::PropObject::Index(6));
        let expected = crate::verify::ExpectedProperty::from_flash_plan(&plan);
        assert_eq!(expected.len(), program.writes.len());
        assert!(expected.iter().all(|e| e.object
            == bussard_download::PropObject::Type {
                object_type: 11,
                occurrence: 0
            }));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Issue #488: a System 7 device with no loaded application gets no
    /// pre-download pass (ETS gives none to a factory-fresh device); one with
    /// an application, an unreadable one and the offline plan keep it.
    #[test]
    fn test_apply_freshness_drops_the_sys7_prelude_on_a_fresh_device() -> TestResult {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
         <ApplicationProgram PeiType="0" Id="M-0083_A-E" ApplicationNumber="14" ApplicationVersion="35"
            MaskVersion="MV-0705" Name="MDT S7" LoadProcedureStyle="ProductProcedure">
          <Static>
           <Code>
            <AbsoluteSegment Id="M-0083_A-E_AS-4" Size="2" Address="17408"><Data>BAU=</Data></AbsoluteSegment>
           </Code>
           <LoadProcedures>
            <LoadProcedure>
             <LdCtrlUnload LsmIdx="3" />
             <LdCtrlLoad LsmIdx="3" />
             <LdCtrlAbsSegment LsmIdx="3" Address="17408" Size="2" />
             <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
             <LdCtrlLoadCompleted LsmIdx="3" />
             <LdCtrlRestart />
            </LoadProcedure>
           </LoadProcedures>
          </Static>
         </ApplicationProgram></KNX>"#;
        let app = bussard_prod::parse_application_program("M-0083_A-E", xml.as_bytes())?;
        let planned = bussard_download::plan_flash(
            &app,
            "1.1.99",
            0x0705,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &BTreeMap::new(),
        )?;
        let prelude = |plan: &FlashPlan| {
            plan.steps.iter().any(|s| {
                matches!(
                    s,
                    bussard_download::FlashStep::Sys7PreDownloadRestart { .. }
                )
            })
        };
        assert!(prelude(&planned));
        let resident = Freshness::Resident {
            resident: None,
            objects: vec!["LSM 3".to_string()],
            reason: None,
        };
        let unknown = Freshness::Unknown {
            reason: "unreadable".to_string(),
        };
        for (freshness, kept) in [
            (Some(&Freshness::Fresh), false),
            (Some(&resident), true),
            (Some(&unknown), true),
            (None, true),
        ] {
            let mut plan = planned.clone();
            apply_freshness(&mut plan, freshness, None, true);
            assert_eq!(prelude(&plan), kept, "{freshness:?}");
        }
        Ok(())
    }
}
