//! The post-write read-back (issues #319, #349): every write command ends
//! with an independent read of what it wrote, compared with what the model
//! (or the plan) asked for. "Verified" means that read found nothing left,
//! never "the write sequence completed".
//!
//! One routine for every surface: `bussard apply`, `bussard flash` and the
//! MCP apply job (both its `apply` and its `flash` method) build an
//! [`Expected`] and call [`read_back`] (on the flash's own last connection)
//! or [`read_back_on`] (on a fresh session after an apply). What is
//! compared:
//!
//! - **Tables**: the address and association tables, read the way `plan`
//!   reads them and diffed the way `plan` diffs them (links present and
//!   absent), plus both table sizes. A full flash also compares the
//!   group-object table's element count with the count the planned image
//!   carries (System B; a System 7 image takes its group-object table from
//!   the product data).
//! - **Parameters**: the parameter memory decoded and compared with the
//!   model ([`crate::params::read_flashed_parameters`], the plan's decode).
//! - **Load-procedure properties** (issue #390): every property an
//!   `LdCtrlWriteProp` of a System 7 or property-only flash wrote, read back
//!   by the object and PID the plan addressed and compared with the value
//!   the plan wrote.
//! - **Security object** (KNX Data Secure, issue #331): the element count of
//!   the group key table (PID 53, whose keys are write-only), the security
//!   individual address table (PID 54) and the group-object security flags
//!   (PID 61), against the program the write sent, and the object's load
//!   state (PID 5, issue #534): anything but `Loaded` is a leftover, because
//!   the device then ignores those tables and drops every secured group
//!   telegram (KNX 3/5/1 §6.3.4, §6.3.7.4, §6.3.8.4; KNX 3/3/7 §5.5.2).
//!
//! What cannot be read (a device that refuses a property, an unsupported
//! mask) is a note, not a difference: a plan treats it as "not compared" too.
//! A session that cannot be opened at all is a leftover: nothing was read.
//!
//! Nothing here reads or prints key material: PID 53 is read for its element
//! count only, and every message names addresses and object numbers.

use std::collections::BTreeSet;

use bussard_download::{
    DesiredTables, FlashPlan, FlashStep, LiveRead, PropObject, SecurityInputs, build_table_images,
    parameter_overrides, plan,
};
use bussard_mgmt::load::LoadState;
use bussard_mgmt::property_ext::{
    PID_GRP_KEY_TABLE, PropertyExtAddress, read_property_ext_element_count, security_load_state,
};
use bussard_mgmt::tables::DeviceTables;
use bussard_mgmt::{ConnectionSeed, L4Channel, Layer4Connection};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_prod::{ApplicationProgram, ProductData};

use crate::bus::{BusService, L4Options};
use crate::params::FlashedParameters;

/// The parameter half of an [`Expected`]: what the memory is decoded with
/// and compared against.
#[derive(Clone, Copy)]
pub struct ExpectedParameters<'a> {
    /// The product data the device's application comes from.
    pub product: &'a ProductData,
    /// The application program the device runs.
    pub app: &'a ApplicationProgram,
    /// The model whose parameter values the device must hold.
    pub model: Option<&'a Model>,
    /// The device's mask version.
    pub device_mask: u16,
}

/// The security object a secured write programmed (issue #331): what its
/// read-back must find.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedSecurity {
    /// How many entries the group key table (PID 53) received.
    pub group_keys: u16,
    /// The individual addresses the security individual address table
    /// (PID 54) received, ascending.
    pub senders: Vec<IndividualAddress>,
    /// The group objects flagged secured in PID 61.
    pub secured_objects: BTreeSet<u16>,
}

impl ExpectedSecurity {
    /// The program an apply's table write sends with `inputs` next to the
    /// address table `addresses` (see
    /// [`bussard_download::program_security_object`]).
    pub fn from_inputs(inputs: &SecurityInputs, addresses: &[GroupAddress]) -> ExpectedSecurity {
        let mut senders: Vec<IndividualAddress> =
            inputs.senders.iter().map(|e| e.address).collect();
        senders.sort();
        senders.dedup();
        ExpectedSecurity {
            group_keys: u16::try_from(inputs.keyed(addresses).len()).unwrap_or(u16::MAX),
            senders,
            secured_objects: inputs.secure_objects.clone(),
        }
    }

    /// The program a full flash's security steps send, `None` when the
    /// flash writes no security object.
    pub fn from_flash_plan(flash: &FlashPlan) -> Option<ExpectedSecurity> {
        if !flash.has_security_program() {
            return None;
        }
        let mut expected = ExpectedSecurity::default();
        for step in &flash.steps {
            match step {
                FlashStep::SecuritySenders { entries } => {
                    expected.senders = entries.iter().map(|e| e.address).collect();
                }
                FlashStep::SecurityGroupKeys { entries } => {
                    expected.group_keys = u16::try_from(entries.len()).unwrap_or(u16::MAX);
                }
                FlashStep::SecurityGoFlags { flags } => {
                    expected.secured_objects = flags
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| **f != 0)
                        .filter_map(|(i, _)| u16::try_from(i + 1).ok())
                        .collect();
                }
                _ => {}
            }
        }
        expected.senders.sort();
        expected.senders.dedup();
        Some(expected)
    }
}

/// A property a load procedure wrote (issue #390): what its read-back must
/// find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedProperty {
    /// The interface object, as the plan addressed it.
    pub object: bussard_download::PropObject,
    /// The property id.
    pub prop_id: u32,
    /// The first element written.
    pub start: u16,
    /// How many elements were written.
    pub count: u16,
    /// The octets written.
    pub value: Vec<u8>,
}

impl ExpectedProperty {
    /// The property writes of `flash` a read-back compares: those of a System
    /// 7 or property-only plan, and the KNXnet/IP parameters of any plan. A
    /// System B plan's program-version writes keep the read-back they had
    /// before issue #390 (none).
    pub fn from_flash_plan(flash: &FlashPlan) -> Vec<ExpectedProperty> {
        // The KNXnet/IP parameters of a device with a KNX IP interface built
        // in (issue #455), on every plan: read back by object type 11, which
        // finds the object whatever index the executor wrote it at.
        let knxnet = flash.knxnet_ip().into_iter().flat_map(|program| {
            program.writes.iter().map(|w| ExpectedProperty {
                object: PropObject::Type {
                    object_type: bussard_mgmt::knxnet::OT_KNXNET_IP_PARAMETER,
                    occurrence: 0,
                },
                prop_id: u32::from(w.prop_id),
                start: w.start,
                count: w.count.max(1),
                value: w.value.clone(),
            })
        });
        if !flash.is_sys7() && !flash.is_property_only() {
            return knxnet.collect();
        }
        let knxnet: Vec<ExpectedProperty> = knxnet.collect();
        flash
            .steps
            .iter()
            .filter_map(|step| match step {
                FlashStep::WriteProp {
                    object,
                    prop_id,
                    value,
                    start_element,
                    count,
                    ..
                } => Some(ExpectedProperty {
                    object: *object,
                    prop_id: *prop_id,
                    start: *start_element,
                    count: (*count).max(1),
                    value: value.clone(),
                }),
                _ => None,
            })
            .chain(knxnet)
            .collect()
    }

    /// `object type 11 PID 205`.
    fn name(&self) -> String {
        format!("{} PID {}", self.object, self.prop_id)
    }
}

/// What a write meant to leave on the device. A `None` field is not
/// compared.
#[derive(Clone, Default)]
pub struct Expected<'a> {
    /// The address and association tables.
    pub tables: Option<DesiredTables>,
    /// The group-object table's element count.
    pub group_objects: Option<u16>,
    /// The System B group-object table image an `apply` reloaded (issue
    /// #540): its count and every descriptor are compared.
    pub object_table: Option<Vec<u8>>,
    /// The parameter values.
    pub parameters: Option<ExpectedParameters<'a>>,
    /// The security object.
    pub security: Option<ExpectedSecurity>,
    /// The properties the load procedure wrote (issue #390).
    pub properties: Vec<ExpectedProperty>,
    /// Where the product puts a System 7 device's tables, the reader's
    /// fallback when the device does not answer `PID_TABLE_REFERENCE`.
    pub table_bases: bussard_download::Sys7TableBases,
}

impl<'a> Expected<'a> {
    /// What a full flash of `app` with `flash` writes for `target`: the
    /// model's tables and group-object count when the download loads the
    /// table objects (a self-contained single-object download does not), the
    /// parameters, and the security object the plan programs.
    pub fn for_flash(
        flash: &FlashPlan,
        product: &'a ProductData,
        app: &'a ApplicationProgram,
        model: Option<&'a Model>,
        target: IndividualAddress,
        device_mask: u16,
    ) -> Expected<'a> {
        // Whether the download loads LSM `lsm` (1 address table, 2
        // association table, 3 group-object table on System B; LSM 1 holds
        // the address and group-object tables on System 7).
        let loads = |lsm: u32| {
            flash.steps.iter().any(|s| match s {
                FlashStep::StartLoading { target: Some(t) } => *t == lsm,
                FlashStep::Sys7StartLoading { lsm: l } => *l == lsm,
                _ => false,
            })
        };
        let (overrides, _) = parameter_overrides(model, target);
        let images = build_table_images(model, target, app, &overrides);
        let links: &[bussard_model::schema::Link] = model
            .and_then(|m| m.links.links.get(&target))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let tables = (images.contains_key(&1) && loads(1) && loads(2))
            .then(|| bussard_download::compute_tables(links));
        // The obj3 image's count word (System B); a System 7 download takes
        // its group-object table from the product's own image.
        let group_objects = if flash.is_sys7() || !loads(3) {
            None
        } else {
            images
                .get(&3)
                .and_then(|img| img.get(..2))
                .map(|w| u16::from_be_bytes([w[0], w[1]]))
        };
        Expected {
            tables,
            group_objects,
            object_table: None,
            parameters: Some(ExpectedParameters {
                product,
                app,
                model,
                device_mask,
            }),
            security: ExpectedSecurity::from_flash_plan(flash),
            properties: ExpectedProperty::from_flash_plan(flash),
            table_bases: bussard_download::sys7_table_bases(app),
        }
    }
}

/// What kind of item a [`Leftover`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeftoverKind {
    /// A link (com-object to group address) present or absent.
    Link,
    /// The group address table's size.
    AddressTable,
    /// The association table's size.
    AssociationTable,
    /// The group-object table's element count.
    GroupObjects,
    /// A System 7 group object's communication flag (C, in its CONFIG octet).
    CommunicationFlag,
    /// A System B group-object descriptor, or the table it sits in (issue
    /// #540).
    GroupObjectDescriptor,
    /// A parameter value.
    Parameter,
    /// The group key table's (PID 53) element count.
    GroupKeyTable,
    /// An entry of the security individual address table (PID 54).
    SecureSender,
    /// A group object's security flag (PID 61).
    SecurityFlag,
    /// The security object's load state (PID 5, issue #534).
    SecurityLoadState,
    /// A property a load procedure wrote (issue #390).
    Property,
    /// The read-back itself could not be made.
    Readback,
}

/// One item the read-back found differing from what the write meant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Leftover {
    /// What kind of item.
    pub kind: LeftoverKind,
    /// The item, in the model's words (`object 22 -> 1/2/3`, a parameter
    /// key, `group key table (PID 53)`).
    pub item: String,
    /// What the device holds.
    pub device: String,
    /// What the model (or the write's plan) asks for.
    pub model: String,
}

impl Leftover {
    /// The leftover in one line.
    pub fn sentence(&self) -> String {
        format!(
            "{}: the device holds {}, the model says {}",
            self.item, self.device, self.model
        )
    }
}

/// How many items of each kind the read-back compared. A `None` field was
/// not compared.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Compared {
    /// Group address table entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<usize>,
    /// Association table entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associations: Option<usize>,
    /// Group-object table entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_objects: Option<u16>,
    /// Parameter values decoded and compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<usize>,
    /// Group key table (PID 53) entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_keys: Option<u16>,
    /// Security individual address table (PID 54) entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_senders: Option<usize>,
    /// Group objects flagged secured (PID 61).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secured_objects: Option<usize>,
    /// The security object's load state as read (PID 5, issue #534).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_load_state: Option<String>,
    /// Properties a load procedure wrote (issue #390).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<usize>,
}

/// What the post-write read-back found.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WriteReadback {
    /// Whether the device holds what the write meant: the read-back ran and
    /// found no leftover.
    pub verified: bool,
    /// How much was compared.
    pub compared: Compared,
    /// What still differs, one item each.
    pub leftovers: Vec<Leftover>,
    /// What could not be compared, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The parameter comparison in full, when parameters were compared (the
    /// flash result's `parameters.differences`).
    #[serde(skip)]
    pub parameters: Option<FlashedParameters>,
}

/// How many leftovers a failure line spells out.
const FAILURE_ITEMS: usize = 12;

impl WriteReadback {
    /// A read-back that could not be made at all.
    pub fn unreadable(why: String) -> WriteReadback {
        WriteReadback {
            verified: false,
            leftovers: vec![Leftover {
                kind: LeftoverKind::Readback,
                item: "the read-back".to_string(),
                device: format!("no answer ({why})"),
                model: "a read of what was written".to_string(),
            }],
            ..WriteReadback::default()
        }
    }

    /// One line naming what still differs, `None` when verified.
    pub fn failure(&self) -> Option<String> {
        if self.leftovers.is_empty() {
            return None;
        }
        let mut items: Vec<String> = self
            .leftovers
            .iter()
            .take(FAILURE_ITEMS)
            .map(Leftover::sentence)
            .collect();
        if self.leftovers.len() > FAILURE_ITEMS {
            items.push(format!("and {} more", self.leftovers.len() - FAILURE_ITEMS));
        }
        Some(format!(
            "not verified: {} item(s) still differ from the model after the write: {}",
            self.leftovers.len(),
            items.join("; ")
        ))
    }

    /// What was compared, in one line (`2 group address(es), 2
    /// association(s), 14 parameter(s)`); `nothing` when nothing was.
    pub fn summary(&self) -> String {
        let c = &self.compared;
        let mut parts = Vec::new();
        if let Some(n) = c.addresses {
            parts.push(format!("{n} group address(es)"));
        }
        if let Some(n) = c.associations {
            parts.push(format!("{n} association(s)"));
        }
        if let Some(n) = c.group_objects {
            parts.push(format!("{n} group object(s)"));
        }
        if let Some(n) = c.parameters {
            parts.push(format!("{n} parameter(s)"));
        }
        if let Some(n) = c.group_keys {
            parts.push(format!("{n} group key(s) (PID 53)"));
        }
        if let Some(n) = c.secure_senders {
            parts.push(format!("{n} secure sender(s) (PID 54)"));
        }
        if let Some(n) = c.secured_objects {
            parts.push(format!("{n} secured object(s) (PID 61)"));
        }
        if let Some(state) = &c.security_load_state {
            parts.push(format!("security object {state} (PID 5)"));
        }
        if let Some(n) = c.properties {
            parts.push(format!("{n} load-procedure property value(s)"));
        }
        if parts.is_empty() {
            "nothing".to_string()
        } else {
            parts.join(", ")
        }
    }

    pub(crate) fn push(&mut self, kind: LeftoverKind, item: String, device: String, model: String) {
        self.leftovers.push(Leftover {
            kind,
            item,
            device,
            model,
        });
    }
}

/// An error and its sources, joined with `": "`.
fn chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut next = err.source();
    while let Some(cause) = next {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        next = cause.source();
    }
    out
}

/// `1 entry`, `3 entries`.
fn entries(n: usize) -> String {
    if n == 1 {
        "1 entry".to_string()
    } else {
        format!("{n} entries")
    }
}

/// Reads back what a write left on the device over the open, authorized
/// session `l4` and compares it with `expected` (see the module docs).
pub async fn read_back<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    expected: &Expected<'_>,
) -> WriteReadback {
    let mut out = WriteReadback::default();
    if expected.tables.is_some() || expected.group_objects.is_some() {
        match bussard_download::read_live_tables_at(l4, expected.table_bases).await {
            Ok(LiveRead::Tables(live)) => {
                compare_tables(&mut out, live.tables(), expected);
                if let (Some(s7), Some(desired)) = (live.sys7(), &expected.tables) {
                    compare_sys7_flags(&mut out, s7, desired);
                }
            }
            Ok(LiveRead::UnsupportedMask { mask, .. }) => out.notes.push(format!(
                "tables not compared: mask {mask:04X} has no table reader"
            )),
            Err(err) => out
                .notes
                .push(format!("tables not compared: {}", chain(&err))),
        }
    }
    if let Some(model) = &expected.object_table {
        compare_object_table(l4, &mut out, model).await;
    }
    if let Some(p) = &expected.parameters {
        let target = l4.target();
        let flashed = crate::params::read_flashed_parameters(
            l4,
            p.product,
            p.app,
            p.model,
            target,
            p.device_mask,
        )
        .await;
        compare_parameters(&mut out, &flashed);
        out.parameters = Some(flashed);
    }
    if let Some(security) = &expected.security {
        compare_security(l4, &mut out, security).await;
    }
    if !expected.properties.is_empty() {
        compare_properties(l4, &mut out, &expected.properties).await;
    }
    out.verified = out.leftovers.is_empty();
    out
}

/// Reads back every property a load procedure wrote and compares it with
/// the octets written; a property that cannot be read is a leftover too (the
/// write cannot be confirmed).
async fn compare_properties<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    out: &mut WriteReadback,
    expected: &[ExpectedProperty],
) {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    for prop in expected {
        let elem = (prop.value.len() / usize::from(prop.count.max(1))).max(1);
        match bussard_download::read_property_value(
            l4,
            prop.object,
            prop.prop_id,
            prop.start,
            prop.count,
            elem,
        )
        .await
        {
            Ok(held) if held == prop.value => {}
            Ok(held) => out.push(
                LeftoverKind::Property,
                prop.name(),
                hex(&held),
                hex(&prop.value),
            ),
            Err(err) => out.push(
                LeftoverKind::Property,
                prop.name(),
                format!("no answer ({})", chain(&err)),
                hex(&prop.value),
            ),
        }
    }
    out.compared.properties = Some(expected.len());
}

/// [`read_back`] on a fresh session to `target` (an apply, after its writes
/// closed their own). `seed` carries the device facts the command's read
/// phase checked (issue #209), so the read-back does not walk the interface
/// objects or negotiate the APDU again; an `options.authorize` of
/// [`Authorize::Skip`](crate::Authorize::Skip) spares a device that never
/// answers `A_Authorize` the timeout (issue #215). A session that cannot be
/// opened is not verified.
pub async fn read_back_on(
    service: &BusService,
    target: IndividualAddress,
    options: &L4Options,
    seed: Option<ConnectionSeed>,
    expected: &Expected<'_>,
) -> WriteReadback {
    let read = service
        .with_l4(target, options, async |l4| {
            if let Some(seed) = seed {
                l4.seed(seed);
            }
            Ok::<_, crate::ServiceError>(read_back(l4, expected).await)
        })
        .await;
    match read {
        Ok(readback) => readback,
        Err(err) => WriteReadback::unreadable(chain(&err)),
    }
}

/// The tables and the group-object count against `expected`.
fn compare_tables(out: &mut WriteReadback, live: &DeviceTables, expected: &Expected<'_>) {
    if let Some(desired) = &expected.tables {
        let report = plan(live, desired);
        for link in &report.additions {
            out.push(
                LeftoverKind::Link,
                format!("object {} -> {}", link.object, link.ga),
                "no link".to_string(),
                "linked".to_string(),
            );
        }
        for link in &report.removals {
            out.push(
                LeftoverKind::Link,
                format!("object {} -> {}", link.object, link.ga),
                "linked".to_string(),
                "no link".to_string(),
            );
        }
        if live.addresses.len() != desired.addresses.len() {
            out.push(
                LeftoverKind::AddressTable,
                "group address table".to_string(),
                entries(live.addresses.len()),
                entries(desired.addresses.len()),
            );
        }
        if live.associations.len() != desired.associations.len() {
            out.push(
                LeftoverKind::AssociationTable,
                "association table".to_string(),
                entries(live.associations.len()),
                entries(desired.associations.len()),
            );
        }
        out.compared.addresses = Some(live.addresses.len());
        out.compared.associations = Some(live.associations.len());
    }
    if let Some(want) = expected.group_objects {
        match live.group_objects {
            Some(count) => {
                if count != want {
                    out.push(
                        LeftoverKind::GroupObjects,
                        "group-object table".to_string(),
                        entries(usize::from(count)),
                        entries(usize::from(want)),
                    );
                }
                out.compared.group_objects = Some(count);
            }
            None => out
                .notes
                .push("group-object count not compared: the table did not read".to_string()),
        }
    }
}

/// The System B group-object table against the image an `apply` reloaded
/// (issue #540): every descriptor that differs is a leftover, and so is a
/// table that cannot be read (the reload cannot be confirmed).
async fn compare_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    out: &mut WriteReadback,
    model: &[u8],
) {
    let count = model
        .get(..2)
        .map_or(0, |w| usize::from(u16::from_be_bytes([w[0], w[1]])));
    let read = match bussard_download::find_object_table(l4).await {
        Ok(Some(index)) => bussard_download::read_object_table_at(l4, index, count)
            .await
            .map_err(|e| chain(&e)),
        Ok(None) => Err("no group-object table object (type 9)".to_string()),
        Err(e) => Err(chain(&e)),
    };
    let live = match read {
        Ok(live) => live,
        Err(why) => {
            out.push(
                LeftoverKind::GroupObjectDescriptor,
                "group-object table".to_string(),
                format!("no answer ({why})"),
                entries(count),
            );
            return;
        }
    };
    if let Some(change) = bussard_download::ObjectTableChange::between(&live, model) {
        for c in &change.objects {
            out.push(
                LeftoverKind::GroupObjectDescriptor,
                format!("object {} descriptor", c.object),
                format!("{:04X}", c.from),
                format!("{:04X}", c.to),
            );
        }
        if change.from_count != change.to_count {
            out.push(
                LeftoverKind::GroupObjects,
                "group-object table".to_string(),
                entries(change.from_count),
                entries(change.to_count),
            );
        }
    }
    out.compared.group_objects = Some(live.count);
}

/// The System 7 communication flags against the model's links: C on for
/// every linked object, off for every object `s7` shows linked before but the
/// model does not (see [`bussard_download::sys7_flag_writes`]). A device whose
/// group-object table did not read gets a note, never a silent pass.
fn compare_sys7_flags(
    out: &mut WriteReadback,
    s7: &bussard_download::Sys7LiveTables,
    desired: &DesiredTables,
) {
    let linked: BTreeSet<u16> = desired.associations.iter().map(|&(_, a)| a).collect();
    let (writes, unchecked) = bussard_download::sys7_flag_writes(s7, &linked);
    for flag in &writes {
        out.push(
            LeftoverKind::CommunicationFlag,
            format!("object {} communication flag", flag.object),
            format!("CONFIG {:02X}", flag.from),
            format!("CONFIG {:02X}", flag.to),
        );
    }
    if s7.group_object_base.is_none() && !linked.is_empty() {
        out.notes.push(
            "communication flags not compared: the group-object table was not read".to_string(),
        );
    } else if !unchecked.is_empty() {
        out.notes.push(format!(
            "communication flags not compared for objects the group-object table does not \
             describe: {unchecked:?}"
        ));
    }
}

/// The parameter comparison as leftovers.
fn compare_parameters(out: &mut WriteReadback, flashed: &FlashedParameters) {
    if let Some(note) = &flashed.note {
        out.notes.push(format!("parameters not compared: {note}"));
        return;
    }
    for d in &flashed.differences {
        let unit = d.unit.as_deref().filter(|u| !u.is_empty());
        let with_unit = |v: &str| match unit {
            Some(u) => format!("{v} {u}"),
            None => v.to_string(),
        };
        out.push(
            LeftoverKind::Parameter,
            format!("parameter {} ({})", d.key, d.name),
            d.device
                .as_deref()
                .map_or_else(|| "an unreadable value".to_string(), with_unit),
            with_unit(&d.model),
        );
    }
    if !flashed.kept.is_empty() {
        let names: Vec<String> = flashed
            .kept
            .iter()
            .map(|k| format!("{} ({})", k.key, k.name))
            .collect();
        out.notes.push(format!(
            "{} parameter(s) kept on the device, not compared: the load procedure's branch \
             does not write their octets, as ETS's download does not (issue #411), and after a \
             fresh allocation the device holds whatever the allocation left there: {}",
            names.len(),
            names.join(", ")
        ));
    }
    out.compared.parameters = Some(flashed.compared);
}

/// The security object's PID 53 count, PID 54 and PID 61 against the
/// program the write sent.
async fn compare_security<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    out: &mut WriteReadback,
    expected: &ExpectedSecurity,
) {
    compare_security_load_state(l4, out).await;
    match read_property_ext_element_count(l4, PropertyExtAddress::security(PID_GRP_KEY_TABLE)).await
    {
        Ok(count) => {
            if count != expected.group_keys {
                out.push(
                    LeftoverKind::GroupKeyTable,
                    "group key table (PID 53)".to_string(),
                    entries(usize::from(count)),
                    entries(usize::from(expected.group_keys)),
                );
            }
            out.compared.group_keys = Some(count);
        }
        Err(err) => out
            .notes
            .push(format!("group key table (PID 53) count not read: {err}")),
    }
    let readback = match bussard_download::read_security_object(l4).await {
        Ok(readback) => readback,
        Err(err) => {
            out.notes
                .push(format!("security object (PID 54, PID 61) not read: {err}"));
            return;
        }
    };
    out.notes.extend(readback.notes.iter().cloned());
    if let Some(senders) = &readback.senders {
        let held: BTreeSet<IndividualAddress> = senders.iter().map(|e| e.address).collect();
        let want: BTreeSet<IndividualAddress> = expected.senders.iter().copied().collect();
        for ia in want.difference(&held) {
            out.push(
                LeftoverKind::SecureSender,
                format!("secure sender {ia} (PID 54)"),
                "not listed".to_string(),
                "listed".to_string(),
            );
        }
        for ia in held.difference(&want) {
            out.push(
                LeftoverKind::SecureSender,
                format!("secure sender {ia} (PID 54)"),
                "listed".to_string(),
                "not listed".to_string(),
            );
        }
        out.compared.secure_senders = Some(held.len());
    }
    if let Some(held) = readback.secured_objects() {
        for object in expected.secured_objects.difference(&held) {
            out.push(
                LeftoverKind::SecurityFlag,
                format!("group object {object} security flag (PID 61)"),
                "plain".to_string(),
                "secured".to_string(),
            );
        }
        for object in held.difference(&expected.secured_objects) {
            out.push(
                LeftoverKind::SecurityFlag,
                format!("group object {object} security flag (PID 61)"),
                "secured".to_string(),
                "plain".to_string(),
            );
        }
        out.compared.secured_objects = Some(held.len());
    }
}

/// The security object's load state (PID 5) against `Loaded` (issue #534).
/// A state that cannot be read is a leftover too: nothing then shows the
/// device uses the tables just written.
async fn compare_security_load_state<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    out: &mut WriteReadback,
) {
    let item = "security object load state (PID 5)".to_string();
    let loaded = "Loaded".to_string();
    match security_load_state(l4).await {
        Ok(LoadState::Loaded) => out.compared.security_load_state = Some(loaded),
        Ok(state) => {
            out.push(
                LeftoverKind::SecurityLoadState,
                item,
                format!(
                    "{state} (it drops every secured group telegram until a write ends Loaded)"
                ),
                loaded,
            );
            out.compared.security_load_state = Some(state.to_string());
        }
        Err(err) => out.push(
            LeftoverKind::SecurityLoadState,
            item,
            format!("no answer ({})", chain(&err)),
            loaded,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A System 7 device linking object 1 (TSAP 1) whose group-object table at
    /// `base` holds objects 0..=2 with the given CONFIG octets.
    fn sys7_live(
        base: Option<u16>,
        configs: [u8; 3],
    ) -> TestResult<bussard_download::Sys7LiveTables> {
        Ok(bussard_download::Sys7LiveTables {
            tables: tables(&["1/0/1"], &[(1, 1)])?,
            address_base: 0x4000,
            association_base: 0x40ED,
            packed_end: None,
            own_ia: 0x1163,
            address_capacity: 237,
            association_capacity: 235,
            group_object_base: base,
            group_object_image: Vec::new(),
            group_objects: if base.is_some() {
                configs
                    .iter()
                    .enumerate()
                    .map(|(i, &config)| bussard_download::Sys7GroupObject {
                        asap: i as u16,
                        data_ptr: 0,
                        config,
                        type_code: 0,
                    })
                    .collect()
            } else {
                Vec::new()
            },
            task_identity: None,
        })
    }

    #[test]
    fn test_compare_sys7_flags_reports_a_flag_left_off() -> TestResult<()> {
        let desired = DesiredTables {
            addresses: vec!["1/0/1".parse()?],
            associations: vec![(1, 1)],
        };
        let mut out = WriteReadback::default();
        compare_sys7_flags(
            &mut out,
            &sys7_live(Some(0x41D8), [0xDB, 0xDB, 0xDB])?,
            &desired,
        );
        assert_eq!(out.leftovers.len(), 1, "{:?}", out.leftovers);
        assert_eq!(out.leftovers[0].kind, LeftoverKind::CommunicationFlag);
        let mut ok = WriteReadback::default();
        compare_sys7_flags(
            &mut ok,
            &sys7_live(Some(0x41D8), [0xDB, 0xDF, 0xDB])?,
            &desired,
        );
        assert!(
            ok.leftovers.is_empty() && ok.notes.is_empty(),
            "{:?}",
            ok.notes
        );
        Ok(())
    }

    #[test]
    fn test_compare_sys7_flags_notes_an_unread_table() -> TestResult<()> {
        let desired = DesiredTables {
            addresses: vec!["1/0/1".parse()?],
            associations: vec![(1, 1)],
        };
        let mut out = WriteReadback::default();
        compare_sys7_flags(&mut out, &sys7_live(None, [0; 3])?, &desired);
        assert!(out.leftovers.is_empty());
        assert_eq!(out.notes.len(), 1, "{:?}", out.notes);
        Ok(())
    }

    fn tables(addresses: &[&str], links: &[(u16, u16)]) -> TestResult<DeviceTables> {
        let addresses: Vec<GroupAddress> = addresses
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()?;
        let resolved = links
            .iter()
            .filter_map(|&(tsap, asap)| {
                let ga = *addresses.get(usize::from(tsap).checked_sub(1)?)?;
                Some(bussard_mgmt::tables::ResolvedLink { object: asap, ga })
            })
            .collect();
        Ok(DeviceTables {
            mask: 0x07B0,
            addresses,
            associations: links.to_vec(),
            resolved,
            sources: Vec::new(),
            notes: Vec::new(),
            group_objects: Some(21),
        })
    }

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn test_compare_tables_names_a_missing_link_and_the_sizes() -> TestResult {
        let live = tables(&["1/2/0"], &[(1, 20)])?;
        let expected = Expected {
            tables: Some(DesiredTables {
                addresses: vec!["1/2/0".parse()?, "1/2/3".parse()?],
                associations: vec![(1, 20), (2, 22)],
            }),
            group_objects: Some(23),
            ..Expected::default()
        };
        let mut out = WriteReadback::default();
        compare_tables(&mut out, &live, &expected);
        let kinds: Vec<LeftoverKind> = out.leftovers.iter().map(|l| l.kind).collect();
        assert_eq!(
            kinds,
            vec![
                LeftoverKind::Link,
                LeftoverKind::AddressTable,
                LeftoverKind::AssociationTable,
                LeftoverKind::GroupObjects
            ]
        );
        assert_eq!(out.leftovers[0].item, "object 22 -> 1/2/3");
        let failure = out.failure().ok_or("expected a failure")?;
        assert!(failure.contains("object 22 -> 1/2/3"), "{failure}");
        assert!(failure.contains("group-object table"), "{failure}");
        Ok(())
    }

    #[test]
    fn test_compare_tables_matching_tables_leave_nothing() -> TestResult {
        let live = tables(&["1/2/0"], &[(1, 20)])?;
        let expected = Expected {
            tables: Some(DesiredTables {
                addresses: vec!["1/2/0".parse()?],
                associations: vec![(1, 20)],
            }),
            group_objects: Some(21),
            ..Expected::default()
        };
        let mut out = WriteReadback::default();
        compare_tables(&mut out, &live, &expected);
        assert!(out.leftovers.is_empty(), "{:?}", out.leftovers);
        assert_eq!(out.compared.addresses, Some(1));
        assert_eq!(out.compared.group_objects, Some(21));
        assert_eq!(
            out.summary(),
            "1 group address(es), 1 association(s), 21 group object(s)"
        );
        Ok(())
    }

    #[test]
    fn test_expected_security_from_inputs_counts_the_keyed_addresses() -> TestResult {
        let ga3: GroupAddress = "1/2/3".parse()?;
        let mut inputs = SecurityInputs::default();
        inputs
            .group_keys
            .insert(ga3, bussard_secure::Key16::new([0x11; 16]));
        inputs.secure_objects.insert(22);
        inputs.senders = vec![bussard_download::SecureSenderEntry {
            address: "1.1.250".parse()?,
            sequence: 7,
        }];
        let expected = ExpectedSecurity::from_inputs(&inputs, &["1/2/0".parse()?, ga3]);
        assert_eq!(expected.group_keys, 1);
        assert_eq!(expected.senders, vec!["1.1.250".parse()?]);
        assert_eq!(expected.secured_objects, BTreeSet::from([22]));
        Ok(())
    }

    #[test]
    fn test_unreadable_is_not_verified() {
        let out = WriteReadback::unreadable("timeout".to_string());
        assert!(!out.verified);
        assert!(out.failure().is_some_and(|f| f.contains("timeout")));
    }

    #[tokio::test]
    async fn test_read_back_names_a_property_the_device_does_not_hold() -> TestResult {
        use bussard_download::PropObject;
        let device = bussard_testkit::MockDevice::new("1.1.200".parse()?)
            .with_property_ext(11, 204, 1, &[0x0A])
            .with_property_ext(11, 205, 4, &[192, 168, 0, 1, 0, 0, 0, 0]);
        let gw = bussard_testkit::MockGateway::builder()
            .device(device)
            .start()
            .await?;
        let mut bus = bussard_transport::Transport::connect(
            &bussard_transport::ConnectionConfig::tunnel(gw.addr()),
        )
        .await?;
        let mut l4 =
            Layer4Connection::connect(&mut bus, "1.1.200".parse()?, "0.0.255".parse()?).await?;
        let ip = PropObject::Type {
            object_type: 11,
            occurrence: 0,
        };
        let expected = Expected {
            properties: vec![
                ExpectedProperty {
                    object: ip,
                    prop_id: 204,
                    start: 1,
                    count: 1,
                    value: vec![0x0A],
                },
                ExpectedProperty {
                    object: ip,
                    prop_id: 205,
                    start: 1,
                    count: 2,
                    value: vec![192, 168, 0, 1, 10, 0, 0, 2],
                },
            ],
            ..Expected::default()
        };
        let out = read_back(&mut l4, &expected).await;
        let _ = l4.disconnect().await;
        assert!(!out.verified);
        assert_eq!(out.compared.properties, Some(2));
        assert_eq!(out.leftovers.len(), 1, "{:?}", out.leftovers);
        assert_eq!(out.leftovers[0].kind, LeftoverKind::Property);
        assert_eq!(out.leftovers[0].item, "object type 11 PID 205");
        assert_eq!(out.leftovers[0].device, "C0A8000100000000");
        Ok(())
    }
}
