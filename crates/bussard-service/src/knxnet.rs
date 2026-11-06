//! The read side of the KNXnet/IP parameter object (issue #391): read an IP
//! interface's object type 11 over a management connection, decode it into
//! [`KnxnetFacts`] and keep it with the device facts.
//!
//! `status <ADDRESS>`, `describe` and `adopt` call [`read_knxnet`] on the
//! connection they already hold. It addresses the object by the index the
//! object table or `PID_IO_LIST` gives (plain property reads), else by object
//! type and instance (the extended property services) after one short probe.
//! A device without the object is `None`. No KNXnet/IP Secure property (PID 91
//! and up) is ever read or written.
//!
//! # The write side
//!
//! `plan` and `apply` of an IP interface (and the MCP `knx_plan_device` /
//! `knx_apply_device`) share three functions: [`read_interface`] reads the
//! object and the device's description of PID 53 on an open session,
//! [`plan_interface`] turns the difference between the device file's
//! `[knxnet]` table and what was read into property writes, and
//! [`apply_interface`] writes them through the property step executor every
//! load procedure uses ([`bussard_download::write_property_value`]), then
//! reads every written property back ([`crate::verify::read_back`]) and the
//! whole object again, and calls the write verified only when both match the
//! model. The object is addressed by type (object type 11, instance 1), as
//! ETS writes the IPS 300 SREG's KNXnet/IP parameters (`LdCtrlWriteProp
//! ObjType="11"`, capture of 2026-10-26); a device that refuses the extended
//! services is written by its object index instead.
//!
//! Changing the IP assignment or the static address set of the interface the
//! session is connected through drops the tunnel once the interface applies
//! it, and rewriting its tunnelling addresses (PID 53) may drop its open
//! tunnels (untested on the IPS 300 SREG, so it counts the same): the plan names
//! that in [`InterfacePlan::self_reconfigure`], and the callers refuse it
//! unless the operator opted in (`apply --allow-self-reconfigure`; the MCP
//! tool has no such switch).

use bussard_mgmt::knxnet::{
    KnxnetAccess, KnxnetValues, OT_KNXNET_IP_PARAMETER, knxnet_index_from_io_list,
    probe_knxnet_ext, read_knxnet_parameters, with_probe_timeout,
};
use bussard_mgmt::knxnet::{
    KnxnetPropertyDescription, PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, PID_DEFAULT_GATEWAY,
    PID_FRIENDLY_NAME, PID_IP_ADDRESS, PID_IP_ASSIGNMENT_METHOD, PID_SUBNET_MASK,
    describe_knxnet_property, encode_friendly_name,
};
use bussard_mgmt::{L4Channel, Layer4Connection, MgmtError};

use std::net::Ipv4Addr;

use bussard_download::{ChangeMark, ChangeSubject, DevicePlan, PlanChange, PlanWrites, PropObject};
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::knxnet::{
    IpAssignment, KnxnetConfig, KnxnetFacts, capability_names, format_mac, join_addresses,
    method_names, state_label,
};
use sha2::{Digest, Sha256};

use crate::facts::{Established, FactsCache, FactsWant};
use crate::verify::{Expected, ExpectedProperty, LeftoverKind, WriteReadback};

/// The index of the KNXnet/IP parameter object in `table` (`(index, object
/// type)` pairs), when the device has one.
pub fn knxnet_object_index(table: &[(u8, u16)]) -> Option<u8> {
    table
        .iter()
        .find(|(_, ot)| *ot == OT_KNXNET_IP_PARAMETER)
        .map(|(index, _)| *index)
}

/// Reads the KNXnet/IP parameter object of the device behind `l4`.
///
/// `table` is the object table in effect (from the device facts),
/// `table_from_io_list` whether it came from `PID_IO_LIST`. The object is
/// found, in this order:
///
/// 1. in `table` (the `PID_OBJECT_TYPE` walk or a checked `PID_IO_LIST`): read
///    by index with the plain property services;
/// 2. in the device object's `PID_IO_LIST` at an index the walk did not reach,
///    when that index answers: read by index;
/// 3. by object type 11, instance 1, with one extended-service probe
///    ([`probe_knxnet_ext`]): read by type and instance. The Jung IPS 300 SREG
///    (mask 0021) is found here: its walk lists a device object and an address
///    table only (live `describe 1.1.200`, 2026-10-26).
///
/// Steps 2 and 3 wait at most [`bussard_mgmt::knxnet::PROBE_RESPONSE_TIMEOUT`]
/// per request, and a device that leaves them unanswered keeps the connection.
/// A device without the object is `None`.
///
/// # Errors
///
/// A transport failure or a malformed response.
pub async fn read_knxnet<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    table: &[(u8, u16)],
    table_from_io_list: bool,
) -> Result<Option<KnxnetFacts>, MgmtError> {
    let from_io_list = if table_from_io_list {
        // The table already is the checked `PID_IO_LIST`.
        None
    } else {
        knxnet_index_from_io_list(l4).await?
    };
    let access = match knxnet_object_index(table).or(from_io_list) {
        Some(index) => KnxnetAccess::Index(index),
        None if probe_knxnet_ext(l4, 1).await? => KnxnetAccess::Ext { instance: 1 },
        None => return Ok(None),
    };
    let values = match access {
        KnxnetAccess::Index(_) => read_knxnet_parameters(l4, access).await?,
        // A device found by the probe may leave some of the properties
        // unanswered; each such read waits the probe timeout, not 3 s.
        KnxnetAccess::Ext { .. } => {
            with_probe_timeout(l4, async |l4| read_knxnet_parameters(l4, access).await).await?
        }
    };
    if values == KnxnetValues::default() {
        return Ok(None);
    }
    let index = match access {
        KnxnetAccess::Index(index) => Some(index),
        KnxnetAccess::Ext { .. } => None,
    };
    Ok(Some(facts_from_values(
        &values,
        index,
        bussard_model::facts::now_stamp(),
    )))
}

/// The KNXnet/IP state of the device behind `l4` with the device facts in
/// effect: `None` without a read when the facts record that the device has
/// no KNXnet/IP parameter object (`no_knxnet`, cleared whenever the facts are
/// read again, `--refresh-facts` included); otherwise [`read_knxnet`], whose
/// result (the values, or the absence) is recorded in the facts.
///
/// # Errors
///
/// As [`read_knxnet`].
pub async fn read_knxnet_with_facts<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
    established: &mut Established,
) -> Result<Option<KnxnetFacts>, MgmtError> {
    if established.record.as_ref().is_some_and(|r| r.no_knxnet) {
        return Ok(None);
    }
    let table = established.object_table();
    let from_io_list = established
        .record
        .as_ref()
        .is_some_and(|r| r.object_table_source == bussard_model::facts::ObjectTableSource::IoList);
    let knxnet = read_knxnet(l4, &table, from_io_list).await?;
    facts.remember_knxnet(established, knxnet.clone());
    Ok(knxnet)
}

/// Decodes the raw property values into the stored facts.
pub fn facts_from_values(
    v: &KnxnetValues,
    object_index: Option<u8>,
    read_at: String,
) -> KnxnetFacts {
    let ip = |q: Option<[u8; 4]>| q.map(std::net::Ipv4Addr::from);
    let names = |bits: Option<u8>| {
        bits.map(|b| {
            method_names(b)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
    };
    KnxnetFacts {
        read_at,
        object_index,
        individual_address: v.individual_address,
        tunnels: v.additional_addresses.clone(),
        current_assignment: names(v.current_assignment),
        assignment: names(v.assignment),
        assignment_mode: v.assignment.and_then(IpAssignment::from_method_bits),
        current_address: ip(v.current_ip),
        current_netmask: ip(v.current_netmask),
        current_gateway: ip(v.current_gateway),
        address: ip(v.ip),
        netmask: ip(v.netmask),
        gateway: ip(v.gateway),
        mac: v.mac.map(|m| format_mac(&m)),
        system_setup_multicast: ip(v.system_setup_multicast),
        routing_multicast: ip(v.routing_multicast),
        ttl: v.ttl,
        capabilities: v.capabilities.map(|c| {
            capability_names(c)
                .into_iter()
                .map(str::to_string)
                .collect()
        }),
        state: v.state.map(state_label),
        friendly_name: v.friendly_name.clone(),
    }
}

// ---------------------------------------------------------------------------
// The write side (issue #391, sub-task b)
// ---------------------------------------------------------------------------

/// The `[knxnet]` table of `target` when `plan`/`apply` write the device as
/// an IP interface: its device file has the table and the model links none of
/// its objects. A device with links keeps the table path.
pub fn interface_config(
    model: &bussard_model::Model,
    target: IndividualAddress,
) -> Option<&KnxnetConfig> {
    let loaded = model.devices.get(&target)?;
    if model
        .links
        .links
        .get(&target)
        .is_some_and(|l| !l.is_empty())
    {
        return None;
    }
    loaded.device.knxnet.as_ref()
}

/// The note an interface plan carries when the device file also sets
/// parameters: an interface plan compares the `[knxnet]` table only, and the
/// application's parameters (on the IPS 300 SREG the properties its load
/// procedure writes, issue #390) are written by `bussard flash`.
pub fn parameters_note(model: &bussard_model::Model, target: IndividualAddress) -> Option<String> {
    let n = model.devices.get(&target)?.device.parameters.len();
    (n > 0).then(|| {
        format!(
            "this plan compares the [knxnet] table only; the {n} parameter{} of \
             devices/{target}.toml {} written by `bussard flash {target}` (the application's \
             load procedure)",
            if n == 1 { "" } else { "s" },
            if n == 1 { "is" } else { "are" }
        )
    })
}

/// How the KNXnet/IP parameter object is written: by type, the first object
/// of type 11, as ETS does (see the module docs).
pub const INTERFACE_OBJECT: PropObject = PropObject::Type {
    object_type: OT_KNXNET_IP_PARAMETER,
    occurrence: 0,
};

/// What `plan` and `apply` read of an IP interface on one session.
#[derive(Debug, Clone)]
pub struct InterfaceRead {
    /// The mask the device reported.
    pub mask: u16,
    /// The device facts in effect (refreshed with the KNXnet/IP values).
    pub established: Established,
    /// The identity verdict against the lock (issue #228, item 5).
    pub check: IdentityCheck,
    /// The KNXnet/IP parameter object as read; `None` when the device has
    /// none.
    pub knxnet: Option<KnxnetFacts>,
    /// The device's description of PID 53 (the tunnelling addresses), when
    /// it gives one.
    pub tunnel_slots: Option<KnxnetPropertyDescription>,
}

/// Reads an IP interface for a plan: the descriptor, the device facts and
/// the identity verdict for `device` (the model's entry), the KNXnet/IP
/// parameter object (recorded with the facts), and the description of PID
/// 53. Read-only.
///
/// # Errors
///
/// A transport failure, or a device that hides its mask (a KNX Data Secure
/// device read without its tool key).
pub async fn read_interface<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
    device: Option<&bussard_model::schema::Device>,
) -> Result<InterfaceRead, MgmtError> {
    let mask = bussard_mgmt::read_device_descriptor(l4).await?;
    if mask == crate::identity::HIDDEN_MASK {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: "the device hides its mask (FFFF): it is secured and answers \
                     only a secured session; pass its tool key (--keyring)"
                .to_string(),
        });
    }
    let mut established = facts.establish(l4, mask, FactsWant::Table).await?;
    let reported = ReportedIdentity {
        mask: bussard_model::facts::format_mask(mask),
        application_id: established
            .record
            .as_ref()
            .and_then(|r| r.application_id.clone()),
    };
    let check = IdentityCheck::compare(device, reported);
    let knxnet = read_knxnet_with_facts(l4, facts, &mut established).await?;
    let tunnel_slots = match &knxnet {
        Some(k) => {
            let access = match k.object_index {
                Some(index) => KnxnetAccess::Index(index),
                None => KnxnetAccess::Ext { instance: 1 },
            };
            describe_knxnet_property(l4, access, PID_ADDITIONAL_INDIVIDUAL_ADDRESSES).await?
        }
        None => None,
    };
    Ok(InterfaceRead {
        mask,
        established,
        check,
        knxnet,
        tunnel_slots,
    })
}

/// How the session reaches the bus, to tell whether a plan reconfigures the
/// interface it runs through.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionLink {
    /// The session's own individual address (the tunnelling address the
    /// gateway assigned).
    pub source: Option<IndividualAddress>,
    /// The IP address of the KNXnet/IP gateway the session tunnels through.
    pub gateway: Option<Ipv4Addr>,
}

impl SessionLink {
    /// The gateway's IP from a `host:port` (or bare host) string, the way
    /// the CLI and the MCP server display it.
    pub fn gateway_of(display: &str) -> Option<Ipv4Addr> {
        let host = display.rsplit_once(':').map_or(display, |(h, _)| h).trim();
        host.parse().ok()
    }

    /// Why the session runs through the interface `facts` describe, when it
    /// does: its gateway is the interface's IP address, or its own address
    /// is one of the interface's tunnelling addresses.
    pub fn through(&self, facts: &KnxnetFacts) -> Option<String> {
        if let Some(gw) = self.gateway
            && (facts.current_address == Some(gw) || facts.address == Some(gw))
        {
            return Some(format!(
                "bussard tunnels through it ({gw} is its IP address)"
            ));
        }
        if let Some(src) = self.source
            && facts.tunnels.contains(&src)
        {
            return Some(format!(
                "bussard's tunnel address {src} is one of its tunnelling addresses"
            ));
        }
        None
    }
}

/// One property write of an interface plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceStep {
    /// The property id (never 91 or above).
    pub prop_id: u8,
    /// The first element written (0 sets an array's element count).
    pub start: u16,
    /// How many elements are written.
    pub count: u16,
    /// The octets written.
    pub value: Vec<u8>,
    /// What the write sets, in words.
    pub label: String,
}

impl InterfaceStep {
    /// The write as the owner reviews it on the wire: `object type 11
    /// instance 1 PID 76 start 1 count 30: 42 6F …`.
    pub fn wire(&self) -> String {
        let hex: Vec<String> = self.value.iter().map(|b| format!("{b:02X}")).collect();
        format!(
            "object type {OT_KNXNET_IP_PARAMETER} instance 1 PID {} start {} count {}: {}",
            self.prop_id,
            self.start,
            self.count,
            hex.join(" ")
        )
    }
}

/// The plan of writing a device file's `[knxnet]` table to the interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterfacePlan {
    /// The writes, in order: the friendly name, the tunnelling addresses,
    /// the static address set, the assignment method last.
    pub steps: Vec<InterfaceStep>,
    /// The changes in the model's words.
    pub changes: Vec<PlanChange>,
    /// What the plan leaves alone, and why.
    pub notes: Vec<String>,
    /// Why (part of) the plan cannot be written; a non-empty list refuses
    /// the whole apply.
    pub refusals: Vec<String>,
    /// Set when the writes reconfigure the interface the session runs
    /// through (the tunnel drops): refused unless the operator opts in.
    pub self_reconfigure: Option<String>,
    /// The fingerprint of the device state the plan was computed from.
    pub state_hash: String,
}

impl InterfacePlan {
    /// Whether nothing is to be written.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty() && self.changes.is_empty()
    }

    /// Why the plan is not written: the refusals, then the self-reconfigure
    /// guard unless `allow_self_reconfigure`.
    pub fn refusal(&self, allow_self_reconfigure: bool) -> Option<String> {
        if !self.refusals.is_empty() {
            return Some(self.refusals.join("; "));
        }
        match &self.self_reconfigure {
            Some(why) if !allow_self_reconfigure => Some(why.clone()),
            _ => None,
        }
    }

    /// What the read-back after the write compares: every written property.
    pub fn expected(&self) -> Vec<ExpectedProperty> {
        self.steps
            .iter()
            .map(|s| ExpectedProperty {
                object: INTERFACE_OBJECT,
                prop_id: u32::from(s.prop_id),
                start: s.start,
                count: s.count.max(1),
                value: s.value.clone(),
            })
            .collect()
    }

    /// The plan in the shape every device plan has (`plan`, `apply`,
    /// `knx_plan_device`).
    pub fn device_plan(
        &self,
        address: IndividualAddress,
        name: &str,
        gateway: &str,
        backup_dir: String,
    ) -> DevicePlan {
        let mut interface_properties: Vec<u8> = Vec::new();
        for step in &self.steps {
            if !interface_properties.contains(&step.prop_id) {
                interface_properties.push(step.prop_id);
            }
        }
        let mut notes = self.notes.clone();
        if let Some(why) = &self.self_reconfigure {
            notes.push(why.clone());
        }
        notes.extend(self.refusals.iter().map(|r| format!("not written: {r}")));
        DevicePlan {
            address: address.to_string(),
            name: name.to_string(),
            gateway: gateway.to_string(),
            changes: self.changes.clone(),
            channels: Default::default(),
            unchanged_objects: 0,
            unchanged_parameters: None,
            writes: PlanWrites {
                interface_properties,
                ..PlanWrites::default()
            },
            backup_dir,
            notes,
            state_hash: self.state_hash.clone(),
        }
    }
}

/// One `[knxnet]` change line.
fn change(mark: ChangeMark, key: &str, sentence: String) -> PlanChange {
    PlanChange {
        mark,
        subject: ChangeSubject::Interface,
        channel: None,
        key: format!("knxnet.{key}"),
        object: None,
        sentence,
    }
}

/// The fingerprint of what a plan was computed from: the values read (not
/// when) and the description of PID 53.
pub fn interface_state_hash(
    facts: &KnxnetFacts,
    tunnel_slots: Option<KnxnetPropertyDescription>,
) -> String {
    let mut hasher = Sha256::new();
    let mut f = facts.clone();
    f.read_at = String::new();
    hasher.update(format!("{f:?}").as_bytes());
    hasher.update(format!("{tunnel_slots:?}").as_bytes());
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `"Alpha"`, or `none`.
fn quoted(name: Option<&str>) -> String {
    match name {
        Some(n) => format!("{n:?}"),
        None => "none".to_string(),
    }
}

/// The plan of writing `config` (the device file's `[knxnet]` table) to the
/// interface `target` whose object reads as `facts`, with `tunnel_slots` the
/// device's description of PID 53 and `link` how the session reaches the
/// bus. Pure: the same inputs give the same plan.
///
/// - **Friendly name** (PID 76): written whole, 30 octets of ISO 8859-1
///   padded with NUL, when the table names one that differs. Absent from the
///   table: the device's name stays.
/// - **Tunnelling addresses** (PID 53): one array write of elements 1..n
///   when the model lists as many addresses as the device holds; a different
///   count first writes element 0 (the element count), which needs a
///   description that calls PID 53 writable with room for them; without a
///   description only the same count is written. An empty list in the model
///   leaves the device's addresses alone.
/// - **Static address set** (PIDs 60, 61, 62) under `assignment = "static"`;
///   a gateway absent from the table stays as it is.
/// - **Assignment method** (PID 55), last: manual (0x01) or DHCP (0x04).
///   Bits the device adds to the model's method (AutoIP next to DHCP) are no
///   change.
///
/// A property the device does not serve cannot be written: that change is a
/// refusal. Nothing at PID 91 or above is touched.
pub fn plan_interface(
    target: IndividualAddress,
    config: &KnxnetConfig,
    facts: &KnxnetFacts,
    tunnel_slots: Option<KnxnetPropertyDescription>,
    link: &SessionLink,
) -> InterfacePlan {
    let mut plan = InterfacePlan {
        state_hash: interface_state_hash(facts, tunnel_slots),
        ..InterfacePlan::default()
    };
    let through = link.through(facts);
    // Whether a step reconfigures the session's own path.
    let mut reconfigures: Vec<&'static str> = Vec::new();

    // PID 76, the friendly name.
    if let Some(want) = &config.friendly_name
        && facts.friendly_name.as_deref() != Some(want.as_str())
    {
        plan.changes.push(change(
            ChangeMark::Changed,
            "friendly_name",
            format!(
                "friendly name = {want:?}, was {}",
                quoted(facts.friendly_name.as_deref())
            ),
        ));
        match (encode_friendly_name(want), &facts.friendly_name) {
            (_, None) => plan.refusals.push(format!(
                "{target} does not serve PID {PID_FRIENDLY_NAME} (friendly name)"
            )),
            (None, _) => plan.refusals.push(format!(
                "friendly name {want:?} is not at most 30 ISO 8859-1 characters (E043)"
            )),
            (Some(octets), Some(_)) => plan.steps.push(InterfaceStep {
                prop_id: PID_FRIENDLY_NAME,
                start: 1,
                count: u16::try_from(octets.len()).unwrap_or(u16::MAX),
                value: octets,
                label: format!("friendly name {want:?}"),
            }),
        }
    }

    // PID 53, the tunnelling addresses.
    if config.tunnels.is_empty() {
        if !facts.tunnels.is_empty() {
            plan.notes.push(format!(
                "[knxnet] lists no tunnel addresses; the device's {} ({}) stay as they are",
                facts.tunnels.len(),
                join_addresses(&facts.tunnels)
            ));
        }
    } else if config.tunnels != facts.tunnels {
        tunnel_changes(&mut plan, config, facts);
        let n = config.tunnels.len();
        let current = facts.tunnels.len();
        let value: Vec<u8> = config
            .tunnels
            .iter()
            .flat_map(|ia| ia.raw().to_be_bytes())
            .collect();
        let elements = u16::try_from(n).unwrap_or(u16::MAX);
        let write = InterfaceStep {
            prop_id: PID_ADDITIONAL_INDIVIDUAL_ADDRESSES,
            start: 1,
            count: elements,
            value,
            label: format!("tunnel addresses {}", join_addresses(&config.tunnels)),
        };
        match tunnel_slots {
            Some(d) if !d.writable => plan.refusals.push(format!(
                "{target} describes PID {PID_ADDITIONAL_INDIVIDUAL_ADDRESSES} (tunnel addresses) \
                 as read-only"
            )),
            _ if n == current => plan.steps.push(write),
            Some(d) if usize::from(d.max_elements) >= n => {
                plan.steps.push(InterfaceStep {
                    prop_id: PID_ADDITIONAL_INDIVIDUAL_ADDRESSES,
                    start: 0,
                    count: 1,
                    value: elements.to_be_bytes().to_vec(),
                    label: format!("tunnel address count {n}, was {current}"),
                });
                plan.steps.push(write);
            }
            Some(d) => plan.refusals.push(format!(
                "[knxnet] lists {n} tunnel addresses; {target} holds at most {} (PID \
                 {PID_ADDITIONAL_INDIVIDUAL_ADDRESSES})",
                d.max_elements
            )),
            None => plan.refusals.push(format!(
                "[knxnet] lists {n} tunnel addresses and {target} holds {current}; it does not \
                 describe PID {PID_ADDITIONAL_INDIVIDUAL_ADDRESSES}, so bussard writes the same \
                 number only: list exactly {current}"
            )),
        }
        // Any PID 53 write on the interface the session runs through counts
        // as reconfiguring it: whether the interface keeps its open tunnels
        // when its tunnelling addresses are rewritten is untested (the IPS
        // 300 SREG included), and the owner's house tunnels through it.
        reconfigures.push("rewrites its tunnelling addresses (PID 53)");
    }

    // PIDs 60 to 62, the static address set.
    if config.assignment == IpAssignment::Static {
        for (pid, what, want, have) in [
            (PID_IP_ADDRESS, "address", config.address, facts.address),
            (PID_SUBNET_MASK, "netmask", config.netmask, facts.netmask),
            (
                PID_DEFAULT_GATEWAY,
                "gateway",
                config.gateway,
                facts.gateway,
            ),
        ] {
            let Some(want) = want else { continue };
            if have == Some(want) {
                continue;
            }
            plan.changes.push(change(
                ChangeMark::Changed,
                what,
                format!(
                    "static {what} = {want}, was {}",
                    have.map_or("none".to_string(), |a| a.to_string())
                ),
            ));
            if have.is_none() {
                plan.refusals
                    .push(format!("{target} does not serve PID {pid} (static {what})"));
                continue;
            }
            plan.steps.push(InterfaceStep {
                prop_id: pid,
                start: 1,
                count: 1,
                value: want.octets().to_vec(),
                label: format!("static {what} {want}"),
            });
            reconfigures.push("changes its IP settings");
        }
    }

    // PID 55, the assignment method, last.
    if facts.assignment_mode != Some(config.assignment) {
        let was = facts
            .assignment
            .as_ref()
            .filter(|m| !m.is_empty())
            .map_or("none".to_string(), |m| m.join(", "));
        match &facts.assignment {
            None if config.assignment == IpAssignment::Dhcp => plan.notes.push(format!(
                "{target} does not report its IP assignment method (PID \
                 {PID_IP_ASSIGNMENT_METHOD}); left as it is"
            )),
            None => {
                plan.changes.push(change(
                    ChangeMark::Changed,
                    "assignment",
                    format!("assignment = {}, was {was}", config.assignment.label()),
                ));
                plan.refusals.push(format!(
                    "{target} does not serve PID {PID_IP_ASSIGNMENT_METHOD} (IP assignment method)"
                ));
            }
            Some(_) => {
                plan.changes.push(change(
                    ChangeMark::Changed,
                    "assignment",
                    format!("assignment = {}, was {was}", config.assignment.label()),
                ));
                plan.steps.push(InterfaceStep {
                    prop_id: PID_IP_ASSIGNMENT_METHOD,
                    start: 1,
                    count: 1,
                    value: vec![config.assignment.method_bits()],
                    label: format!("IP assignment {}", config.assignment.label()),
                });
                reconfigures.push("changes its IP assignment");
            }
        }
    }

    if let Some(through) = through
        && !reconfigures.is_empty()
    {
        reconfigures.dedup();
        let ip = reconfigures.iter().any(|r| !r.contains("PID 53"));
        let consequence = if ip {
            "the tunnel drops when the interface applies it"
        } else {
            "the interface may drop its open tunnels, bussard's included (untested on this \
             device)"
        };
        plan.self_reconfigure = Some(format!(
            "this write {} of {target}, and {through}: {consequence}, and the read-back may not \
             reach the device; run it with --allow-self-reconfigure from a session that can \
             reach {target} afterwards, or through another interface",
            reconfigures.join(" and ")
        ));
    }
    plan
}

/// The PID 53 change in sentences: addresses added and removed, or a new
/// slot order.
fn tunnel_changes(plan: &mut InterfacePlan, config: &KnxnetConfig, facts: &KnxnetFacts) {
    let added: Vec<_> = config
        .tunnels
        .iter()
        .filter(|ia| !facts.tunnels.contains(ia))
        .collect();
    let removed: Vec<_> = facts
        .tunnels
        .iter()
        .filter(|ia| !config.tunnels.contains(ia))
        .collect();
    for ia in &added {
        plan.changes.push(change(
            ChangeMark::Added,
            "tunnels",
            format!("tunnel address {ia} added"),
        ));
    }
    for ia in &removed {
        plan.changes.push(change(
            ChangeMark::Removed,
            "tunnels",
            format!("tunnel address {ia} removed"),
        ));
    }
    if added.is_empty() && removed.is_empty() {
        plan.changes.push(change(
            ChangeMark::Changed,
            "tunnels",
            format!(
                "tunnel slots = {}, was {}",
                join_addresses(&config.tunnels),
                join_addresses(&facts.tunnels)
            ),
        ));
    }
}

/// What [`apply_interface`] did.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InterfaceApply {
    /// The writes the device confirmed.
    pub written: usize,
    /// The write that failed, when one did (the rest were not sent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_error: Option<String>,
    /// The read-back of every planned property, and of the whole object
    /// against the model.
    pub readback: WriteReadback,
}

impl InterfaceApply {
    /// Verified: every write confirmed and read back equal, and the object
    /// read again matches the model.
    pub fn verified(&self) -> bool {
        self.write_error.is_none() && self.readback.verified
    }

    /// Why the apply did not verify, `None` when it did.
    pub fn failure(&self) -> Option<String> {
        match (&self.write_error, self.readback.failure()) {
            (Some(write), Some(left)) => Some(format!("{write}; {left}")),
            (Some(write), None) => Some(write.clone()),
            (None, left) => left,
        }
    }
}

/// Writes `plan` on the open session `l4`, then verifies it: every planned
/// property is read back and compared with the octets written (the shared
/// [`crate::verify::read_back`]), and the object is read again and planned
/// against `config`; anything left differs is a leftover. The values read
/// again are recorded with the device facts when `facts` is given. A write
/// that fails stops the sequence; the read-back still runs, so the result
/// says what the device holds.
pub async fn apply_interface<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    target: IndividualAddress,
    config: &KnxnetConfig,
    plan: &InterfacePlan,
    facts: Option<(&FactsCache, &mut Established)>,
) -> InterfaceApply {
    let mut written = 0;
    let mut write_error = None;
    for step in &plan.steps {
        let result = bussard_download::write_property_value(
            l4,
            INTERFACE_OBJECT,
            u32::from(step.prop_id),
            step.start,
            step.count,
            &step.value,
            false,
        )
        .await;
        match result {
            Ok(()) => written += 1,
            Err(err) => {
                write_error = Some(format!("writing the {}: {}", step.label, chain(&err)));
                break;
            }
        }
    }
    let expected = Expected {
        properties: plan.expected(),
        ..Expected::default()
    };
    let mut readback = crate::verify::read_back(l4, &expected).await;
    // The whole object again, against the model.
    let again = match facts {
        Some((cache, established)) => read_knxnet_with_facts(l4, cache, established).await,
        None => read_knxnet(l4, &[], false).await,
    };
    match again {
        Ok(Some(after)) => {
            let residual = plan_interface(target, config, &after, None, &SessionLink::default());
            for c in &residual.changes {
                readback.push(
                    LeftoverKind::Property,
                    c.key.clone(),
                    "differs".to_string(),
                    c.sentence.clone(),
                );
            }
        }
        Ok(None) => readback.notes.push(format!(
            "{target}'s KNXnet/IP parameter object did not answer the read after the write"
        )),
        Err(err) => readback.push(
            LeftoverKind::Readback,
            "KNXnet/IP parameter object".to_string(),
            format!("no answer ({})", chain(&err)),
            "read again after the write".to_string(),
        ),
    }
    readback.verified = readback.leftovers.is_empty();
    InterfaceApply {
        written,
        write_error,
        readback,
    }
}

/// An error and its sources, joined with `": "`.
fn chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(next) = source {
        out.push_str(": ");
        out.push_str(&next.to_string());
        source = next.source();
    }
    out
}

/// Writes the interface's values as read before an apply to
/// `<dir>/captures/backups/<ia>-knxnet-<unix seconds>.json`: what to put
/// back by hand if the new settings do not work.
///
/// # Errors
///
/// The directory or the file cannot be written.
pub fn write_interface_backup(
    dir: &std::path::Path,
    target: IndividualAddress,
    facts: &KnxnetFacts,
) -> std::io::Result<std::path::PathBuf> {
    let root = bussard_download::backup::backups_root(dir);
    std::fs::create_dir_all(&root)?;
    let stamp = bussard_download::backup::unix_seconds(std::time::SystemTime::now());
    let path = root.join(format!("{target}-knxnet-{stamp}.toml"));
    std::fs::write(&path, backup_text(target, facts))?;
    Ok(path)
}

/// The backup's text: a `[knxnet]` table of the values as read (the shape of
/// the device file, so it can be pasted back) and the facts as comments.
fn backup_text(target: IndividualAddress, facts: &KnxnetFacts) -> String {
    let mut out = format!(
        "# The KNXnet/IP parameter object of {target} before an apply, read at {}.\n\
         # Paste the table into devices/{target}.toml and apply to put it back.\n",
        facts.read_at
    );
    for (label, value) in facts.lines() {
        out.push_str(&format!("# {label}: {value}\n"));
    }
    out.push_str("\n[knxnet]\n");
    let config = facts.as_config();
    out.push_str(&format!("assignment = {:?}\n", config.assignment.label()));
    for (key, value) in [
        ("address", facts.address),
        ("netmask", facts.netmask),
        ("gateway", facts.gateway),
    ] {
        if let Some(v) = value.filter(|_| config.assignment == IpAssignment::Static) {
            out.push_str(&format!("{key} = \"{v}\"\n"));
        }
    }
    if let Some(name) = &facts.friendly_name {
        out.push_str(&format!("friendly_name = {name:?}\n"));
    }
    let tunnels: Vec<String> = facts.tunnels.iter().map(|t| format!("\"{t}\"")).collect();
    out.push_str(&format!("tunnels = [{}]\n", tunnels.join(", ")));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_facts_from_values_decodes_every_field() -> Result<(), Box<dyn std::error::Error>> {
        let values = KnxnetValues {
            individual_address: Some("1.1.200".parse()?),
            additional_addresses: vec!["1.1.22".parse()?, "1.1.23".parse()?],
            current_assignment: Some(0x04),
            assignment: Some(0x04),
            current_ip: Some([192, 168, 1, 74]),
            current_netmask: Some([255, 255, 255, 0]),
            current_gateway: Some([192, 168, 1, 1]),
            ip: Some([0, 0, 0, 0]),
            mac: Some([0x00, 0x00, 0x5E, 0x00, 0x53, 0x01]),
            routing_multicast: Some([224, 0, 23, 12]),
            capabilities: Some(0x0003),
            state: Some(0),
            friendly_name: Some("Alpha".to_string()),
            ..KnxnetValues::default()
        };
        let facts = facts_from_values(&values, Some(4), "2026-10-26T10:00:00Z".to_string());
        assert_eq!(facts.assignment_mode, Some(IpAssignment::Dhcp));
        assert_eq!(facts.current_address, Some("192.168.1.74".parse()?));
        assert_eq!(facts.mac.as_deref(), Some("00:00:5E:00:53:01"));
        assert_eq!(facts.state.as_deref(), Some("ok"));
        assert_eq!(
            facts.capabilities,
            Some(vec![
                "device management".to_string(),
                "tunnelling".to_string()
            ])
        );
        let lines = facts.lines();
        assert_eq!(lines[0], ("IP address", "192.168.1.74 (dhcp)".to_string()));
        assert!(
            lines
                .iter()
                .any(|(k, v)| *k == "tunnels" && v == "1.1.22, 1.1.23")
        );
        Ok(())
    }

    #[test]
    fn test_knxnet_object_index_finds_type_11() {
        assert_eq!(knxnet_object_index(&[(0, 0), (1, 1), (4, 11)]), Some(4));
        assert_eq!(knxnet_object_index(&[(0, 0)]), None);
    }
    fn ia(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
        Ok(s.parse()?)
    }

    /// The device as the read side decodes the house's 1.1.200: DHCP, eight
    /// tunnels, a friendly name.
    fn device() -> Result<KnxnetFacts, Box<dyn std::error::Error>> {
        Ok(KnxnetFacts {
            read_at: "2026-10-26T10:00:00Z".to_string(),
            object_index: Some(7),
            individual_address: Some(ia("1.1.200")?),
            tunnels: (22..=29)
                .map(|n| ia(&format!("1.1.{n}")))
                .collect::<Result<_, _>>()?,
            assignment: Some(vec!["dhcp".to_string()]),
            assignment_mode: Some(IpAssignment::Dhcp),
            current_address: Some(Ipv4Addr::new(192, 168, 1, 74)),
            address: Some(Ipv4Addr::UNSPECIFIED),
            netmask: Some(Ipv4Addr::UNSPECIFIED),
            gateway: Some(Ipv4Addr::UNSPECIFIED),
            friendly_name: Some("Bocklisch Alpha".to_string()),
            ..KnxnetFacts::default()
        })
    }

    fn slots(writable: bool, max: u16) -> Option<KnxnetPropertyDescription> {
        Some(KnxnetPropertyDescription {
            writable,
            max_elements: max,
        })
    }

    fn pids(plan: &InterfacePlan) -> Vec<(u8, u16, u16)> {
        plan.steps
            .iter()
            .map(|s| (s.prop_id, s.start, s.count))
            .collect()
    }

    #[test]
    fn test_plan_interface_matching_table_is_empty() -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let plan = plan_interface(
            ia("1.1.200")?,
            &facts.as_config(),
            &facts,
            slots(true, 8),
            &SessionLink::default(),
        );
        assert!(plan.is_empty(), "{plan:?}");
        assert!(plan.refusal(false).is_none());
        Ok(())
    }

    #[test]
    fn test_plan_interface_friendly_name_is_one_padded_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.friendly_name = Some("Bocklisch Beta".to_string());
        // Through this very interface: a name change does not drop the tunnel.
        let link = SessionLink {
            source: Some(ia("1.1.22")?),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 74)),
        };
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &link);
        assert_eq!(pids(&plan), [(76, 1, 30)]);
        assert_eq!(plan.steps[0].value.len(), 30);
        assert_eq!(&plan.steps[0].value[..14], b"Bocklisch Beta");
        assert!(plan.steps[0].value[14..].iter().all(|&b| b == 0));
        assert_eq!(
            plan.changes[0].sentence,
            "friendly name = \"Bocklisch Beta\", was \"Bocklisch Alpha\""
        );
        assert!(plan.self_reconfigure.is_none());
        assert!(plan.refusal(false).is_none());
        Ok(())
    }

    #[test]
    fn test_plan_interface_absent_friendly_name_is_left_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.friendly_name = None;
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &Default::default());
        assert!(plan.is_empty());
        Ok(())
    }

    #[test]
    fn test_plan_interface_same_count_tunnels_is_one_array_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.tunnels[7] = ia("1.1.30")?;
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &Default::default());
        assert_eq!(pids(&plan), [(53, 1, 8)]);
        assert_eq!(&plan.steps[0].value[14..], &[0x11, 0x1E]);
        let lines: Vec<String> = plan.changes.iter().map(PlanChange::line).collect();
        assert_eq!(
            lines,
            [
                "+ tunnel address 1.1.30 added",
                "- tunnel address 1.1.29 removed"
            ]
        );
        Ok(())
    }

    #[test]
    fn test_plan_interface_tunnel_count_change_follows_the_description()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.tunnels.truncate(4);
        let target = ia("1.1.200")?;
        let link = SessionLink::default();
        let plan = plan_interface(target, &config, &facts, slots(true, 8), &link);
        assert_eq!(pids(&plan), [(53, 0, 1), (53, 1, 4)]);
        assert_eq!(plan.steps[0].value, [0, 4]);
        assert_eq!(plan.changes.len(), 4, "four addresses removed");
        // More than the device holds, no description, or read-only: refused.
        config.tunnels = (22..=30)
            .map(|n| ia(&format!("1.1.{n}")))
            .collect::<Result<_, _>>()?;
        let plan = plan_interface(target, &config, &facts, slots(true, 8), &link);
        assert!(plan.steps.is_empty());
        assert!(plan.refusal(true).is_some_and(|r| r.contains("at most 8")));
        let plan = plan_interface(target, &config, &facts, None, &link);
        assert!(
            plan.refusal(true)
                .is_some_and(|r| r.contains("list exactly 8"))
        );
        config.tunnels.truncate(8);
        config.tunnels[0] = ia("1.1.31")?;
        let plan = plan_interface(target, &config, &facts, slots(false, 8), &link);
        assert!(plan.refusal(true).is_some_and(|r| r.contains("read-only")));
        Ok(())
    }

    #[test]
    fn test_plan_interface_empty_tunnel_list_leaves_the_device_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.tunnels.clear();
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &Default::default());
        assert!(plan.steps.is_empty());
        assert!(plan.notes[0].contains("stay as they are"));
        Ok(())
    }

    #[test]
    fn test_plan_interface_static_set_then_assignment_last()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.assignment = IpAssignment::Static;
        config.address = Some(Ipv4Addr::new(192, 168, 1, 80));
        config.netmask = Some(Ipv4Addr::new(255, 255, 255, 0));
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &Default::default());
        assert_eq!(pids(&plan), [(60, 1, 1), (61, 1, 1), (55, 1, 1)]);
        assert_eq!(plan.steps[0].value, [192, 168, 1, 80]);
        assert_eq!(plan.steps[2].value, [0x01]);
        assert!(
            plan.self_reconfigure.is_none(),
            "not the session's interface"
        );
        Ok(())
    }

    #[test]
    fn test_plan_interface_dhcp_with_autoip_is_no_change() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut facts = device()?;
        facts.assignment = Some(vec!["dhcp".to_string(), "autoip".to_string()]);
        let plan = plan_interface(
            ia("1.1.200")?,
            &facts.as_config(),
            &facts,
            None,
            &Default::default(),
        );
        assert!(plan.is_empty());
        Ok(())
    }

    #[test]
    fn test_plan_interface_self_reconfigure_is_refused_unless_allowed()
    -> Result<(), Box<dyn std::error::Error>> {
        let facts = device()?;
        let mut config = facts.as_config();
        config.assignment = IpAssignment::Static;
        config.address = Some(Ipv4Addr::new(192, 168, 1, 80));
        config.netmask = Some(Ipv4Addr::new(255, 255, 255, 0));
        let by_ip = SessionLink {
            source: None,
            gateway: SessionLink::gateway_of("192.168.1.74:3671"),
        };
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &by_ip);
        let why = plan.refusal(false).ok_or("refused")?;
        assert!(why.contains("tunnel drops"), "{why}");
        assert!(why.contains("--allow-self-reconfigure"), "{why}");
        assert!(plan.refusal(true).is_none());
        // Any tunnel rewrite on the session's interface, too, even of a slot
        // the session does not use: the interface may drop its tunnels.
        let mut config = facts.as_config();
        config.tunnels[7] = ia("1.1.30")?;
        let by_source = SessionLink {
            source: Some(ia("1.1.22")?),
            gateway: None,
        };
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &by_source);
        let why = plan.refusal(false).ok_or("refused")?;
        assert!(why.contains("PID 53"), "{why}");
        assert!(why.contains("may drop its open tunnels"), "{why}");
        assert!(plan.refusal(true).is_none());
        // Another interface: the same rewrite is allowed.
        let elsewhere = SessionLink {
            source: Some(ia("1.1.255")?),
            gateway: Some(Ipv4Addr::LOCALHOST),
        };
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &elsewhere);
        assert!(plan.refusal(false).is_none());
        // The friendly name alone stays allowed through it.
        let mut config = facts.as_config();
        config.friendly_name = Some("Beta".to_string());
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &by_source);
        assert!(plan.refusal(false).is_none());
        Ok(())
    }

    #[test]
    fn test_plan_interface_unserved_property_is_refused() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut facts = device()?;
        facts.friendly_name = None;
        facts.assignment = None;
        facts.assignment_mode = None;
        let mut config = facts.as_config();
        config.friendly_name = Some("Alpha".to_string());
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &Default::default());
        assert!(plan.steps.is_empty());
        assert!(plan.refusal(false).is_some_and(|r| r.contains("PID 76")));
        assert!(plan.notes.iter().any(|n| n.contains("PID 55")));
        Ok(())
    }

    #[test]
    fn test_interface_plan_device_plan_renders_the_writes() -> Result<(), Box<dyn std::error::Error>>
    {
        let facts = device()?;
        let mut config = facts.as_config();
        config.friendly_name = Some("Beta".to_string());
        let plan = plan_interface(ia("1.1.200")?, &config, &facts, None, &Default::default());
        let text = plan
            .device_plan(ia("1.1.200")?, "KNX IP Interface", "gw", "b".to_string())
            .render_text();
        assert_eq!(
            text,
            "1.1.200 KNX IP Interface\n  ~ friendly name = \"Beta\", was \"Bocklisch Alpha\"\n  \
             writes: KNXnet/IP parameter object (PID 76)\n  backup: b\n"
        );
        assert_eq!(
            plan.steps[0].wire(),
            "object type 11 instance 1 PID 76 start 1 count 30: 42 65 74 61 00 00 00 00 00 00 00 \
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        );
        Ok(())
    }

    #[test]
    fn test_session_link_gateway_of_parses_host_and_port() {
        assert_eq!(
            SessionLink::gateway_of("192.168.1.74:3671"),
            Some(Ipv4Addr::new(192, 168, 1, 74))
        );
        assert_eq!(
            SessionLink::gateway_of("127.0.0.1"),
            Some(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(SessionLink::gateway_of("routing"), None);
    }

    /// A mock IP interface at 1.1.200 that takes writes (listed at an index,
    /// or by object type only as the IPS 300 SREG), read, planned against
    /// `config`, applied, and planned again. Returns the second plan, the
    /// apply result and the device as it ends up.
    async fn round_trip(
        listed: bool,
        config: &KnxnetConfig,
    ) -> Result<
        (InterfacePlan, InterfaceApply, bussard_testkit::MockDevice),
        Box<dyn std::error::Error>,
    > {
        let target = ia("1.1.200")?;
        let knxnet = bussard_testkit::MockKnxnet {
            tunnels: (22..=29)
                .map(|n| ia(&format!("1.1.{n}")))
                .collect::<Result<_, _>>()?,
            friendly_name: "Bocklisch Alpha".to_string(),
            ..bussard_testkit::MockKnxnet::default()
        };
        let device = bussard_testkit::MockDevice::new(target).with_mask(0x0021);
        let device = if listed {
            device.with_knxnet_writable(&knxnet, 8)
        } else {
            device.with_knxnet_unlisted_writable(&knxnet, 8)
        };
        let gw = bussard_testkit::MockGateway::builder()
            .device(device)
            .start()
            .await?;
        let mut bus = bussard_transport::Transport::connect(
            &bussard_transport::ConnectionConfig::tunnel(gw.addr()),
        )
        .await?;
        let mut l4 = Layer4Connection::connect(
            &mut bus,
            target,
            "0.0.255".parse()?,
            bussard_mgmt::ConnectOptions::default(),
        )
        .await?;
        let cache = FactsCache::disabled();
        let mut read = read_interface(&mut l4, &cache, None).await?;
        let facts = read.knxnet.clone().ok_or("the mock serves the object")?;
        assert_eq!(facts.object_index.is_some(), listed);
        assert_eq!(read.tunnel_slots.map(|d| d.max_elements), Some(8));
        let plan = plan_interface(
            target,
            config,
            &facts,
            read.tunnel_slots,
            &SessionLink::default(),
        );
        assert!(!plan.steps.is_empty());
        let applied = apply_interface(
            &mut l4,
            target,
            config,
            &plan,
            Some((&cache, &mut read.established)),
        )
        .await;
        let again = read_interface(&mut l4, &cache, None).await?;
        let after = again.knxnet.ok_or("read again")?;
        let replan = plan_interface(
            target,
            config,
            &after,
            again.tunnel_slots,
            &SessionLink::default(),
        );
        let _ = l4.disconnect().await;
        let device = gw.devices()?.into_iter().next().ok_or("the mock device")?;
        Ok((replan, applied, device))
    }

    fn changed_config() -> Result<KnxnetConfig, Box<dyn std::error::Error>> {
        Ok(KnxnetConfig {
            assignment: IpAssignment::Static,
            address: Some(Ipv4Addr::new(192, 168, 1, 80)),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            friendly_name: Some("Bocklisch Beta".to_string()),
            tunnels: (22..=27)
                .map(|n| ia(&format!("1.1.{n}")))
                .collect::<Result<_, _>>()?,
        })
    }

    #[tokio::test]
    async fn test_apply_interface_by_index_then_plan_is_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = changed_config()?;
        let (replan, applied, device) = round_trip(true, &config).await?;
        assert!(applied.verified(), "{:?}", applied.failure());
        assert!(replan.is_empty(), "{replan:?}");
        assert_eq!(device.knxnet_property(55), Some(&[0x01][..]));
        assert_eq!(device.knxnet_property(60), Some(&[192, 168, 1, 80][..]));
        assert_eq!(device.knxnet_property(53).map(<[u8]>::len), Some(12));
        Ok(())
    }

    #[tokio::test]
    async fn test_apply_interface_by_type_then_plan_is_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = changed_config()?;
        let (replan, applied, device) = round_trip(false, &config).await?;
        assert!(applied.verified(), "{:?}", applied.failure());
        assert!(replan.is_empty(), "{replan:?}");
        let name = device.knxnet_property(76).ok_or("PID 76")?;
        assert_eq!(
            bussard_mgmt::knxnet::decode_friendly_name(name),
            "Bocklisch Beta"
        );
        // Nothing at or above the first KNXnet/IP Secure PID was asked for.
        assert!(
            device
                .ext_reads
                .iter()
                .all(|(pid, _, _)| *pid < u16::from(bussard_mgmt::knxnet::FIRST_SECURE_PID))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_apply_interface_reports_a_value_the_device_did_not_take()
    -> Result<(), Box<dyn std::error::Error>> {
        // A device that confirms PID 76 but keeps its old name: never verified.
        let target = ia("1.1.200")?;
        let knxnet = bussard_testkit::MockKnxnet::default();
        let device = bussard_testkit::MockDevice::new(target)
            .with_knxnet_writable(&knxnet, 2)
            .with_hook(|_, apci, data| {
                (apci == 0x1CE && data.get(4) == Some(&76)).then(|| {
                    let mut out = data[..8].to_vec();
                    out.push(0);
                    bussard_testkit::Reaction::Answer(0x1CF, out)
                })
            });
        let gw = bussard_testkit::MockGateway::builder()
            .device(device)
            .start()
            .await?;
        let mut bus = bussard_transport::Transport::connect(
            &bussard_transport::ConnectionConfig::tunnel(gw.addr()),
        )
        .await?;
        let mut l4 = Layer4Connection::connect(
            &mut bus,
            target,
            "0.0.255".parse()?,
            bussard_mgmt::ConnectOptions::default(),
        )
        .await?;
        let read = read_interface(&mut l4, &FactsCache::disabled(), None).await?;
        let facts = read.knxnet.ok_or("object")?;
        let mut config = facts.as_config();
        config.friendly_name = Some("Beta".to_string());
        let plan = plan_interface(target, &config, &facts, None, &SessionLink::default());
        let applied = apply_interface(&mut l4, target, &config, &plan, None).await;
        let _ = l4.disconnect().await;
        assert_eq!(applied.written, 1, "the device confirmed the write");
        assert!(!applied.verified());
        let failure = applied.failure().ok_or("a failure")?;
        assert!(failure.contains("PID 76"), "{failure}");
        Ok(())
    }
}
