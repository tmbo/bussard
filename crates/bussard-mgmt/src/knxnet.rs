//! Reads of the KNXnet/IP parameter object (interface object type 11) of a KNX
//! IP interface or router (issue #391): its individual address, the tunnelling
//! slots (additional individual addresses), the IP assignment method, the
//! current and configured IP settings, the MAC address, the multicast settings,
//! the device capabilities and state, and the friendly name.
//!
//! # Property ids
//!
//! CONFIRMED against the KNX master data an ETS 6 export ships
//! (`knx_master.xml`, `<InterfaceObjectType Id="OT-11" Number="11"
//! Name="OT_KNXIP_PARAMETER">` and its `<InterfaceObjectProperty
//! ObjectType="OT-11">` rows, export of 2026-10-26): id, name and property
//! data type of every PID below. The value encodings (the assignment-method
//! bits, the capability and state bits) follow the published KNX standard,
//! volume 3/8/3 "KNXnet/IP Device Management", section "KNXnet/IP Parameter
//! Object". `docs/` holds no spec text for this object.
//!
//! PIDs 91 and up (`PID_BACKBONE_KEY`, `PID_DEVICE_AUTHENTICATION_CODE`,
//! `PID_PASSWORD_HASHES`, …) belong to KNXnet/IP Secure. Nothing here reads
//! them, and [`read_knxnet_parameters`] refuses to: they are key material.
//!
//! # Addressing
//!
//! [`KnxnetAccess::Index`] reads with the plain `A_PropertyValue_Read` on the
//! object's index (from the object table every device with interface objects
//! answers); [`KnxnetAccess::Ext`] reads with `A_PropertyExtValue_Read` by
//! object type 11 and instance, for a device whose object-index walk does not
//! list the object (the Jung IPS 300 SREG, mask 0021, issue #391). Both return
//! the same octets. [`probe_knxnet_ext`] and [`knxnet_index_from_io_list`]
//! find the object when the walk does not.
//!
//! The module never sends a write. The write side of the object (issue #391,
//! `plan`/`apply` of the `[knxnet]` table) goes through the property step
//! executor every load procedure shares (`bussard_download::write_property_value`);
//! [`describe_knxnet_property`] gives it the device's own description of a
//! property (writable, maximum element count) before it plans an array write.

use std::time::Duration;

use bussard_model::IndividualAddress;

use crate::connection::{L4Channel, Layer4Connection};
use crate::error::{MgmtError, Result, SilenceKind};
use crate::property_ext::{
    PropertyExtAddress, read_property_ext, read_property_ext_description, read_property_ext_table,
};

/// The KNXnet/IP parameter object (`OT_KNXIP_PARAMETER`, knx_master.xml `OT-11`).
pub const OT_KNXNET_IP_PARAMETER: u16 = 11;

/// `PID_PROJECT_INSTALLATION_ID` (51, PDT_UNSIGNED_INT): the project and
/// installation number (KNX 3/8/3). ETS writes it on an IP-enabled device's
/// download (issue #455).
pub const PID_PROJECT_INSTALLATION_ID: u8 = 51;
/// `PID_KNX_INDIVIDUAL_ADDRESS` (52, PDT_UNSIGNED_INT): the interface's own address.
pub const PID_KNX_INDIVIDUAL_ADDRESS: u8 = 52;
/// `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES` (53, PDT_UNSIGNED_INT array): the
/// tunnelling slots.
pub const PID_ADDITIONAL_INDIVIDUAL_ADDRESSES: u8 = 53;
/// `PID_CURRENT_IP_ASSIGNMENT_METHOD` (54, PDT_UNSIGNED_CHAR).
pub const PID_CURRENT_IP_ASSIGNMENT_METHOD: u8 = 54;
/// `PID_IP_ASSIGNMENT_METHOD` (55, PDT_UNSIGNED_CHAR): the configured method.
pub const PID_IP_ASSIGNMENT_METHOD: u8 = 55;
/// `PID_CURRENT_IP_ADDRESS` (57, PDT_UNSIGNED_LONG).
pub const PID_CURRENT_IP_ADDRESS: u8 = 57;
/// `PID_CURRENT_SUBNET_MASK` (58, PDT_UNSIGNED_LONG).
pub const PID_CURRENT_SUBNET_MASK: u8 = 58;
/// `PID_CURRENT_DEFAULT_GATEWAY` (59, PDT_UNSIGNED_LONG).
pub const PID_CURRENT_DEFAULT_GATEWAY: u8 = 59;
/// `PID_IP_ADDRESS` (60, PDT_UNSIGNED_LONG): the configured static address.
pub const PID_IP_ADDRESS: u8 = 60;
/// `PID_SUBNET_MASK` (61, PDT_UNSIGNED_LONG): the configured static netmask.
pub const PID_SUBNET_MASK: u8 = 61;
/// `PID_DEFAULT_GATEWAY` (62, PDT_UNSIGNED_LONG): the configured static gateway.
pub const PID_DEFAULT_GATEWAY: u8 = 62;
/// `PID_MAC_ADDRESS` (64, PDT_GENERIC_06).
pub const PID_MAC_ADDRESS: u8 = 64;
/// `PID_SYSTEM_SETUP_MULTICAST_ADDRESS` (65, PDT_UNSIGNED_LONG).
pub const PID_SYSTEM_SETUP_MULTICAST_ADDRESS: u8 = 65;
/// `PID_ROUTING_MULTICAST_ADDRESS` (66, PDT_UNSIGNED_LONG).
pub const PID_ROUTING_MULTICAST_ADDRESS: u8 = 66;
/// `PID_TTL` (67, PDT_UNSIGNED_CHAR).
pub const PID_TTL: u8 = 67;
/// `PID_KNXNETIP_DEVICE_CAPABILITIES` (68, PDT_BITSET16).
pub const PID_KNXNETIP_DEVICE_CAPABILITIES: u8 = 68;
/// `PID_KNXNETIP_DEVICE_STATE` (69, PDT_UNSIGNED_CHAR).
pub const PID_KNXNETIP_DEVICE_STATE: u8 = 69;
/// `PID_FRIENDLY_NAME` (76, PDT_UNSIGNED_CHAR array of 30): ISO 8859-1,
/// padded with NUL.
pub const PID_FRIENDLY_NAME: u8 = 76;
/// The first KNXnet/IP Secure PID (`PID_BACKBONE_KEY`, 91). This module never
/// reads it or anything above it.
pub const FIRST_SECURE_PID: u8 = 91;

/// The length of `PID_FRIENDLY_NAME` in octets.
pub const FRIENDLY_NAME_OCTETS: usize = 30;

/// The octets of the plain property response header besides the data: the low
/// APCI octet, object index, PID and the count/start word.
const PLAIN_READ_OVERHEAD: u16 = 5;

/// The most elements a plain property read asks for (4-bit count).
const PLAIN_MAX_COUNT: usize = 15;

/// How the KNXnet/IP parameter object is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnxnetAccess {
    /// The plain property services on this object index.
    Index(u8),
    /// The extended property services on object type 11, this instance.
    Ext {
        /// The 1-based instance.
        instance: u16,
    },
}

impl std::fmt::Display for KnxnetAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnxnetAccess::Index(i) => write!(f, "object {i}"),
            KnxnetAccess::Ext { instance } => {
                write!(
                    f,
                    "object type {OT_KNXNET_IP_PARAMETER} instance {instance}"
                )
            }
        }
    }
}

/// The values read from the KNXnet/IP parameter object. A property the device
/// does not serve (it answered zero elements) is `None` (or empty).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnxnetValues {
    /// PID 52.
    pub individual_address: Option<IndividualAddress>,
    /// PID 53, in slot order.
    pub additional_addresses: Vec<IndividualAddress>,
    /// PID 54, the raw method bits.
    pub current_assignment: Option<u8>,
    /// PID 55, the raw method bits.
    pub assignment: Option<u8>,
    /// PID 57.
    pub current_ip: Option<[u8; 4]>,
    /// PID 58.
    pub current_netmask: Option<[u8; 4]>,
    /// PID 59.
    pub current_gateway: Option<[u8; 4]>,
    /// PID 60.
    pub ip: Option<[u8; 4]>,
    /// PID 61.
    pub netmask: Option<[u8; 4]>,
    /// PID 62.
    pub gateway: Option<[u8; 4]>,
    /// PID 64.
    pub mac: Option<[u8; 6]>,
    /// PID 65.
    pub system_setup_multicast: Option<[u8; 4]>,
    /// PID 66.
    pub routing_multicast: Option<[u8; 4]>,
    /// PID 67.
    pub ttl: Option<u8>,
    /// PID 68, the raw bits.
    pub capabilities: Option<u16>,
    /// PID 69, the raw bits.
    pub state: Option<u8>,
    /// PID 76, decoded from ISO 8859-1 with the NUL padding removed.
    pub friendly_name: Option<String>,
}

/// Reads one property of the KNXnet/IP parameter object: `elem_size`-octet
/// elements, all of them for an array (`array`), element 1 otherwise. `None`
/// when the device does not serve it (zero elements).
///
/// # Errors
///
/// A transport failure or a malformed response. A PID of
/// [`FIRST_SECURE_PID`] or above is refused before anything is sent.
pub async fn read_knxnet_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    access: KnxnetAccess,
    pid: u8,
    elem_size: usize,
    array: bool,
) -> Result<Option<Vec<u8>>> {
    if pid >= FIRST_SECURE_PID {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "PID {pid} of the KNXnet/IP parameter object is KNXnet/IP Secure key material; \
                 bussard does not read it"
            ),
        });
    }
    match access {
        KnxnetAccess::Index(index) => plain_read(l4, index, pid, elem_size, array).await,
        KnxnetAccess::Ext { instance } => {
            let addr = PropertyExtAddress {
                object_type: OT_KNXNET_IP_PARAMETER,
                object_instance: instance,
                property_id: u16::from(pid),
            };
            let before = l4.numbered_exchanges();
            let result = if array {
                read_property_ext_table(l4, addr, elem_size).await
            } else {
                read_property_ext(l4, addr, 1, 1).await.map(|v| v.data)
            };
            match result {
                Ok(data) if data.is_empty() && !array => Ok(None),
                Ok(data) => Ok(Some(data)),
                Err(MgmtError::ServiceRejected { .. }) => Ok(None),
                // T_ACKed but never answered: the property is not served, and
                // the connection stays usable (as `authorize` treats it).
                Err(err) if acked_but_unanswered(l4, before, &err) => {
                    l4.reopen_after_unanswered();
                    Ok(None)
                }
                Err(err) => Err(err),
            }
        }
    }
}

/// What a device says about one property of its KNXnet/IP parameter object
/// (`A_PropertyDescription_Read` by index, `A_PropertyExtDescription_Read` by
/// object type): whether it takes writes and how many elements it holds at
/// most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnxnetPropertyDescription {
    /// The write-enable bit.
    pub writable: bool,
    /// The maximum number of elements (the array capacity).
    pub max_elements: u16,
}

/// Reads the description of `pid` of the KNXnet/IP parameter object. `None`
/// when the device does not describe it: a zero-element description, a
/// refusal, or a request it acknowledges and leaves unanswered (the
/// connection stays usable). Read under [`PROBE_RESPONSE_TIMEOUT`].
///
/// # Errors
///
/// A transport failure. A PID of [`FIRST_SECURE_PID`] or above is refused
/// before anything is sent.
pub async fn describe_knxnet_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    access: KnxnetAccess,
    pid: u8,
) -> Result<Option<KnxnetPropertyDescription>> {
    if pid >= FIRST_SECURE_PID {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "PID {pid} of the KNXnet/IP parameter object is KNXnet/IP Secure; bussard does \
                 not touch it"
            ),
        });
    }
    with_probe_timeout(l4, async |l4| {
        let before = l4.numbered_exchanges();
        let answer = match access {
            KnxnetAccess::Index(index) => {
                crate::connection::property_description_request(l4, index, pid, 0)
                    .await
                    .map(|d| {
                        (d.property_id == pid).then_some(KnxnetPropertyDescription {
                            writable: d.writable,
                            max_elements: d.max_elements,
                        })
                    })
            }
            KnxnetAccess::Ext { instance } => {
                let addr = PropertyExtAddress {
                    object_type: OT_KNXNET_IP_PARAMETER,
                    object_instance: instance,
                    property_id: u16::from(pid),
                };
                read_property_ext_description(l4, addr, 0).await.map(|d| {
                    (d.addr.property_id == u16::from(pid)).then_some(KnxnetPropertyDescription {
                        writable: d.write_enable,
                        max_elements: d.max_elements,
                    })
                })
            }
        };
        match answer {
            Ok(desc) => Ok(desc.filter(|d| d.max_elements > 0)),
            Err(MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. }) => {
                Ok(None)
            }
            Err(err) if acked_but_unanswered(l4, before, &err) => {
                l4.reopen_after_unanswered();
                Ok(None)
            }
            Err(err) => Err(err),
        }
    })
    .await
}

/// How long a probe for the KNXnet/IP parameter object waits for an answer.
/// A device that serves the object answers a property read within a few
/// hundred milliseconds (about 200 ms per request on the Data Secure devices
/// of the speed deep dive of 2026-09-24, the figure the testkit's
/// `response_delay` models); one that does not implement the extended
/// property services `T_ACK`s the request and stays silent (knx-sim models
/// that, the plain-device branch of its extended-service handler), so the
/// probe would otherwise cost the full 3 s response timeout.
pub const PROBE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Whether `err` is a request the device `T_ACK`ed (the exchange counter moved
/// past `before`) but never answered: the peer is alive and the sequence
/// numbers agree, so the connection can be reopened.
fn acked_but_unanswered<Ch: L4Channel>(
    l4: &Layer4Connection<Ch>,
    before: u32,
    err: &MgmtError,
) -> bool {
    matches!(
        err,
        MgmtError::NoResponse { .. }
            | MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }
    ) && l4.numbered_exchanges() > before
}

/// Runs `f` with the connection's response timeout shortened to
/// [`PROBE_RESPONSE_TIMEOUT`] (never lengthened), restoring it afterwards.
pub async fn with_probe_timeout<Ch: L4Channel, T>(
    l4: &mut Layer4Connection<Ch>,
    f: impl AsyncFnOnce(&mut Layer4Connection<Ch>) -> T,
) -> T {
    let saved = l4.timeouts();
    let mut short = saved;
    short.response_timeout = saved.response_timeout.min(PROBE_RESPONSE_TIMEOUT);
    l4.set_timeouts(short);
    let out = f(l4).await;
    l4.set_timeouts(saved);
    out
}

/// Probes for the KNXnet/IP parameter object by type and instance: one
/// `A_PropertyExtValue_Read` of `PID_KNX_INDIVIDUAL_ADDRESS` (52), element 1,
/// under [`PROBE_RESPONSE_TIMEOUT`]. `true` when the device answers with the
/// value. A zero-count answer, an off-service answer, or a request the device
/// `T_ACK`s and leaves unanswered is `false`, and the connection stays usable.
///
/// This is how a KNX IP interface whose object-index walk does not list the
/// object is found: the Jung IPS 300 SREG (mask 0021) answers the walk with a
/// device object and an address table only, while ETS writes its KNXnet/IP
/// parameters by object type 11 (`LdCtrlWriteProp ObjType="11"`).
///
/// # Errors
///
/// A transport failure, or a device that did not even `T_ACK` the request.
pub async fn probe_knxnet_ext<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    instance: u16,
) -> Result<bool> {
    let addr = PropertyExtAddress {
        object_type: OT_KNXNET_IP_PARAMETER,
        object_instance: instance,
        property_id: u16::from(PID_KNX_INDIVIDUAL_ADDRESS),
    };
    with_probe_timeout(l4, async |l4| {
        let before = l4.numbered_exchanges();
        match read_property_ext(l4, addr, 1, 1).await {
            Ok(v) => Ok(v.count >= 1 && v.data.len() >= 2),
            Err(MgmtError::ServiceRejected { .. } | MgmtError::MalformedResponse { .. }) => {
                Ok(false)
            }
            Err(err) if acked_but_unanswered(l4, before, &err) => {
                l4.reopen_after_unanswered();
                Ok(false)
            }
            Err(err) => Err(err),
        }
    })
    .await
}

/// The index of the KNXnet/IP parameter object as the device object's
/// `PID_IO_LIST` (71) lists it, when the device offers the list, lists object
/// type 11, and that index answers a plain read of
/// `PID_KNX_INDIVIDUAL_ADDRESS`. A second source next to the
/// `PID_OBJECT_TYPE` walk, for a device whose walk stops early. Read under
/// [`PROBE_RESPONSE_TIMEOUT`]; any refusal or silence is `None`.
///
/// # Errors
///
/// A transport failure.
pub async fn knxnet_index_from_io_list<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<u8>> {
    with_probe_timeout(l4, async |l4| {
        let Some(types) = crate::io_list::read_io_list(l4).await? else {
            return Ok(None);
        };
        let Some(position) = types.iter().position(|&t| t == OT_KNXNET_IP_PARAMETER) else {
            return Ok(None);
        };
        let Ok(index) = u8::try_from(position) else {
            return Ok(None);
        };
        let before = l4.numbered_exchanges();
        match checked_plain(l4, index, PID_KNX_INDIVIDUAL_ADDRESS, 1, 1).await {
            Ok(resp) if resp.count >= 1 && resp.data.len() >= 2 => Ok(Some(index)),
            Ok(_) | Err(MgmtError::MalformedResponse { .. }) => Ok(None),
            Err(err) if acked_but_unanswered(l4, before, &err) => {
                l4.reopen_after_unanswered();
                Ok(None)
            }
            Err(err) => Err(err),
        }
    })
    .await
}

/// A plain `A_PropertyValue_Read` of one property: element 1 for a scalar;
/// the count (element 0) and then the elements in chunks sized to the APDU
/// budget for an array. A chunk the device refuses is retried at half the
/// size down to one element.
async fn plain_read<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    index: u8,
    pid: u8,
    elem_size: usize,
    array: bool,
) -> Result<Option<Vec<u8>>> {
    let elem_size = elem_size.max(1);
    if !array {
        let resp = checked_plain(l4, index, pid, 1, 1).await?;
        if resp.count == 0 || resp.data.len() < elem_size {
            return Ok(None);
        }
        return Ok(Some(resp.data[..elem_size].to_vec()));
    }
    let head = checked_plain(l4, index, pid, 0, 1).await?;
    let count = match head.data.as_slice() {
        _ if head.count == 0 => return Ok(None),
        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
        [b] => u16::from(*b),
        [] => return Ok(None),
    };
    let budget = usize::from(l4.effective_max_apdu().saturating_sub(PLAIN_READ_OVERHEAD));
    let mut chunk = (budget / elem_size).clamp(1, PLAIN_MAX_COUNT);
    let mut out = Vec::with_capacity(usize::from(count) * elem_size);
    let mut next: u16 = 1;
    while next <= count {
        let remaining = usize::from(count - next) + 1;
        let want = chunk.min(remaining).max(1);
        // `want` is at most PLAIN_MAX_COUNT.
        let want_u8 = u8::try_from(want).unwrap_or(1);
        let resp = checked_plain(l4, index, pid, next, want_u8).await?;
        let got = usize::from(resp.count).min(want);
        if got == 0 || resp.data.len() < got * elem_size {
            if want > 1 {
                chunk = want / 2;
                continue;
            }
            return Err(MgmtError::MalformedResponse {
                address: l4.target(),
                reason: format!(
                    "object {index} PID {pid} element {next}: {} octet(s) for {got} element(s)",
                    resp.data.len()
                ),
            });
        }
        out.extend_from_slice(&resp.data[..got * elem_size]);
        // `got` is at most 15.
        next = next.saturating_add(u16::try_from(got).unwrap_or(1));
    }
    Ok(Some(out))
}

/// One plain property read whose echoed object, PID and start are checked.
async fn checked_plain<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    index: u8,
    pid: u8,
    start: u16,
    count: u8,
) -> Result<crate::apci::PropertyValueResponse> {
    let resp = crate::connection::property_request(l4, index, pid, start, count).await?;
    if resp.object_index != index || resp.property_id != pid || resp.start != start {
        return Err(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "A_PropertyValue_Response for object {} PID {} start {} does not answer object \
                 {index} PID {pid} start {start}",
                resp.object_index, resp.property_id, resp.start
            ),
        });
    }
    Ok(resp)
}

/// Reads every property of the KNXnet/IP parameter object this module knows
/// (PIDs 52 to 76, never a KNXnet/IP Secure PID). A property the device does
/// not serve stays unset.
///
/// # Errors
///
/// A transport failure or a malformed response; the read stops there.
pub async fn read_knxnet_parameters<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    access: KnxnetAccess,
) -> Result<KnxnetValues> {
    let mut v = KnxnetValues::default();
    if let Some(d) = read_knxnet_property(l4, access, PID_KNX_INDIVIDUAL_ADDRESS, 2, false).await? {
        v.individual_address = ia_of(&d);
    }
    if let Some(d) =
        read_knxnet_property(l4, access, PID_ADDITIONAL_INDIVIDUAL_ADDRESSES, 2, true).await?
    {
        v.additional_addresses = d
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| IndividualAddress::from_raw(u16::from_be_bytes(*c)))
            .collect();
    }
    v.current_assignment = byte(l4, access, PID_CURRENT_IP_ASSIGNMENT_METHOD).await?;
    v.assignment = byte(l4, access, PID_IP_ASSIGNMENT_METHOD).await?;
    v.current_ip = quad(l4, access, PID_CURRENT_IP_ADDRESS).await?;
    v.current_netmask = quad(l4, access, PID_CURRENT_SUBNET_MASK).await?;
    v.current_gateway = quad(l4, access, PID_CURRENT_DEFAULT_GATEWAY).await?;
    v.ip = quad(l4, access, PID_IP_ADDRESS).await?;
    v.netmask = quad(l4, access, PID_SUBNET_MASK).await?;
    v.gateway = quad(l4, access, PID_DEFAULT_GATEWAY).await?;
    v.mac = read_knxnet_property(l4, access, PID_MAC_ADDRESS, 6, false)
        .await?
        .and_then(|d| <[u8; 6]>::try_from(d.get(..6)?).ok());
    v.system_setup_multicast = quad(l4, access, PID_SYSTEM_SETUP_MULTICAST_ADDRESS).await?;
    v.routing_multicast = quad(l4, access, PID_ROUTING_MULTICAST_ADDRESS).await?;
    v.ttl = byte(l4, access, PID_TTL).await?;
    v.capabilities = read_knxnet_property(l4, access, PID_KNXNETIP_DEVICE_CAPABILITIES, 2, false)
        .await?
        .and_then(|d| Some(u16::from_be_bytes([*d.first()?, *d.get(1)?])));
    v.state = byte(l4, access, PID_KNXNETIP_DEVICE_STATE).await?;
    v.friendly_name = read_knxnet_property(l4, access, PID_FRIENDLY_NAME, 1, true)
        .await?
        .map(|d| decode_friendly_name(&d));
    Ok(v)
}

/// A one-octet property.
async fn byte<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    access: KnxnetAccess,
    pid: u8,
) -> Result<Option<u8>> {
    Ok(read_knxnet_property(l4, access, pid, 1, false)
        .await?
        .and_then(|d| d.first().copied()))
}

/// A four-octet property (an IPv4 address).
async fn quad<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    access: KnxnetAccess,
    pid: u8,
) -> Result<Option<[u8; 4]>> {
    Ok(read_knxnet_property(l4, access, pid, 4, false)
        .await?
        .and_then(|d| <[u8; 4]>::try_from(d.get(..4)?).ok()))
}

/// An individual address from two octets.
fn ia_of(d: &[u8]) -> Option<IndividualAddress> {
    Some(IndividualAddress::from_raw(u16::from_be_bytes([
        *d.first()?,
        *d.get(1)?,
    ])))
}

/// Decodes `PID_FRIENDLY_NAME`: ISO 8859-1 octets, cut at the first NUL.
pub fn decode_friendly_name(octets: &[u8]) -> String {
    octets
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect()
}

/// Encodes a friendly name as `PID_FRIENDLY_NAME` octets: ISO 8859-1, padded
/// with NUL to [`FRIENDLY_NAME_OCTETS`]. `None` when a character is outside
/// ISO 8859-1 or the name is longer than 30 characters.
pub fn encode_friendly_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(FRIENDLY_NAME_OCTETS);
    for c in name.chars() {
        out.push(u8::try_from(u32::from(c)).ok()?);
    }
    if out.len() > FRIENDLY_NAME_OCTETS {
        return None;
    }
    out.resize(FRIENDLY_NAME_OCTETS, 0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_friendly_name_pads_and_round_trips() -> std::result::Result<(), String> {
        let octets = encode_friendly_name("Bocklisch Alpha").ok_or("encodes")?;
        assert_eq!(octets.len(), FRIENDLY_NAME_OCTETS);
        assert_eq!(&octets[..3], b"Boc");
        assert_eq!(octets[15], 0);
        assert_eq!(decode_friendly_name(&octets), "Bocklisch Alpha");
        assert_eq!(
            decode_friendly_name(&encode_friendly_name("Küche").ok_or("latin-1")?),
            "Küche"
        );
        Ok(())
    }

    #[test]
    fn test_encode_friendly_name_refuses_long_or_wide() {
        assert!(encode_friendly_name(&"x".repeat(31)).is_none());
        assert!(encode_friendly_name("€uro").is_none());
        assert!(encode_friendly_name(&"x".repeat(30)).is_some());
    }

    #[test]
    fn test_knxnet_access_display() {
        assert_eq!(KnxnetAccess::Index(4).to_string(), "object 4");
        assert_eq!(
            KnxnetAccess::Ext { instance: 1 }.to_string(),
            "object type 11 instance 1"
        );
    }
}
