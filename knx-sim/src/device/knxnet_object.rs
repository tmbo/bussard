//! The KNXnet/IP parameter object (interface object type 11) of a simulated
//! KNX IP interface (bussard issue #391), read side.
//!
//! A KNXnet/IP interface or router exposes its IP configuration through this
//! object: its KNX individual address (PID 52), the additional individual
//! addresses its tunnelling connections use (PID 53, an array), the current
//! and configured IP assignment method (PIDs 54, 55: bit 0 manual, bit 1
//! BootP, bit 2 DHCP, bit 3 AutoIP), the current IP address, netmask and
//! default gateway (57 to 59), the configured static ones (60 to 62), the MAC
//! address (64), the multicast addresses (65, 66), the TTL (67), the device
//! capabilities (68) and state (69) and the friendly name (76, 30 octets of
//! ISO 8859-1, NUL-padded). Ids and data types from the KNX master data
//! (`knx_master.xml`, `OT-11`); the encodings from the KNX standard volume
//! 3/8/3 (KNXnet/IP Device Management).
//!
//! The simulator serves the properties with array semantics: a read of start
//! index 0 answers the element count, a read of `count` elements from `start`
//! answers those elements, and anything past the end is refused with the
//! zero-count response. The write side (bussard issue #391, sub-task b): PIDs
//! 53, 55, 60 to 62 and 76 take `A_PropertyValue_Write` and
//! `A_PropertyExtValue_WriteCon` element by element (element 0 of PID 53 sets
//! the element count, up to the tunnel slots its description declares), and
//! both description services describe every property with its real element
//! count. KNXnet/IP Secure PIDs (91 and up) are not modelled.

use super::interface_object::{InterfaceObject, PID_OBJECT_TYPE, Property, PropertyDescription};

/// The interface-object type of the KNXnet/IP parameter object.
pub const IOT_KNXNET_IP_PARAMETER: u16 = 11;

/// The IP configuration a simulated interface reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnxnetParameters {
    /// PID 52, the interface's individual address (raw).
    pub individual_address: u16,
    /// PID 53, the tunnelling addresses (raw), in slot order.
    pub tunnels: Vec<u16>,
    /// PID 54, the method bits in use.
    pub current_assignment: u8,
    /// PID 55, the configured method bits.
    pub assignment: u8,
    /// PIDs 57 to 59: address, netmask, gateway in use.
    pub current: [[u8; 4]; 3],
    /// PIDs 60 to 62: the configured static address, netmask, gateway.
    pub configured: [[u8; 4]; 3],
    /// PID 64.
    pub mac: [u8; 6],
    /// PID 65.
    pub system_setup_multicast: [u8; 4],
    /// PID 66.
    pub routing_multicast: [u8; 4],
    /// PID 67.
    pub ttl: u8,
    /// PID 68: device management and tunnelling.
    pub capabilities: u16,
    /// PID 69: 0, no fault.
    pub state: u8,
    /// PID 76.
    pub friendly_name: String,
    /// How many tunnelling addresses PID 53 holds at most (its description's
    /// maximum element count).
    pub tunnel_slots: u16,
}

/// The PIDs a simulated interface takes writes on: the tunnelling addresses,
/// the assignment method, the static address set, the routing multicast
/// address and TTL (ETS writes 66 on a router download, ALLinBOX 1612) and the
/// friendly name.
pub const WRITABLE: [u8; 9] = [51, 53, 55, 60, 61, 62, 66, 67, 76];

/// The `A_PropertyExtValue_WriteConResponse` APCI.
pub const EXT_WRITE_CON_RESPONSE: u16 = 0x1CF;

/// The `A_PropertyExtDescription_Response` APCI.
pub const EXT_DESCRIPTION_RESPONSE: u16 = 0x1D3;

impl KnxnetParameters {
    /// A DHCP interface at `individual_address` with `tunnels`.
    pub fn dhcp(individual_address: u16, tunnels: Vec<u16>) -> Self {
        let tunnel_slots = u16::try_from(tunnels.len()).unwrap_or(u16::MAX);
        KnxnetParameters {
            tunnel_slots,
            individual_address,
            tunnels,
            current_assignment: 0x04,
            assignment: 0x04,
            current: [[192, 168, 1, 74], [255, 255, 255, 0], [192, 168, 1, 1]],
            configured: [[0; 4]; 3],
            mac: [0x00, 0x00, 0x5E, 0x00, 0x53, 0x01],
            system_setup_multicast: [224, 0, 23, 12],
            routing_multicast: [224, 0, 23, 12],
            ttl: 16,
            capabilities: 0x0003,
            state: 0,
            friendly_name: "knx-sim IP interface".to_string(),
        }
    }

    /// The interface object holding these values.
    pub fn object(&self) -> InterfaceObject {
        let mut obj = InterfaceObject::new();
        obj.set_property(
            PID_OBJECT_TYPE,
            Property::read_only(IOT_KNXNET_IP_PARAMETER.to_be_bytes().to_vec()),
        );
        let mut name: Vec<u8> = self
            .friendly_name
            .chars()
            .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
            .take(30)
            .collect();
        name.resize(30, 0);
        let values: [(u8, Vec<u8>); 21] = [
            // PID 51 project installation id: ETS writes it first when it
            // configures the IP part of a device (Zennio ALLinBOX 1612,
            // ETS-against-sim capture 2026-10-28).
            (51, vec![0, 0]),
            (52, self.individual_address.to_be_bytes().to_vec()),
            (
                53,
                self.tunnels.iter().flat_map(|t| t.to_be_bytes()).collect(),
            ),
            (54, vec![self.current_assignment]),
            (55, vec![self.assignment]),
            (57, self.current[0].to_vec()),
            (58, self.current[1].to_vec()),
            (59, self.current[2].to_vec()),
            (60, self.configured[0].to_vec()),
            (61, self.configured[1].to_vec()),
            (62, self.configured[2].to_vec()),
            (56, vec![0x07]),       // IP capabilities: BootP, DHCP, AutoIP
            (63, vec![0, 0, 0, 0]), // DHCP/BootP server
            (64, self.mac.to_vec()),
            (65, self.system_setup_multicast.to_vec()),
            (66, self.routing_multicast.to_vec()),
            (67, vec![self.ttl]),
            (68, self.capabilities.to_be_bytes().to_vec()),
            (69, vec![self.state]),
            (70, vec![0x00]), // routing capabilities: none listed
            (76, name),
        ];
        for (pid, value) in values {
            let prop = if WRITABLE.contains(&pid) {
                Property::writable(value)
            } else {
                Property::read_only(value)
            };
            obj.set_property(pid, prop);
        }
        obj
    }
}

/// Whether `obj` is a KNXnet/IP parameter object.
pub fn is_knxnet(obj: &InterfaceObject) -> bool {
    obj.property(PID_OBJECT_TYPE).map(|p| p.value.as_slice())
        == Some(&IOT_KNXNET_IP_PARAMETER.to_be_bytes()[..])
}

/// `desc` (the generic description of PID `desc.pid` of `obj`) with the
/// property's real data type and element count: PID 53 holds up to `slots`
/// elements, every other property the elements it has.
pub fn refine(desc: PropertyDescription, obj: &InterfaceObject, slots: u16) -> PropertyDescription {
    let size = element_size(desc.pid);
    let count = obj.property(desc.pid).map_or(0, |p| {
        u16::try_from(p.value.len() / size).unwrap_or(u16::MAX)
    });
    PropertyDescription {
        pdt: match size {
            2 => 0x04,
            4 => 0x09,
            6 => 0x16,
            _ => 0x02,
        },
        max_elements: if desc.pid == 53 {
            slots.max(count)
        } else {
            count.max(1)
        },
        write_level: if desc.writable { 2 } else { 15 },
        ..desc
    }
}

/// Writes `data` from element `start` into `value`, the property `pid`
/// (element sizes as [`element_size`]): element 0 sets the element count of
/// PID 53 (at most `slots`); elements 1 and up replace elements in place, and
/// on PID 53 may extend the array up to `slots`. `false` refuses the write
/// (malformed, past the end) and leaves `value` as it was.
pub fn array_write(pid: u8, value: &mut Vec<u8>, start: u16, data: &[u8], slots: u16) -> bool {
    let size = element_size(pid);
    if data.is_empty() || (start != 0 && !data.len().is_multiple_of(size)) {
        return false;
    }
    let capacity = if pid == 53 {
        usize::from(slots).max(value.len() / size)
    } else {
        value.len() / size
    };
    if start == 0 {
        if pid != 53 {
            return false;
        }
        let count = match data {
            [hi, lo] => usize::from(u16::from_be_bytes([*hi, *lo])),
            [n] => usize::from(*n),
            _ => return false,
        };
        if count > capacity {
            return false;
        }
        value.resize(count * size, 0);
        return true;
    }
    let first = usize::from(start) - 1;
    let n = data.len() / size;
    if first + n > capacity || first * size > value.len() {
        return false;
    }
    let end = (first + n) * size;
    if value.len() < end {
        value.resize(end, 0);
    }
    value[first * size..end].copy_from_slice(data);
    true
}

/// The PID an extended request (`[type:16][instance:12|pid:12]…`) names.
pub fn ext_pid(request: &[u8]) -> Option<u8> {
    let h = request.get(..5)?;
    u8::try_from(ext_header(h).2).ok()
}

/// The header fields of an extended request: `(object type, instance, pid)`.
fn ext_header(h: &[u8]) -> (u16, u32, u16) {
    let object_type = u16::from_be_bytes([h[0], h[1]]);
    let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
    (object_type, packed >> 12, (packed & 0x0FFF) as u16)
}

/// The `A_PropertyExtValue_WriteConResponse` payload for an
/// `A_PropertyExtValue_WriteCon` (`[type:16][instance:12|pid:12][count]
/// [start:16][data]`) of the KNXnet/IP parameter object `obj`, and the PID
/// written when the write took: the echoed header, count and start and a
/// return code (0 taken, 1 refused). `None` for another object type.
pub fn ext_write(
    obj: &mut InterfaceObject,
    request: &[u8],
    slots: u16,
) -> Option<(Vec<u8>, Option<u8>)> {
    let h = request.get(..8)?;
    let (object_type, instance, pid) = ext_header(h);
    if object_type != IOT_KNXNET_IP_PARAMETER {
        return None;
    }
    let start = u16::from_be_bytes([h[6], h[7]]);
    let data = &request[8..];
    let written = match (instance, u8::try_from(pid)) {
        (1, Ok(pid)) if pid != PID_OBJECT_TYPE => obj
            .property_mut(pid)
            .filter(|p| !p.read_only)
            .is_some_and(|p| array_write(pid, &mut p.value, start, data, slots))
            .then_some(pid),
        _ => None,
    };
    let mut out = h.to_vec();
    out.push(if written.is_some() { 0 } else { 1 });
    Some((out, written))
}

/// The `A_PropertyExtDescription_Response` payload for an
/// `A_PropertyExtDescription_Read` (`[type:16][instance:12|pid:12]
/// [type:4|index:12]`) of the KNXnet/IP parameter object `obj`: the
/// [`refine`]d description, or zero elements for an unknown property. `None`
/// for another object type.
pub fn ext_description(obj: &InterfaceObject, request: &[u8], slots: u16) -> Option<Vec<u8>> {
    let h = request.get(..7)?;
    if ext_header(h).0 != IOT_KNXNET_IP_PARAMETER {
        return None;
    }
    describe_ext(obj, request, Some(slots))
}

/// The `A_PropertyExtDescription_Response` payload for an object of any type
/// reached by type (a vendor object such as the ABB Modbus RTU gateway's type
/// 65281, whose PID 207 ETS describes before comparing it, 2026-10-28).
pub fn typed_ext_description(obj: &InterfaceObject, request: &[u8]) -> Option<Vec<u8>> {
    describe_ext(obj, request, None)
}

/// The description payload; `slots` refines the KNXnet/IP object's PID 53.
fn describe_ext(obj: &InterfaceObject, request: &[u8], slots: Option<u16>) -> Option<Vec<u8>> {
    let h = request.get(..7)?;
    let (object_type, instance, pid) = ext_header(h);
    let index = u16::from_be_bytes([h[5], h[6]]) & 0x0FFF;
    let desc = match (instance, u8::try_from(pid)) {
        (1, Ok(0)) => u8::try_from(index)
            .ok()
            .and_then(|i| obj.describe_at_index(i)),
        (1, Ok(pid)) => obj.describe_pid(pid),
        _ => None,
    }
    .map(|d| match slots {
        Some(slots) => refine(d, obj, slots),
        None => d,
    });
    let (pid, type_octet, max, access) = match desc {
        Some(d) => (
            u16::from(d.pid),
            if d.writable { 0x80 } else { 0 } | (d.pdt & 0x3F),
            d.max_elements & 0x0FFF,
            ((d.read_level & 0x0F) << 4) | (d.write_level & 0x0F),
        ),
        None => (pid, 0, 0, 0),
    };
    let packed = (instance << 12) | u32::from(pid);
    let mut out = object_type.to_be_bytes().to_vec();
    out.extend_from_slice(&packed.to_be_bytes()[1..]);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, type_octet]);
    out.extend_from_slice(&max.to_be_bytes());
    out.push(access);
    Some(out)
}

/// The element size in octets of a KNXnet/IP parameter object property.
pub fn element_size(pid: u8) -> usize {
    match pid {
        51 | 52 | 53 | 68 => 2,
        // 205: the Jung IPS 300 SREG's preferred tunnel IP addresses
        // (`PID_ENX_BASICCRI_TUNNELLING_Preferred_IP`, bussard issue #390).
        57..=63 | 65 | 66 | 205 => 4,
        64 => 6,
        _ => 1,
    }
}

/// The answer to `A_PropertyValue_Read(count, start)` of a property holding
/// `value` (`pid` decides the element size): `(count, octets)`, or `None` for
/// the zero-count refusal. Start 0 is the element count; a range past the end
/// is refused whole, as a real device does.
pub fn array_read(pid: u8, value: &[u8], count: u8, start: u16) -> Option<(u8, Vec<u8>)> {
    let size = element_size(pid);
    let total = value.len() / size;
    if start == 0 {
        let n = u16::try_from(total).ok()?;
        return Some((1, n.to_be_bytes().to_vec()));
    }
    let first = usize::from(start);
    let last = first + usize::from(count).max(1) - 1;
    if count == 0 || last > total {
        return None;
    }
    Some((count, value[(first - 1) * size..last * size].to_vec()))
}

/// The `A_PropertyExtValue_Response` payload for an `A_PropertyExtValue_Read`
/// (`[type:16][instance:12|pid:12][count][start:16]`) of the KNXnet/IP
/// parameter object `obj`: the echoed header, the served count, the start and
/// the elements, with count 0 for an unknown property, another instance or a
/// range past the end. `None` when the request addresses another object type
/// (the security object's handler takes it) or is too short.
pub fn ext_read(obj: &InterfaceObject, request: &[u8]) -> Option<Vec<u8>> {
    let h = request.get(..8)?;
    let object_type = u16::from_be_bytes([h[0], h[1]]);
    if object_type != IOT_KNXNET_IP_PARAMETER {
        return None;
    }
    let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
    let instance = packed >> 12;
    let pid = u8::try_from(packed & 0x0FFF).ok();
    let count = h[5];
    let start = u16::from_be_bytes([h[6], h[7]]);
    let answer = match (instance, pid) {
        (1, Some(pid)) if pid != PID_OBJECT_TYPE => obj
            .property(pid)
            .and_then(|p| array_read(pid, &p.value, count, start)),
        _ => None,
    };
    let (n, bytes) = answer.unwrap_or((0, Vec::new()));
    let mut out = h[..5].to_vec();
    out.push(n);
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&bytes);
    Some(out)
}

/// The element size of property `pid` of an object of `object_type` reached
/// by type: the KNXnet/IP parameter object's own sizes, else one element of
/// the whole value.
fn typed_element_size(object_type: u16, pid: u8, value_len: usize) -> usize {
    if object_type == IOT_KNXNET_IP_PARAMETER {
        element_size(pid)
    } else {
        value_len.max(1)
    }
}

/// The answer to an `A_PropertyExtValue_Read` of `obj`, an object of
/// `object_type` reached by type (bussard issue #390): the request header,
/// the served count, the start and the elements. Instance 1 only; count 0
/// refuses (no such property, a range past the end).
pub fn typed_ext_read(object_type: u16, obj: &InterfaceObject, request: &[u8]) -> Option<Vec<u8>> {
    let h = request.get(..8)?;
    let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
    let instance = packed >> 12;
    let pid = u8::try_from(packed & 0x0FFF).ok();
    let count = h[5];
    let start = u16::from_be_bytes([h[6], h[7]]);
    let answer = match (instance, pid) {
        (1, Some(pid)) => obj.property(pid).and_then(|p| {
            let size = typed_element_size(object_type, pid, p.value.len());
            let total = p.value.len() / size;
            if start == 0 {
                return Some((1, u16::try_from(total).ok()?.to_be_bytes().to_vec()));
            }
            let first = usize::from(start);
            let last = first + usize::from(count).max(1) - 1;
            (count != 0 && last <= total)
                .then(|| (count, p.value[(first - 1) * size..last * size].to_vec()))
        }),
        _ => None,
    };
    let (n, bytes) = answer.unwrap_or((0, Vec::new()));
    let mut out = h[..5].to_vec();
    out.push(n);
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&bytes);
    Some(out)
}

/// Applies an `A_PropertyExtValue_WriteCon` to `obj`, an object of
/// `object_type` reached by type (bussard issue #390), and returns the
/// confirmation: the request header, count and start, and return code 0 when
/// a writable property of instance 1 took the elements, else 1.
pub fn typed_ext_write(
    object_type: u16,
    obj: &mut InterfaceObject,
    request: &[u8],
) -> Option<Vec<u8>> {
    let h = request.get(..8)?;
    let data = request.get(8..).unwrap_or_default();
    let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
    let instance = packed >> 12;
    let pid = u8::try_from(packed & 0x0FFF).ok();
    let count = usize::from(h[5]);
    let start = usize::from(u16::from_be_bytes([h[6], h[7]]));
    let mut rc = 0x01;
    if let (1, Some(pid)) = (instance, pid)
        && count > 0
        && start >= 1
        && let Some(prop) = obj.property_mut(pid)
        && !prop.read_only
    {
        let size = if object_type == IOT_KNXNET_IP_PARAMETER {
            element_size(pid)
        } else {
            (data.len() / count).max(1)
        };
        let from = (start - 1) * size;
        let end = from + data.len();
        if prop.value.len() < end {
            prop.value.resize(end, 0);
        }
        prop.value[from..end].copy_from_slice(data);
        rc = 0x00;
    }
    let mut out = h.to_vec();
    out.push(rc);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_ext_description_of_a_vendor_object() -> Result<(), Box<dyn std::error::Error>> {
        // The ABB Modbus RTU gateway's object type 65281, PID 207 = 01.
        let mut obj = InterfaceObject::new();
        obj.set_property(207, crate::device::Property::read_only(vec![0x01]));
        // [type 0xFF01][instance 1 | PID 207][index 0]
        let req = [0xFF, 0x01, 0x00, 0x10, 0xCF, 0x00, 0x00];
        let out = typed_ext_description(&obj, &req).ok_or("a description")?;
        assert_eq!(&out[..5], &req[..5], "type, instance and PID echoed");
        assert_eq!(out[12] >> 4 & 0x0F, 0, "read level 0");
        assert_ne!(
            u16::from_be_bytes([out[10], out[11]]),
            0,
            "max elements set"
        );
        Ok(())
    }

    #[test]
    fn test_array_write_elements_count_and_capacity() {
        let mut tunnels = vec![0x11, 0x16, 0x11, 0x17];
        assert!(array_write(53, &mut tunnels, 2, &[0x11, 0x1E], 3));
        assert_eq!(tunnels, [0x11, 0x16, 0x11, 0x1E]);
        assert!(
            array_write(53, &mut tunnels, 0, &[0, 3], 3),
            "grow to the slots"
        );
        assert_eq!(tunnels.len(), 6);
        assert!(
            !array_write(53, &mut tunnels, 0, &[0, 4], 3),
            "past the slots"
        );
        assert!(!array_write(53, &mut tunnels, 4, &[0x11, 0x20], 3));
        assert!(array_write(53, &mut tunnels, 0, &[0, 1], 3), "shrink");
        assert_eq!(tunnels, [0x11, 0x16]);
        let mut name = vec![0; 30];
        assert!(array_write(76, &mut name, 1, b"Beta", 0));
        assert!(
            !array_write(76, &mut name, 28, b"long", 0),
            "past 30 octets"
        );
        assert!(
            !array_write(76, &mut name, 0, &[0, 4], 0),
            "a fixed-size count"
        );
        assert_eq!(&name[..5], b"Beta\0");
    }

    #[test]
    fn test_array_read_count_elements_and_refusal() {
        let p = KnxnetParameters::dhcp(0x11C8, vec![0x1116, 0x1117, 0x1118]);
        let obj = p.object();
        let tunnels = obj
            .property(53)
            .map(|p| p.value.clone())
            .unwrap_or_default();
        assert_eq!(array_read(53, &tunnels, 1, 0), Some((1, vec![0, 3])));
        assert_eq!(
            array_read(53, &tunnels, 2, 2),
            Some((2, vec![0x11, 0x17, 0x11, 0x18]))
        );
        assert_eq!(array_read(53, &tunnels, 2, 3), None, "past the end");
        let name = obj
            .property(76)
            .map(|p| p.value.clone())
            .unwrap_or_default();
        assert_eq!(name.len(), 30);
        assert_eq!(array_read(76, &name, 1, 0), Some((1, vec![0, 30])));
        let ip = obj
            .property(57)
            .map(|p| p.value.clone())
            .unwrap_or_default();
        assert_eq!(array_read(57, &ip, 1, 1), Some((1, vec![192, 168, 1, 74])));
        assert_eq!(
            obj.property(PID_OBJECT_TYPE).map(|p| p.value.clone()),
            Some(vec![0, 11])
        );
    }
}
