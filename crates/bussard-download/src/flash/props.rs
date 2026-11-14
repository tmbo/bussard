//! Executing the property steps of a load procedure (issue #390): one
//! implementation of [`FlashStep::WriteProp`](super::FlashStep::WriteProp) with
//! `Count`/`Verify`, of [`FlashStep::CompareProp`](super::FlashStep::CompareProp)
//! on an object named by type, and of the property read the read-back uses,
//! shared by the System B, System 7 and property-only executors and by
//! `bussard-service`'s post-write read-back.
//!
//! An object named by index is addressed with the plain `A_PropertyValue_*`
//! services. An object named by type is addressed with the extended
//! `A_PropertyExtValue_*` services (object type + 1-based instance), as ETS
//! addresses the KNXnet/IP parameter object of the IPS 300 SREG in the
//! capture of 2026-10-26; a device that refuses or ignores them is addressed
//! by the index its interface-object table gives that type instead.

use super::PropObject;
use bussard_mgmt::MgmtError;
use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{WriteError, read_property_elements, write_property};
use bussard_mgmt::property_ext::{
    PropertyExtAddress, declined_as_none, max_read_elements, read_property_ext,
    read_property_ext_description_optional, write_property_ext_chunked,
};

/// The octets an `A_PropertyValue_Write`/`_Response` adds to its value on the
/// APDU budget: the object index, the PID and the count/start word, on top of
/// the octet the APDU length does not count (see
/// [`bussard_mgmt::apci::memory_chunk_for_apdu`]).
const PROPERTY_APDU_OVERHEAD: u16 = 5;

/// The largest element count the plain services carry (a 4-bit field).
const MAX_PLAIN_ELEMENTS: usize = 15;

/// `object` and `prop_id` in words, for errors and labels.
pub(crate) fn property_name(object: PropObject, prop_id: u32) -> String {
    format!("{object} PID {prop_id}")
}

/// The extended-service address of an object named by type.
fn ext_address(object_type: u16, occurrence: u16, prop_id: u32) -> PropertyExtAddress {
    PropertyExtAddress {
        object_type,
        object_instance: occurrence.saturating_add(1),
        property_id: u16::try_from(prop_id).unwrap_or(u16::MAX),
    }
}

/// The device object's `PID_IO_LIST` read at most once per session:
/// `None` until read, then the answer (`None` inside for a device without
/// the list).
pub(super) type IoListCache = Option<Option<Vec<u16>>>;

/// The index of the `occurrence`-th object of `object_type`, the one
/// resolver of an object named by type for the write and the read-back
/// (issue #964). From `known`, the interface-object list the caller already
/// holds (the System B executor's resumable walk before the first step); a
/// type `known` misses is looked up in the device object's `PID_IO_LIST`,
/// read once per session into `io_list`, since the IPS 300 SREG's walk stops
/// before its KNXnet/IP parameter object (object 7 on 1.1.200, issue #393).
/// The `PID_OBJECT_TYPE` walk (or the table the connection was seeded with)
/// runs only when `known` is empty: a second walk ends where the first did,
/// and a one-shot walk on a device with a small per-connection budget dies
/// mid-flash. Every table is read by the index it records
/// ([`listed_index`]), never by position, so a list with a gap names the
/// same object for the write and the read-back.
///
/// `None` when no list holds the type.
///
/// # Errors
///
/// A transport failure.
pub(super) async fn resolve_type_index<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    known: &[(u8, u16)],
    io_list: &mut IoListCache,
    object_type: u16,
    occurrence: u16,
) -> Result<Option<u8>, WriteError> {
    if let Some(index) = listed_index(known, object_type, occurrence) {
        return Ok(Some(index));
    }
    let types = match io_list {
        Some(types) => types,
        None => io_list.insert(bussard_mgmt::read_io_list(l4).await?),
    };
    if let Some(types) = types {
        let table: Vec<(u8, u16)> = types
            .iter()
            .enumerate()
            .filter_map(|(i, ot)| u8::try_from(i).ok().map(|i| (i, *ot)))
            .collect();
        if let Some(index) = listed_index(&table, object_type, occurrence) {
            return Ok(Some(index));
        }
    }
    if !known.is_empty() {
        return Ok(None);
    }
    let table = bussard_mgmt::probe_object_types(l4).await?;
    Ok(listed_index(&table, object_type, occurrence))
}

/// [`resolve_type_index`] with no list in hand, a type no list holds an
/// error: the fallback of the extended services for a device that refuses
/// them.
pub(super) async fn index_of_type<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_type: u16,
    occurrence: u16,
) -> Result<u8, WriteError> {
    resolve_type_index(l4, &[], &mut None, object_type, occurrence)
        .await?
        .ok_or_else(|| {
            WriteError::Mgmt(MgmtError::MalformedResponse {
                address: l4.target(),
                reason: format!(
                    "the device has no interface object of type {object_type} (occurrence \
                     {occurrence}) in its object list or walk, and declined the extended \
                     property services"
                ),
            })
        })
}

/// The index of the `occurrence`-th object of `object_type` in the
/// interface-object list `table` (`index`, `PID_OBJECT_TYPE`): where ETS
/// writes an object a program that is not Data Secure enabled names by type
/// (issue #948).
pub(super) fn listed_index(table: &[(u8, u16)], object_type: u16, occurrence: u16) -> Option<u8> {
    table
        .iter()
        .filter(|(_, ot)| *ot == object_type)
        .nth(usize::from(occurrence))
        .map(|(index, _)| *index)
}

/// The octets per element of `value` written as `count` elements.
fn element_size(value: &[u8], count: u16) -> usize {
    (value.len() / usize::from(count.max(1))).max(1)
}

/// How many elements of `elem` octets one plain `A_PropertyValue_Write`
/// carries under an APDU limit of `max_apdu`: what fits the budget, at most
/// the 15 the 4-bit count field holds. The executor splits a multi-element
/// write with it, and the dry-run dump lists the same requests.
pub fn plain_write_elements(max_apdu: u16, elem: usize) -> usize {
    let budget = usize::from(max_apdu.saturating_sub(PROPERTY_APDU_OVERHEAD));
    (budget / elem.max(1)).clamp(1, MAX_PLAIN_ELEMENTS)
}

/// How many elements of `elem` octets one plain request carries on `l4`.
fn plain_elements<Ch: L4Channel>(l4: &Layer4Connection<Ch>, elem: usize) -> usize {
    plain_write_elements(l4.effective_max_apdu(), elem)
}

/// One request of a property write: the element it starts at, how many
/// elements it carries, and which octets of the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyWriteRequest {
    /// The 1-based element the request writes from.
    pub start: u16,
    /// The elements it carries.
    pub count: usize,
    /// The octets of the value it carries.
    pub octets: std::ops::Range<usize>,
}

/// The requests a [`FlashStep::WriteProp`](super::FlashStep::WriteProp) of
/// `value_len` octets (`count` elements from `start`) goes out as under an
/// APDU limit of `max_apdu`, by the rule the executor follows: on the plain
/// service a single element is written whole and more are split into requests
/// of at most 15 elements ([`plain_write_elements`]); an object named by type
/// goes out on the extended service in requests of at most 255
/// ([`bussard_mgmt::property_ext::write_elements_for_apdu`]), unless
/// `typed_by_list`: the System B executor writes an object a program that is
/// not Data Secure enabled names by type at the index the device's object
/// list gives it, on the plain service (issue #948), so it splits as an
/// index. The executor, the dry-run dump and (through the dump) `knxtrace`
/// list the same requests (issue #964).
pub fn property_write_requests(
    object: PropObject,
    start: u16,
    count: u16,
    value_len: usize,
    max_apdu: u16,
    typed_by_list: bool,
) -> Vec<PropertyWriteRequest> {
    let elem = (value_len / usize::from(count.max(1))).max(1);
    let plain = matches!(object, PropObject::Index(_)) || typed_by_list;
    let per = match object {
        _ if plain && count <= 1 => {
            return vec![PropertyWriteRequest {
                start,
                count: 1,
                octets: 0..value_len,
            }];
        }
        _ if plain => plain_write_elements(max_apdu, elem),
        _ => bussard_mgmt::property_ext::write_elements_for_apdu(max_apdu, elem),
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut element = start;
    while at < value_len {
        let end = (at + per * elem).min(value_len);
        let n = (end - at) / elem;
        out.push(PropertyWriteRequest {
            start: element,
            count: n,
            octets: at..end,
        });
        element = element.saturating_add(u16::try_from(n).unwrap_or(u16::MAX));
        at = end;
    }
    out
}

/// Writes `value` (`count` elements from `start`) to `index` with
/// `A_PropertyValue_Write`, each request echo-validated, in the requests
/// [`property_write_requests`] lists.
async fn write_plain<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    index: u8,
    pid: u8,
    start: u16,
    count: u16,
    value: &[u8],
) -> Result<(), WriteError> {
    let requests = property_write_requests(
        PropObject::Index(u32::from(index)),
        start,
        count,
        value.len(),
        l4.effective_max_apdu(),
        false,
    );
    for request in requests {
        let n = u8::try_from(request.count).unwrap_or(u8::MAX);
        let chunk = value.get(request.octets).unwrap_or_default();
        write_property(l4, index, pid, n, request.start, chunk, None).await?;
    }
    Ok(())
}

/// Reads `count` elements of `elem` octets from `start` with
/// `A_PropertyValue_Read`, in requests sized to the APDU budget.
async fn read_plain<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    index: u8,
    pid: u8,
    start: u16,
    count: u16,
    elem: usize,
) -> Result<Vec<u8>, WriteError> {
    let per = plain_elements(l4, elem) as u16;
    let mut out = Vec::new();
    let mut at = start;
    let end = start.saturating_add(count.max(1));
    while at < end {
        let n = per.min(end - at);
        out.extend(read_property_elements(l4, index, pid, at, n as u8).await?);
        at += n;
    }
    Ok(out)
}

/// Reads `count` elements of `elem` octets from `start` with
/// `A_PropertyExtValue_Read`, in requests sized to the APDU budget.
async fn read_ext<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    addr: PropertyExtAddress,
    start: u16,
    count: u16,
    elem: usize,
) -> Result<Vec<u8>, MgmtError> {
    let per = max_read_elements(l4, elem) as u16;
    let mut out = Vec::new();
    let mut at = start;
    let end = start.saturating_add(count.max(1));
    while at < end {
        let n = per.min(end - at);
        let resp = read_property_ext(l4, addr, n as u8, at).await?;
        out.extend(resp.data);
        at += n;
    }
    Ok(out)
}

/// The 8-bit index and PID the plain services address `index`/`prop_id`
/// with. An index or PID past 8 bits is an error, never clamped to 255: a
/// plan that reached the executor without its plan-time check
/// ([`check_addressable`](super::plan_props::check_addressable)) must not
/// write another property (issue #964).
fn plain_target<Ch: L4Channel>(
    l4: &Layer4Connection<Ch>,
    index: u32,
    prop_id: u32,
) -> Result<(u8, u8), WriteError> {
    match (u8::try_from(index), u8::try_from(prop_id)) {
        (Ok(index), Ok(pid)) => Ok((index, pid)),
        _ => Err(WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "object {index} PID {prop_id} exceeds the 8-bit object index or PID the plain \
                 property services address"
            ),
        })),
    }
}

/// Reads `count` elements from `start` of the property `object`/`prop_id`,
/// each element `elem` octets: the read a `Verify="true"` write and the
/// post-write read-back compare against what was written.
///
/// # Errors
///
/// The device refusing the read on both services, or a transport failure.
pub async fn read_property_value<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object: PropObject,
    prop_id: u32,
    start: u16,
    count: u16,
    elem: usize,
) -> Result<Vec<u8>, WriteError> {
    match object {
        PropObject::Index(index) => {
            let (index, pid) = plain_target(l4, index, prop_id)?;
            read_plain(l4, index, pid, start, count, elem).await
        }
        PropObject::Type {
            object_type,
            occurrence,
        } => {
            let addr = ext_address(object_type, occurrence, prop_id);
            match declined_as_none(l4, async |l4| read_ext(l4, addr, start, count, elem).await)
                .await?
            {
                Some(data) => Ok(data),
                None => {
                    let index = index_of_type(l4, object_type, occurrence).await?;
                    let (index, pid) = plain_target(l4, u32::from(index), prop_id)?;
                    read_plain(l4, index, pid, start, count, elem).await
                }
            }
        }
    }
}

/// Executes an `LdCtrlWriteProp`: writes `value` (`count` elements from
/// `start`) to `object`/`prop_id`, and with `verify` reads it back and fails
/// on a difference ([`WriteError::PropertyMismatch`]).
///
/// # Errors
///
/// A refused or unconfirmed write, a failed verify read-back, or a transport
/// failure.
pub async fn write_property_value<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object: PropObject,
    prop_id: u32,
    start: u16,
    count: u16,
    value: &[u8],
    verify: bool,
) -> Result<(), WriteError> {
    let elem = element_size(value, count);
    let object = match object {
        PropObject::Index(index) => {
            let (index, pid) = plain_target(l4, index, prop_id)?;
            write_plain(l4, index, pid, start, count, value).await?;
            PropObject::Index(u32::from(index))
        }
        PropObject::Type {
            object_type,
            occurrence,
        } => {
            let addr = ext_address(object_type, occurrence, prop_id);
            let written = declined_as_none(l4, async |l4| {
                write_property_ext_chunked(l4, addr, start, elem, value, |_| {}).await
            })
            .await?;
            match written {
                Some(()) => object,
                None => {
                    let index = index_of_type(l4, object_type, occurrence).await?;
                    let (index, pid) = plain_target(l4, u32::from(index), prop_id)?;
                    write_plain(l4, index, pid, start, count, value).await?;
                    PropObject::Index(u32::from(index))
                }
            }
        }
    };
    if verify {
        let held = read_property_value(l4, object, prop_id, start, count.max(1), elem).await?;
        if held != value {
            return Err(WriteError::PropertyMismatch {
                address: l4.target(),
                property: property_name(object, prop_id),
                what: "verify read-back",
                expected: value.to_vec(),
                actual: held,
            });
        }
    }
    Ok(())
}

use crate::param_props::masked_equal;

/// `PDT_VARIABLE_LENGTH` (KNX 3/7/3 §3.3).
const PDT_VARIABLE_LENGTH: u8 = 0x10;

/// Executes a [`FlashStep::DescribeProp`](super::FlashStep::DescribeProp):
/// reads the description of `object`/`prop_id` as ETS does for a property
/// write it has no value for (issue #841), on the extended service for an
/// object named by type and the plain one for an index. A device that stays
/// silent or declines keeps the flash going.
///
/// With `unwritten` (issue #947) the read stands in for a write of that many
/// octets the plan leaves out, as ETS leaves out a property described as
/// `PDT_VARIABLE_LENGTH`: a device that describes the property with any other
/// type and at least one element fails the flash. Without it the answer
/// changes nothing.
///
/// # Errors
///
/// [`WriteError::PropertyNotVariableLength`], and a transport failure.
pub async fn describe_property<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object: PropObject,
    prop_id: u32,
    unwritten: Option<usize>,
) -> Result<(), WriteError> {
    let described = match object {
        PropObject::Type {
            object_type,
            occurrence,
        } => read_property_ext_description_optional(
            l4,
            ext_address(object_type, occurrence, prop_id),
        )
        .await?
        .map(|d| (d.pdt, d.max_elements)),
        PropObject::Index(index) => {
            let (Ok(index), Ok(pid)) = (u8::try_from(index), u8::try_from(prop_id)) else {
                return Ok(());
            };
            bussard_mgmt::connection::read_property_description_optional(l4, index, pid)
                .await?
                .map(|d| (d.pdt, d.max_elements))
        }
    };
    match (unwritten, described) {
        (Some(octets), Some((pdt, max_elements)))
            if max_elements > 0 && pdt != PDT_VARIABLE_LENGTH =>
        {
            Err(WriteError::PropertyNotVariableLength {
                address: l4.target(),
                property: property_name(object, prop_id),
                pdt,
                max_elements,
                octets,
            })
        }
        _ => Ok(()),
    }
}

/// Executes an `LdCtrlCompareProp`: reads element `start` (1-based) of
/// `object`/`prop_id` and compares its first `expected.len()` octets under
/// `mask`. An index-addressed object keeps the historical
/// [`bussard_mgmt::compare_property`].
///
/// # Errors
///
/// A mismatch ([`WriteError::PropCompareMismatch`] or
/// [`WriteError::PropertyMismatch`]), a refused read, or a transport failure.
pub async fn compare_property_value<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object: PropObject,
    prop_id: u32,
    start: u16,
    expected: &[u8],
    mask: Option<&[u8]>,
) -> Result<(), WriteError> {
    if let PropObject::Index(index) = object {
        let (index, pid) = plain_target(l4, index, prop_id)?;
        return bussard_mgmt::compare_property(l4, index, pid, start, expected, mask).await;
    }
    let held = read_property_value(l4, object, prop_id, start, 1, expected.len().max(1)).await?;
    let actual: Vec<u8> = held.iter().take(expected.len()).copied().collect();
    if masked_equal(expected, &actual, mask) {
        Ok(())
    } else {
        Err(WriteError::PropertyMismatch {
            address: l4.target(),
            property: property_name(object, prop_id),
            what: "compare (the application's LdCtrlCompareProp precondition)",
            expected: expected.to_vec(),
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listed_index_takes_the_nth_object_of_the_type() {
        // Issue #948: the Siemens dimmer's type 50215 sits at object 6.
        let table = [(0, 0), (1, 1), (4, 3), (6, 50215), (7, 50215)];
        assert_eq!(listed_index(&table, 50215, 0), Some(6));
        assert_eq!(listed_index(&table, 50215, 1), Some(7));
        assert_eq!(listed_index(&table, 50215, 2), None);
        assert_eq!(listed_index(&table, 11, 0), None);
    }

    #[test]
    fn test_masked_equal_ignores_masked_octets() {
        assert!(masked_equal(
            &[0, 0, 0, 0x16, 0, 0],
            &[0, 0, 0, 0x16, 0x12, 0x34],
            Some(&[0xFF, 0xFF, 0xFF, 0xFF, 0, 0])
        ));
        assert!(!masked_equal(&[0, 4], &[0, 5], None));
        assert!(!masked_equal(&[0, 4], &[0], None));
    }

    #[test]
    fn test_element_size_splits_count() {
        assert_eq!(element_size(&[0; 32], 8), 4);
        assert_eq!(element_size(&[0; 10], 2), 5);
        assert_eq!(element_size(&[0; 3], 1), 3);
    }

    #[test]
    fn test_ext_address_is_one_based() {
        let addr = ext_address(11, 0, 205);
        assert_eq!(addr.object_type, 11);
        assert_eq!(addr.object_instance, 1);
        assert_eq!(addr.property_id, 205);
    }
}
