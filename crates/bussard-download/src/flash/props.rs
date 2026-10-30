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
    write_property_ext_chunked,
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

/// The index of the `occurrence`-th object of `object_type`: from the device
/// object's `PID_IO_LIST` when the device offers it, else from the
/// `PID_OBJECT_TYPE` walk. The IPS 300 SREG's walk stops before its
/// KNXnet/IP parameter object (object 7 on 1.1.200, issue #393); its own
/// writes go out on the extended services, so this is the fallback for a
/// device that refuses those.
pub(super) async fn index_of_type<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_type: u16,
    occurrence: u16,
) -> Result<u8, WriteError> {
    let nth = |types: &[u16]| {
        types
            .iter()
            .enumerate()
            .filter(|(_, ot)| **ot == object_type)
            .nth(usize::from(occurrence))
            .and_then(|(index, _)| u8::try_from(index).ok())
    };
    if let Some(types) = bussard_mgmt::read_io_list(l4).await?
        && let Some(index) = nth(&types)
    {
        return Ok(index);
    }
    let table = bussard_mgmt::probe_object_types(l4).await?;
    let types: Vec<u16> = table.iter().map(|(_, ot)| *ot).collect();
    // The walk lists objects from index 0 without gaps.
    nth(&types).ok_or_else(|| {
        WriteError::Mgmt(MgmtError::MalformedResponse {
            address: l4.target(),
            reason: format!(
                "the device has no interface object of type {object_type} (occurrence \
                 {occurrence}) in its object list or walk {table:?}, and declined the \
                 extended property services"
            ),
        })
    })
}

/// The octets per element of `value` written as `count` elements.
fn element_size(value: &[u8], count: u16) -> usize {
    (value.len() / usize::from(count.max(1))).max(1)
}

/// How many elements of `elem` octets one plain request carries on `l4`.
fn plain_elements<Ch: L4Channel>(l4: &Layer4Connection<Ch>, elem: usize) -> usize {
    let budget = usize::from(
        l4.effective_max_apdu()
            .saturating_sub(PROPERTY_APDU_OVERHEAD),
    );
    (budget / elem.max(1)).clamp(1, MAX_PLAIN_ELEMENTS)
}

/// Writes `value` (`count` elements from `start`) to `index` with
/// `A_PropertyValue_Write`, each request echo-validated. One element is
/// written whole as before issue #390; more are split to the APDU budget.
async fn write_plain<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    index: u8,
    pid: u8,
    start: u16,
    count: u16,
    value: &[u8],
) -> Result<(), WriteError> {
    if count <= 1 {
        write_property(l4, index, pid, 1, start, value, None).await?;
        return Ok(());
    }
    let elem = element_size(value, count);
    let per = plain_elements(l4, elem);
    let mut at = start;
    for chunk in value.chunks(per * elem) {
        let n = chunk.len() / elem;
        write_property(l4, index, pid, n as u8, at, chunk, None).await?;
        at = at.saturating_add(n as u16);
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

/// The 8-bit index and PID of an index-addressed property.
fn plain_target(index: u32, prop_id: u32) -> (u8, u8) {
    (
        u8::try_from(index).unwrap_or(u8::MAX),
        u8::try_from(prop_id).unwrap_or(u8::MAX),
    )
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
            let (index, pid) = plain_target(index, prop_id);
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
                    let pid = u8::try_from(prop_id).unwrap_or(u8::MAX);
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
            let (index, pid) = plain_target(index, prop_id);
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
                    let pid = u8::try_from(prop_id).unwrap_or(u8::MAX);
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

/// Whether `actual` matches `expected` under `mask` (`0x00` ignores a
/// position, a missing mask octet compares it).
fn masked_equal(expected: &[u8], actual: &[u8], mask: Option<&[u8]>) -> bool {
    actual.len() == expected.len()
        && expected.iter().zip(actual).enumerate().all(|(i, (e, a))| {
            let m = mask.and_then(|m| m.get(i)).copied().unwrap_or(0xFF);
            (e & m) == (a & m)
        })
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
        let (index, pid) = plain_target(index, prop_id);
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
