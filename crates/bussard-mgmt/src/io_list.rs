//! The interface-object table from `PID_IO_LIST` (issue #209).
//!
//! The device object's `PID_IO_LIST` (PID 71) lists the object type of every
//! interface object, element `i` being the object at index `i - 1`. Reading it
//! takes one count read and one multi-element read per 15 objects (fewer on a
//! standard-frame device), where the `PID_OBJECT_TYPE` walk of
//! [`probe_object_types`](crate::probe_object_types) takes one read per object
//! plus the terminating one: 12 reads on an 11-object Data Secure device.
//!
//! Not every device offers the property or multi-element reads, and the
//! list's order is only as good as the device's implementation, so
//! [`discover_object_table`] takes the list only when it passes a check
//! against `PID_OBJECT_TYPE` (the last object, the index after it, and the
//! first application-program object) and falls back to the walk on the first
//! refusal, short answer, timeout or mismatch.

use crate::connection::{
    L4Channel, Layer4Connection, MAX_OBJECT_INDEX, probe_object_type, probe_object_types,
    property_request,
};
use crate::error::{MgmtError, Result, SilenceKind};
use crate::tables::{OT_APPLICATION_PROGRAM, OT_DEVICE};

/// `PID_IO_LIST` (71) on the device object: the list of interface-object
/// types (KNX 3/5/1 §4.3, device object).
pub const PID_IO_LIST: u8 = 71;

/// The most elements one `A_PropertyValue_Read` can ask for: the count is a
/// 4-bit field (KNX 3/3/7 §3.4.3.2).
const MAX_ELEMENTS_PER_READ: u8 = 15;

/// Which read produced an object table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectTableSource {
    /// `PID_IO_LIST`, checked against `PID_OBJECT_TYPE`.
    IoList,
    /// The `PID_OBJECT_TYPE` walk.
    Walk,
}

/// Reads `PID_IO_LIST` as a list of object types in index order.
///
/// `Ok(None)` when the device does not offer it the way the fast path needs:
/// a zero-element or malformed answer, no answer, a count of zero or above
/// [`MAX_OBJECT_INDEX`], or a multi-element read answered with fewer elements
/// than asked for. Only a transport failure is an `Err`.
pub async fn read_io_list<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<Vec<u16>>> {
    let Some(count) = tolerant_read(l4, 0, 1).await?.and_then(|resp| {
        (resp.count == 1 && resp.data.len() >= 2)
            .then(|| u16::from_be_bytes([resp.data[0], resp.data[1]]))
    }) else {
        tracing::debug!(target = %l4.target(), "PID_IO_LIST not offered; walking the objects");
        return Ok(None);
    };
    if count == 0 || count > u16::from(MAX_OBJECT_INDEX) {
        tracing::debug!(target = %l4.target(), count, "PID_IO_LIST count out of range");
        return Ok(None);
    }
    let per_read = (l4.max_property_read_octets() / 2).clamp(1, MAX_ELEMENTS_PER_READ);
    let mut types: Vec<u16> = Vec::with_capacity(usize::from(count));
    while types.len() < usize::from(count) {
        let remaining = usize::from(count) - types.len();
        let want = u8::try_from(remaining).unwrap_or(u8::MAX).min(per_read);
        let start = u16::try_from(types.len() + 1).unwrap_or(u16::MAX);
        let Some(resp) = tolerant_read(l4, start, want).await? else {
            return Ok(None);
        };
        if resp.count != want || resp.data.len() < 2 * usize::from(want) {
            tracing::debug!(
                target = %l4.target(),
                asked = want,
                got = resp.count,
                "PID_IO_LIST multi-element read refused; walking the objects"
            );
            return Ok(None);
        }
        types.extend(
            resp.data
                .as_chunks::<2>()
                .0
                .iter()
                .take(usize::from(want))
                .map(|c| u16::from_be_bytes(*c)),
        );
    }
    Ok(Some(types))
}

/// Discovers the interface-object table: `PID_IO_LIST` when the device offers
/// it and it agrees with `PID_OBJECT_TYPE`, the walk otherwise.
///
/// The result is the table [`probe_object_types`] returns on the same device,
/// which the fallback makes true by construction; the check makes it true for
/// the fast path on every device whose list is complete and in index order.
///
/// # Errors
///
/// A transport failure, from the check or the walk.
pub async fn discover_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<(Vec<(u8, u16)>, ObjectTableSource)> {
    if let Some(types) = read_io_list(l4).await?
        && let Some(table) = checked_table(l4, &types).await?
    {
        return Ok((table, ObjectTableSource::IoList));
    }
    Ok((probe_object_types(l4).await?, ObjectTableSource::Walk))
}

/// Checks a `PID_IO_LIST` answer against `PID_OBJECT_TYPE`: the device object
/// first, the last object's type, the index after it answering no object (the
/// walk's terminator), and the first application-program object's type.
/// `None` on any disagreement.
async fn checked_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    types: &[u16],
) -> Result<Option<Vec<(u8, u16)>>> {
    if types.first() != Some(&OT_DEVICE) {
        tracing::debug!(target = %l4.target(), "PID_IO_LIST does not start with the device object");
        return Ok(None);
    }
    let table: Vec<(u8, u16)> = types
        .iter()
        .enumerate()
        .filter_map(|(i, ot)| u8::try_from(i).ok().map(|i| (i, *ot)))
        .collect();
    let last = table.len().saturating_sub(1);
    let mut checks: Vec<usize> = Vec::new();
    if last > 0 {
        checks.push(last);
    }
    if let Some(app) = table
        .iter()
        .position(|(_, ot)| *ot == OT_APPLICATION_PROGRAM)
        && app != 0
        && app != last
    {
        checks.push(app);
    }
    for i in checks {
        let (index, want) = table[i];
        if probe_object_type(l4, index).await? != Some(want) {
            tracing::debug!(target = %l4.target(), index, "PID_IO_LIST disagrees with PID_OBJECT_TYPE");
            return Ok(None);
        }
    }
    if let Ok(next) = u8::try_from(table.len())
        && next < MAX_OBJECT_INDEX
        && probe_object_type(l4, next).await?.is_some()
    {
        tracing::debug!(target = %l4.target(), next, "an object follows the PID_IO_LIST entries");
        return Ok(None);
    }
    Ok(Some(table))
}

/// One `PID_IO_LIST` read that folds a device-level refusal into `None`: an
/// off-service or malformed answer, a zero count, or no answer at all. A device
/// that `T_ACK`ed the read but never answered keeps the connection usable for
/// the fallback walk, as [`Layer4Connection::authorize`] does.
async fn tolerant_read<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    start: u16,
    count: u8,
) -> Result<Option<crate::apci::PropertyValueResponse>> {
    let before = l4.numbered_exchanges();
    match property_request(l4, 0, PID_IO_LIST, start, count).await {
        Ok(resp) if resp.count == 0 => Ok(None),
        Ok(resp) => Ok(Some(resp)),
        Err(MgmtError::MalformedResponse { .. }) => Ok(None),
        Err(
            err @ (MgmtError::NoResponse { .. }
            | MgmtError::MidSessionSilence {
                kind: SilenceKind::NoResponse,
                ..
            }),
        ) => {
            if l4.numbered_exchanges() > before {
                l4.reopen_after_unanswered();
                Ok(None)
            } else {
                Err(err)
            }
        }
        Err(other) => Err(other),
    }
}
