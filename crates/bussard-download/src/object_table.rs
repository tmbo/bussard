//! The System B group-object table (object type 9) on `plan` and `apply`
//! (issue #540).
//!
//! A full flash writes the group-object table from the model: one descriptor
//! word per com-object, with the Communication flag (bit 10, KNX 03_05_01
//! §4.18.6.2.4, Table 87) set only where the model links the object
//! ([`crate::build_table_images`]). A device ignores every telegram for an
//! object whose flag is off (03_04_01 §3.3.2 to §3.3.5), so an `apply` that
//! only rewrote the address and association tables could link an object the
//! last flash left unlinked and report the link verified while the device
//! never acted on it. #432 showed exactly that on System 7.
//!
//! This module keeps the table in step on System B:
//!
//! - [`object_table_image`] takes the image from the full flash plan, so
//!   `apply` writes the very bytes `flash` would (one builder, one image).
//! - [`check_object_table`] reads the device's table through the object's
//!   `PID_TABLE_REFERENCE` and memory, and [`ObjectTableCheck::change`] names
//!   every descriptor that differs from the model's.
//! - [`write_object_table`] reloads the table the way the standard's partial
//!   download of the group-object table does (03_05_03 §3.5.3: Load, Data
//!   Relative Allocation, write, LoadCompleted), the same shape `apply` uses
//!   for the address and association tables (see [`crate::apply`]), and reads
//!   it back.
//!
//! No ETS capture shows a partial download that links a previously unlinked
//! object on a 07B0 device yet, so the order (object table first, then the
//! link tables) follows the standard's procedure, not a capture.

use bussard_mgmt::connection::{L4Channel, Layer4Connection};
use bussard_mgmt::load::{
    LoadControl, LoadState, WriteError, allocate_segment, read_table_reference, write_load_control,
    write_memory_chunked,
};
use bussard_mgmt::tables::OT_GROUP_OBJECT_TABLE;

use crate::flash::{FlashPlan, FlashStep, ImageKind};

/// The load procedure's index of the group-object table object (`LsmIdx` /
/// `ObjIdx` 3), the object a System B full flash streams the table into.
pub const OBJECT_TABLE_INDEX: u32 = 3;

/// The Communication flag of a descriptor word (bit 10).
const COMMUNICATION: u16 = 1 << 10;

/// The model's group-object table image as the full flash `plan` writes it:
/// the table image its `WriteRelMem` streams into object 3. `None` on System 7
/// and when the load procedure does not write the table (a self-contained
/// procedure whose code image carries it), where `apply` leaves the table to
/// `flash` as before.
pub fn object_table_image(plan: &FlashPlan) -> Option<&[u8]> {
    if plan.is_sys7() {
        return None;
    }
    plan.steps.iter().find_map(|step| match step {
        FlashStep::WriteRelMem {
            offset: 0,
            image,
            target: Some(OBJECT_TABLE_INDEX),
        } if image.kind == ImageKind::Table => plan.image_bytes(&image.segment_id),
        _ => None,
    })
}

/// The entry count of a table image (its leading big-endian word).
fn image_count(image: &[u8]) -> usize {
    match image {
        [hi, lo, ..] => usize::from(u16::from_be_bytes([*hi, *lo])),
        _ => 0,
    }
}

/// The descriptor words of a table image, up to its entry count.
fn image_words(image: &[u8]) -> Vec<u16> {
    image
        .get(2..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .take(image_count(image))
        .map(|w| u16::from_be_bytes(*w))
        .collect()
}

/// A device's group-object table as read: its count word and the first
/// descriptors (as many as the model's table has, so a corrupt count never
/// turns into an unbounded read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveObjectTable {
    /// The interface-object index of the group-object table object.
    pub object_index: u8,
    /// Where the table starts, from `PID_TABLE_REFERENCE` (`0`: no segment,
    /// the object is unloaded).
    pub base: u32,
    /// The entry count the table's first word holds.
    pub count: u16,
    /// The descriptor words read, entry 1 first.
    pub descriptors: Vec<u16>,
}

impl LiveObjectTable {
    /// The octets read, in the image layout: the count word, then the
    /// descriptors read.
    pub fn image(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 * self.descriptors.len());
        out.extend_from_slice(&self.count.to_be_bytes());
        for w in &self.descriptors {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// Whether the table is exactly `model` (count and every descriptor).
    pub fn matches(&self, model: &[u8]) -> bool {
        usize::from(self.count) == image_count(model) && self.descriptors == image_words(model)
    }
}

/// One descriptor that differs between the device and the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorChange {
    /// The com-object number (the table's 1-based entry).
    pub object: u16,
    /// The device's descriptor word (`0`: no entry).
    pub from: u16,
    /// The model's descriptor word (`0`: no entry).
    pub to: u16,
}

impl DescriptorChange {
    /// Whether the change switches the Communication flag on.
    pub fn enables(&self) -> bool {
        self.from & COMMUNICATION == 0 && self.to & COMMUNICATION != 0
    }

    /// Whether the change switches the Communication flag off.
    pub fn disables(&self) -> bool {
        self.from & COMMUNICATION != 0 && self.to & COMMUNICATION == 0
    }

    /// `object 7: communication flag on (descriptor 1800 → 1C00)`.
    pub fn sentence(&self) -> String {
        let what = if self.enables() {
            "communication flag on"
        } else if self.disables() {
            "communication flag off"
        } else {
            "descriptor changes"
        };
        format!(
            "object {}: {what} (descriptor {:04X} → {:04X})",
            self.object, self.from, self.to
        )
    }
}

/// How the device's group-object table differs from the model's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectTableChange {
    /// The device's entry count.
    pub from_count: usize,
    /// The model's entry count.
    pub to_count: usize,
    /// The descriptors that differ, by object number.
    pub objects: Vec<DescriptorChange>,
}

impl ObjectTableChange {
    /// The differences between `live` and `model`; `None` when they agree.
    pub fn between(live: &LiveObjectTable, model: &[u8]) -> Option<ObjectTableChange> {
        if live.matches(model) {
            return None;
        }
        let words = image_words(model);
        let held = |i: usize| -> u16 {
            if i < usize::from(live.count) {
                live.descriptors.get(i).copied().unwrap_or(0)
            } else {
                0
            }
        };
        let objects = words
            .iter()
            .enumerate()
            .filter_map(|(i, &to)| {
                let from = held(i);
                let object = u16::try_from(i + 1).ok()?;
                (from != to).then_some(DescriptorChange { object, from, to })
            })
            .collect();
        Some(ObjectTableChange {
            from_count: usize::from(live.count),
            to_count: words.len(),
            objects,
        })
    }

    /// One sentence per difference, for a plan's notes.
    pub fn sentences(&self) -> Vec<String> {
        let mut out: Vec<String> = self.objects.iter().map(|c| c.sentence()).collect();
        if self.from_count != self.to_count {
            out.push(format!(
                "group-object table: {} entries on the device, {} in the model",
                self.from_count, self.to_count
            ));
        }
        out
    }
}

/// What the plan phase learned about the group-object table: the model's
/// image and the device's table, or why it could not be read.
#[derive(Debug, Clone)]
pub struct ObjectTableCheck {
    /// The image the full flash writes, which `apply` writes when it differs.
    pub model: Vec<u8>,
    /// The device's table, or why it was not read.
    pub live: Result<LiveObjectTable, String>,
}

impl ObjectTableCheck {
    /// How the device differs from the model; `None` when it matches or was
    /// not read.
    pub fn change(&self) -> Option<ObjectTableChange> {
        self.live
            .as_ref()
            .ok()
            .and_then(|live| ObjectTableChange::between(live, &self.model))
    }
}

/// Finds the group-object table object (type 9) among the device's interface
/// objects. A seeded connection answers from its seed.
pub async fn find_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<Option<u8>, WriteError> {
    let objects = bussard_mgmt::probe_object_types(l4)
        .await
        .map_err(WriteError::Mgmt)?;
    Ok(objects
        .iter()
        .find(|&&(_, ot)| ot == OT_GROUP_OBJECT_TABLE)
        .map(|&(index, _)| index))
}

/// Reads the group-object table of object `object_index`: its base from
/// `PID_TABLE_REFERENCE`, its count word, and at most `max_entries`
/// descriptors. An unloaded object (base `0`) reads as an empty table.
pub async fn read_object_table_at<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    max_entries: usize,
) -> Result<LiveObjectTable, WriteError> {
    let base = read_table_reference(l4, object_index).await?;
    if base == 0 {
        return Ok(LiveObjectTable {
            object_index,
            base,
            count: 0,
            descriptors: Vec::new(),
        });
    }
    let head = bussard_mgmt::read_memory_range(l4, base, 2).await?;
    let count = match head.as_slice() {
        [hi, lo] => u16::from_be_bytes([*hi, *lo]),
        _ => 0,
    };
    let entries = usize::from(count).min(max_entries);
    let body = bussard_mgmt::read_memory_range(l4, base + 2, 2 * entries).await?;
    Ok(LiveObjectTable {
        object_index,
        base,
        count,
        descriptors: body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|w| u16::from_be_bytes(*w))
            .collect(),
    })
}

/// Reads the device's group-object table and pairs it with the model's
/// image from `plan` (see the module docs). `None` when the plan does not
/// write the table ([`object_table_image`]); a read that fails is kept as
/// its reason, so the plan can say the table was not compared.
pub async fn check_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plan: &FlashPlan,
) -> Option<ObjectTableCheck> {
    let model = object_table_image(plan)?.to_vec();
    let live = match find_object_table(l4).await {
        Ok(Some(index)) => read_object_table_at(l4, index, image_count(&model))
            .await
            .map_err(|e| format!("the group-object table did not read: {e}")),
        Ok(None) => Err("the device lists no group-object table object (type 9)".to_string()),
        Err(e) => Err(format!("the interface objects did not read: {e}")),
    };
    Some(ObjectTableCheck { model, live })
}

/// What reloading the group-object table left on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectTableOutcome {
    /// The object's load state after `LoadCompleted` (must be `Loaded`).
    pub state: LoadState,
    /// Whether the table read back equals the written image.
    pub matches: bool,
    /// The entry count written.
    pub entries: usize,
}

impl ObjectTableOutcome {
    /// Loaded and read back equal.
    pub fn ok(&self) -> bool {
        self.state == LoadState::Loaded && self.matches
    }
}

/// Reloads the group-object table of object `object_index` with `image`
/// (count word and descriptors, as [`object_table_image`] gives it) and
/// reads it back.
///
/// The sequence is the standard's partial download of the table (03_05_03
/// §3.5.3) in the form `apply` already uses for the link tables:
/// `StartLoading`, a relative allocation sized to the image (no fill, as the
/// full flash allocates it), the image through `A_Memory_Write` /
/// `A_MemoryExtended_Write`, `LoadCompleted`, then a read of the table
/// through its fresh `PID_TABLE_REFERENCE`. A failure surfaces with the step;
/// the caller prints the recovery guidance.
pub async fn write_object_table<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    object_index: u8,
    image: &[u8],
) -> Result<ObjectTableOutcome, WriteError> {
    write_load_control(l4, object_index, LoadControl::StartLoading).await?;
    let segment = allocate_segment(l4, object_index, image.len() as u32, None).await?;
    write_memory_chunked(l4, segment.address, image, |_| {}).await?;
    let state = write_load_control(l4, object_index, LoadControl::LoadCompleted).await?;
    let entries = image_count(image);
    let back = read_object_table_at(l4, object_index, entries).await?;
    Ok(ObjectTableOutcome {
        state,
        matches: back.matches(image),
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(words: &[u16]) -> Vec<u8> {
        let mut out = (words.len() as u16).to_be_bytes().to_vec();
        for w in words {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn live(count: u16, descriptors: &[u16]) -> LiveObjectTable {
        LiveObjectTable {
            object_index: 3,
            base: 0x4000,
            count,
            descriptors: descriptors.to_vec(),
        }
    }

    #[test]
    fn test_object_table_change_names_a_communication_flag_switched_on() -> Result<(), String> {
        let model = image(&[0x1C00, 0x1C00, 0x0000]);
        let device = live(3, &[0x1C00, 0x1800, 0x0000]);
        let change = ObjectTableChange::between(&device, &model).ok_or("the tables differ")?;
        assert_eq!(
            change.objects,
            vec![DescriptorChange {
                object: 2,
                from: 0x1800,
                to: 0x1C00
            }]
        );
        assert!(change.objects[0].enables());
        assert_eq!(
            change.sentences(),
            vec!["object 2: communication flag on (descriptor 1800 → 1C00)".to_string()]
        );
        Ok(())
    }

    #[test]
    fn test_object_table_change_none_when_equal() {
        let model = image(&[0x1C00, 0x0800]);
        assert!(ObjectTableChange::between(&live(2, &[0x1C00, 0x0800]), &model).is_none());
        assert!(live(2, &[0x1C00, 0x0800]).matches(&model));
    }

    #[test]
    fn test_object_table_change_counts_a_shorter_device_table() -> Result<(), String> {
        let model = image(&[0x1C00, 0x1C00]);
        let change =
            ObjectTableChange::between(&live(1, &[0x1C00]), &model).ok_or("the tables differ")?;
        assert_eq!(change.from_count, 1);
        assert_eq!(change.to_count, 2);
        assert_eq!(change.objects.len(), 1);
        assert_eq!(change.objects[0].from, 0);
        assert!(change.objects[0].enables());
        assert_eq!(change.sentences().len(), 2);
        Ok(())
    }

    #[test]
    fn test_object_table_change_unloaded_table_differs() {
        let model = image(&[0x1C00]);
        assert!(ObjectTableChange::between(&live(0, &[]), &model).is_some());
    }

    #[test]
    fn test_descriptor_change_sentence_for_a_flag_switched_off() {
        let change = DescriptorChange {
            object: 9,
            from: 0x1C00,
            to: 0x1800,
        };
        assert!(change.disables());
        assert_eq!(
            change.sentence(),
            "object 9: communication flag off (descriptor 1C00 → 1800)"
        );
    }
}
