//! The load-control records a flash step sends, as the wire carries them: the
//! offline oracle compares them with an ETS capture (issue #419).
//!
//! A load-control record is a write to a load-state machine: the 10-octet
//! `PID_LOAD_STATE_CONTROL` (PID 5) value on an index-addressed object (System
//! B, and the System 7 property realisation), or the 11-octet memory-mapped
//! record a System 7 `0701` device takes at its LSM control address. The
//! records come from the same encoders the executors call, so a dry run can
//! list them without a device. The KNX Data Secure security object's load
//! control ([`FlashStep::SecurityLoadControl`]) goes out on the extended
//! function-property service and is compared with the property writes, not
//! here.

use bussard_mgmt::{LoadControl, LsmAccess, sys7};

use super::{FlashPlan, FlashStep};

/// Where a load-control record goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadControlForm {
    /// `A_PropertyValue_Write` of `PID_LOAD_STATE_CONTROL` on an object.
    Property {
        /// The object index, or `None` when the step names no index and the
        /// executor resolves it to the discovered application object on the
        /// device (System B).
        object: Option<u32>,
    },
    /// `A_Memory_Write` of the 11-octet System 7 LSM record.
    Memory {
        /// The 1-based load-state machine the record's opcode nibble names.
        lsm: u8,
        /// The LSM control address the record is written to.
        address: u16,
    },
}

/// One load-control record a step sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadControlRecord {
    /// Where the record goes.
    pub form: LoadControlForm,
    /// What the record does: `unload`, `start-loading`, `load-completed`,
    /// `abs-segment`, `rel-segment`, `task-segment` or `task-ctrl1`.
    pub event: &'static str,
    /// The record's octets as written.
    pub bytes: Vec<u8>,
}

impl FlashPlan {
    /// The load-control records `step` sends, in order, as the executor
    /// encodes them. Empty for a step that sends none.
    ///
    /// Not modelled: the re-open and re-allocation a System B
    /// [`FlashStep::MasterReset`] runs only when the device reports the object
    /// unloaded after the reset (KNX Virtual), since that depends on the
    /// device's answer.
    pub fn load_control_records(&self, step: &FlashStep) -> Vec<LoadControlRecord> {
        match self.sys7_lsm_access() {
            Some(access) => sys7_records(&access, step),
            None => system_b_records(step),
        }
    }
}

fn simple(control: LoadControl) -> &'static str {
    match control {
        LoadControl::Unload => "unload",
        LoadControl::StartLoading => "start-loading",
        LoadControl::LoadCompleted => "load-completed",
        LoadControl::AdditionalLoadControls => "additional",
        LoadControl::NoOperation => "no-operation",
    }
}

fn system_b_records(step: &FlashStep) -> Vec<LoadControlRecord> {
    let simple_record = |target: Option<u32>, control: LoadControl| LoadControlRecord {
        form: LoadControlForm::Property { object: target },
        event: simple(control),
        bytes: control.encode_full().to_vec(),
    };
    match step {
        FlashStep::Unload { target, .. } => vec![simple_record(*target, LoadControl::Unload)],
        FlashStep::StartLoading { target } => {
            vec![simple_record(*target, LoadControl::StartLoading)]
        }
        FlashStep::LoadCompleted { target } => {
            vec![simple_record(*target, LoadControl::LoadCompleted)]
        }
        FlashStep::AllocateSegment { size, target, fill } => vec![LoadControlRecord {
            form: LoadControlForm::Property { object: *target },
            event: "rel-segment",
            bytes: bussard_mgmt::encode_rel_segment(*size, fill.mode, fill.fill).to_vec(),
        }],
        _ => Vec::new(),
    }
}

/// A System 7 record field the plan carries that does not fit the record (the
/// planner refuses such a plan; a hand-built one can carry it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sys7FieldOutOfRange {
    /// The field, as the error names it.
    pub field: &'static str,
    /// Its value.
    pub value: u32,
}

impl Sys7FieldOutOfRange {
    /// Why the record cannot carry the value.
    pub(super) fn detail(&self) -> String {
        let Self { field, value } = *self;
        if field == "task control count" {
            format!(
                "System 7 task control count {value} does not fit the record's single count octet"
            )
        } else {
            format!("System 7 {field} {value:#X} exceeds the 16-bit A_Memory space")
        }
    }
}

/// `value` as the record's 16-bit field, or the field named out of range.
fn field_u16(field: &'static str, value: u32) -> Result<u16, Sys7FieldOutOfRange> {
    u16::try_from(value).map_err(|_| Sys7FieldOutOfRange { field, value })
}

/// One 10-octet System 7 load event: the LSM it goes to, what it does, and
/// its octets.
pub(super) type Sys7Event = (u32, &'static str, [u8; sys7::LOAD_EVENT_SIZE]);

impl FlashStep {
    /// The 10-octet System 7 event this step sends to its load-state machine,
    /// as both the executor and [`FlashPlan::load_control_records`] encode it;
    /// `None` for a step that sends none (or several: the pre-download
    /// unloads).
    pub(super) fn sys7_event(&self) -> Option<Result<Sys7Event, Sys7FieldOutOfRange>> {
        let simple_event = |lsm: u32, control: LoadControl| {
            Ok((lsm, simple(control), sys7::simple_event(control)))
        };
        Some(match self {
            FlashStep::Sys7Unload { lsm } => simple_event(*lsm, LoadControl::Unload),
            FlashStep::Sys7StartLoading { lsm } => simple_event(*lsm, LoadControl::StartLoading),
            FlashStep::Sys7LoadCompleted { lsm } => simple_event(*lsm, LoadControl::LoadCompleted),
            FlashStep::Sys7AbsSegment {
                lsm,
                address,
                size,
                mem_type,
                access,
                seg_flags,
                seg_type,
                ..
            } => field_u16("segment address", *address).and_then(|address| {
                let size = field_u16("segment size", *size)?;
                Ok((
                    *lsm,
                    "abs-segment",
                    sys7::encode_alloc_segment(
                        *seg_type, address, size, *access, *mem_type, *seg_flags,
                    ),
                ))
            }),
            FlashStep::Sys7TaskSegment {
                lsm,
                address,
                identity,
            } => field_u16("task segment address", *address).map(|address| {
                (
                    *lsm,
                    "task-segment",
                    sys7::encode_task_segment(address, identity),
                )
            }),
            FlashStep::Sys7TaskCtrl1 {
                lsm,
                address,
                count,
            } => field_u16("task control address", *address).and_then(|address| {
                let count = u8::try_from(*count).map_err(|_| Sys7FieldOutOfRange {
                    field: "task control count",
                    value: *count,
                })?;
                Ok((*lsm, "task-ctrl1", sys7::encode_task_ctrl1(address, count)))
            }),
            FlashStep::Sys7TaskPtr {
                lsm,
                init,
                save,
                pei_handler,
            } => Ok((
                *lsm,
                "task-ptr",
                sys7::encode_task_ptr(*init, *save, *pei_handler),
            )),
            FlashStep::Sys7TaskCtrl2 {
                lsm,
                callback,
                com_objects,
                segment_1,
                segment_2,
            } => Ok((
                *lsm,
                "task-ctrl2",
                sys7::encode_task_ctrl2(*callback, *com_objects, *segment_1, *segment_2),
            )),
            _ => return None,
        })
    }
}

/// The 10-octet System 7 events of `step`, with the LSM each goes to. A field
/// the plan validated as out of range (the planner refuses such a plan) yields
/// no event.
fn sys7_events(step: &FlashStep) -> Vec<Sys7Event> {
    match step {
        FlashStep::Sys7PreDownloadRestart { unload } => unload
            .iter()
            .map(|lsm| {
                (
                    *lsm,
                    simple(LoadControl::Unload),
                    sys7::simple_event(LoadControl::Unload),
                )
            })
            .collect(),
        _ => step.sys7_event().and_then(Result::ok).into_iter().collect(),
    }
}

fn sys7_records(access: &LsmAccess, step: &FlashStep) -> Vec<LoadControlRecord> {
    sys7_events(step)
        .into_iter()
        .filter_map(|(lsm, event, bytes)| {
            // The executor refuses an LSM outside 1..=15 (`lsm_octet`).
            let octet = u8::try_from(lsm)
                .ok()
                .filter(|idx| (1..=15).contains(idx))?;
            Some(match access {
                LsmAccess::Property => LoadControlRecord {
                    form: LoadControlForm::Property {
                        object: Some(u32::from(octet)),
                    },
                    event,
                    bytes: bytes.to_vec(),
                },
                LsmAccess::MemoryMapped { control_addr, .. } => LoadControlRecord {
                    form: LoadControlForm::Memory {
                        lsm: octet,
                        address: *control_addr,
                    },
                    event,
                    bytes: sys7::wrap_memory_lsm_record(octet, &bytes).to_vec(),
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::SegmentFill;

    #[test]
    fn test_system_b_records_rel_segment_with_fill() {
        let records = system_b_records(&FlashStep::AllocateSegment {
            size: 0x0100,
            target: Some(4),
            fill: SegmentFill::filled(0xFF),
        });
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].form,
            LoadControlForm::Property { object: Some(4) }
        );
        assert_eq!(
            records[0].bytes,
            vec![0x03, 0x0B, 0x00, 0x00, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x00]
        );
    }

    #[test]
    fn test_system_b_records_rel_segment_mode_0_fill_255() {
        // `syn-relseg-fill`: `LdCtrlRelSegment LsmIdx="4" Size="256" Mode="0"
        // Fill="255"`. ETS sends `03 0b 00 00 01 00 00 ff 00 00`
        // (captures/synthetic/syn-relseg-fill/defaults/ops.txt op 17, #480).
        let records = system_b_records(&FlashStep::AllocateSegment {
            size: 0x0100,
            target: Some(4),
            fill: SegmentFill {
                mode: 0x00,
                fill: 0xFF,
            },
        });
        assert_eq!(
            records[0].bytes,
            vec![0x03, 0x0B, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0x00]
        );
    }

    #[test]
    fn test_system_b_records_rel_segment_table_object() {
        // A table object allocation: `00 00`, as in the house's 07B0
        // captures (1.1.7 and 1.1.8 obj1-3).
        let records = system_b_records(&FlashStep::AllocateSegment {
            size: 42,
            target: Some(1),
            fill: SegmentFill::NONE,
        });
        assert_eq!(
            records[0].bytes,
            vec![0x03, 0x0B, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_system_b_records_unload_unresolved_object() {
        let records = system_b_records(&FlashStep::Unload {
            target: None,
            absent_ok: false,
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].form, LoadControlForm::Property { object: None });
        assert_eq!(records[0].event, "unload");
        assert_eq!(records[0].bytes[0], 0x04);
    }

    #[test]
    fn test_sys7_records_memory_mapped_matches_capture() {
        // Theben 0701 Meteodata capture: `33 04 00 46 eb 01 00 00 00 00 00`.
        let access = LsmAccess::MemoryMapped {
            control_addr: 0x0104,
            status_addr: 0xB6EA,
        };
        let records = sys7_records(
            &access,
            &FlashStep::Sys7TaskCtrl1 {
                lsm: 3,
                address: 0x46EB,
                count: 1,
            },
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].form,
            LoadControlForm::Memory {
                lsm: 3,
                address: 0x0104
            }
        );
        assert_eq!(
            records[0].bytes,
            vec![
                0x33, 0x04, 0x00, 0x46, 0xEB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn test_sys7_records_pre_download_unloads_each_lsm() {
        let records = sys7_records(
            &LsmAccess::Property,
            &FlashStep::Sys7PreDownloadRestart {
                unload: vec![1, 2, 3, 4],
            },
        );
        let objects: Vec<_> = records.iter().map(|r| r.form).collect();
        assert_eq!(
            objects,
            (1..=4)
                .map(|o| LoadControlForm::Property { object: Some(o) })
                .collect::<Vec<_>>()
        );
        assert!(
            records
                .iter()
                .all(|r| r.bytes[0] == 0x04 && r.bytes.len() == 10)
        );
    }

    #[test]
    fn test_sys7_records_stack_segment_matches_ets() {
        // Issue #487, MDT `M-0083_A-0222-21-0004` LSM 3 record 4: ETS sends
        // `03 01 07 f6 00 01 00 02 00 00` for the `SegType="1"` allocation.
        let records = sys7_records(
            &LsmAccess::Property,
            &FlashStep::Sys7AbsSegment {
                lsm: 3,
                address: 0x07F6,
                size: 1,
                mem_type: 2,
                access: 0,
                seg_flags: 0,
                seg_type: sys7::S7_SUB_ALLOC_STACK,
                image: None,
            },
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].bytes,
            vec![0x03, 0x01, 0x07, 0xF6, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00]
        );
    }

    #[test]
    fn test_sys7_records_lsm_out_of_range_yields_nothing() {
        let records = sys7_records(&LsmAccess::Property, &FlashStep::Sys7Unload { lsm: 16 });
        assert!(records.is_empty());
    }
}
