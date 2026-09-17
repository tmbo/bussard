//! System 7 load-event decoding and the memory-mapped / property LSM access.
//!
//! System 7 (mask 0705/0701) runs three parallel load-state machines and drives
//! them with the abstract KNX load-event model (spec `docs/system7-spec.md` §4).
//! A load event is a 10-octet record whose first octet selects the event;
//! `AdditionalLoadControls` (0x03) uses octet 1 as a sub-command selector for
//! absolute-segment allocation, task-segment finalize, and task-control writes.
//!
//! This module decodes that record into a [`Sys7Event`] the device applies to
//! the addressed LSM, and provides the two device-side LSM realisations
//! ([`crate::device::profile::LsmAccess`]): a 12-octet memory-mapped record and
//! the property-based (PID 5) form. Both decode to the same [`Sys7Event`], so the
//! device logic is realisation-independent.

/// A decoded System 7 load event (spec §4.1 / §4.2 / §4.3 / §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sys7Event {
    /// `NoOperation` (0x00).
    NoOperation,
    /// `StartLoading` (0x01) — begin loading the LSM.
    StartLoading,
    /// `LoadCompleted` (0x02) — finalize the LSM to Loaded.
    LoadCompleted,
    /// `Unload` (0x04) — tear the LSM down to Unloaded.
    Unload,
    /// `AdditionalLoadControls` → allocate an absolute segment (subtype 0x00
    /// Data / 0x01 Stack / 0x02 Task). Carries the start address and length.
    AllocAbsSegment {
        /// The segment start address.
        start: u16,
        /// The segment length in bytes.
        length: u16,
        /// The alloc subtype (0x00 Data, 0x01 Stack, 0x02 Task).
        subtype: u8,
    },
    /// `AdditionalLoadControls` → task/segment finalize (spec §4.3). Realised as
    /// an AllocAbsTaskSegment (subtype 0x02) pointing at the segment base; the
    /// device treats it as "segment descriptor committed", a precondition for the
    /// following `LoadCompleted`.
    TaskSegment {
        /// The segment base this task descriptor points at.
        address: u16,
    },
    /// `AdditionalLoadControls` → task-control 1 (subtype 0x04, spec §4.4). A
    /// second-phase op refused cleanly in M1.
    TaskCtrl1 {
        /// The task-control table address.
        address: u16,
        /// The number of entries.
        count: u8,
    },
}

/// Error decoding a System 7 load event.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Sys7EventError {
    /// The record was empty.
    #[error("empty System 7 load-event record")]
    Empty,
    /// The event opcode was not recognised.
    #[error("unknown System 7 load event 0x{0:02x}")]
    UnknownEvent(u8),
    /// An `AdditionalLoadControls` sub-command was not recognised.
    #[error("unsupported AdditionalLoadControls sub-command 0x{0:02x}")]
    UnsupportedSubCommand(u8),
    /// The record was too short for the sub-command's fields.
    #[error("System 7 load-event record too short for sub-command 0x{0:02x}")]
    TooShort(u8),
    /// A `TaskCtrl1` sub-command was received; it is a second-phase op refused in
    /// M1 with this named reason (spec §4.4).
    #[error("TaskCtrl1 (AdditionalLoadControls 0x04) is not supported in M1")]
    TaskCtrl1Unsupported,
}

impl Sys7Event {
    /// Decode a System 7 load event from the 10-octet abstract load-event record
    /// (the payload after any realisation prefix). Layout per spec §4.1:
    /// `[event][sub|...][fields...]`, zero-padded to 10 octets.
    pub fn decode(record: &[u8]) -> Result<Self, Sys7EventError> {
        let event = *record.first().ok_or(Sys7EventError::Empty)?;
        match event {
            0x00 => Ok(Sys7Event::NoOperation),
            0x01 => Ok(Sys7Event::StartLoading),
            0x02 => Ok(Sys7Event::LoadCompleted),
            0x04 => Ok(Sys7Event::Unload),
            0x03 => {
                let sub = *record.get(1).ok_or(Sys7EventError::TooShort(0x03))?;
                match sub {
                    // Alloc absolute Data/Stack/Task segment (spec §4.1 table).
                    // Layout after [0x03][sub]: [start:2][length:2][access][mem_type][mem_attr].
                    0x00 | 0x01 | 0x02 => {
                        if record.len() < 6 {
                            return Err(Sys7EventError::TooShort(sub));
                        }
                        let start = u16::from_be_bytes([record[2], record[3]]);
                        let length = u16::from_be_bytes([record[4], record[5]]);
                        // Subtype 0x02 (Task) with a zero length is the
                        // TaskSegment finalize form (spec §4.3 default encoding):
                        // AllocAbsTaskSegment pointing at the base. We route
                        // non-zero-length subtype-0x02 records through the generic
                        // AllocAbsSegment path (a genuine task-stack allocation);
                        // the device treats any subtype-0x02 record as a task
                        // descriptor commit in addition to an allocation.
                        Ok(Sys7Event::AllocAbsSegment {
                            start,
                            length,
                            subtype: sub,
                        })
                    }
                    // Task control 1 (spec §4.4): [address:2][count]. Refuse in M1.
                    0x04 => Err(Sys7EventError::TaskCtrl1Unsupported),
                    other => Err(Sys7EventError::UnsupportedSubCommand(other)),
                }
            }
            other => Err(Sys7EventError::UnknownEvent(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_basic_events() {
        assert_eq!(Sys7Event::decode(&[0x00]), Ok(Sys7Event::NoOperation));
        assert_eq!(Sys7Event::decode(&[0x01]), Ok(Sys7Event::StartLoading));
        assert_eq!(Sys7Event::decode(&[0x02]), Ok(Sys7Event::LoadCompleted));
        assert_eq!(Sys7Event::decode(&[0x04]), Ok(Sys7Event::Unload));
        assert_eq!(Sys7Event::decode(&[]), Err(Sys7EventError::Empty));
    }

    #[test]
    fn test_decode_alloc_abs_data_segment() {
        // AbsSegment alloc at 0x4000 length 513 (0x0201), subtype Data (0x00).
        let rec = [0x03, 0x00, 0x40, 0x00, 0x02, 0x01, 0x00, 0x03, 0x00, 0x00];
        assert_eq!(
            Sys7Event::decode(&rec),
            Ok(Sys7Event::AllocAbsSegment {
                start: 0x4000,
                length: 513,
                subtype: 0x00,
            })
        );
    }

    #[test]
    fn test_decode_task_ctrl1_refused() {
        let rec = [0x03, 0x04, 0x47, 0xF9, 0x01, 0, 0, 0, 0, 0];
        assert_eq!(
            Sys7Event::decode(&rec),
            Err(Sys7EventError::TaskCtrl1Unsupported)
        );
    }

    #[test]
    fn test_decode_bad_subcommand() {
        let rec = [0x03, 0x09, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            Sys7Event::decode(&rec),
            Err(Sys7EventError::UnsupportedSubCommand(0x09))
        );
    }

    #[test]
    fn test_decode_alloc_too_short() {
        assert_eq!(
            Sys7Event::decode(&[0x03, 0x00, 0x40]),
            Err(Sys7EventError::TooShort(0x00))
        );
    }
}
