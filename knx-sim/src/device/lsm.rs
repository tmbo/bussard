//! The load-state machine (LSM) for one loadable interface object.
//!
//! A System-B loadable object moves through load states driven by writes to
//! `PID_LOAD_STATE_CONTROL` (PID 5). The load-control byte written selects a
//! *load event*; the device answers by reporting the resulting *load state*.
//!
//! Load events (first data byte of a PID 5 write):
//!
//! ```text
//!   0x01  StartLoading
//!   0x02  LoadCompleted
//!   0x03  AdditionalLoadControls (sub-command in following bytes)
//!   0x04  Unload
//! ```
//!
//! Load states (reported back by a PID 5 read, and echoed in the write
//! response):
//!
//! ```text
//!   0x00  Unloaded
//!   0x01  Loaded
//!   0x02  Loading
//!   0x03  Error
//! ```
//!
//! The `AdditionalLoadControls` sub-command `0x0B` is `RelSegment`: it allocates
//! a relative segment whose size is the 4 bytes at data\[2..6] big-endian. These
//! encodings match the ETS→KNX-Virtual capture and the KNX device-management
//! model (System B).

/// The load state of one loadable object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    /// No valid data loaded.
    Unloaded,
    /// Fully loaded and operational.
    Loaded,
    /// Mid-load (allocation/writes in progress).
    Loading,
    /// The last load event was rejected or invalid.
    Error,
}

impl LoadState {
    /// The wire byte reported for this state.
    pub fn to_byte(self) -> u8 {
        match self {
            LoadState::Unloaded => 0x00,
            LoadState::Loaded => 0x01,
            LoadState::Loading => 0x02,
            LoadState::Error => 0x03,
        }
    }
}

/// A load event decoded from a `PID_LOAD_STATE_CONTROL` write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadEvent {
    /// `StartLoading` (0x01).
    StartLoading,
    /// `LoadCompleted` (0x02).
    LoadCompleted,
    /// `AdditionalLoadControls` → `RelSegment` (0x03, sub 0x0B) with a size.
    AllocRelSegment {
        /// The requested segment size in bytes.
        size: u32,
    },
    /// `Unload` (0x04).
    Unload,
}

/// Error decoding a load-control write payload.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoadEventError {
    /// The payload was empty.
    #[error("empty load-control payload")]
    Empty,
    /// The load event byte was not recognised.
    #[error("unknown load event 0x{0:02x}")]
    UnknownEvent(u8),
    /// An AdditionalLoadControls sub-command was not recognised.
    #[error("unsupported AdditionalLoadControls sub-command 0x{0:02x}")]
    UnsupportedSubCommand(u8),
    /// A RelSegment allocation was missing its 4-byte size field.
    #[error("RelSegment allocation missing size field")]
    MissingSize,
}

impl LoadEvent {
    /// Decode a load event from the data bytes of a PID 5 write.
    pub fn decode(data: &[u8]) -> Result<Self, LoadEventError> {
        let first = *data.first().ok_or(LoadEventError::Empty)?;
        match first {
            0x01 => Ok(LoadEvent::StartLoading),
            0x02 => Ok(LoadEvent::LoadCompleted),
            0x03 => {
                let sub = *data.get(1).ok_or(LoadEventError::MissingSize)?;
                if sub != 0x0B {
                    return Err(LoadEventError::UnsupportedSubCommand(sub));
                }
                if data.len() < 6 {
                    return Err(LoadEventError::MissingSize);
                }
                let size = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                Ok(LoadEvent::AllocRelSegment { size })
            }
            0x04 => Ok(LoadEvent::Unload),
            other => Err(LoadEventError::UnknownEvent(other)),
        }
    }
}

/// The load-state machine for one object: its current state plus the segment
/// size allocated (if any). Strict: transitions that violate the model move the
/// object to `Error` and are reported as rejected.
#[derive(Debug, Clone)]
pub struct LoadStateMachine {
    state: LoadState,
    allocated_size: Option<u32>,
}

impl Default for LoadStateMachine {
    fn default() -> Self {
        Self {
            state: LoadState::Unloaded,
            allocated_size: None,
        }
    }
}

impl LoadStateMachine {
    /// Create an LSM in the given initial state.
    pub fn new(initial: LoadState) -> Self {
        Self {
            state: initial,
            allocated_size: None,
        }
    }

    /// The current load state.
    pub fn state(&self) -> LoadState {
        self.state
    }

    /// The size allocated for this object's segment, if allocation happened.
    pub fn allocated_size(&self) -> Option<u32> {
        self.allocated_size
    }

    /// Apply a load event, enforcing the transition rules. On success returns
    /// the new state; on a rule violation returns `Err(())` and moves to
    /// `Error` (a real device reports `Error` on the next state read).
    pub fn apply(&mut self, event: LoadEvent) -> Result<LoadState, TransitionError> {
        match (self.state, event) {
            // Unload is always accepted and returns to Unloaded.
            (_, LoadEvent::Unload) => {
                self.state = LoadState::Unloaded;
                self.allocated_size = None;
            }
            // StartLoading is accepted from Unloaded or Loaded (re-flash) and
            // enters Loading.
            (LoadState::Unloaded | LoadState::Loaded, LoadEvent::StartLoading) => {
                self.state = LoadState::Loading;
                self.allocated_size = None;
            }
            // Allocation is only valid while Loading.
            (LoadState::Loading, LoadEvent::AllocRelSegment { size }) => {
                self.allocated_size = Some(size);
            }
            // LoadCompleted is only valid from Loading and finalises to Loaded.
            (LoadState::Loading, LoadEvent::LoadCompleted) => {
                self.state = LoadState::Loaded;
            }
            // Anything else is an illegal transition.
            (state, event) => {
                self.state = LoadState::Error;
                return Err(TransitionError { from: state, event });
            }
        }
        Ok(self.state)
    }
}

/// An illegal load-state transition was attempted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("illegal load-state transition: {event:?} from {from:?}")]
pub struct TransitionError {
    /// The state the object was in.
    pub from: LoadState,
    /// The event that was rejected.
    pub event: LoadEvent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_load_events() -> Result<(), LoadEventError> {
        assert_eq!(LoadEvent::decode(&[0x01])?, LoadEvent::StartLoading);
        assert_eq!(LoadEvent::decode(&[0x02])?, LoadEvent::LoadCompleted);
        assert_eq!(LoadEvent::decode(&[0x04])?, LoadEvent::Unload);
        assert_eq!(
            LoadEvent::decode(&[0x03, 0x0b, 0x00, 0x00, 0x01, 0x00])?,
            LoadEvent::AllocRelSegment { size: 256 }
        );
        Ok(())
    }

    #[test]
    fn test_decode_bad_subcommand() {
        assert_eq!(
            LoadEvent::decode(&[0x03, 0xff, 0, 0, 0, 0]),
            Err(LoadEventError::UnsupportedSubCommand(0xff))
        );
    }

    #[test]
    fn test_happy_path_reaches_loaded() -> Result<(), TransitionError> {
        let mut lsm = LoadStateMachine::default();
        assert_eq!(lsm.apply(LoadEvent::StartLoading)?, LoadState::Loading);
        assert_eq!(
            lsm.apply(LoadEvent::AllocRelSegment { size: 256 })?,
            LoadState::Loading
        );
        assert_eq!(lsm.allocated_size(), Some(256));
        assert_eq!(lsm.apply(LoadEvent::LoadCompleted)?, LoadState::Loaded);
        Ok(())
    }

    #[test]
    fn test_load_completed_without_start_is_rejected() {
        let mut lsm = LoadStateMachine::default();
        let err = lsm.apply(LoadEvent::LoadCompleted);
        assert!(err.is_err());
        assert_eq!(lsm.state(), LoadState::Error);
    }

    #[test]
    fn test_alloc_before_start_is_rejected() {
        let mut lsm = LoadStateMachine::default();
        assert!(lsm.apply(LoadEvent::AllocRelSegment { size: 256 }).is_err());
        assert_eq!(lsm.state(), LoadState::Error);
    }
}
