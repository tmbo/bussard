//! The address write once for every surface and flow (issue #902): the wait
//! for the one device in programming mode, the check that the target is
//! free, the confirmation, the `A_IndividualAddress_Write`, the independent
//! read-back and the programming-mode re-check.
//!
//! `bussard assign`, `adopt`, `replace` and `commission` and the MCP tools
//! `knx_add_device`, `knx_replace_device` and `knx_commission_line` run these
//! steps through one [`Observer`]; the bus functions underneath are
//! [`crate::assign`]'s (the address write and the verify read-back stay the
//! same functions). Nothing here prints: a [`Stop`] names why a flow did not
//! go on, and the surface words it.

use std::time::Duration;

use bussard_model::IndividualAddress;

use super::{Declined, Observer, Question, Step, ask};
use crate::assign::{
    AssignError, Occupant, ProgrammingWait, Verified, VerifyError, VerifyKey, WaitEvent,
    in_programming_mode, probe_occupant, still_in_programming_mode, verify_assignment_with,
    wait_for_programming_mode, write_address,
};
use crate::identity::SecureStatus;
use crate::{BusService, ServiceError};

/// Why an addressing flow stopped. Every variant before the address write
/// means nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum Stop {
    /// Several devices are in programming mode; a flow works on one.
    #[error("{} devices are in programming mode", .0.len())]
    Several(Vec<IndividualAddress>),
    /// Nothing entered programming mode within the budget.
    #[error("no device entered programming mode within {}s", .waited.as_secs())]
    Nothing {
        /// The budget waited.
        waited: Duration,
    },
    /// The device in programming mode is no longer the one identified
    /// (`now` are the devices in programming mode now).
    #[error("{current} is no longer the one device in programming mode")]
    Moved {
        /// Where it answered before.
        current: IndividualAddress,
        /// What answers the programming-mode broadcast now.
        now: Vec<IndividualAddress>,
    },
    /// Something answers at the address to be given (Management Procedures
    /// 03_05_02 §2.3, issue #530).
    #[error("{target} is already in use: a device answers there ({})", .occupant.describe())]
    Occupied {
        /// The address.
        target: IndividualAddress,
        /// What answers there.
        occupant: Occupant,
    },
    /// The device in programming mode did not answer the identification.
    #[error("connecting to the device in programming mode at {current}")]
    Identify {
        /// Where it answered the programming-mode broadcast.
        current: IndividualAddress,
        /// The cause.
        #[source]
        source: ServiceError,
    },
    /// The human said no, or could not be asked.
    #[error(transparent)]
    Declined(#[from] Declined),
    /// The flow refuses; the sentence says why.
    #[error("{0}")]
    Refused(String),
    /// The read-back of a device that hides its mask found no tool key to
    /// open it with ([`Assign::refuse_hidden`]).
    #[error("the device hides its mask and no tool key opens it")]
    Hidden(Box<Verified>),
    /// The device answering at the new address is not the one identified
    /// ([`Assign::require_identified`]).
    #[error("the device answering at {target} is not the one identified")]
    OtherDevice {
        /// The new address.
        target: IndividualAddress,
        /// What the read-back there reported.
        verified: Box<Verified>,
    },
    /// The address broadcast failed.
    #[error("broadcasting the new individual address")]
    Write(#[source] AssignError),
    /// The read-back at the new address failed.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// The address, the model, the bus lease or a broadcast failed.
    #[error(transparent)]
    Assign(#[from] AssignError),
    /// Another step failed; the error says which.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Stop {
    /// Wraps any other failure.
    pub fn other(err: impl std::error::Error + Send + Sync + 'static) -> Stop {
        Stop::Other(Box::new(err))
    }
}

/// One address write, as [`AssignFlow::assign`] runs it.
#[derive(Debug, Clone)]
pub struct Assign<'a> {
    /// Where the device answered the programming-mode broadcast.
    pub current: IndividualAddress,
    /// The address it gets. Equal to `current`: nothing is written, the
    /// device is only read back (an adopted device that keeps its address).
    pub target: IndividualAddress,
    /// The question before the write; `None` when the yes came earlier.
    pub question: Option<&'a Question>,
    /// The tool key of the read-back (issue #203).
    pub key: &'a VerifyKey,
    /// Clear programming mode in the read-back, as ETS does (`adopt` does
    /// not: its broadcast re-check warns instead).
    pub clear_programming_mode: bool,
    /// What the identification before the write read: the read-back is
    /// compared with it (serial and mask).
    pub identified: Option<&'a Verified>,
    /// A read-back that finds the mask hidden and no key is [`Stop::Hidden`]
    /// (`adopt`, issue #201); otherwise it is the outcome.
    pub refuse_hidden: bool,
    /// A read-back that names another device than the identified one is
    /// [`Stop::OtherDevice`] (`commission`, `knx_replace_device`); otherwise
    /// [`Assigned::matches_identified`] says so.
    pub require_identified: bool,
    /// The model directory whose stored device facts of `target` are dropped
    /// once the new box answers there ([`forget_facts`]); `None` keeps them.
    pub forget_facts: Option<&'a std::path::Path>,
}

/// The device after its address was written (or kept) and read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assigned {
    /// Where it answered the programming-mode broadcast.
    pub current: IndividualAddress,
    /// Its address now.
    pub target: IndividualAddress,
    /// What the read-back at `target` reported (its warnings included).
    pub verified: Verified,
    /// The address was broadcast (`false` when the device kept it).
    pub written: bool,
    /// It still answers the programming-mode broadcast after the write.
    pub still_in_programming_mode: bool,
    /// The read-back names the identified device (serial and mask), or
    /// nothing was identified to compare with.
    pub matches_identified: bool,
}

/// The bus and the source address an addressing flow runs on.
#[derive(Clone, Copy)]
pub struct AssignFlow<'a> {
    /// The bus.
    pub service: &'a BusService,
    /// The checked source address.
    pub source: IndividualAddress,
}

impl AssignFlow<'_> {
    /// Waits for exactly one device in programming mode, telling the
    /// observer the button prompt, the reminder and the countdown.
    ///
    /// # Errors
    ///
    /// [`Stop::Several`], [`Stop::Nothing`], or the broadcast failed.
    pub async fn wait_for_one<O: Observer + Send>(
        &self,
        observer: &mut O,
    ) -> Result<IndividualAddress, Stop> {
        observer.step(Step::PressButton);
        let mut on_event = |event: WaitEvent| {
            observer.step(match event {
                WaitEvent::Remind => Step::Remind,
                WaitEvent::Waiting { remaining } => Step::Waiting { remaining },
            });
        };
        let found = wait_for_programming_mode(self.service, self.source, &mut on_event).await?;
        match found {
            ProgrammingWait::One(current) => {
                observer.step(Step::Found { current });
                Ok(current)
            }
            ProgrammingWait::Several(found) => Err(Stop::Several(found)),
            ProgrammingWait::Nothing { waited } => Err(Stop::Nothing { waited }),
        }
    }

    /// The fresh read before a write that was confirmed earlier: `current`
    /// is still the one device in programming mode.
    ///
    /// # Errors
    ///
    /// [`Stop::Moved`], or the broadcast failed.
    pub async fn still_the_one(&self, current: IndividualAddress) -> Result<(), Stop> {
        let now = in_programming_mode(self.service, self.source).await?;
        if now != [current] {
            return Err(Stop::Moved { current, now });
        }
        Ok(())
    }

    /// Step 1 of NM_IndividualAddress_Write (Management Procedures 03_05_02
    /// §2.3, issue #530): nothing may answer at `target`. `Ok(None)` when it
    /// is free; with `force` an occupant is `Ok(Some(occupant))` for the
    /// surface to warn about.
    ///
    /// # Errors
    ///
    /// [`Stop::Occupied`] without `force`.
    pub async fn check_free<O: Observer>(
        &self,
        target: IndividualAddress,
        force: bool,
        observer: &mut O,
    ) -> Result<Option<Occupant>, Stop> {
        observer.step(Step::CheckFree { target });
        let occupant = probe_occupant(self.service, self.source, target).await;
        observer.done(Step::CheckFree { target }, occupant.is_none());
        match occupant {
            Some(occupant) if !force => Err(Stop::Occupied { target, occupant }),
            other => Ok(other),
        }
    }

    /// Asks, writes the address (unless the device keeps it), reads the
    /// device back independently at `target` and re-checks the
    /// programming-mode broadcast once.
    ///
    /// # Errors
    ///
    /// The human declined, the broadcast or the read-back failed, or a
    /// check the request asks for did not hold.
    pub async fn assign<O: Observer>(
        &self,
        req: &Assign<'_>,
        observer: &mut O,
    ) -> Result<Assigned, Stop> {
        let (current, target) = (req.current, req.target);
        if let Some(question) = req.question {
            ask(observer, question)?;
        }
        let written = target != current;
        if written {
            observer.step(Step::WriteAddress { target });
            write_address(self.service, self.source, target)
                .await
                .map_err(Stop::Write)?;
            observer.done(Step::WriteAddress { target }, true);
        }
        observer.step(Step::ReadAddress { target });
        let verified = verify_assignment_with(
            self.service,
            self.source,
            target,
            req.clear_programming_mode,
            req.key,
        )
        .await?;
        if req.refuse_hidden && verified.secure == SecureStatus::ActivatedNoKey {
            return Err(Stop::Hidden(Box::new(verified)));
        }
        let matches_identified = req
            .identified
            .is_none_or(|before| same_device(before, &verified));
        if req.require_identified && !matches_identified {
            return Err(Stop::OtherDevice {
                target,
                verified: Box::new(verified),
            });
        }
        if let Some(dir) = req.forget_facts {
            forget_facts(dir, target);
        }
        let still_in_programming_mode =
            written && still_in_programming_mode(self.service, self.source, target).await;
        let assigned = Assigned {
            current,
            target,
            verified,
            written,
            still_in_programming_mode,
            matches_identified,
        };
        observer.step(Step::Assigned(&assigned));
        Ok(assigned)
    }
}

/// Drops the device facts stored for `address`: a new box now answers there,
/// and facts stored for it describe whatever was there before (issues #209,
/// #228 item 5). Best-effort.
pub fn forget_facts(dir: &std::path::Path, address: IndividualAddress) {
    let _ = std::fs::remove_file(bussard_model::facts::facts_path(dir, address));
}

/// Whether a read-back names the identified device: the serial and the mask
/// match where both were read.
pub fn same_device(before: &Verified, after: &Verified) -> bool {
    let serial = match (&after.serial, &before.serial) {
        (Some(now), Some(then)) => now == then,
        _ => true,
    };
    let mask = match (after.mask, before.mask) {
        (Some(now), Some(then)) => now == then,
        _ => true,
    };
    serial && mask
}

/// `read` completed by `before` where it left a field empty.
pub fn completed(read: &Verified, before: &Verified) -> Verified {
    Verified {
        mask: read.mask.or(before.mask),
        manufacturer_id: read.manufacturer_id.or(before.manufacturer_id),
        serial: read.serial.clone().or_else(|| before.serial.clone()),
        order: read.order.clone().or_else(|| before.order.clone()),
        ..read.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_device_compares_only_what_both_read() {
        let before = Verified {
            mask: Some(0x07B0),
            serial: Some(vec![1, 2, 3, 4, 5, 6]),
            ..Verified::default()
        };
        assert!(same_device(&before, &before.clone()));
        assert!(same_device(&before, &Verified::default()));
        let other = Verified {
            serial: Some(vec![9; 6]),
            ..before.clone()
        };
        assert!(!same_device(&before, &other));
    }

    #[test]
    fn test_completed_fills_the_gaps_of_the_read_back() {
        let before = Verified {
            order: Some("A".into()),
            manufacturer_id: Some(0x83),
            ..Verified::default()
        };
        let read = Verified {
            mask: Some(0x07B0),
            ..Verified::default()
        };
        let merged = completed(&read, &before);
        assert_eq!(merged.mask, Some(0x07B0));
        assert_eq!(merged.order.as_deref(), Some("A"));
        assert_eq!(merged.manufacturer_id, Some(0x83));
    }
}
