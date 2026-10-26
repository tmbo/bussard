//! The property-only executor (issue #390): runs a plan that only compares
//! and writes interface-object properties (the Jung IPS 300 SREG, mask 0021),
//! then reads every written property back.
//!
//! Such a device loads nothing: there is no load-state machine to drive, no
//! application object to discover and no memory to stream. The compares run
//! first in procedure order and stop the flash on a mismatch before anything
//! is written; each write is confirmed (an echo or a return code) and, with
//! `Verify="true"`, read back at once; after the last write every written
//! property is read back again and compared, so "verified" means the device
//! holds the values, never that the sequence completed.

use super::props::{compare_property_value, read_property_value, write_property_value};
use super::session::{Connector, MAX_RESUME_RECONNECTS, Session, resumable_death};
use super::{FlashOutcome, FlashPlan, FlashStep, Progress};
use bussard_mgmt::load::{LoadState, WriteError};

/// Runs a property-only `plan` (see [`FlashPlan::is_property_only`]).
///
/// # Errors
///
/// A failed compare or verify, a refused write, or a transport failure the
/// session cannot reconnect from.
pub(super) async fn flash_properties<C: Connector, F: FnMut(Progress)>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    mut progress: F,
) -> Result<FlashOutcome, WriteError> {
    let total = plan.steps.len();
    let mut restart = false;
    for (i, step) in plan.steps.iter().enumerate() {
        progress(Progress::Step {
            index: i + 1,
            total,
            label: plan.step_label(step),
        });
        let mut reconnects = 0;
        loop {
            let result = match step {
                FlashStep::CompareProp {
                    object,
                    prop_id,
                    expected: Some(expected),
                    mask,
                } => {
                    compare_property_value(
                        session.l4(),
                        *object,
                        *prop_id,
                        expected,
                        mask.as_deref(),
                    )
                    .await
                }
                FlashStep::WriteProp {
                    object,
                    prop_id,
                    value,
                    start_element,
                    count,
                    verify,
                } => {
                    write_property_value(
                        session.l4(),
                        *object,
                        *prop_id,
                        *start_element,
                        *count,
                        value,
                        *verify,
                    )
                    .await
                }
                FlashStep::Restart => {
                    // Sent after the read-back below: the device is unreachable
                    // while it reboots.
                    restart = true;
                    Ok(())
                }
                // A `Range`-only compare carries no literal expectation.
                _ => Ok(()),
            };
            match result {
                Ok(()) => break,
                // A dropped connection: the steps are idempotent, so reconnect
                // and run the step again (bounded).
                Err(e) if resumable_death(&e, session) && reconnects < MAX_RESUME_RECONNECTS => {
                    reconnects += 1;
                    session.reconnect().await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // The read-back: every property the plan wrote, read and compared.
    let mut warnings = Vec::new();
    let mut all_match = true;
    for step in &plan.steps {
        let FlashStep::WriteProp {
            object,
            prop_id,
            value,
            start_element,
            count,
            ..
        } = step
        else {
            continue;
        };
        let elem = (value.len() / usize::from((*count).max(1))).max(1);
        let held = read_property_value(
            session.l4(),
            *object,
            *prop_id,
            *start_element,
            (*count).max(1),
            elem,
        )
        .await;
        match held {
            Ok(held) if &held == value => {}
            Ok(held) => {
                all_match = false;
                warnings.push(format!(
                    "{object} PID {prop_id} reads back {held:02X?}, the plan wrote {value:02X?}"
                ));
            }
            Err(e) => {
                all_match = false;
                warnings.push(format!(
                    "{object} PID {prop_id} could not be read back: {e}"
                ));
            }
        }
    }

    if restart {
        let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
        let _ = session.l4().send_data_unacked(apci, &payload).await;
    }

    Ok(FlashOutcome {
        load_state: LoadState::Loaded,
        object_states: Vec::new(),
        spot_checks_match: all_match,
        warnings,
        reboot_readiness: Vec::new(),
        property_only: true,
    })
}
