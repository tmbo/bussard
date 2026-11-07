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

use super::props::read_property_value;
use super::session::{Connector, Session};
use super::steps::{Reboot, StepExecutor, run_shared_step, run_steps, send_restart};
use super::{FlashOutcome, FlashPlan, FlashStep, Progress};
use bussard_mgmt::load::{LoadState, WriteError};

/// The property-only step semantics: the shared property steps, and a
/// restart deferred until after the read-back.
struct PropertyOnly {
    /// Whether the plan ends with a restart.
    restart: bool,
}

impl StepExecutor for PropertyOnly {
    fn reboot(&self, _step: &FlashStep) -> Reboot {
        Reboot::No
    }

    async fn run<C: Connector, F: FnMut(Progress)>(
        &mut self,
        session: &mut Session<C>,
        _progress: &mut F,
        _index: usize,
        step: &FlashStep,
    ) -> Result<(), WriteError> {
        if let FlashStep::Restart = step {
            // Sent after the read-back below: the device is unreachable
            // while it reboots.
            self.restart = true;
            return Ok(());
        }
        run_shared_step(session, step).await.unwrap_or(Ok(()))
    }
}

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
    // The steps are idempotent, so a dropped connection reconnects and runs
    // the step again; nothing cycles the connection proactively.
    let mut exec = PropertyOnly { restart: false };
    run_steps(session, plan, 0, &mut progress, &mut exec).await?;

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
        // A load-state transition is confirmed by the state the device
        // answered, not read back as the value written (issue #947).
        if step.load_state_control().is_some() {
            continue;
        }
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

    if exec.restart {
        send_restart(session).await;
    }

    Ok(FlashOutcome {
        load_state: LoadState::Loaded,
        object_states: Vec::new(),
        spot_checks_match: all_match,
        warnings,
        reboot_readiness: Vec::new(),
        verify_echoes: None,
        property_only: true,
    })
}
