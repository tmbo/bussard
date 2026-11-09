//! The step loop the three executors share (issue #897): System B
//! ([`super::flash`]), System 7 and property-only plans run their steps
//! through [`run_steps`], which owns the progress report, the proactive L4
//! cycle, and the resume-on-drop policy. What a step does stays with each
//! family's [`StepExecutor`]; the steps every family runs the same way are
//! [`run_shared_step`].

use super::session::{Connector, MAX_RESUME_RECONNECTS, Session, resumable_death};
use super::{FlashPlan, FlashStep, Progress};
use bussard_mgmt::load::WriteError;

/// How a step relates to a device reboot, as the step loop sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reboot {
    /// The step does not reboot the device.
    No,
    /// The step reboots the device and reconnects, so no proactive cycle runs
    /// before it, but a connection death in it is replayed like any other
    /// (the System 7 pre-download restart: its unloads are idempotent).
    Replayed,
    /// The step reboots the device and reconnects itself: its silence is
    /// expected, so it is repeated only when the gateway link was lost while
    /// it ran (issue #192).
    SelfReconnecting,
}

/// One family's step semantics, driven by [`run_steps`].
pub(super) trait StepExecutor {
    /// How `step` relates to a device reboot.
    fn reboot(&self, step: &FlashStep) -> Reboot;

    /// The progress label of a step this executor skips without running it,
    /// or `None` to run it.
    fn skip(&mut self, _step: &FlashStep) -> Option<String> {
        None
    }

    /// Whether the terminal restart already ran and verified the download, so
    /// a later step cut short by a link loss is not repeated.
    fn restart_verified(&self) -> bool {
        false
    }

    /// Runs `step` (number `index`, from 0) once.
    async fn run<C: Connector, F: FnMut(Progress)>(
        &mut self,
        session: &mut Session<C>,
        progress: &mut F,
        index: usize,
        step: &FlashStep,
    ) -> Result<(), WriteError>;

    /// Decides a failure the step loop does not recover: `Ok` turns it into
    /// a finding of the executor, `Err` fails the flash.
    fn recover(
        &mut self,
        _index: usize,
        _step: &FlashStep,
        err: WriteError,
    ) -> Result<(), WriteError> {
        Err(err)
    }
}

/// Runs every step of `plan` through `exec`.
///
/// Before a step that does not reboot the device, a connection that reached
/// `reconnect_threshold` numbered exchanges (0 = never, the default for every
/// device but KNX Virtual, issue #116) is cycled. The objects' load states and
/// allocated segments are device state, so they survive the cycle; the check
/// runs between steps, never mid memory write.
///
/// Resume-on-drop: a step that dies from an unexpected connection death is run
/// again on a fresh connection, at most [`MAX_RESUME_RECONNECTS`] times per
/// step. Load state and segments survive the drop and every write is
/// addressed, so replaying the step is safe. A step that reboots and
/// reconnects itself is repeated only after a gateway link loss (issue #192):
/// the restart may never have reached the device, so it is sent again once the
/// device answers.
pub(super) async fn run_steps<C: Connector, F: FnMut(Progress), E: StepExecutor>(
    session: &mut Session<C>,
    plan: &FlashPlan,
    reconnect_threshold: u32,
    progress: &mut F,
    exec: &mut E,
) -> Result<(), WriteError> {
    let total = plan.steps.len();
    for (i, step) in plan.steps.iter().enumerate() {
        if let Some(label) = exec.skip(step) {
            progress(Progress::Step {
                index: i + 1,
                total,
                label,
            });
            continue;
        }
        let reboot = exec.reboot(step);
        if reconnect_threshold > 0
            && session.can_reconnect()
            && reboot == Reboot::No
            && session.numbered_exchanges() >= reconnect_threshold
        {
            session.cycle_l4().await?;
        }
        progress(Progress::Step {
            index: i + 1,
            total,
            label: plan.step_label(step),
        });
        let mut resume_reconnects = 0u32;
        loop {
            let losses_before_attempt = session.link_losses();
            let Err(e) = exec.run(session, progress, i, step).await else {
                break;
            };
            if resumable_death(&e, session) && resume_reconnects < MAX_RESUME_RECONNECTS {
                if reboot != Reboot::SelfReconnecting {
                    // The old connection is dead: re-open a fresh one and
                    // re-authorize (no graceful T_Disconnect the dead peer
                    // would not answer), then replay the step.
                    resume_reconnects += 1;
                    session.reconnect().await?;
                    continue;
                }
                if !exec.restart_verified() && session.link_losses() != losses_before_attempt {
                    resume_reconnects += 1;
                    tracing::warn!(
                        "step {} ({}) was cut short by a gateway link loss ({e}); \
                         reconnecting and repeating it",
                        i + 1,
                        plan.step_label(step)
                    );
                    session.reconnect_after_reboot().await?;
                    continue;
                }
            }
            exec.recover(i, step, e)?;
            break;
        }
    }
    Ok(())
}

/// Runs a step every family executes the same way: a property description
/// read, compare or write, the KNXnet/IP parameters, a delay. `None` for any
/// other step.
///
/// The System B executor keeps its own front end for property writes (the
/// skipped template objects, the per-entry MCB writes) and hands the rest
/// here.
pub(super) async fn run_shared_step<C: Connector>(
    session: &mut Session<C>,
    step: &FlashStep,
) -> Option<Result<(), WriteError>> {
    let result = match step {
        // ETS's description read for a property write it has no value for
        // (issue #841); the answer changes nothing.
        FlashStep::DescribeProp { object, prop_id } => {
            super::props::describe_property(session.l4(), *object, *prop_id).await
        }
        // Read the named interface object's property and compare it with the
        // vendor's expected data. The op names the object by its own index
        // (0 = the device object), not the discovered application object. A
        // `Range`-only op has no literal expectation and is skipped.
        FlashStep::CompareProp {
            object,
            prop_id,
            expected,
            mask,
            start_element,
        } => match expected {
            Some(expected) => {
                super::props::compare_property_value(
                    session.l4(),
                    *object,
                    *prop_id,
                    *start_element,
                    expected,
                    mask.as_deref(),
                )
                .await
            }
            None => Ok(()),
        },
        // A procedure's own load-state transition (issue #947): the device
        // answers it with the resulting load state, not an echo of the
        // value, so it is confirmed as a load control.
        FlashStep::WriteProp {
            object: super::PropObject::Index(index),
            ..
        } if step.load_state_control().is_some() => {
            match (step.load_state_control(), u8::try_from(*index)) {
                (Some((_, control)), Ok(obj)) => {
                    bussard_mgmt::load::write_load_control(session.l4(), obj, control)
                        .await
                        .map(|_| ())
                }
                _ => Err(WriteError::Mgmt(
                    bussard_mgmt::MgmtError::MalformedResponse {
                        address: session.l4().target(),
                        reason: format!("object index {index} exceeds the 8-bit index space"),
                    },
                )),
            }
        }
        // A property write of the procedure (issue #390), with its Count and
        // Verify.
        FlashStep::WriteProp {
            object,
            prop_id,
            value,
            start_element,
            count,
            verify,
            ..
        } => {
            super::props::write_property_value(
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
        // The KNXnet/IP parameters of an IP-enabled device (issue #455).
        FlashStep::KnxnetIpParameters { program } => {
            super::knxnet_ip::write_knxnet_ip(session.l4(), program).await
        }
        FlashStep::Delay { milliseconds } => {
            super::execute::delay_step(*milliseconds).await;
            Ok(())
        }
        // A function property call (issue #946): the state response must
        // carry return code 00h.
        FlashStep::InvokeFunctionProp {
            object,
            prop_id,
            data,
        } => {
            super::function_prop::invoke_function_property(session.l4(), *object, *prop_id, data)
                .await
        }
        // A write whose value the device holds after the parameter reset
        // (issue #951): the description read ETS makes for an undeclared
        // property, then the property is read, and written as before when
        // it does not hold the value or does not answer (the fallback to the
        // previous behaviour, CLAUDE.md "Speed Changes"): a device whose
        // parameter reset leaves something else there ends with the model's
        // value all the same.
        FlashStep::FactoryHeldProp {
            object,
            prop_id,
            value,
            start_element,
            count,
            verify,
            describe,
            ..
        } => {
            async {
                if *describe {
                    super::props::describe_property(session.l4(), *object, *prop_id).await?;
                }
                let elem = (value.len() / usize::from((*count).max(1))).max(1);
                let read = super::props::read_property_value(
                    session.l4(),
                    *object,
                    *prop_id,
                    *start_element,
                    *count,
                    elem,
                )
                .await;
                match read {
                    Ok(held) if held == *value => {
                        tracing::debug!(
                            %object,
                            prop_id,
                            "LdCtrlWriteProp: the device holds the value after the parameter \
                             reset, nothing written"
                        );
                        Ok(())
                    }
                    other => {
                        tracing::warn!(
                            %object,
                            prop_id,
                            start_element,
                            read = ?other.as_ref().map(|v| v.len()),
                            "the device does not hold the LoadedImage value after the parameter \
                             reset; writing the property"
                        );
                        super::props::write_property_value(
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
                }
            }
            .await
        }
        // A property declaration (issue #938): the planner sized the write
        // that follows from it; ETS sends nothing for it, and neither does
        // bussard.
        FlashStep::DeclareProp {
            object,
            prop_id,
            prop_type,
            max_elements,
        } => {
            tracing::debug!(
                %object,
                prop_id,
                prop_type = prop_type.as_str(),
                max_elements,
                "LdCtrlDeclarePropDesc: declared, nothing sent"
            );
            Ok(())
        }
        _ => return None,
    };
    Some(result)
}

/// Sends the bare A_Restart and ignores the outcome: the device drops the
/// connection while it reboots, so no answer is expected.
pub(super) async fn send_restart<C: Connector>(session: &mut Session<C>) {
    let (apci, payload) = bussard_mgmt::apci::encode_restart(0);
    let _ = session.l4().send_data_unacked(apci, &payload).await;
}
