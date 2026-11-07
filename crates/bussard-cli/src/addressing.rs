//! The terminal side of the addressing flows (issue #902): `assign`,
//! `adopt`, `replace` and `commission` run
//! [`bussard_service::program::assign`] through
//! [`crate::progress::Terminal`], ask [`question`], and word a [`Stop`] with
//! [`stopped`].

use std::process::ExitCode;

use anyhow::anyhow;
use bussard_model::IndividualAddress;
use bussard_service::assign::Occupant;
use bussard_service::program::assign::Stop;
use bussard_service::program::{Declined, Question};

/// The question before an address write: `<verb> <current> → <target> via
/// <gateway>?`.
pub(crate) fn question(
    verb: &str,
    current: IndividualAddress,
    target: IndividualAddress,
    gateway: &str,
) -> Question {
    Question::write(
        format!("{verb} {current} → {target} via {gateway}?"),
        format!("{verb} {current} → {target} via {gateway}"),
    )
}

/// The warning for an occupied address `--force` overrode.
pub(crate) fn warn_forced(target: IndividualAddress, occupant: &Occupant) {
    eprintln!(
        "warning: {target} already answers on the bus ({}); --force given, continuing",
        occupant.describe()
    );
}

/// Words a [`Stop`] of `bussard <verb>`: a refusal or a wait that found no
/// single device is a clean failure; anything else is an error.
///
/// # Errors
///
/// A stop that is an error (the bus, the read-back, a refusal without a
/// terminal).
pub(crate) fn stopped(stop: Stop, verb: &str) -> anyhow::Result<ExitCode> {
    match stop {
        Stop::Several(found) => {
            eprintln!("{} devices are in programming mode:", found.len());
            for address in &found {
                eprintln!("  {address}");
            }
            eprintln!(
                "{verb} works on one device at a time — leave programming mode on all but the one \
                 you want, then re-run."
            );
        }
        Stop::Nothing { waited } => {
            eprintln!();
            eprintln!(
                "no device entered programming mode within {}s.",
                waited.as_secs()
            );
            eprintln!(
                "press the programming button on the new device (its LED usually lights up), \
                 then re-run `bussard {verb}`."
            );
        }
        Stop::Occupied { target, occupant } => eprintln!(
            "{}",
            bussard_service::assign::occupied_refusal(target, &occupant, verb)
        ),
        Stop::Declined(Declined::No) => eprintln!("aborted; no address was written."),
        Stop::Declined(Declined::Refused(refusal)) => return Err(anyhow!(refusal)),
        other => return Err(other.into()),
    }
    Ok(ExitCode::FAILURE)
}
