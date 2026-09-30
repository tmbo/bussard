//! Device facts for the CLI's bus commands (issue #209): which store a command
//! uses, and the table-reading commands' shared step that checks or reads the
//! facts on an open connection.
//!
//! `describe` walks property descriptions through the same store
//! ([`bussard_service::FactsCache`]); `reconstruct`, `plan`, `apply` and the
//! flash pre-flight need only the object table, the max APDU and the
//! application id, which [`establish_table_facts`] provides.
//!
//! It is also the one place a management command turns what a device reports
//! into the identity verdict against `bussard.lock` (issue #228, item 5):
//! [`identify`] on an open connection, [`observe`] for a probe that has only
//! the mask (`scan`, `assign`, `audit --live`), and [`identity_line`], the one
//! sentence every command prints.

use std::path::Path;

use bussard_mgmt::{L4Channel, Layer4Connection};
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::schema::Device;
use bussard_service::{Authorize, FactsCache};

/// The facts store of a command run against the model in `dir`: `None` for
/// `model_loaded == false` (no model, so nothing is written next to it).
pub(crate) fn cache(dir: &Path, model_loaded: bool, refresh: bool) -> FactsCache {
    if model_loaded {
        FactsCache::new(dir, refresh)
    } else {
        FactsCache::disabled()
    }
}

/// The authorize step of a **read-only** session to `target`: skipped when the
/// facts say the device never answers `A_Authorize` (the deferred key corrects
/// a stale verdict on the same connection), the best-effort free-access
/// authorize otherwise.
pub(crate) fn read_only_authorize(facts: &mut FactsCache, target: IndividualAddress) -> Authorize {
    let key = bussard_mgmt::apci::FREE_ACCESS_KEY;
    if facts.may_skip_authorize(target) {
        facts.defer_authorize(key);
        Authorize::Skip
    } else {
        Authorize::BestEffort(key)
    }
}

/// The identity verdict for a device a probe read only the mask of (`scan`,
/// `assign`, `audit --live`), with the application id the stored facts carry
/// for it. Stored facts under another mask are stale: they are removed, so
/// the next connection reads them again (the facts refresh of a command that
/// opens no management connection).
pub(crate) fn observe(
    dir: &Path,
    model_loaded: bool,
    target: IndividualAddress,
    mask: u16,
    device: Option<&Device>,
) -> IdentityCheck {
    let mask_text = bussard_model::facts::format_mask(mask);
    let stored = if model_loaded {
        bussard_model::facts::load_facts(dir, target).ok().flatten()
    } else {
        None
    };
    let application_id = match stored {
        Some(record) if record.mask.eq_ignore_ascii_case(&mask_text) => record.application_id,
        Some(_) if mask != bussard_service::identity::HIDDEN_MASK => {
            let _ = std::fs::remove_file(bussard_model::facts::facts_path(dir, target));
            None
        }
        _ => None,
    };
    IdentityCheck::compare(
        device,
        ReportedIdentity {
            mask: mask_text,
            application_id,
        },
    )
}

pub(crate) use bussard_service::{Identified, identity_line, seed_of};

/// Checks (or reads, and stores) the device facts and compares what the
/// device reports with what the lock pins for `device`
/// ([`bussard_service::identify`]).
///
/// # Errors
///
/// A connection death from one of the facts reads.
pub(crate) async fn identify<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
    device: Option<&Device>,
) -> anyhow::Result<Identified> {
    Ok(bussard_service::identify(l4, facts, device).await?)
}

/// Refuses a write to a device whose identity drifted from the lock, naming
/// the `bussard flash` it needs (`apply`, `commission --apply` through it,
/// `replace --no-flash`).
pub(crate) fn refuse_drift(
    target: IndividualAddress,
    check: &IdentityCheck,
    verb: &str,
) -> anyhow::Result<()> {
    match bussard_service::drift_refusal(target, check, verb) {
        Some(refusal) => anyhow::bail!("{refusal}"),
        None => Ok(()),
    }
}
