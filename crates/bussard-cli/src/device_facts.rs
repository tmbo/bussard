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

use bussard_mgmt::{ConnectionSeed, L4Channel, Layer4Connection, MaskProfile};
use bussard_model::IndividualAddress;
use bussard_model::identity::{IdentityCheck, ReportedIdentity};
use bussard_model::schema::Device;
use bussard_service::{Authorize, Established, FactsCache, FactsSource, FactsWant};

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

/// Reads the descriptor and, on a System B device (the family whose table
/// reader walks the objects), checks or reads the device facts and seeds the
/// connection, so the table reader and the freshness probe skip their object
/// walks and the second descriptor read.
///
/// `Ok(None)` when nothing was seeded: the descriptor read failed (the reader
/// repeats it and reports the failure as it always did) or the mask is not
/// System B (the reader refuses it, or reads System 7 memory, as before).
///
/// # Errors
///
/// A connection death from one of the facts reads.
pub(crate) async fn establish_table_facts<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
) -> anyhow::Result<Option<Established>> {
    let mask = match bussard_mgmt::read_device_descriptor(l4).await {
        Ok(mask) => mask,
        Err(err) => {
            tracing::debug!("{} descriptor read before the facts: {err}", l4.target());
            return Ok(None);
        }
    };
    if !MaskProfile::from_mask(mask).tables_supported() {
        return Ok(None);
    }
    Ok(Some(facts.establish(l4, mask, FactsWant::Table).await?))
}

/// The seed for a later connection of the same command (the write phase of
/// `apply`), from facts its read phase established.
pub(crate) fn seed_of(established: Option<&Established>) -> Option<ConnectionSeed> {
    let established = established?;
    if established.source == FactsSource::Unavailable {
        return None;
    }
    let record = established.record.as_ref()?;
    Some(ConnectionSeed {
        mask: record.mask_value(),
        object_table: record.object_table(),
        max_apdu: record.max_apdu,
        authorize_unanswered: record.authorize
            == Some(bussard_model::facts::AuthorizeVerdict::Unsupported),
    })
}

/// The one sentence every management command prints for a device's identity
/// against `bussard.lock` (issue #228, item 5): `identity of 1.1.4: matches
/// bussard.lock (application id 0004D14122, mask 07B0)`, `… drift from
/// bussard.lock: …` or `… not pinned in bussard.lock`.
pub(crate) fn identity_line(target: IndividualAddress, check: &IdentityCheck) -> String {
    format!("identity of {target}: {}", check.summary())
}

/// What [`identify`] found on the connection.
pub(crate) struct Identified {
    /// The device facts in effect (System B), for seeding a later connection.
    pub established: Option<Established>,
    /// The identity verdict, when the descriptor answered.
    pub check: Option<IdentityCheck>,
}

/// Checks (or reads, and stores) the device facts through
/// [`establish_table_facts`] and compares what the device reports with what
/// the lock pins for `device`. The one step every management command that
/// opens a connection to a device runs first.
///
/// # Errors
///
/// A connection death from one of the facts reads.
pub(crate) async fn identify<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    facts: &FactsCache,
    device: Option<&Device>,
) -> anyhow::Result<Identified> {
    let established = establish_table_facts(l4, facts).await?;
    let reported = match established.as_ref().and_then(|e| e.record.as_ref()) {
        Some(record) => Some(ReportedIdentity {
            mask: record.mask.clone(),
            application_id: record.application_id.clone(),
        }),
        // Outside System B (or without facts) the mask alone.
        None => bussard_mgmt::read_device_descriptor(l4)
            .await
            .ok()
            .map(|mask| ReportedIdentity {
                mask: bussard_model::facts::format_mask(mask),
                application_id: None,
            }),
    };
    Ok(Identified {
        established,
        check: reported.map(|r| IdentityCheck::compare(device, r)),
    })
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

/// Refuses a write to a device whose identity drifted from the lock, naming
/// the `bussard flash` it needs (`apply`, `commission --apply` through it,
/// `replace --no-flash`).
pub(crate) fn refuse_drift(
    target: IndividualAddress,
    check: &IdentityCheck,
    verb: &str,
) -> anyhow::Result<()> {
    if check.is_drift() {
        anyhow::bail!(
            "refusing to {verb} {target}: {}. The model's parameters and tables are for the \
             application the lock pins; run `bussard flash {target}` to load it, or re-import \
             the project if the lock is stale",
            check.differences.join("; ")
        );
    }
    Ok(())
}
