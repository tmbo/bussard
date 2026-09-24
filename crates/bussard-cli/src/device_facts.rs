//! Device facts for the CLI's bus commands (issue #209): which store a command
//! uses, and the table-reading commands' shared step that checks or reads the
//! facts on an open connection.
//!
//! `describe` walks property descriptions through the same store
//! ([`bussard_service::FactsCache`]); `reconstruct`, `plan`, `apply` and the
//! flash pre-flight need only the object table, the max APDU and the
//! application id, which [`establish_table_facts`] provides.

use std::path::Path;

use bussard_mgmt::{ConnectionSeed, L4Channel, Layer4Connection, MaskProfile};
use bussard_model::IndividualAddress;
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
    })
}
