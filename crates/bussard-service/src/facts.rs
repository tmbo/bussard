//! Device facts on the bus (issue #209): check the cached facts of a device
//! against a cheap identity read, reuse them on a match, read them again on a
//! mismatch, and seed the management connection with them.
//!
//! The stored form is [`bussard_model::facts`]; this module decides when they
//! are valid and what reading them costs:
//!
//! - **Cached and valid** (the device's mask equals the stored one and the
//!   application object's `PID_PROGRAM_VERSION` equals the stored application
//!   id): one property read, on top of the descriptor read every command does
//!   anyway. The connection is seeded ([`Layer4Connection::seed`]), so the
//!   object walk of the table reader, the freshness probe and the incremental
//!   apply is skipped, and `PID_MAX_APDU_LENGTH` is not re-read.
//! - **Missing, changed, or `--refresh-facts`**: the facts are read as before
//!   (max APDU, object table, application id; property descriptions when
//!   asked), written to the facts file and seeded. The object table comes from
//!   `PID_IO_LIST` when a System B device offers it and it agrees with
//!   `PID_OBJECT_TYPE`, from the walk otherwise
//!   ([`bussard_mgmt::discover_object_table`]).
//!
//! A facts file that cannot be read or written only costs the fast path: the
//! command runs as it did before facts existed and says why at debug level.

use std::path::{Path, PathBuf};

use bussard_mgmt::tables::OT_APPLICATION_PROGRAM;
use bussard_mgmt::{
    AuthorizeOutcome, ConnectionSeed, L4Channel, Layer4Connection, MaskFamily, MaskProfile,
    MgmtError, ObjectTableSource, PropertyDesc,
};
use bussard_model::IndividualAddress;
use bussard_model::facts::{self, AuthorizeVerdict, DeviceFactsRecord, ObjectFacts, PropertyFacts};

use crate::identity::HIDDEN_MASK;

/// Which facts a command needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsWant {
    /// Mask, max APDU, object table, application id, authorize verdict.
    Table,
    /// [`Table`](Self::Table) plus every object's property descriptions.
    /// `force` walks them even when the cached facts carry them (`describe
    /// --full`).
    Properties {
        /// Walk the descriptions even when cached.
        force: bool,
    },
}

/// Where the facts in effect came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactsSource {
    /// The cached facts matched the device.
    Cached,
    /// The facts were read from the device in this session.
    Read,
    /// No usable facts: the device answered no interface object (a refused or
    /// objectless device) or reported the hidden mask of a Data Secure device
    /// read in the clear. Nothing was seeded or stored.
    Unavailable,
}

/// The result of [`FactsCache::establish`].
#[derive(Debug, Clone)]
pub struct Established {
    /// Where the facts came from.
    pub source: FactsSource,
    /// The facts in effect. `None` only for [`FactsSource::Unavailable`].
    pub record: Option<DeviceFactsRecord>,
    /// Why cached facts were not used, when there were some.
    pub invalidated: Option<String>,
}

impl Established {
    /// The object table in effect (empty when unavailable).
    pub fn object_table(&self) -> Vec<(u8, u16)> {
        self.record
            .as_ref()
            .map(DeviceFactsRecord::object_table)
            .unwrap_or_default()
    }
}

/// The facts store of one command: the model directory it reads and writes
/// facts under, and whether `--refresh-facts` was given.
#[derive(Debug, Clone, Default)]
pub struct FactsCache {
    /// The model directory, or `None` when facts are off (no model loaded).
    dir: Option<PathBuf>,
    /// Ignore cached facts and read them again.
    refresh: bool,
    /// A key to present when the session skipped authorize on the strength of a
    /// cached "unsupported" verdict and the facts then turned out stale.
    deferred_authorize: Option<u32>,
}

impl FactsCache {
    /// A store under the model directory `dir`; `refresh` is `--refresh-facts`.
    pub fn new(dir: &Path, refresh: bool) -> Self {
        FactsCache {
            dir: Some(dir.to_path_buf()),
            refresh,
            deferred_authorize: None,
        }
    }

    /// No store: facts are read each time and never written.
    pub fn disabled() -> Self {
        FactsCache::default()
    }

    /// Whether `--refresh-facts` was given.
    pub fn refresh(&self) -> bool {
        self.refresh
    }

    /// The cached facts of `target`, ignoring `--refresh-facts`. `None` when
    /// facts are off, missing, or the file is unreadable (logged).
    pub fn load(&self, target: IndividualAddress) -> Option<DeviceFactsRecord> {
        let dir = self.dir.as_deref()?;
        match facts::load_facts(dir, target) {
            Ok(record) => record,
            Err(err) => {
                tracing::warn!("ignoring the device facts of {target}: {err}");
                None
            }
        }
    }

    /// Whether a read-only session may skip `A_Authorize_Request`: the cached
    /// facts say the device does not answer it, and `--refresh-facts` was not
    /// given. Saves the full response timeout such a device costs per session
    /// (3 s, the speed deep dive of 2026-09-24, section 1.3). Write sessions
    /// never skip it.
    ///
    /// When this returns true, call [`defer_authorize`](Self::defer_authorize)
    /// so a stale verdict is corrected on the same connection.
    pub fn may_skip_authorize(&self, target: IndividualAddress) -> bool {
        !self.refresh
            && self
                .load(target)
                .is_some_and(|r| r.authorize == Some(AuthorizeVerdict::Unsupported))
    }

    /// Presents `key` (best-effort) when the session skipped authorize and the
    /// cached facts turn out stale.
    pub fn defer_authorize(&mut self, key: u32) {
        self.deferred_authorize = Some(key);
    }

    /// Checks the cached facts of the connection's device against `mask` (the
    /// descriptor the caller just read on this connection) and the application
    /// id, reads them again when they are missing, stale or `--refresh-facts`
    /// was given, stores what was read, and seeds the connection.
    ///
    /// # Errors
    ///
    /// A connection death from one of the reads the facts need (max APDU, the
    /// object walk, the property descriptions), the same error those reads
    /// raised before facts existed. Device-level refusals are folded into the
    /// fallbacks.
    pub async fn establish<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        mask: u16,
        want: FactsWant,
    ) -> Result<Established, MgmtError> {
        let target = l4.target();
        let mut invalidated = None;
        let cached = if self.refresh {
            None
        } else {
            self.load(target)
        };
        if let Some(record) = cached {
            match stale_reason(l4, &record, mask).await {
                None => return self.reuse(l4, record, mask, want).await,
                Some(reason) => {
                    tracing::info!(
                        "device facts of {target} are stale ({reason}); reading them again"
                    );
                    invalidated = Some(reason);
                }
            }
            if let Some(key) = self.deferred_authorize
                && l4.last_authorize().is_none()
                && let Err(err) = l4.authorize_or_fail(key).await
            {
                tracing::debug!("{target} authorize did not grant: {err}");
            }
        }
        let mut established = self.read(l4, mask, want).await?;
        established.invalidated = invalidated;
        Ok(established)
    }

    /// Seeds the connection from valid cached facts, walks the property
    /// descriptions when asked and missing, and records a changed authorize
    /// verdict.
    async fn reuse<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        mut record: DeviceFactsRecord,
        mask: u16,
        want: FactsWant,
    ) -> Result<Established, MgmtError> {
        seed(l4, &record, mask);
        let mut dirty = false;
        if let Some(verdict) = l4.last_authorize().map(verdict_of)
            && record.authorize != Some(verdict)
        {
            record.authorize = Some(verdict);
            dirty = true;
        }
        if let FactsWant::Properties { force } = want
            && (force || !record.has_properties())
        {
            walk_properties(l4, &mut record.objects).await?;
            record.read_at = facts::now_stamp();
            dirty = true;
        }
        if dirty {
            self.save(&record);
        }
        Ok(Established {
            source: FactsSource::Cached,
            record: Some(record),
            invalidated: None,
        })
    }

    /// Reads the facts from the device, stores and seeds them.
    async fn read<Ch: L4Channel>(
        &self,
        l4: &mut Layer4Connection<Ch>,
        mask: u16,
        want: FactsWant,
    ) -> Result<Established, MgmtError> {
        let target = l4.target();
        let max_apdu = l4.negotiate_max_apdu().await?;
        // PID_IO_LIST only on System B, the family whose devices serve the
        // property services; elsewhere the walk runs exactly as before.
        let (table, source) =
            if matches!(MaskProfile::from_mask(mask).family(), MaskFamily::SystemB) {
                bussard_mgmt::discover_object_table(l4).await?
            } else {
                (
                    bussard_mgmt::probe_object_types(l4).await?,
                    ObjectTableSource::Walk,
                )
            };
        if table.is_empty() || mask == HIDDEN_MASK {
            return Ok(Established {
                source: FactsSource::Unavailable,
                record: None,
                invalidated: None,
            });
        }
        let application_object = table
            .iter()
            .find(|(_, ot)| *ot == OT_APPLICATION_PROGRAM)
            .map(|(index, _)| *index);
        let application_id = match application_object {
            Some(index) => application_id(l4, index).await,
            None => None,
        };
        let mut objects: Vec<ObjectFacts> = table
            .iter()
            .map(|&(index, object_type)| ObjectFacts {
                index,
                object_type,
                properties: None,
            })
            .collect();
        if matches!(want, FactsWant::Properties { .. }) {
            walk_properties(l4, &mut objects).await?;
        }
        let record = DeviceFactsRecord {
            address: target,
            read_at: facts::now_stamp(),
            mask: facts::format_mask(mask),
            application_object,
            application_id,
            max_apdu,
            authorize: l4.last_authorize().map(verdict_of),
            object_table_source: match source {
                ObjectTableSource::IoList => facts::ObjectTableSource::IoList,
                ObjectTableSource::Walk => facts::ObjectTableSource::Walk,
            },
            objects,
        };
        seed(l4, &record, mask);
        self.save(&record);
        Ok(Established {
            source: FactsSource::Read,
            record: Some(record),
            invalidated: None,
        })
    }

    /// Writes `record`, logging a failure (the facts are a cache).
    fn save(&self, record: &DeviceFactsRecord) {
        let Some(dir) = self.dir.as_deref() else {
            return;
        };
        match facts::save_facts(dir, record) {
            Ok(path) => tracing::debug!("device facts written to {}", path.display()),
            Err(err) => tracing::warn!("could not write the device facts: {err}"),
        }
    }
}

/// Why `record` does not describe the device behind `l4`, or `None` when it
/// does: the mask differs, or the application id read now differs from the
/// stored one.
async fn stale_reason<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    record: &DeviceFactsRecord,
    mask: u16,
) -> Option<String> {
    if record.mask_value() != Some(mask) {
        return Some(format!(
            "mask {} now reads {}",
            record.mask,
            facts::format_mask(mask)
        ));
    }
    if record.objects.is_empty() {
        return Some("no interface objects recorded".to_string());
    }
    let index = record.application_object?;
    let now = application_id(l4, index).await;
    (now != record.application_id).then(|| {
        format!(
            "application id {} now reads {}",
            record.application_id.as_deref().unwrap_or("none"),
            now.as_deref().unwrap_or("none")
        )
    })
}

/// Reads the application id (`PID_PROGRAM_VERSION`) of object `index` as hex,
/// `None` when the object reports none or the read fails.
async fn application_id<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>, index: u8) -> Option<String> {
    match bussard_mgmt::read_program_version(l4, index).await {
        Ok(Some(bytes)) => Some(facts::format_application_id(&bytes)),
        Ok(None) => None,
        Err(err) => {
            tracing::debug!(
                "{} PID_PROGRAM_VERSION of object {index}: {err}",
                l4.target()
            );
            None
        }
    }
}

/// Walks the property descriptions of every object in `objects`.
async fn walk_properties<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    objects: &mut [ObjectFacts],
) -> Result<(), MgmtError> {
    for object in objects {
        let descs = bussard_mgmt::describe_object_properties(l4, object.index).await?;
        object.properties = Some(descs.iter().map(property_facts).collect());
    }
    Ok(())
}

/// Seeds `l4` with `record`.
fn seed<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>, record: &DeviceFactsRecord, mask: u16) {
    l4.seed(ConnectionSeed {
        mask: Some(mask),
        object_table: record.object_table(),
        max_apdu: record.max_apdu,
        authorize_unanswered: record.authorize == Some(AuthorizeVerdict::Unsupported),
    });
}

/// The stored form of an authorize outcome.
fn verdict_of(outcome: &AuthorizeOutcome) -> AuthorizeVerdict {
    match outcome {
        AuthorizeOutcome::Granted { .. } => AuthorizeVerdict::Granted,
        AuthorizeOutcome::Denied { .. } => AuthorizeVerdict::Denied,
        AuthorizeOutcome::Unsupported { .. } => AuthorizeVerdict::Unsupported,
    }
}

/// The stored form of a property description.
pub fn property_facts(desc: &PropertyDesc) -> PropertyFacts {
    PropertyFacts {
        index: desc.property_index,
        pid: desc.property_id,
        pdt: desc.pdt,
        writable: desc.writable,
        max_elements: desc.max_elements,
        read_level: desc.read_level,
        write_level: desc.write_level,
    }
}

/// A property description from its stored form, on object `object_index`.
pub fn property_desc(object_index: u8, facts: &PropertyFacts) -> PropertyDesc {
    PropertyDesc {
        object_index,
        property_id: facts.pid,
        property_index: facts.index,
        pdt: facts.pdt,
        writable: facts.writable,
        max_elements: facts.max_elements,
        read_level: facts.read_level,
        write_level: facts.write_level,
    }
}
