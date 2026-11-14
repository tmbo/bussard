//! The read-only half of every programming flow: what `bussard plan`,
//! `bussard apply`, `bussard restore`, `knx_plan_device` and
//! `knx_apply_device` read from one device on one management session, in
//! one order (issue #901): the device facts and the identity verdict, the
//! live link tables, the parameter memory, the security individual address
//! table (PID 54) and the group-object security flags (PID 61).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bussard_download::program::LiveReadError;
use bussard_download::{LiveRead, LiveTables, SecureSenderEntry};
use bussard_mgmt::{L4Channel, Layer4Connection, MgmtError};
use bussard_model::{GroupAddress, IndividualAddress, Model};
use bussard_secure::Key16;

use crate::facts::{FactsCache, Identified};
use crate::params::{ParamState, ProductSource};
use crate::property_plan::PropertyRow;
use crate::{BusService, L4Options, ServiceError};

/// What the PID 61 read does with the flags cached in the device facts
/// (issue #336).
pub enum FlagsCache<'a> {
    /// Neither read nor written.
    Off,
    /// A plan: flags a previous plan read stand in for the read when they
    /// show no pending change, and a live read is remembered.
    Plan {
        /// The model directory.
        dir: &'a std::path::Path,
        /// `--refresh-facts`: always read.
        refresh: bool,
        /// The tables the plan writes.
        desired: &'a bussard_download::DesiredTables,
        /// The group keys of the key store.
        group_keys: Option<&'a HashMap<GroupAddress, Key16>>,
    },
    /// A write: the flags may change, so the next plan reads them again.
    Forget {
        /// The model directory.
        dir: &'a std::path::Path,
    },
}

/// What one read of a device covers.
pub struct ReadRequest<'a> {
    /// The device.
    pub target: IndividualAddress,
    /// The model, for the identity verdict and the parameter decoding.
    pub model: Option<&'a Model>,
    /// The product data the parameter memory is decoded with; `None` reads
    /// no parameters (and places System 7 tables at the corpus defaults).
    pub product: Option<&'a ProductSource>,
    /// The stored device facts.
    pub facts: &'a FactsCache,
    /// The tunnelling addresses `admit_tunnel_senders` admits: PID 54 is
    /// read only when there are any (issue #297).
    pub tunnel: &'a [IndividualAddress],
    /// Whether the session is secured: only then is PID 61 read (issue #331).
    pub secured: bool,
    /// The PID 61 cache.
    pub flags_cache: FlagsCache<'a>,
    /// A property-only load procedure (issue #390): read its properties
    /// when no table reader speaks the device's mask.
    pub properties: Option<&'a bussard_download::FlashPlan>,
    /// Read the fixed property writes of the parameter-only download even
    /// when it writes nothing (a restore puts them back; issue #1085,
    /// [`crate::params::read_state`]).
    pub fixed_properties: bool,
}

/// What one read of a device returned. `L` is the live read: a
/// [`LiveRead`] as read, or the [`LiveTables`] of a supported device
/// ([`DeviceRead::into_tables`]).
pub struct DeviceRead<L = LiveRead> {
    /// The live link tables, or the unsupported-mask refusal.
    pub live: L,
    /// The device facts in effect and the identity verdict.
    pub identified: Identified,
    /// The parameter read-back, when product data was given and the tables
    /// read.
    pub params: Option<ParamState>,
    /// How long the parameter read took (bus reads, plan and decode).
    pub parameter_time: Option<Duration>,
    /// PID 54, when read (and answered).
    pub senders: Option<Vec<SecureSenderEntry>>,
    /// PID 61, when read (and answered), or the cached flags.
    pub flags: Option<Vec<u8>>,
    /// The group key table's entry count (PID 53), read on a secured System
    /// B session of a device whose group key table the lock records (issue
    /// #1094), the cross-check of that record; `Err` when the read failed,
    /// `None` when not read.
    pub group_keys: Option<Result<u16, String>>,
    /// Whether [`DeviceRead::flags`] came from the cache.
    pub flags_cached: bool,
    /// The properties of a property-only load procedure, when read.
    pub property_rows: Option<Vec<PropertyRow>>,
}

impl DeviceRead {
    /// The read of a device whose tables were read; `Err` carries the device
    /// and the mask no table reader speaks.
    ///
    /// # Errors
    ///
    /// The device reported a mask outside the System B and System 7
    /// families.
    pub fn into_tables(self) -> Result<DeviceRead<LiveTables>, (IndividualAddress, u16)> {
        let DeviceRead {
            live,
            identified,
            params,
            parameter_time,
            senders,
            flags,
            flags_cached,
            group_keys,
            property_rows,
        } = self;
        match live {
            LiveRead::Tables(live) => Ok(DeviceRead {
                live,
                identified,
                params,
                parameter_time,
                senders,
                flags,
                flags_cached,
                group_keys,
                property_rows,
            }),
            LiveRead::UnsupportedMask { address, mask } => Err((address, mask)),
        }
    }
}

impl<L> DeviceRead<L> {
    /// The identity verdict against the lock, when the descriptor answered.
    pub fn check(&self) -> Option<&bussard_model::identity::IdentityCheck> {
        self.identified.check.as_ref()
    }

    /// The device facts this read checked, as the seed of the write and
    /// read-back connections (issues #209, #761).
    pub fn seed(&self) -> Option<bussard_mgmt::ConnectionSeed> {
        crate::facts::seed_of(self.identified.established.as_ref())
    }
}

/// Why a device read failed.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The session could not be opened (source check, lease, connect,
    /// authorize).
    #[error(transparent)]
    Open(#[from] ServiceError),
    /// A management read failed.
    #[error(transparent)]
    Mgmt(#[from] MgmtError),
    /// The live table read failed.
    #[error(transparent)]
    Tables(#[from] LiveReadError),
}

/// Where the device's product puts a System 7 device's tables
/// ([`bussard_download::sys7_table_bases`]); the corpus defaults without one.
pub fn table_bases(product: Option<&ProductSource>) -> bussard_download::Sys7TableBases {
    product
        .and_then(ProductSource::app)
        .map(bussard_download::sys7_table_bases)
        .unwrap_or_default()
}

/// Reads `req.target` on an open (and authorized) session, in the one order:
/// facts and identity, live tables, parameter memory, PID 54, PID 61, and the
/// properties of a property-only procedure.
///
/// # Errors
///
/// A management read failed (PID 61 is informational: a refused read leaves
/// the flags unknown).
pub async fn read_on<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    req: &ReadRequest<'_>,
) -> Result<DeviceRead, ReadError> {
    let target = req.target;
    let device = req
        .model
        .and_then(|m| m.devices.get(&target))
        .map(|d| &d.device);
    // A plan's cached PID 61 with no pending change stands in for the read
    // (issue #336); looked up before the session touches the facts.
    let known = match (&req.flags_cache, req.secured) {
        (
            FlagsCache::Plan {
                dir,
                refresh,
                desired,
                group_keys,
            },
            true,
        ) => {
            let empty = HashMap::new();
            let keys = group_keys.unwrap_or(&empty);
            let inputs = bussard_download::security_inputs_for(req.model, target, desired, keys);
            crate::security_change::unchanged_cached_flags(dir, target, desired, &inputs, *refresh)
        }
        _ => None,
    };
    let identified = crate::facts::identify(l4, req.facts, device).await?;
    let live = bussard_download::read_live_tables(l4, table_bases(req.product)).await?;
    let (params, parameter_time) = match (&live, req.product) {
        (LiveRead::Tables(tables), Some(product)) => {
            let started = Instant::now();
            let state = crate::params::read_state(
                l4,
                product,
                req.model,
                target,
                tables.tables().mask,
                req.fixed_properties,
            )
            .await;
            (Some(state), Some(started.elapsed()))
        }
        _ => (None, None),
    };
    let system_b = matches!(&live, LiveRead::Tables(t) if t.sys7().is_none());
    // PID 54, for `admit_tunnel_senders` only (issue #297).
    let senders = if system_b && !req.tunnel.is_empty() {
        bussard_download::read_security_sender_table(l4).await?
    } else {
        None
    };
    let flags_cached = system_b && known.is_some();
    // PID 53's entry count (issue #1094), before PID 61, the session's last
    // read: only for a device whose group key table the lock records, the
    // cross-check of that record (a plan and the write's re-read alike, so
    // the plan digest covers it). A failed read is reported, not guessed.
    let recorded = device
        .and_then(|d| d.security.as_ref())
        .is_some_and(|s| s.group_keys.is_some());
    let group_keys = if system_b && req.secured && recorded {
        Some(
            bussard_mgmt::property_ext::read_property_ext_element_count(
                l4,
                bussard_mgmt::property_ext::PropertyExtAddress::security(
                    bussard_mgmt::property_ext::PID_GRP_KEY_TABLE,
                ),
            )
            .await
            .map_err(|err| err.to_string()),
        )
    } else {
        None
    };
    // PID 61 on a secured session (issue #331), the session's last read.
    let flags = match known.filter(|_| system_b) {
        Some(flags) => Some(flags),
        None if system_b && req.secured => match bussard_download::read_security_flags(l4).await {
            Ok(flags) => flags,
            Err(err) => {
                tracing::debug!("{target}: PID 61 not read: {err}");
                None
            }
        },
        None => None,
    };
    let property_rows = match (&live, req.properties) {
        (LiveRead::UnsupportedMask { .. }, Some(plan)) => {
            Some(crate::property_plan::read_property_rows(l4, plan).await)
        }
        _ => None,
    };
    match (&req.flags_cache, &flags) {
        (FlagsCache::Plan { dir, .. }, Some(flags)) if !flags_cached => {
            crate::security_change::remember_flags(dir, target, flags);
        }
        (FlagsCache::Forget { dir }, _) => crate::security_change::forget_flags(dir, target),
        _ => {}
    }
    Ok(DeviceRead {
        live,
        identified,
        params,
        parameter_time,
        senders,
        flags,
        flags_cached,
        group_keys,
        property_rows,
    })
}

/// Opens a management session to `req.target` with `options` and reads it
/// ([`read_on`]), disconnecting on every path.
///
/// # Errors
///
/// [`ReadError::Open`] when the session could not be opened, else as
/// [`read_on`].
pub async fn read_device(
    service: &BusService,
    options: &L4Options,
    req: &ReadRequest<'_>,
) -> Result<DeviceRead, ReadError> {
    service
        .with_l4(req.target, options, async |l4| read_on(l4, req).await)
        .await
}
