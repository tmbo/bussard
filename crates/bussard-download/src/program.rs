//! The table-programming flow shared by `bussard plan` / `apply` and the MCP
//! programming tier (issue #118).
//!
//! Every surface that plans or writes a device's link tables runs the same
//! steps: compute the desired tables from the model, read the live tables with
//! the reader for the device's mask family, diff them, render the plan as the
//! sentences the CLI prints, back up the pre-state, and drive the write for the
//! family ([`crate::apply`] for System B, [`crate::apply_sys7`] for System 7).
//! Those pieces live here so the CLI and the MCP server share one
//! implementation; the surfaces keep only their own confirmation and output.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use bussard_mgmt::load::{LoadState, WriteError};
use bussard_mgmt::tables::{DeviceTables, TablesError, read_tables};
use bussard_mgmt::{L4Channel, Layer4Connection, MaskProfile, SecureLayer, system_type};
use bussard_model::{IndividualAddress, Model};

use crate::apply::{VerifyOutcome, discover_table_objects, negotiate_session_apdu};
use crate::apply_sys7::{Sys7ApplyError, Sys7TableImages, Sys7VerifyOutcome, apply_sys7_tables};
use crate::backup::{BackupError, DeviceBackup, backups_root, write_device_backup};
use crate::compute::{DesiredTables, compute_tables};
use crate::flash::Sys7TableBases;
use crate::plan::PlanReport;
use crate::tables_sys7::{Sys7LiveTables, Sys7TablesError, read_sys7_tables_at};

/// A device's live tables, whichever family served them.
///
/// Both variants carry the shared [`DeviceTables`] view (mask, address table,
/// association table, resolved links), so every consumer (the diff, the
/// `reconstruct` report, the `apply` backup) works on either. The System 7
/// variant additionally carries the device's own individual address and its
/// group-object descriptor image, which a write needs to rewrite the `0x4000`
/// region without disturbing what the download put there.
#[derive(Debug, Clone)]
pub enum LiveTables {
    /// A System B (`x7B0`) device read through interface-object properties.
    SystemB(DeviceTables),
    /// A System 7 (`0705` / `0701`) device read out of absolute memory.
    Sys7(Box<Sys7LiveTables>),
}

impl LiveTables {
    /// The family-agnostic table view.
    pub fn tables(&self) -> &DeviceTables {
        match self {
            LiveTables::SystemB(t) => t,
            LiveTables::Sys7(s) => &s.tables,
        }
    }

    /// The System 7 detail, when this is a System 7 device.
    pub fn sys7(&self) -> Option<&Sys7LiveTables> {
        match self {
            LiveTables::SystemB(_) => None,
            LiveTables::Sys7(s) => Some(s),
        }
    }
}

/// The outcome of one live table read: the tables, or a mask no family reader
/// speaks (System 1 / 2 / unknown), which the caller reports.
#[derive(Debug, Clone)]
pub enum LiveRead {
    /// The tables were read.
    Tables(LiveTables),
    /// The device answered with a mask bussard cannot read tables for.
    UnsupportedMask {
        /// The device.
        address: IndividualAddress,
        /// The mask version it reported.
        mask: u16,
    },
}

/// A live table read that failed on the bus.
#[derive(Debug, thiserror::Error)]
pub enum LiveReadError {
    /// The System B reader (or the descriptor read before it) failed.
    #[error("reading device tables")]
    Tables(#[source] TablesError),
    /// The System 7 memory-mapped reader failed.
    #[error("reading {address}'s System 7 tables")]
    Sys7 {
        /// The device.
        address: IndividualAddress,
        /// The reader's failure.
        #[source]
        error: Sys7TablesError,
    },
}

/// Reads a device's live tables on an open (and authorized) connection, picking
/// the reader by mask family.
///
/// System B is tried first; its `UnsupportedMask` refusal carries the mask, which
/// routes a System 7 device to the memory-mapped reader instead of failing. Any
/// other family is reported back as [`LiveRead::UnsupportedMask`].
pub async fn read_live_tables<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
) -> Result<LiveRead, LiveReadError> {
    read_live_tables_at(l4, Sys7TableBases::default()).await
}

/// [`read_live_tables`] with the System 7 table bases the device's product
/// allocates ([`crate::sys7_table_bases`]), the fallback the System 7 reader
/// uses when the device does not answer `PID_TABLE_REFERENCE`. Every surface
/// that has the product at hand reads (and so writes) the tables where the
/// product put them; System B ignores `bases`.
pub async fn read_live_tables_at<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    bases: Sys7TableBases,
) -> Result<LiveRead, LiveReadError> {
    match read_tables(l4).await {
        Ok(tables) => Ok(LiveRead::Tables(LiveTables::SystemB(tables))),
        // The System B reader refused: route to the System 7 memory-mapped reader
        // when the central capability table says this mask has table support.
        Err(TablesError::UnsupportedMask { address, mask })
            if MaskProfile::from_mask(mask).capabilities().plan_apply =>
        {
            let live = read_sys7_tables_at(l4, bases)
                .await
                .map_err(|error| LiveReadError::Sys7 { address, error })?;
            Ok(LiveRead::Tables(LiveTables::Sys7(Box::new(live))))
        }
        Err(TablesError::UnsupportedMask { address, mask }) => {
            Ok(LiveRead::UnsupportedMask { address, mask })
        }
        Err(err) => Err(LiveReadError::Tables(err)),
    }
}

/// The model has no links for the device, so its desired tables would be empty.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the model has no links for {0}; refusing to plan an empty table set \
     (add links to the device file (devices/<address>.toml), or check the device address)"
)]
pub struct NoLinks(pub IndividualAddress);

/// Computes the desired tables from the model's links for `target`.
///
/// A device with no links in the model would compute empty tables; that is
/// almost certainly a mistake (it would wipe the device), so it is refused.
pub fn desired_tables_for(
    model: &Model,
    target: IndividualAddress,
) -> Result<DesiredTables, NoLinks> {
    let links = model
        .links
        .links
        .get(&target)
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    if links.is_empty() {
        return Err(NoLinks(target));
    }
    Ok(compute_tables(links))
}

/// [`desired_tables_for`] knowing the device's application `app`: a program
/// with no group objects (the Jung IPS 300 SREG KNX IP interface, whose load
/// procedure only writes properties, issue #390) has nothing to link, so its
/// empty table set is its correct state and is not refused. Every program
/// with group objects, or an unknown one (`None`), keeps the refusal.
pub fn desired_tables_for_app(
    model: &Model,
    target: IndividualAddress,
    app: Option<&bussard_prod::ApplicationProgram>,
) -> Result<DesiredTables, NoLinks> {
    match desired_tables_for(model, target) {
        Err(NoLinks(_)) if app.is_some_and(has_no_group_objects) => Ok(compute_tables(&[])),
        other => other,
    }
}

/// Whether `app` declares no group object at all.
pub fn has_no_group_objects(app: &bussard_prod::ApplicationProgram) -> bool {
    app.com_objects.is_empty() && app.resolved_com_objects().is_empty()
}

/// [`render_plan_text`] for a full application download (`method: flash`,
/// issue #326): the tables are rewritten with the image even when their
/// contents stay, so the plan says what the download writes instead of
/// "nothing to do".
pub fn render_full_image_plan_text(
    target: IndividualAddress,
    live: &DeviceTables,
    report: &PlanReport,
    full: &crate::device_plan::FullImage,
) -> String {
    let text = render_plan_text(target, live, report);
    let line = format!("full download: writes {}", full.describe());
    if report.is_noop() {
        let head = text.lines().next().unwrap_or_default();
        format!("{head}\n\n{line}\n")
    } else {
        format!("{text}\n{line}\n")
    }
}

/// Renders the plan exactly as `bussard plan` prints it, without the closing
/// "run `bussard apply`" hint (which is the CLI's to add).
///
/// Additions and removals come first, then the resulting table sizes and the
/// load operations a write would run. A no-op plan is the header plus one
/// "nothing to do" line.
pub fn render_plan_text(
    target: IndividualAddress,
    live: &DeviceTables,
    report: &PlanReport,
) -> String {
    // `writeln!` into a String cannot fail; the results are discarded.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "plan for {target} — mask {:04X} ({})",
        live.mask,
        system_type(live.mask)
    );
    if report.is_noop() {
        let _ = writeln!(
            out,
            "\nnothing to do — the device tables already match the model"
        );
        return out;
    }
    let _ = writeln!(
        out,
        "\n{} addition(s), {} removal(s), {} unchanged:",
        report.additions.len(),
        report.removals.len(),
        report.unchanged.len()
    );
    for p in &report.additions {
        let _ = writeln!(out, "  + add:    object {:>4} → {}", p.object, p.ga);
    }
    for p in &report.removals {
        let _ = writeln!(out, "  - remove: object {:>4} → {}", p.object, p.ga);
    }
    let _ = writeln!(
        out,
        "\ntable sizes: group addresses {} → {}, associations {} → {}",
        report.current_address_count,
        report.resulting_address_count,
        report.current_association_count,
        report.resulting_association_count,
    );
    let _ = writeln!(out, "\nload operations `apply` would run (in order):");
    for step in &report.load_steps {
        let _ = writeln!(out, "  StartLoading → write → LoadCompleted: {step}");
    }
    out
}

/// Serialises the live pre-state tables to a JSON backup under
/// `<dir>/captures/backups/<ia>-<timestamp>.json` and returns its path.
///
/// Every write path takes this backup before it touches a load state; the
/// format itself is [`DeviceBackup`].
pub fn write_pre_write_backup(
    dir: &Path,
    target: IndividualAddress,
    live: &DeviceTables,
    sys7: Option<&Sys7LiveTables>,
) -> Result<PathBuf, BackupError> {
    let backup = DeviceBackup::capture(target, live, sys7, None, std::time::SystemTime::now());
    write_device_backup(&backups_root(dir), &backup)
}

/// Runs the on-bus write sequence for a **System B** device: connect,
/// authorize, discover the table objects, then [`crate::apply::apply_tables`].
pub async fn write_system_b<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    desired: &DesiredTables,
    secure: SecureLayer,
) -> Result<VerifyOutcome, WriteError> {
    write_system_b_secured(channel, target, source, desired, secure, None).await
}

/// [`write_system_b`] that also reprograms the KNX Data Secure security object
/// when `security` is given (issue #156, see
/// [`apply_tables_secured`](crate::apply::apply_tables_secured)).
pub async fn write_system_b_secured<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    desired: &DesiredTables,
    secure: SecureLayer,
    security: Option<&crate::security::SecurityInputs>,
) -> Result<VerifyOutcome, WriteError> {
    let load = crate::apply::SystemBLoad {
        security,
        ..Default::default()
    };
    write_system_b_seeded(channel, target, source, desired, secure, load, None).await
}

/// [`write_system_b_secured`] on a connection seeded with the device facts the
/// command's read phase verified (issue #209): the object table replaces the
/// `PID_OBJECT_TYPE` walks of the table discovery and of the read-back, the
/// max APDU replaces the `PID_MAX_APDU_LENGTH` read, and the mask replaces the
/// read-back's descriptor read. The written frames are the same with or
/// without a seed; `None` is [`write_system_b_secured`]. `load` adds the
/// security object and the group-object table reload (issue #540, see
/// [`crate::apply::apply_tables_with`]).
pub async fn write_system_b_seeded<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    desired: &DesiredTables,
    secure: SecureLayer,
    load: crate::apply::SystemBLoad<'_>,
    seed: Option<bussard_mgmt::ConnectionSeed>,
) -> Result<VerifyOutcome, WriteError> {
    let mut l4 = Layer4Connection::connect_with_secure(
        channel,
        target,
        source,
        bussard_mgmt::Timeouts::default(),
        secure,
    )
    .await
    .map_err(WriteError::Mgmt)?;
    if let Some(seed) = seed {
        l4.seed(seed);
    }
    // Authorize the write session with the free-access key before any table
    // write, exactly as ETS does (issue #52 finding #1). This is the mutating
    // path, so fail loudly on an explicit access-denied (a keyed device needs its
    // BCU key) rather than proceeding into writes that the device would drop; a
    // device that does not implement authorize is tolerated and continues.
    // A device the read phase (or its checked facts) saw stay silent is not
    // asked again: the unanswered request costs the full 3 s response timeout
    // (issue #215). A device that answered is always asked.
    if !l4.seeded_authorize_unanswered() {
        l4.authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
            .await
            .map_err(WriteError::Mgmt)?;
    }
    // Negotiate PID_MAX_APDU_LENGTH once, right after authorize, like ETS's
    // opening property read (#116); the table writes then use its chunk size.
    negotiate_session_apdu(&mut l4).await?;
    let objects = discover_table_objects(&mut l4).await?;
    let result = crate::apply::apply_tables_with(&mut l4, objects, desired, load).await;
    let _ = l4.disconnect().await;
    result
}

/// Runs the on-bus write sequence for a **System 7** device: authorize, then
/// drive the table load-state machines and restart the device (see
/// [`crate::apply_sys7`]).
///
/// The LSM realisation (property-based on `0705`, memory-mapped on `0701`) comes
/// from the mask-family default profile, exactly as the flash path selects it.
pub async fn write_sys7<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    mask: u16,
    images: &Sys7TableImages,
    secure: SecureLayer,
) -> Result<Sys7VerifyOutcome, Sys7ApplyError> {
    // Refuse before the connection opens: every TaskSegment record carries the
    // application's identity, which only the product gives.
    let task_identity = images.task_identity.ok_or(Sys7ApplyError::NoTaskIdentity)?;
    let mut l4 = Layer4Connection::connect_with_secure(
        channel,
        target,
        source,
        bussard_mgmt::Timeouts::default(),
        secure,
    )
    .await
    .map_err(|e| Sys7ApplyError::Write(WriteError::Mgmt(e)))?;
    // System 7 gates every memory access behind A_Authorize (spec §6); this is
    // the mutating path, so an explicit access-denied fails loudly.
    l4.authorize_or_fail(bussard_mgmt::apci::FREE_ACCESS_KEY)
        .await
        .map_err(|e| Sys7ApplyError::Write(WriteError::Mgmt(e)))?;
    // Negotiate PID_MAX_APDU_LENGTH once, right after authorize, like ETS's
    // opening property read (#116); the table writes then use its chunk size.
    negotiate_session_apdu(&mut l4).await?;
    let profile = MaskProfile::from_mask(mask)
        .sys7_default_profile()
        .unwrap_or_else(bussard_mgmt::Sys7Profile::corpus_default);
    let lsm = bussard_mgmt::lsm_access_from_profile(&profile);
    let result = apply_sys7_tables(&mut l4, &lsm, &profile, images, &task_identity).await;
    let _ = l4.disconnect().await;
    result
}

/// The family-agnostic result of one write phase, so every surface reports the
/// same verified or failed outcome.
#[derive(Debug, Clone)]
pub struct TableWriteSummary {
    /// Whether everything loaded and read back byte-for-byte.
    pub ok: bool,
    /// The address table's (LSM 1's) final load state.
    pub address_state: LoadState,
    /// The association table's (LSM 2's) final load state.
    pub association_state: LoadState,
    /// The full outcome, for a report when something did not verify.
    pub detail: String,
    /// Whether the write ended with a restart (System 7, after it verified):
    /// the device drops off the bus while it starts, so the caller waits for
    /// it to answer again before the next connection.
    pub restarted: bool,
    /// The System B group-object table reload, when the write carried one
    /// (issue #540).
    pub object_table: Option<crate::object_table::ObjectTableOutcome>,
}

/// Runs the write for whichever family the device is: the System 7 path when
/// `sys7_images` is given, the System B path otherwise.
///
/// A failure that stopped the sequence is returned as its message; a sequence
/// that ran to the end but did not verify is `Ok` with `ok == false`.
pub async fn write_tables<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    mask: u16,
    desired: &DesiredTables,
    sys7_images: Option<&Sys7TableImages>,
    secure: SecureLayer,
) -> Result<TableWriteSummary, String> {
    write_tables_secured(
        channel,
        target,
        source,
        mask,
        desired,
        sys7_images,
        secure,
        None,
    )
    .await
}

/// [`write_tables`] that also reprograms the KNX Data Secure security object of
/// a System B device when `security` is given (issue #156). System 7 devices
/// have no security object; `security` is ignored for them.
#[allow(clippy::too_many_arguments)] // `write_tables`' inputs plus the security inputs
pub async fn write_tables_secured<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    mask: u16,
    desired: &DesiredTables,
    sys7_images: Option<&Sys7TableImages>,
    secure: SecureLayer,
    security: Option<&crate::security::SecurityInputs>,
) -> Result<TableWriteSummary, String> {
    let load = crate::apply::SystemBLoad {
        security,
        ..Default::default()
    };
    write_tables_seeded(
        channel,
        target,
        source,
        mask,
        desired,
        sys7_images,
        secure,
        load,
        None,
    )
    .await
}

/// [`write_tables_secured`] with the verified device facts of the read phase
/// seeded into the System B write connection (see [`write_system_b_seeded`]),
/// and the System B `load` beyond the link tables: the security object and
/// the group-object table reload (issue #540). The System 7 path takes no
/// seed and ignores `load`.
#[allow(clippy::too_many_arguments)] // `write_tables_secured`' inputs plus the seed
pub async fn write_tables_seeded<Ch: L4Channel>(
    channel: Ch,
    target: IndividualAddress,
    source: IndividualAddress,
    mask: u16,
    desired: &DesiredTables,
    sys7_images: Option<&Sys7TableImages>,
    secure: SecureLayer,
    load: crate::apply::SystemBLoad<'_>,
    seed: Option<bussard_mgmt::ConnectionSeed>,
) -> Result<TableWriteSummary, String> {
    match sys7_images {
        Some(images) => write_sys7(channel, target, source, mask, images, secure)
            .await
            .map(|v| TableWriteSummary {
                ok: v.ok(),
                address_state: v.address_state,
                association_state: v.association_state,
                detail: format!("{v:?}"),
                restarted: v.restarted,
                object_table: None,
            })
            .map_err(|e| e.to_string()),
        None => write_system_b_seeded(channel, target, source, desired, secure, load, seed)
            .await
            .map(|v| TableWriteSummary {
                ok: v.ok(),
                address_state: v.address_state,
                association_state: v.association_state,
                detail: format!("{v:?}"),
                restarted: false,
                object_table: v.object_table.clone(),
            })
            .map_err(|e| e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::plan;

    fn live_with(addresses: &[&str], associations: &[(u16, u16)]) -> DeviceTables {
        let addresses: Vec<bussard_model::GroupAddress> =
            addresses.iter().filter_map(|s| s.parse().ok()).collect();
        // Resolve each association (tsap is 1-based into the address table).
        let resolved = associations
            .iter()
            .filter_map(|&(tsap, asap)| {
                let ga = *addresses.get(usize::from(tsap).checked_sub(1)?)?;
                Some(bussard_mgmt::tables::ResolvedLink { object: asap, ga })
            })
            .collect();
        DeviceTables {
            mask: 0x07B0,
            addresses,
            associations: associations.to_vec(),
            resolved,
            sources: Vec::new(),
            notes: Vec::new(),
            group_objects: None,
        }
    }

    #[test]
    fn test_render_plan_text_noop_says_nothing_to_do() -> Result<(), Box<dyn std::error::Error>> {
        let live = live_with(&["1/2/0"], &[(1, 20)]);
        let desired = DesiredTables {
            addresses: vec!["1/2/0".parse()?],
            associations: vec![(1, 20)],
        };
        let report = plan(&live, &desired);
        let text = render_plan_text("1.1.4".parse()?, &live, &report);
        assert!(text.starts_with("plan for 1.1.4"));
        assert!(text.contains("nothing to do"));
        Ok(())
    }

    #[test]
    fn test_render_plan_text_lists_additions_and_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let live = live_with(&["1/2/0"], &[(1, 20)]);
        let desired = DesiredTables {
            addresses: vec!["1/2/0".parse()?, "1/2/2".parse()?],
            associations: vec![(1, 20), (2, 22)],
        };
        let report = plan(&live, &desired);
        let text = render_plan_text("1.1.4".parse()?, &live, &report);
        assert!(text.contains("1 addition(s), 0 removal(s), 1 unchanged:"));
        assert!(text.contains("+ add:    object   22 → 1/2/2"));
        assert!(text.contains("table sizes: group addresses 1 → 2, associations 1 → 2"));
        Ok(())
    }
}
