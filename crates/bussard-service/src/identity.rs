//! Identifying a device over management: its mask version, manufacturer,
//! serial number and order info, in the clear or over KNX Data Secure
//! (issue #203).
//!
//! A Data Secure-activated device answers a plain `A_DeviceDescriptor_Read`
//! with mask [`HIDDEN_MASK`] (`FFFF`) and drops every other plain management
//! request. `scan`, `assign` and `audit --live` identify devices, so they share
//! these probes:
//!
//! - [`identify_plain`]: the historical `scan` probe, frame for frame, except
//!   that a hidden mask ends it (the property reads that would follow are
//!   refused anyway, each costing a timeout).
//! - [`identify_secured`]: the same reads inside an `A_SecureData` session
//!   (the secure layer opens it with `S-A_Sync`), as `describe --keyring` does.
//! - [`probe`]: the rule `scan` applies per address, returning an
//!   [`Identity`] and a [`SecureStatus`].

use bussard_mgmt::apci::{FREE_ACCESS_KEY, PID_MANUFACTURER_ID, PID_ORDER_INFO, PID_SERIAL_NUMBER};
use bussard_model::IndividualAddress;
use bussard_secure::Key16;

use crate::bus::{BusService, L4Options};
use crate::error::ServiceError;
use crate::util::clean_ascii;
use bussard_mgmt::{L4Channel, Layer4Connection, MgmtError, read_device_descriptor};

/// The mask a Data Secure-activated device reports to a plain descriptor read.
pub const HIDDEN_MASK: u16 = 0xFFFF;

/// What one probe read from a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The device address.
    pub address: IndividualAddress,
    /// The mask version ([`HIDDEN_MASK`] from a plain read of an activated
    /// device).
    pub mask: u16,
    /// The KNX manufacturer id, when readable.
    pub manufacturer_id: Option<u16>,
    /// The serial number, when readable.
    pub serial: Option<Vec<u8>>,
    /// The order info as printable ASCII, when readable.
    pub order: Option<String>,
}

impl Identity {
    /// Whether the mask is the [`HIDDEN_MASK`] of a plain read of an activated
    /// device.
    pub fn mask_hidden(&self) -> bool {
        self.mask == HIDDEN_MASK
    }
}

/// How a device was identified, with respect to KNX Data Secure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecureStatus {
    /// Read in the clear with a real mask: not Data Secure-activated.
    #[default]
    Plain,
    /// Read over `A_SecureData` with the tool key: activated, real mask known.
    Activated,
    /// The plain descriptor read returned [`HIDDEN_MASK`] and no tool key was
    /// available: activated, mask hidden.
    ActivatedNoKey,
    /// A tool key was available but the secured read was not answered, while
    /// the plain read returned [`HIDDEN_MASK`]: activated, but the key is not
    /// this device's.
    KeyRefused,
}

impl SecureStatus {
    /// The stable `--json` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            SecureStatus::Plain => "plain",
            SecureStatus::Activated => "activated",
            SecureStatus::ActivatedNoKey => "activated_no_key",
            SecureStatus::KeyRefused => "key_refused",
        }
    }

    /// Whether the device is Data Secure-activated.
    pub fn activated(self) -> bool {
        !matches!(self, SecureStatus::Plain)
    }
}

/// The plain probe: connect, read the descriptor, authorize with the free
/// access key, then best-effort read manufacturer, serial and order. `None` for
/// an absent or refusing device. A [`HIDDEN_MASK`] answer skips the authorize
/// and the property reads.
///
/// `options.tool_key` is ignored (forced to `None`); `options.authorize`
/// should be [`Authorize::Skip`](crate::Authorize::Skip), since the probe authorizes after the
/// descriptor read, as ETS does.
pub async fn identify_plain(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
) -> Option<Identity> {
    let options = options.clone().with_tool_key(None);
    session(service, address, &options, true).await.ok()
}

/// The secured probe: the reads of [`identify_plain`] over `A_SecureData` with
/// `tool_key`. `None` when the device is absent or does not answer the secured
/// session (a wrong key, or a device that is not activated).
pub async fn identify_secured(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
    tool_key: Key16,
) -> Option<Identity> {
    let options = options.clone().with_tool_key(Some(tool_key));
    session(service, address, &options, false).await.ok()
}

/// Whether `address` answers a secured session under its factory default
/// setup key `fdsk` (issue #532): the descriptor read of [`identify_secured`]
/// with the FDSK as the session key.
///
/// The converse of the tool key's FDSK fallback: a device the model does not
/// mark activated that refuses plain access may have its security mode on
/// with no tool key set yet, or may have been reset to default after a
/// commissioning the key store no longer reflects. A Secure-capable device
/// answers S-A_Data under its FDSK while no tool key is set (KNX 3/5/1
/// §6.1.4). Read-only: nothing is written under the factory key.
pub async fn answers_under_factory_key(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
    fdsk: Key16,
) -> bool {
    let options = options
        .clone()
        .with_factory_key(None)
        .with_authorize(crate::Authorize::Skip);
    identify_secured(service, address, &options, fdsk)
        .await
        .is_some()
}

/// The FDSK fallback of a describe whose plain walk was refused (issue
/// #532), the one decision `bussard describe` and the MCP
/// `knx_describe_device` share (issue #571): with `refused` set, no tool key
/// in `options` and the device's FDSK in `options.factory_key`, whether the
/// device answers a secured descriptor read under that factory key
/// ([`answers_under_factory_key`]). `false` without a probe otherwise.
/// Read-only.
pub async fn refused_walk_answers_under_factory_key(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
    refused: bool,
) -> bool {
    match (
        refused,
        options.tool_key.is_none(),
        options.factory_key.clone(),
    ) {
        (true, true, Some(fdsk)) => {
            answers_under_factory_key(service, address, options, fdsk).await
        }
        _ => false,
    }
}

/// The error for a device that refuses plain access and answers under its
/// factory key (issue #532), worded once for the CLI and the MCP tier.
pub fn factory_key_message(target: IndividualAddress) -> String {
    format!(
        "{target} refuses plain management and answers a secured read under its factory key \
         (FDSK) from the key store: its Data Secure security mode is on and no tool key is set, \
         or it was reset to default after a commissioning. bussard does not write under the \
         factory key. Commission it with ETS (download with security) and import the new keyring \
         export (`bussard keys import`)"
    )
}

/// Why [`probe_classified`] found no identity at an address (issue #45).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMiss {
    /// The interface reported a negative `L_Data.con` for the connect or the
    /// descriptor read: nothing acknowledged the frame on the medium, so the
    /// address is absent. Established in tens of milliseconds, only under a
    /// budget that opts in
    /// ([`Timeouts::absent_on_negative_confirmation`](bussard_mgmt::Timeouts::absent_on_negative_confirmation)).
    NegativeConfirmation,
    /// Nothing answered within the ACK timeout and its repetitions: absent,
    /// established the slow way (the fallback on an interface that reports no
    /// negative confirmations).
    Timeout,
    /// A device reacted but did not identify itself (a refused descriptor
    /// read, a disconnect), or the session could not be opened.
    Refused,
}

impl ProbeMiss {
    /// The stable `--json` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeMiss::NegativeConfirmation => "absent_negative_confirmation",
            ProbeMiss::Timeout => "absent_timeout",
            ProbeMiss::Refused => "refused",
        }
    }

    /// The miss a failed probe session's error stands for.
    fn from_error(err: &MgmtError) -> ProbeMiss {
        match err {
            MgmtError::NotConfirmed { .. } => ProbeMiss::NegativeConfirmation,
            MgmtError::NoResponse { .. } => ProbeMiss::Timeout,
            _ => ProbeMiss::Refused,
        }
    }
}

/// Identifies `address` the way `scan` does (issue #203).
///
/// With a tool key the secured probe runs first; when it is not answered the
/// plain probe runs, so an absent key entry never hides a device. Without a key
/// the plain probe runs alone: a plain device costs exactly the frames it
/// always did.
pub async fn probe(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
    tool_key: Option<Key16>,
) -> Option<(Identity, SecureStatus)> {
    probe_classified(service, address, options, tool_key)
        .await
        .ok()
}

/// [`probe`], saying why an address yielded no identity (issue #45): absent by
/// a negative `L_Data.con`, absent by timeout, or refused. The frames are those
/// of [`probe`]; with a tool key, a negative confirmation of the secured probe
/// ends the probe there, since it proves nothing sits at the address.
pub async fn probe_classified(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
    tool_key: Option<Key16>,
) -> Result<(Identity, SecureStatus), ProbeMiss> {
    let had_key = tool_key.is_some();
    if let Some(key) = tool_key {
        let secured = options.clone().with_tool_key(Some(key));
        match session(service, address, &secured, false).await {
            Ok(identity) => return Ok((identity, SecureStatus::Activated)),
            Err(ProbeMiss::NegativeConfirmation) => return Err(ProbeMiss::NegativeConfirmation),
            Err(_) => {}
        }
        tracing::debug!("{address} did not answer the secured probe; trying the plain probe");
    }
    let plain = options.clone().with_tool_key(None);
    let identity = session(service, address, &plain, true).await?;
    let status = match (identity.mask_hidden(), had_key) {
        (false, _) => SecureStatus::Plain,
        (true, false) => SecureStatus::ActivatedNoKey,
        (true, true) => SecureStatus::KeyRefused,
    };
    Ok((identity, status))
}

/// One probe session; `plain` selects the hidden-mask short cut.
async fn session(
    service: &BusService,
    address: IndividualAddress,
    options: &L4Options,
    plain: bool,
) -> Result<Identity, ProbeMiss> {
    let outcome = service
        .with_l4(address, options, async |l4| {
            Ok::<_, ServiceError>(read_identity(l4, plain).await)
        })
        .await;
    match outcome {
        Ok(Ok(identity)) => Ok(identity),
        Ok(Err(err)) | Err(ServiceError::Mgmt(err)) => Err(ProbeMiss::from_error(&err)),
        Err(_) => Err(ProbeMiss::Refused),
    }
}

/// Reads a device's identity on an open session: the descriptor, then a
/// best-effort free-access authorize (as ETS does right after the descriptor
/// read, issue #52 finding #1) and the manufacturer, serial number and order
/// info, each best-effort.
///
/// With `plain`, a [`HIDDEN_MASK`] answer ends the reads there: a Data
/// Secure-activated device drops every further plain request, each costing a
/// timeout.
///
/// # Errors
///
/// The descriptor read failed (absent, refusing, disconnected).
pub async fn read_identity<Ch: L4Channel>(
    l4: &mut Layer4Connection<Ch>,
    plain: bool,
) -> Result<Identity, MgmtError> {
    let address = l4.target();
    let mask = read_device_descriptor(l4).await.inspect_err(|err| {
        if err.device_present() {
            tracing::debug!("{address} is present but refused the descriptor read: {err}");
        }
    })?;
    let mut identity = Identity {
        address,
        mask,
        manufacturer_id: None,
        serial: None,
        order: None,
    };
    if plain && mask == HIDDEN_MASK {
        return Ok(identity);
    }
    if let Err(err) = l4.authorize_or_fail(FREE_ACCESS_KEY).await {
        tracing::debug!("{address} authorize (free access) did not grant: {err}");
    }
    identity.manufacturer_id = read_manufacturer(l4).await;
    identity.serial = read_serial(l4).await;
    identity.order = read_order(l4).await;
    Ok(identity)
}

/// `PID_MANUFACTURER_ID`, when readable (two octets or more).
pub async fn read_manufacturer<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Option<u16> {
    match l4.read_device_property(PID_MANUFACTURER_ID).await {
        Ok(bytes) if bytes.len() >= 2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        _ => None,
    }
}

/// `PID_SERIAL_NUMBER`, when readable and not empty.
pub async fn read_serial<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Option<Vec<u8>> {
    l4.read_device_property(PID_SERIAL_NUMBER)
        .await
        .ok()
        .filter(|v| !v.is_empty())
}

/// `PID_ORDER_INFO` as printable ASCII, when readable and not empty.
pub async fn read_order<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Option<String> {
    l4.read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_status_as_str_is_stable() {
        assert_eq!(SecureStatus::Plain.as_str(), "plain");
        assert_eq!(SecureStatus::Activated.as_str(), "activated");
        assert_eq!(SecureStatus::ActivatedNoKey.as_str(), "activated_no_key");
        assert_eq!(SecureStatus::KeyRefused.as_str(), "key_refused");
        assert!(!SecureStatus::Plain.activated());
        assert!(SecureStatus::ActivatedNoKey.activated());
    }
}
