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

use crate::bus::{BusService, Device, L4Options};
use crate::error::ServiceError;
use bussard_mgmt::MgmtError;

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
    let options = L4Options {
        tool_key: None,
        ..options.clone()
    };
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
    let options = L4Options {
        tool_key: Some(tool_key),
        ..options.clone()
    };
    session(service, address, &options, false).await.ok()
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
        let secured = L4Options {
            tool_key: Some(key),
            ..options.clone()
        };
        match session(service, address, &secured, false).await {
            Ok(identity) => return Ok((identity, SecureStatus::Activated)),
            Err(ProbeMiss::NegativeConfirmation) => return Err(ProbeMiss::NegativeConfirmation),
            Err(_) => {}
        }
        tracing::debug!("{address} did not answer the secured probe; trying the plain probe");
    }
    let plain = L4Options {
        tool_key: None,
        ..options.clone()
    };
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
        .with_device(address, options, async |dev| {
            Ok::<_, ServiceError>(identify(dev, address, plain).await)
        })
        .await;
    match outcome {
        Ok(result) => result,
        Err(ServiceError::Mgmt(err)) => Err(ProbeMiss::from_error(&err)),
        Err(_) => Err(ProbeMiss::Refused),
    }
}

/// The reads of one probe on its open session.
async fn identify(
    dev: &mut Device,
    address: IndividualAddress,
    plain: bool,
) -> Result<Identity, ProbeMiss> {
    let mask = match dev.device_descriptor().await {
        Ok(mask) => mask,
        Err(err) => {
            if err.device_present() {
                tracing::debug!("{address} is present but refused the descriptor read: {err}");
            }
            return Err(ProbeMiss::from_error(&err));
        }
    };
    if plain && mask == HIDDEN_MASK {
        // Data Secure-activated: every further plain read is dropped.
        return Ok(Identity {
            address,
            mask,
            manufacturer_id: None,
            serial: None,
            order: None,
        });
    }
    // Authorize with the free-access key right after the descriptor read, as
    // ETS does (issue #52 finding #1). Best-effort.
    if let Err(err) = dev.authorize(FREE_ACCESS_KEY).await {
        tracing::debug!("{address} authorize (free access) did not grant: {err}");
    }
    let manufacturer_id = match dev.read_device_property(PID_MANUFACTURER_ID).await {
        Ok(bytes) if bytes.len() >= 2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
        _ => None,
    };
    let serial = dev
        .read_device_property(PID_SERIAL_NUMBER)
        .await
        .ok()
        .filter(|v| !v.is_empty());
    let order = dev
        .read_device_property(PID_ORDER_INFO)
        .await
        .ok()
        .map(|v| clean_ascii(&v))
        .filter(|s| !s.is_empty());
    Ok(Identity {
        address,
        mask,
        manufacturer_id,
        serial,
        order,
    })
}

/// Cleans a raw property value to printable ASCII, up to the first NUL,
/// trimmed.
pub fn clean_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| char::from(*b))
        .collect();
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_ascii_strips_nul_and_control() {
        assert_eq!(clean_ascii(b"ABB/S 1.1\0\0"), "ABB/S 1.1");
        assert_eq!(clean_ascii(&[0x01, 0x02]), "");
    }

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
