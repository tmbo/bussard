//! KNX Data Secure **group communication** for `read` and `write`
//! (issue #172), shared by the CLI, the MCP server and viz.
//!
//! A group address is *secured* when the model marks it `secure: true` or the
//! keyring holds a group key for it. A secured GA is read and written with
//! `A_SecureData` telegrams sealed under its group key; a device with a secured
//! group object ignores a plain telegram on it. A plain GA takes the plain path
//! byte for byte.
//!
//! - [`group_key_for`] decides, before anything is sent, whether a GA is plain,
//!   secured with a key, or secured without one (refused with a hint).
//! - [`BusService::read_group`] sends the `GroupValueRead` (plain or secured)
//!   and, for a secured GA, accepts only a response that verifies under the
//!   group key.
//! - The secured write is [`BusService::send_prepared`](crate::BusService::send_prepared)
//!   with a [`PreparedWrite`](crate::PreparedWrite) whose `group_key` is set.
//!
//! The send sequence is `max(clock, last sent + 1)` from the service's
//! [`group_high_water`](BusService::group_high_water) (spec §5.8), so a
//! long-lived server never repeats one and a later process starts above an
//! earlier one. The source is the tunnel's individual address, which is what
//! the gateway puts on the bus and what the MAC covers.
//!
//! A receiving device only accepts a secured group telegram from a sender it
//! knows: ETS lists the senders of each secured GA in the device's security
//! individual-address table. bussard's tunnel address must be among them, or
//! the device drops the telegram silently. Nothing here prints key material.

use std::collections::HashMap;
use std::time::Duration;

use bussard_bus::ops::{self, ReadOutcome};
use bussard_bus::{BusError, SendReceipt};
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model};
use bussard_secure::{AsduError, Key16, SecurityAlgorithm, Sequence, decode_group, encode_group};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, MessageCode};

use crate::bus::BusService;

/// The keyring's group keys, by group address (the `.knxkeys`
/// `GroupAddresses/Group@Key` entries).
pub type GroupKeys = HashMap<GroupAddress, Key16>;

/// Why a secured GA cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecureGroupError {
    /// The GA is secured in the model but no group key is available for it.
    #[error("GA {ga} is secured (KNX Data Secure) but no group key is available for it")]
    NoKey {
        /// The GA.
        ga: GroupAddress,
        /// Whether a keyring was given at all (`false`: pass one; `true`: the
        /// keyring has no key for this GA).
        keyring_given: bool,
    },
}

/// The group key to secure `ga` with, `None` for the plain path.
///
/// A key in `keys` secures the GA whatever the model says; a GA marked
/// `secure: true` in the model without a key is refused.
///
/// # Errors
///
/// [`SecureGroupError::NoKey`] for a secured GA without a key.
pub fn group_key_for(
    model: Option<&Model>,
    ga: GroupAddress,
    keys: Option<&GroupKeys>,
) -> Result<Option<Key16>, SecureGroupError> {
    if let Some(key) = keys.and_then(|k| k.get(&ga)) {
        return Ok(Some(key.clone()));
    }
    let secured_in_model = model
        .and_then(|m| m.groups.groups.get(&ga))
        .is_some_and(|g| g.secure);
    if secured_in_model {
        return Err(SecureGroupError::NoKey {
            ga,
            keyring_given: keys.is_some(),
        });
    }
    Ok(None)
}

/// Why a secured group telegram could not be sent.
#[derive(Debug, thiserror::Error)]
pub enum GroupSendError {
    /// Sealing the APDU failed (an APDU too long for the length octet).
    #[error("sealing the secured group telegram")]
    Seal(#[from] AsduError),
    /// The send itself failed.
    #[error(transparent)]
    Bus(#[from] BusError),
}

/// The result of a [`BusService::read_group`].
#[derive(Debug, Clone)]
pub struct GroupRead {
    /// The response, as the plain read reports it.
    pub outcome: ReadOutcome,
    /// Whether the read and its response were secured (the response's MAC
    /// verified under the group key).
    pub secured: bool,
    /// The responder's sequence number, for a secured response.
    pub sequence: Option<u64>,
}

/// A secured group telegram that was sent.
#[derive(Debug, Clone)]
pub struct SecuredSend {
    /// The gateway's receipt.
    pub receipt: SendReceipt,
    /// The source address the telegram was sealed for.
    pub source: IndividualAddress,
    /// The sequence number it carried.
    pub sequence: Sequence,
}

impl BusService {
    /// Seals the plain group `apdu` under `key` for `ga` and sends it once,
    /// completion-tracked.
    ///
    /// Takes the next sequence from [`group_high_water`](Self::group_high_water)
    /// and records it before sending, so a failed send never frees a sequence
    /// for reuse. Does not check the write policy: a secured `GroupValueRead`
    /// is a read.
    ///
    /// # Errors
    ///
    /// [`GroupSendError::Bus`] when the send fails, [`GroupSendError::Seal`]
    /// when the APDU cannot be sealed.
    pub async fn send_group_secured(
        &self,
        ga: GroupAddress,
        apdu: &Apdu,
        key: &Key16,
    ) -> Result<SecuredSend, GroupSendError> {
        let source = ops::group_source(self.handle());
        let sequence = self.group_high_water().next_seed();
        self.group_high_water().observe(sequence);
        let asdu = encode_group(
            key,
            SecurityAlgorithm::AuthenticationEncryption,
            sequence,
            source.raw(),
            ga.raw(),
            &apdu.group_tpdu_bytes(),
        )?;
        let receipt = self
            .handle()
            .send(CemiFrame::group_secure(ga, source, asdu))
            .await?;
        Ok(SecuredSend {
            receipt,
            source,
            sequence,
        })
    }

    /// Sends a `GroupValueRead` for `ga` and waits up to `timeout` for the
    /// answer, decoded against `dpt` when given.
    ///
    /// `key` `None` is exactly [`bussard_bus::ops::read_group`]. With a key the
    /// read is sealed under it, and only a `GroupValueResponse` /
    /// `GroupValueWrite` to `ga` from another source whose MAC verifies under
    /// the same key is accepted; a telegram that does not verify is skipped.
    /// Returns `Ok(None)` on timeout.
    ///
    /// # Errors
    ///
    /// [`GroupSendError`] when the read cannot be sealed or sent.
    pub async fn read_group(
        &self,
        ga: GroupAddress,
        dpt: Option<Dpt>,
        key: Option<&Key16>,
        timeout: Duration,
    ) -> Result<Option<GroupRead>, GroupSendError> {
        let Some(key) = key else {
            let outcome = ops::read_group(self.handle(), ga, dpt, timeout).await?;
            return Ok(outcome.map(|outcome| GroupRead {
                outcome,
                secured: false,
                sequence: None,
            }));
        };
        // Subscribe before sending so a fast response cannot be missed.
        let mut sub = self.handle().subscribe();
        let sent = self
            .send_group_secured(ga, &Apdu::GroupValueRead, key)
            .await?;
        let own = sent.source;
        let matched = sub
            .wait_for_matching(timeout, |stamped, code| {
                code != MessageCode::LDataCon
                    && stamped.frame.source != own
                    && unwrap_answer(&stamped.frame, ga, key).is_some()
            })
            .await;
        let Some(inbound) = matched else {
            return Ok(None);
        };
        let Some((payload, sequence)) = unwrap_answer(&inbound.frame, ga, key) else {
            return Ok(None);
        };
        let value = match (dpt, payload.is_empty()) {
            (Some(d), false) => Some(bussard_model::decode(&d, &payload)),
            _ => None,
        };
        Ok(Some(GroupRead {
            outcome: ReadOutcome {
                payload,
                value,
                dpt,
                source: inbound.frame.source,
            },
            secured: true,
            sequence: Some(sequence),
        }))
    }
}

/// The payload and sequence of a secured `GroupValueResponse` /
/// `GroupValueWrite` to `ga` that verifies under `key`, else `None`.
fn unwrap_answer(frame: &CemiFrame, ga: GroupAddress, key: &Key16) -> Option<(Vec<u8>, u64)> {
    if frame.destination != Destination::Group(ga) {
        return None;
    }
    let asdu = frame.secure_asdu()?;
    let plain = decode_group(key, asdu, frame.source.raw(), ga.raw()).ok()?;
    match Apdu::from_group_tpdu(&plain.apdu).ok()? {
        Apdu::GroupValueResponse(d) | Apdu::GroupValueWrite(d) => {
            Some((d.bytes(), plain.sequence.value()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn model(secure: bool) -> Result<Model, Box<dyn std::error::Error>> {
        let mut groups = BTreeMap::new();
        groups.insert(
            "1/2/3".parse()?,
            Group {
                name: "Secured dimming".to_string(),
                dpt: Some("5.001".parse()?),
                description: None,
                protected: false,
                secure,
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        })
    }

    #[test]
    fn test_group_key_for_plain_ga_is_none() -> TestResult {
        let ga: GroupAddress = "1/2/3".parse()?;
        assert!(group_key_for(Some(&model(false)?), ga, None)?.is_none());
        assert!(group_key_for(None, ga, Some(&GroupKeys::new()))?.is_none());
        Ok(())
    }

    #[test]
    fn test_group_key_for_uses_the_keyring_key() -> TestResult {
        let ga: GroupAddress = "1/2/3".parse()?;
        let mut keys = GroupKeys::new();
        keys.insert(ga, Key16::new([7; 16]));
        // A key secures the GA even when the model does not say so.
        assert_eq!(
            group_key_for(Some(&model(false)?), ga, Some(&keys))?,
            Some(Key16::new([7; 16]))
        );
        assert!(group_key_for(Some(&model(true)?), ga, Some(&keys))?.is_some());
        Ok(())
    }

    #[test]
    fn test_group_key_for_refuses_a_secured_ga_without_a_key() -> TestResult {
        let ga: GroupAddress = "1/2/3".parse()?;
        assert_eq!(
            group_key_for(Some(&model(true)?), ga, None),
            Err(SecureGroupError::NoKey {
                ga,
                keyring_given: false
            })
        );
        assert_eq!(
            group_key_for(Some(&model(true)?), ga, Some(&GroupKeys::new())),
            Err(SecureGroupError::NoKey {
                ga,
                keyring_given: true
            })
        );
        Ok(())
    }
}
