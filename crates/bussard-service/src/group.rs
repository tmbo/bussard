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
use std::path::{Path, PathBuf};
use std::time::Duration;

use bussard_bus::ops::{self, ReadOutcome};
use bussard_bus::{BusError, SendReceipt};
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model};
use bussard_secure::{AsduError, Key16, SecurityAlgorithm, Sequence, decode_group, encode_group};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, MessageCode};

use crate::admission::{Admission, AdmissionEvidence, LiveTables, Resolved};
use crate::bus::BusService;
use crate::limit::ReadLimiter;
use crate::secure::{SecureKeyError, ToolKeySource, ToolKeys};
use crate::warm::WarmConnection;

/// The keyring's group keys, by group address (the `.knxkeys`
/// `GroupAddresses/Group@Key` entries).
pub type GroupKeys = HashMap<GroupAddress, Key16>;

/// Why a secured GA cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecureGroupError {
    /// The GA is secured in the model but no group key is available for it.
    #[error("group address {ga} is secured but no group key is available for it")]
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

/// Why a group read or write could not start; nothing was sent.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    /// The keyring's group keys did not load.
    #[error("loading group keys from {}", path.display())]
    Keys {
        /// The keyring.
        path: PathBuf,
        /// Why.
        #[source]
        source: SecureKeyError,
    },
    /// The GA is secured but has no group key.
    #[error(transparent)]
    NoKey(#[from] SecureGroupError),
    /// The keyring's interface entries (the admission evidence) did not load.
    #[error("loading the interfaces of {}", path.display())]
    Evidence {
        /// The keyring.
        path: PathBuf,
        /// Why.
        #[source]
        source: SecureKeyError,
    },
    /// The receivers' tool keys (for their PID 54 read) did not load.
    #[error(transparent)]
    ToolKeys(SecureKeyError),
}

/// The keyring's group keys, `None` without a keyring.
///
/// # Errors
///
/// [`GroupError::Keys`] when the keyring does not load.
pub fn load_keys(keyring: Option<&Path>) -> Result<Option<GroupKeys>, GroupError> {
    keyring
        .map(|path| {
            crate::secure::load_group_keys(path).map_err(|source| GroupError::Keys {
                path: path.to_path_buf(),
                source,
            })
        })
        .transpose()
}

/// The group key to read `ga` with ([`group_key_for`] over the keyring's
/// keys), `None` for the plain path.
///
/// # Errors
///
/// The keyring does not load, or the GA is secured without a key.
pub fn read_key(
    model: Option<&Model>,
    ga: GroupAddress,
    keyring: Option<&Path>,
) -> Result<Option<Key16>, GroupError> {
    let keys = load_keys(keyring)?;
    Ok(group_key_for(model, ga, keys.as_ref())?)
}

/// What a group read or write shares with the surface that runs it.
pub struct GroupContext<'a> {
    /// The model: the GA's DPT, its receivers and the admission evidence of
    /// the lock.
    pub model: Option<&'a Model>,
    /// The keyring: the admission evidence and the receivers' tool keys.
    pub keyring: Option<&'a Path>,
    /// The model directory whose lock records a PID 54 read, `None` to
    /// record nothing.
    pub lock_dir: Option<&'a Path>,
    /// The PID 54 tables read so far; a surface that keeps them (the MCP
    /// server, for its lifetime) reads each device once (issue #316).
    pub live: &'a tokio::sync::Mutex<LiveTables>,
    /// The warm management connection, released before a PID 54 read opens
    /// its own session (issue #215).
    pub warm: Option<&'a WarmConnection>,
    /// The rate limiter, held across the read or the send.
    pub limiter: Option<&'a ReadLimiter>,
}

/// What a group read or write did.
#[derive(Debug)]
pub struct GroupOutcome<R> {
    /// The tunnel's individual address, the telegram's source.
    pub sender: IndividualAddress,
    /// The sender admission verdict of a secured GA (issue #297).
    pub admission: Option<Admission>,
    /// The note of a secured telegram sent without admission evidence.
    pub note: Option<String>,
    /// The receivers whose PID 54 was read and recorded in the lock.
    pub tables_read: Vec<IndividualAddress>,
    /// The read or the send, or the refused admission when nothing was sent.
    pub result: Result<R, Admission>,
}

/// What [`read`] returns: the response, `None` on a timeout.
pub type ReadResult = Result<Option<GroupRead>, GroupSendError>;

/// What [`write`] returns: the send.
pub type WriteResult = Result<crate::write::WriteOutcome, crate::write::WriteRefusal>;

/// Resolves the sender admission of a secured GA (issue #297): the evidence of
/// the keyring and the lock, and on an unknown verdict the receivers' PID 54
/// read (issue #316).
async fn admission(
    service: &BusService,
    ctx: &GroupContext<'_>,
    verdict: impl Fn(&AdmissionEvidence, &LiveTables) -> Admission,
) -> Result<Resolved, GroupError> {
    let evidence = match ctx.keyring {
        Some(path) => {
            crate::secure::load_admission_evidence(path).map_err(|source| GroupError::Evidence {
                path: path.to_path_buf(),
                source,
            })?
        }
        None => AdmissionEvidence::default(),
    };
    let keys = match ctx.keyring {
        Some(_) => ToolKeys::load(ToolKeySource {
            keyring: ctx.keyring,
            tool_key: None,
        })
        .map_err(GroupError::ToolKeys)?,
        None => ToolKeys::default(),
    };
    // Management calls are sequential (issue #215): the read opens its own
    // lease, so the warm connection is released first.
    let mut warm = match ctx.warm {
        Some(warm) => Some(warm.lock().await),
        None => None,
    };
    if let Some(warm) = warm.as_mut() {
        warm.release().await;
    }
    let mut live = ctx.live.lock().await;
    let resolved =
        crate::admission::resolve_unknown(service, ctx.lock_dir, &keys, &mut live, |live| {
            verdict(&evidence, live)
        })
        .await;
    drop(warm);
    Ok(resolved)
}

/// Reads `ga` (issue #172): the secured `GroupValueRead` under `key`, after
/// the sender admission of a secured GA (issue #297), held under the rate
/// limiter. A responder known not to admit the tunnel address is not asked.
///
/// # Errors
///
/// The admission evidence or the tool keys did not load; nothing was sent.
pub async fn read(
    service: &BusService,
    ctx: &GroupContext<'_>,
    ga: GroupAddress,
    key: Option<Key16>,
    timeout: Duration,
) -> Result<GroupOutcome<ReadResult>, GroupError> {
    let sender = ops::group_source(service.handle());
    let model = ctx.model;
    let resolved = match key {
        Some(_) => Some(
            admission(service, ctx, |evidence, live| {
                crate::admission::check_sender_admission(model, ga, sender, evidence, live)
            })
            .await?,
        ),
        None => None,
    };
    let dpt = model
        .and_then(|m| m.groups.groups.get(&ga))
        .and_then(|g| g.dpt);
    Ok(outcome(sender, resolved, ctx.limiter, async || {
        service.read_group(ga, dpt, key.as_ref(), timeout).await
    })
    .await)
}

/// Sends the checked `write` ([`crate::write::prepare_group_write`]) once,
/// after the sender admission of a secured GA (issue #297), held under the
/// rate limiter. A write the receivers would discard is not sent.
///
/// # Errors
///
/// The admission evidence or the tool keys did not load; nothing was sent.
pub async fn write(
    service: &BusService,
    ctx: &GroupContext<'_>,
    write: crate::write::PreparedWrite,
) -> Result<GroupOutcome<WriteResult>, GroupError> {
    let sender = ops::group_source(service.handle());
    let (model, ga) = (ctx.model, write.ga);
    // E038 (issue #348): a tunnel-only secured GA whose devices admit no
    // tunnelling address is refused while admit_tunnel_senders is off; an
    // unknown verdict reads the receivers' PID 54 first, and a "not listed"
    // there refuses too (issue #316).
    let resolved = if write.is_secured() {
        Some(
            admission(service, ctx, |evidence, live| {
                crate::admission::check_tunnel_write(model, ga, sender, evidence, live)
            })
            .await?,
        )
    } else {
        None
    };
    Ok(outcome(sender, resolved, ctx.limiter, async || {
        service.send_prepared(write).await
    })
    .await)
}

/// Runs `send` under the rate limiter unless the admission refused it.
async fn outcome<R>(
    sender: IndividualAddress,
    resolved: Option<Resolved>,
    limiter: Option<&ReadLimiter>,
    send: impl AsyncFnOnce() -> R,
) -> GroupOutcome<R> {
    let note = resolved.as_ref().and_then(Resolved::note);
    let (admission, tables_read) = match resolved {
        Some(r) => (Some(r.admission), r.read),
        None => (None, Vec::new()),
    };
    let result = match admission.as_ref().filter(|a| a.is_refused()) {
        Some(refused) => Err(refused.clone()),
        None => {
            let _permit = match limiter {
                Some(limiter) => limiter.acquire().await,
                None => None,
            };
            Ok(send().await)
        }
    };
    GroupOutcome {
        sender,
        admission,
        note,
        tables_read,
        result,
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
