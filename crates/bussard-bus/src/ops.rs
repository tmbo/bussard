//! Shared group read/write operations over a [`BusHandle`](crate::BusHandle).
//!
//! These are the single implementations the CLI (`bussard read`/`write`) and the
//! MCP server (`knx_read_group`/`knx_write_group`) both call, so the send +
//! echo-skip + wait logic lives in one place. Policy — protected GAs, `--force`,
//! passive mode, rate limiting — stays at the *edges* (the caller decides whether
//! to call these at all, and passes an already-resolved DPT/payload).
//!
//! Both use the bus's assigned individual address as the group-traffic source
//! (falling back to `0.0.255` on a routing transport that assigns none) — the
//! deferred #30 item.

use std::time::Duration;

use bussard_model::codec::TypedValue;
use bussard_model::{Dpt, GroupAddress, IndividualAddress};
use bussard_transport::cemi::{Apdu, CemiFrame, Destination, MessageCode};

use crate::{BusError, BusHandle, SendReceipt};

/// The fallback group-traffic source when the transport assigns no individual
/// address (routing, or a gateway reporting `0.0.0`).
pub const FALLBACK_SOURCE_IA: &str = "0.0.255";

/// The source individual address to present on group traffic: the tunnel-assigned
/// address if the gateway gave one, else [`FALLBACK_SOURCE_IA`] (issue #30).
pub fn group_source(handle: &BusHandle) -> IndividualAddress {
    handle
        .assigned_individual_address()
        .map(IndividualAddress::from_raw)
        .unwrap_or_else(|| {
            FALLBACK_SOURCE_IA
                .parse()
                .expect("valid fallback source IA")
        })
}

/// The outcome of a [`read_group`] call.
#[derive(Debug, Clone)]
pub struct ReadOutcome {
    /// The raw APDU payload octets of the response.
    pub payload: Vec<u8>,
    /// The typed value, decoded against `dpt` when one was supplied and decoding
    /// succeeded.
    pub value: Option<TypedValue>,
    /// The DPT the value was decoded against, if any.
    pub dpt: Option<Dpt>,
    /// The individual address that answered.
    pub source: IndividualAddress,
}

/// Sends a `GroupValueRead` for `ga` and waits for the answering
/// `GroupValueResponse`/`Write`, decoding it against `dpt` if given.
///
/// The wait skips the gateway's `L_Data.con` echo of our own request and any
/// frame from our own source address, so the value returned is the device's real
/// answer (issue #32). Returns `Ok(None)` on timeout (no responder), which the
/// caller renders as an honest non-zero exit / `ok: false`.
///
/// The send itself is completion-tracked: if the `GroupValueRead` cannot even be
/// transmitted (bus reconnecting past the staleness cutoff, ACK exhaustion) that
/// [`BusError`] is returned rather than silently timing out.
pub async fn read_group(
    handle: &BusHandle,
    ga: GroupAddress,
    dpt: Option<Dpt>,
    timeout: Duration,
) -> Result<Option<ReadOutcome>, BusError> {
    let source = group_source(handle);

    // Subscribe before sending so the response cannot be missed (issue #32).
    let mut sub = handle.subscribe();

    // Transmit the read, completion-tracked. A transport error is surfaced; a
    // successful receipt means the read is on the wire.
    handle.send(CemiFrame::group_read(ga, source)).await?;

    let matched = sub
        .wait_for_matching(timeout, |stamped, code| {
            let frame = &stamped.frame;
            is_group(frame, ga)
                && matches!(
                    frame.apdu,
                    Apdu::GroupValueResponse(_) | Apdu::GroupValueWrite(_)
                )
                && code != MessageCode::LDataCon
                && frame.source != source
        })
        .await;

    let Some(frame) = matched else {
        return Ok(None);
    };

    let payload = group_payload(&frame.frame.apdu);
    let value = match (dpt, payload.is_empty()) {
        (Some(d), false) => Some(bussard_model::decode(&d, &payload)),
        _ => None,
    };
    Ok(Some(ReadOutcome {
        payload,
        value,
        dpt,
        source: frame.frame.source,
    }))
}

/// The outcome of a [`write_group`] call.
#[derive(Debug, Clone)]
pub struct WriteOutcome {
    /// The transport receipt: the write was ACKed by the gateway.
    pub receipt: SendReceipt,
    /// Whether a bus confirmation (an `L_Data.con`/indication for our GA) was
    /// observed within the settle window. KNX group writes are fire-and-forget,
    /// so `false` is not an error — but it is reported.
    pub confirmed: bool,
    /// The source individual address the write was sent from.
    pub source: IndividualAddress,
}

/// Options controlling [`write_group`]'s confirmation behaviour.
#[derive(Debug, Clone, Copy)]
pub struct WriteOptions {
    /// How long to watch for a bus confirmation after the ACKed send. Zero skips
    /// the confirmation wait entirely (pure fire-and-forget).
    pub confirm_timeout: Duration,
}

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions {
            confirm_timeout: Duration::from_millis(1500),
        }
    }
}

/// Sends a `GroupValueWrite` of `payload` to `ga`, completion-tracked, and
/// optionally watches for a bus confirmation.
///
/// The returned [`WriteOutcome`] carries the [`SendReceipt`] (the gateway ACKed
/// the frame — the honest success signal the CLI's exit code and MCP's `ok` now
/// hinge on) plus whether a confirmation echo/indication for the GA was seen. A
/// transport failure (ACK exhaustion, staleness) is a [`BusError`], not a silent
/// success.
pub async fn write_group(
    handle: &BusHandle,
    ga: GroupAddress,
    payload: &[u8],
    opts: WriteOptions,
) -> Result<WriteOutcome, BusError> {
    let source = group_source(handle);

    // Subscribe before sending so a fast confirmation cannot be missed.
    let mut sub = handle.subscribe();

    let receipt = handle
        .send(CemiFrame::group_write(ga, source, payload))
        .await?;

    let confirmed = if opts.confirm_timeout.is_zero() {
        false
    } else {
        sub.wait_for_matching(opts.confirm_timeout, |stamped, _code| {
            is_group(&stamped.frame, ga)
        })
        .await
        .is_some()
    };

    Ok(WriteOutcome {
        receipt,
        confirmed,
        source,
    })
}

/// Whether a frame targets group address `ga`.
fn is_group(frame: &CemiFrame, ga: GroupAddress) -> bool {
    matches!(frame.destination, Destination::Group(g) if g == ga)
}

/// Extracts the group APDU payload octets, if any.
fn group_payload(apdu: &Apdu) -> Vec<u8> {
    match apdu {
        Apdu::GroupValueResponse(d) | Apdu::GroupValueWrite(d) => d.bytes(),
        _ => Vec::new(),
    }
}
