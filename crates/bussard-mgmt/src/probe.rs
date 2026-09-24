//! The pre-flight **source address** probe: is the individual address bussard is
//! about to speak from already taken by a device on the bus?
//!
//! # Why this exists
//!
//! A KNX device tells its management clients apart by **source individual
//! address only**. There is no session id, no nonce, no port number. If a real
//! device (or a second tool) answers at the address bussard presents as its
//! source, the numbered telegrams of both parties land inside the *same* layer-4
//! session at the device: sequence numbers interleave, and a memory write meant
//! for one session can be applied on behalf of the other while both sides still
//! see a `T_ACK`. That is silent configuration corruption, not a loud failure.
//!
//! ETS performs this exact check before it uses an interface. bussard runs it
//! from [`crate::probe::probe_own_address`] before any connection-oriented device
//! operation.
//!
//! # What is actually probed
//!
//! A layer-4 session is opened **to** our own address **from** our own address
//! and a single `A_DeviceDescriptor_Read` is sent. Only a genuine
//! `A_DeviceDescriptor_Response` carrying a mask version counts as
//! [`AddressProbe::Occupied`]. Everything else — silence, a `T_Disconnect`, a
//! NAK, or any non-response APDU — is [`AddressProbe::Free`].
//!
//! ## The echo case (why only a *Response* may count)
//!
//! Some gateways do not put a frame addressed to one of their own tunnel
//! individual addresses on TP1 at all: they loop it straight back down the
//! tunnel. The `L_Data.con` confirmation of our own send has the same shape. In
//! both cases we receive **our own** frames with `source == destination == our
//! address`, which is exactly the address pair the layer-4 state machine accepts
//! as "from my peer, to me". So the probe sees:
//!
//! * our own `T_Connect` — classified as a transport-control connect, which the
//!   state machine ignores in both its ACK wait and its response wait; and
//! * our own numbered `A_DeviceDescriptor_**Read**` — which the state machine
//!   acknowledges and hands back as if it were the answer.
//!
//! Treating that second frame as evidence of a device would make the probe fire
//! on every gateway that loops back, so the classification below accepts a
//! *Response* selector and nothing else, and keeps waiting after an echo until a
//! real response arrives or the budget runs out.

use bussard_bus::BusHandle;
use bussard_model::IndividualAddress;

use crate::apci;
use crate::connection::{L4Channel, Layer4Connection, LeaseChannel, Timeouts, map_bus_error};
use crate::error::{MgmtError, Result};

/// The outcome of a source-address probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressProbe {
    /// Nothing on the bus answered at the address: it is safe to use as a
    /// management source.
    Free,
    /// A device answered with a device descriptor: the address is in use on the
    /// bus and must not be used as a management source.
    Occupied {
        /// The mask version (device descriptor type 0) the responder reported.
        mask: u16,
    },
}

/// How many inbound APDUs to look at before giving up on a real response.
///
/// Each iteration costs at most one `response_timeout`. The bound exists so a
/// gateway that echoes a burst of our own frames cannot hold the probe open
/// indefinitely; two or three echoes is already more than any observed gateway
/// produces.
const MAX_INBOUND_APDUS: usize = 4;

/// Environment variable that overrides the per-attempt source-address probe
/// timeout in milliseconds. Set by the integration tests to keep the mock runs
/// fast; unset in normal use, where [`crate::PROBE_TIMEOUT`] applies.
pub const ADDRESS_PROBE_MS_ENV: &str = "BUSSARD_ADDRESS_PROBE_MS";

/// The source-address probe budget, honouring [`ADDRESS_PROBE_MS_ENV`] when set.
pub fn probe_timeouts_from_env() -> Timeouts {
    match std::env::var(ADDRESS_PROBE_MS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(ms) => Timeouts {
            ack_timeout: std::time::Duration::from_millis(ms),
            max_repetitions: 0,
            response_timeout: std::time::Duration::from_millis(ms),
            absent_on_negative_confirmation: false,
        },
        None => Timeouts::probe(),
    }
}

/// Why [`checked_source`] refused to hand out a source address.
#[derive(Debug, thiserror::Error)]
pub enum SourceCheckError {
    /// The probe itself failed on the transport (the bus actor is gone).
    #[error("probing whether a device answers at our source address {address}")]
    Probe {
        /// The source address that was being probed.
        address: IndividualAddress,
        /// The transport failure.
        #[source]
        error: MgmtError,
    },
    /// A device on the bus already answers at our source address.
    #[error(
        "refusing to continue: a device on the bus (mask {mask:04X}) already answers at \
         {address}, the individual address this connection would use as its source. Sharing a \
         source address with a live device can silently corrupt device downloads. Fix the \
         gateway's tunnel address assignment, or pass --skip-address-check if you are sure."
    )]
    Occupied {
        /// Our source address.
        address: IndividualAddress,
        /// The mask version the occupant reported.
        mask: u16,
    },
}

/// The source individual address for a **connection-oriented** device
/// operation, checked against the bus first.
///
/// Resolves the source exactly as [`bussard_bus::ops::group_source`] does (the
/// tunnel-assigned individual address, or the `0.0.255` fallback on routing),
/// then, unless `skip` is set, probes the bus for a device answering at that
/// very address and refuses if one does. The budget is
/// [`probe_timeouts_from_env`]. Shared by every CLI device command and the MCP
/// programming tier, so both refuse on the same evidence.
pub async fn checked_source(
    handle: &BusHandle,
    skip: bool,
) -> std::result::Result<IndividualAddress, SourceCheckError> {
    let source = bussard_bus::ops::group_source(handle);
    if skip {
        tracing::debug!(%source, "source-address check skipped");
        return Ok(source);
    }
    let probe = probe_own_address(handle, source, probe_timeouts_from_env())
        .await
        .map_err(|error| SourceCheckError::Probe {
            address: source,
            error,
        })?;
    match probe {
        AddressProbe::Free => {
            tracing::debug!(%source, "source-address check passed: no device answers there");
            Ok(source)
        }
        AddressProbe::Occupied { mask } => Err(SourceCheckError::Occupied {
            address: source,
            mask,
        }),
    }
}

/// Probes whether a device on the bus answers at `address` — the address this
/// tool is about to use as its own management **source**.
///
/// Leases the bus (the exclusive layer-4 slot), opens a connection-oriented
/// session to `address` presenting `address` as the source, sends one
/// `A_DeviceDescriptor_Read`, and classifies the reaction; the session is torn
/// down (with a `T_Disconnect` whenever a peer answered) and the lease released
/// before returning.
///
/// Use a tight, single-attempt budget such as [`Timeouts::probe`]: on a free
/// address the whole probe costs one `ack_timeout`.
///
/// Only a real transport failure (the bus actor is gone, the socket died on the
/// way out) returns `Err`. A device that is absent, refusing, disconnecting or
/// echoing is [`AddressProbe::Free`].
pub async fn probe_own_address(
    handle: &BusHandle,
    address: IndividualAddress,
    timeouts: Timeouts,
) -> Result<AddressProbe> {
    let lease = handle.lease().await.map_err(map_bus_error)?;
    probe_own_address_on(LeaseChannel::new(lease), address, timeouts).await
}

/// The channel-level probe behind [`probe_own_address`], for callers that
/// already hold a frame channel (and for the unit tests, which drive a scripted
/// one).
///
/// `address` is used as **both** the target and the source, which is the whole
/// point: it asks "does anyone else answer where I am about to speak from?".
pub async fn probe_own_address_on<Ch: L4Channel>(
    conn: Ch,
    address: IndividualAddress,
    timeouts: Timeouts,
) -> Result<AddressProbe> {
    let mut l4 = Layer4Connection::connect_with(conn, address, address, timeouts).await?;
    let outcome = classify(&mut l4).await;
    // Leave the slot clean: when a peer actually answered, this puts a
    // `T_Disconnect` on the bus so the device does not hold the session open. A
    // session that already timed out or was torn down is closed locally and
    // sends nothing (there is nobody to tell), which is the state machine's
    // standing behaviour for every other procedure.
    let _ = l4.disconnect().await;
    outcome
}

/// Sends the descriptor read and classifies what comes back.
async fn classify<Ch: L4Channel>(l4: &mut Layer4Connection<Ch>) -> Result<AddressProbe> {
    let (req_apci, payload) = apci::encode_device_descriptor_read(0);
    match l4.send_data(req_apci, &payload).await {
        Ok(()) => {}
        // Nothing acknowledged our telegram (or the peer tore the link down, or
        // NAKed it): no device is answering here.
        Err(err) if is_device_silence(&err) => return Ok(AddressProbe::Free),
        Err(err) => return Err(err),
    }

    for _ in 0..MAX_INBOUND_APDUS {
        match l4.recv_response().await {
            Ok((apci, data))
                if apci & apci::APCI_SELECTOR_MASK == apci::A_DEVICE_DESCRIPTOR_RESPONSE
                    && data.len() >= 2 =>
            {
                return Ok(AddressProbe::Occupied {
                    mask: u16::from_be_bytes([data[0], data[1]]),
                });
            }
            // Anything else is not a device descriptor answer: most often the
            // gateway's loop-back of our own `A_DeviceDescriptor_Read`. Keep
            // waiting for a genuine response rather than concluding either way.
            Ok(_) => continue,
            Err(err) if is_device_silence(&err) => return Ok(AddressProbe::Free),
            Err(err) => return Err(err),
        }
    }
    Ok(AddressProbe::Free)
}

/// Whether an error means "no device is answering here" rather than "the bus
/// itself failed".
///
/// A NAK and a malformed answer are folded in deliberately: the probe's contract
/// is that only a well-formed device descriptor response proves occupancy, so
/// every other device-level reaction is reported as free.
fn is_device_silence(err: &MgmtError) -> bool {
    matches!(
        err,
        MgmtError::NoResponse { .. }
            | MgmtError::NotConfirmed { .. }
            | MgmtError::Disconnected { .. }
            | MgmtError::MidSessionSilence { .. }
            | MgmtError::Nak { .. }
            | MgmtError::MalformedResponse { .. }
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::{Duration, SystemTime};

    use bussard_transport::TimestampedFrame;
    use bussard_transport::cemi::CemiFrame;
    use bussard_transport::tpci;

    use super::*;

    /// A scripted [`L4Channel`]: hands back a pre-queued list of inbound frames
    /// and blocks forever once it is exhausted, so the timeout paths fire
    /// deterministically under a tiny [`Timeouts`] budget.
    struct ScriptedChannel {
        sent: Vec<CemiFrame>,
        inbox: VecDeque<CemiFrame>,
    }

    impl ScriptedChannel {
        fn new(inbox: Vec<CemiFrame>) -> Self {
            ScriptedChannel {
                sent: Vec::new(),
                inbox: inbox.into(),
            }
        }
    }

    impl L4Channel for &mut ScriptedChannel {
        async fn send(&mut self, frame: CemiFrame) -> Result<()> {
            self.sent.push(frame);
            Ok(())
        }

        async fn recv(&mut self) -> Result<TimestampedFrame> {
            match self.inbox.pop_front() {
                Some(frame) => Ok(TimestampedFrame {
                    received_at: SystemTime::now(),
                    frame,
                }),
                None => std::future::pending().await,
            }
        }
    }

    fn ours() -> IndividualAddress {
        "1.1.255".parse().expect("valid address")
    }

    fn fast() -> Timeouts {
        Timeouts {
            ack_timeout: Duration::from_millis(40),
            max_repetitions: 0,
            response_timeout: Duration::from_millis(40),
            absent_on_negative_confirmation: false,
        }
    }

    /// An inbound transport-control frame. During this probe the peer address
    /// and our own address are the same, so a device's frame and the gateway's
    /// loop-back of our own frame are **indistinguishable** by address: only the
    /// APCI tells them apart.
    fn inbound_control(octet: u8) -> CemiFrame {
        CemiFrame::t_control(ours(), ours(), octet)
    }

    /// An inbound numbered data telegram — see [`inbound_control`] on why the
    /// addresses cannot say whether it is a device or our own echo.
    fn inbound_ndt(seq: u8, apci: u16, data: &[u8]) -> CemiFrame {
        CemiFrame::t_data_connected(ours(), ours(), tpci::ndt(seq), apci, data)
    }

    #[tokio::test]
    async fn probe_own_address_is_free_when_nothing_answers() -> Result<()> {
        let mut bus = ScriptedChannel::new(Vec::new());
        let outcome = probe_own_address_on(&mut bus, ours(), fast()).await?;
        assert_eq!(outcome, AddressProbe::Free);
        Ok(())
    }

    #[tokio::test]
    async fn probe_own_address_is_occupied_when_a_device_answers() -> Result<()> {
        let mut bus = ScriptedChannel::new(vec![
            inbound_control(tpci::t_ack(0)),
            inbound_ndt(0, apci::A_DEVICE_DESCRIPTOR_RESPONSE, &[0x07, 0xB0]),
        ]);
        let outcome = probe_own_address_on(&mut bus, ours(), fast()).await?;
        assert_eq!(outcome, AddressProbe::Occupied { mask: 0x07B0 });
        // A device answered, so the session is torn down explicitly rather than
        // left open on the device.
        let last = bus.sent.last().expect("at least one frame was sent");
        assert_eq!(last.tpci_octet(), tpci::T_DISCONNECT);
        Ok(())
    }

    /// The gateway loop-back case: a gateway that does not put a frame for one
    /// of its own tunnel addresses on TP1 echoes our `T_Connect` and our own
    /// numbered `A_DeviceDescriptor_Read` back at us. Neither may be read as a
    /// device — the address is free.
    #[tokio::test]
    async fn probe_own_address_treats_our_own_echo_as_free() -> Result<()> {
        let (read_apci, _payload) = apci::encode_device_descriptor_read(0);
        let mut bus = ScriptedChannel::new(vec![
            // Our own T_Connect, looped back.
            inbound_control(tpci::T_CONNECT),
            // Our own numbered descriptor READ, looped back at the sequence the
            // state machine is expecting to receive on.
            inbound_ndt(0, read_apci, &[]),
        ]);
        let outcome = probe_own_address_on(&mut bus, ours(), fast()).await?;
        assert_eq!(
            outcome,
            AddressProbe::Free,
            "a looped-back Read must never be classified as a device"
        );
        // The echo was acknowledged (so a real device would not retransmit) and
        // then waited past: the read APCI alone never proves occupancy.
        assert!(
            bus.sent.iter().any(|f| f.tpci_octet() == tpci::t_ack(0)),
            "the echoed NDT must still be acknowledged"
        );
        Ok(())
    }

    /// A device that disconnects us instead of answering is not proof of a
    /// descriptor-speaking device at our address.
    #[tokio::test]
    async fn probe_own_address_treats_a_disconnect_as_free() -> Result<()> {
        let mut bus = ScriptedChannel::new(vec![inbound_control(tpci::T_DISCONNECT)]);
        let outcome = probe_own_address_on(&mut bus, ours(), fast()).await?;
        assert_eq!(outcome, AddressProbe::Free);
        Ok(())
    }

    /// The probe always speaks from the very address it is asking about.
    #[tokio::test]
    async fn probe_own_address_uses_the_address_as_its_own_source() -> Result<()> {
        let mut bus = ScriptedChannel::new(Vec::new());
        let _ = probe_own_address_on(&mut bus, ours(), fast()).await?;
        let connect = bus.sent.first().expect("a T_Connect was sent");
        assert_eq!(connect.source, ours());
        assert_eq!(connect.individual_destination(), Some(ours()));
        Ok(())
    }
}
