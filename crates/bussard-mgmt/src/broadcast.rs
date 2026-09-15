//! Connectionless broadcast management helpers.
//!
//! These use `T_Data_Broadcast` (unnumbered, to the broadcast group `0/0/0`)
//! rather than a connection-oriented session. They are groundwork for
//! `bussard assign` (#22); the frame plumbing is identical to the rest of the
//! management layer, so they live here.

use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_transport::BusConnection;
use bussard_transport::cemi::CemiFrame;
use tokio::time::{Instant, timeout};

use crate::apci;
use crate::error::Result;

/// How long to collect `A_IndividualAddress_Response` telegrams after the
/// broadcast read. A device in programming mode answers quickly; this window is
/// generous enough to catch a single expected responder.
pub const PROGRAMMING_MODE_WINDOW: Duration = Duration::from_millis(1500);

/// Broadcasts `A_IndividualAddress_Read` and collects the individual addresses
/// of every device currently in programming mode.
///
/// Each device in programming mode answers with an
/// `A_IndividualAddress_Response` whose **source** is its own individual
/// address; there is no payload. Returns the responders (deduplicated, in the
/// order first seen). Normally there is exactly zero or one — pressing the
/// programming button on two devices at once is a user error this surfaces.
pub async fn devices_in_programming_mode<C: BusConnection>(
    bus: &mut C,
    source: IndividualAddress,
) -> Result<Vec<IndividualAddress>> {
    let request = CemiFrame::t_broadcast(source, apci::A_INDIVIDUAL_ADDRESS_READ, &[]);
    bus.send(request).await?;

    let mut found: Vec<IndividualAddress> = Vec::new();
    let deadline = Instant::now() + PROGRAMMING_MODE_WINDOW;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let stamped = match timeout(remaining, bus.recv()).await {
            Ok(Ok(stamped)) => stamped,
            Ok(Err(_)) => break,
            Err(_elapsed) => break,
        };
        let frame = stamped.frame;
        if is_individual_address_response(&frame) {
            let addr = frame.source;
            if !found.contains(&addr) {
                found.push(addr);
            }
        }
    }
    Ok(found)
}

/// Whether a frame is an `A_IndividualAddress_Response`.
fn is_individual_address_response(frame: &CemiFrame) -> bool {
    use bussard_transport::cemi::Apdu;
    matches!(
        &frame.apdu,
        Apdu::Other { apci, .. } if *apci == apci::A_INDIVIDUAL_ADDRESS_RESPONSE
    )
}

/// Broadcasts `A_IndividualAddress_Write`, setting the individual address of
/// the device **currently in programming mode** to `new_address`.
///
/// The payload is the 2-byte raw new address. Only a device in programming mode
/// applies it; every other device ignores the broadcast. The KNX standard
/// defines **no response** for this service, so this returns as soon as the
/// telegram is sent — the caller must verify the change separately (open a
/// connection to `new_address` and read the device descriptor). Sending this
/// while more than one device is in programming mode would address them all
/// identically, so callers must ensure exactly one responder first.
pub async fn write_individual_address<C: BusConnection>(
    bus: &mut C,
    source: IndividualAddress,
    new_address: IndividualAddress,
) -> Result<()> {
    let payload = new_address.raw().to_be_bytes();
    let frame = CemiFrame::t_broadcast(source, apci::A_INDIVIDUAL_ADDRESS_WRITE, &payload);
    bus.send(frame).await?;
    Ok(())
}

/// Broadcasts `A_IndividualAddressSerialNumber_Read` for `serial` and returns
/// the individual address the matching device reports, or `None` if no device
/// with that serial answers within [`PROGRAMMING_MODE_WINDOW`].
///
/// Unlike the programming-mode read, this targets one specific device by its
/// 6-byte KNX serial number, so **no button press is required**. The answering
/// device's address is the frame source of its
/// `A_IndividualAddressSerialNumber_Response`.
pub async fn read_individual_address_by_serial<C: BusConnection>(
    bus: &mut C,
    source: IndividualAddress,
    serial: [u8; 6],
) -> Result<Option<IndividualAddress>> {
    let frame = CemiFrame::t_broadcast(source, apci::A_INDIVIDUAL_ADDRESS_SERIAL_READ, &serial);
    bus.send(frame).await?;

    let deadline = Instant::now() + PROGRAMMING_MODE_WINDOW;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let stamped = match timeout(remaining, bus.recv()).await {
            Ok(Ok(stamped)) => stamped,
            Ok(Err(_)) => break,
            Err(_elapsed) => break,
        };
        if is_serial_response_for(&stamped.frame, &serial) {
            return Ok(Some(stamped.frame.source));
        }
    }
    Ok(None)
}

/// Broadcasts `A_IndividualAddressSerialNumber_Write`, setting the individual
/// address of the device with serial number `serial` to `new_address` — no
/// programming-button press needed.
///
/// The payload is the 6-byte serial number, the 2-byte new address, then 4
/// reserved zero octets (the field the standard reserves for a domain address).
/// Like [`write_individual_address`], this service defines no response, so the
/// caller must verify separately.
pub async fn write_individual_address_by_serial<C: BusConnection>(
    bus: &mut C,
    source: IndividualAddress,
    serial: [u8; 6],
    new_address: IndividualAddress,
) -> Result<()> {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&serial);
    payload.extend_from_slice(&new_address.raw().to_be_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    let frame = CemiFrame::t_broadcast(source, apci::A_INDIVIDUAL_ADDRESS_SERIAL_WRITE, &payload);
    bus.send(frame).await?;
    Ok(())
}

/// Whether a frame is an `A_IndividualAddressSerialNumber_Response` whose echoed
/// serial number matches `serial`.
fn is_serial_response_for(frame: &CemiFrame, serial: &[u8; 6]) -> bool {
    use bussard_transport::cemi::Apdu;
    matches!(
        &frame.apdu,
        Apdu::Other { apci, data }
            if *apci == apci::A_INDIVIDUAL_ADDRESS_SERIAL_RESPONSE
                && data.len() >= 6
                && &data[..6] == serial
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_individual_address_response() {
        let frame = CemiFrame::t_broadcast(
            "1.1.4".parse().unwrap(),
            apci::A_INDIVIDUAL_ADDRESS_RESPONSE,
            &[],
        );
        assert!(is_individual_address_response(&frame));

        let other = CemiFrame::t_broadcast(
            "1.1.4".parse().unwrap(),
            apci::A_INDIVIDUAL_ADDRESS_READ,
            &[],
        );
        assert!(!is_individual_address_response(&other));
    }
}
