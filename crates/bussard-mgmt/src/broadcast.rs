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
