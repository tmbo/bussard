//! How a device answers a management frame it refused (bussard issue #869).
//!
//! [`Device::handle_cemi`] reports a refusal as a [`DeviceError`]; the bus
//! logs it as `REJECTED by …` and asks [`Device::refusal_answer`] what the
//! device puts on the wire. Before #869 the answer was always silence, so ETS
//! repeated the frame and reported a dead device instead of a refusal.
//!
//! Two layers answer independently:
//!
//! - The transport layer acknowledges every numbered data frame it accepted
//!   (the open connection's peer, the expected sequence), whatever the
//!   application layer then makes of it. A refused frame is still `T_ACK`ed.
//! - The application layer answers with the service's negative response where
//!   the standard defines one, and stays silent where it says to ignore.
//!
//! The reason decides first, the service second:
//!
//! | refusal | service | answer |
//! |---|---|---|
//! | no open connection, other peer, unexpected sequence, APDU too short | any | silence (the transport layer did not accept the frame) |
//! | System 7 wire strictness | memory services | silence (the frame does not exist for a System 7 device) |
//! | KNX Data Secure (plain access to a protected service, failed `A_SecureData`) | any | `T_ACK` only: a secured answer cannot be built for a frame that did not authenticate |
//! | absent object or PID, read-only, missing access, bad value length | `A_PropertyValue_Write`, `A_PropertyValue_Read` with a whole header | `T_ACK` and the zero-count `A_PropertyValue_Response` (KNX 3/3/7 §3.4.4.1, §3.4.4.2 error handling) |
//! | any | `A_PropertyValue_Write`, `A_PropertyValue_Read` with less than the four header octets | `T_ACK` only: there is no header to echo |
//! | any | `A_Memory_Write` in verify mode, with an address | `T_ACK` and an `A_Memory_Response` with number zero (KNX 3/3/7 §3.5.4 error handling) |
//! | any | `A_Memory_Write` outside verify mode, `A_UserMemory_Write`, `A_MemoryExtended_Write` | `T_ACK` only: the indication is ignored (KNX 3/3/7 §3.5.4) |
//! | any | every other service (`A_Authorize_Request`, `A_Restart`, `A_Memory_Read` without an address, `A_PropertyDescription_Read` and the function-property services with a short header, ...) | `T_ACK` only |
//!
//! A connectionless (`T_Data_Individual`) frame has no transport
//! acknowledgement: a refused connectionless property service gets its
//! zero-count response unnumbered, everything else is silence.

use std::time::Instant;

use crate::wire::apdu::{Apci, Apdu};
use crate::wire::{CemiLData, IndividualAddress};

use super::{Device, DeviceError};

/// The application-layer part of a refusal answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Negative {
    /// The transport layer did not accept the frame: nothing at all.
    Silence,
    /// The application layer ignores the frame; only the transport layer
    /// answers.
    None,
    /// The zero-count `A_PropertyValue_Response` echoing object, PID and start.
    PropertyZeroCount,
    /// The zero-number `A_Memory_Response` echoing the address.
    MemoryZeroCount,
}

/// `A_PropertyValue_Response`.
const APCI_PROPERTY_VALUE_RESPONSE: u16 = 0x3D6;
/// `A_Memory_Response` with number zero.
const APCI_MEMORY_RESPONSE: u16 = 0x240;

impl Device {
    /// The frames the device sends for `cemi`, which [`Device::handle_cemi`]
    /// refused with `err`. The table in the module documentation lists the
    /// answer per refusal and service. A numbered negative response waits for
    /// its `T_ACK` like any other response; the bus puts the transport `T_ACK`
    /// of the request in front of it.
    pub fn refusal_answer(&mut self, cemi: &CemiLData, err: &DeviceError) -> Vec<CemiLData> {
        self.refusal_answer_at(cemi, err, Instant::now())
    }

    /// [`refusal_answer`](Self::refusal_answer) at the instant `now`, which
    /// the transport timers measure against.
    pub fn refusal_answer_at(
        &mut self,
        cemi: &CemiLData,
        err: &DeviceError,
        now: Instant,
    ) -> Vec<CemiLData> {
        let unnumbered = cemi.tpdu.first().is_some_and(|b| b & 0xC0 == 0x00);
        let accepted = self.accepted_numbered_seq(cemi);
        if accepted.is_none() && !unnumbered {
            return Vec::new();
        }
        let Some(apdu) = Apdu::parse(&cemi.tpdu) else {
            return accepted.map_or_else(Vec::new, |seq| vec![self.t_ack(cemi.source, seq)]);
        };
        let negative = self.negative_for(&apdu, err);
        let tool = cemi.source;
        match accepted {
            Some(seq) => {
                let answer = self.negative_frame(tool, &apdu, negative);
                match answer {
                    Some(frame) => {
                        let responses = vec![frame];
                        self.await_ack(&responses, now);
                        responses
                    }
                    None if negative == Negative::Silence => Vec::new(),
                    None => vec![self.t_ack(tool, seq)],
                }
            }
            // Connectionless: only the property services answer, unnumbered.
            None if negative == Negative::PropertyZeroCount && !self.connected => {
                let saved = self.tx_seq;
                let frame = self.negative_frame(tool, &apdu, negative);
                self.tx_seq = saved;
                frame
                    .map(|mut f| {
                        if let Some(first) = f.tpdu.first_mut() {
                            *first &= 0x03;
                        }
                        f
                    })
                    .into_iter()
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// The application-layer answer to `apdu` refused with `err`: the reason
    /// first, the service second (module documentation).
    fn negative_for(&self, apdu: &Apdu, err: &DeviceError) -> Negative {
        match err {
            DeviceError::NotConnected | DeviceError::WireStrictness { .. } => Negative::Silence,
            DeviceError::Secure(_) => Negative::None,
            DeviceError::NoProperty { .. }
            | DeviceError::ReadOnlyProperty { .. }
            | DeviceError::Unauthorized { .. }
            | DeviceError::LoadControl(_)
            | DeviceError::Memory(_)
            | DeviceError::Malformed { .. } => match apdu.apci {
                Apci::PropertyValueWrite | Apci::PropertyValueRead if apdu.data.len() >= 4 => {
                    Negative::PropertyZeroCount
                }
                Apci::MemoryWrite(_) if apdu.data.len() >= 2 && self.verify_mode() => {
                    Negative::MemoryZeroCount
                }
                _ => Negative::None,
            },
        }
    }

    /// The negative response frame for `negative`, `None` when it has none.
    fn negative_frame(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
        negative: Negative,
    ) -> Option<CemiLData> {
        match negative {
            Negative::PropertyZeroCount => {
                // Echo object, PID and start index with nr_of_elem zero and no
                // data (KNX 3/3/7 §3.4.4.2 error handling).
                let data = [
                    apdu.data[0],
                    apdu.data[1],
                    apdu.data[2] & 0x0F,
                    apdu.data[3],
                ];
                Some(self.respond(tool, APCI_PROPERTY_VALUE_RESPONSE, &data))
            }
            Negative::MemoryZeroCount => {
                // Number zero, the address echoed, no data (KNX 3/3/7 §3.5.4
                // error handling, verify mode).
                let data = [apdu.data[0], apdu.data[1]];
                Some(self.respond(tool, APCI_MEMORY_RESPONSE, &data))
            }
            Negative::Silence | Negative::None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::device::test_support::*;
    use crate::device::*;

    /// Connect and authorize a fixture-free System B device.
    fn authorized() -> Result<Device, Box<dyn std::error::Error>> {
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        Ok(dev)
    }

    #[test]
    fn test_refusal_answer_read_only_property_write_is_zero_count()
    -> Result<(), Box<dyn std::error::Error>> {
        // PID_OBJECT_TYPE of the device object is read-only.
        let mut dev = authorized()?;
        let frame = data(&dev, 0x3D7, &[0x00, 0x01, 0x10, 0x01, 0x00, 0x00]);
        let Err(err) = dev.handle_cemi(&frame) else {
            return Err("the write was accepted".into());
        };
        assert_eq!(err, DeviceError::ReadOnlyProperty { object: 0, pid: 1 });
        let out = dev.refusal_answer(&frame, &err);
        assert_eq!(out.len(), 1, "{out:?}");
        // A numbered A_PropertyValue_Response under the device's sequence 1
        // (the authorize answer took 0): nr_of_elem 0, no data.
        assert_eq!(out[0].tpdu, vec![0x47, 0xd6, 0x00, 0x01, 0x00, 0x01]);
        Ok(())
    }

    #[test]
    fn test_refusal_answer_memory_write_in_verify_mode_is_zero_number()
    -> Result<(), Box<dyn std::error::Error>> {
        // KNX 3/3/7 §3.5.4: in verify mode a failed write answers with number
        // zero; outside it only the T_ACK.
        // PID_DEVICE_CONTROL (14) bit 2 is verify mode; this device starts
        // with it set, so clear it first.
        let mut dev = authorized()?;
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x00, 0x0E, 0x10, 0x01, 0x00]))?;
        let frame = data(&dev, 0x281, &[0x40, 0x00, 0xAA]);
        let Err(err) = dev.handle_cemi(&frame) else {
            return Err("the write was accepted".into());
        };
        let out = dev.refusal_answer(&frame, &err);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].tpdu, vec![Tpci::ack_byte(2)], "T_ACK only");
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x00, 0x0E, 0x10, 0x01, 0x04]))?;
        let frame = data(&dev, 0x281, &[0x40, 0x00, 0xAA]);
        let Err(err) = dev.handle_cemi(&frame) else {
            return Err("the write was accepted".into());
        };
        let out = dev.refusal_answer(&frame, &err);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            out[0].tpdu[1..],
            [0x40, 0x40, 0x00],
            "number 0, address echoed"
        );
        Ok(())
    }

    #[test]
    fn test_refusal_answer_unaccepted_sequence_is_silent() -> Result<(), Box<dyn std::error::Error>>
    {
        // A refusal the transport layer did not accept (not the sequence the
        // device just took) draws nothing.
        let mut dev = authorized()?;
        let frame = data_seq(&dev, 9, 0x3D7, &[0x08, 0x05, 0x10, 0x01]);
        let err = DeviceError::NoProperty { object: 8, pid: 5 };
        assert!(dev.refusal_answer(&frame, &err).is_empty());
        Ok(())
    }
}
