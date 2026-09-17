//! The virtual bus: routes cEMI telegrams to devices and publishes the
//! observable event stream.

pub mod event;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::device::Device;
use crate::wire::{Apci, CemiLData, GroupAddress, IndividualAddress, Tpci};
use event::{Direction, Event, EventSink};

/// The virtual bus. Holds every device by its individual address and dispatches
/// management (connection-oriented / individually-addressed) telegrams to the
/// addressed device. Group telegrams are broadcast (stubbed for Phase 1).
pub struct Bus {
    devices: BTreeMap<IndividualAddress, Device>,
    /// The scripted stimulus schedule (empty for a quiet bus).
    stimulus: Vec<StimulusJob>,
    events: Arc<dyn EventSink>,
}

impl Bus {
    /// Create an empty bus that publishes to `events`.
    pub fn new(events: Arc<dyn EventSink>) -> Self {
        Self {
            devices: BTreeMap::new(),
            stimulus: Vec::new(),
            events,
        }
    }

    /// Add a device to the bus.
    pub fn add_device(&mut self, device: Device) {
        self.devices.insert(device.address(), device);
    }

    /// Number of devices on the bus.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Borrow a device by address (for tests/observability).
    pub fn device(&self, address: IndividualAddress) -> Option<&Device> {
        self.devices.get(&address)
    }

    /// Deliver an inbound telegram from the tool. Returns the response telegrams
    /// the addressed device produced (already framed as `L_Data.ind`). Every
    /// telegram in both directions is published on the event stream.
    pub fn deliver_from_tool(&mut self, cemi: &CemiLData) -> Vec<CemiLData> {
        self.events.emit(Event::Telegram {
            direction: Direction::ToBus,
            cemi: cemi.encode(),
            summary: summarize(cemi),
        });

        if cemi.is_group() {
            return self.deliver_group(cemi);
        }

        let dest = cemi.dest_individual();
        let responses = match self.devices.get_mut(&dest) {
            Some(dev) => match dev.handle_cemi(cemi) {
                Ok(reaction) => reaction.responses,
                Err(err) => {
                    // A strict device rejects by not responding; surface the
                    // reason on the event stream for the observer.
                    self.events.emit(Event::Telegram {
                        direction: Direction::ToBus,
                        cemi: cemi.encode(),
                        summary: format!("REJECTED by {dest}: {err}"),
                    });
                    Vec::new()
                }
            },
            None => Vec::new(),
        };

        for r in &responses {
            self.events.emit(Event::Telegram {
                direction: Direction::ToTool,
                cemi: r.encode(),
                summary: summarize(r),
            });
        }
        responses
    }

    /// Deliver a group telegram: broadcast it to every device on the bus and
    /// collect any group telegrams the devices produce in reply (e.g. an
    /// `A_GroupValue_Response` from a device that holds the Read flag).
    ///
    /// A group telegram is seen by all devices, not just an addressed one — the
    /// defining property of a shared bus. Every reply is itself a bus telegram,
    /// so it is fed back to the other devices (they update their listeners) and
    /// returned to the tunnel client. Emits each reply on the event stream.
    fn deliver_group(&mut self, cemi: &CemiLData) -> Vec<CemiLData> {
        let Some((apci, ga, payload)) = decode_group(cemi) else {
            return Vec::new();
        };
        // The source device (if the telegram came from a device, not the tool)
        // must not react to its own transmission.
        let origin = cemi.source;
        let mut replies = Vec::new();
        for (addr, dev) in self.devices.iter_mut() {
            if *addr == origin {
                continue;
            }
            replies.extend(dev.handle_group(apci, ga, &payload));
        }
        // Fan replies back onto the bus (devices see each other's responses) and
        // out to the tool. A response updates listeners but should not itself
        // trigger further responses (it is not a read), so one pass suffices.
        let mut out = Vec::new();
        for reply in replies {
            self.events.emit(Event::Telegram {
                direction: Direction::ToTool,
                cemi: reply.encode(),
                summary: summarize(&reply),
            });
            if let Some((r_apci, r_ga, r_payload)) = decode_group(&reply) {
                let r_origin = reply.source;
                for (addr, dev) in self.devices.iter_mut() {
                    if *addr == r_origin {
                        continue;
                    }
                    // Only writes/responses update listeners; ignore any further
                    // responses to avoid a reply storm.
                    let _ = dev.handle_group(response_as_write(r_apci), r_ga, &r_payload);
                }
            }
            out.push(reply);
        }
        out
    }

    /// Broadcast a device-originated group telegram (e.g. scripted stimulus) onto
    /// the bus: deliver it to every other device (listeners update) and return it
    /// for the tunnel client. Emits it on the event stream in both directions.
    pub fn inject_from_device(&mut self, cemi: &CemiLData) -> Vec<CemiLData> {
        self.events.emit(Event::Telegram {
            direction: Direction::ToTool,
            cemi: cemi.encode(),
            summary: summarize(cemi),
        });
        if let Some((apci, ga, payload)) = decode_group(cemi) {
            let origin = cemi.source;
            for (addr, dev) in self.devices.iter_mut() {
                if *addr == origin {
                    continue;
                }
                let _ = dev.handle_group(response_as_write(apci), ga, &payload);
            }
        }
        vec![cemi.clone()]
    }

    /// Drive every configured stimulus that is due, returning the telegrams to
    /// forward to the tunnel client. `now_ms` is a monotonic millisecond clock.
    /// Each due stimulus makes its device transmit the next value in its cycle;
    /// a device that is not yet loaded/linked simply produces nothing.
    pub fn tick_stimulus(&mut self, now_ms: u128) -> Vec<CemiLData> {
        let mut out = Vec::new();
        // Take the schedule out to avoid borrowing self while mutating devices.
        let mut schedule = std::mem::take(&mut self.stimulus);
        for s in &mut schedule {
            if now_ms < s.next_due_ms {
                continue;
            }
            s.next_due_ms = now_ms + s.period_ms;
            let payload = s.values[s.cursor % s.values.len()].clone();
            s.cursor = s.cursor.wrapping_add(1);
            if let Some(dev) = self.devices.get_mut(&s.device) {
                if let Some(cemi) = dev.emit_stimulus(s.object, &payload) {
                    out.extend(self.inject_from_device(&cemi));
                }
            }
        }
        self.stimulus = schedule;
        out
    }

    /// Register the scripted stimulus schedule (from the installation config).
    pub fn set_stimulus(&mut self, stimulus: Vec<StimulusJob>) {
        self.stimulus = stimulus;
    }

    /// The earliest time (ms) at which any stimulus is next due, for scheduling a
    /// wakeup. `None` when there is no stimulus.
    pub fn next_stimulus_due_ms(&self) -> Option<u128> {
        self.stimulus.iter().map(|s| s.next_due_ms).min()
    }
}

/// A prepared stimulus job: a device transmits `values` (already encoded to
/// group-data octets) on `object` every `period_ms`, cycling through the list.
#[derive(Debug, Clone)]
pub struct StimulusJob {
    /// The transmitting device's address.
    pub device: IndividualAddress,
    /// The com-object number that transmits.
    pub object: u16,
    /// The period between transmits, in milliseconds.
    pub period_ms: u128,
    /// The pre-encoded payloads to cycle through.
    pub values: Vec<Vec<u8>>,
    /// The next due time (ms). Seed to the first fire time.
    pub next_due_ms: u128,
    /// The index of the next value to send.
    pub cursor: usize,
}

/// Map a group service to the "listener-updating" service: a `_Response` updates
/// listeners just like a `_Write` does, while a `_Read` never updates a value.
fn response_as_write(apci: Apci) -> Apci {
    match apci {
        Apci::GroupValueResponse => Apci::GroupValueWrite,
        other => other,
    }
}

/// Decode a group telegram into `(service, group address, payload octets)`.
///
/// Handles both the "small" packed APDU form (a sub-byte value in the APCI low
/// bits, NPDU length 1) and the "large" form (value in trailing octets).
/// Returns `None` for non-group services or malformed frames.
fn decode_group(cemi: &CemiLData) -> Option<(Apci, GroupAddress, Vec<u8>)> {
    if !cemi.is_group() || cemi.tpdu.len() < 2 {
        return None;
    }
    let apci10 = ((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16;
    let apci = Apci::from_u10(apci10);
    let payload = match apci {
        Apci::GroupValueRead => Vec::new(),
        Apci::GroupValueWrite | Apci::GroupValueResponse => {
            if cemi.tpdu.len() > 2 {
                // Large form: the value is in the trailing octets.
                cemi.tpdu[2..].to_vec()
            } else {
                // Small form: the value is packed into the APCI low 6 bits.
                vec![(apci10 & 0x3F) as u8]
            }
        }
        _ => return None,
    };
    Some((apci, cemi.dest_group(), payload))
}

/// A short human summary of a telegram for the event log.
fn summarize(cemi: &CemiLData) -> String {
    let src = cemi.source;
    let dst = if cemi.is_group() {
        cemi.dest_group().to_string()
    } else {
        cemi.dest_individual().to_string()
    };
    if cemi.tpdu.is_empty() {
        return format!("{src}->{dst} (empty)");
    }
    let ctl = match Tpci::from_byte(cemi.tpdu[0]) {
        Tpci::Connect => "T_Connect".to_string(),
        Tpci::Disconnect => "T_Disconnect".to_string(),
        Tpci::Ack(s) => format!("T_ACK({s})"),
        Tpci::Nak(s) => format!("T_NAK({s})"),
        Tpci::DataUnnumbered | Tpci::DataConnected(_) => {
            match crate::wire::apdu::Apdu::parse(&cemi.tpdu) {
                Some(a) => format!("{:?}", a.apci),
                None => "data".to_string(),
            }
        }
    };
    format!("{src}->{dst} {ctl} [{}]", hex(&cemi.tpdu))
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::event::RecordingSink;
    use crate::device::LoadState;
    use crate::prod::read_knxprod_bytes;
    use crate::wire::MessageCode;

    #[test]
    fn test_bus_dispatches_and_records() -> Result<(), Box<dyn std::error::Error>> {
        let Some(fixture) = crate::testfixtures::da_tp_knxprod() else {
            eprintln!("SKIP: DA.tp fixture not present");
            return Ok(());
        };
        let sink = Arc::new(RecordingSink::new());
        let pd = read_knxprod_bytes(&fixture, None)?;
        let dev = Device::from_product(
            IndividualAddress::new(1, 1, 2),
            &pd,
            LoadState::Loaded,
            sink.clone(),
        );
        let mut bus = Bus::new(sink.clone());
        bus.add_device(dev);
        // T_Connect then Authorize
        let connect = CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress::new(0, 0, 0),
            dest: IndividualAddress::new(1, 1, 2).raw(),
            tpdu: vec![0x80],
        };
        bus.deliver_from_tool(&connect);
        // A_Authorize_Request (APCI 0x3D1): TPCI 0x40 must carry the top two
        // APCI bits, so the byte is 0x40 | ((0x3D1 >> 8) & 3) = 0x43.
        let auth = CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: IndividualAddress::new(0, 0, 0),
            dest: IndividualAddress::new(1, 1, 2).raw(),
            tpdu: vec![0x43, 0xd1, 0x00, 0xff, 0xff, 0xff, 0xff],
        };
        let resp = bus.deliver_from_tool(&auth);
        assert_eq!(resp.len(), 1, "authorize should produce a response");
        assert!(!sink.events().is_empty());
        Ok(())
    }
}
