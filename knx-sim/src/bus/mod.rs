//! The virtual bus: routes cEMI telegrams to devices and publishes the
//! observable event stream.

pub mod event;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::device::Device;
use crate::wire::{CemiLData, IndividualAddress, Tpci};
use event::{Direction, Event, EventSink};

/// The virtual bus. Holds every device by its individual address and dispatches
/// management (connection-oriented / individually-addressed) telegrams to the
/// addressed device. Group telegrams are broadcast (stubbed for Phase 1).
pub struct Bus {
    devices: BTreeMap<IndividualAddress, Device>,
    events: Arc<dyn EventSink>,
}

impl Bus {
    /// Create an empty bus that publishes to `events`.
    pub fn new(events: Arc<dyn EventSink>) -> Self {
        Self {
            devices: BTreeMap::new(),
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
            // Group broadcast is stubbed: no runtime group behavior in Phase 1.
            return Vec::new();
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
