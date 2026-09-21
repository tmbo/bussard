//! The virtual bus: routes cEMI telegrams to devices and publishes the
//! observable event stream.

pub mod event;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::device::Device;
use crate::wire::{Apci, CemiLData, GroupAddress, IndividualAddress, MessageCode, Tpci};
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

        // A broadcast A_IndividualAddress_Read (a group frame to 0/0/0) is
        // answered by every device currently in programming mode, each with an
        // A_IndividualAddress_Response carrying its own address. This is the
        // discovery step `bussard assign` and `bussard viz --watch-prog` rely on.
        if is_individual_address_read(cemi) {
            return self.deliver_individual_address_read();
        }

        // A broadcast A_IndividualAddress_Write (a group frame to 0/0/0 carrying
        // the new 2-byte address) is adopted by the device currently in
        // programming mode. This is `bussard assign`'s write step.
        if let Some(new_address) = individual_address_write_target(cemi) {
            return self.deliver_individual_address_write(new_address);
        }

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

    /// Deliver a group telegram from the tool: echo it back to the sender as an
    /// `L_Data.con`, broadcast it to every device on the bus, and collect any
    /// group telegrams the devices produce in reply (e.g. an
    /// `A_GroupValue_Response` from a device that holds the Read flag).
    ///
    /// A group telegram is seen by all devices, not just an addressed one — the
    /// defining property of a shared bus. Every reply is itself a bus telegram,
    /// so it is fed back to the other devices (they update their listeners) and
    /// returned to the tunnel client. Emits each reply on the event stream.
    ///
    /// The leading `L_Data.con` mirrors real KNXnet/IP gateway behaviour: a
    /// tunnel client is told its own transmission went out on the bus. Without
    /// it a monitor/viz sharing that tunnel would never see the writes it sends
    /// (issue #64), because a tool does not otherwise observe its own traffic.
    fn deliver_group(&mut self, cemi: &CemiLData) -> Vec<CemiLData> {
        let Some((apci, ga, payload)) = decode_group(cemi) else {
            return Vec::new();
        };
        // Echo the tool's own transmission back as a local confirmation
        // (L_Data.con) toward the sender — a real gateway confirms every request
        // it puts on the bus, and the connected monitor/viz relies on that echo
        // to see its own group writes (issue #64). A bare GroupValueRead carries
        // no value to log and is answered by a device's Response instead, so it
        // is left unechoed to keep read semantics (and the existing tests) exact.
        let echo = match apci {
            Apci::GroupValueWrite | Apci::GroupValueResponse => {
                let echo = confirm_echo(cemi);
                self.events.emit(Event::Telegram {
                    direction: Direction::ToTool,
                    cemi: echo.encode(),
                    summary: summarize(&echo),
                });
                Some(echo)
            }
            _ => None,
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
        // The confirmation echo (when present) leads so the tool sees its own
        // write before any device reply.
        let mut out: Vec<CemiLData> = echo.into_iter().collect();
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

    /// Answer a broadcast `A_IndividualAddress_Read`: collect an
    /// `A_IndividualAddress_Response` from every device currently in programming
    /// mode, emit each toward the tool, and return them for the tunnel to
    /// forward. A device not in programming mode stays silent, so the usual case
    /// (nobody programming) returns an empty vec.
    fn deliver_individual_address_read(&mut self) -> Vec<CemiLData> {
        let mut responses = Vec::new();
        for dev in self.devices.values() {
            if let Some(resp) = dev.individual_address_response() {
                self.events.emit(Event::Telegram {
                    direction: Direction::ToTool,
                    cemi: resp.encode(),
                    summary: summarize(&resp),
                });
                responses.push(resp);
            }
        }
        responses
    }

    /// Apply a broadcast `A_IndividualAddress_Write`: the device currently in
    /// programming mode adopts `new_address` and is re-keyed under it, so every
    /// subsequent individually-addressed telegram reaches it at its new address.
    /// The service defines no response, so this always returns no telegrams.
    ///
    /// Strictness: the write is refused (with a warning on the log) unless
    /// **exactly one** device is in programming mode, and unless `new_address`
    /// is free. Addressing two devices identically, or colliding with a device
    /// that is already there, is precisely the mistake a tool must not make —
    /// `bussard assign` guarantees a single responder before sending this — and
    /// the bus keys devices by address, so silently letting one overwrite the
    /// other would hide the bug instead of exposing it.
    fn deliver_individual_address_write(
        &mut self,
        new_address: IndividualAddress,
    ) -> Vec<CemiLData> {
        let in_prog: Vec<IndividualAddress> = self
            .devices
            .iter()
            .filter(|(_, dev)| dev.prog_mode())
            .map(|(addr, _)| *addr)
            .collect();
        let [old_address] = in_prog[..] else {
            if !in_prog.is_empty() {
                tracing::warn!(
                    count = in_prog.len(),
                    %new_address,
                    "refusing A_IndividualAddress_Write: more than one device is in programming mode"
                );
            }
            return Vec::new();
        };
        if old_address != new_address && self.devices.contains_key(&new_address) {
            tracing::warn!(
                %old_address,
                %new_address,
                "refusing A_IndividualAddress_Write: another device already holds that address"
            );
            return Vec::new();
        }
        if let Some(mut dev) = self.devices.remove(&old_address) {
            dev.adopt_individual_address(new_address);
            self.devices.insert(dev.address(), dev);
        }
        Vec::new()
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

/// Build the `L_Data.con` echo of a tool-originated telegram: the same frame
/// re-coded as a local confirmation back toward the sender. A real KNXnet/IP
/// gateway confirms every request the tool puts on the bus; the connected
/// monitor/viz relies on that echo to see its own group writes.
fn confirm_echo(cemi: &CemiLData) -> CemiLData {
    CemiLData {
        message_code: MessageCode::LDataCon,
        ..cemi.clone()
    }
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

/// Whether a telegram is a broadcast `A_IndividualAddress_Read`: a group frame
/// to the broadcast group address `0/0/0` whose APCI decodes to
/// [`Apci::IndividualAddressRead`].
fn is_individual_address_read(cemi: &CemiLData) -> bool {
    if !cemi.is_group() || cemi.dest != 0x0000 || cemi.tpdu.len() < 2 {
        return false;
    }
    let apci10 = ((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16;
    Apci::from_u10(apci10) == Apci::IndividualAddressRead
}

/// The new individual address carried by a broadcast `A_IndividualAddress_Write`
/// — a group frame to the broadcast group address `0/0/0` whose APCI decodes to
/// [`Apci::IndividualAddressWrite`] and whose payload is the 2-byte raw address.
/// `None` for anything else, including a write whose payload is too short.
fn individual_address_write_target(cemi: &CemiLData) -> Option<IndividualAddress> {
    if !cemi.is_group() || cemi.dest != 0x0000 || cemi.tpdu.len() < 4 {
        return None;
    }
    let apci10 = ((cemi.tpdu[0] as u16 & 0x03) << 8) | cemi.tpdu[1] as u16;
    if Apci::from_u10(apci10) != Apci::IndividualAddressWrite {
        return None;
    }
    Some(IndividualAddress(u16::from_be_bytes([
        cemi.tpdu[2],
        cemi.tpdu[3],
    ])))
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
    use crate::device::{LoadState, ProfileOverrides};
    use crate::prod::read_knxprod_bytes;
    use crate::wire::MessageCode;

    /// A broadcast `A_IndividualAddress_Read` from the tool: a group frame to the
    /// broadcast group address `0/0/0`, TPCI unnumbered + the read APCI, no data.
    fn individual_address_read() -> CemiLData {
        let apci10 = Apci::IndividualAddressRead.to_u10();
        CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0xe0, // group destination bit set (broadcast)
            source: IndividualAddress::new(0, 0, 255),
            dest: 0x0000,
            tpdu: vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8],
        }
    }

    /// Build a fixture-free System 7 device (synthetic product) at `address`,
    /// optionally starting in programming mode.
    fn prog_device(
        address: IndividualAddress,
        prog_mode: bool,
        sink: Arc<dyn EventSink>,
    ) -> Result<Device, String> {
        let pd = crate::testfixtures::synthetic_mdt_sys7_product();
        Device::from_product_with_overrides(
            address,
            &pd,
            LoadState::Loaded,
            ProfileOverrides {
                prog_mode,
                ..Default::default()
            },
            sink,
        )
    }

    #[test]
    fn test_broadcast_individual_address_read_answered_by_prog_mode_devices()
    -> Result<(), Box<dyn std::error::Error>> {
        // Two devices: one in programming mode, one not. A broadcast
        // A_IndividualAddress_Read draws exactly one response, from the
        // programming-mode device, carrying its own address as the source.
        let sink = Arc::new(RecordingSink::new());
        let programming = IndividualAddress::new(1, 1, 2);
        let quiet = IndividualAddress::new(1, 1, 3);
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(programming, true, sink.clone())?);
        bus.add_device(prog_device(quiet, false, sink.clone())?);

        let responses = bus.deliver_from_tool(&individual_address_read());
        assert_eq!(responses.len(), 1, "only the prog-mode device answers");
        let resp = &responses[0];
        assert_eq!(resp.source, programming);
        assert_eq!(resp.dest, 0x0000);
        let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
        assert_eq!(Apci::from_u10(apci10), Apci::IndividualAddressResponse);
        Ok(())
    }

    /// A broadcast `A_IndividualAddress_Write` from the tool, exactly as
    /// `bussard assign` puts it on the bus: a group frame to `0/0/0` whose
    /// payload is the raw 2-byte new address.
    fn individual_address_write(new_address: IndividualAddress) -> CemiLData {
        let apci10 = Apci::IndividualAddressWrite.to_u10();
        let mut tpdu = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
        tpdu.extend_from_slice(&new_address.raw().to_be_bytes());
        CemiLData {
            message_code: MessageCode::LDataReq,
            ctrl1: 0xbc,
            ctrl2: 0xe0, // group destination bit set (broadcast)
            source: IndividualAddress::new(0, 0, 255),
            dest: 0x0000,
            tpdu,
        }
    }

    #[test]
    fn test_broadcast_individual_address_write_is_adopted_in_programming_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        // The device in programming mode adopts the broadcast address; the quiet
        // one keeps its own. Afterwards the device answers at the NEW address and
        // is gone from the old one — the property `bussard assign` verifies.
        let sink = Arc::new(RecordingSink::new());
        let old = IndividualAddress::new(15, 15, 255);
        let quiet = IndividualAddress::new(1, 1, 3);
        let new = IndividualAddress::new(1, 1, 9);
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(old, true, sink.clone())?);
        bus.add_device(prog_device(quiet, false, sink.clone())?);

        let responses = bus.deliver_from_tool(&individual_address_write(new));
        assert!(responses.is_empty(), "the service defines no response");
        assert!(bus.device(old).is_none(), "the old address is vacated");
        assert_eq!(bus.device(new).map(|d| d.address()), Some(new));
        assert_eq!(
            bus.device(quiet).map(|d| d.address()),
            Some(quiet),
            "a device not in programming mode ignores the broadcast"
        );
        // The discovery read now reports the new address.
        let found = bus.deliver_from_tool(&individual_address_read());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source, new);
        assert!(sink.events().iter().any(|e| matches!(
            e,
            Event::AddressChanged { device, new_address }
                if *device == old && *new_address == new
        )));
        Ok(())
    }

    #[test]
    fn test_broadcast_individual_address_write_ignored_when_none_programming()
    -> Result<(), Box<dyn std::error::Error>> {
        let sink = Arc::new(RecordingSink::new());
        let addr = IndividualAddress::new(1, 1, 2);
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(addr, false, sink.clone())?);
        bus.deliver_from_tool(&individual_address_write(IndividualAddress::new(1, 1, 9)));
        assert_eq!(bus.device(addr).map(|d| d.address()), Some(addr));
        assert!(bus.device(IndividualAddress::new(1, 1, 9)).is_none());
        Ok(())
    }

    #[test]
    fn test_broadcast_individual_address_write_refused_with_two_responders()
    -> Result<(), Box<dyn std::error::Error>> {
        // Two devices in programming mode would be addressed identically. The sim
        // refuses rather than silently merging them, so the tool bug is visible.
        let sink = Arc::new(RecordingSink::new());
        let a = IndividualAddress::new(15, 15, 254);
        let b = IndividualAddress::new(15, 15, 255);
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(a, true, sink.clone())?);
        bus.add_device(prog_device(b, true, sink.clone())?);
        bus.deliver_from_tool(&individual_address_write(IndividualAddress::new(1, 1, 9)));
        assert_eq!(bus.device_count(), 2, "both devices still on the bus");
        assert!(bus.device(a).is_some() && bus.device(b).is_some());
        Ok(())
    }

    #[test]
    fn test_broadcast_individual_address_write_refused_on_collision()
    -> Result<(), Box<dyn std::error::Error>> {
        // The requested address is already taken by another device: refuse, so
        // the existing device is not evicted from the bus.
        let sink = Arc::new(RecordingSink::new());
        let programming = IndividualAddress::new(15, 15, 255);
        let taken = IndividualAddress::new(1, 1, 9);
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(programming, true, sink.clone())?);
        bus.add_device(prog_device(taken, false, sink.clone())?);
        bus.deliver_from_tool(&individual_address_write(taken));
        assert_eq!(bus.device_count(), 2);
        assert_eq!(
            bus.device(programming).map(|d| d.address()),
            Some(programming)
        );
        Ok(())
    }

    #[test]
    fn test_broadcast_individual_address_write_ignores_short_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        // A write with no (or a 1-byte) address payload is not an address write:
        // it must be ignored, never read past the TPDU.
        let sink = Arc::new(RecordingSink::new());
        let addr = IndividualAddress::new(15, 15, 255);
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(addr, true, sink.clone())?);
        let apci10 = Apci::IndividualAddressWrite.to_u10();
        for tail in [vec![], vec![0x11u8]] {
            let mut tpdu = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
            tpdu.extend_from_slice(&tail);
            let cemi = CemiLData {
                message_code: MessageCode::LDataReq,
                ctrl1: 0xbc,
                ctrl2: 0xe0,
                source: IndividualAddress::new(0, 0, 255),
                dest: 0x0000,
                tpdu,
            };
            bus.deliver_from_tool(&cemi);
            assert_eq!(bus.device(addr).map(|d| d.address()), Some(addr));
        }
        Ok(())
    }

    #[test]
    fn test_broadcast_individual_address_read_silent_when_none_programming()
    -> Result<(), Box<dyn std::error::Error>> {
        // No device in programming mode: the broadcast read draws no response.
        let sink = Arc::new(RecordingSink::new());
        let mut bus = Bus::new(sink.clone());
        bus.add_device(prog_device(
            IndividualAddress::new(1, 1, 2),
            false,
            sink.clone(),
        )?);
        let responses = bus.deliver_from_tool(&individual_address_read());
        assert!(responses.is_empty(), "no responders when none programming");
        Ok(())
    }

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
