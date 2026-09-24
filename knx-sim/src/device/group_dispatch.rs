//! Group-communication dispatch: rebuilding the runtime routing from the
//! flashed tables and handling inbound and stimulus-driven group telegrams.

use crate::bus::event::Event;
use crate::wire::apdu::Apci;
use crate::wire::{CemiLData, GroupAddress, MessageCode};

use super::{Device, LoadState, group_comm, sys7_group_comm};

impl Device {
    /// Rebuild the runtime routing from the device's flashed tables, but only
    /// when the address (obj1), association (obj2) and com-object (obj3) table
    /// objects have all reached `Loaded`. A device that is not fully loaded stays
    /// silent on the group side (`group_comm` becomes `None`).
    ///
    /// This reads obj1/obj2/obj3 straight back out of the device's own memory —
    /// the exact bytes the download wrote — so the routing is self-describing and
    /// a mistake in the written tables shows up as wrong bus behaviour.
    pub(super) fn refresh_group_comm(&mut self) {
        // System 7: the three LSMs are the tables. Once LSM 1 and 2 are Loaded the
        // device self-parses its own written S7-format tables from the absolute
        // memory anchors (spec §7) and comes alive.
        if let Some(s7) = &self.sys7 {
            let tables_loaded = [1u8, 2]
                .iter()
                .all(|&i| self.load_state(i) == Some(LoadState::Loaded));
            if !tables_loaded {
                self.group_comm = None;
                return;
            }
            let addr_base = s7.profile.memory_map.lsm1_table;
            let assoc_base = s7.profile.memory_map.lsm2_table;
            // The group-object descriptor table follows the address table inside
            // the LSM 1 region (spec §7: the GrAT and GO table are co-located).
            // Its base is the address table's end: [CNT:1][own-IA + GAs: CNT*2].
            // S7-CAL: confirm the group-object table offset within the 0x4000
            // region against a live 0705 capture (co-located vs a fixed sub-addr).
            let addr_cnt = self.memory.read(u32::from(addr_base), 1)[0] as u16;
            let go_base = addr_base.wrapping_add(1).wrapping_add(addr_cnt * 2);
            let gc = sys7_group_comm::Sys7GroupComm::from_tables(
                &self.memory,
                addr_base,
                assoc_base,
                go_base,
            );
            self.group_comm = if gc.is_empty() { None } else { Some(gc) };
            return;
        }
        let tables_loaded = [1u8, 2, 3]
            .iter()
            .all(|&i| self.load_state(i) == Some(LoadState::Loaded));
        if !tables_loaded {
            self.group_comm = None;
            return;
        }
        let (Some(addr_base), Some(assoc_base), Some(comobj_base)) =
            (self.base_of(1), self.base_of(2), self.base_of(3))
        else {
            self.group_comm = None;
            return;
        };
        let gc =
            group_comm::GroupComm::from_tables(&self.memory, addr_base, assoc_base, comobj_base);
        self.group_comm = if gc.is_empty() { None } else { Some(gc) };
    }

    /// Handle an inbound **group** telegram addressed to `ga`, updating the
    /// device's com-objects and producing any response the device must send.
    ///
    /// Returns the response telegrams (an `A_GroupValue_Response` when the device
    /// holds the Read flag on the read GA). A device that is not loaded, not
    /// linked, or not associated with `ga` returns nothing — exactly as a real
    /// device silently ignores group traffic it does not subscribe to.
    pub fn handle_group(&mut self, apci: Apci, ga: GroupAddress, payload: &[u8]) -> Vec<CemiLData> {
        let Some(gc) = self.group_comm.as_mut() else {
            return Vec::new();
        };
        match apci {
            Apci::GroupValueWrite => {
                let updated = gc.on_group_write(ga, payload);
                for asap in updated {
                    self.emit(Event::GroupObjectUpdated {
                        device: self.address,
                        object: asap,
                        ga: ga.raw(),
                    });
                }
                Vec::new()
            }
            Apci::GroupValueRead => match gc.on_group_read(ga) {
                Some(value) => vec![self.group_telegram(Apci::GroupValueResponse, ga, &value)],
                None => Vec::new(),
            },
            // A device ignores responses/writes it did not solicit beyond the
            // write handling above; other services never reach the group path.
            _ => Vec::new(),
        }
    }

    /// Build an outgoing group telegram (`L_Data.ind`) from this device: an
    /// `A_GroupValue_Write`/`_Response` to `ga` carrying `payload`.
    ///
    /// A sub-byte payload (a single octet `<= 0x3F`) is packed into the APCI low
    /// bits (the "small" APDU form), matching how a real device and the tool
    /// encode a 1-bit DPT; anything else rides as separate data octets.
    pub fn group_telegram(&self, apci: Apci, ga: GroupAddress, payload: &[u8]) -> CemiLData {
        let apci10 = apci.to_u10();
        let packable = payload.len() == 1 && payload[0] <= 0x3F;
        let tpdu = if packable {
            // Small form: TPCI DataGroup (0x00) + APCI high bits; second octet is
            // APCI low bits with the 6-bit value packed in.
            vec![
                (apci10 >> 8) as u8 & 0x03,
                ((apci10 & 0xC0) as u8) | (payload[0] & 0x3F),
            ]
        } else {
            let mut t = vec![(apci10 >> 8) as u8 & 0x03, (apci10 & 0xFF) as u8];
            t.extend_from_slice(payload);
            t
        };
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0xe0, // group destination (bit 7) + hop count 6
            source: self.address,
            dest: ga.raw(),
            tpdu,
        }
    }

    /// Whether the device may transmit on `object`, and if so its sending GA:
    /// used by scripted stimulus to address a periodic transmit.
    pub fn stimulus_send_ga(&self, object: u16) -> Option<GroupAddress> {
        self.group_comm.as_ref().and_then(|gc| gc.send_ga(object))
    }

    /// Seed a transmitting com-object's value and build the group telegram that
    /// pushes it onto the bus, or `None` if the object cannot transmit (not
    /// loaded, not linked, or lacks the Transmit flag). Used by stimulus.
    pub fn emit_stimulus(&mut self, object: u16, payload: &[u8]) -> Option<CemiLData> {
        let ga = self.stimulus_send_ga(object)?;
        if let Some(gc) = self.group_comm.as_mut() {
            gc.set_value(object, payload);
        }
        Some(self.group_telegram(Apci::GroupValueWrite, ga, payload))
    }
}
