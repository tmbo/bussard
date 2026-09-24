//! Memory services: `A_Memory_Read`/`_Write` and
//! `A_MemoryExtended_Read`/`_Write` against the device's memory map.

use crate::bus::event::Event;
use crate::wire::IndividualAddress;
use crate::wire::apdu::{Apci, Apdu};

use super::{Device, DeviceError, DeviceReaction, LoadState, MemoryError, profile};

/// A decoded `A_MemoryExtended_*` request: the count, the 24-bit address and (for
/// a write) the data octets.
struct ExtendedMemoryRequest {
    /// Number of octets to write/read.
    count: u8,
    /// The 24-bit memory address.
    addr: u32,
    /// The data octets (empty for a read request).
    data: Vec<u8>,
}

/// Decode an `A_MemoryExtended_Write`/`_Read` payload `[count][addr:3 BE][data]`.
///
/// `is_write` selects whether the trailing `count` data octets are required.
/// Returns `None` if the payload is shorter than the 4-octet `[count][addr:3]`
/// header, or (for a write) holds fewer data octets than `count` advertises. This
/// is the sim's own decoder — the simulator never links a bussard crate.
fn bussard_extended_request(payload: &[u8], is_write: bool) -> Option<ExtendedMemoryRequest> {
    if payload.len() < 4 {
        return None;
    }
    let count = payload[0];
    let addr = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
    let data = &payload[4..];
    if is_write {
        if data.len() < usize::from(count) {
            return None;
        }
        Some(ExtendedMemoryRequest {
            count,
            addr,
            data: data[..usize::from(count)].to_vec(),
        })
    } else {
        Some(ExtendedMemoryRequest {
            count,
            addr,
            data: Vec::new(),
        })
    }
}

impl Device {
    pub(super) fn on_memory_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let n = apdu.memory_count() as usize;
        if apdu.data.len() < 2 {
            return Err(DeviceError::Malformed {
                service: "A_MemoryRead".into(),
                detail: "missing address".into(),
            });
        }
        let addr = u16::from_be_bytes([apdu.data[0], apdu.data[1]]);
        // System 7 memory-mapped LSM status poll: a read at the status address
        // returns the addressed LSM's live state (spec section 5). The per-LSM
        // status byte is at `status_addr + (lsm_index - 1)`.
        let bytes = if let Some(status) = self.sys7_status_bytes(addr, n) {
            status
        } else {
            self.memory.read(u32::from(addr), n)
        };
        // A_MemoryResponse: apci 0x240 | count, then addr(2), then data.
        let mut data = Vec::with_capacity(2 + bytes.len());
        data.extend_from_slice(&addr.to_be_bytes());
        data.extend_from_slice(&bytes);
        let resp = self.respond(tool, 0x240 | (n as u16 & 0x3F), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    pub(super) fn on_memory_write(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if self.access_level != 0 {
            return Err(DeviceError::Unauthorized {
                level: self.access_level,
            });
        }
        let n = apdu.memory_count() as usize;
        if apdu.data.len() < 2 + n {
            return Err(DeviceError::Malformed {
                service: "A_MemoryWrite".into(),
                detail: "payload shorter than declared count".into(),
            });
        }
        let addr = u16::from_be_bytes([apdu.data[0], apdu.data[1]]);
        let payload = &apdu.data[2..2 + n];

        // System 7 memory-mapped LSM control: a write to the LSM control address
        // is a load-event record, not a segment write (spec section 5). Decode and
        // drive the addressed LSM.
        if let Some(s7) = &self.sys7 {
            if s7.profile.lsm_access == profile::LsmAccess::MemoryMapped
                && addr == s7.profile.mm_lsm.control_addr
            {
                return self.on_sys7_lsm_record(tool, payload);
            }
        }

        // Determine which object owns this address: strict — the address must be
        // inside exactly one open segment, and that object must be Loading.
        let addr32 = u32::from(addr);
        let seg = self
            .memory
            .segment_at(addr32)
            .ok_or(MemoryError::OutOfSegment {
                addr: addr32,
                len: n,
            })?;
        let owner = seg.owner;
        if self.load_state(owner) != Some(LoadState::Loading) {
            return Err(DeviceError::LoadControl(format!(
                "memory write to object {owner} while not Loading"
            )));
        }
        self.memory.write(owner, addr32, payload)?;
        self.emit(Event::MemoryWritten {
            device: self.address,
            addr: addr32,
            len: n,
        });
        // A_MemoryWrite is not acknowledged at the application layer in the
        // captured flow (the tool relies on the transport T_ACK), so no APDU
        // response is produced.
        Ok(DeviceReaction::default())
    }

    /// Handle an `A_MemoryExtended_Write` (APCI 0x1FB): the System B extended
    /// memory service ETS drives every capable 07B0 device with (verified against
    /// four real ETS6 downloads). The payload is `[count][addr:3 BE][data]`, so
    /// this reaches the 24-bit space a plain `A_Memory_Write` cannot. It is
    /// bounded and access-checked exactly like [`on_memory_write`]: the address
    /// must fall inside exactly one open segment whose owner is Loading. Unlike
    /// the plain write it is confirmed **inline** with an
    /// `A_MemoryExtended_Write_Response` (0x1FC) carrying a return code (0 = ok)
    /// and the echoed address, so no separate read-back is needed.
    pub(super) fn on_memory_extended_write(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if self.access_level != 0 {
            return Err(DeviceError::Unauthorized {
                level: self.access_level,
            });
        }
        let req = bussard_extended_request(&apdu.data, true).ok_or(DeviceError::Malformed {
            service: "A_MemoryExtended_Write".into(),
            detail: "payload shorter than [count][addr:3] or truncated data".into(),
        })?;
        let addr = req.addr;
        let n = req.data.len();

        // Same strict segment/ownership discipline as the plain write.
        let seg = self
            .memory
            .segment_at(addr)
            .ok_or(MemoryError::OutOfSegment { addr, len: n })?;
        let owner = seg.owner;
        if self.load_state(owner) != Some(LoadState::Loading) {
            return Err(DeviceError::LoadControl(format!(
                "extended memory write to object {owner} while not Loading"
            )));
        }
        self.memory.write(owner, addr, &req.data)?;
        self.emit(Event::MemoryWritten {
            device: self.address,
            addr,
            len: n,
        });
        // Confirm inline: return code 0x00 + echoed 3-octet address.
        let mut data = Vec::with_capacity(4);
        data.push(0x00);
        data.extend_from_slice(&[(addr >> 16) as u8, (addr >> 8) as u8, addr as u8]);
        let resp = self.respond(tool, Apci::MemoryExtendedWriteResponse.to_u10(), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// Handle an `A_MemoryExtended_Read` (APCI 0x1FD): read `count` octets at the
    /// 24-bit address and answer with an `A_MemoryExtended_Read_Response` (0x1FE)
    /// carrying `[return_code][addr:3][data]`. The read is served from the sparse
    /// memory (unwritten cells read back as 0x00), modelling verify-on-read for
    /// the tool. No segment gate on reads — a tool verifies freely.
    pub(super) fn on_memory_extended_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let req = bussard_extended_request(&apdu.data, false).ok_or(DeviceError::Malformed {
            service: "A_MemoryExtended_Read".into(),
            detail: "payload shorter than [count][addr:3]".into(),
        })?;
        let addr = req.addr;
        let bytes = self.memory.read(addr, req.count as usize);
        let mut data = Vec::with_capacity(4 + bytes.len());
        data.push(0x00);
        data.extend_from_slice(&[(addr >> 16) as u8, (addr >> 8) as u8, addr as u8]);
        data.extend_from_slice(&bytes);
        let resp = self.respond(tool, Apci::MemoryExtendedReadResponse.to_u10(), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::device::test_support::*;
    use crate::device::*;

    #[test]
    fn test_memory_write_without_auth_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        // Start loading object 4 needs auth too; write should be rejected as
        // unauthorized before any load state work.
        let mw = data(&dev, 0x280 | 4, &[0x60, 0x00, 1, 2, 3, 4]);
        assert!(matches!(
            dev.handle_cemi(&mw),
            Err(DeviceError::Unauthorized { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_memory_write_to_wrong_base_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        dev.handle_cemi(&data(&dev, 0x3D7, &[0x04, 0x05, 0x10, 0x01, 0x01]))?;
        dev.handle_cemi(&data(
            &dev,
            0x3D7,
            &[0x04, 0x05, 0x10, 0x01, 0x03, 0x0b, 0x00, 0x00, 0x01, 0x00],
        ))?;
        // Write to 0x8000 (com-object base) while only obj4@0x6000 is open.
        let mw = data(&dev, 0x280 | 4, &[0x80, 0x00, 1, 2, 3, 4]);
        assert!(dev.handle_cemi(&mw).is_err());
        Ok(())
    }
}
