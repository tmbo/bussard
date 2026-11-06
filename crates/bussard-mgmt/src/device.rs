//! The typed management procedures on a [`Layer4Connection`]: property
//! reads and writes, property descriptions, memory reads, the interactive
//! memory write and restart.
//!
//! Each procedure sends its request, waits for the acknowledged response, and
//! decodes it, translating a missing answer into [`MgmtError::NoResponse`]
//! (device absent) and a NAK/disconnect into a "present but refusing" error.
//! The device descriptor is [`read_device_descriptor`](crate::read_device_descriptor);
//! the authorize step is [`Layer4Connection::authorize_or_fail`].

use crate::apci;
use crate::connection::{
    L4Channel, Layer4Connection, PropertyDesc, describe_object_properties,
    property_description_request, property_request, property_write_request,
};
use crate::error::{MgmtError, Result};

impl<Ch: L4Channel> Layer4Connection<Ch> {
    /// Reads `count` elements of a property, starting at element `start`, of the
    /// interface object at `object_index`.
    ///
    /// Sends `A_PropertyValue_Read` and returns the raw value octets from the
    /// `Response`. A response with `count == 0` means the object or property is
    /// absent on this device; that surfaces as an empty `Vec`.
    pub async fn read_property(
        &mut self,
        object_index: u8,
        property_id: u8,
        start: u16,
        count: u8,
    ) -> Result<Vec<u8>> {
        let resp = property_request(self, object_index, property_id, start, count).await?;
        if resp.count == 0 {
            return Ok(Vec::new());
        }
        Ok(resp.data)
    }

    /// Convenience: reads a device-object (index 0) property in one element.
    pub async fn read_device_property(&mut self, property_id: u8) -> Result<Vec<u8>> {
        self.read_property(apci::DEVICE_OBJECT_INDEX, property_id, 1, 1)
            .await
    }

    /// Writes `value` to `count` element(s) of a property starting at element
    /// `start` of the interface object at `object_index`, returning the octets the
    /// device echoes back (the KNX application layer echoes the *stored* value).
    ///
    /// Sends `A_PropertyValue_Write` and returns the response payload. A response
    /// with `count == 0` means the device refused the write; that surfaces as an
    /// empty `Vec` for the caller to check against what it wrote.
    pub async fn write_property(
        &mut self,
        object_index: u8,
        property_id: u8,
        start: u16,
        count: u8,
        value: &[u8],
    ) -> Result<Vec<u8>> {
        let resp =
            property_write_request(self, object_index, property_id, count, start, value).await?;
        if resp.count == 0 {
            return Ok(Vec::new());
        }
        Ok(resp.data)
    }

    /// Clears the device's programming mode by writing `PID_PROGMODE = 0` on the
    /// device object (index 0), exactly as ETS does after an individual-address
    /// assignment.
    ///
    /// A conformant device leaves programming mode on its own when it takes a new
    /// address, but ETS clears it explicitly and so does bussard: this writes a
    /// single `0x00` octet to element 1 of [`PID_PROGMODE`](apci::PID_PROGMODE) on
    /// the device object. Returns whether the write was confirmed (the device
    /// echoed the stored `0x00`); an unconfirmed write is not an error here (the
    /// caller falls back to the broadcast-based persistence check).
    pub async fn clear_programming_mode(&mut self) -> Result<bool> {
        let echoed = self
            .write_property(apci::DEVICE_OBJECT_INDEX, apci::PID_PROGMODE, 1, 1, &[0x00])
            .await?;
        Ok(echoed.first() == Some(&0x00))
    }

    /// Reads the *description* of one property (issue #72): its data type,
    /// element count and access levels, rather than its value.
    ///
    /// Sends `A_PropertyDescription_Read` for the property `property_id` of the
    /// interface object at `object_index` and returns the decoded
    /// [`PropertyDesc`]. Pass `property_id = 0` to address the property at a given
    /// index instead (the enumeration form — see
    /// [`describe_object`](Self::describe_object)). Read-only on the bus.
    pub async fn describe_property(
        &mut self,
        object_index: u8,
        property_id: u8,
        property_index: u8,
    ) -> Result<PropertyDesc> {
        let desc =
            property_description_request(self, object_index, property_id, property_index).await?;
        Ok(desc.into())
    }

    /// Enumerates every property of one interface object by walking the property
    /// index until the device reports none (issue #72).
    ///
    /// Drives [`describe_object_properties`], returning one [`PropertyDesc`] per
    /// property the object exposes. The introspection value: describing an
    /// unknown device's property set without knowing its PIDs in advance.
    /// Read-only on the bus; a device that does not implement the description
    /// service yields an empty list rather than an error.
    pub async fn describe_object(&mut self, object_index: u8) -> Result<Vec<PropertyDesc>> {
        describe_object_properties(self, object_index).await
    }

    /// Reads `len` octets of device memory starting at `addr`.
    ///
    /// `len` is clamped to [`apci::MAX_MEMORY_READ_LEN`] per telegram (this is
    /// the golden-fixture dump primitive; callers loop over addresses for larger
    /// ranges). Returns the octets from the `A_Memory_Response`.
    pub async fn read_memory(&mut self, addr: u32, len: u8) -> Result<Vec<u8>> {
        // Delegate to [`crate::memory`], the crate's single memory module, which
        // picks the plain A_Memory_Read or the 24-bit A_MemoryExtended_Read from
        // the address (see `memory::select_extended_memory`).
        crate::memory::read_memory(self, addr, len)
            .await
            .map_err(|e| e.into_mgmt(self.target()))
    }

    /// Writes `data` to device memory starting at `addr`, in
    /// [`apci::MAX_MEMORY_WRITE_LEN`]-octet chunks, **verifying each chunk by
    /// read-back**.
    ///
    /// For every chunk this sends `A_Memory_Write` (count in the APCI low bits,
    /// payload `[addr_hi, addr_lo, data…]`), then immediately reads the same
    /// address back with `A_Memory_Read` and compares. Any divergence fails with
    /// [`MgmtError::MemoryVerifyFailed`], naming the address, the octets written
    /// and the octets read back, so a partial or silently-dropped write surfaces
    /// loudly rather than corrupting device memory.
    ///
    /// # Why read-back rather than the write's own echo
    ///
    /// `A_Memory_Write` has **no mandatory response**. Some System B devices run
    /// in a "verify mode" where they answer an `A_Memory_Response` echoing the
    /// stored octets, but that mode is optional, device-configurable and not
    /// observable from the tool ahead of time. An explicit `A_Memory_Read`
    /// read-back is the one confirmation that works across every stack, so it is
    /// the path bussard takes; the optional write echo is ignored.
    ///
    /// # This is not the download path
    ///
    /// The flash/apply engine streams segments with
    /// [`crate::memory::write_memory_chunked`], which deliberately does **not**
    /// read each chunk back: on a multi-kilobyte image that doubles the numbered
    /// exchanges (exhausting a device's per-connection L4 budget) and interleaves
    /// stray `A_Memory_Response`s into the stream. Integrity there is confirmed by
    /// the device's own MCB CRC and the end-of-segment spot check. This method is
    /// the small, interactive, one-shot write — a few octets a human or a test is
    /// about to look at — so it keeps the per-chunk read-back and the plain 63-octet
    /// chunk; the service selection and the 24-bit address bound are shared with
    /// [`crate::memory`] so the two paths cannot disagree about *what* a memory
    /// access is.
    ///
    /// An empty `data` is a no-op.
    pub async fn write_memory_read_back(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        // An application without extended memory services is written above
        // 0xFFFF with A_UserMemory_Write, 15 octets at most (issue #472).
        let user = crate::memory::memory_service(self, addr, data.len())
            == crate::memory::MemoryService::User;
        let chunk = if user {
            usize::from(apci::MAX_USER_MEMORY_LEN)
        } else {
            usize::from(apci::MAX_MEMORY_WRITE_LEN)
        };
        let mut offset = 0usize;
        while offset < data.len() {
            let take = chunk.min(data.len() - offset);
            let piece = &data[offset..offset + take];
            // A 24-bit address space; a write that would run past 0xFF_FFFF is a
            // programming error caught here rather than silently wrapping.
            let chunk_addr = u32::try_from(offset)
                .ok()
                .and_then(|off| addr.checked_add(off))
                .filter(|&a| a <= apci::MAX_MEMORY_ADDRESS)
                .ok_or(MgmtError::MalformedResponse {
                    address: self.target(),
                    reason: "memory write range exceeds the 24-bit address space".to_string(),
                })?;

            // Pick the plain A_Memory_Write or the 24-bit A_MemoryExtended_Write
            // from the address, keeping the ≤16-bit path byte-identical. The
            // extended write is confirmed inline; the plain write is verified by a
            // separate read-back compare (the historical dump-primitive discipline).
            if !user && crate::memory::select_extended_memory(chunk_addr, take) {
                let (req_apci, payload) = apci::encode_memory_extended_write(chunk_addr, piece);
                let (resp_apci, resp) = self.request(req_apci, &payload).await?;
                crate::memory::check_extended_write_response(
                    self.target(),
                    chunk_addr,
                    &payload,
                    resp_apci,
                    &resp,
                )?;
                offset += take;
                continue;
            }

            let (req_apci, payload) = if user {
                apci::encode_user_memory_write(chunk_addr, piece)
            } else {
                apci::encode_memory_write(chunk_addr as u16, piece)
            };
            // A_Memory_Write (and A_UserMemory_Write) is acknowledged (T_ACK) but
            // not answered, so send it and wait only for the ACK; the read-back
            // is the confirmation.
            self.send_data(req_apci, &payload).await?;
            if user {
                self.discard_pending_response();
            }

            // Verify: read the same address back and compare octet-for-octet.
            let got = crate::memory::read_memory_strict(self, chunk_addr, take as u8)
                .await
                .map_err(|e| e.into_mgmt(self.target()))?;
            if got != piece {
                return Err(MgmtError::MemoryVerifyFailed {
                    address: self.target(),
                    addr: chunk_addr,
                    expected: piece.to_vec(),
                    got,
                });
            }
            offset += take;
        }
        Ok(())
    }

    /// Restarts the device (`A_Restart`). Fire-and-forget: the device reboots on
    /// the request and never `T_ACK`s it (it drops the L4 link immediately), so
    /// this sends the telegram **without** awaiting the ACK — waiting would
    /// retransmit and then spuriously report the device absent. The caller waits
    /// out the reboot and reconnects.
    ///
    /// This is the same realisation the download engine uses for its terminal
    /// basic restart, the one verified against the real ETS→KNX-Virtual
    /// capture.
    pub async fn restart(&mut self) -> Result<()> {
        let (apci, payload) = apci::encode_restart(0);
        self.send_data_unacked(apci, &payload).await
    }
}
