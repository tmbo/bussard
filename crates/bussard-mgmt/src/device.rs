//! The typed management client: [`DeviceConnection`].
//!
//! Wraps a [`Layer4Connection`](crate::connection::Layer4Connection) and exposes
//! the high-level procedures `bussard scan`, `assign` and the downloader need:
//! device descriptor, property reads, memory reads and restart. Each procedure
//! sends its request, waits for the acknowledged response, and decodes it,
//! translating a missing answer into [`MgmtError::NoResponse`] (device absent)
//! and a NAK/disconnect into a "present but refusing" error.

use bussard_model::IndividualAddress;

use crate::apci;
use crate::connection::{L4Channel, Layer4Connection, Timeouts};
use crate::error::{MgmtError, Result};

/// A management client bound to a single device over a connection-oriented
/// session.
///
/// Construct one with [`DeviceConnection::connect`]; it opens a `T_Connect`.
/// Call the typed procedures; then drop or [`DeviceConnection::disconnect`] to
/// send a clean `T_Disconnect`.
pub struct DeviceConnection<Ch: L4Channel> {
    inner: Layer4Connection<Ch>,
}

impl<Ch: L4Channel> DeviceConnection<Ch> {
    /// Opens a connection-oriented session to `target`, presenting `source` as
    /// the tool's own individual address.
    ///
    /// `conn` is the frame channel — a borrowed
    /// [`BusConnection`](bussard_transport::BusConnection) or a
    /// [`LeaseChannel`](crate::connection::LeaseChannel) over the bus actor.
    pub async fn connect(
        conn: Ch,
        target: IndividualAddress,
        source: IndividualAddress,
    ) -> Result<DeviceConnection<Ch>> {
        let inner = Layer4Connection::connect(conn, target, source).await?;
        Ok(DeviceConnection { inner })
    }

    /// Like [`connect`](Self::connect) but with an explicit timeout budget — use
    /// [`Timeouts::discovery`] for fast absent-address probing during a scan.
    pub async fn connect_with(
        conn: Ch,
        target: IndividualAddress,
        source: IndividualAddress,
        timeouts: Timeouts,
    ) -> Result<DeviceConnection<Ch>> {
        let inner = Layer4Connection::connect_with(conn, target, source, timeouts).await?;
        Ok(DeviceConnection { inner })
    }

    /// The device this connection targets.
    pub fn target(&self) -> IndividualAddress {
        self.inner.target()
    }

    /// Reads the device descriptor (type 0): the 16-bit **mask version** that
    /// decides property-based vs memory-based link writes.
    ///
    /// Sends `A_DeviceDescriptor_Read` with the descriptor type in the APCI low
    /// bits and an **empty** payload (the spec-correct framing — strict devices
    /// `T_Disconnect` the over-long form), and decodes the `Response`,
    /// validating that its APCI is an `A_DeviceDescriptor_Response`.
    pub async fn device_descriptor(&mut self) -> Result<u16> {
        let (req_apci, payload) = apci::encode_device_descriptor_read(0);
        let (resp_apci, data) = self.inner.request(req_apci, &payload).await?;
        if resp_apci & apci::APCI_SELECTOR_MASK != apci::A_DEVICE_DESCRIPTOR_RESPONSE {
            return Err(MgmtError::MalformedResponse {
                address: self.inner.target(),
                reason: "expected A_DeviceDescriptor_Response",
            });
        }
        apci::decode_device_descriptor_response(&data).ok_or(MgmtError::MalformedResponse {
            address: self.inner.target(),
            reason: "device descriptor response too short",
        })
    }

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
        let payload = apci::encode_property_value_read(object_index, property_id, count, start);
        let (resp_apci, data) = self
            .inner
            .request(apci::A_PROPERTY_VALUE_READ, &payload)
            .await?;
        if resp_apci != apci::A_PROPERTY_VALUE_RESPONSE {
            return Err(MgmtError::MalformedResponse {
                address: self.inner.target(),
                reason: "expected A_PropertyValue_Response",
            });
        }
        let resp =
            apci::decode_property_value_response(&data).ok_or(MgmtError::MalformedResponse {
                address: self.inner.target(),
                reason: "property value response too short",
            })?;
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

    /// Reads `len` octets of device memory starting at `addr`.
    ///
    /// `len` is clamped to [`apci::MAX_MEMORY_READ_LEN`] per telegram (this is
    /// the golden-fixture dump primitive; callers loop over addresses for larger
    /// ranges). Returns the octets from the `A_Memory_Response`.
    pub async fn read_memory(&mut self, addr: u16, len: u8) -> Result<Vec<u8>> {
        let (req_apci, payload) = apci::encode_memory_read(addr, len);
        let (resp_apci, data) = self.inner.request(req_apci, &payload).await?;
        let resp =
            apci::decode_memory_response(resp_apci, &data).ok_or(MgmtError::MalformedResponse {
                address: self.inner.target(),
                reason: "expected A_Memory_Response with matching count",
            })?;
        Ok(resp.data)
    }

    /// Restarts the device (`A_Restart`). Fire-and-forget: the device does not
    /// answer and typically drops the connection as it reboots, so this only
    /// sends the request NDT and awaits its `T_ACK`.
    ///
    /// Nothing in phase 2 calls this yet; it is here for the downloader.
    pub async fn restart(&mut self) -> Result<()> {
        let (apci, payload) = apci::encode_restart(0);
        self.inner.send_data(apci, &payload).await
    }

    /// Sends a clean `T_Disconnect`.
    pub async fn disconnect(self) -> Result<()> {
        self.inner.disconnect().await
    }
}
