//! KNXnet/IP device management connections (issue #523).
//!
//! A [`DeviceManagement`] connection reaches the KNXnet/IP server itself, not
//! the bus behind it: CONNECT_REQUEST with the 2-octet CRI `02 03`
//! (`DEVICE_MGMT_CONNECTION`, KNXnet/IP Device Management 3/8/3 §4.2.3 and
//! §4.2.4, p. 22), then DEVICE_CONFIGURATION_REQUEST (0310h) frames that carry
//! one cEMI frame each (§4.2.5-§4.2.6, p. 23).
//!
//! # Carriers
//!
//! * Plain UDP: every DEVICE_CONFIGURATION_REQUEST is acknowledged with a
//!   DEVICE_CONFIGURATION_ACK (0311h). A request unacknowledged within the
//!   "DEVICE_CONFIGURATION_REQUEST_TIMEOUT" of 10 s, or acknowledged with an
//!   error, is repeated three times, then the connection is ended with a
//!   DISCONNECT_REQUEST (3/8/3 §2.3.2, p. 7). Inbound requests are
//!   acknowledged in turn; one with an unexpected sequence number is
//!   discarded, the repeat of the last one is acknowledged again.
//! * Inside a KNXnet/IP Secure session (TCP): no ACK is sent and a received
//!   one is ignored (§2.3.2). Only the management user (user id 1) may open a
//!   device management connection in a session (KNX IP Secure 3/8/9
//!   §2.2.1.4.2, p. 13), so a secure connection needs that user's password
//!   ([`MANAGEMENT_USER`]).
//!
//! Heartbeats (CONNECTIONSTATE_REQUEST every 60 s) and the secure session
//! keepalive run as on a tunnel. A lost connection is reported, not
//! re-established: the bus actor reconnects.
//!
//! # The transport-layer bridge
//!
//! Opening the connection switches the server's transport layer to "cEMI
//! Transport Layer mode" (3/8/3 §2.6.1.2, p. 17): the server holds the
//! transport connection to its own device for as long as the device
//! management connection lasts, and the client hands it APDUs in cEMI
//! `T_Data_Connected.req` / `T_Data_Individual.req` frames (EMI 3/6/3
//! §4.1.6.4-§4.1.6.5, p. 101-103). So that bussard's management layer
//! (`bussard-mgmt`'s `Layer4Connection` and everything built on it) runs
//! unchanged on this carrier, [`DeviceManagement`] implements
//! [`BusConnection`] and bridges its `L_Data` frames:
//!
//! * `T_Connect`, `T_Disconnect`, `T_ACK` and `T_NAK` stay local: the server
//!   runs the transport connection.
//! * A numbered data telegram is sent as a `T_Data_Connected.req`; once the
//!   server has it (its ACK on UDP, §2.6.1.4) the bridge answers the
//!   management layer with the `T_ACK` its peer would send.
//!   `A_PropertyExtValue_Read` and `A_PropertyExtValue_WriteCon` go as the
//!   local device management services `M_PropRead.req` / `M_PropWrite.req`
//!   instead (EMI 3/6/3 §4.1.7.3, p. 105-106), which address the interface
//!   object by type and instance as the extended services do (3/8/3 §4.2.5).
//!   A request whose fields do not fit the local services (more than 15
//!   elements, a start index above 4095, an instance or property id above
//!   255) stays a `T_Data_Connected.req`.
//! * An unnumbered telegram to an individual address is sent as a
//!   `T_Data_Individual.req`.
//! * The server's `T_Data_Connected.ind`, `M_PropRead.con` and
//!   `M_PropWrite.con` come back as numbered data from the device (as the
//!   matching extended responses for the local services), its
//!   `T_Data_Individual.ind` as unnumbered data.
//! * Group and broadcast telegrams have no bus to go to:
//!   [`TransportError::NotOnDeviceManagement`].
//!
//! Every telegram the management layer addresses reaches the server's own
//! device, whatever its destination address: the connection has no other
//! destination.

use std::collections::VecDeque;
use std::net::SocketAddrV4;
use std::time::{Duration, SystemTime};

use bussard_model::IndividualAddress;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use crate::cemi::{CemiFrame, Destination, MessageCode};
use crate::config::{
    CONNECT_TIMEOUT, ConnectionConfig, DISCONNECT_TIMEOUT, HEARTBEAT_ATTEMPTS, HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT, SECURE_KEEPALIVE_INTERVAL, SECURE_PROBE_TIMEOUT, SecureUser,
};
use crate::conn::{BusConnection, TimestampedFrame};
use crate::error::{Result, TransportError};
use crate::knxnet::{self, ConnectionHeader, FAMILY_DEVICE_MANAGEMENT, Hpai, ServiceType};
use crate::secure::UserKeys;
use crate::tpci::{self, TpciKind};
use crate::tunnel::{Link, UdpLink, connect_handshake, open_secure, udp_socket};

/// The KNXnet/IP Secure user id of the management user, the only user that
/// may open a device management connection inside a secure session (KNX IP
/// Secure 3/8/9 §2.2.1.4.2).
pub const MANAGEMENT_USER: u8 = 1;

/// How long a DEVICE_CONFIGURATION_REQUEST waits for its ACK over UDP
/// ("DEVICE_CONFIGURATION_REQUEST_TIMEOUT", 3/8/3 §2.3.2).
pub const DEVICE_CONFIGURATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an unacknowledged DEVICE_CONFIGURATION_REQUEST is repeated
/// before the connection is ended (3/8/3 §2.3.2).
pub const DEVICE_CONFIGURATION_REPEATS: u32 = 3;

/// `M_PropRead.req` (EMI 3/6/3 §4.1.7.3.2).
pub const M_PROP_READ_REQ: u8 = 0xFC;
/// `M_PropRead.con` (§4.1.7.3.3).
pub const M_PROP_READ_CON: u8 = 0xFB;
/// `M_PropWrite.req` (§4.1.7.3.4).
pub const M_PROP_WRITE_REQ: u8 = 0xF6;
/// `M_PropWrite.con` (§4.1.7.3.5).
pub const M_PROP_WRITE_CON: u8 = 0xF5;
/// `M_Reset.req`.
pub const M_RESET_REQ: u8 = 0xF1;
/// cEMI `T_Data_Connected.req` (§4.1.6.5.4).
pub const T_DATA_CONNECTED_REQ: u8 = 0x41;
/// cEMI `T_Data_Connected.ind` (§4.1.6.5.5).
pub const T_DATA_CONNECTED_IND: u8 = 0x89;
/// cEMI `T_Data_Individual.req` (§4.1.6.4.4).
pub const T_DATA_INDIVIDUAL_REQ: u8 = 0x4A;
/// cEMI `T_Data_Individual.ind` (§4.1.6.4.5).
pub const T_DATA_INDIVIDUAL_IND: u8 = 0x94;

/// `A_PropertyExtValue_Read`.
const A_PROPERTY_EXT_VALUE_READ: u16 = 0x1CC;
/// `A_PropertyExtValue_Response`.
const A_PROPERTY_EXT_VALUE_RESPONSE: u16 = 0x1CD;
/// `A_PropertyExtValue_WriteCon`.
const A_PROPERTY_EXT_VALUE_WRITE_CON: u16 = 0x1CE;
/// `A_PropertyExtValue_WriteConResponse`.
const A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE: u16 = 0x1CF;

/// The interface object property a local device management service
/// addresses: by object type and instance, never by index (3/8/3 §4.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalProperty {
    /// The interface object type.
    pub object_type: u16,
    /// The object instance, 1 for the first.
    pub instance: u8,
    /// The property id.
    pub pid: u8,
}

/// Encodes an `M_PropRead.req` (EMI 3/6/3 §4.1.7.3.2): `count` elements (at
/// most 15) from `start` (at most 4095). `None` when they do not fit.
pub fn prop_read_req(property: LocalProperty, count: u8, start: u16) -> Option<Vec<u8>> {
    prop_header(M_PROP_READ_REQ, property, count, start)
}

/// Encodes an `M_PropWrite.req` (EMI 3/6/3 §4.1.7.3.4) of `data`. `None` when
/// `count` or `start` do not fit, as for [`prop_read_req`].
pub fn prop_write_req(
    property: LocalProperty,
    count: u8,
    start: u16,
    data: &[u8],
) -> Option<Vec<u8>> {
    let mut out = prop_header(M_PROP_WRITE_REQ, property, count, start)?;
    out.extend_from_slice(data);
    Some(out)
}

/// The common header of the local property services.
fn prop_header(mc: u8, property: LocalProperty, count: u8, start: u16) -> Option<Vec<u8>> {
    if count > 0x0F || start > 0x0FFF {
        return None;
    }
    let [ot_hi, ot_lo] = property.object_type.to_be_bytes();
    let [six_hi, six_lo] = start.to_be_bytes();
    Some(vec![
        mc,
        ot_hi,
        ot_lo,
        property.instance,
        property.pid,
        (count << 4) | six_hi,
        six_lo,
    ])
}

/// A decoded `M_PropRead.con` or `M_PropWrite.con`.
#[derive(Clone, PartialEq, Eq)]
pub struct PropConfirmation {
    /// Whether it confirms a write.
    pub write: bool,
    /// The property it confirms.
    pub property: LocalProperty,
    /// The element count: 0 on a negative confirmation.
    pub count: u8,
    /// The start index.
    pub start: u16,
    /// The elements read (empty for a write and a negative confirmation).
    pub data: Vec<u8>,
    /// The error code of a negative confirmation (EMI 3/6/3 §4.1.7.3.7.2).
    pub error: Option<u8>,
}

impl std::fmt::Debug for PropConfirmation {
    // The data may be key material (a KNXnet/IP Secure property): never
    // format it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PropConfirmation")
            .field("write", &self.write)
            .field("property", &self.property)
            .field("count", &self.count)
            .field("start", &self.start)
            .field("data_len", &self.data.len())
            .field("error", &self.error)
            .finish()
    }
}

/// Decodes an `M_PropRead.con` / `M_PropWrite.con`; `None` for any other
/// frame or a truncated one.
pub fn decode_prop_con(cemi: &[u8]) -> Option<PropConfirmation> {
    let (&mc, rest) = cemi.split_first()?;
    let write = match mc {
        M_PROP_READ_CON => false,
        M_PROP_WRITE_CON => true,
        _ => return None,
    };
    let h = rest.get(..6)?;
    let property = LocalProperty {
        object_type: u16::from_be_bytes([h[0], h[1]]),
        instance: h[2],
        pid: h[3],
    };
    let count = h[4] >> 4;
    let start = (u16::from(h[4] & 0x0F) << 8) | u16::from(h[5]);
    let tail = rest.get(6..).unwrap_or_default();
    let (data, error) = if count == 0 {
        (Vec::new(), Some(tail.first().copied().unwrap_or(0)))
    } else if write {
        (Vec::new(), None)
    } else {
        (tail.to_vec(), None)
    };
    Some(PropConfirmation {
        write,
        property,
        count,
        start,
        data,
        error,
    })
}

/// The name of a cEMI local management error code (EMI 3/6/3 §4.1.7.3.7.2,
/// p. 107).
pub fn local_error_name(code: u8) -> &'static str {
    match code {
        0x00 => "unspecified error",
        0x01 => "out of range",
        0x02 => "out of max range",
        0x03 => "out of min range",
        0x04 => "memory error",
        0x05 => "read only",
        0x06 => "illegal command",
        0x07 => "void DP (no such property)",
        0x08 => "type conflict",
        0x09 => "property index range error",
        0x0A => "value temporarily not writeable",
        _ => "undefined",
    }
}

/// The application-layer return code (03_03_07 generic return codes) that
/// stands for a cEMI local management error in the extended response the
/// bridge hands the management layer.
fn return_code_of(error: u8) -> u8 {
    match error {
        0x01 => 0xF5,        // E_DATA_OVERFLOW
        0x02 => 0xF7,        // E_DATA_MAX
        0x03 => 0xF6,        // E_DATA_MIN
        0x04 => 0xF1,        // E_MEMORY_ERROR
        0x05 => 0xFB,        // E_ACCESS_READ_ONLY
        0x07 | 0x09 => 0xFD, // E_ADDRESS_VOID
        0x08 => 0xFE,        // E_DATA_TYPE_CONFLICT
        0x0A => 0xF9,        // E_TEMPORARILY_NOT_AVAILABLE
        _ => 0xFF,           // E_ERROR
    }
}

/// Encodes a cEMI `T_Data_Connected.req` (`connected`) or
/// `T_Data_Individual.req` carrying the APDU of `tpdu` (its first octet's
/// transport-control bits are cleared, as the frame's reserved bits are):
/// message code, no additional information, six reserved octets, the length
/// and the TPDU (EMI 3/6/3 §4.1.6.4.4, §4.1.6.5.4).
pub fn t_data_req(connected: bool, tpdu: &[u8]) -> Vec<u8> {
    let mc = if connected {
        T_DATA_CONNECTED_REQ
    } else {
        T_DATA_INDIVIDUAL_REQ
    };
    let mut out = vec![mc, 0x00, 0, 0, 0, 0, 0, 0];
    out.push(tpdu.len().saturating_sub(1) as u8);
    if let Some((&first, rest)) = tpdu.split_first() {
        out.push(first & 0x03);
        out.extend_from_slice(rest);
    }
    out
}

/// Decodes a cEMI `T_Data_Connected.ind` / `T_Data_Individual.ind` into
/// whether it is connected and its TPDU. `None` for any other frame.
pub fn decode_t_data_ind(cemi: &[u8]) -> Option<(bool, Vec<u8>)> {
    let connected = match *cemi.first()? {
        T_DATA_CONNECTED_IND => true,
        T_DATA_INDIVIDUAL_IND => false,
        _ => return None,
    };
    let add = usize::from(*cemi.get(1)?);
    let tpdu = cemi.get(2 + add + 7..)?;
    if tpdu.is_empty() {
        return None;
    }
    Some((connected, tpdu.to_vec()))
}

/// The local device management request that carries the extended property
/// APDU `apci`/`data`, when it is a read or a confirmed write whose fields fit
/// (see the module docs); with the count the confirmation must echo.
fn local_request(apci: u16, data: &[u8]) -> Option<(Vec<u8>, u8)> {
    let write = match apci {
        A_PROPERTY_EXT_VALUE_READ => false,
        A_PROPERTY_EXT_VALUE_WRITE_CON => true,
        _ => return None,
    };
    let h = data.get(..8)?;
    let object_type = u16::from_be_bytes([h[0], h[1]]);
    let packed = (u32::from(h[2]) << 16) | (u32::from(h[3]) << 8) | u32::from(h[4]);
    let instance = u8::try_from(packed >> 12).ok()?;
    let pid = u8::try_from(packed & 0x0FFF).ok()?;
    let count = h[5];
    let start = u16::from_be_bytes([h[6], h[7]]);
    let property = LocalProperty {
        object_type,
        instance,
        pid,
    };
    let cemi = if write {
        prop_write_req(property, count, start, data.get(8..).unwrap_or_default())?
    } else {
        prop_read_req(property, count, start)?
    };
    Some((cemi, count))
}

/// The extended response APDU that answers a local confirmation; `count` is
/// the element count of the request it confirms.
fn ext_response(con: &PropConfirmation, count: u8) -> (u16, Vec<u8>) {
    let packed = (u32::from(con.property.instance) << 12) | u32::from(con.property.pid);
    let mut out = con.property.object_type.to_be_bytes().to_vec();
    out.extend_from_slice(&packed.to_be_bytes()[1..]);
    if con.write {
        out.push(count);
        out.extend_from_slice(&con.start.to_be_bytes());
        out.push(con.error.map_or(0x00, return_code_of));
        (A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE, out)
    } else {
        out.push(con.count);
        out.extend_from_slice(&con.start.to_be_bytes());
        match con.error {
            Some(error) => out.push(return_code_of(error)),
            None => out.extend_from_slice(&con.data),
        }
        (A_PROPERTY_EXT_VALUE_RESPONSE, out)
    }
}

/// The TPDU octets of an `L_Data` frame, re-encoded.
fn tpdu_of(frame: &CemiFrame) -> Vec<u8> {
    let raw = frame.encode();
    let add = usize::from(raw.get(1).copied().unwrap_or(0));
    raw.get(2 + add + 7..).unwrap_or_default().to_vec()
}

/// The 10-bit APCI and the data after it of a TPDU.
fn apdu_of(tpdu: &[u8]) -> Option<(u16, &[u8])> {
    let hi = u16::from(*tpdu.first()? & 0x03);
    let lo = u16::from(*tpdu.get(1)?);
    Some(((hi << 8) | lo, tpdu.get(2..).unwrap_or_default()))
}

/// An `L_Data.ind` from `device` to `tool` with `tpdu` (its transport-control
/// bits replaced by `tpci`, or kept for a control frame without an APDU).
fn indication(
    tool: IndividualAddress,
    device: IndividualAddress,
    tpci: u8,
    tpdu: &[u8],
) -> Result<CemiFrame> {
    let mut raw = vec![MessageCode::LDataInd as u8, 0x00, 0xB0, 0x60];
    raw.extend_from_slice(&device.raw().to_be_bytes());
    raw.extend_from_slice(&tool.raw().to_be_bytes());
    raw.push(tpdu.len().saturating_sub(1) as u8);
    match tpdu.split_first() {
        Some((&first, rest)) => {
            raw.push(tpci | (first & 0x03));
            raw.extend_from_slice(rest);
        }
        None => raw.push(tpci),
    }
    CemiFrame::decode(&raw)
}

/// The management session the bridge serves and what it owes it.
#[derive(Debug, Default)]
struct Bridge {
    /// The tool and the device of the session (source and destination of the
    /// management layer's latest frame).
    peer: Option<(IndividualAddress, IndividualAddress)>,
    /// The sequence number of the next numbered telegram handed to the tool.
    device_seq: u8,
    /// The element counts of the local requests awaiting confirmation, in
    /// order.
    local: VecDeque<u8>,
    /// Frames for the management layer, delivered before anything from the
    /// server.
    pending: VecDeque<CemiFrame>,
}

impl Bridge {
    /// Turns one cEMI frame from the server into the frame the management
    /// layer would get from the device, if any.
    fn inbound(&mut self, cemi: &[u8]) -> Option<CemiFrame> {
        let Some((tool, device)) = self.peer else {
            tracing::debug!(code = ?cemi.first(), "device management: dropped a frame outside a session");
            return None;
        };
        let (connected, tpdu) = if let Some(con) = decode_prop_con(cemi) {
            let count = self.local.pop_front().unwrap_or(con.count);
            let (apci, data) = ext_response(&con, count);
            let mut tpdu = vec![(apci >> 8) as u8, apci as u8];
            tpdu.extend_from_slice(&data);
            (true, tpdu)
        } else if let Some(ind) = decode_t_data_ind(cemi) {
            ind
        } else {
            tracing::debug!(code = ?cemi.first(), "device management: ignored a frame");
            return None;
        };
        let tpci = if connected {
            let seq = self.device_seq;
            self.device_seq = (seq + 1) & 0x0F;
            tpci::ndt(seq)
        } else {
            0x00
        };
        match indication(tool, device, tpci, &tpdu) {
            Ok(frame) => Some(frame),
            Err(err) => {
                tracing::debug!(%err, "device management: could not build an indication");
                None
            }
        }
    }
}

/// Command sent from a [`DeviceManagement`] handle to its task.
enum Command {
    /// Send one cEMI frame; reply once the server has it.
    Send {
        cemi: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Disconnect; reply when done.
    Close { reply: oneshot::Sender<Result<()>> },
}

/// A KNXnet/IP device management connection (see the module docs).
pub struct DeviceManagement {
    commands: mpsc::Sender<Command>,
    frames: mpsc::UnboundedReceiver<Result<Vec<u8>>>,
    task: Option<JoinHandle<()>>,
    secure_user: Option<u8>,
    bridge: Bridge,
}

impl DeviceManagement {
    /// Opens a device management connection to the server named in
    /// `config.gateway`.
    ///
    /// Inside a KNXnet/IP Secure session when `config.secure` lists the
    /// management user ([`MANAGEMENT_USER`]) and the server does not answer
    /// its extended description with device management unsecured; over
    /// plain UDP otherwise. A plain CONNECT the server refuses because device
    /// management is a secured service family there becomes
    /// [`TransportError::SecureRequired`].
    ///
    /// # Errors
    ///
    /// No gateway configured, the session or the CONNECT failing or being
    /// refused.
    pub async fn connect(config: &ConnectionConfig) -> Result<Self> {
        let gateway = config.gateway.ok_or(TransportError::InvalidField {
            field: "device management gateway (none configured)",
            value: 0,
        })?;
        let user = management_user(config, gateway).await;
        let (mut link, hpai) = match &user {
            Some(user) => {
                let keys = UserKeys::derive(user);
                let requested = config
                    .secure
                    .as_ref()
                    .map(|s| s.transport)
                    .unwrap_or_default();
                let link = open_secure(
                    gateway,
                    config.local_interface,
                    &keys,
                    requested,
                    None,
                    CONNECT_TIMEOUT,
                )
                .await?;
                let hpai = link.hpai();
                (Link::Secure(Box::new(link)), hpai)
            }
            None => {
                let (socket, hpai) = udp_socket(gateway, config.local_interface).await?;
                (Link::Udp(UdpLink::new(socket, gateway)), hpai)
            }
        };
        let request = knxnet::connect_request_device_mgmt(hpai, hpai);
        let granted = match connect_handshake(&mut link, &request).await {
            Ok(granted) => granted,
            Err(err) => {
                link.close().await;
                return Err(match err {
                    TransportError::GatewayStatus { status: 0x22, .. }
                        if user.is_none() && secures_device_management(gateway).await =>
                    {
                        TransportError::SecureRequired {
                            gateway,
                            reason: "device management is a secured service there and no \
                                     management user (user 1) password was given"
                                .to_string(),
                        }
                    }
                    other => other,
                });
            }
        };
        let secure_user = user.as_ref().map(|u| u.user_id);
        tracing::info!(
            channel = granted.channel_id,
            secure = secure_user.is_some(),
            "device management connection to {gateway} established"
        );
        let keepalive = config
            .secure
            .as_ref()
            .map(|s| s.keepalive)
            .unwrap_or(SECURE_KEEPALIVE_INTERVAL);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        let task = Task {
            link,
            channel: granted.channel_id,
            hpai,
            tx_seq: 0,
            rx_seq: 0,
            commands: cmd_rx,
            frames: frame_tx,
            keepalive,
            ack_timeout: DEVICE_CONFIGURATION_REQUEST_TIMEOUT,
        };
        Ok(DeviceManagement {
            commands: cmd_tx,
            frames: frame_rx,
            task: Some(tokio::spawn(task.run())),
            secure_user,
            bridge: Bridge::default(),
        })
    }

    /// The KNXnet/IP Secure user the connection authenticated as
    /// ([`MANAGEMENT_USER`]), or `None` over plain UDP.
    pub fn secure_user_id(&self) -> Option<u8> {
        self.secure_user
    }

    /// Sends one raw cEMI frame (a local management request or a cEMI
    /// transport-layer frame), returning once the server has it.
    ///
    /// # Errors
    ///
    /// The connection is closed or lost, or the server did not acknowledge
    /// the request after its repeats.
    pub async fn send_cemi(&self, cemi: Vec<u8>) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Send { cemi, reply })
            .await
            .map_err(|_| TransportError::Closed)?;
        rx.await.map_err(|_| TransportError::Closed)?
    }

    /// Receives the next raw cEMI frame from the server.
    ///
    /// Use it or the [`BusConnection`] bridge on one connection, not both:
    /// both take frames from the same queue. Cancel-safe.
    ///
    /// # Errors
    ///
    /// The connection is closed or lost.
    pub async fn recv_cemi(&mut self) -> Result<Vec<u8>> {
        self.frames.recv().await.ok_or(TransportError::Closed)?
    }

    /// Sends a local device management request and waits up to `timeout`
    /// for its confirmation, skipping any other frame meanwhile.
    ///
    /// # Errors
    ///
    /// As [`send_cemi`](Self::send_cemi); [`TransportError::Timeout`] when no
    /// confirmation came.
    pub async fn request_local(
        &mut self,
        cemi: Vec<u8>,
        timeout: Duration,
    ) -> Result<PropConfirmation> {
        self.send_cemi(cemi).await?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let frame = time::timeout(remaining, self.recv_cemi())
                .await
                .map_err(|_| TransportError::Timeout("M_PropRead.con / M_PropWrite.con"))??;
            if let Some(con) = decode_prop_con(&frame) {
                return Ok(con);
            }
        }
    }
}

/// The management user to open a secure session with, if `config` names
/// one and the server does not say device management is unsecured.
async fn management_user(config: &ConnectionConfig, gateway: SocketAddrV4) -> Option<SecureUser> {
    let user = config
        .secure
        .as_ref()?
        .users
        .iter()
        .find(|u| u.user_id == MANAGEMENT_USER)?
        .clone();
    match device_management_secured(gateway).await {
        Some(false) => {
            tracing::debug!(
                "{gateway} does not secure device management; connecting without a session"
            );
            None
        }
        // Secured, or unanswered: the credentials decide.
        Some(true) | None => Some(user),
    }
}

/// Whether the server's extended description lists device management among
/// its secured service families; `None` when it does not answer.
async fn device_management_secured(gateway: SocketAddrV4) -> Option<bool> {
    let description = crate::discovery::describe_gateway_extended(gateway, SECURE_PROBE_TIMEOUT)
        .await
        .ok()?;
    Some(
        description
            .secured_service_families
            .as_ref()
            .is_some_and(|f| {
                f.iter()
                    .any(|&(family, _)| family == FAMILY_DEVICE_MANAGEMENT)
            }),
    )
}

/// Whether the server is known to secure device management.
async fn secures_device_management(gateway: SocketAddrV4) -> bool {
    device_management_secured(gateway).await == Some(true)
}

impl BusConnection for DeviceManagement {
    async fn send(&mut self, frame: CemiFrame) -> Result<()> {
        if frame.message_code != MessageCode::LDataReq {
            return Ok(());
        }
        let Destination::Individual(device) = frame.destination else {
            return Err(TransportError::NotOnDeviceManagement {
                what: "group or broadcast telegrams",
            });
        };
        let tool = frame.source;
        match tpci::classify(frame.tpci_octet()) {
            TpciKind::Connect => {
                self.bridge.peer = Some((tool, device));
                self.bridge.device_seq = 0;
                self.bridge.local.clear();
                Ok(())
            }
            TpciKind::Disconnect => {
                self.bridge.peer = None;
                Ok(())
            }
            TpciKind::Ack(_) | TpciKind::Nak(_) | TpciKind::Unknown(_) => Ok(()),
            TpciKind::NumberedData(seq) => {
                self.bridge.peer = Some((tool, device));
                let tpdu = tpdu_of(&frame);
                let local = apdu_of(&tpdu).and_then(|(apci, data)| local_request(apci, data));
                match local {
                    Some((cemi, count)) => {
                        self.bridge.local.push_back(count);
                        if let Err(err) = self.send_cemi(cemi).await {
                            self.bridge.local.pop_back();
                            return Err(err);
                        }
                    }
                    None => self.send_cemi(t_data_req(true, &tpdu)).await?,
                }
                // T_Data_Connected.con (3/8/3 §2.6.1.4): the peer's T_ACK.
                let mut ack = CemiFrame::t_control(tool, device, tpci::t_ack(seq));
                ack.message_code = MessageCode::LDataInd;
                self.bridge.pending.push_back(ack);
                Ok(())
            }
            TpciKind::UnnumberedData => {
                if self.bridge.peer.is_none() {
                    self.bridge.peer = Some((tool, device));
                }
                self.send_cemi(t_data_req(false, &tpdu_of(&frame))).await
            }
        }
    }

    async fn recv(&mut self) -> Result<TimestampedFrame> {
        loop {
            if let Some(frame) = self.bridge.pending.pop_front() {
                return Ok(TimestampedFrame {
                    received_at: SystemTime::now(),
                    frame,
                });
            }
            let cemi = self.recv_cemi().await?;
            if let Some(frame) = self.bridge.inbound(&cemi) {
                self.bridge.pending.push_back(frame);
            }
        }
    }

    async fn close(mut self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        if self.commands.send(Command::Close { reply }).await.is_ok() {
            let _ = rx.await;
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        Ok(())
    }
}

/// The task that owns the link of one device management connection.
struct Task {
    link: Link,
    channel: u8,
    hpai: Hpai,
    tx_seq: u8,
    rx_seq: u8,
    commands: mpsc::Receiver<Command>,
    frames: mpsc::UnboundedSender<Result<Vec<u8>>>,
    keepalive: Duration,
    /// [`DEVICE_CONFIGURATION_REQUEST_TIMEOUT`]; shorter in the unit tests.
    ack_timeout: Duration,
}

impl Task {
    async fn run(mut self) {
        let mut buf = vec![0u8; 1024];
        let mut next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
        let secure = !self.link.is_udp() && !self.keepalive.is_zero();
        let mut next_keepalive = Instant::now() + self.keepalive;
        loop {
            let keepalive_at = if secure {
                next_keepalive
            } else {
                // Never: a day out.
                Instant::now() + Duration::from_secs(86_400)
            };
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(Command::Send { cemi, reply }) => {
                        let result = self.send(&cemi, &mut buf).await;
                        let failed = result.is_err();
                        let _ = reply.send(result);
                        if failed {
                            self.fail(TransportError::Timeout("DEVICE_CONFIGURATION_ACK"), &mut buf)
                                .await;
                            return;
                        }
                        next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
                    }
                    Some(Command::Close { reply }) => {
                        let result = self.disconnect(&mut buf).await;
                        self.link.close().await;
                        let _ = reply.send(result);
                        return;
                    }
                    None => {
                        let _ = self.disconnect(&mut buf).await;
                        self.link.close().await;
                        return;
                    }
                },
                received = self.link.recv(&mut buf) => match received {
                    Ok(n) => {
                        let datagram = buf[..n].to_vec();
                        if !self.handle_inbound(&datagram).await {
                            self.link.close().await;
                            return;
                        }
                    }
                    Err(err) => {
                        let _ = self.frames.send(Err(err));
                        self.link.close().await;
                        return;
                    }
                },
                () = time::sleep_until(next_heartbeat) => {
                    if let Err(err) = self.heartbeat(&mut buf).await {
                        self.fail(err, &mut buf).await;
                        return;
                    }
                    next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
                }
                () = time::sleep_until(keepalive_at) => {
                    if let Err(err) = self.link.keepalive().await {
                        let _ = self.frames.send(Err(err));
                        self.link.close().await;
                        return;
                    }
                    next_keepalive = Instant::now() + self.keepalive;
                }
            }
        }
    }

    /// Ends the connection after `err`: a DISCONNECT_REQUEST (best effort),
    /// the session closed, the error delivered to the reader.
    async fn fail(&mut self, err: TransportError, buf: &mut [u8]) {
        let _ = self.disconnect(buf).await;
        self.link.close().await;
        let _ = self.frames.send(Err(err));
    }

    /// Sends one DEVICE_CONFIGURATION_REQUEST; over UDP waits for its ACK,
    /// repeating it as 3/8/3 §2.3.2 says.
    async fn send(&mut self, cemi: &[u8], buf: &mut [u8]) -> Result<()> {
        let seq = self.tx_seq;
        let request = knxnet::device_configuration_request(
            ConnectionHeader {
                channel_id: self.channel,
                seq,
            },
            cemi,
        );
        if !self.link.acks() {
            self.link.send_data(&request).await?;
            self.tx_seq = seq.wrapping_add(1);
            return Ok(());
        }
        for attempt in 0..=DEVICE_CONFIGURATION_REPEATS {
            if attempt > 0 {
                tracing::debug!(seq, attempt, "repeating a DEVICE_CONFIGURATION_REQUEST");
            }
            self.link.send_data(&request).await?;
            let deadline = Instant::now() + self.ack_timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok(received) = time::timeout(remaining, self.link.recv(buf)).await else {
                    break;
                };
                let datagram = buf[..received?].to_vec();
                let Ok(parsed) = knxnet::parse(&datagram) else {
                    continue;
                };
                if parsed.service == ServiceType::DeviceConfigurationAck {
                    let Ok((header, status)) = knxnet::parse_tunneling_ack(parsed.body) else {
                        continue;
                    };
                    if header.channel_id != self.channel || header.seq != seq {
                        continue;
                    }
                    if status == 0 {
                        self.tx_seq = seq.wrapping_add(1);
                        return Ok(());
                    }
                    tracing::debug!(seq, status, "DEVICE_CONFIGURATION_ACK with an error");
                    break;
                }
                if !self.handle_inbound(&datagram).await {
                    return Err(TransportError::Disconnected(self.channel));
                }
            }
        }
        Err(TransportError::Timeout("DEVICE_CONFIGURATION_ACK"))
    }

    /// Handles one datagram from the server; `false` when the server ended
    /// the connection.
    async fn handle_inbound(&mut self, datagram: &[u8]) -> bool {
        let Ok(parsed) = knxnet::parse(datagram) else {
            return true;
        };
        match parsed.service {
            ServiceType::DeviceConfigurationRequest => {
                let Ok((header, cemi)) = knxnet::parse_tunneling_header(parsed.body) else {
                    return true;
                };
                if header.channel_id != self.channel {
                    return true;
                }
                if self.link.acks() {
                    let expected = self.rx_seq;
                    if header.seq == expected.wrapping_sub(1) {
                        // A repeat of the last one: our ACK was lost.
                        let ack = knxnet::device_configuration_ack(self.channel, header.seq, 0);
                        let _ = self.link.send_data(&ack).await;
                        return true;
                    }
                    if header.seq != expected {
                        tracing::debug!(
                            seq = header.seq,
                            expected,
                            "discarded a DEVICE_CONFIGURATION_REQUEST out of sequence"
                        );
                        return true;
                    }
                    let ack = knxnet::device_configuration_ack(self.channel, header.seq, 0);
                    if let Err(err) = self.link.send_data(&ack).await {
                        let _ = self.frames.send(Err(err));
                        return false;
                    }
                    self.rx_seq = expected.wrapping_add(1);
                }
                let _ = self.frames.send(Ok(cemi.to_vec()));
                true
            }
            ServiceType::DisconnectRequest => match knxnet::parse_disconnect_request(parsed.body) {
                Ok(channel) if channel == self.channel => {
                    let response = knxnet::disconnect_response(self.channel, 0);
                    let _ = self.link.send(&response).await;
                    let _ = self
                        .frames
                        .send(Err(TransportError::Disconnected(self.channel)));
                    false
                }
                _ => true,
            },
            _ => true,
        }
    }

    /// Sends CONNECTIONSTATE_REQUESTs until one is answered with success,
    /// as a tunnel does (Core 3/8/2 §5.4).
    async fn heartbeat(&mut self, buf: &mut [u8]) -> Result<()> {
        let request = knxnet::connectionstate_request(self.channel, self.hpai);
        for _ in 0..HEARTBEAT_ATTEMPTS {
            self.link.send(&request).await?;
            let deadline = Instant::now() + HEARTBEAT_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Ok(received) = time::timeout(remaining, self.link.recv(buf)).await else {
                    break;
                };
                let datagram = buf[..received?].to_vec();
                let Ok(parsed) = knxnet::parse(&datagram) else {
                    continue;
                };
                if parsed.service == ServiceType::ConnectionstateResponse {
                    if let Ok(status) = knxnet::parse_channel_status(parsed.body)
                        && status.channel_id == self.channel
                    {
                        if status.status == 0 {
                            return Ok(());
                        }
                        break;
                    }
                } else if !self.handle_inbound(&datagram).await {
                    return Err(TransportError::Disconnected(self.channel));
                }
            }
        }
        Err(TransportError::HeartbeatLost)
    }

    /// The DISCONNECT_REQUEST / DISCONNECT_RESPONSE exchange (best effort).
    async fn disconnect(&mut self, buf: &mut [u8]) -> Result<()> {
        let request = knxnet::disconnect_request(self.channel, self.hpai);
        self.link.send(&request).await?;
        let deadline = Instant::now() + DISCONNECT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match time::timeout(remaining, self.link.recv(buf)).await {
                Ok(Ok(n)) => {
                    if let Ok(parsed) = knxnet::parse(&buf[..n])
                        && parsed.service == ServiceType::DisconnectResponse
                    {
                        return Ok(());
                    }
                }
                Ok(Err(_)) | Err(_) => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type BoxError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = std::result::Result<(), BoxError>;

    const KNXNET: LocalProperty = LocalProperty {
        object_type: 11,
        instance: 1,
        pid: 76,
    };

    #[test]
    fn test_prop_read_req_encodes_type_instance_and_element_window() -> TestResult {
        let req = prop_read_req(KNXNET, 1, 0).ok_or("fits")?;
        assert_eq!(req, vec![0xFC, 0x00, 0x0B, 0x01, 76, 0x10, 0x00]);
        assert_eq!(prop_read_req(KNXNET, 16, 0), None);
        assert_eq!(prop_read_req(KNXNET, 1, 0x1000), None);
        Ok(())
    }

    #[test]
    fn test_decode_prop_con_reads_data_and_negative_confirmations() -> TestResult {
        let con = decode_prop_con(&[0xFB, 0x00, 0x0B, 0x01, 76, 0x10, 0x01, b'A', b'B'])
            .ok_or("decodes")?;
        assert_eq!((con.write, con.count, con.start), (false, 1, 1));
        assert_eq!(con.data, b"AB");
        assert_eq!(con.error, None);
        let neg =
            decode_prop_con(&[0xF5, 0x00, 0x0B, 0x01, 76, 0x00, 0x01, 0x05]).ok_or("decodes")?;
        assert_eq!((neg.write, neg.count, neg.error), (true, 0, Some(0x05)));
        assert!(decode_prop_con(&[0x29, 0x00]).is_none());
        Ok(())
    }

    #[test]
    fn test_t_data_req_clears_the_transport_bits_and_counts_the_npdu() {
        // A_DeviceDescriptor_Read (0x300) as numbered data with sequence 3.
        let req = t_data_req(true, &[0x4F, 0x00]);
        assert_eq!(req, vec![0x41, 0x00, 0, 0, 0, 0, 0, 0, 0x01, 0x03, 0x00]);
        let ind = t_data_req(false, &[0x03, 0x40, 0x07, 0xB0]);
        assert_eq!(ind[0], 0x4A);
        assert_eq!(ind[8], 3);
    }

    #[test]
    fn test_decode_t_data_ind_returns_the_tpdu() -> TestResult {
        let (connected, tpdu) =
            decode_t_data_ind(&[0x89, 0x00, 0, 0, 0, 0, 0, 0, 0x03, 0x03, 0x40, 0x07, 0xB0])
                .ok_or("decodes")?;
        assert!(connected);
        assert_eq!(tpdu, vec![0x03, 0x40, 0x07, 0xB0]);
        assert!(decode_t_data_ind(&[0xFB, 0x00]).is_none());
        Ok(())
    }

    #[test]
    fn test_local_request_maps_ext_read_and_write_con_only() -> TestResult {
        // Object type 11, instance 1, PID 76, count 1, start 1.
        let header = [0x00, 0x0B, 0x00, 0x10, 76, 0x01, 0x00, 0x01];
        let (read, count) =
            local_request(A_PROPERTY_EXT_VALUE_READ, &header).ok_or("a local read")?;
        assert_eq!(read, vec![0xFC, 0x00, 0x0B, 0x01, 76, 0x10, 0x01]);
        assert_eq!(count, 1);
        let mut write = header.to_vec();
        write.extend_from_slice(b"xy");
        let (cemi, _) =
            local_request(A_PROPERTY_EXT_VALUE_WRITE_CON, &write).ok_or("a local write")?;
        assert_eq!(cemi[0], M_PROP_WRITE_REQ);
        assert_eq!(&cemi[7..], b"xy");
        // An instance above 255 stays a transport-layer request.
        let wide = [0x00, 0x0B, 0x10, 0x00, 76, 0x01, 0x00, 0x01];
        assert!(local_request(A_PROPERTY_EXT_VALUE_READ, &wide).is_none());
        assert!(local_request(0x3D5, &header).is_none());
        Ok(())
    }

    #[test]
    fn test_ext_response_answers_a_write_with_the_requested_count() {
        let con = PropConfirmation {
            write: true,
            property: KNXNET,
            count: 0,
            start: 1,
            data: Vec::new(),
            error: Some(0x05),
        };
        let (apci, data) = ext_response(&con, 2);
        assert_eq!(apci, A_PROPERTY_EXT_VALUE_WRITE_CON_RESPONSE);
        assert_eq!(data, vec![0x00, 0x0B, 0x00, 0x10, 76, 2, 0x00, 0x01, 0xFB]);
    }

    /// A task on a UDP link to a scripted server socket, with `ack_timeout`.
    async fn udp_task(
        ack_timeout: Duration,
    ) -> std::result::Result<(Task, tokio::net::UdpSocket), BoxError> {
        let server =
            tokio::net::UdpSocket::bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0))
                .await?;
        let std::net::SocketAddr::V4(addr) = server.local_addr()? else {
            return Err("IPv6".into());
        };
        let (socket, hpai) = udp_socket(addr, std::net::Ipv4Addr::LOCALHOST).await?;
        let (_cmd_tx, commands) = mpsc::channel(1);
        let (frames, _rx) = mpsc::unbounded_channel();
        let task = Task {
            link: Link::Udp(UdpLink::new(socket, addr)),
            channel: 0x81,
            hpai,
            tx_seq: 0,
            rx_seq: 0,
            commands,
            frames,
            keepalive: Duration::ZERO,
            ack_timeout,
        };
        Ok((task, server))
    }

    /// Receives one KNXnet/IP frame on the server socket: its service and
    /// body.
    async fn next_frame(
        server: &tokio::net::UdpSocket,
    ) -> std::result::Result<(ServiceType, Vec<u8>, std::net::SocketAddr), BoxError> {
        let mut buf = [0u8; 256];
        let (n, from) = time::timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await??;
        let parsed = knxnet::parse(&buf[..n])?;
        Ok((parsed.service, parsed.body.to_vec(), from))
    }

    #[tokio::test]
    async fn test_task_send_repeats_an_unacknowledged_request_then_disconnects() -> TestResult {
        let (mut task, server) = udp_task(Duration::from_millis(50)).await?;
        let mut buf = vec![0u8; 512];
        let script = tokio::spawn(async move {
            let mut seqs = Vec::new();
            loop {
                let (service, body, from) = next_frame(&server).await?;
                match service {
                    ServiceType::DeviceConfigurationRequest => seqs.push(body[2]),
                    ServiceType::DisconnectRequest => {
                        let response = knxnet::disconnect_response(body[0], 0);
                        server.send_to(&response, from).await?;
                        return Ok::<_, BoxError>(seqs);
                    }
                    _ => {}
                }
            }
        });
        let result = task.send(&[M_RESET_REQ], &mut buf).await;
        assert!(
            matches!(result, Err(TransportError::Timeout(_))),
            "{result:?}"
        );
        task.disconnect(&mut buf).await?;
        let seqs = script.await?.map_err(|e| e.to_string())?;
        // The request and its three repeats, all under sequence 0.
        assert_eq!(seqs, vec![0, 0, 0, 0]);
        Ok(())
    }

    #[tokio::test]
    async fn test_task_send_repeats_after_an_error_ack_and_counts_on_success() -> TestResult {
        let (mut task, server) = udp_task(Duration::from_secs(2)).await?;
        let mut buf = vec![0u8; 512];
        let script = tokio::spawn(async move {
            let mut statuses = vec![0x29u8, 0x00, 0x00];
            let mut seqs = Vec::new();
            while !statuses.is_empty() {
                let (service, body, from) = next_frame(&server).await?;
                if service == ServiceType::DeviceConfigurationRequest {
                    seqs.push(body[2]);
                    let ack =
                        knxnet::device_configuration_ack(body[1], body[2], statuses.remove(0));
                    server.send_to(&ack, from).await?;
                }
            }
            Ok::<_, BoxError>(seqs)
        });
        task.send(&[M_RESET_REQ], &mut buf).await?;
        task.send(&[M_RESET_REQ], &mut buf).await?;
        let seqs = script.await?.map_err(|e| e.to_string())?;
        // An error status repeats the request; the next one counts on.
        assert_eq!(seqs, vec![0, 0, 1]);
        Ok(())
    }

    #[tokio::test]
    async fn test_task_handle_inbound_acks_in_sequence_and_discards_the_rest() -> TestResult {
        let (mut task, server) = udp_task(Duration::from_secs(2)).await?;
        let (frames_tx, mut frames_rx) = mpsc::unbounded_channel();
        task.frames = frames_tx;
        let request = |seq: u8| {
            knxnet::device_configuration_request(
                ConnectionHeader {
                    channel_id: 0x81,
                    seq,
                },
                &[0xFB, 0x00],
            )
        };
        assert!(task.handle_inbound(&request(0)).await);
        assert!(task.handle_inbound(&request(0)).await); // a repeat: ACKed again
        assert!(task.handle_inbound(&request(5)).await); // out of sequence
        assert!(task.handle_inbound(&request(1)).await);
        let mut acked = Vec::new();
        for _ in 0..3 {
            let (service, body, _) = next_frame(&server).await?;
            assert_eq!(service, ServiceType::DeviceConfigurationAck);
            acked.push(body[2]);
        }
        assert_eq!(acked, vec![0, 0, 1]);
        let mut delivered = 0;
        while frames_rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 2);
        Ok(())
    }

    #[test]
    fn test_bridge_inbound_numbers_connected_answers_from_the_device() -> TestResult {
        let tool = IndividualAddress::from_raw(0x0000);
        let device: IndividualAddress = "1.1.200".parse()?;
        let mut bridge = Bridge {
            peer: Some((tool, device)),
            ..Bridge::default()
        };
        bridge.local.push_back(1);
        let first = bridge
            .inbound(&[0xFB, 0x00, 0x0B, 0x01, 76, 0x10, 0x01, b'A'])
            .ok_or("an answer")?;
        assert_eq!(first.source, device);
        assert_eq!(first.tpci_octet() & 0xFC, tpci::ndt(0));
        let second = bridge
            .inbound(&[0x89, 0x00, 0, 0, 0, 0, 0, 0, 0x03, 0x03, 0x40, 0x07, 0xB0])
            .ok_or("an answer")?;
        assert_eq!(second.tpci_octet() & 0xFC, tpci::ndt(1));
        Ok(())
    }
}
