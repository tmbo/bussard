//! cEMI (common External Message Interface) `L_Data` codec.
//!
//! This module is pure (no I/O) and heavily unit-tested. It encodes and decodes
//! the cEMI frames that carry KNX link-layer telegrams inside KNXnet/IP:
//! `L_Data.req` (0x11), `L_Data.con` (0x2E) and `L_Data.ind` (0x29).
//!
//! # Frame layout
//!
//! ```text
//! +--------+----------+-----------+------+------+--------+------+--------+-----+------+
//! | msgcode| AI-len   | AI-bytes… | CTL1 | CTL2 | src IA | dst  | NPDU   | TPCI | APDU |
//! |  1 B   |  1 B     |  0..n B   | 1 B  | 1 B  |  2 B   | 2 B  | len 1B | /APCI + data|
//! +--------+----------+-----------+------+------+--------+------+--------+------+------+
//! ```
//!
//! - **CTL1** (control field 1): bit7 frame type (1 = standard/short, 0 = extended),
//!   bit5 repeat (0 = repeated), bit4 system-broadcast, bits3-2 priority,
//!   bit1 ack-request, bit0 confirm/error.
//! - **CTL2** (control field 2): bit7 destination address type (1 = group,
//!   0 = individual), bits6-4 hop count, bits3-0 extended frame format.
//! - **NPDU length**: number of APDU octets *after* the length byte, **not counting**
//!   the octet that holds the TPCI/APCI high bits.
//! - **TPCI/APCI**: two octets. The KNX application layer packs the 10-bit APCI so
//!   the top 6 bits live in octet 0 (bits 1-0) + octet 1 (bits 7-6), and small
//!   payloads (≤ 6 bits) are packed into the low 6 bits of octet 1 — see
//!   [`Apdu`] for the gory detail.

use bussard_model::{GroupAddress, IndividualAddress};

use crate::error::{Result, TransportError};

/// cEMI message code identifying the L_Data primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageCode {
    /// `L_Data.req` — a request to transmit (tool → bus). Value `0x11`.
    LDataReq = 0x11,
    /// `L_Data.con` — local confirmation that a request was sent. Value `0x2E`.
    LDataCon = 0x2E,
    /// `L_Data.ind` — an indication of a received telegram (bus → tool). Value `0x29`.
    LDataInd = 0x29,
}

impl MessageCode {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x11 => Ok(MessageCode::LDataReq),
            0x2E => Ok(MessageCode::LDataCon),
            0x29 => Ok(MessageCode::LDataInd),
            other => Err(TransportError::InvalidField {
                field: "cEMI message code",
                value: other as u16,
            }),
        }
    }
}

/// KNX telegram priority (control field 1, bits 3-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Priority {
    /// System priority (highest). Value `0b00`.
    System = 0,
    /// Normal priority. Value `0b01`.
    #[default]
    Normal = 1,
    /// Urgent priority. Value `0b10`.
    Urgent = 2,
    /// Low priority. Value `0b11`.
    Low = 3,
}

impl Priority {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Priority::System,
            2 => Priority::Urgent,
            3 => Priority::Low,
            _ => Priority::Normal,
        }
    }
}

/// Control field 1: transmission attributes of the frame.
///
/// Bit meanings follow EN 50090 / the cEMI spec. Defaults match a typical
/// outgoing `GroupValueWrite` (standard frame, not repeated, normal priority,
/// ack requested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control1 {
    /// Frame type: `true` = standard (short) frame, `false` = extended frame.
    pub standard_frame: bool,
    /// Repeat flag: `true` means this frame is a repetition.
    pub repeated: bool,
    /// System-broadcast flag (bit 4). `true` = broadcast on the domain.
    pub system_broadcast: bool,
    /// Telegram priority.
    pub priority: Priority,
    /// Acknowledge-request flag.
    pub ack_requested: bool,
    /// Confirm/error flag: on an `L_Data.con`, `true` means the transmission failed.
    pub error: bool,
}

impl Default for Control1 {
    fn default() -> Self {
        Control1 {
            standard_frame: true,
            repeated: false,
            system_broadcast: true,
            priority: Priority::Normal,
            ack_requested: true,
            error: false,
        }
    }
}

impl Control1 {
    fn from_byte(b: u8) -> Self {
        Control1 {
            standard_frame: b & 0x80 != 0,
            // Bit 5: 0 = repeated (repetition allowed / this is a repeat), 1 = not repeated.
            repeated: b & 0x20 == 0,
            system_broadcast: b & 0x10 != 0,
            priority: Priority::from_bits(b >> 2),
            ack_requested: b & 0x02 != 0,
            error: b & 0x01 != 0,
        }
    }

    fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.standard_frame {
            b |= 0x80;
        }
        if !self.repeated {
            b |= 0x20;
        }
        if self.system_broadcast {
            b |= 0x10;
        }
        b |= (self.priority as u8) << 2;
        if self.ack_requested {
            b |= 0x02;
        }
        if self.error {
            b |= 0x01;
        }
        b
    }
}

/// Control field 2: addressing attributes of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control2 {
    /// Destination address type: `true` = group address, `false` = individual.
    pub group_address: bool,
    /// Routing hop count (0-7). Decremented by each coupler; 0 drops the frame.
    pub hop_count: u8,
    /// Extended frame format nibble (0 for standard frames).
    pub extended_frame_format: u8,
}

impl Default for Control2 {
    fn default() -> Self {
        Control2 {
            group_address: true,
            hop_count: 6,
            extended_frame_format: 0,
        }
    }
}

impl Control2 {
    fn from_byte(b: u8) -> Self {
        Control2 {
            group_address: b & 0x80 != 0,
            hop_count: (b >> 4) & 0x07,
            extended_frame_format: b & 0x0f,
        }
    }

    fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.group_address {
            b |= 0x80;
        }
        b |= (self.hop_count & 0x07) << 4;
        b |= self.extended_frame_format & 0x0f;
        b
    }
}

/// The destination of an L_Data frame: a group or an individual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// A group address (multicast to all listeners).
    Group(GroupAddress),
    /// An individual (physical) device address.
    Individual(IndividualAddress),
}

/// The Transport-layer PDU kind carried in the two high bits of the first APDU
/// octet (bits 7-6 of the TPCI byte).
///
/// bussard phase 0 only needs the connectionless data primitives; the
/// connection-oriented management primitives (T_Connect, T_Disconnect, numbered
/// data) are carried through as [`Tpci::Other`] so nothing panics on
/// management traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpci {
    /// `T_Data_Group` unnumbered data telegram (UDT/NDT), TPCI high bits `00`.
    /// This is what group value services use.
    DataGroup,
    /// A transport-control frame with no application layer: `T_Connect`,
    /// `T_Disconnect`, `T_ACK`, `T_NAK`. The full raw TPCI octet is preserved and
    /// there is no APDU (the paired [`Apdu`] is [`Apdu::Empty`]). This is a
    /// decode-time refinement of [`Tpci::Other`] for the single-octet
    /// connection-control telegrams the management layer sends and receives.
    Control(u8),
    /// Any other TPCI (connection-oriented numbered data, etc.). The full raw
    /// first octet is preserved so the frame round-trips untouched.
    Other(u8),
}

/// Application-layer service (APCI) plus its payload.
///
/// The three group-value services carry a payload that is either **packed into
/// the low 6 bits of the second APDU octet** (when it is a single 6-bit value —
/// the classic 1-bit switch, or a small scene number) or **appended as separate
/// octets** (for larger DPTs). This distinction is the trickiest part of the
/// KNX application layer and is captured explicitly here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Apdu {
    /// `GroupValueRead` (APCI `0x000`). No payload.
    GroupValueRead,
    /// `GroupValueResponse` (APCI `0x040`).
    GroupValueResponse(GroupData),
    /// `GroupValueWrite` (APCI `0x080`).
    GroupValueWrite(GroupData),
    /// Any other APCI service (management, etc.), preserved verbatim: the raw
    /// 10-bit APCI value and any trailing data octets. Never panics on unknown
    /// services.
    Other {
        /// The 10-bit APCI value.
        apci: u16,
        /// Trailing data octets after the APCI octets.
        data: Vec<u8>,
    },
    /// No application layer at all: the frame is a single-octet transport-control
    /// telegram (`T_Connect` / `T_Disconnect` / `T_ACK` / `T_NAK`). Paired with
    /// [`Tpci::Control`]. Its on-wire NPDU length is 0 (one TPDU octet total).
    Empty,
}

/// The payload of a group-value service, tagging the "small" packed form apart
/// from the "large" multi-octet form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupData {
    /// A value that fits in 6 bits, packed into the APCI's low bits (the on-wire
    /// APDU length is 1). This is the common case for 1-bit DPTs (switch,
    /// up/down) where the value 0 or 1 lives in the low bits.
    Small(u8),
    /// A payload of one or more separate data octets (APDU length ≥ 2).
    Large(Vec<u8>),
}

impl GroupData {
    /// The raw payload bytes, regardless of packing.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            GroupData::Small(v) => vec![*v & 0x3f],
            GroupData::Large(b) => b.clone(),
        }
    }
}

// APCI service constants (10-bit values).
const APCI_GROUP_READ: u16 = 0x000;
const APCI_GROUP_RESPONSE: u16 = 0x040;
const APCI_GROUP_WRITE: u16 = 0x080;
// Mask for the APCI-selector bits used to distinguish the group services from
// each other and from extended/management APCIs.
const APCI_GROUP_MASK: u16 = 0x03c0;

/// The largest NPDU length that fits a KNX **standard** (short) L_Data frame.
///
/// The standard-frame length field (LG) is 4 bits, so it can encode 0..=15 NPDU
/// octets. An APDU whose NPDU length exceeds this must be sent in an EXTENDED
/// (long) frame, where the length is a full octet. [`CemiFrame::encode`] selects
/// the frame type from this threshold.
const MAX_STANDARD_NPDU_LEN: usize = 15;

/// A decoded cEMI L_Data frame.
///
/// Construct outgoing frames with the [`CemiFrame::group_write`] /
/// [`CemiFrame::group_read`] helpers, or field-by-field. Decode incoming ones
/// with [`CemiFrame::decode`]; serialize with [`CemiFrame::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CemiFrame {
    /// The L_Data primitive (req / con / ind).
    pub message_code: MessageCode,
    /// Additional information block (usually empty). Preserved verbatim so that,
    /// e.g., extended timestamp/RF info round-trips.
    pub additional_info: Vec<u8>,
    /// Control field 1.
    pub control1: Control1,
    /// Control field 2.
    pub control2: Control2,
    /// Source individual address.
    pub source: IndividualAddress,
    /// Destination (group or individual, per `control2.group_address`).
    pub destination: Destination,
    /// Transport-layer PDU kind.
    pub tpci: Tpci,
    /// Application-layer service and payload.
    pub apdu: Apdu,
}

impl CemiFrame {
    /// Builds an `L_Data.req` carrying a `GroupValueWrite` to a group address,
    /// deciding the APDU form from the caller's DPT-derived `packed` intent.
    ///
    /// The 6-bit "small" APDU form is legal ONLY for sub-byte DPTs (main 1/2/3);
    /// pass `packed = dpt.is_packable()`. A byte-sized-or-larger value whose byte
    /// happens to be `<= 0x3F` (DPT 5.001 `50`, 20.102, 17.001) must go as a
    /// separate data octet, so `packed = false` forces the large form regardless
    /// of the byte value (issue #59). Pass the exact DPT bytes; the caller encodes
    /// the value.
    ///
    /// See [`CemiFrame::group_write_packed`] for a byte-length-only shortcut used
    /// by tests and internal 1-bit sends.
    pub fn group_write(
        destination: GroupAddress,
        source: IndividualAddress,
        payload: &[u8],
        packed: bool,
    ) -> Self {
        let data = group_data(payload, packed);
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1::default(),
            control2: Control2::default(),
            source,
            destination: Destination::Group(destination),
            tpci: Tpci::DataGroup,
            apdu: Apdu::GroupValueWrite(data),
        }
    }

    /// Builds an `L_Data.req` carrying a `GroupValueRead` to a group address.
    pub fn group_read(destination: GroupAddress, source: IndividualAddress) -> Self {
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1::default(),
            control2: Control2::default(),
            source,
            destination: Destination::Group(destination),
            tpci: Tpci::DataGroup,
            apdu: Apdu::GroupValueRead,
        }
    }

    /// Builds an `L_Data.req` carrying a `GroupValueResponse` to a group address,
    /// deciding the APDU form from the caller's DPT-derived `packed` intent (see
    /// [`CemiFrame::group_write`] for the packing rule; issue #59).
    pub fn group_response(
        destination: GroupAddress,
        source: IndividualAddress,
        payload: &[u8],
        packed: bool,
    ) -> Self {
        let data = group_data(payload, packed);
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1::default(),
            control2: Control2::default(),
            source,
            destination: Destination::Group(destination),
            tpci: Tpci::DataGroup,
            apdu: Apdu::GroupValueResponse(data),
        }
    }

    /// Builds a `GroupValueWrite` choosing the APDU form by byte length alone (a
    /// single byte `<= 0x3F` packs). Use this ONLY where the payload is a genuine
    /// sub-byte DPT (e.g. a 1-bit switch) or in tests; the DPT-aware
    /// [`CemiFrame::group_write`] is the correct entry point on the write path,
    /// because a byte-sized DPT with a small value must NOT pack (issue #59).
    pub fn group_write_packed(
        destination: GroupAddress,
        source: IndividualAddress,
        payload: &[u8],
    ) -> Self {
        let packed = payload.len() == 1 && payload[0] <= 0x3f;
        Self::group_write(destination, source, payload, packed)
    }

    /// Builds a `GroupValueResponse` choosing the APDU form by byte length alone
    /// (a single byte `<= 0x3F` packs). The response twin of
    /// [`CemiFrame::group_write_packed`]; use the DPT-aware
    /// [`CemiFrame::group_response`] on any real response path (issue #59).
    pub fn group_response_packed(
        destination: GroupAddress,
        source: IndividualAddress,
        payload: &[u8],
    ) -> Self {
        let packed = payload.len() == 1 && payload[0] <= 0x3f;
        Self::group_response(destination, source, payload, packed)
    }

    /// Decodes a cEMI L_Data frame from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(buf);
        let message_code = MessageCode::from_u8(cur.u8("message code")?)?;

        let ai_len = cur.u8("additional-info length")? as usize;
        let additional_info = cur.take(ai_len, "additional info")?.to_vec();

        let control1 = Control1::from_byte(cur.u8("control field 1")?);
        let control2 = Control2::from_byte(cur.u8("control field 2")?);
        let source = IndividualAddress::from_raw(cur.u16("source address")?);
        let dst_raw = cur.u16("destination address")?;
        let destination = if control2.group_address {
            Destination::Group(GroupAddress::from_raw(dst_raw))
        } else {
            Destination::Individual(IndividualAddress::from_raw(dst_raw))
        };

        // NPDU: length byte, then (length + 1) octets of TPDU/APDU. The length
        // counts APDU octets *not* including the octet holding the TPCI/APCI
        // high bits, so the total TPDU length is `npdu_len + 1`.
        let npdu_len = cur.u8("NPDU length")? as usize;
        let tpdu = cur.take(npdu_len + 1, "TPDU")?;

        let (tpci, apdu) = decode_tpdu(tpdu, npdu_len)?;

        Ok(CemiFrame {
            message_code,
            additional_info,
            control1,
            control2,
            source,
            destination,
            tpci,
            apdu,
        })
    }

    /// Serializes this frame to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.push(self.message_code as u8);
        out.push(self.additional_info.len() as u8);
        out.extend_from_slice(&self.additional_info);
        out.push(self.control1.to_byte());
        out.push(self.control2.to_byte());
        out.extend_from_slice(&self.source.raw().to_be_bytes());
        let dst_raw = match self.destination {
            Destination::Group(g) => g.raw(),
            Destination::Individual(i) => i.raw(),
        };
        out.extend_from_slice(&dst_raw.to_be_bytes());

        let (tpdu, npdu_len) = encode_tpdu(&self.tpci, &self.apdu);
        // Frame-type selection (CTL1 bit 7): a KNX standard (short) frame carries
        // an NPDU length that fits the 4-bit LG field (0..=15). An APDU longer than
        // that MUST go in an EXTENDED (long) frame — exactly what ETS does for the
        // 63-octet A_Memory_Write telegrams. bussard builds every management frame
        // with `Control1::default()` (standard), so we override the frame-type bit
        // here based on the encoded NPDU length: > 15 octets forces extended,
        // anything shorter stays standard. This keeps short group/control traffic
        // untouched while letting large memory writes ride an extended frame the
        // way a real device expects (the connection-oriented L4 budget was
        // exhausted by 12-byte chunks; larger extended writes fix it).
        let mut control1 = self.control1;
        control1.standard_frame = npdu_len <= MAX_STANDARD_NPDU_LEN;
        // CTL1 was pushed above with the pre-override value; rewrite it in place at
        // its known offset (msgcode + AI-len byte + AI-bytes).
        let ctl1_offset = 2 + self.additional_info.len();
        out[ctl1_offset] = control1.to_byte();
        out.push(npdu_len as u8);
        out.extend_from_slice(&tpdu);
        out
    }

    /// Convenience: the destination as a group address, if it is one.
    pub fn group_destination(&self) -> Option<GroupAddress> {
        match self.destination {
            Destination::Group(g) => Some(g),
            Destination::Individual(_) => None,
        }
    }

    /// Convenience: the destination as an individual address, if it is one.
    ///
    /// The connection-oriented management layer addresses a single device, so it
    /// needs the individual-address view of the destination.
    pub fn individual_destination(&self) -> Option<IndividualAddress> {
        match self.destination {
            Destination::Individual(i) => Some(i),
            Destination::Group(_) => None,
        }
    }

    /// Builds an `L_Data.req` carrying a raw transport-control frame (no APDU)
    /// to an **individual** address.
    ///
    /// This is the primitive the connection-oriented management layer uses for
    /// `T_Connect`, `T_Disconnect`, `T_ACK` and `T_NAK`: frames whose entire
    /// meaning lives in the single TPCI octet with no application layer. The
    /// `tpci` byte is placed verbatim as the first (and only) TPDU octet; the
    /// on-wire NPDU length is 0.
    ///
    /// See [`tpci`](crate::tpci) for the control-octet constants.
    pub fn t_control(destination: IndividualAddress, source: IndividualAddress, tpci: u8) -> Self {
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1::default(),
            control2: Control2 {
                group_address: false,
                ..Control2::default()
            },
            source,
            destination: Destination::Individual(destination),
            tpci: Tpci::Control(tpci),
            apdu: Apdu::Empty,
        }
    }

    /// Builds an `L_Data.req` carrying a numbered connection-oriented data
    /// telegram (`T_Data_Connected`, NDT) to an **individual** address.
    ///
    /// `tpci` is the full NDT control octet (`0x40 | seq << 2`); `apci` is the
    /// 10-bit application service and `data` its trailing octets. This is how
    /// every A_* management service (device descriptor, property, memory, …) is
    /// carried once a connection is open.
    pub fn t_data_connected(
        destination: IndividualAddress,
        source: IndividualAddress,
        tpci: u8,
        apci: u16,
        data: &[u8],
    ) -> Self {
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1::default(),
            control2: Control2 {
                group_address: false,
                ..Control2::default()
            },
            source,
            destination: Destination::Individual(destination),
            tpci: Tpci::Other(tpci),
            apdu: Apdu::Other {
                apci,
                data: data.to_vec(),
            },
        }
    }

    /// Builds an `L_Data.req` carrying a connectionless broadcast APDU (a
    /// `T_Data_Broadcast`, unnumbered) to the broadcast group address `0/0/0`.
    ///
    /// Broadcast management services (`A_IndividualAddress_Read`,
    /// `A_IndividualAddress_Write`, …) use TPCI `0x00` with a `system_broadcast`
    /// frame and a group destination of raw `0x0000`.
    pub fn t_broadcast(source: IndividualAddress, apci: u16, data: &[u8]) -> Self {
        CemiFrame {
            message_code: MessageCode::LDataReq,
            additional_info: Vec::new(),
            control1: Control1 {
                system_broadcast: true,
                ..Control1::default()
            },
            control2: Control2 {
                group_address: true,
                ..Control2::default()
            },
            source,
            destination: Destination::Group(GroupAddress::from_raw(0x0000)),
            tpci: Tpci::DataGroup,
            apdu: Apdu::Other {
                apci,
                data: data.to_vec(),
            },
        }
    }

    /// The raw TPCI octet of this frame, whatever its kind.
    ///
    /// For [`Tpci::DataGroup`] the transport-control bits are `00`, so this
    /// reconstructs the octet from the APCI high bits; for the connection-oriented
    /// kinds it is the preserved raw octet. Management code inspects this to
    /// classify incoming `T_Connect` / `T_ACK` / NDT frames.
    pub fn tpci_octet(&self) -> u8 {
        match self.tpci {
            Tpci::DataGroup => match &self.apdu {
                Apdu::GroupValueRead => (APCI_GROUP_READ >> 8) as u8 & 0x03,
                Apdu::GroupValueResponse(_) => (APCI_GROUP_RESPONSE >> 8) as u8 & 0x03,
                Apdu::GroupValueWrite(_) => (APCI_GROUP_WRITE >> 8) as u8 & 0x03,
                Apdu::Other { apci, .. } => (apci >> 8) as u8 & 0x03,
                Apdu::Empty => 0,
            },
            Tpci::Control(raw) | Tpci::Other(raw) => raw,
        }
    }
}

/// Builds the group-value APDU payload, honouring the caller's `packed` intent.
///
/// The small (6-bit) form is used only when the caller asks for it AND the
/// payload physically fits (a single byte `<= 0x3F`). `packed` is a DPT property
/// the caller supplies (`Dpt::is_packable()`): a byte-sized DPT passes
/// `packed = false`, so its value is always emitted as a separate data octet even
/// when it happens to be `<= 0x3F` (issue #59). A multi-byte payload is always
/// large regardless of `packed`.
fn group_data(payload: &[u8], packed: bool) -> GroupData {
    if packed && payload.len() == 1 && payload[0] <= 0x3f {
        GroupData::Small(payload[0])
    } else {
        GroupData::Large(payload.to_vec())
    }
}

/// Decodes the TPDU (TPCI + APCI + payload) portion.
///
/// `npdu_len` is the on-wire NPDU length byte; the TPDU slice is `npdu_len + 1`
/// octets long.
fn decode_tpdu(tpdu: &[u8], npdu_len: usize) -> Result<(Tpci, Apdu)> {
    // A single-octet TPDU (npdu_len == 0) is a transport-control frame with no
    // application layer: T_Connect / T_Disconnect / T_ACK / T_NAK. The TPCI
    // control bits are the two high bits of the octet; the whole octet is
    // preserved for the management layer to classify.
    if tpdu.len() == 1 {
        return Ok((Tpci::Control(tpdu[0]), Apdu::Empty));
    }

    // At minimum we need the two octets that carry TPCI + APCI high bits.
    if tpdu.len() < 2 {
        return Err(TransportError::Truncated {
            needed: 2,
            had: tpdu.len(),
            context: "TPDU (TPCI/APCI)",
        });
    }
    let octet0 = tpdu[0];
    let octet1 = tpdu[1];

    // TPCI lives in the two high bits of octet0. `00` = unnumbered data (group).
    let tpci = if octet0 & 0xc0 == 0x00 {
        Tpci::DataGroup
    } else {
        // Connection-oriented / management: preserve verbatim.
        Tpci::Other(octet0)
    };

    // APCI is 10 bits: bits 1-0 of octet0 are the two high bits, bits 7-6 of
    // octet1 are the next two, and — for extended APCIs — bits 5-0 of octet1 are
    // the low bits. The group services only use the top four bits.
    let apci = (((octet0 & 0x03) as u16) << 8) | (octet1 as u16);
    let apci_selector = apci & APCI_GROUP_MASK;

    if let Tpci::Other(_) = tpci {
        // Management traffic: hand back the raw APCI + any trailing data.
        let data = tpdu[2..].to_vec();
        return Ok((tpci, Apdu::Other { apci, data }));
    }

    // For group data, npdu_len == 1 means the value is packed into octet1's low
    // 6 bits (the "small APDU"); npdu_len >= 2 means separate data octets follow.
    let apdu = match apci_selector {
        APCI_GROUP_READ => Apdu::GroupValueRead,
        APCI_GROUP_RESPONSE => Apdu::GroupValueResponse(decode_group_data(octet1, tpdu, npdu_len)),
        APCI_GROUP_WRITE => Apdu::GroupValueWrite(decode_group_data(octet1, tpdu, npdu_len)),
        _ => Apdu::Other {
            apci,
            data: tpdu[2..].to_vec(),
        },
    };
    Ok((tpci, apdu))
}

/// Extracts the group payload given the second APDU octet and the NPDU length.
fn decode_group_data(octet1: u8, tpdu: &[u8], npdu_len: usize) -> GroupData {
    if npdu_len <= 1 {
        // 6-bit value packed into the low bits of octet1.
        GroupData::Small(octet1 & 0x3f)
    } else {
        // Separate data octets follow the two APCI octets.
        GroupData::Large(tpdu[2..].to_vec())
    }
}

/// Encodes TPCI + APCI + payload, returning the TPDU bytes and the NPDU length
/// byte (which excludes the first APDU octet).
fn encode_tpdu(tpci: &Tpci, apdu: &Apdu) -> (Vec<u8>, usize) {
    match tpci {
        // A transport-control frame: exactly one octet, NPDU length 0.
        Tpci::Control(raw) => (vec![*raw], 0),
        Tpci::Other(raw) => {
            // Management / connection-oriented: rebuild from the raw APCI + data.
            let (apci, data) = match apdu {
                Apdu::Other { apci, data } => (*apci, data.clone()),
                // A non-group APDU under a non-group TPCI should not normally
                // occur; fall back to an empty APCI so encoding never panics.
                _ => (0, Vec::new()),
            };
            let mut tpdu = vec![*raw | ((apci >> 8) as u8 & 0x03), (apci & 0xff) as u8];
            tpdu.extend_from_slice(&data);
            let npdu_len = tpdu.len() - 1;
            (tpdu, npdu_len)
        }
        Tpci::DataGroup => {
            let (apci, small, large): (u16, Option<u8>, Option<Vec<u8>>) = match apdu {
                Apdu::GroupValueRead => (APCI_GROUP_READ, Some(0), None),
                Apdu::GroupValueResponse(d) => (APCI_GROUP_RESPONSE, gd_small(d), gd_large(d)),
                Apdu::GroupValueWrite(d) => (APCI_GROUP_WRITE, gd_small(d), gd_large(d)),
                Apdu::Other { apci, data } => {
                    let mut tpdu = vec![(apci >> 8) as u8 & 0x03, (apci & 0xff) as u8];
                    tpdu.extend_from_slice(data);
                    let npdu_len = tpdu.len() - 1;
                    return (tpdu, npdu_len);
                }
                // An empty APDU under group TPCI should not occur; emit a single
                // zero octet (a bare T_Data_Group) so encoding never panics.
                Apdu::Empty => return (vec![0x00], 0),
            };

            // octet0: TPCI (00) + APCI high two bits.
            let octet0 = (apci >> 8) as u8 & 0x03;
            // octet1: APCI low bits; for small payloads OR in the 6-bit value.
            let mut octet1 = (apci & 0xff) as u8;
            let mut tpdu = Vec::with_capacity(2);
            match (small, large) {
                (Some(v), None) => {
                    octet1 |= v & 0x3f;
                    tpdu.push(octet0);
                    tpdu.push(octet1);
                    // npdu_len = 1: value packed into octet1.
                    (tpdu, 1)
                }
                (_, Some(bytes)) => {
                    tpdu.push(octet0);
                    tpdu.push(octet1);
                    tpdu.extend_from_slice(&bytes);
                    // npdu_len excludes octet0.
                    let npdu_len = tpdu.len() - 1;
                    (tpdu, npdu_len)
                }
                (None, None) => {
                    tpdu.push(octet0);
                    tpdu.push(octet1);
                    (tpdu, 1)
                }
            }
        }
    }
}

fn gd_small(d: &GroupData) -> Option<u8> {
    match d {
        GroupData::Small(v) => Some(*v),
        GroupData::Large(_) => None,
    }
}

fn gd_large(d: &GroupData) -> Option<Vec<u8>> {
    match d {
        GroupData::Small(_) => None,
        GroupData::Large(b) => Some(b.clone()),
    }
}

/// A tiny forward-only byte reader that produces [`TransportError::Truncated`]
/// instead of panicking.
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize, context: &'static str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(TransportError::Truncated {
                needed: n,
                had: self.remaining(),
                context,
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub(crate) fn u8(&mut self, context: &'static str) -> Result<u8> {
        Ok(self.take(1, context)?[0])
    }

    pub(crate) fn u16(&mut self, context: &'static str) -> Result<u16> {
        let s = self.take(2, context)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ga(s: &str) -> GroupAddress {
        s.parse().expect("valid fixture address")
    }
    fn ia(s: &str) -> IndividualAddress {
        s.parse().expect("valid fixture address")
    }

    #[test]
    fn roundtrip_group_write_1bit_small_apdu() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // L_Data.ind, no AI, ctl1=0xBC (std, not-repeated, broadcast, low prio,
        // ack req), ctl2=0xE0 (group, hops=6), src 1.1.1, dst 3/0/4,
        // NPDU len 1, TPDU 00 81 (GroupValueWrite, value 1 packed).
        // 3/0/4 = (3<<11)|4 = 0x1804.
        let hex: &[u8] = &[
            0x29, // L_Data.ind
            0x00, // AI len 0
            0xBC, // ctl1
            0xE0, // ctl2 (group)
            0x11, 0x01, // src 1.1.1
            0x18, 0x04, // dst 3/0/4
            0x01, // NPDU length 1
            0x00, 0x81, // TPCI/APCI = GroupValueWrite, small value 1
        ];
        let frame = CemiFrame::decode(hex)?;
        assert_eq!(frame.message_code, MessageCode::LDataInd);
        assert_eq!(frame.source, ia("1.1.1"));
        assert_eq!(frame.group_destination(), Some(ga("3/0/4")));
        assert_eq!(frame.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        // Round-trips byte-for-byte.
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn build_group_write_small() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let frame = CemiFrame::group_write_packed(ga("3/0/4"), ia("1.1.1"), &[1]);
        let bytes = frame.encode();
        // Last three bytes: NPDU len 1, APCI 0x00, 0x81.
        assert_eq!(&bytes[bytes.len() - 3..], &[0x01, 0x00, 0x81]);
        let back = CemiFrame::decode(&bytes)?;
        assert_eq!(back.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        Ok(())
    }

    #[test]
    fn roundtrip_group_write_large_2byte() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // GroupValueWrite of a 2-byte payload (e.g. DPT 9 temperature). NPDU
        // length 3 (one APCI octet + two data octets). TPDU: 00 80 0C 1A.
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x03, // NPDU length 3
            0x00, 0x80, // GroupValueWrite, no packed value
            0x0C, 0x1A, // two data octets
        ];
        let frame = CemiFrame::decode(hex)?;
        assert_eq!(
            frame.apdu,
            Apdu::GroupValueWrite(GroupData::Large(vec![0x0C, 0x1A]))
        );
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn roundtrip_group_read_no_payload() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // GroupValueRead: APCI 0x000, NPDU len 1, TPDU 00 00.
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x00,
        ];
        let frame = CemiFrame::decode(hex)?;
        assert_eq!(frame.apdu, Apdu::GroupValueRead);
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn roundtrip_group_response_small() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // GroupValueResponse (0x040) small value 1: TPDU 00 41.
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x41,
        ];
        let frame = CemiFrame::decode(hex)?;
        assert_eq!(frame.apdu, Apdu::GroupValueResponse(GroupData::Small(1)));
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn additional_info_present_roundtrips() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // L_Data.ind with a 4-byte AI block (e.g. extended relative timestamp).
        let hex: &[u8] = &[
            0x29, 0x04, // AI len 4
            0x03, 0x02, 0xAA, 0xBB, // AI bytes
            0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x81,
        ];
        let frame = CemiFrame::decode(hex)?;
        assert_eq!(frame.additional_info, vec![0x03, 0x02, 0xAA, 0xBB]);
        assert_eq!(frame.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn individual_destination_decoded() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // ctl2 with group bit clear (0x60): destination is an individual address.
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0x60, 0x11, 0x01, 0x11, 0x02, 0x01, 0x00, 0x00,
        ];
        let frame = CemiFrame::decode(hex)?;
        match frame.destination {
            Destination::Individual(i) => assert_eq!(i, ia("1.1.2")),
            other => panic!("expected individual, got {other:?}"),
        }
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn control_fields_decode_flags() {
        // 0xBC = 1011_1100: std frame, not-repeated, broadcast, priority Low
        // (bits 3-2 = 11), ack bit (1) clear, error bit (0) clear.
        let c1 = Control1::from_byte(0xBC);
        assert!(c1.standard_frame);
        assert!(!c1.repeated); // bit5 set => not repeated
        assert!(c1.system_broadcast);
        assert_eq!(c1.priority, Priority::Low);
        assert!(!c1.ack_requested);
        assert!(!c1.error);
        assert_eq!(c1.to_byte(), 0xBC);

        let c2 = Control2::from_byte(0xE0);
        assert!(c2.group_address);
        assert_eq!(c2.hop_count, 6);
        assert_eq!(c2.extended_frame_format, 0);
        assert_eq!(c2.to_byte(), 0xE0);
    }

    #[test]
    fn management_apci_preserved() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A connection-oriented management TPDU (TPCI high bits != 00), here a
        // DeviceDescriptorRead-like APCI. We only require it round-trips and does
        // not panic.
        let hex: &[u8] = &[
            0x29, 0x00, 0xBC, 0x60, 0x11, 0x01, 0x11, 0x02, 0x02, // NPDU len 2
            0x43, 0x00, 0x00, // TPCI 0x43 (numbered/connected) + APCI + data
        ];
        let frame = CemiFrame::decode(hex)?;
        match frame.tpci {
            Tpci::Other(0x43) => {}
            other => panic!("expected Tpci::Other(0x43), got {other:?}"),
        }
        assert!(matches!(frame.apdu, Apdu::Other { .. }));
        assert_eq!(frame.encode(), hex);
        Ok(())
    }

    #[test]
    fn truncated_is_error_not_panic() {
        assert!(CemiFrame::decode(&[0x29]).is_err());
        assert!(CemiFrame::decode(&[]).is_err());
        // NPDU length claims more than present.
        let hex: &[u8] = &[0x29, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x05, 0x00];
        assert!(CemiFrame::decode(hex).is_err());
    }

    #[test]
    fn bad_message_code_is_error() {
        let hex: &[u8] = &[
            0xFF, 0x00, 0xBC, 0xE0, 0x11, 0x01, 0x18, 0x04, 0x01, 0x00, 0x00,
        ];
        assert!(CemiFrame::decode(hex).is_err());
    }

    #[test]
    fn small_boundary_value_63_packs() {
        // Value 0x3f is the largest that fits in the packed small form.
        let frame = CemiFrame::group_write_packed(ga("1/1/1"), ia("1.1.1"), &[0x3f]);
        assert_eq!(frame.apdu, Apdu::GroupValueWrite(GroupData::Small(0x3f)));
        let bytes = frame.encode();
        assert_eq!(&bytes[bytes.len() - 2..], &[0x00, 0x80 | 0x3f]);
    }

    #[test]
    fn t_connect_control_frame_roundtrips() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // T_Connect (0x80) to an individual address, NPDU length 0, one TPDU
        // octet. This exercises the new single-octet control path.
        let frame = CemiFrame::t_control(ia("1.1.4"), ia("0.0.255"), 0x80);
        let bytes = frame.encode();
        // Last two bytes: NPDU length 0, TPCI 0x80.
        assert_eq!(&bytes[bytes.len() - 2..], &[0x00, 0x80]);
        let back = CemiFrame::decode(&bytes)?;
        assert_eq!(back.tpci, Tpci::Control(0x80));
        assert_eq!(back.apdu, Apdu::Empty);
        assert_eq!(back.individual_destination(), Some(ia("1.1.4")));
        assert_eq!(back.tpci_octet(), 0x80);
        assert_eq!(back.encode(), bytes);
        Ok(())
    }

    #[test]
    fn t_ack_control_frame_roundtrips() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // T_ACK for seq 3 = 0xC2 | (3<<2) = 0xCE.
        let frame = CemiFrame::t_control(ia("1.1.4"), ia("0.0.255"), 0xCE);
        let back = CemiFrame::decode(&frame.encode())?;
        assert_eq!(back.tpci, Tpci::Control(0xCE));
        assert_eq!(back.tpci_octet(), 0xCE);
        Ok(())
    }

    #[test]
    fn ndt_data_connected_roundtrips() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // NDT seq 0 (0x40) carrying A_DeviceDescriptor_Read (APCI 0x300). The
        // APCI's top two bits (0x03) share octet0 with the TPCI, so the encoded
        // first octet is 0x40 | 0x03 = 0x43 — this is the real KNX packing, and
        // the APCI reconstructs to 0x300 on decode.
        let frame = CemiFrame::t_data_connected(ia("1.1.4"), ia("0.0.255"), 0x40, 0x300, &[]);
        let bytes = frame.encode();
        let back = CemiFrame::decode(&bytes)?;
        assert_eq!(back.tpci, Tpci::Other(0x43));
        match back.apdu {
            Apdu::Other { apci, ref data } => {
                assert_eq!(apci, 0x300);
                assert!(data.is_empty());
            }
            other => panic!("expected Apdu::Other, got {other:?}"),
        }
        // The transport-control bits (masking off the APCI's shared bits) are NDT
        // seq 0.
        assert_eq!(back.tpci_octet() & 0xfc, 0x40);
        assert_eq!(back.encode(), bytes);
        Ok(())
    }

    #[test]
    fn ndt_with_data_roundtrips() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // NDT seq 1 (0x44) carrying A_Memory_Read (0x200) with 3 trailing octets.
        let frame = CemiFrame::t_data_connected(
            ia("1.1.4"),
            ia("0.0.255"),
            0x44,
            0x200,
            &[0x03, 0x01, 0x00],
        );
        let back = CemiFrame::decode(&frame.encode())?;
        match back.apdu {
            Apdu::Other { apci, ref data } => {
                assert_eq!(apci, 0x200);
                assert_eq!(data, &[0x03, 0x01, 0x00]);
            }
            other => panic!("expected Apdu::Other, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn broadcast_frame_targets_zero_group() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A_IndividualAddress_Read (0x100) as a system broadcast.
        let frame = CemiFrame::t_broadcast(ia("0.0.255"), 0x100, &[]);
        assert_eq!(frame.group_destination(), Some(GroupAddress::from_raw(0)));
        assert!(frame.control1.system_broadcast);
        let back = CemiFrame::decode(&frame.encode())?;
        match back.apdu {
            Apdu::Other { apci, .. } => assert_eq!(apci, 0x100),
            other => panic!("expected Apdu::Other, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn value_64_goes_large() {
        // 0x40 doesn't fit in 6 bits, so it becomes a separate data octet.
        let frame = CemiFrame::group_write_packed(ga("1/1/1"), ia("1.1.1"), &[0x40]);
        assert_eq!(
            frame.apdu,
            Apdu::GroupValueWrite(GroupData::Large(vec![0x40]))
        );
    }

    // ---------------------------------------------------------------------
    // Issue #59: DPT-driven packing intent, not value-driven guessing.
    // ---------------------------------------------------------------------

    #[test]
    fn unpacked_intent_forces_large_even_for_small_byte()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A byte-sized DPT (e.g. 5.001 value 50 -> 0x32, or 20.102 value 2) whose
        // byte is <= 0x3F must NOT be packed: with packed=false it is a separate
        // data octet, and it round-trips as such.
        for byte in [0x02u8, 0x05, 0x19, 0x32] {
            let frame = CemiFrame::group_write(ga("3/0/4"), ia("1.1.1"), &[byte], false);
            assert_eq!(
                frame.apdu,
                Apdu::GroupValueWrite(GroupData::Large(vec![byte])),
                "byte {byte:#04X} with packed=false must be a separate data octet"
            );
            // Round-trips: still large, still the same byte.
            let back = CemiFrame::decode(&frame.encode())?;
            assert_eq!(
                back.apdu,
                Apdu::GroupValueWrite(GroupData::Large(vec![byte]))
            );
        }
        Ok(())
    }

    #[test]
    fn packed_intent_packs_sub_byte_value() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A sub-byte DPT (1.x On, 3.x step) with packed=true uses the small form.
        let frame = CemiFrame::group_write(ga("3/0/4"), ia("1.1.1"), &[1], true);
        assert_eq!(frame.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        let back = CemiFrame::decode(&frame.encode())?;
        assert_eq!(back.apdu, Apdu::GroupValueWrite(GroupData::Small(1)));
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Extended vs standard frame selection: a long management APDU must ride an
    // EXTENDED (long) L_Data frame; short frames stay standard.
    // ---------------------------------------------------------------------

    #[test]
    fn long_apdu_encodes_as_extended_frame() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // A 63-octet A_Memory_Write (APCI 0x280 | 63) to 0x6000: the TPDU is
        // 2 APCI octets + 2 address octets + 63 data octets = 67, so NPDU len = 66
        // — far beyond the 15-octet standard-frame ceiling. It must encode with the
        // frame-type bit clear (extended).
        let data = vec![0xFFu8; 63];
        let apci = 0x280 | 63;
        let mut payload = vec![0x60, 0x00];
        payload.extend_from_slice(&data);
        let frame =
            CemiFrame::t_data_connected(ia("1.1.4"), ia("0.0.255"), tpci_ndt(0), apci, &payload);
        let bytes = frame.encode();
        // CTL1 is at offset 2 (msgcode, AI-len=0, then CTL1).
        let ctl1 = bytes[2];
        assert_eq!(
            ctl1 & 0x80,
            0x00,
            "long APDU must clear the frame-type bit (extended)"
        );
        // The NPDU length octet is 66.
        let back = CemiFrame::decode(&bytes)?;
        assert!(
            !back.control1.standard_frame,
            "decoded frame must report extended"
        );
        // Round-trips byte-for-byte.
        assert_eq!(back.encode(), bytes);
        match back.apdu {
            Apdu::Other {
                apci: a,
                data: ref d,
            } => {
                assert_eq!(a, apci);
                assert_eq!(d.len(), 2 + 63);
            }
            other => panic!("expected Apdu::Other, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn short_apdu_stays_standard_frame() {
        // A 12-octet A_Memory_Write: TPDU is 2 + 2 + 12 = 16, NPDU len = 15 — the
        // largest that still fits a standard frame. The frame-type bit stays set.
        let data = vec![0xAAu8; 12];
        let apci = 0x280 | 12;
        let mut payload = vec![0x60, 0x00];
        payload.extend_from_slice(&data);
        let frame =
            CemiFrame::t_data_connected(ia("1.1.4"), ia("0.0.255"), tpci_ndt(0), apci, &payload);
        let bytes = frame.encode();
        assert_eq!(bytes[2] & 0x80, 0x80, "NPDU len 15 stays standard");
        // One octet more (NPDU len 16) crosses into extended.
        let mut payload2 = vec![0x60, 0x00];
        payload2.extend_from_slice(&[0xAAu8; 13]);
        let frame2 = CemiFrame::t_data_connected(
            ia("1.1.4"),
            ia("0.0.255"),
            tpci_ndt(0),
            0x280 | 13,
            &payload2,
        );
        assert_eq!(
            frame2.encode()[2] & 0x80,
            0x00,
            "NPDU len 16 must become extended"
        );
    }

    #[test]
    fn group_write_stays_standard() {
        // A small group write is always well within the standard ceiling.
        let frame = CemiFrame::group_write_packed(ga("3/0/4"), ia("1.1.1"), &[1]);
        assert_eq!(frame.encode()[2] & 0x80, 0x80);
    }

    /// Local NDT TPCI helper for the extended-frame tests (bits 5-2 = seq).
    fn tpci_ndt(seq: u8) -> u8 {
        0x40 | ((seq & 0x0f) << 2)
    }

    #[test]
    fn packed_intent_still_goes_large_for_multibyte() {
        // Even packed=true cannot pack a 2-byte payload.
        let frame = CemiFrame::group_write(ga("3/0/4"), ia("1.1.1"), &[0x0C, 0x1A], true);
        assert_eq!(
            frame.apdu,
            Apdu::GroupValueWrite(GroupData::Large(vec![0x0C, 0x1A]))
        );
    }
}
