//! The connection-oriented L4 transport: numbered data telegrams, their
//! sequence checks and acknowledgements, and framing of connected responses.

use crate::bus::event::Event;
use crate::wire::apdu::Apdu;
use crate::wire::{CemiLData, IndividualAddress, MessageCode, Tpci};

use super::{Device, DeviceError, DeviceReaction};

impl Device {
    /// Handle a numbered data telegram (NDT) with strict L4 sequence checking.
    ///
    /// KNX style-1 rationalised transport, device side (the mirror of bussard's
    /// `Layer4Connection`):
    ///
    /// - **Expected sequence** (`seq == rx_seq`): process the APDU, advance the
    ///   receive sequence, and acknowledge. Verbs that carry their own
    ///   application-layer response (property read/write, authorize,
    ///   device-descriptor, master-reset) let that response stand as the
    ///   acknowledgement — the response NDT's arrival is what the tool waits on.
    ///   Response-less verbs (`A_MemoryWrite`, a bare `A_Restart`) get an explicit
    ///   `T_ACK(seq)` so the tool is not left retransmitting.
    /// - **Duplicate of the last accepted frame** (`seq == rx_seq - 1` mod 16): a
    ///   retransmit whose `T_ACK` the tool missed. Re-acknowledge with `T_ACK(seq)`
    ///   but do **not** reprocess it (idempotency — reprocessing a memory write or
    ///   double-advancing state would corrupt the session).
    /// - **Anything else** (out of window): ignore silently, exactly as a real
    ///   device does — it neither ACKs nor processes an unexpected sequence, so a
    ///   tool that desynced its send sequence stalls here rather than being
    ///   quietly tolerated. This makes any bussard L4 sequencing bug reproduce
    ///   locally.
    pub(super) fn handle_numbered_data(
        &mut self,
        cemi: &CemiLData,
        seq: u8,
    ) -> Result<DeviceReaction, DeviceError> {
        let tool = cemi.source;

        // A retransmit of the frame we last accepted: re-ACK, do not reprocess.
        let last_accepted = self.rx_seq.wrapping_sub(1) & 0x0F;
        if seq == last_accepted {
            return Ok(DeviceReaction {
                responses: vec![self.t_ack(tool, seq)],
                did_master_reset: false,
            });
        }

        // Out-of-window sequence: a strict device ignores it entirely.
        if seq != self.rx_seq {
            self.emit(Event::Telegram {
                direction: crate::bus::event::Direction::ToBus,
                cemi: cemi.encode(),
                summary: format!(
                    "DROPPED by {}: out-of-sequence NDT seq {seq} (expected {})",
                    self.address, self.rx_seq
                ),
            });
            return Ok(DeviceReaction::default());
        }

        // Per-connection exchange budget: a real connection-oriented device drops
        // a long-held L4 connection after a bounded number of numbered exchanges
        // (KNX Virtual DA.tp drops at ~35). This expected-sequence NDT is one such
        // exchange; if accepting it would exceed the budget, the device drops the
        // connection instead — it stops answering entirely (silence), exactly as
        // the real device does, so the tool sees "device absent" unless it cycled
        // the connection in time. Reset per connection on T_Connect. `None` =
        // unlimited (the default), leaving existing behaviour unchanged.
        if let Some(budget) = self.l4_exchange_budget {
            if self.l4_exchanges >= budget {
                self.connected = false;
                self.emit(Event::Telegram {
                    direction: crate::bus::event::Direction::ToBus,
                    cemi: cemi.encode(),
                    summary: format!(
                        "DROPPED by {}: L4 exchange budget {budget} exhausted; connection dropped",
                        self.address
                    ),
                });
                return Ok(DeviceReaction::default());
            }
            self.l4_exchanges += 1;
        }

        // Expected sequence: parse, process, advance, acknowledge.
        let apdu = Apdu::parse(&cemi.tpdu).ok_or(DeviceError::Malformed {
            service: "APDU".into(),
            detail: "too short".into(),
        })?;
        self.rx_seq = (self.rx_seq + 1) & 0x0F;
        let mut reaction = self.handle_apdu(cemi, &apdu)?;
        if reaction.responses.is_empty() {
            reaction.responses.push(self.t_ack(tool, seq));
        }
        Ok(reaction)
    }

    /// Build a transport-layer `T_ACK(seq)` frame back toward `to`.
    ///
    /// A real device T_ACKs every numbered data telegram at the transport layer,
    /// including an `A_Restart` — which, unlike a property/memory verb, carries no
    /// application-layer response. The management tool waits for that T_ACK before
    /// it considers the restart delivered (see bussard's
    /// `master_reset_via_basic_restart`), so the simulator must emit it before it
    /// reboots and drops the connection, or the tool retransmits into the void.
    fn t_ack(&self, to: IndividualAddress, seq: u8) -> CemiLData {
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: self.address,
            dest: to.raw(),
            tpdu: vec![Tpci::ack_byte(seq)],
        }
    }

    /// Build a connected `L_Data.ind` response back toward `dest` (the tool).
    pub(super) fn respond(&mut self, to: IndividualAddress, apci10: u16, data: &[u8]) -> CemiLData {
        let seq = self.tx_seq;
        self.tx_seq = (self.tx_seq + 1) & 0x0F;
        let tpdu = Apdu::encode_connected(seq, apci10, data);
        CemiLData {
            message_code: MessageCode::LDataInd,
            ctrl1: 0xbc,
            ctrl2: 0x60,
            source: self.address,
            dest: to.raw(),
            tpdu,
        }
    }
}
