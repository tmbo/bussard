//! KNX Data Secure on the device side: unwrapping `A_SecureData`, answering
//! `SyncRequest`, and serving the security interface object over the extended
//! property services.

use crate::bus::event::Event;
use crate::wire::apdu::Apdu;
use crate::wire::{CemiLData, IndividualAddress};

use super::{Device, DeviceError, DeviceReaction, SecurityLimits, SecurityObject, security_object};

impl Device {
    /// The transport-control "tpci_int" the CCM nonce folds in (spec §5.4): the
    /// carrier telegram's TPCI top bits shifted down. For an unnumbered data
    /// telegram this is 0; for a connected data telegram it is the sequence-
    /// bearing value. Extracted from the carrier's first TPDU byte.
    fn carrier_tpci_int(cemi: &CemiLData) -> u8 {
        match cemi.tpdu.first() {
            // Connected data (01ssssxx): the 6-bit TPCI value above the 2 APCI
            // bits, i.e. the top 6 bits of the byte.
            Some(b) if b & 0xC0 == 0x40 => (b >> 2) & 0x3F,
            // Unnumbered data (00xxxxxx): no sequence, tpci_int = 0.
            _ => 0,
        }
    }

    /// Handle an inbound A_SecureData (spec §5, §6): unwrap and verify, dispatch
    /// the inner APDU through the normal management path, then re-wrap each
    /// response into A_SecureData with the device's own sequence.
    ///
    /// A wrong MAC, a stale/replayed sequence, or a malformed ASDU is refused —
    /// the device drops the frame (returns an error, no response), exactly as a
    /// real activated device does (spec §12.2).
    pub(super) fn handle_secure_data(
        &mut self,
        cemi: &CemiLData,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let tpci_int = Self::carrier_tpci_int(cemi);
        // S-A_Sync_Req (SCF service 2): answer with S-A_Sync_Res as the real
        // device does (secure-1-1-12 capture), before any S-A_Data.
        if apdu
            .data
            .first()
            .and_then(|&b| crate::secure::Scf::from_byte(b))
            .is_some_and(|scf| scf.service == crate::secure::SecService::SyncReq)
        {
            return self.handle_sync_request(cemi, tpci_int, apdu);
        }
        // The ASDU is the bytes after the two APCI bytes, i.e. apdu.data.
        let unwrapped = {
            let session = self
                .secure
                .as_mut()
                .expect("handle_secure_data requires an activated session");
            session.unwrap_incoming(cemi, tpci_int, &apdu.data)?
        };
        // Observe the decoded frame (key-free, plaintext-free).
        self.emit(Event::SecureFrame {
            device: self.address,
            summary: crate::secure::DataSecureSession::describe_frame(
                "recv",
                unwrapped.scf,
                &unwrapped.seq,
                &unwrapped.inner_tpdu,
            ),
        });
        // The reply algorithm mirrors the request's (auth-only stays auth-only;
        // auth+enc stays auth+enc), matching a real device that answers in kind.
        let reply_alg = unwrapped.scf.algorithm;

        // Parse and dispatch the inner APDU through the ordinary management path.
        let inner = Apdu::parse(&unwrapped.inner_tpdu).ok_or(DeviceError::Malformed {
            service: "A_SecureData inner APDU".into(),
            detail: "too short".into(),
        })?;
        // Dispatch the unwrapped inner APDU directly (bypassing the secure
        // interception, which would otherwise refuse the now-authenticated
        // protected function).
        let reaction = self.dispatch_apdu(cemi, &inner)?;

        // Re-wrap each response's inner APDU into A_SecureData. A response is a
        // connected data telegram whose TPDU is [TPCI/APCI][APCI][data]; we take
        // its inner TPDU, wrap it, and rebuild the carrier TPDU as an unnumbered
        // A_SecureData carrying the ASDU. The transport sequence is dropped in the
        // re-wrap (the secure layer's own 6-byte sequence supersedes it here); the
        // response still rides back to the tool as a connected NDT via `respond`.
        let mut secured = Vec::with_capacity(reaction.responses.len());
        for resp in reaction.responses {
            // A pure transport ACK carries no APDU to secure; forward as-is.
            if Apdu::parse(&resp.tpdu).is_none() {
                secured.push(resp);
                continue;
            }
            // The inner TPDU minus the transport-sequence bits: rebuild the APCI
            // header without the connected-sequence nibble so the wrapped inner is
            // the pure application PDU.
            let inner_tpdu = Self::strip_transport_seq(&resp.tpdu);
            // Wrap with the RESPONSE carrier's own tpci_int (derived from the
            // response TPDU) so the receiving tool can reconstruct the identical
            // CCM nonce from the response frame alone.
            let resp_tpci_int = Self::carrier_tpci_int(&resp);
            let (asdu, seq) = {
                let session = self
                    .secure
                    .as_mut()
                    .expect("activated session present for wrap");
                session.wrap_outgoing(&resp, resp_tpci_int, reply_alg, &inner_tpdu)
            };
            let scf = crate::secure::Scf {
                tool_access: true,
                algorithm: reply_alg,
                system_broadcast: false,
                service: crate::secure::SecService::Data,
            };
            self.emit(Event::SecureFrame {
                device: self.address,
                summary: crate::secure::DataSecureSession::describe_frame(
                    "send",
                    scf,
                    &seq,
                    &inner_tpdu,
                ),
            });
            // Rebuild the response carrier: same transport framing (connected NDT
            // with the response's own sequence bits), APCI = A_SecureData (0x3F1),
            // payload = the ASDU.
            let tx_seq = (resp.tpdu[0] >> 2) & 0x0F;
            let apci10 = crate::secure::A_SECURE_DATA_APCI;
            let mut tpdu = vec![
                0x40 | ((tx_seq & 0x0F) << 2) | ((apci10 >> 8) as u8 & 0x03),
                (apci10 & 0xFF) as u8,
            ];
            tpdu.extend_from_slice(&asdu);
            secured.push(CemiLData { tpdu, ..resp });
        }
        Ok(DeviceReaction {
            responses: secured,
            did_master_reset: reaction.did_master_reset,
        })
    }

    /// Answer an S-A_Sync_Req (spec §6.3): T_ACK it and send the S-A_Sync_Res as
    /// a connected data telegram. A request that does not verify is dropped.
    fn handle_sync_request(
        &mut self,
        cemi: &CemiLData,
        tpci_int: u8,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let tool = cemi.source;
        // Build the response carrier first so the ASDU's nonce context matches
        // the frame that carries it (connected NDT with the device's sequence).
        let mut resp = self.respond(tool, crate::secure::A_SECURE_DATA_APCI, &[]);
        let resp_tpci_int = Self::carrier_tpci_int(&resp);
        let asdu = {
            let session = self
                .secure
                .as_mut()
                .expect("handle_sync_request requires an activated session");
            match session.answer_sync_request(cemi, tpci_int, &apdu.data, &resp, resp_tpci_int) {
                Ok(asdu) => asdu,
                Err(err) => {
                    // The response sequence was reserved by `respond`; give it
                    // back since nothing is sent.
                    self.tx_seq = self.tx_seq.wrapping_sub(1) & 0x0F;
                    return Err(err.into());
                }
            }
        };
        self.emit(Event::SecureFrame {
            device: self.address,
            summary: "SECURE recv S-A_Sync_Req, send S-A_Sync_Res".to_string(),
        });
        resp.tpdu.extend_from_slice(&asdu);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// Strip the connected-transport sequence bits from a response TPDU, leaving
    /// the pure application PDU (`[APCI-high bits only][APCI low][data...]`). The
    /// first byte keeps only the two APCI high bits (transport type reset to
    /// unnumbered-data form) so the wrapped inner is transport-agnostic, matching
    /// how the secured APDU is authenticated (spec §5.4 protects only the inner
    /// APCI, not the carrier transport sequence).
    fn strip_transport_seq(tpdu: &[u8]) -> Vec<u8> {
        if tpdu.is_empty() {
            return Vec::new();
        }
        let mut out = tpdu.to_vec();
        // Keep only the two APCI high bits; clear the transport-control bits.
        out[0] &= 0x03;
        out
    }

    /// The range facts the security object checks against: the group-object
    /// count from the loaded group-object table (obj 3) and the address-table
    /// length from the loaded address table (obj 1).
    fn security_limits(&self) -> SecurityLimits {
        SecurityLimits {
            group_objects: self.loaded_table_count(3),
            address_table_len: self.loaded_table_count(1),
        }
    }

    /// Handle an extended property service (`A_PropertyExtValue_*`,
    /// `A_PropertyExtDescription_Read`, `A_FunctionPropertyExt_*`).
    ///
    /// Only a security-activated device carries the security interface object;
    /// a plain device does not implement these services and stays silent (the
    /// numbered frame is still T_ACKed). An activated device only reaches this
    /// through A_SecureData: a plain request is refused by the secure
    /// interception in [`Device::handle_apdu`].
    pub(super) fn on_extended_property(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let limits = self.security_limits();
        let Some(obj) = self.security_object.as_mut() else {
            return Ok(DeviceReaction::default());
        };
        let reply = obj
            .handle(apdu.apci, &apdu.data, limits)
            .map_err(|e| match e {
                security_object::ExtServiceError::Malformed { service, detail } => {
                    DeviceError::Malformed {
                        service: service.into(),
                        detail,
                    }
                }
            })?;
        let Some(reply) = reply else {
            return Ok(DeviceReaction::default());
        };
        self.emit(Event::SecurityObject {
            device: self.address,
            summary: reply.summary,
        });
        let resp = self.respond(tool, reply.apci.to_u10(), &reply.data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    /// The security interface object, when the device is security-activated
    /// (for tests/observability).
    pub fn security_object(&self) -> Option<&SecurityObject> {
        self.security_object.as_ref()
    }
}
