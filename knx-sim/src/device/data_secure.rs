//! KNX Data Secure on the device side: unwrapping `A_SecureData`, answering
//! `SyncRequest`, and serving the security interface object over the extended
//! property services.

use crate::bus::event::Event;
use crate::wire::apdu::{Apci, Apdu};
use crate::wire::{CemiLData, IndividualAddress};

use super::{
    Device, DeviceError, DeviceReaction, PID_LOAD_STATE_CONTROL, SecurityLimits, SecurityObject,
    security_object,
};

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
        // A tool key or send sequence written by this APDU (bussard issue
        // #398): the answer already goes under the new key, with the new
        // sequence, as the IP interface in the ETS activation capture does.
        if let Some(obj) = self.security_object.as_mut() {
            let key = obj.take_pending_tool_key();
            let seq = obj.take_pending_seq();
            if let Some(session) = self.secure.as_mut() {
                if let Some(key) = key {
                    session.set_tool_key(crate::secure::Key16::new(key));
                }
                if let Some(seq) = seq {
                    session.set_tx_seq(seq);
                }
            }
        }

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
            // Rebuild the response carrier: same transport framing as the plain
            // response (a connected NDT with its own sequence bits, or an
            // unnumbered T_Data_Individual for a connectionless request, KNX
            // 3/3/7 §5.5.5.3, 03_03_07 Application Layer v02.01.01 line 9715),
            // APCI = A_SecureData (0x3F1), payload = the ASDU.
            let apci10 = crate::secure::A_SECURE_DATA_APCI;
            let tpci = if resp.tpdu[0] & 0xC0 == 0x40 {
                0x40 | (((resp.tpdu[0] >> 2) & 0x0F) << 2)
            } else {
                0x00
            };
            let mut tpdu = vec![tpci | ((apci10 >> 8) as u8 & 0x03), (apci10 & 0xFF) as u8];
            tpdu.extend_from_slice(&asdu);
            secured.push(CemiLData { tpdu, ..resp });
        }
        Ok(DeviceReaction {
            responses: secured,
            did_master_reset: reaction.did_master_reset,
        })
    }

    /// Answer an S-A_Sync_Req (spec §6.3) in the request's communication mode:
    /// a connected request is T_ACKed and answered with a connected data
    /// telegram, a connectionless one (`T_Data_Individual`, as ETS 6 sends it
    /// before it connects, #423) with an unnumbered one. KNX 3/3/7 §5.3.2
    /// (03_03_07 Application Layer v02.01.01 lines 8897-8898, 8950-8953): the
    /// receiver takes the request on either transport service and answers with
    /// the comm_mode of the request. A request that does not verify is dropped.
    fn handle_sync_request(
        &mut self,
        cemi: &CemiLData,
        tpci_int: u8,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let tool = cemi.source;
        let connectionless = cemi.tpdu.first().is_some_and(|b| b & 0xC0 == 0x00);
        // Build the response carrier first so the ASDU's nonce context matches
        // the frame that carries it.
        let saved_tx_seq = self.tx_seq;
        let mut resp = self.respond(tool, crate::secure::A_SECURE_DATA_APCI, &[]);
        if connectionless {
            // T_Data_Individual: no transport sequence, nothing consumed.
            self.tx_seq = saved_tx_seq;
            if let Some(first) = resp.tpdu.first_mut() {
                *first &= 0x03;
            }
        }
        let resp_tpci_int = Self::carrier_tpci_int(&resp);
        let receiver = crate::secure::SyncReceiver {
            serial: self.own_serial(),
            now: std::time::Instant::now(),
        };
        let asdu = {
            let session = self
                .secure
                .as_mut()
                .expect("handle_sync_request requires an activated session");
            match session.answer_sync_request(
                cemi,
                tpci_int,
                &apdu.data,
                &resp,
                resp_tpci_int,
                receiver,
            ) {
                Ok(asdu) => asdu,
                Err(err) => {
                    // The response sequence was reserved by `respond`; give it
                    // back since nothing is sent.
                    self.tx_seq = saved_tx_seq;
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

    /// The device's KNX serial number, the device object's `PID_SERIAL_NUMBER`
    /// (11), when it holds a 6-octet value.
    fn own_serial(&self) -> Option<[u8; 6]> {
        let prop = self.objects.get(&0)?.property(11)?;
        <[u8; 6]>::try_from(prop.value.as_slice()).ok()
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
    /// count from the group-object table (obj 3), loaded or being loaded
    /// (`table_count_being_loaded`), and the address-table length from the
    /// loaded address table (obj 1).
    fn security_limits(&self) -> SecurityLimits {
        SecurityLimits {
            group_objects: self.table_count_being_loaded(3),
            address_table_len: self.loaded_table_count(1),
        }
    }

    /// `A_FunctionPropertyExt_Command` / `_State_Read` on a function property
    /// of an object reached by type (KNX 3/3/7 §3.4.8): the answer is an
    /// `A_FunctionPropertyExt_State_Response` with return code 00h and no
    /// output data (bussard issue #422: the Gira IR-Gateway calls PID 208 of
    /// type 65281 with `FF`, `[d4 ff 01 00 10 d0 ff]`; the sim acknowledged it
    /// at the transport layer and never answered, and ETS reported "Das Gerät
    /// antwortet nicht", ETS sweep 2026-11-06). `None` when the property is
    /// not a function property of such an object (the security object and
    /// the KNXnet/IP object keep their own handlers).
    fn typed_function_call(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
        object_type: u16,
    ) -> Option<DeviceReaction> {
        if !matches!(
            apdu.apci,
            Apci::FunctionPropertyExtCommand | Apci::FunctionPropertyExtStateRead
        ) || object_type == security_object::IOT_SECURITY
            || object_type == super::knxnet_object::IOT_KNXNET_IP_PARAMETER
        {
            return None;
        }
        let header = apdu.data.get(..5)?;
        let packed =
            (u32::from(header[2]) << 16) | (u32::from(header[3]) << 8) | u32::from(header[4]);
        if packed >> 12 != 1 {
            return None;
        }
        let pid = u8::try_from(packed & 0x0FFF).ok()?;
        let is_type = |o: &super::InterfaceObject| {
            o.property(super::interface_object::PID_OBJECT_TYPE)
                .is_some_and(|p| p.value.as_slice() == object_type.to_be_bytes())
        };
        let function = self
            .typed_objects
            .get(&object_type)
            .or_else(|| self.objects.values().find(|o| is_type(o)))
            .and_then(|o| o.property(pid))
            .is_some_and(|p| p.is_function());
        if !function {
            return None;
        }
        let mut data = header.to_vec();
        data.push(0x00);
        Some(DeviceReaction {
            responses: vec![self.respond(tool, 0x1D6, &data)],
            did_master_reset: false,
        })
    }

    /// `A_FunctionPropertyExt_Command` / `_State_Read` on PID 5
    /// (`PID_LOAD_STATE_CONTROL`) of an object reached by type that has a
    /// load-state machine (bussard issue #422): the Gira Eco
    /// (`M-0008_A-C02A-21`) loads its vendor object type 40960 with
    /// `LdCtrlUnload ObjType="40960"`, which ETS sends as
    /// `[d4 a0 00 00 10 05 04 00 ..]`; the sim did not answer and ETS
    /// reported "Das Gerät antwortet nicht" (ETS sweep, 2026-11-06). The
    /// command applies the 10-octet load event; the answer is an
    /// `A_FunctionPropertyExt_State_Response` with return code 0 and the new
    /// state, or a non-zero return code and no data when the event is refused
    /// (PDT_CONTROL, KNX 3/3/7 §3.4.8.4, as the security object answers).
    /// `None` when the request is not for such an object.
    fn typed_load_control(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
        object_type: u16,
    ) -> Result<Option<DeviceReaction>, DeviceError> {
        let command = match apdu.apci {
            Apci::FunctionPropertyExtCommand => true,
            Apci::FunctionPropertyExtStateRead => false,
            _ => return Ok(None),
        };
        if object_type == super::security_object::IOT_SECURITY {
            return Ok(None);
        }
        let Some(header) = apdu.data.get(..5) else {
            return Ok(None);
        };
        let packed =
            (u32::from(header[2]) << 16) | (u32::from(header[3]) << 8) | u32::from(header[4]);
        if packed >> 12 != 1 || packed & 0x0FFF != u32::from(PID_LOAD_STATE_CONTROL) {
            return Ok(None);
        }
        let Some(index) = self
            .objects
            .iter()
            .find(|(i, o)| {
                self.loadables.contains_key(i)
                    && o.property(super::interface_object::PID_OBJECT_TYPE)
                        .is_some_and(|p| p.value.as_slice() == object_type.to_be_bytes())
            })
            .map(|(i, _)| *i)
        else {
            return Ok(None);
        };
        let accepted = if command {
            let body = apdu.data.get(5..).unwrap_or_default();
            // The by-index load control's checks and events; its answer is
            // replaced by the State_Response below, so the transport
            // sequence number it took is given back: the dropped answer used
            // seq 0 and the State_Response went out as seq 1 on a fresh
            // connection, which ETS refused with T_NAK until the sim gave up
            // (Gira Eco, ETS sweep 2026-11-06).
            let saved = self.tx_seq;
            let ok = self.on_load_state_write(tool, index, 1, 1, body).is_ok();
            self.tx_seq = saved;
            ok
        } else {
            true
        };
        let mut data = header.to_vec();
        match (accepted, self.report_load_state(index)) {
            (true, Some(state)) => data.extend_from_slice(&[0x00, state]),
            // E_IMPOSSIBLE_COMMAND (KNX 3/5/1 §6.3.9.3.3), as the security
            // object answers an event its state machine refuses.
            _ => data.push(security_object::rc::IMPOSSIBLE_COMMAND),
        }
        Ok(Some(DeviceReaction {
            responses: vec![self.respond(tool, 0x1D6, &data)],
            did_master_reset: false,
        }))
    }

    /// Handle an extended property service (`A_PropertyExtValue_*`,
    /// `A_PropertyExtDescription_Read`, `A_FunctionPropertyExt_*`).
    ///
    /// Only a security-activated device carries the security interface object;
    /// a plain device does not implement these services and stays silent (the
    /// numbered frame is still T_ACKed). A simulated IP interface answers an
    /// `A_PropertyExtValue_Read` of its KNXnet/IP parameter object (object type
    /// 11, bussard issue #391). An activated device only reaches this
    /// through A_SecureData: a plain request is refused by the secure
    /// interception in [`Device::handle_apdu`].
    pub(super) fn on_extended_property(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        // An object reached by type: the KNXnet/IP parameter object (type 11)
        // or a further typed object of a property-only device (bussard issue
        // #390). Read and confirmed write; the security object keeps its own
        // handler below.
        let object_type = apdu.data.get(..2).map(|t| u16::from_be_bytes([t[0], t[1]]));
        // The KNXnet/IP Secure properties of a KNX IP interface (bussard issue
        // #398): PIDs 91 to 97 of object type 11.
        if let Some(ip) = self.ip_secure.as_mut() {
            let answer = match apdu.apci {
                Apci::PropertyExtValueWriteCon => ip.write(&apdu.data).map(|d| (0x1CF, d)),
                Apci::PropertyExtValueRead => ip.read(&apdu.data).map(|d| (0x1CD, d)),
                Apci::FunctionPropertyExtCommand => {
                    ip.function(&apdu.data, true).map(|d| (0x1D6, d))
                }
                Apci::FunctionPropertyExtStateRead => {
                    ip.function(&apdu.data, false).map(|d| (0x1D6, d))
                }
                _ => None,
            };
            if let Some((apci, data)) = answer {
                let resp = self.respond(tool, apci, &data);
                return Ok(DeviceReaction {
                    responses: vec![resp],
                    did_master_reset: false,
                });
            }
        }
        if let Some(object_type) = object_type
            && let Some(reaction) = self.typed_load_control(tool, apdu, object_type)?
        {
            return Ok(reaction);
        }
        if let Some(object_type) = object_type
            && let Some(reaction) = self.typed_function_call(tool, apdu, object_type)
        {
            return Ok(reaction);
        }
        // The PIDs the `[knxnet]` table sets (bussard issue #391) are written
        // with array semantics below (element counts, both copies in step).
        let knxnet_write = apdu.apci == Apci::PropertyExtValueWriteCon
            && object_type == Some(super::knxnet_object::IOT_KNXNET_IP_PARAMETER)
            && super::knxnet_object::ext_pid(&apdu.data)
                .is_some_and(|pid| super::knxnet_object::WRITABLE.contains(&pid));
        if let Some(object_type) = object_type
            && !knxnet_write
            && matches!(
                apdu.apci,
                Apci::PropertyExtValueRead | Apci::PropertyExtValueWriteCon
            )
        {
            // An object the device holds by index, reached by its type: the
            // device object as type 0 (ETS reads PID 12 that way on the ABB
            // Modbus RTU gateway, 2026-10-28) or any object whose
            // PID_OBJECT_TYPE names the type.
            let by_index = self
                .objects
                .iter()
                .find(|(idx, o)| {
                    o.property(super::interface_object::PID_OBJECT_TYPE)
                        .map(|p| p.value.as_slice() == object_type.to_be_bytes())
                        .unwrap_or(object_type == 0 && **idx == 0)
                })
                .map(|(idx, _)| *idx);
            let obj = if object_type == super::knxnet_object::IOT_KNXNET_IP_PARAMETER {
                self.knxnet_by_type.as_mut()
            } else if self.typed_objects.contains_key(&object_type) {
                self.typed_objects.get_mut(&object_type)
            } else {
                by_index.and_then(|idx| self.objects.get_mut(&idx))
            };
            let reply = obj.and_then(|obj| {
                if apdu.apci == Apci::PropertyExtValueRead {
                    super::knxnet_object::typed_ext_read(object_type, obj, &apdu.data)
                        .map(|data| (0x1CD, data))
                } else {
                    super::knxnet_object::typed_ext_write(object_type, obj, &apdu.data)
                        .map(|data| (0x1CF, data))
                }
            });
            // A product's own PID of the KNXnet/IP object (bussard issue
            // #422) is written here: the listed copy follows.
            if object_type == super::knxnet_object::IOT_KNXNET_IP_PARAMETER
                && let Some((0x1CF, data)) = &reply
                && data.last() == Some(&0)
                && let Some(pid) = super::knxnet_object::ext_pid(&apdu.data)
            {
                self.knxnet_sync(pid, false);
            }
            if let Some((apci, data)) = reply {
                let resp = self.respond(tool, apci, &data);
                return Ok(DeviceReaction {
                    responses: vec![resp],
                    did_master_reset: false,
                });
            }
        }
        let slots = self.knxnet_slots;
        if knxnet_write
            && let Some(obj) = self.knxnet_by_type.as_mut()
            && let Some((data, written)) = super::knxnet_object::ext_write(obj, &apdu.data, slots)
        {
            if let Some(pid) = written {
                self.knxnet_sync(pid, false);
                let object = self.knxnet_index().unwrap_or(u8::MAX);
                self.emit(Event::PropertyWritten {
                    device: self.address,
                    object,
                    pid,
                });
            }
            let resp = self.respond(tool, super::knxnet_object::EXT_WRITE_CON_RESPONSE, &data);
            return Ok(DeviceReaction {
                responses: vec![resp],
                did_master_reset: false,
            });
        }
        if apdu.apci == Apci::PropertyExtDescriptionRead
            && let Some(obj) = &self.knxnet_by_type
            && let Some(data) = super::knxnet_object::ext_description(obj, &apdu.data, slots)
        {
            let resp = self.respond(tool, super::knxnet_object::EXT_DESCRIPTION_RESPONSE, &data);
            return Ok(DeviceReaction {
                responses: vec![resp],
                did_master_reset: false,
            });
        }
        // Any other object reached by type: a vendor object the procedure
        // compares (typed_objects) or an indexed object by its type.
        if apdu.apci == Apci::PropertyExtDescriptionRead
            && let Some(object_type) = object_type
            && object_type != super::knxnet_object::IOT_KNXNET_IP_PARAMETER
            && object_type != super::security_object::IOT_SECURITY
        {
            let by_index = self
                .objects
                .iter()
                .find(|(idx, o)| {
                    o.property(super::interface_object::PID_OBJECT_TYPE)
                        .map(|p| p.value.as_slice() == object_type.to_be_bytes())
                        .unwrap_or(object_type == 0 && **idx == 0)
                })
                .map(|(_, o)| o);
            let obj = self.typed_objects.get(&object_type).or(by_index);
            if let Some(data) =
                obj.and_then(|o| super::knxnet_object::typed_ext_description(o, &apdu.data))
            {
                let resp =
                    self.respond(tool, super::knxnet_object::EXT_DESCRIPTION_RESPONSE, &data);
                return Ok(DeviceReaction {
                    responses: vec![resp],
                    did_master_reset: false,
                });
            }
        }
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

/// The security tables of an `activated` start state (bussard issue #1054):
/// what a tool's earlier secured download left in the security object, given
/// in the config instead of replayed.
#[derive(Debug, Clone, Default)]
pub struct ActivatedTables {
    /// Group key rows by address-table index: `(index, key)`.
    pub group_keys_by_index: Vec<(u16, crate::secure::Key16)>,
    /// Group keys by group address (raw), resolved against the loaded
    /// address table: `(address, key, required)`. A required one must
    /// resolve; the others (a keyring's keys) are dropped when the device
    /// does not use the address.
    pub group_keys_by_address: Vec<(u16, crate::secure::Key16, bool)>,
    /// Security individual address table rows: `(sender IA, sequence)`.
    pub senders: Vec<(u16, u64)>,
    /// Group-object security flags: `(PID 61 element, flags)`.
    pub go_flags: Vec<(u16, u8)>,
}

impl Device {
    /// Presets the security object's tables of an `activated` start state
    /// (bussard issue #1054). The keys given by group address wait for
    /// [`Device::settle_activated_tables`], which runs once the address table
    /// is where it will be (after any replay). Refused on a device without a
    /// security object (no `security` block).
    pub fn with_activated_tables(mut self, tables: ActivatedTables) -> Result<Self, String> {
        let obj = self
            .security_object
            .as_mut()
            .ok_or("activated security tables need a `security` block")?;
        obj.preset_tables(
            &tables.group_keys_by_index,
            &tables.senders,
            &tables.go_flags,
        )?;
        obj.defer_group_keys(tables.group_keys_by_address);
        Ok(self)
    }

    /// Resolves the group keys of the `activated` start state given by group
    /// address against the loaded address table, once any replay has run: a
    /// required key whose address the table does not hold (or a device
    /// without a loaded address table) is an error, a keyring key for an
    /// address the device does not use is dropped.
    pub fn settle_activated_tables(&mut self) -> Result<(), String> {
        let addresses: Option<Vec<u16>> = (self.load_state(1) == Some(super::LoadState::Loaded))
            .then(|| self.base_of(1))
            .flatten()
            .map(|base| {
                super::group_comm::address_table(&self.memory, base)
                    .iter()
                    .map(|ga| ga.raw())
                    .collect()
            });
        let Some(obj) = self.security_object.as_mut() else {
            return Ok(());
        };
        if !obj.has_pending_group_keys() {
            return Ok(());
        }
        let missing = obj.resolve_pending_group_keys(&addresses.unwrap_or_default())?;
        if missing.is_empty() {
            return Ok(());
        }
        let names: Vec<String> = missing
            .iter()
            .map(|ga| crate::wire::GroupAddress(*ga).to_string())
            .collect();
        Err(format!(
            "group key for {}: the device's address table does not hold the address (load the \
             application first, e.g. with `replay`, or give the row by `index`)",
            names.join(", ")
        ))
    }
}
