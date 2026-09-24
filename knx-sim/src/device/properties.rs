//! Interface-object property services: `A_PropertyDescription_Read`,
//! `A_PropertyValue_Read` and `A_PropertyValue_Write`.

use crate::bus::event::Event;
use crate::wire::IndividualAddress;
use crate::wire::apdu::{Apci, Apdu};

use super::{
    Device, DeviceError, DeviceReaction, LoadState, PID_LOAD_STATE_CONTROL, PID_MCB_TABLE,
    PID_PROGMODE, PID_TABLE, profile,
};

impl Device {
    /// Decode the object/pid/count/start header shared by property verbs.
    /// Layout: `[obj, pid, (count<<4)|(start_hi), start_lo, value...]`.
    fn property_header(apdu: &Apdu) -> Result<(u8, u8, u8, u16, usize), DeviceError> {
        if apdu.data.len() < 4 {
            return Err(DeviceError::Malformed {
                service: "A_PropertyValue".into(),
                detail: "header too short".into(),
            });
        }
        let object = apdu.data[0];
        let pid = apdu.data[1];
        let count = apdu.data[2] >> 4;
        let start = (((apdu.data[2] & 0x0F) as u16) << 8) | apdu.data[3] as u16;
        Ok((object, pid, count, start, 4))
    }

    /// Answer an `A_PropertyDescription_Read` (issue #72).
    ///
    /// Request payload: `[object_index][property_id][property_index]`. A
    /// `property_id` of 0 addresses the property **by index** (the enumeration
    /// path — a tool walks the index `1..N`); a non-zero `property_id` addresses
    /// it by PID. The response echoes the object index, the real PID, and the
    /// property index, then the descriptor: a type octet (write-enable bit |
    /// PDT), a 2-octet big-endian element count, and an access octet (read level
    /// in the high nibble, write level in the low nibble).
    ///
    /// A request for a property or index the object does not define is answered
    /// with a `max_elements == 0` descriptor — the spec's "no property here"
    /// signal that terminates an enumeration walk, exactly as the value-read path
    /// answers an unknown PID with `nr_of_elem == 0` rather than going silent.
    pub(super) fn on_property_description_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if apdu.data.len() < 3 {
            return Err(DeviceError::Malformed {
                service: "A_PropertyDescription_Read".into(),
                detail: "header too short".into(),
            });
        }
        let object = apdu.data[0];
        let req_pid = apdu.data[1];
        let req_index = apdu.data[2];

        let desc = self.objects.get(&object).and_then(|io| {
            if req_pid != 0 {
                io.describe_pid(req_pid)
            } else {
                io.describe_at_index(req_index)
            }
        });

        // The 7-octet response payload. On absence, echo the addressing with a
        // zero type / zero count / zero access — a real "no property" descriptor.
        let data = match desc {
            Some(d) => {
                let type_octet = (if d.writable { 0x80u8 } else { 0 }) | (d.pdt & 0x3F);
                let max = d.max_elements & 0x0FFF;
                let access = ((d.read_level & 0x0F) << 4) | (d.write_level & 0x0F);
                vec![
                    object,
                    d.pid,
                    // Echo the property index the tool asked for when addressing by
                    // index; when addressing by PID the request index is 0, so
                    // report the PID's own index (its 1-based position).
                    if req_pid != 0 {
                        self.objects
                            .get(&object)
                            .map(|io| {
                                io.pids()
                                    .iter()
                                    .position(|&p| p == d.pid)
                                    .map_or(0, |i| i as u8 + 1)
                            })
                            .unwrap_or(0)
                    } else {
                        req_index
                    },
                    type_octet,
                    (max >> 8) as u8,
                    (max & 0xFF) as u8,
                    access,
                ]
            }
            None => vec![object, req_pid, req_index, 0x00, 0x00, 0x00, 0x00],
        };
        let resp = self.respond(tool, Apci::PropertyDescriptionResponse.to_u10(), &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    pub(super) fn on_property_read(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let (object, pid, count, start, _) = Self::property_header(apdu)?;
        // PID_LOAD_STATE_CONTROL read-back returns the LIVE load state as a
        // single octet (the 10-octet load-event value is write-only). The state
        // lives in the load-state machine, not the seeded property, so a read
        // must reflect the current LSM state — otherwise a tool that reads PID 5
        // to verify a StartLoading/LoadCompleted sees a stale value and stalls.
        // (Spec Resources 03.05.01 §4.23.2; ref `knx-device-spec-references.md`
        // §2.1/§2.3.)
        let value = if pid == PID_LOAD_STATE_CONTROL {
            self.load_state(object).map(|s| vec![s.to_byte()])
        } else if pid == PID_MCB_TABLE {
            // PID_MCB_TABLE (27) is device-computed: answer with the 8-octet
            // memory-control-block entry (size + CRC-16/AUG-CCITT) over the bytes
            // this object currently holds in its allocated segment. A tool's
            // LdCtrlLoadImageProp verify step reads this back and compares the CRC
            // to the image it streamed, so it must reflect the real stored bytes.
            //
            // ONE entry per request. A real Jung 3361-1MWW (mask 0705,
            // application `M-0004_A-A011-13`) REFUSED a multi-element read:
            // bussard sent `A_PropertyValue_Read obj=3 pid=27 count=6 start=1`,
            // taken literally from `LdCtrlLoadImageProp ObjIdx="3" PropId="27"
            // Count="6"`, and the device answered count 0 with no data (issue
            // #89 campaign, 1.1.36). Six 8-octet entries are 48 octets of value,
            // far past a standard-frame APDU, and a real device does not
            // partially answer a property read — it refuses the whole request
            // with the zero-count response. The 1.1.31 ETS capture reads the six
            // entries one at a time (`count=1`, index 1..=6), which is the only
            // shape a tool may rely on. `None` here lands in the zero-count
            // branch below, the same signal the Jung sent.
            if count > 1 {
                None
            } else {
                self.mcb_entry_for(object)
            }
        } else {
            self.objects
                .get(&object)
                .and_then(|o| o.property(pid))
                .map(|p| p.value.clone())
        };
        match value {
            Some(value) => {
                // Response echoes obj/pid/count/start then the value.
                let mut data = vec![
                    object,
                    pid,
                    (count << 4) | ((start >> 8) as u8 & 0x0F),
                    (start & 0xFF) as u8,
                ];
                data.extend_from_slice(&value);
                let resp = self.respond(tool, 0x3D6, &data);
                Ok(DeviceReaction {
                    responses: vec![resp],
                    did_master_reset: false,
                })
            }
            // Unknown object or PID: the spec-mandated error signal for a
            // property read is an A_PropertyValue_Response that echoes the
            // header with nr_of_elem = 0 and no data (KNX App-Layer 03.03.07
            // §3.4.4.2; ref `knx-device-spec-references.md` §4.4). This is what
            // lets a tool distinguish "no such object/property" (e.g. the end
            // of the interface-object table while probing PID_OBJECT_TYPE) from
            // a dropped telegram, so it must be a real response, not silence.
            None => Ok(DeviceReaction {
                responses: vec![self.respond(
                    tool,
                    0x3D6,
                    &[object, pid, (start >> 8) as u8 & 0x0F, (start & 0xFF) as u8],
                )],
                did_master_reset: false,
            }),
        }
    }

    pub(super) fn on_property_write(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let (object, pid, count, start, hdr) = Self::property_header(apdu)?;
        let value = &apdu.data[hdr..];

        // Writes require authorization (level 0).
        if self.access_level != 0 {
            return Err(DeviceError::Unauthorized {
                level: self.access_level,
            });
        }

        // PID_LOAD_STATE_CONTROL drives the load-state machine.
        if pid == PID_LOAD_STATE_CONTROL {
            // A System 7 device configured for property-based LSM access decodes
            // the 10-octet load event straight from the PID 5 value and drives the
            // addressed LSM (spec section 5, LsmAccess::Property). A System 7
            // device configured memory-mapped refuses a PID 5 load write — a real
            // memory-mapped device does not accept it, so a tool that used the
            // wrong realisation is caught.
            if let Some(s7) = &self.sys7 {
                if s7.profile.lsm_access == profile::LsmAccess::Property {
                    self.apply_sys7_event(tool, object, value)?;
                    // Property-based LSM write echoes the resulting state.
                    let state = self.load_state(object).unwrap_or(LoadState::Error);
                    let mut data = vec![
                        object,
                        PID_LOAD_STATE_CONTROL,
                        (count << 4) | ((start >> 8) as u8 & 0x0F),
                        (start & 0xFF) as u8,
                    ];
                    data.push(state.to_byte());
                    let resp = self.respond(tool, 0x3D6, &data);
                    return Ok(DeviceReaction {
                        responses: vec![resp],
                        did_master_reset: false,
                    });
                }
                return Err(DeviceError::LoadControl(
                    "System 7 memory-mapped device does not accept a PID 5 load write".into(),
                ));
            }
            return self.on_load_state_write(tool, object, count, start, value);
        }

        // PID_TABLE (23) is NOT a download path. A real device realises a
        // loadable table in the object's allocated segment: the tool sizes it
        // with an `AdditionalLoadControls` / `LdCtrlRelSegment` write, reads the
        // placement from `PID_TABLE_REFERENCE`, and streams the image (count word
        // + elements) with `A_Memory_Write` / `A_MemoryExtended_Write`.
        //
        // Evidence (issue #89, 2026 physical campaign): a Jung F50 push-button
        // module (52911ST, application `M-0004_A-D141-22`) REFUSED
        // `A_PropertyValue_Write` to PID 23 with a zero-count
        // `A_PropertyValue_Response` — the header echoed back with
        // `nr_of_elem = 0` and no data (KNX App-Layer 03.03.07 §3.4.4.2, the same
        // "cannot serve this access" signal a property read uses). Two
        // independent ETS captures (a Jung F50 sibling at 1.1.18, and KNX Virtual
        // DA.tp) show ETS never attempts the property path either. Only the
        // lenient KNX Virtual stack happens to *accept* such a write, which is
        // precisely why a tool tested against it alone can ship a download that
        // no real device performs. The simulator is the adversarial peer, so it
        // takes the real device's side: refused, with no opt-out.
        if pid == PID_TABLE {
            let resp = self.respond(
                tool,
                0x3D6,
                &[object, pid, (start >> 8) as u8 & 0x0F, (start & 0xFF) as u8],
            );
            return Ok(DeviceReaction {
                responses: vec![resp],
                did_master_reset: false,
            });
        }

        let io = self
            .objects
            .get_mut(&object)
            .ok_or(DeviceError::NoProperty { object, pid })?;
        let prop = io
            .property_mut(pid)
            .ok_or(DeviceError::NoProperty { object, pid })?;
        if prop.read_only {
            return Err(DeviceError::ReadOnlyProperty { object, pid });
        }
        prop.value = value.to_vec();
        self.emit(Event::PropertyWritten {
            device: self.address,
            object,
            pid,
        });
        // A write of PID_PROGMODE on the device object (index 0) enters (value
        // != 0) or leaves (0) programming mode, exactly as ETS/`bussard assign`
        // toggle it. Keep the runtime bit in sync so the broadcast-read answer
        // tracks the property. (`prop.value` above already stored the byte; this
        // re-affirms it and flips the bit / emits the change event.)
        if object == 0 && pid == PID_PROGMODE {
            self.sync_prog_mode(value.first().copied().unwrap_or(0) != 0);
        }
        // Response echoes obj/pid/count/start + the written value.
        let mut data = vec![
            object,
            pid,
            (count << 4) | ((start >> 8) as u8 & 0x0F),
            (start & 0xFF) as u8,
        ];
        data.extend_from_slice(value);
        let resp = self.respond(tool, 0x3D6, &data);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }
}
