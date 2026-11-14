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

    /// `A_FunctionPropertyCommand` / `A_FunctionPropertyState_Read` by
    /// object index (KNX 3/3/7 §3.4.7): a property of `PDT_FUNCTION` runs and
    /// answers `A_FunctionPropertyState_Response` with return code 00h
    /// (success) and no output data; any other property, or none, answers
    /// without return code and data (§3.4.7.3). The Siemens 0701 programs
    /// (`M-0006_A-E01D-01`) call object 5's PID 52 with `04` before the
    /// download; the sim did not answer and ETS reported "Das Gerät antwortet
    /// nicht" (ETS sweep, 2026-11-05).
    pub(super) fn on_function_property(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        let (Some(&object), Some(&pid)) = (apdu.data.first(), apdu.data.get(1)) else {
            return Err(DeviceError::Malformed {
                service: "A_FunctionPropertyCommand".into(),
                detail: format!("{} octet(s), need object index and PID", apdu.data.len()),
            });
        };
        let function = self
            .objects
            .get(&object)
            .and_then(|o| o.property(pid))
            .is_some_and(|p| p.is_function());
        let mut data = vec![object, pid];
        if function {
            data.push(0x00);
            if apdu.apci == Apci::FunctionPropertyCommand {
                self.emit(Event::PropertyWritten {
                    device: self.address,
                    object,
                    pid,
                });
            }
        }
        Ok(DeviceReaction {
            responses: vec![self.respond(tool, 0x2C9, &data)],
            did_master_reset: false,
        })
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

        // The KNXnet/IP parameter object describes its real element counts.
        let desc = match (desc, self.objects.get(&object)) {
            (Some(d), Some(obj)) if super::knxnet_object::is_knxnet(obj) => {
                Some(super::knxnet_object::refine(d, obj, self.knxnet_slots))
            }
            (desc, _) => desc,
        };
        // ETS 6.4 reads the description of PID_TABLE on the table objects
        // before a System B download. A real device describes it (PDT 0x14,
        // writable, one element, read level 3, property index 3: three house
        // devices in the ETS captures of 2026-10-27) although it then refuses
        // the table write itself (DESIGN.md). Without a description ETS
        // disconnects and reports the download as failed.
        let table_object = self.objects.get(&object).is_some_and(|io| {
            io.property(super::interface_object::PID_OBJECT_TYPE)
                .is_some_and(|p| matches!(p.value.as_slice(), [0, 1] | [0, 2] | [0, 3]))
        });
        let synthesized =
            desc.is_none() && req_pid == super::interface_object::PID_TABLE && table_object;
        let desc = desc.or_else(|| {
            synthesized.then_some(super::interface_object::PropertyDescription {
                pid: super::interface_object::PID_TABLE,
                pdt: 0x14,
                writable: true,
                max_elements: 1,
                read_level: 3,
                write_level: 0,
            })
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
        let mut data = data;
        if synthesized {
            data[2] = 3; // the property index the house devices report for PID_TABLE
        }
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
        // The KNXnet/IP parameter object of an IP interface (bussard issue
        // #391) serves its properties as arrays: start 0 is the element count,
        // a range past the end is refused whole.
        if pid != super::interface_object::PID_OBJECT_TYPE
            && let Some(obj) = self.objects.get(&object)
            && obj
                .property(super::interface_object::PID_OBJECT_TYPE)
                .map(|p| p.value.as_slice())
                == Some(&super::knxnet_object::IOT_KNXNET_IP_PARAMETER.to_be_bytes()[..])
        {
            let answer = obj
                .property(pid)
                .and_then(|p| super::knxnet_object::array_read(pid, &p.value, count, start));
            let (n, bytes) = answer.unwrap_or((0, Vec::new()));
            let mut data = vec![
                object,
                pid,
                (n << 4) | ((start >> 8) as u8 & 0x0F),
                (start & 0xFF) as u8,
            ];
            data.extend_from_slice(&bytes);
            return Ok(DeviceReaction {
                responses: vec![self.respond(tool, 0x3D6, &data)],
                did_master_reset: false,
            });
        }
        // PID_LOAD_STATE_CONTROL read-back returns the LIVE load state as a
        // single octet (the 10-octet load-event value is write-only). The state
        // lives in the load-state machine, not the seeded property, so a read
        // must reflect the current LSM state — otherwise a tool that reads PID 5
        // to verify a StartLoading/LoadCompleted sees a stale value and stalls.
        // (Spec Resources 03.05.01 §4.23.2; ref `knx-device-spec-references.md`
        // §2.1/§2.3.)
        let value = if pid == PID_LOAD_STATE_CONTROL {
            self.report_load_state(object).map(|s| vec![s])
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
                // Start index 0 answers entry 1, as it always did here:
                // bussard's resident-MCB pre-pass reads it that way (its
                // standard meaning, the element count, is not modelled).
                self.mcb_entry_at(object, start.max(1))
            }
        } else {
            self.objects
                .get(&object)
                .and_then(|o| o.property(pid))
                // A function property holds no value: the zero-count answer
                // (KNX 3/3/7 §3.4.7.3).
                .filter(|p| !p.is_function())
                .and_then(|p| {
                    // An array property (a product's `Count` > 1 write, issue
                    // #692) answers the elements asked for; a range past its
                    // end is the zero-count refusal below.
                    if p.max_elements > 1 {
                        p.read_elements(start, count)
                    } else {
                        Some(p.value.clone())
                    }
                })
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

        // The KNXnet/IP parameter object of an IP interface (bussard issue
        // #391) takes writes element by element; a refused write is the
        // zero-count response.
        if pid != super::interface_object::PID_OBJECT_TYPE
            && self
                .objects
                .get(&object)
                .is_some_and(super::knxnet_object::is_knxnet)
        {
            let slots = self.knxnet_slots;
            let taken = self
                .objects
                .get_mut(&object)
                .and_then(|o| o.property_mut(pid))
                .filter(|p| !p.read_only)
                .is_some_and(|p| {
                    super::knxnet_object::array_write(pid, &mut p.value, start, value, slots)
                });
            let mut data = vec![
                object,
                pid,
                ((if taken { count } else { 0 }) << 4) | ((start >> 8) as u8 & 0x0F),
                (start & 0xFF) as u8,
            ];
            if taken {
                data.extend_from_slice(value);
                self.knxnet_sync(pid, true);
                self.emit(Event::PropertyWritten {
                    device: self.address,
                    object,
                    pid,
                });
            }
            return Ok(DeviceReaction {
                responses: vec![self.respond(tool, 0x3D6, &data)],
                did_master_reset: false,
            });
        }

        // PID_LOAD_STATE_CONTROL drives the load-state machine.
        if pid == PID_LOAD_STATE_CONTROL {
            // The write value is always 10 octets (Resources §4.2.5); a
            // shorter one is a tool bug a real device need not understand.
            if value.len() != 10 {
                return Err(DeviceError::LoadControl(format!(
                    "PID_LOAD_STATE_CONTROL write of {} octet(s); the value is always 10",
                    value.len()
                )));
            }
            // A System 7 device configured for property-based LSM access decodes
            // the 10-octet load event straight from the PID 5 value and drives the
            // addressed LSM (spec section 5, LsmAccess::Property). A System 7
            // device configured memory-mapped refuses a PID 5 load write — a real
            // memory-mapped device does not accept it, so a tool that used the
            // wrong realisation is caught.
            if let Some(s7) = &self.sys7 {
                if s7.profile.lsm_access == profile::LsmAccess::Property {
                    self.apply_sys7_event(tool, object, value)?;
                    // Property-based LSM write echoes the resulting state
                    // (the intermediate one first, bussard issue #479).
                    let state = self
                        .report_load_state(object)
                        .unwrap_or(LoadState::Error.to_byte());
                    let mut data = vec![
                        object,
                        PID_LOAD_STATE_CONTROL,
                        (count << 4) | ((start >> 8) as u8 & 0x0F),
                        (start & 0xFF) as u8,
                    ];
                    data.push(state);
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

        // PID_MCB_TABLE (27) is device-computed on read (see `on_property_read`),
        // but a load procedure may seed it first: the Jung F50 push-button
        // (`M-0004_A-D142-21`) writes the expected 10-octet entry to object 4
        // with `LdCtrlWriteProp` before it streams the segment, and the real
        // device accepts that write. Accept it on a loadable object while it is
        // Loading, echo it, and keep computing the read from the stored bytes.
        // Each 8-octet entry is kept by element: its size, CRC control byte
        // and access read back as written, with the CRC the device computes
        // over its subsegment (bussard issues #840 and #1073,
        // `Device::mcb_entry_at`).
        if pid == PID_MCB_TABLE && self.load_state(object) == Some(LoadState::Loading) {
            if count == 1
                && let Ok(entry) = <[u8; super::MCB_ENTRY_LEN]>::try_from(value)
                && let Some(state) = self.loadables.get_mut(&object)
            {
                state.mcb_written.insert(start, entry);
            }
            let mut data = vec![
                object,
                pid,
                (count << 4) | ((start >> 8) as u8 & 0x0F),
                (start & 0xFF) as u8,
            ];
            data.extend_from_slice(value);
            self.emit(Event::PropertyWritten {
                device: self.address,
                object,
                pid,
            });
            let resp = self.respond(tool, 0x3D6, &data);
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
        if prop.max_elements > 1 {
            // An array property (a product's `Count` > 1 write, issue #692):
            // `count` elements from `start`. A write that does not fit the
            // described elements is refused whole with the zero-count response.
            if !prop.write_elements(start, count, value) {
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
        } else {
            prop.value = value.to_vec();
        }
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

#[cfg(test)]
mod tests {
    use crate::device::test_support::*;
    use crate::device::*;

    /// Bussard issue #422: the Siemens 0701 program `M-0006_A-E01D-01`
    /// writes object 5's PID 51 and calls its function property PID 52 with
    /// `04` (`LdCtrlInvokeFunctionProp`), the frames ETS sent in the sweep
    /// capture of 2026-11-05.
    #[test]
    fn test_function_property_command_answers_the_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut product = crate::testfixtures::synthetic_mdt_sys7_product();
        product.mask_version = "MV-0701".into();
        product.written_props.push((5, 51, 10, 1));
        product.function_props.push((5, 52));
        let mut dev = Device::from_product(
            IndividualAddress::new(1, 1, 1),
            &product,
            LoadState::Unloaded,
            std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
        );
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]))?;
        // [c7 05 34 04]: A_FunctionPropertyState_Response [c9 05 34 00].
        let r = dev.handle_cemi(&data(&dev, 0x2C7, &[0x05, 0x34, 0x04]))?;
        let resp = r.responses.last().ok_or("an answer")?;
        assert_eq!(resp.tpdu[0] & 0x03, 0x02);
        assert_eq!(resp.tpdu[1..], [0xC9, 0x05, 0x34, 0x00]);
        // The full,par variant calls it with 10; the state read answers too.
        let r = dev.handle_cemi(&data(&dev, 0x2C7, &[0x05, 0x34, 0x10]))?;
        assert_eq!(
            r.responses.last().ok_or("an answer")?.tpdu[1..],
            [0xC9, 0x05, 0x34, 0x00]
        );
        let r = dev.handle_cemi(&data(&dev, 0x2C8, &[0x05, 0x34]))?;
        assert_eq!(
            r.responses.last().ok_or("an answer")?.tpdu[1..],
            [0xC9, 0x05, 0x34, 0x00]
        );
        // Described as PDT_FUNCTION, one element (KNX 3/3/7 §3.4.7.3).
        let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x05, 0x34, 0x00]))?;
        let d = &r.responses.last().ok_or("a description")?.tpdu;
        assert_eq!(d[5] & 0x3F, 0x3E);
        assert_eq!(u16::from_be_bytes([d[6], d[7]]) & 0x0FFF, 1);
        // A data property: no return code, no data.
        let r = dev.handle_cemi(&data(&dev, 0x2C7, &[0x05, 0x33, 0x01]))?;
        assert_eq!(
            r.responses.last().ok_or("an answer")?.tpdu[1..],
            [0xC9, 0x05, 0x33]
        );
        Ok(())
    }

    #[test]
    fn test_object_type_discovery_returns_iot_per_index() -> Result<(), Box<dyn std::error::Error>>
    {
        // A tool discovers the interface-object table by reading PID_OBJECT_TYPE
        // (PID 1) on each object index. The device must report each object's
        // IOT: [0:device, 1:address-table, 2:association-table,
        // 3:group-object-table, 4:application-program]. The object that owns the
        // application code segment (LSM index 4 at base 0x6000) is the
        // application-program object (type 3), and the com-object table (LSM index
        // 3 at 0x8000) is the group-object-table object (type 9) — so a tool's
        // MCB image-integrity read lands on the object that actually holds each
        // segment.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let expected: [(u8, u16); 5] = [
            (0, iot::DEVICE),
            (1, iot::ADDRESS_TABLE),
            (2, iot::ASSOCIATION_TABLE),
            (3, iot::GROUP_OBJECT_TABLE),
            (4, iot::APPLICATION_PROGRAM),
        ];
        for (object, want) in expected {
            // A_PropertyValue_Read obj/pid=1/count=1/start=1.
            let r = dev.handle_cemi(&data(&dev, 0x3D5, &[object, 0x01, 0x10, 0x01]))?;
            let value = prop_response_value(&r);
            assert_eq!(
                value,
                want.to_be_bytes(),
                "object {object} reported wrong interface-object type"
            );
        }
        Ok(())
    }

    #[test]
    fn test_property_read_unknown_object_returns_error_signal()
    -> Result<(), Box<dyn std::error::Error>> {
        // Reading PID_OBJECT_TYPE past the end of the object table must return
        // the spec error signal: an A_PropertyValue_Response echoing the header
        // with nr_of_elem = 0 and no value (not silence), so a probing tool can
        // detect the table end rather than time out.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        // Object 6 does not exist on the DA.tp device.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x06, 0x01, 0x10, 0x01]))?;
        assert_eq!(r.responses.len(), 1, "must respond, not drop");
        let resp = &r.responses[0];
        // TPDU: [tpci][d6][obj=06][pid=01][count|start_hi][start_lo]; count = 0.
        let count = resp.tpdu[4] >> 4;
        assert_eq!(count, 0, "unknown property must report nr_of_elem = 0");
        assert_eq!(resp.tpdu.len(), 6, "error signal carries no value bytes");
        Ok(())
    }

    #[test]
    fn test_property_description_read_by_index_and_terminates()
    -> Result<(), Box<dyn std::error::Error>> {
        // A_PropertyDescription_Read on object 0 by index (PID 0): the device
        // answers each index with a 7-octet descriptor and reports the first
        // absent index with max_elements == 0 (the enumeration terminator).
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        // Object 0 exposes several device-object properties; index 1 is PID 1
        // (PID_OBJECT_TYPE) since the property map is PID-sorted.
        let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x00, 0x00, 0x01]))?;
        assert_eq!(r.responses.len(), 1, "must respond to a description read");
        let resp = &r.responses[0];
        // TPDU: [tpci][apci_lo][obj][pid][index][type][max_hi][max_lo][access].
        let payload = &resp.tpdu[2..];
        assert_eq!(payload[0], 0x00, "object index echoed");
        assert_eq!(payload[1], PID_OBJECT_TYPE, "index 1 is PID_OBJECT_TYPE");
        assert_eq!(payload[2], 0x01, "property index echoed");
        // PID_OBJECT_TYPE is read-only → write-enable bit clear, PDT generic.
        assert_eq!(payload[3] & 0x80, 0, "read-only property");
        assert_eq!(payload[3] & 0x3F, PDT_VARIABLE_LENGTH);
        let max = u16::from_be_bytes([payload[4], payload[5]]);
        assert_eq!(max, 1, "one element");
        // read level 3 (high nibble), write level 15 (read-only, low nibble).
        assert_eq!(payload[6] >> 4, 3);
        assert_eq!(payload[6] & 0x0F, 15);

        // Walk indices until absence: the device reports max_elements == 0 once
        // the index runs past the object's property list.
        let mut last_present = 0u8;
        for index in 1u8..=32 {
            let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x00, 0x00, index]))?;
            let payload = &r.responses[0].tpdu[2..];
            let max = u16::from_be_bytes([payload[4], payload[5]]);
            if max == 0 {
                break;
            }
            last_present = index;
        }
        assert!(last_present >= 1, "object 0 has at least one property");
        Ok(())
    }

    #[test]
    fn test_property_description_read_by_pid() -> Result<(), Box<dyn std::error::Error>> {
        // Addressing by PID (non-zero property_id) returns that PID's descriptor
        // and reports its 1-based property index. PID_PROGMODE is writable.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x00, PID_PROGMODE, 0x00]))?;
        let payload = &r.responses[0].tpdu[2..];
        assert_eq!(payload[1], PID_PROGMODE, "PID echoed");
        assert!(payload[2] >= 1, "a real 1-based property index reported");
        assert_eq!(payload[3] & 0x80, 0x80, "PID_PROGMODE is writable");
        assert_eq!(payload[6] & 0x0F, 0, "writable → write level 0");
        Ok(())
    }

    #[test]
    fn test_property_description_read_unknown_reports_zero_max()
    -> Result<(), Box<dyn std::error::Error>> {
        // A description read for an object that does not exist is answered with a
        // zero-max descriptor (not silence), matching the value-read error signal.
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D8, &[0x40, 0x00, 0x01]))?;
        assert_eq!(r.responses.len(), 1, "must respond, not drop");
        let payload = &r.responses[0].tpdu[2..];
        let max = u16::from_be_bytes([payload[4], payload[5]]);
        assert_eq!(max, 0, "unknown object → max_elements 0");
        Ok(())
    }

    #[test]
    fn test_pid_table_property_write_is_refused_with_zero_count()
    -> Result<(), Box<dyn std::error::Error>> {
        // A real System B device does not take a loadable table through the
        // PID_TABLE property array. The Jung F50 52911ST answered this write with
        // a zero-count A_PropertyValue_Response (issue #89); the simulator models
        // that, so a tool that skips the allocate + memory-write realisation is
        // caught here rather than on a real bus.
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        // Authorize first, so the refusal is about PID 23 and not about access.
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        assert_eq!(dev.access_level, 0);

        // A_PropertyValue_Write(object 1, PID 23, count 1, start 1, [0x12, 0x34]).
        let write = data(&dev, 0x3D7, &[0x01, PID_TABLE, 0x10, 0x01, 0x12, 0x34]);
        let reaction = dev.handle_cemi(&write)?;

        // A refusal is still an answer, not silence: the tool must be able to
        // tell "refused" from "dropped telegram".
        let resp = reaction
            .responses
            .first()
            .ok_or("a refused PID_TABLE write must still be answered")?;
        let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
        assert_eq!(Apci::from_u10(apci10), Apci::PropertyValueResponse);
        assert_eq!(
            &resp.tpdu[2..],
            // object, pid, nr_of_elem = 0 in the high nibble | start_hi, start_lo
            &[0x01, PID_TABLE, 0x00, 0x01],
            "the header is echoed with nr_of_elem = 0 and no data"
        );

        // And nothing was stored: no PID 23 appeared on the object, and the write
        // left the device's memory untouched.
        assert!(
            dev.objects
                .get(&1)
                .map(|o| o.property(PID_TABLE).is_none())
                .unwrap_or(true),
            "a refused write must not create or fill PID_TABLE"
        );
        Ok(())
    }

    const PID_PEI_TYPE: u8 = 16;

    #[test]
    fn test_load_procedure_property_write_is_echoed() -> Result<(), Box<dyn std::error::Error>> {
        // An ABB i-bus load procedure (`M-0002_A-A0ED-10`) writes the PEI type
        // with `LdCtrlWriteProp ObjIdx=4 PropId=16 InlineData=0A` before the
        // image. A real System B device accepts it; the simulator must answer
        // too, or the tool waits on a dropped telegram.
        let mut pd = crate::testfixtures::synthetic_mdt_sys7_product();
        pd.objects.push(crate::prod::LoadableObject {
            lsm_index: 4,
            name: "application program".into(),
            max_size: None,
            image: Vec::new(),
        });
        pd.written_props.push((4, PID_PEI_TYPE, 1, 1));
        let mut dev = Device::from_product_with_overrides(
            IndividualAddress::new(1, 1, 2),
            &pd,
            LoadState::Unloaded,
            ProfileOverrides {
                mask: Some("07B0".into()),
                ..Default::default()
            },
            std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
        )?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;

        let write = data(&dev, 0x3D7, &[0x04, PID_PEI_TYPE, 0x10, 0x01, 0x0A]);
        let reaction = dev.handle_cemi(&write)?;
        assert_eq!(prop_response_value(&reaction), vec![0x0A]);
        let stored = dev
            .objects
            .get(&4)
            .and_then(|o| o.property(PID_PEI_TYPE))
            .map(|p| p.value.clone());
        assert_eq!(stored, Some(vec![0x0A]));
        Ok(())
    }

    #[test]
    fn test_sys7_pid78_preflight_value_is_readable() -> Result<(), Box<dyn std::error::Error>> {
        // Object-0 PID 78 (PID_HARDWARE_TYPE) serves the 10-octet preflight
        // value the MDT CompareProp matches. App 14 seeds byte 5 = 0x0E.
        let mut dev = sys7_device(LsmAccess::MemoryMapped);
        connect(&mut dev)?;
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x00, 0x4E, 0x10, 0x01]))?;
        let value = prop_response_value(&r);
        assert_eq!(value.len(), 10, "PID 78 is a 10-octet value");
        assert_eq!(value[4], 0x03, "byte 4 is the run-state marker");
        Ok(())
    }

    /// One System B load of object 4: StartLoading, a 4-octet segment, the
    /// MCB entry `mcb` written when given, the image, LoadCompleted; returns
    /// the PID 27 read-back.
    fn load_object_4(
        dev: &mut Device,
        mcb: Option<[u8; 8]>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let event = |dev: &mut Device, e: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
            let mut payload = vec![0x04, PID_LOAD_STATE_CONTROL, 0x10, 0x01];
            payload.extend_from_slice(e);
            payload.resize(14, 0);
            dev.handle_cemi(&data(dev, 0x3D7, &payload))?;
            Ok(())
        };
        event(dev, &[0x04])?; // Unload
        event(dev, &[0x01])?; // StartLoading
        event(dev, &[0x03, 0x0b, 0x00, 0x00, 0x00, 0x04])?; // 4-octet segment
        if let Some(entry) = mcb {
            let mut write = vec![0x04, PID_MCB_TABLE, 0x10, 0x01];
            write.extend_from_slice(&entry);
            let r = dev.handle_cemi(&data(dev, 0x3D7, &write))?;
            assert_eq!(prop_response_value(&r), entry.to_vec(), "write echoed");
        }
        dev.handle_cemi(&data(dev, 0x280 | 4, &[0x60, 0x00, 1, 2, 3, 4]))?;
        event(dev, &[0x02])?; // LoadCompleted
        let r = dev.handle_cemi(&data(dev, 0x3D5, &[0x04, PID_MCB_TABLE, 0x10, 0x01]))?;
        Ok(prop_response_value(&r))
    }

    #[test]
    fn test_on_property_write_mcb_entry_reads_back_with_device_crc()
    -> Result<(), Box<dyn std::error::Error>> {
        // ETS writes object 4's MCB entry while Loading
        // (`LdCtrlWriteProp ObjIdx="4" PropId="27"`, ekinex A-4945:
        // `00000016 00 32 0000`) and reads it back after LoadCompleted. A
        // device keeps size, CRC control byte and access, and computes the
        // CRC on the way to Loaded (Resources 03.05.01 §4.2.27). The sim
        // answered `00 ff 20ba` (2026-11-04, bussard issue #840).
        let mut dev = Device::from_product_with_overrides(
            crate::wire::IndividualAddress::new(1, 1, 1),
            &crate::testfixtures::synthetic_system_b_product(),
            LoadState::Loaded,
            ProfileOverrides::default(),
            std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
        )?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        let crc = crc16_aug_ccitt(&[1, 2, 3, 4]).to_be_bytes();
        let mcb = load_object_4(&mut dev, Some([0, 0, 0, 4, 0x00, 0x32, 0, 0]))?;
        assert_eq!(mcb, vec![0, 0, 0, 4, 0x00, 0x32, crc[0], crc[1]]);
        // The entry covers the size written: two octets of the four.
        let mcb = load_object_4(&mut dev, Some([0, 0, 0, 2, 0x01, 0x32, 0, 0]))?;
        let crc2 = crc16_aug_ccitt(&[1, 2]).to_be_bytes();
        assert_eq!(mcb, vec![0, 0, 0, 2, 0x01, 0x32, crc2[0], crc2[1]]);
        // An Unload forgets it: a load without the write reads the
        // device's own entry over the written span.
        let mcb = load_object_4(&mut dev, None)?;
        assert_eq!(mcb, vec![0, 0, 0, 4, 0x00, 0xff, crc[0], crc[1]]);
        Ok(())
    }

    #[test]
    fn test_mcb_entry_at_answers_each_written_subsegment() -> Result<(), Box<dyn std::error::Error>>
    {
        // Bussard issue #1073: the Jung `M-0004_A-146F-11-17FA-O00F4`
        // procedure writes four entries and ETS reads each back. Entry 2
        // describes the octets after entry 1's, with the CRC over them; it
        // answered entry 1 before.
        let mut dev = Device::from_product_with_overrides(
            crate::wire::IndividualAddress::new(1, 1, 1),
            &crate::testfixtures::synthetic_system_b_product(),
            LoadState::Loaded,
            ProfileOverrides::default(),
            std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
        )?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        let first = load_object_4(&mut dev, Some([0, 0, 0, 3, 0x00, 0x33, 0, 0]))?;
        let crc1 = crc16_aug_ccitt(&[1, 2, 3]).to_be_bytes();
        assert_eq!(first, vec![0, 0, 0, 3, 0x00, 0x33, crc1[0], crc1[1]]);
        // The second entry, written while Loading: reload with both.
        let event = |dev: &mut Device, e: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
            let mut payload = vec![0x04, PID_LOAD_STATE_CONTROL, 0x10, 0x01];
            payload.extend_from_slice(e);
            payload.resize(14, 0);
            dev.handle_cemi(&data(dev, 0x3D7, &payload))?;
            Ok(())
        };
        event(&mut dev, &[0x04])?;
        event(&mut dev, &[0x01])?;
        event(&mut dev, &[0x03, 0x0b, 0x00, 0x00, 0x00, 0x04])?;
        for (element, entry) in [
            (1u8, [0, 0, 0, 3, 0x00, 0x33, 0, 0]),
            (2, [0, 0, 0, 1, 0x01, 0x33, 0, 0]),
        ] {
            let mut write = vec![0x04, PID_MCB_TABLE, 0x10, element];
            write.extend_from_slice(&entry);
            dev.handle_cemi(&data(&dev, 0x3D7, &write))?;
        }
        dev.handle_cemi(&data(&dev, 0x280 | 4, &[0x60, 0x00, 1, 2, 3, 4]))?;
        event(&mut dev, &[0x02])?;
        let read = |dev: &mut Device, element: u8| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let r = dev.handle_cemi(&data(dev, 0x3D5, &[0x04, PID_MCB_TABLE, 0x10, element]))?;
            Ok(prop_response_value(&r))
        };
        assert_eq!(
            read(&mut dev, 1)?,
            vec![0, 0, 0, 3, 0x00, 0x33, crc1[0], crc1[1]]
        );
        let crc2 = crc16_aug_ccitt(&[4]).to_be_bytes();
        assert_eq!(
            read(&mut dev, 2)?,
            vec![0, 0, 0, 1, 0x01, 0x33, crc2[0], crc2[1]]
        );
        assert!(read(&mut dev, 3)?.is_empty(), "no third entry");
        Ok(())
    }

    #[test]
    fn test_sys7_serves_mcb_table_after_load() -> Result<(), Box<dyn std::error::Error>> {
        // A System 7 device serves PID_MCB_TABLE (27) per loadable object,
        // computed over the written segment memory (Jung A-A011 uses
        // LoadImageProp on System 7). Drive LSM 1 to hold real bytes, then read
        // PID 27 and expect an 8-octet integrity block whose CRC matches.
        let mut dev = sys7_device(LsmAccess::MemoryMapped);
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        // StartLoading + alloc LSM 1 at 0x4000 via the 11-octet memory record
        // (state machine in the high nibble of octet 0, segment ID in octet 2).
        let start_rec = [0x11u8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &start_rec))?;
        let alloc_rec = [
            0x13u8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        ];
        dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &alloc_rec))?;
        // Write 8 bytes into the segment.
        dev.handle_cemi(&mem_write_frame(&dev, 0x4000, &[1, 2, 3, 4, 5, 6, 7, 8]))?;
        // Read PID_MCB_TABLE (27) on object 1.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x10, 0x01]))?;
        let mcb = prop_response_value(&r);
        assert_eq!(mcb.len(), MCB_ENTRY_LEN, "MCB entry is 8 octets");
        // The size field is the 8 written bytes; the CRC matches an independent
        // computation over those bytes.
        assert_eq!(&mcb[0..4], &[0, 0, 0, 8]);
        let crc = crc16_aug_ccitt(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&mcb[6..8], &crc.to_be_bytes());
        Ok(())
    }

    #[test]
    fn test_sys7_multi_element_mcb_read_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        // A real Jung 3361-1MWW (mask 0705, `M-0004_A-A011-13`) refused a
        // multi-element MCB read: `A_PropertyValue_Read obj=3 pid=27 count=6
        // start=1` came back count 0 with no data (issue #89 campaign,
        // 1.1.36). Six 8-octet entries never fit a standard-frame APDU and a
        // real device does not partially answer. ETS reads them one at a
        // time, so the sim serves count=1 and refuses anything wider.
        let mut dev = sys7_device(LsmAccess::MemoryMapped);
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        let start_rec = [0x11u8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &start_rec))?;
        let alloc_rec = [
            0x13u8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        ];
        dev.handle_cemi(&mem_write_frame(&dev, 0x0104, &alloc_rec))?;
        dev.handle_cemi(&mem_write_frame(&dev, 0x4000, &[1, 2, 3, 4, 5, 6, 7, 8]))?;

        // count = 6, start = 1 — the shape the Jung refused.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x60, 0x01]))?;
        let resp = &r.responses[0];
        assert_eq!(
            &resp.tpdu[2..],
            &[0x01, 27, 0x00, 0x01],
            "a multi-element MCB read is refused with nr_of_elem = 0 and no data"
        );

        // count = 1 at the same index still serves the entry.
        let r = dev.handle_cemi(&data(&dev, 0x3D5, &[0x01, 27, 0x10, 0x01]))?;
        assert_eq!(prop_response_value(&r).len(), MCB_ENTRY_LEN);
        Ok(())
    }
}
