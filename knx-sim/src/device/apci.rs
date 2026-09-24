//! APCI dispatch: routes one decoded management APDU to its handler, enforces
//! the access level and Data Secure protection, and answers `A_Authorize` and
//! `A_DeviceDescriptor_Read`.

use crate::bus::event::Event;
use crate::wire::apdu::{Apci, Apdu};
use crate::wire::{CemiLData, IndividualAddress};

use super::{Device, DeviceError, DeviceReaction, FREE_ACCESS_KEY, SYS7_MAX_MEMORY_CHUNK};

impl Device {
    /// Handle a management APDU, applying the KNX Data Secure interception before
    /// ordinary dispatch (spec §5, §6, §12.2). On an activated device:
    ///  - A_SecureData (APCI 0x3F1) → unwrap (verify MAC + sequence), dispatch the
    ///    inner APDU, and re-wrap each response with the device's own sequence.
    ///  - a PLAIN access to a protected function → refused, exactly as a real
    ///    activated device behaves (spec §6.4). Bare transport verbs and the
    ///    broadcast individual-address services are not "protected functions", so
    ///    they still flow (they carry no management payload to protect).
    ///
    /// This is the single interception point; the inner (unwrapped) APDU is
    /// dispatched via [`Device::dispatch_apdu`], which does NOT re-apply the
    /// secure check, so the inner management verb runs exactly as on a plain
    /// device once authenticated.
    pub(super) fn handle_apdu(
        &mut self,
        cemi: &CemiLData,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if apdu.apci_raw == crate::secure::A_SECURE_DATA_APCI && self.secure.is_none() {
            // A_SecureData to a device that was never security-activated: it has
            // no tool key, so it cannot authenticate the frame and drops it
            // (spec §6.4, the converse direction — see `SecureError::NotActivated`).
            self.emit(Event::SecureFrame {
                device: self.address,
                summary:
                    "A_SecureData to a device that is NOT security-activated: dropped (no tool key)"
                        .to_string(),
            });
            return Err(DeviceError::Secure(
                crate::secure::SecureError::NotActivated,
            ));
        }
        if self.secure.is_some() {
            if apdu.apci_raw == crate::secure::A_SECURE_DATA_APCI {
                if !self.connected {
                    return Err(DeviceError::NotConnected);
                }
                return self.handle_secure_data(cemi, apdu);
            }
            if let Some(reaction) = self.plain_allowed_on_activated(cemi, apdu)? {
                return Ok(reaction);
            }
            if Self::is_protected_function(apdu.apci) {
                self.emit(Event::SecureFrame {
                    device: self.address,
                    summary: format!(
                        "PLAIN access to protected {:?} refused (device requires KNX Data Secure)",
                        apdu.apci
                    ),
                });
                return Err(DeviceError::Secure(
                    crate::secure::SecureError::PlainAccessRefused,
                ));
            }
        }
        self.dispatch_apdu(cemi, apdu)
    }

    /// Dispatch a management APDU to its handler (no secure interception). Called
    /// directly for a plain device and for the unwrapped inner APDU of an
    /// A_SecureData frame. Returns response telegrams.
    pub(super) fn dispatch_apdu(
        &mut self,
        cemi: &CemiLData,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        if !self.connected {
            return Err(DeviceError::NotConnected);
        }
        let tool = cemi.source;

        // System 7 wire strictness (spec section 6): a memory op to a System 7
        // device must ride a STANDARD frame and carry at most 12 data octets. An
        // extended cEMI frame or a >12-octet memory op is exactly the trap that
        // catches a tool wrongly sending 63-byte chunks; a real device refuses it.
        if self.profile.is_system7()
            && matches!(apdu.apci, Apci::MemoryRead(_) | Apci::MemoryWrite(_))
        {
            let count = apdu.memory_count() as usize;
            if !cemi.is_standard_frame() {
                return Err(DeviceError::WireStrictness {
                    detail: "System 7 memory op on an extended frame".into(),
                });
            }
            if count > SYS7_MAX_MEMORY_CHUNK {
                return Err(DeviceError::WireStrictness {
                    detail: format!(
                        "System 7 memory op count {count} exceeds the {SYS7_MAX_MEMORY_CHUNK}-octet \
                         standard-frame ceiling"
                    ),
                });
            }
        }
        match apdu.apci {
            Apci::AuthorizeRequest => self.on_authorize(tool, apdu),
            Apci::PropertyValueRead => self.on_property_read(tool, apdu),
            Apci::PropertyValueWrite => self.on_property_write(tool, apdu),
            Apci::MemoryRead(_) => self.on_memory_read(tool, apdu),
            Apci::MemoryWrite(_) => self.on_memory_write(tool, apdu),
            Apci::MemoryExtendedWrite => self.on_memory_extended_write(tool, apdu),
            Apci::MemoryExtendedRead => self.on_memory_extended_read(tool, apdu),
            Apci::DeviceDescriptorRead(t) => self.on_device_descriptor_read(tool, t),
            Apci::Restart => self.on_restart(tool, apdu),
            // A_RestartMasterReset (0x381) decodes as RestartResponse in the raw
            // APCI table; route it to the restart handler too.
            Apci::RestartResponse => self.on_restart(tool, apdu),
            // A property-description read: answer with the property's descriptor
            // (type, element count, access levels) so a tool can introspect and
            // enumerate the device's property set (issue #72).
            Apci::PropertyDescriptionRead => self.on_property_description_read(tool, apdu),
            // The extended property services reach the security interface object
            // of an activated device (issue #156).
            Apci::PropertyExtValueRead
            | Apci::PropertyExtValueWriteCon
            | Apci::PropertyExtDescriptionRead
            | Apci::FunctionPropertyExtCommand
            | Apci::FunctionPropertyExtStateRead => self.on_extended_property(tool, apdu),
            _ => Ok(DeviceReaction::default()),
        }
    }

    /// Whether an APCI names a "protected function" that a security-activated
    /// device requires to ride A_SecureData (spec §6.4). The management verbs
    /// (authorize, property/memory read/write, restart, device-descriptor) are
    /// protected; group-value and the broadcast individual-address services are
    /// not (they are the plain-coexistence surface, spec §6.4).
    /// The few management services an activated device still answers PLAIN,
    /// as the real Jung F50 (secure-1-1-12 capture) does and ETS relies on for
    /// its readiness probe:
    ///
    /// - `A_DeviceDescriptor_Read` type 0, answered with mask `FFFF` (the real
    ///   device hides its mask until the tool talks secured);
    /// - `A_Authorize_Request`, answered as usual;
    /// - `A_PropertyValue_Read` of PID 56 (max APDU length) on the device
    ///   object, answered with its value.
    ///
    /// Returns `Ok(None)` for every other APDU, which then meets the ordinary
    /// "plain access refused" rule.
    fn plain_allowed_on_activated(
        &mut self,
        cemi: &CemiLData,
        apdu: &Apdu,
    ) -> Result<Option<DeviceReaction>, DeviceError> {
        const PID_MAX_APDU_LENGTH: u8 = 56;
        let tool = cemi.source;
        let reaction = match apdu.apci {
            Apci::DeviceDescriptorRead(0) => {
                let resp = self.respond(tool, 0x340, &[0xFF, 0xFF]);
                DeviceReaction {
                    responses: vec![resp],
                    did_master_reset: false,
                }
            }
            Apci::AuthorizeRequest => self.dispatch_apdu(cemi, apdu)?,
            Apci::PropertyValueRead
                if apdu.data.first() == Some(&0)
                    && apdu.data.get(1) == Some(&PID_MAX_APDU_LENGTH) =>
            {
                self.dispatch_apdu(cemi, apdu)?
            }
            _ => return Ok(None),
        };
        self.emit(Event::SecureFrame {
            device: self.address,
            summary: format!(
                "PLAIN {:?} answered (allowed unsecured on an activated device)",
                apdu.apci
            ),
        });
        Ok(Some(reaction))
    }

    fn is_protected_function(apci: Apci) -> bool {
        matches!(
            apci,
            Apci::AuthorizeRequest
                | Apci::PropertyValueRead
                | Apci::PropertyValueWrite
                | Apci::PropertyDescriptionRead
                | Apci::PropertyExtValueRead
                | Apci::PropertyExtValueWriteCon
                | Apci::PropertyExtDescriptionRead
                | Apci::FunctionPropertyExtCommand
                | Apci::FunctionPropertyExtStateRead
                | Apci::MemoryRead(_)
                | Apci::MemoryWrite(_)
                | Apci::MemoryExtendedRead
                | Apci::MemoryExtendedWrite
                | Apci::DeviceDescriptorRead(_)
                | Apci::Restart
                | Apci::RestartResponse
        )
    }

    fn on_authorize(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        // A_Authorize_Request: data = [reserved, key(4 BE)]. On a free-access
        // device any key unlocks to level 0 (the DA.tp capture uses FF FF FF FF).
        // On a keyed System 7 device the presented key must match the configured
        // BCU key (or be the free-access key) to grant level 0; otherwise the
        // device grants the "failed" level 15, and subsequent memory writes are
        // refused as unauthorized.
        if apdu.data.len() < 5 {
            return Err(DeviceError::Malformed {
                service: "A_Authorize".into(),
                detail: "expected 5 data bytes".into(),
            });
        }
        let key = u32::from_be_bytes([apdu.data[1], apdu.data[2], apdu.data[3], apdu.data[4]]);
        let granted = match self.profile.system7().and_then(|p| p.bcu_key) {
            // Keyed device: match the key (free-access key always accepted).
            Some(required) if key != required && key != FREE_ACCESS_KEY => 15,
            _ => 0,
        };
        self.access_level = granted;
        self.emit(Event::AuthChanged {
            device: self.address,
            level: granted,
        });
        // Response: A_Authorize_Response with the granted level byte.
        let resp = self.respond(tool, 0x3D2, &[self.access_level]);
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }

    fn on_device_descriptor_read(
        &mut self,
        tool: IndividualAddress,
        dtype: u8,
    ) -> Result<DeviceReaction, DeviceError> {
        // Descriptor type 0 → mask version. A real device reports its true mask;
        // the profile carries it (0x07B0 System B, 0x0705/0x0701 System 7).
        let mask: u16 = self.profile.mask();
        let resp = self.respond(tool, 0x340 | (dtype as u16 & 0x3F), &mask.to_be_bytes());
        Ok(DeviceReaction {
            responses: vec![resp],
            did_master_reset: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::device::test_support::*;

    #[test]
    fn test_authorize_unlocks() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut dev) = da_tp_device()? else {
            return Ok(());
        };
        connect(&mut dev)?;
        let auth = data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]);
        let r = dev.handle_cemi(&auth)?;
        assert_eq!(r.responses.len(), 1);
        assert_eq!(dev.access_level, 0);
        Ok(())
    }
}
