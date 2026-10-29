//! Restart and master reset (`A_Restart`), including the factory reset that keeps
//! the individual address.

use crate::bus::event::Event;
use crate::wire::IndividualAddress;
use crate::wire::apdu::{Apci, Apdu};

use super::interface_object::iot;
use super::{
    Device, DeviceError, DeviceReaction, ERASE_CODE_FACTORY_RESET_KEEP_IA, LoadState,
    LoadStateMachine, PID_OBJECT_TYPE, Sys7LoadStateMachine,
};

impl Device {
    /// Unloads the loadable objects `select` picks (by interface-object type)
    /// and erases their segments: the Unload of Configuration Procedures
    /// §3.5.1.2 (memory freed, `PID_TABLE_REFERENCE` zero), on both device
    /// generations. The individual address and the interface-object table are
    /// not touched. The group runtime is re-evaluated, so a device whose tables
    /// were reset goes silent.
    fn unload_objects(&mut self, select: impl Fn(u16) -> bool) {
        let objects: Vec<u8> = self
            .loadables
            .keys()
            .copied()
            .filter(|&object| select(self.object_type(object)))
            .collect();
        for object in objects {
            self.memory.erase_owner(object);
            if let Some(state) = self.loadables.get_mut(&object) {
                state.lsm = LoadStateMachine::new(LoadState::Unloaded);
            }
            if let Some(s7) = self.sys7.as_mut()
                && let Some(lsm) = s7.lsms.get_mut(&object)
            {
                *lsm = Sys7LoadStateMachine::new(LoadState::Unloaded);
            }
            if self.sys7.is_none() {
                self.set_table_reference(object, 0);
            }
            self.emit(Event::LoadStateChanged {
                device: self.address,
                object,
                state: LoadState::Unloaded.to_byte(),
            });
        }
        self.refresh_group_comm();
    }

    /// The interface-object type of loadable object `object`: its
    /// `PID_OBJECT_TYPE` on System B, the LSM index itself on System 7 (whose
    /// LSMs 1 to 4 are the address table, association table, application and
    /// PEI program, KNX 3/5/2 §3.31.2).
    fn object_type(&self, object: u8) -> u16 {
        if self.sys7.is_some() {
            return u16::from(object);
        }
        self.objects
            .get(&object)
            .and_then(|o| o.property(PID_OBJECT_TYPE))
            .and_then(|p| p.value.get(..2))
            .map_or(u16::from(object), |v| u16::from_be_bytes([v[0], v[1]]))
    }

    /// Resets the individual address to the TP1 default `15.15.255` (erase
    /// codes 2 and 3).
    fn reset_individual_address(&mut self) {
        let default = IndividualAddress::new(15, 15, 255);
        if self.address != default {
            self.emit(Event::AddressChanged {
                device: self.address,
                new_address: default,
            });
            self.address = default;
        }
    }

    /// Executes the reset an accepted master reset names (KNX 3/5/2
    /// §3.7.1.2.3, Table 4). The sim models no persistently stored
    /// application data (code 8 resets nothing) and keeps the parameters in
    /// the application program's segment, so a parameter reset (code 5)
    /// unloads the application program with them.
    fn execute_master_reset(&mut self, erase_code: u8) {
        match erase_code {
            // Factory reset: everything, the individual address included.
            0x02 => {
                self.unload_objects(|_| true);
                self.reset_individual_address();
            }
            0x03 => self.reset_individual_address(),
            0x04 | 0x05 => self.unload_objects(|t| t == iot::APPLICATION_PROGRAM),
            0x06 => self.unload_objects(|t| t == iot::ADDRESS_TABLE || t == iot::ASSOCIATION_TABLE),
            ERASE_CODE_FACTORY_RESET_KEEP_IA => self.unload_objects(|_| true),
            // 1 (confirmed restart) and 8 (no persistent data here).
            _ => {}
        }
    }

    /// Sets the process time (seconds) the device reports in its
    /// `A_Restart_Response` to a factory reset (erase code 7). Defaults to
    /// [`DEFAULT_RESTART_PROCESS_TIME_S`].
    pub fn set_restart_process_time(&mut self, seconds: u16) {
        self.restart_process_time_s = seconds;
    }

    pub(super) fn on_restart(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        // A_Restart classification (KNX App-Layer 03.03.07 §3.4.2.2; ref
        // knx-device-spec-references.md §5):
        //   * APCI 0x380 with NO payload  = Basic Restart: reboot, drop the L4
        //     connection, unconfirmed. It does NOT erase loaded tables. Both the
        //     pre-flash restart and the final post-flash restart ETS sends to the
        //     KNX-Virtual device are this bare form (verified in dumpfile.pcap:
        //     `4f 80` and `73 80`), so a basic restart must never wipe memory —
        //     otherwise the just-loaded image would be lost.
        //   * APCI 0x381 with `[erase_code][channel]` = Master Reset: confirmed
        //     with A_Restart_Response (0x3A1) carrying `[error_code][process_time]`.
        //     erase codes 0x02..=0x08 reset the resources of KNX 3/5/2 Table 4;
        //     0x01 (ConfirmedRestart) resets nothing. Range 0x01..=0x08 is
        //     valid; others are refused. The mid-procedure master reset ETS
        //     sends KNX Virtual is the bare form above (`4f 80`).
        let is_master_reset = matches!(apdu.apci, Apci::RestartResponse) // 0x381
            || apdu.apci_raw == 0x381;

        let mut responses = Vec::new();

        if is_master_reset {
            let erase_code = apdu.data.first().copied().unwrap_or(0x01);
            let channel = apdu.data.get(1).copied().unwrap_or(0);
            // KNX 3/5/2 §3.7.1.2.3, Tables 4 and 5: erase codes 0 and 9 to 255
            // are answered "unsupported erase code" (2) and nothing runs. The
            // sim models no application channels, so a channel number other
            // than 0 is "invalid channel number" (3) for every code: codes 1,
            // 3 and 4 fix it at 0, and for the others the server does not
            // support channels.
            let error_code: u8 = if !(0x01..=0x08).contains(&erase_code) {
                0x02
            } else if channel != 0 {
                0x03
            } else {
                0x00
            };
            let mut process_time = 0;
            if error_code == 0 {
                // A KNX IP interface: its KNXnet/IP Secure properties take
                // effect (bussard issue #398).
                self.apply_ip_secure();
                self.execute_master_reset(erase_code);
                // Erase code 7 opens an initial System B download (issue
                // #117); the device reports its configured process time.
                if erase_code == ERASE_CODE_FACTORY_RESET_KEEP_IA {
                    process_time = self.restart_process_time_s;
                }
            }
            // A_Restart_Response (0x3A1): [error_code][process_time:2].
            let [pt_hi, pt_lo] = process_time.to_be_bytes();
            responses.push(self.respond(tool, 0x3A1, &[error_code, pt_hi, pt_lo]));
        }

        // Every restart drops the transport connection (side effect of reboot).
        self.connected = false;
        self.emit(Event::Restarted {
            device: self.address,
            master_reset: is_master_reset,
        });
        Ok(DeviceReaction {
            responses,
            did_master_reset: is_master_reset,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::device::test_support::*;
    use crate::device::*;

    #[test]
    fn test_master_reset_erase_code_7_clears_application_and_keeps_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dev = system_b_device()?;
        dev.set_restart_process_time(8);
        // A previous image in the application object's segment (object 3).
        let base = dev.loadables.get(&3).ok_or("object 3")?.base;
        dev.memory.allocate(3, base, 6);
        dev.memory.write(3, base, &[0xAA; 6])?;

        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        // The ETS request from the issue #117 capture: A_Restart master reset,
        // erase code 7, channel 0.
        let reaction = dev.handle_cemi(&data(&dev, 0x381, &[0x07, 0x00]))?;
        assert!(reaction.did_master_reset);
        let resp = reaction
            .responses
            .iter()
            .find(|r| r.tpdu.len() == 5)
            .ok_or("an A_Restart_Response")?;
        // `.. a1 00 00 08`: APCI 0x3A1, error 0, process time 8 s.
        let apci10 = ((resp.tpdu[0] as u16 & 0x03) << 8) | resp.tpdu[1] as u16;
        assert_eq!(apci10, 0x3A1);
        assert_eq!(&resp.tpdu[2..], &[0x00, 0x00, 0x08]);

        // Application erased, every object Unloaded, address kept, rebooted.
        for object in 1u8..=3 {
            assert_eq!(dev.load_state(object), Some(LoadState::Unloaded));
        }
        assert_eq!(dev.memory().read(base, 6), vec![0x00; 6]);
        assert!(dev.memory().segment_of(3).is_none());
        assert_eq!(dev.address(), IndividualAddress::new(1, 1, 2));
        assert!(!dev.connected);
        Ok(())
    }

    #[test]
    fn test_master_reset_confirmed_restart_erases_nothing() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut dev = system_b_device()?;
        let base = dev.loadables.get(&3).ok_or("object 3")?.base;
        dev.memory.allocate(3, base, 2);
        dev.memory.write(3, base, &[0x12, 0x34])?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        let reaction = dev.handle_cemi(&data(&dev, 0x381, &[0x01, 0x00]))?;
        let resp = reaction
            .responses
            .iter()
            .find(|r| r.tpdu.len() == 5)
            .ok_or("an A_Restart_Response")?;
        assert_eq!(&resp.tpdu[2..], &[0x00, 0x00, 0x00]);
        assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
        assert_eq!(dev.memory().read(base, 2), vec![0x12, 0x34]);
        Ok(())
    }

    /// The `[error code][process time:2]` of the master reset `erase` on
    /// `channel`.
    fn master_reset(
        dev: &mut Device,
        erase: u8,
        channel: u8,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        connect(dev)?;
        let reaction = dev.handle_cemi(&data(dev, 0x381, &[erase, channel]))?;
        let resp = reaction
            .responses
            .iter()
            .find(|r| r.tpdu.len() == 5)
            .ok_or("an A_Restart_Response")?;
        Ok(resp.tpdu[2..].to_vec())
    }

    #[test]
    fn test_on_restart_channel_number_is_invalid() -> Result<(), Box<dyn std::error::Error>> {
        // KNX 3/5/2 Table 5: a channel number other than 0 where the code
        // fixes 0 (1, 3, 4), or on a server without channels, is error 3; the
        // reset does not run.
        for erase in [0x01u8, 0x03, 0x04, 0x07] {
            let mut dev = system_b_device()?;
            assert_eq!(master_reset(&mut dev, erase, 1)?, vec![0x03, 0x00, 0x00]);
            assert_eq!(dev.load_state(3), Some(LoadState::Loaded), "{erase}");
            assert_eq!(dev.address(), IndividualAddress::new(1, 1, 2), "{erase}");
        }
        Ok(())
    }

    #[test]
    fn test_on_restart_reserved_erase_code_is_unsupported() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut dev = system_b_device()?;
        assert_eq!(master_reset(&mut dev, 0x09, 0)?, vec![0x02, 0x00, 0x00]);
        Ok(())
    }

    #[test]
    fn test_on_restart_reset_ia_keeps_the_application() -> Result<(), Box<dyn std::error::Error>> {
        let mut dev = system_b_device()?;
        assert_eq!(master_reset(&mut dev, 0x03, 0)?[0], 0x00);
        assert_eq!(dev.address(), IndividualAddress::new(15, 15, 255));
        assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
        Ok(())
    }

    #[test]
    fn test_on_restart_factory_reset_resets_ia_and_application()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut dev = system_b_device()?;
        assert_eq!(master_reset(&mut dev, 0x02, 0)?[0], 0x00);
        assert_eq!(dev.address(), IndividualAddress::new(15, 15, 255));
        for object in 1u8..=3 {
            assert_eq!(dev.load_state(object), Some(LoadState::Unloaded));
        }
        Ok(())
    }

    /// A loaded System 7 device: its LSM 3 is the application program
    /// (KNX 3/5/2 §3.31.2).
    fn sys7_loaded() -> Result<Device, String> {
        Device::from_product_with_overrides(
            IndividualAddress::new(1, 1, 5),
            &crate::testfixtures::synthetic_mdt_sys7_product(),
            LoadState::Loaded,
            ProfileOverrides::default(),
            std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
        )
    }

    #[test]
    fn test_on_restart_reset_ap_unloads_only_the_application()
    -> Result<(), Box<dyn std::error::Error>> {
        for erase in [0x04u8, 0x05] {
            let mut dev = sys7_loaded()?;
            assert_eq!(master_reset(&mut dev, erase, 0)?[0], 0x00);
            assert_eq!(dev.load_state(3), Some(LoadState::Unloaded), "{erase}");
            assert_eq!(dev.load_state(1), Some(LoadState::Loaded), "{erase}");
            assert_eq!(dev.load_state(2), Some(LoadState::Loaded), "{erase}");
        }
        Ok(())
    }

    #[test]
    fn test_on_restart_reset_links_unloads_the_tables() -> Result<(), Box<dyn std::error::Error>> {
        let mut dev = system_b_device()?;
        assert_eq!(master_reset(&mut dev, 0x06, 0)?[0], 0x00);
        assert_eq!(dev.load_state(1), Some(LoadState::Unloaded));
        assert_eq!(dev.load_state(2), Some(LoadState::Unloaded));
        assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
        Ok(())
    }

    #[test]
    fn test_on_restart_erase_persistent_data_keeps_everything()
    -> Result<(), Box<dyn std::error::Error>> {
        // The sim stores no persistent application data: code 8 succeeds and
        // resets nothing.
        let mut dev = system_b_device()?;
        assert_eq!(master_reset(&mut dev, 0x08, 0)?[0], 0x00);
        for object in 1u8..=3 {
            assert_eq!(dev.load_state(object), Some(LoadState::Loaded));
        }
        Ok(())
    }
}
