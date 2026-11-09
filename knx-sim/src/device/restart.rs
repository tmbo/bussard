//! Restart and master reset (`A_Restart`), including the factory reset that keeps
//! the individual address.

use crate::bus::event::Event;
use crate::wire::IndividualAddress;
use crate::wire::apdu::{Apci, Apdu};

use super::interface_object::iot;
use super::{
    Device, DeviceError, DeviceReaction, ERASE_CODE_FACTORY_RESET_KEEP_IA, LoadState,
    LoadStateMachine, MasterResetSupport, PID_OBJECT_TYPE, Sys7LoadStateMachine,
};

impl Device {
    /// Unloads the loadable objects `select` picks (by interface-object type)
    /// and erases their segments: the Unload of Configuration Procedures
    /// §3.5.1.2 (memory freed, `PID_TABLE_REFERENCE` zero), on both device
    /// generations. The individual address and the interface-object table are
    /// not touched. The group runtime is re-evaluated, so a device whose tables
    /// were reset goes silent.
    fn unload_objects(&mut self, select: impl Fn(u16) -> bool) {
        let objects = self.loadables_of_type(select);
        self.unload(objects);
    }

    /// [`Self::unload_objects`] over the objects `select` picks that are not
    /// in a running load procedure (state `Loading`).
    fn unload_idle_objects(&mut self, select: impl Fn(u16) -> bool) {
        let objects: Vec<u8> = self
            .loadables_of_type(select)
            .into_iter()
            .filter(|&object| self.load_state(object) != Some(LoadState::Loading))
            .collect();
        self.unload(objects);
    }

    /// The loadable objects whose interface-object type `select` picks.
    fn loadables_of_type(&self, select: impl Fn(u16) -> bool) -> Vec<u8> {
        self.loadables
            .keys()
            .copied()
            .filter(|&object| select(self.object_type(object)))
            .collect()
    }

    /// Unloads `objects` and erases their segments (see
    /// [`Self::unload_objects`]).
    fn unload(&mut self, objects: Vec<u8>) {
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

    /// Writes the property values the device holds in factory state
    /// ([`crate::prod::ProductData::factory_properties`], the kind 5 entries
    /// of the catalogue's `LoadedImage`, bussard issue #1012) into its
    /// properties: on build, and after a master reset that resets the
    /// parameters (erase code 2, 5 or 7 on channel 0). The real device holds
    /// them there, and ETS leaves out a procedure write the value already
    /// holds (the sweep captures of `M-0009_A-E0D0-11-434F`).
    ///
    /// An entry's start counts elements of the property (every entry of the
    /// corpus is on a one-octet element, where elements and octets agree).
    /// Bits the entry's mask leaves undefined keep their value. An entry
    /// whose object or property the device lacks, or that runs past the
    /// property's value, is left out with a warning: no product of the
    /// corpus has one, and a resized property would change its description.
    pub(super) fn restore_factory_properties(&mut self) {
        for held in &self.factory_properties {
            let prop = self
                .objects
                .get_mut(&held.object)
                .and_then(|o| o.property_mut(held.pid));
            let slot = prop.and_then(|p| {
                let from = usize::try_from(held.start)
                    .ok()?
                    .checked_mul(p.element_size())?;
                let to = from.checked_add(held.data.len())?;
                p.value.get_mut(from..to)
            });
            let Some(slot) = slot else {
                tracing::warn!(
                    object = held.object,
                    pid = held.pid,
                    start = held.start,
                    len = held.data.len(),
                    "the LoadedImage holds a property value the device does not have room for; \
                     left out"
                );
                continue;
            };
            for (i, (octet, data)) in slot.iter_mut().zip(&held.data).enumerate() {
                let mask = held.mask.get(i).copied().unwrap_or(0xFF);
                *octet = (*octet & !mask) | (data & mask);
            }
        }
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
    ///
    /// The partial resets (codes 4, 5 and 6) leave an object that is in
    /// `Loading` alone: its state, its allocated segment and its
    /// `PID_TABLE_REFERENCE`. Table 4 has code 4 reset the application
    /// program memory "to the default application", that is a loaded
    /// resource back to its default. It does not name an abort of a load
    /// procedure the management client is running on that resource, and in
    /// the System B load procedure (KNX 3/5/3 §3.5.2) an object leaves
    /// `Loading` through the client's own load controls (`LoadCompleted`,
    /// `Unload`). ETS relies on that: its KNX Virtual
    /// DA.tp download sends `StartLoading` and a 256-octet `LdCtrlRelSegment`
    /// to the application object, then this master reset with erase code 4,
    /// reconnects and writes the parameters into the segment it allocated
    /// (the 2026-10-27 sweep capture of `M-00FA_A-2500-10-51CB`, bussard
    /// issue #600). Outside a load procedure the reset unloads as before.
    /// The factory resets (codes 2 and 7) still unload every object.
    ///
    /// The resets of every channel's parameters (codes 2, 5 and 7 on channel
    /// 0; the device answers any other channel before it gets here) restore
    /// the property values the catalogue lists as the factory state
    /// ([`Self::restore_factory_properties`], bussard issue #1012).
    fn execute_master_reset(&mut self, erase_code: u8) {
        if matches!(erase_code, 0x02 | 0x05 | ERASE_CODE_FACTORY_RESET_KEEP_IA) {
            self.restore_factory_properties();
        }
        match erase_code {
            // Factory reset: everything, the individual address included.
            0x02 => {
                self.unload_objects(|_| true);
                self.reset_individual_address();
            }
            0x03 => self.reset_individual_address(),
            0x04 | 0x05 => self.unload_idle_objects(|t| t == iot::APPLICATION_PROGRAM),
            0x06 => {
                self.unload_idle_objects(|t| t == iot::ADDRESS_TABLE || t == iot::ASSOCIATION_TABLE)
            }
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

    /// How the device answers a Master Reset (builder-style; the
    /// `master_reset` device option). [`MasterResetSupport::Supported`] by
    /// default; the other two model a device without the Master Reset, so a
    /// tool's handling of the refusal can be exercised (bussard issue #611:
    /// ETS fails the download on `Refuse`).
    pub fn with_master_reset(mut self, support: MasterResetSupport) -> Self {
        self.master_reset = support;
        self
    }

    pub(super) fn on_restart(
        &mut self,
        tool: IndividualAddress,
        apdu: &Apdu,
    ) -> Result<DeviceReaction, DeviceError> {
        // A_Restart classification (KNX App-Layer 03.03.07 §3.4.2.2; ref
        // knx-device-spec-references.md §5):
        //   * APCI 0x380 with NO payload  = Basic Restart: reboot, drop the L4
        //     connection, unconfirmed. It does NOT erase loaded tables. The
        //     restart after the address assignment and the final post-flash
        //     restart ETS sends to the KNX-Virtual device are this bare form
        //     (verified in dumpfile.pcap: `4f 80` and `73 80`), so a basic
        //     restart must never wipe memory — otherwise the just-loaded image
        //     would be lost.
        //   * APCI 0x381 with `[erase_code][channel]` = Master Reset: confirmed
        //     with A_Restart_Response (0x3A1) carrying `[error_code][process_time]`.
        //     erase codes 0x02..=0x08 reset the resources of KNX 3/5/2 Table 4;
        //     0x01 (ConfirmedRestart) resets nothing. Range 0x01..=0x08 is
        //     valid; others are refused. The mid-procedure master reset ETS
        //     sends KNX Virtual is this confirmed form too (dumpfile.pcap
        //     `43 81 04 00`, answered error 0, process time 0; bussard #611).
        //   * The `master_reset` option models a device without the Master
        //     Reset: `refuse` answers error code 2 and does nothing (no
        //     reboot), `basic` runs it as a Basic Restart without an answer.
        let addressed_master_reset = matches!(apdu.apci, Apci::RestartResponse) // 0x381
            || apdu.apci_raw == 0x381;
        if addressed_master_reset && self.master_reset == MasterResetSupport::Refuse {
            // KNX 3/5/2 §3.7.1.2.3, Table 5: "unsupported erase code", process
            // time 0; neither a Basic Restart nor a Master Reset runs.
            let response = self.respond(tool, 0x3A1, &[0x02, 0x00, 0x00]);
            return Ok(DeviceReaction {
                responses: vec![response],
                did_master_reset: false,
            });
        }
        let is_master_reset =
            addressed_master_reset && self.master_reset == MasterResetSupport::Supported;

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

    /// `PID_LOAD_STATE_CONTROL` write of `event` to object `object`.
    fn pid5(dev: &Device, object: u8, event: &[u8]) -> crate::wire::cemi::CemiLData {
        let mut payload = vec![object, PID_LOAD_STATE_CONTROL, 0x10, 0x01];
        payload.extend_from_slice(event);
        payload.resize(4 + 10, 0x00);
        data(dev, 0x3D7, &payload)
    }

    #[test]
    fn test_on_restart_reset_ap_keeps_the_segment_of_a_running_load()
    -> Result<(), Box<dyn std::error::Error>> {
        // ETS's KNX Virtual DA.tp download (bussard issue #600): StartLoading
        // and a 256-octet RelSegment on the application object, master reset
        // erase code 4, reconnect, parameter writes into the segment,
        // LoadCompleted. Object 3 is the application program here.
        let mut dev = system_b_device()?;
        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        dev.handle_cemi(&pid5(&dev, 3, &[0x01]))?;
        dev.handle_cemi(&pid5(&dev, 3, &[0x03, 0x0b, 0x00, 0x00, 0x01, 0x00]))?;
        let base = dev.memory().segment_of(3).ok_or("segment allocated")?.base;

        assert_eq!(master_reset(&mut dev, 0x04, 0)?[0], 0x00);
        assert!(!dev.connected);
        assert_eq!(dev.load_state(3), Some(LoadState::Loading));
        assert_eq!(dev.memory().segment_of(3).map(|s| s.base), Some(base));

        connect(&mut dev)?;
        dev.handle_cemi(&data(&dev, 0x3D1, &[0x00, 0xff, 0xff, 0xff, 0xff]))?;
        let addr = u16::try_from(base)?;
        dev.handle_cemi(&mem_write_frame(&dev, addr, &[0x05, 0x05, 0xff, 0xff]))?;
        dev.handle_cemi(&mem_write_frame(&dev, addr + 0xfc, &[0xaa; 4]))?;
        dev.handle_cemi(&pid5(&dev, 3, &[0x02]))?;
        assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
        assert_eq!(dev.memory().read(base, 4), vec![0x05, 0x05, 0xff, 0xff]);
        assert_eq!(dev.memory().read(base + 0xfc, 4), vec![0xaa; 4]);
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

    #[test]
    fn test_on_restart_master_reset_refuse_answers_error_2_and_keeps_the_device()
    -> Result<(), Box<dyn std::error::Error>> {
        // bussard #611: a device without the Master Reset (`master_reset:
        // refuse`) answers error code 2 to every erase code, keeps its
        // connection and resets nothing.
        let mut dev = system_b_device()?.with_master_reset(MasterResetSupport::Refuse);
        let base = dev.loadables.get(&3).ok_or("object 3")?.base;
        dev.memory.allocate(3, base, 2);
        dev.memory.write(3, base, &[0x12, 0x34])?;
        for erase in [0x01u8, 0x04, 0x07] {
            connect(&mut dev)?;
            let reaction = dev.handle_cemi(&data(&dev, 0x381, &[erase, 0x00]))?;
            assert!(!reaction.did_master_reset);
            let resp = reaction
                .responses
                .iter()
                .find(|r| r.tpdu.len() == 5)
                .ok_or("an A_Restart_Response")?;
            assert_eq!(&resp.tpdu[2..], &[0x02, 0x00, 0x00], "erase code {erase}");
            assert!(dev.connected, "no reboot after a refusal");
        }
        assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
        assert_eq!(dev.memory().read(base, 2), vec![0x12, 0x34]);
        // The Basic Restart a client sends instead still reboots the device.
        let reaction = dev.handle_cemi(&data(&dev, 0x380, &[]))?;
        assert!(!reaction.responses.iter().any(|r| r.tpdu.len() == 5));
        assert!(!dev.connected);
        Ok(())
    }

    #[test]
    fn test_on_restart_master_reset_basic_reboots_without_an_answer()
    -> Result<(), Box<dyn std::error::Error>> {
        // `master_reset: basic`: the request runs as a Basic Restart, no
        // A_Restart_Response, nothing erased.
        let mut dev = system_b_device()?.with_master_reset(MasterResetSupport::Basic);
        let base = dev.loadables.get(&3).ok_or("object 3")?.base;
        dev.memory.allocate(3, base, 2);
        dev.memory.write(3, base, &[0x12, 0x34])?;
        connect(&mut dev)?;
        let reaction = dev.handle_cemi(&data(&dev, 0x381, &[0x04, 0x00]))?;
        assert!(!reaction.did_master_reset);
        assert!(!reaction.responses.iter().any(|r| r.tpdu.len() == 5));
        assert!(!dev.connected);
        assert_eq!(dev.load_state(3), Some(LoadState::Loaded));
        assert_eq!(dev.memory().read(base, 2), vec![0x12, 0x34]);
        Ok(())
    }

    /// A product whose procedure writes object 6 PID 208 (four one-octet
    /// elements) and whose `LoadedImage` holds elements 2 and 3 of it, the
    /// second with its high nibble undefined (bussard issue #1012).
    fn factory_product(mut product: crate::prod::ProductData) -> crate::prod::ProductData {
        product.written_props.push((6, 208, 4, 4));
        product.factory_properties = vec![crate::prod::FactoryProperty {
            object: 6,
            pid: 208,
            start: 1,
            data: vec![0x11, 0x22],
            mask: vec![0xFF, 0x0F],
        }];
        product
    }

    fn pid_208(dev: &Device) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(dev
            .objects
            .get(&6)
            .and_then(|o| o.property(208))
            .ok_or("object 6 PID 208")?
            .value
            .clone())
    }

    fn set_pid_208(dev: &mut Device, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        dev.objects
            .get_mut(&6)
            .and_then(|o| o.property_mut(208))
            .ok_or("object 6 PID 208")?
            .value = value.to_vec();
        Ok(())
    }

    /// Issue #1012: a factory device holds the `LoadedImage` values, and a
    /// reset of the parameters (erase codes 2, 5, 7 on channel 0) brings
    /// them back over what a download wrote; erase code 4 and a reset on
    /// another channel do not.
    #[test]
    fn test_restore_factory_properties_after_build_and_parameter_reset()
    -> Result<(), Box<dyn std::error::Error>> {
        let products = [
            factory_product(crate::testfixtures::synthetic_system_b_product()),
            factory_product(crate::testfixtures::synthetic_mdt_sys7_product()),
        ];
        for product in &products {
            let build = || {
                Device::from_product_with_overrides(
                    IndividualAddress::new(1, 1, 5),
                    product,
                    LoadState::Loaded,
                    ProfileOverrides::default(),
                    std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
                )
            };
            let mask = &product.mask_version;
            let mut dev = build()?;
            assert_eq!(pid_208(&dev)?, vec![0x00, 0x11, 0x02, 0x00], "{mask}");
            for erase in [0x02u8, 0x05, 0x07] {
                let mut dev = build()?;
                set_pid_208(&mut dev, &[0xAA; 4])?;
                assert_eq!(master_reset(&mut dev, erase, 0)?[0], 0x00);
                assert_eq!(
                    pid_208(&dev)?,
                    vec![0xAA, 0x11, 0xA2, 0xAA],
                    "{mask} erase code {erase}"
                );
            }
            for (erase, channel) in [(0x04u8, 0u8), (0x01, 0), (0x05, 1)] {
                set_pid_208(&mut dev, &[0xAA; 4])?;
                master_reset(&mut dev, erase, channel)?;
                assert_eq!(pid_208(&dev)?, vec![0xAA; 4], "{mask} {erase} {channel}");
            }
        }
        Ok(())
    }

    /// A value the device has no room for (an object, a property or an
    /// extent it lacks) is left out; the rest is held.
    #[test]
    fn test_restore_factory_properties_skips_what_does_not_fit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut product = factory_product(crate::testfixtures::synthetic_system_b_product());
        for (object, pid, start) in [(9u8, 208u8, 0u32), (6, 209, 0), (6, 208, 3)] {
            product.factory_properties.insert(
                0,
                crate::prod::FactoryProperty {
                    object,
                    pid,
                    start,
                    data: vec![0x55, 0x55],
                    mask: Vec::new(),
                },
            );
        }
        let dev = Device::from_product(
            IndividualAddress::new(1, 1, 5),
            &product,
            LoadState::Unloaded,
            std::sync::Arc::new(crate::bus::event::RecordingSink::new()),
        );
        assert_eq!(pid_208(&dev)?, vec![0x00, 0x11, 0x02, 0x00]);
        assert!(!dev.objects.contains_key(&9));
        Ok(())
    }
}
