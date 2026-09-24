//! Restart and master reset (`A_Restart`), including the factory reset that keeps
//! the individual address.

use crate::bus::event::Event;
use crate::wire::IndividualAddress;
use crate::wire::apdu::{Apci, Apdu};

use super::{
    Device, DeviceError, DeviceReaction, ERASE_CODE_FACTORY_RESET_KEEP_IA, LoadState,
    LoadStateMachine,
};

impl Device {
    /// Erase code 7: drop every loadable object back to `Unloaded` and erase its
    /// segment, so a following download starts from a blank device. The
    /// individual address, the interface-object table and the object bases are
    /// not touched. The device's group runtime goes silent with its tables.
    fn factory_reset_keep_address(&mut self) {
        let objects: Vec<u8> = self.loadables.keys().copied().collect();
        for object in objects {
            self.memory.erase_owner(object);
            if let Some(state) = self.loadables.get_mut(&object) {
                state.lsm = LoadStateMachine::new(LoadState::Unloaded);
            }
            self.emit(Event::LoadStateChanged {
                device: self.address,
                object,
                state: LoadState::Unloaded.to_byte(),
            });
        }
        self.refresh_group_comm();
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
        //     erase codes 0x02..=0x08 erase state; 0x01 (ConfirmedRestart) erases
        //     nothing. Range 0x01..=0x08 is valid; others are refused.
        let is_master_reset = matches!(apdu.apci, Apci::RestartResponse) // 0x381
            || apdu.apci_raw == 0x381;

        let mut responses = Vec::new();

        if is_master_reset {
            let erase_code = apdu.data.first().copied().unwrap_or(0x01);
            let channel = apdu.data.get(1).copied().unwrap_or(0);
            // Strict: reject reserved erase codes (0x00, 0x09..=0xFF).
            let error_code: u8 = if (0x01..=0x08).contains(&erase_code) {
                0x00 // success
            } else {
                0x02 // unsupported erase code
            };
            // NOTE on erase semantics: in the ETS→KNX-Virtual capture the tool
            // issues A_RestartMasterReset with erase code 0x04 (ResetApplication-
            // Program) *mid-flash*, right after allocating object 4's segment,
            // and the subsequent writes to that segment still succeed with no
            // re-allocation. So on this real device the master reset does NOT
            // discard the in-progress load; it reboots and confirms only. The
            // simulator models that observed behavior: object state is cleared by
            // the explicit Unload load-event, not by the restart. (A device that
            // truly erased here would fail the capture.)
            let _ = channel;
            // Erase code 0x07 (factory reset without individual address, the
            // ETS opening of an initial System B download, issue #117): erase
            // every loadable object's image and load state, keep the individual
            // address. The KNX-Virtual 0x04 behaviour above is left as observed.
            let process_time = if erase_code == ERASE_CODE_FACTORY_RESET_KEEP_IA {
                self.factory_reset_keep_address();
                self.restart_process_time_s
            } else {
                0
            };
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
