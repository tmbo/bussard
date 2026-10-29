//! Which restart ETS sends a device, decided from its product data (issue
//! #452).
//!
//! ETS restarts a device in one of two forms, at the end of a download and for
//! its standalone "Restart device":
//!
//! - the **confirmed** restart: `A_Restart` master reset, erase code 1,
//!   channel 0, answered by `A_Restart_Response` with an error code and a
//!   process time;
//! - the **basic** restart: a bare `A_Restart`, which a device may or may not
//!   acknowledge and never answers.
//!
//! The device's answers do not decide it; the application's product data
//! does. Across the reference installation (22 devices, ETS download captures)
//! and the ETS defaults sweep (38 applications, `captures/ets-sweep/`), ETS
//! uses the confirmed form exactly for System B applications that declare
//! `IsSecureEnabled="true"`. Neither the mask, nor the answered device object
//! PID 56, nor a filled segment, nor `MinEtsVersion` separates them: 1.1.45
//! (`M-0112_A-0003-10-D375`) and 1.1.51 (`M-008E_A-7188-31-AF96`) are 07B0
//! applications with a filled segment and get the basic form, and so do twelve
//! 07B0 applications of the sweep with `MinEtsVersion="5.0"`.
//!
//! The same split holds for the factory reset (erase code 7) ETS opens an
//! "unload + download" of a secure-capable device with: an application that
//! is not secure-capable is unloaded with load controls and a basic restart,
//! never with a master reset. [`FlashPlan`](super::FlashPlan) therefore adds
//! its factory reset only where [`restart_form`] is
//! [`RestartForm::Confirmed`].
//!
//! # Master Reset support
//!
//! KNX 3/5/2 §3.7.1.2.3.1 has a client verify that the server supports a
//! Master Reset before it calls one, and call only a Basic Restart otherwise.
//! The clause names no resource that announces the support, so bussard checks
//! on the device itself, with the confirmed restart's own error code:
//!
//! - The factory reset (erase code 7) opens a download only where this module
//!   says ETS sends one. Error code 2 ("unsupported erase code") or no answer
//!   fails the flash before anything is written; `--no-factory-reset` is the
//!   way past it.
//! - A load procedure's `LdCtrlMasterReset` goes out in the confirmed form
//!   with the op's erase code and channel number (§3.7.1.2.3) on every device
//!   but KNX Virtual, whose ETS capture shows a bare `A_Restart`. Error code 2
//!   means the device does not support that Master Reset, so the flash sends a
//!   Basic Restart instead and goes on; any other error code fails it. No
//!   vendor application in the corpus carries the op (only KNX Virtual's
//!   DA.tp does), so no capture of the confirmed form exists yet.

use bussard_mgmt::MaskProfile;
use bussard_prod::ApplicationProgram;

/// The form of the restart ETS sends a device (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartForm {
    /// `A_Restart` master reset, erase code 1, channel 0. The device answers
    /// `A_Restart_Response`, and only an answer with error code 0 confirms the
    /// restart.
    Confirmed,
    /// A bare `A_Restart`. The device answers nothing, so the restart itself
    /// cannot be confirmed.
    Basic,
}

impl RestartForm {
    /// Whether this is the confirmed form.
    pub fn is_confirmed(self) -> bool {
        self == RestartForm::Confirmed
    }

    /// The short name the CLI and MCP reports use: `confirmed` or `basic`.
    pub fn name(self) -> &'static str {
        match self {
            RestartForm::Confirmed => "confirmed",
            RestartForm::Basic => "basic",
        }
    }
}

/// The restart form ETS uses for a device running `app`: confirmed for a
/// System B application that declares `IsSecureEnabled="true"`, basic for
/// every other one (see the module docs for the evidence).
pub fn restart_form(app: &ApplicationProgram) -> RestartForm {
    let system_b = app
        .mask_version
        .as_deref()
        .and_then(|m| u16::from_str_radix(m.trim(), 16).ok())
        .is_some_and(|mask| MaskProfile::from_mask(mask).is_system_b());
    if system_b && app.is_secure_enabled {
        RestartForm::Confirmed
    } else {
        RestartForm::Basic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(mask: &str, secure: bool) -> ApplicationProgram {
        ApplicationProgram {
            id: "M-0004_A-0000-10-0000".to_string(),
            mask_version: Some(mask.to_string()),
            is_secure_enabled: secure,
            ..ApplicationProgram::default()
        }
    }

    #[test]
    fn test_restart_form_secure_system_b_is_confirmed() {
        assert_eq!(restart_form(&app("07B0", true)), RestartForm::Confirmed);
        assert_eq!(restart_form(&app("57B0", true)), RestartForm::Confirmed);
    }

    #[test]
    fn test_restart_form_plain_system_b_is_basic() {
        // 1.1.45 and 1.1.51: 07B0, filled segment, not secure-capable.
        assert_eq!(restart_form(&app("07B0", false)), RestartForm::Basic);
    }

    #[test]
    fn test_restart_form_system_7_is_basic() {
        assert_eq!(restart_form(&app("0705", false)), RestartForm::Basic);
        assert_eq!(restart_form(&app("0701", true)), RestartForm::Basic);
    }

    #[test]
    fn test_restart_form_without_mask_is_basic() {
        let mut no_mask = app("07B0", true);
        no_mask.mask_version = None;
        assert_eq!(restart_form(&no_mask), RestartForm::Basic);
    }
}
