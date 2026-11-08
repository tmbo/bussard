//! The KNX Secure diagnostics and the KNXnet/IP Secure switch in one shape
//! each (issue #904): `bussard secure diag --json` and
//! `knx_clear_security_log`; `bussard interface secure --json` and
//! `knx_interface_secure`.

use bussard_download::SecurityDiagnostics;
use serde::Serialize;

use crate::ip_secure::Switch;
use crate::report::{Approval, Report, is_false};

/// A device's Data Secure diagnostics, and whether its log was cleared.
#[derive(Debug, Clone, Serialize)]
pub struct SecureDiagReport {
    /// It was read (and, when asked, cleared).
    pub ok: bool,
    /// The device.
    pub address: String,
    /// The resolved gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Whether the log was cleared and read back clear.
    pub cleared: bool,
    /// What the device holds now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<SecurityDiagnostics>,
    /// What it held before the clear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<SecurityDiagnostics>,
    /// The diagnostics in words.
    pub lines: Vec<String>,
    /// Why the clear failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The question and digest of a clear.
    #[serde(flatten)]
    pub approval: Approval,
}

impl SecureDiagReport {
    /// The diagnostics `diag` of `address`; `cleared` when this run cleared
    /// them.
    pub fn new(address: impl ToString, diag: SecurityDiagnostics, cleared: bool) -> Self {
        SecureDiagReport {
            ok: true,
            address: address.to_string(),
            gateway: None,
            cleared,
            lines: diag.lines(),
            diagnostics: Some(diag),
            before: None,
            reason: None,
            approval: Approval::default(),
        }
    }
}

impl Report for SecureDiagReport {
    const SCHEMA: u32 = 2;
}

/// A KNXnet/IP Secure switch: the plan, or what the switch did.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceSecureReport {
    /// It worked (a plan: always).
    pub ok: bool,
    /// The read-back matched (absent for a plan).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// The interface.
    pub address: String,
    /// `on` or `off`.
    pub switch: Switch,
    /// A dry run: nothing sent, nothing saved.
    #[serde(skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// The steps, one line each.
    pub steps: Vec<String>,
    /// The credentials the plan generates (names only).
    pub generated: Vec<String>,
    /// The security mode read back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_mode: Option<bool>,
    /// The tunnelling users read back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_users: Option<Vec<(u8, u8)>>,
    /// Whether the tunnel after the switch is secure-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_secure_only: Option<bool>,
    /// What the read-back found wrong.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<String>,
    /// Whether the key store was saved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_store_updated: Option<bool>,
    /// Why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What to do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
    /// The question and digest of a plan.
    #[serde(flatten)]
    pub approval: Approval,
}

impl InterfaceSecureReport {
    /// The plan of switching `switch` on `address`: `steps` and the
    /// `generated` credentials.
    pub fn plan(
        address: impl ToString,
        switch: Switch,
        steps: Vec<String>,
        generated: Vec<String>,
    ) -> Self {
        InterfaceSecureReport {
            ok: true,
            verified: None,
            address: address.to_string(),
            switch,
            dry_run: false,
            steps,
            generated,
            security_mode: None,
            tunnel_users: None,
            gateway_secure_only: None,
            mismatches: Vec::new(),
            key_store_updated: None,
            reason: None,
            recovery: None,
            approval: Approval::default(),
        }
    }
}

impl Report for InterfaceSecureReport {
    const SCHEMA: u32 = 2;
}
