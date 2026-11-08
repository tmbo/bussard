//! The bus connection and the telegram tools in one shape each (issue
//! #904): `knx_bus_status`, `knx_bus_reconnect`, `knx_recent_telegrams`
//! and `knx_wait_for_telegram`.

use serde::Serialize;
use serde_json::Value;

use crate::report::{Report, is_false};

/// The bus connection: its state and, while down, why (issue #287).
#[derive(Debug, Clone, Serialize)]
pub struct BusView {
    /// `connected`, `connecting`, `disconnected` or `disabled`.
    pub state: String,
    /// `tunnel` or `routing`.
    pub transport: String,
    /// Whether the bus is connected.
    pub connected: bool,
    /// The interface.
    pub interface: Option<String>,
    /// The tunnelling user.
    pub tunnel_user: Option<u8>,
    /// The last transport error.
    pub last_error: Option<String>,
    /// When it happened, RFC 3339.
    pub last_error_at: Option<String>,
    /// Failed attempts since the last connect.
    pub attempts: u32,
    /// Seconds until the next attempt.
    pub retry_in_seconds: Option<u64>,
    /// When the bus connected, RFC 3339.
    pub connected_since: Option<String>,
    /// The fatal error the bus stopped on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
    /// Other `bussard mcp` processes for this project on this host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_instances: Option<Vec<u32>>,
    /// Why it is not connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Report for BusView {
    const SCHEMA: u32 = 1;
}

/// `knx_bus_reconnect`: whether a fresh connect worked.
#[derive(Debug, Clone, Serialize)]
pub struct ReconnectReport {
    /// Connected after the attempt.
    pub ok: bool,
    /// The bus.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bus: Option<BusView>,
    /// What else happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Why it is not connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Report for ReconnectReport {
    const SCHEMA: u32 = 1;
}

/// `knx_recent_telegrams`: telegrams, oldest first, as `monitor --json`
/// prints them.
#[derive(Debug, Clone, Serialize)]
pub struct TelegramsReport {
    /// How many.
    pub count: usize,
    /// The telegrams.
    pub telegrams: Vec<Value>,
}

impl Report for TelegramsReport {
    const SCHEMA: u32 = 1;
}

/// `knx_wait_for_telegram`: the telegram that matched, or that none did.
#[derive(Debug, Clone, Serialize)]
pub struct WaitReport {
    /// A telegram matched.
    pub matched: bool,
    /// It.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram: Option<Value>,
    /// The wait ran out.
    #[serde(skip_serializing_if = "is_false")]
    pub timed_out: bool,
    /// How long it waited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waited_seconds: Option<u64>,
}

impl Report for WaitReport {
    const SCHEMA: u32 = 1;
}

/// `bussard test --secure-idle --json`: whether a KNXnet/IP Secure session
/// survives an idle period.
#[derive(Debug, Clone, Serialize)]
pub struct SecureIdleView {
    /// The gateway probed.
    pub gateway: String,
    /// The tunnelling user.
    pub user_id: u8,
    /// The carrier.
    pub transport: String,
    /// The idle period, in seconds.
    pub idle_secs: u64,
    /// `alive`, `dropped` or `silent`.
    pub outcome: &'static str,
    /// When alive: how fast the probe was answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_ms: Option<u64>,
    /// When dropped: after how long.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_ms: Option<u64>,
    /// When dropped: why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SecureIdleView {
    /// The view of `report`.
    pub fn of(report: &crate::transport::SecureIdleReport) -> SecureIdleView {
        use crate::transport::SecureIdleOutcome;
        let (outcome, answered_ms, after_ms, reason) = match &report.outcome {
            SecureIdleOutcome::Alive { answered_in } => {
                ("alive", Some(answered_in.as_millis() as u64), None, None)
            }
            SecureIdleOutcome::Dropped { after, reason } => (
                "dropped",
                None,
                Some(after.as_millis() as u64),
                Some(reason.clone()),
            ),
            SecureIdleOutcome::Silent => ("silent", None, None, None),
        };
        SecureIdleView {
            gateway: report.gateway.to_string(),
            user_id: report.user_id,
            transport: report.transport.to_string(),
            idle_secs: report.idle.as_secs(),
            outcome,
            answered_ms,
            after_ms,
            reason,
        }
    }
}

impl Report for SecureIdleView {
    const SCHEMA: u32 = 1;
}

/// `knx_viz`: the read-only browser view of the installation.
#[derive(Debug, Clone, Serialize)]
pub struct VizReport {
    /// The page runs.
    pub ok: bool,
    /// Its address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Always `true`: the page never writes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Whether it shows live traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_traffic: Option<bool>,
    /// Why it did not start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Report for VizReport {
    const SCHEMA: u32 = 1;
}
