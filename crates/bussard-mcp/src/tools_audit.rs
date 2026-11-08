//! The `knx_audit` MCP tool (issue #93): runs the installation audit of
//! [`bussard_service::audit`], the same report `bussard audit` prints, and
//! returns it as JSON (issue #896).

use std::time::{Duration, SystemTime};

use crate::args::Parameters;
use bussard_model::Model;
use bussard_service::audit::{
    AuditReport, DEFAULT_WINDOW, GatewayReport, LiveReport, SampledTelegram, SecureLiveReport,
    SecureProbe, TrafficReport,
};
use bussard_service::monitor::{DestinationRef, Filter};
use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_router};
use serde::Deserialize;

use crate::server::BussardMcp;

/// Longest traffic-sample window the MCP tool accepts.
pub const MAX_MCP_WINDOW_SECS: u32 = 3600;

/// Arguments for `knx_audit`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct AuditArgs {
    /// Add the live part: the gateway description with its tunnel slots and a
    /// traffic sample from the telegrams the server observed over the last
    /// `window_seconds`. Read-only; refused when the server runs `--passive`.
    #[serde(default)]
    pub live: bool,
    /// The traffic-sample window in seconds for a live audit (default 30, max
    /// 3600). The sample is taken from the server's telegram buffer, so the call
    /// returns immediately.
    #[serde(default)]
    pub window_seconds: Option<u32>,
}

/// The `knx_audit` tool, on its own router so it can live in this module.
///
/// `BussardMcp::new` merges `audit_router()` into the main router.
// The `tool_router` macro generates the public `audit_router()` constructor and
// offers no way to attach a doc comment to it, so `missing_docs` is allowed on
// this impl only.
#[allow(missing_docs)]
#[tool_router(router = audit_router, vis = "pub")]
impl BussardMcp {
    // `knx_audit`.
    #[doc = include_str!("../guidance/tools/knx_audit.md")]
    #[tool]
    pub async fn knx_audit(
        &self,
        Parameters(args): Parameters<AuditArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state();
        let model = state.model.current();
        // The server's `--keyring` (password from BUSSARD_KEYRING_PASSWORD in
        // the server's environment) checks Secure-device coverage and, live,
        // probes them secured (issue #203). A keyring that does not load leaves
        // coverage unchecked rather than failing the audit.
        let keys =
            match bussard_service::secure::ToolKeys::load(bussard_service::secure::ToolKeySource {
                keyring: state.keyring.as_deref(),
                tool_key: None,
            }) {
                Ok(keys) => keys,
                Err(err) => {
                    tracing::warn!(
                        "knx_audit: the keyring did not load ({err}); coverage unchecked"
                    );
                    bussard_service::secure::ToolKeys::default()
                }
            };
        let keyring_devices = keys.keyring_given().then(|| keys.listed());
        let mut report = AuditReport::from_model(&model, keyring_devices.as_deref());
        if !args.live {
            return structured(&report, &model);
        }
        if state.passive {
            return Err(ErrorData::invalid_params(
                "a live audit is refused in --passive mode (it queries the gateway); \
                 call knx_audit with live: false"
                    .to_string(),
                None,
            ));
        }

        let window = Duration::from_secs(u64::from(
            args.window_seconds
                .unwrap_or(DEFAULT_WINDOW.as_secs() as u32)
                .clamp(1, MAX_MCP_WINDOW_SECS),
        ));

        // Gateway description: one UDP exchange with the interface, paced by the
        // shared read limiter like every other bus-touching tool.
        let endpoint = state.bus.gateway();
        let gateway = match endpoint {
            Some(endpoint) => {
                let _permit = state.read_limiter.acquire().await;
                GatewayReport::describe(endpoint).await
            }
            None => GatewayReport::unavailable(
                None,
                "no tunnelling gateway configured (routing transport)".to_string(),
            ),
        };

        // Traffic sample from the ring: group telegrams within the window.
        let since = SystemTime::now()
            .checked_sub(window)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let telegrams: Vec<SampledTelegram> = state
            .ring
            .recent(&Filter::default(), None)
            .into_iter()
            .filter(|t| t.timestamp >= since)
            .filter_map(|t| match t.destination {
                DestinationRef::Group(ga) => Some(SampledTelegram {
                    at: t.timestamp,
                    source: t.source,
                    ga,
                    payload: t.payload,
                    repeat_flag: false,
                }),
                DestinationRef::Individual(_) => None,
            })
            .collect();

        let secure = self.probe_secure_devices(&model, &keys).await;

        report.live = Some(LiveReport {
            bus: state.bus.to_json(),
            gateway,
            scan: None,
            secure,
            traffic: TrafficReport::new(&model, window, &telegrams),
        });
        structured(&report, &model)
    }
}

/// The report as the tool's structured result.
fn structured(
    report: &AuditReport,
    model: &bussard_model::Model,
) -> Result<CallToolResult, ErrorData> {
    crate::reply::ok_report(report, model)
}

impl BussardMcp {
    /// Probes the model's KNX Data Secure devices for `live.secure`
    /// (issue #203): the plain descriptor read, then a secured one when the
    /// keyring holds the device's tool key and the plain read was hidden or
    /// unanswered. `None` when the bus is not connected.
    async fn probe_secure_devices(
        &self,
        model: &Model,
        keys: &bussard_service::secure::ToolKeys,
    ) -> Option<SecureLiveReport> {
        let state = self.state();
        let service = state.live_service(crate::state::Need::Manage).ok()?;
        let options = bussard_service::audit::secure_probe_options(service);
        let mut probes = Vec::new();
        for (addr, loaded) in &model.devices {
            if !bussard_service::audit::is_secure_candidate(model, keys, *addr) {
                continue;
            }
            // One permit per device: two short sessions at most.
            let _permit = state.read_limiter.acquire().await;
            let plain_mask = bussard_service::identity::identify_plain(service, *addr, &options)
                .await
                .map(|id| id.mask);
            probes.push(
                SecureProbe::run(
                    service,
                    *addr,
                    loaded.device.name.clone(),
                    keys,
                    plain_mask,
                    &options,
                )
                .await,
            );
        }
        Some(SecureLiveReport::new(&probes))
    }
}
