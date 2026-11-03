//! Resolving the gateway a new model talks to: given, routing, or found by
//! KNXnet/IP discovery across every local interface, with a best-effort
//! reachability check of a given one.

use std::net::{SocketAddrV4, ToSocketAddrs};
use std::time::Duration;

use bussard_model::IndividualAddress;
use bussard_transport::config::DEFAULT_PORT;
use bussard_transport::knxnet::{GatewayDescription, GatewayInfo};
use bussard_transport::{BusConnection, ConnectionConfig, Transport};

use super::{Context as _, Output, SetupError, SetupHooks};

/// Per-interface discovery timeout.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for the unicast DESCRIPTION_REQUEST sent to the resolved gateway.
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How a gateway (if any) was resolved, which decides the emitted transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Tunneling to a specific gateway endpoint.
    Tunnel(SocketAddrV4),
    /// Routing (multicast); no gateway needed.
    Routing,
    /// No gateway could be resolved; write a skeleton with a placeholder so the
    /// user can fill in the address later.
    Placeholder,
}

/// Decides which transport to emit, running discovery only when needed.
/// `None` when a hook stopped (no gateway, or several and none chosen).
///
/// # Errors
///
/// `gateway` does not resolve to an IPv4 address, discovery failed, or the
/// choice among several gateways failed.
pub fn resolve<H: SetupHooks>(
    gateway: Option<&str>,
    routing: bool,
    hooks: &mut H,
    out: &mut dyn Output,
) -> Result<Option<Resolution>, SetupError> {
    // Routing wins: no gateway needed.
    if routing {
        out.say("Configuring KNXnet/IP routing (multicast 224.0.23.12:3671).");
        return Ok(Some(Resolution::Routing));
    }

    // A gateway given: use it, skip discovery, but do a best-effort probe.
    if let Some(spec) = gateway {
        let endpoint = parse_gateway(spec)?;
        hooks.probe(endpoint, out);
        return Ok(Some(Resolution::Tunnel(endpoint)));
    }

    // Neither: discover across all local interfaces.
    out.say("Searching for KNXnet/IP gateways on the local network...");
    let mut found = hooks.discover()?;
    // Deterministic ordering for a stable prompt / output.
    found.sort_by_key(|g| g.endpoint);
    found.dedup_by_key(|g| g.endpoint);

    match found.len() {
        0 => Ok(hooks.no_gateway(out).then_some(Resolution::Placeholder)),
        1 => {
            let gw = &found[0];
            out.say(&format!("Found gateway: {}", describe_gateway(gw)));
            Ok(Some(Resolution::Tunnel(gw.endpoint)))
        }
        _ => Ok(hooks
            .choose_gateway(&found, out)?
            .and_then(|i| found.get(i))
            .map(|gw| Resolution::Tunnel(gw.endpoint))),
    }
}

/// Renders a gateway for human output: `name (ip:port, IA a.l.d, N tunnels, M in use)`.
///
/// The tunnel clause appears only when the gateway advertised its tunnelling
/// slots (issue #105); older interfaces send no such DIB and are rendered
/// exactly as before.
pub fn describe_gateway(gw: &GatewayInfo) -> String {
    let name = gw.name.as_deref().unwrap_or("KNXnet/IP gateway");
    let mut parts = vec![gw.endpoint.to_string()];
    if let Some(raw) = gw.individual_address {
        parts.push(format!("IA {}", IndividualAddress::from_raw(raw)));
    }
    if let Some(tunnels) = tunnel_clause(&gw.description) {
        parts.push(tunnels);
    }
    if gw.description.tunnelling_secure_only() {
        parts.push("KNXnet/IP Secure only".to_string());
    } else if gw.description.secure_capable() {
        parts.push("KNXnet/IP Secure capable".to_string());
    }
    format!("{name} ({})", parts.join(", "))
}

/// Renders the tunnel budget as `N tunnels, M in use`, or `None` when the
/// interface did not report its slots.
pub fn tunnel_clause(description: &GatewayDescription) -> Option<String> {
    let capacity = description.tunnel_capacity()?;
    if description.tunnel_slots.is_some() {
        Some(format!(
            "{} tunnel{}, {} in use",
            capacity.total,
            if capacity.total == 1 { "" } else { "s" },
            capacity.in_use
        ))
    } else {
        // Only the additional-individual-addresses DIB was present: the count is
        // the slot budget, but occupancy is unknown — do not claim "0 in use".
        Some(format!(
            "{} tunnel{} (usage not reported)",
            capacity.total,
            if capacity.total == 1 { "" } else { "s" }
        ))
    }
}

/// Parses `host[:port]` into a socket address, defaulting the port to 3671.
///
/// # Errors
///
/// The name does not resolve, or not to an IPv4 address.
pub fn parse_gateway(spec: &str) -> Result<SocketAddrV4, SetupError> {
    let with_port = if spec.contains(':') {
        spec.to_string()
    } else {
        format!("{spec}:{DEFAULT_PORT}")
    };
    let addr = with_port
        .to_socket_addrs()
        .ctx(|| format!("resolving gateway address {spec:?}"))?
        .find_map(|a| match a {
            std::net::SocketAddr::V4(v4) => Some(v4),
            std::net::SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| SetupError::Message(format!("no IPv4 address for gateway {spec:?}")))?;
    Ok(addr)
}

/// The message for a gateway whose tunnel slots are all taken.
pub fn no_free_tunnel_message(gateway: impl std::fmt::Display) -> String {
    format!(
        "error: {gateway} has no free tunnelling connection (E_NO_MORE_CONNECTIONS).\n\
         A KNXnet/IP interface has a fixed number of tunnel slots, often one to five, and each \
         client holds one for as long as it is connected. The usual occupants are Home \
         Assistant's KNX integration, an open ETS project, and another bussard command or \
         `bussard viz` / `bussard mcp` still running.\n\
         Close one of them (or wait for its connection to time out) and retry; \
         `bussard init --gateway {gateway}` prints the slot count when the interface reports it."
    )
}

/// Runs `future` to completion from synchronous code: on the current tokio
/// runtime when called from one of its blocking threads (the MCP tool), else
/// on a short-lived runtime (the CLI).
fn block_on<F: std::future::Future>(future: F) -> std::io::Result<F::Output> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => Ok(handle.block_on(future)),
        Err(_) => Ok(tokio::runtime::Runtime::new()?.block_on(future)),
    }
}

/// Best-effort reachability probe: open a tunnel and immediately close it.
///
/// A failure only warns — the user may legitimately be offline while setting up
/// the repo. Runs with an overall timeout so a black-holing address cannot
/// hang the setup.
pub fn probe_reachability(endpoint: SocketAddrV4, out: &mut dyn Output) {
    // Ask the interface to describe itself first: it is a single unicast
    // exchange, costs no tunnel slot, and carries the tunnelling budget the
    // owner needs to see (issue #105).
    // The extended search (issue #182) also says whether the interface
    // requires KNXnet/IP Secure; it falls back to the plain description.
    let description = match block_on(bussard_transport::describe_gateway_extended(
        endpoint,
        DESCRIBE_TIMEOUT,
    )) {
        Ok(result) => result.ok(),
        Err(err) => {
            tracing::debug!("could not start runtime for reachability probe: {err}");
            return;
        }
    };
    if let Some(description) = &description {
        describe_to(endpoint, description, out);
        if description.tunnelling_secure_only() {
            out.say(&format!(
                "Reachability check skipped: a plain tunnel is refused by this interface. \
                 Commands need its tunnelling credentials: {}.",
                crate::guidance::tunnel_credentials_hint()
            ));
            return;
        }
    }

    let config = ConnectionConfig::tunnel(endpoint);
    let result = block_on(async {
        let probe = async {
            let conn = Transport::connect(&config).await?;
            conn.close().await
        };
        tokio::time::timeout(Duration::from_secs(5), probe).await
    });
    match result {
        Err(err) => tracing::debug!("could not start runtime for reachability probe: {err}"),
        Ok(Ok(Ok(()))) => out.say(&format!(
            "Reachability check: gateway {endpoint} responded."
        )),
        Ok(Ok(Err(bussard_transport::TransportError::NoMoreConnections))) => {
            out.warn(&no_free_tunnel_message(endpoint));
            out.warn("Writing the config anyway; free a tunnel before the first command.");
        }
        Ok(Ok(Err(err))) => out.warn(&format!(
            "warning: could not reach gateway {endpoint} ({err}); \
             writing the config anyway (you may be offline)."
        )),
        Ok(Err(_)) => out.warn(&format!(
            "warning: gateway {endpoint} did not respond within 5s; \
             writing the config anyway (you may be offline)."
        )),
    }
}

/// Says what a DESCRIPTION_RESPONSE said about the interface.
fn describe_to(endpoint: SocketAddrV4, description: &GatewayDescription, out: &mut dyn Output) {
    let name = description.name.as_deref().unwrap_or("KNXnet/IP gateway");
    let ia = description
        .individual_address
        .map(|raw| format!(", IA {}", IndividualAddress::from_raw(raw)))
        .unwrap_or_default();
    out.say(&format!("Gateway: {name} ({endpoint}{ia})"));
    match tunnel_clause(description) {
        Some(clause) => out.say(&format!("Tunnelling: {clause}.")),
        None => out.say(
            "Tunnelling: the interface does not report its slot count \
             (older KNXnet/IP interfaces do not).",
        ),
    }
    if let Some(summary) = description.security_summary() {
        out.say(&format!("{summary}."));
    }
}

/// The real discovery source: every KNXnet/IP gateway answering a search on
/// any local interface.
///
/// # Errors
///
/// No runtime could be started, or discovery failed.
pub fn real_discover() -> Result<Vec<GatewayInfo>, SetupError> {
    block_on(bussard_transport::discover_all(DISCOVER_TIMEOUT))
        .ctx(|| "starting tokio runtime for discovery".to_string())?
        .ctx(|| "discovering gateways".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gateway_defaults_the_port() -> Result<(), SetupError> {
        assert_eq!(parse_gateway("127.0.0.1")?.port(), DEFAULT_PORT);
        assert_eq!(parse_gateway("127.0.0.1:3700")?.port(), 3700);
        Ok(())
    }
}
