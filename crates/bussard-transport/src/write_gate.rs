//! The non-loopback write gate (issue #74), shared by every bus-writing surface.
//!
//! A command or tool that writes to the bus and whose resolved gateway is **not**
//! loopback refuses to run unless the operator has explicitly opted in, either
//! with an explicit flag (the CLI's `--allow-remote-gateway`) or by setting
//! [`ALLOW_REAL_GATEWAY_ENV`] to `1`. Loopback gateways (the local simulator, the
//! test suite) are always permitted. Routing counts as non-loopback: a multicast
//! write reaches the real bus.
//!
//! The policy lives here, next to [`ConnectionConfig`], so the CLI and the MCP
//! server apply one rule instead of two copies of it.

use crate::config::{ConnectionConfig, TransportKind};

/// The environment variable that opts a write into a non-loopback gateway.
///
/// This is the safety envelope that stops a scripted or fat-fingered command
/// from silently mutating the real house (issue #74).
pub const ALLOW_REAL_GATEWAY_ENV: &str = "BUSSARD_ALLOW_REAL_GATEWAY";

/// Why a write was allowed through the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteGate {
    /// The gateway is loopback; no opt-in is needed.
    Loopback,
    /// The gateway is real and the operator opted in (flag or environment).
    OptedIn,
}

/// A refused write: the gateway is not loopback and nobody opted in.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "refusing to write to non-loopback gateway {gateway}: this looks like a real KNX bus.\n\
     If you really mean to write to it, re-run with --allow-remote-gateway or set \
     {env}=1.\n\
     (Loopback gateways such as 127.0.0.1 — the local simulator — are always allowed.)",
    env = ALLOW_REAL_GATEWAY_ENV
)]
pub struct WriteGateRefused {
    /// The gateway as [`gateway_display`] renders it.
    pub gateway: String,
}

/// Renders the resolved gateway of a [`ConnectionConfig`] for a confirmation
/// line, e.g. `192.0.2.10:3671` for a tunnel or `multicast 224.0.23.12:3671`
/// for routing.
pub fn gateway_display(config: &ConnectionConfig) -> String {
    match (&config.transport, config.gateway) {
        (TransportKind::Tunnel, Some(gw)) => gw.to_string(),
        (TransportKind::Routing, _) => format!("multicast {}", config.multicast),
        // A tunnel with no gateway cannot be built by the config resolvers, but
        // render something honest rather than panicking.
        (TransportKind::Tunnel, None) => "<no gateway>".to_string(),
    }
}

/// Returns `true` if the resolved gateway is a loopback endpoint (127.0.0.0/8).
///
/// Routing (multicast) is treated as **non-loopback**: a multicast write reaches
/// the real bus, so it must go through the same opt-in gate.
pub fn is_loopback_gateway(config: &ConnectionConfig) -> bool {
    match config.transport {
        TransportKind::Tunnel => config
            .gateway
            .map(|gw| gw.ip().is_loopback())
            .unwrap_or(false),
        TransportKind::Routing => false,
    }
}

/// Whether [`ALLOW_REAL_GATEWAY_ENV`] is set to `1` in this process.
pub fn real_gateway_env_opt_in() -> bool {
    std::env::var(ALLOW_REAL_GATEWAY_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Applies the write gate: loopback passes, a real gateway passes only with
/// `allow_flag` or the environment opt-in, anything else is refused.
pub fn check_write_gate(
    config: &ConnectionConfig,
    allow_flag: bool,
) -> Result<WriteGate, WriteGateRefused> {
    if is_loopback_gateway(config) {
        return Ok(WriteGate::Loopback);
    }
    if allow_flag || real_gateway_env_opt_in() {
        return Ok(WriteGate::OptedIn);
    }
    Err(WriteGateRefused {
        gateway: gateway_display(config),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn tunnel(ip: Ipv4Addr) -> ConnectionConfig {
        ConnectionConfig::tunnel(SocketAddrV4::new(ip, 3671))
    }

    #[test]
    fn test_check_write_gate_loopback_passes() {
        assert_eq!(
            check_write_gate(&tunnel(Ipv4Addr::LOCALHOST), false),
            Ok(WriteGate::Loopback)
        );
    }

    #[test]
    fn test_check_write_gate_real_gateway_needs_opt_in() {
        // SAFETY: nextest runs each test in its own process, so this env
        // mutation cannot race another test.
        unsafe {
            std::env::remove_var(ALLOW_REAL_GATEWAY_ENV);
        }
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        let err = check_write_gate(&real, false).err();
        assert!(
            err.is_some_and(|e| e.to_string().contains("192.0.2.10:3671")),
            "a real gateway without opt-in must be refused, naming the host"
        );
        assert_eq!(check_write_gate(&real, true), Ok(WriteGate::OptedIn));
    }
}
