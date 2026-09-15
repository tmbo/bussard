//! Shared connection setup for the `monitor` and `capture` commands.
//!
//! Resolves a [`ConnectionConfig`] from an optional model directory's
//! `bussard.yaml` plus command-line overrides, and loads the model (warning and
//! continuing when the directory is absent).

use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::path::Path;

use anyhow::{Context, anyhow};
use bussard_model::Model;
use bussard_model::schema::Transport as ModelTransport;
use bussard_transport::config::{DEFAULT_MULTICAST, DEFAULT_PORT};
use bussard_transport::{ConnectionConfig, TransportKind};

/// Command-line connection overrides shared by `monitor` and `capture`.
#[derive(Debug, Clone, Default)]
pub struct ConnOverrides {
    /// `--gateway host[:port]` for tunneling.
    pub gateway: Option<String>,
    /// `--routing` to force multicast routing.
    pub routing: bool,
}

/// Loads the model from `dir` if it exists, warning and returning `None`
/// otherwise (the monitor still runs with numeric addresses).
pub fn load_model_optional(dir: &Path) -> Option<Model> {
    if !dir.exists() {
        tracing::warn!(
            "model directory {} not found; monitoring without decode (numeric addresses only)",
            dir.display()
        );
        return None;
    }
    match Model::load(dir) {
        Ok(model) => Some(model),
        Err(err) => {
            tracing::warn!(
                "failed to load model from {}: {err}; continuing without decode",
                dir.display()
            );
            None
        }
    }
}

/// Resolves a [`ConnectionConfig`] from the model config plus overrides.
///
/// Precedence: `--routing` and `--gateway` override `bussard.yaml`, which
/// overrides the built-in defaults. A tunnel with no gateway anywhere is an
/// error (there is nothing to connect to).
pub fn resolve_config(
    model: Option<&Model>,
    overrides: &ConnOverrides,
) -> anyhow::Result<ConnectionConfig> {
    let yaml = model.map(|m| &m.config.connection);

    // Decide the transport: explicit --routing wins, else --gateway implies
    // tunnel, else the YAML setting, else default to tunnel.
    let use_routing = if overrides.routing {
        true
    } else if overrides.gateway.is_some() {
        false
    } else {
        matches!(yaml.map(|c| c.transport), Some(ModelTransport::Routing))
    };

    if use_routing {
        let multicast = match yaml.and_then(|c| c.multicast.as_deref()) {
            Some(m) => parse_socket(m).context("parsing multicast address from bussard.yaml")?,
            None => SocketAddrV4::new(DEFAULT_MULTICAST, DEFAULT_PORT),
        };
        return Ok(ConnectionConfig {
            transport: TransportKind::Routing,
            gateway: None,
            multicast,
            local_interface: Ipv4Addr::UNSPECIFIED,
        });
    }

    // Tunnel: gateway from the override, else from YAML.
    let gateway_str = overrides
        .gateway
        .clone()
        .or_else(|| yaml.and_then(|c| c.gateway.clone()))
        .ok_or_else(|| {
            anyhow!("no gateway configured; set connection.gateway in bussard.yaml or pass --gateway host[:port] (or use --routing)")
        })?;
    let gateway = parse_socket(&gateway_str).context("parsing gateway address")?;

    Ok(ConnectionConfig {
        transport: TransportKind::Tunnel,
        gateway: Some(gateway),
        multicast: SocketAddrV4::new(DEFAULT_MULTICAST, DEFAULT_PORT),
        local_interface: Ipv4Addr::UNSPECIFIED,
    })
}

/// Parses `host[:port]`, defaulting the port to the KNXnet/IP default, and
/// resolving a hostname to an IPv4 address.
fn parse_socket(s: &str) -> anyhow::Result<SocketAddrV4> {
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{DEFAULT_PORT}")
    };

    // Resolve (handles both literal IPs and hostnames), taking the first IPv4.
    let addr = with_port
        .to_socket_addrs()
        .with_context(|| format!("resolving {with_port:?}"))?
        .find_map(|a| match a {
            std::net::SocketAddr::V4(v4) => Some(v4),
            std::net::SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| anyhow!("no IPv4 address found for {with_port:?}"))?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socket_adds_default_port() {
        let a = parse_socket("127.0.0.1").unwrap();
        assert_eq!(a.port(), DEFAULT_PORT);
        assert_eq!(a.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_socket_explicit_port() {
        let a = parse_socket("10.0.0.5:1234").unwrap();
        assert_eq!(a.port(), 1234);
    }

    #[test]
    fn routing_override_forces_multicast() {
        let cfg = resolve_config(
            None,
            &ConnOverrides {
                routing: true,
                gateway: None,
            },
        )
        .unwrap();
        assert_eq!(cfg.transport, TransportKind::Routing);
        assert_eq!(cfg.multicast.ip(), &DEFAULT_MULTICAST);
    }

    #[test]
    fn gateway_override_forces_tunnel() {
        let cfg = resolve_config(
            None,
            &ConnOverrides {
                gateway: Some("192.168.1.10".to_string()),
                routing: false,
            },
        )
        .unwrap();
        assert_eq!(cfg.transport, TransportKind::Tunnel);
        assert_eq!(cfg.gateway.unwrap().port(), DEFAULT_PORT);
    }

    #[test]
    fn tunnel_without_gateway_errors() {
        let err = resolve_config(None, &ConnOverrides::default()).unwrap_err();
        assert!(err.to_string().contains("no gateway"), "got {err}");
    }
}
