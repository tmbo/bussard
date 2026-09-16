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

/// Loads the model from `dir` for a **monitoring** command that may safely
/// degrade to numeric addresses. An absent directory or a parse error both warn
/// and return `None` (monitor still runs). Write and management commands must
/// NOT use this: a model that is present but broken must be a hard error there,
/// so they call [`load_model_required`] instead.
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

/// Loads the model from `dir` for a **write or management** command, where a
/// broken model must never silently disable a safety gate (issue #55).
///
/// Distinguishes two cases the monitoring loader collapses together:
///
/// * The model directory is **absent** — a fresh project. Returns `Ok(None)`;
///   the caller proceeds unmodeled (a `write --dpt` still works, and there are
///   no protected GAs to enforce because there is no `groups.yaml` yet).
/// * The directory is **present but fails to parse** (malformed `groups.yaml`,
///   schema violation, duplicate device address, I/O error). Returns `Err`, so
///   the command aborts loudly rather than proceeding with `None` — which would
///   fail the protected-GA gate *open* exactly when the config is broken.
///
/// An existing-but-empty project directory (no `groups.yaml` yet) loads to the
/// default empty model via [`Model::load`], so it is `Ok(Some(empty))` — still
/// a fresh project with nothing to protect.
pub fn load_model_required(dir: &Path) -> anyhow::Result<Option<Model>> {
    if !dir.exists() {
        tracing::warn!(
            "model directory {} not found; proceeding without a model (fresh project)",
            dir.display()
        );
        return Ok(None);
    }
    Model::load(dir).map(Some).map_err(|err| {
        anyhow!(
            "failed to load model from {}: {err}. Refusing to run a write/management command \
             against a broken model (a parse error must not silently bypass the protected-GA \
             gate); fix the model files or pass an explicit path",
            dir.display()
        )
    })
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

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bussard-conn-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn load_model_required_absent_dir_is_ok_none() {
        // A fresh project: the directory does not exist. Required-load returns
        // Ok(None) so the caller may proceed unmodeled (issue #55).
        let dir = tmp_dir("absent");
        let out = load_model_required(&dir).unwrap();
        assert!(out.is_none(), "absent dir must be Ok(None)");
    }

    #[test]
    fn load_model_required_broken_model_is_hard_error() {
        // A present-but-malformed groups.yaml must be a hard error, NOT a silent
        // None that would fail the protected-GA gate open (issue #55).
        let dir = tmp_dir("broken");
        std::fs::create_dir_all(&dir).unwrap();
        // Duplicate keys make the YAML parse fail.
        std::fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"1/0/0\":\n    name: a\n  \"1/0/0\":\n    name: b\n",
        )
        .unwrap();
        let err = load_model_required(&dir).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to load model"), "got {msg}");
        assert!(
            msg.contains("broken model") || msg.contains("protected"),
            "got {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_model_required_empty_dir_is_fresh_project() {
        // An existing but empty project dir (no groups.yaml) loads to the default
        // empty model — a fresh project with nothing to protect.
        let dir = tmp_dir("empty");
        std::fs::create_dir_all(&dir).unwrap();
        let out = load_model_required(&dir).unwrap();
        assert!(out.is_some(), "empty dir loads the default model");
        assert!(out.unwrap().groups.groups.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
