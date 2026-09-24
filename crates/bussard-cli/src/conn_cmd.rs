//! Shared connection setup for every bus-facing command.
//!
//! Resolves a [`ConnectionConfig`] from an optional model directory's
//! `bussard.yaml` plus command-line overrides, and loads the model (warning and
//! continuing when the directory is absent). It also holds the two pre-flight
//! gates every device command runs: the non-loopback write gate
//! ([`enforce_write_gate`]) and the source-address check ([`checked_source`]).

use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::path::Path;

use anyhow::{Context, anyhow};
use bussard_model::IndividualAddress;
use bussard_model::Model;
use bussard_model::schema::Transport as ModelTransport;
use bussard_service::{BusService, ServiceError, WritePolicy};
use bussard_transport::config::{DEFAULT_MULTICAST, DEFAULT_PORT};
use bussard_transport::write_gate::WriteGate;
use bussard_transport::{ConnectionConfig, SecureTunnelConfig, TransportKind, TunnelReconnect};

/// Command-line connection overrides shared by `monitor` and `capture`.
#[derive(Debug, Clone, Default)]
pub struct ConnOverrides {
    /// `--gateway host[:port]` for tunneling.
    pub gateway: Option<String>,
    /// `--routing` to force multicast routing.
    pub routing: bool,
    /// `--skip-address-check` to skip the pre-flight probe that no bus device
    /// answers at bussard's own source individual address.
    pub skip_address_check: bool,
}

/// The source individual address for a **connection-oriented** device command,
/// checked against the bus first.
///
/// Resolves the source exactly as [`bussard_bus::ops::group_source`] does (the tunnel-assigned
/// individual address, or the `0.0.255` fallback on routing), then — unless
/// `--skip-address-check` was passed — probes the bus for a device answering at
/// that very address and refuses to continue if one does.
///
/// # Why the check is not optional by default
///
/// A KNX device distinguishes its management clients by source individual
/// address alone. If a real device answers where we speak from, both parties'
/// numbered telegrams land inside one layer-4 session at the device: a memory
/// write can be applied on behalf of the wrong session while both sides still
/// see a `T_ACK`. That is silent configuration corruption, which is why ETS runs
/// the same check before it uses an interface.
///
/// Group-only commands (`read`, `write`, `monitor`, `capture`, `learn`, `test`) are
/// connectionless and do not need this.
pub async fn checked_source(
    service: &BusService,
    overrides: &ConnOverrides,
) -> anyhow::Result<IndividualAddress> {
    // The probe and its refusal live in `bussard_mgmt` (behind the service) so
    // the MCP programming tier refuses on the same evidence.
    Ok(service.checked_source(overrides.skip_address_check).await?)
}

/// [`checked_source`], closing `service` before returning an error.
///
/// Every device command owns its [`BusService`] for the length of one runtime
/// block and closes it when it is done. A refusal from the source-address check
/// happens before any of that, so without this the gateway would hold the tunnel
/// slot open for its full idle timeout (about two minutes) after a command that
/// did nothing — see issue #31 for the same hazard on Ctrl-C.
pub async fn checked_source_or_close(
    service: &BusService,
    overrides: &ConnOverrides,
) -> anyhow::Result<IndividualAddress> {
    match checked_source(service, overrides).await {
        Ok(source) => Ok(source),
        Err(err) => {
            service.close().await;
            Err(err)
        }
    }
}

/// A management session that could not be opened, as an error for the
/// command: a lease failure as it is, a connect failure under `context` (the
/// `.with_context` the command put on its own connect before issue #86).
pub fn session_open_error(err: ServiceError, context: impl FnOnce() -> String) -> anyhow::Error {
    match err {
        ServiceError::Lease(_) => err.into(),
        other => anyhow::Error::new(other).context(context()),
    }
}

/// Renders a management session that could not be opened the way the device
/// commands report it in a per-device row: `leasing the bus: <cause>` or
/// `connecting: <cause>`.
pub fn session_error_detail(err: &ServiceError) -> String {
    match err {
        ServiceError::Lease(cause) => format!("leasing the bus: {cause}"),
        other => format!("connecting: {other}"),
    }
}

/// The exit code for "the gateway has no free tunnelling connection"
/// (`E_NO_MORE_CONNECTIONS`, issue #105).
///
/// Distinct from the generic failure code `1` so a script can tell a full
/// interface from a network timeout or a refusal.
pub const EXIT_NO_FREE_TUNNEL: u8 = 4;

/// The message printed when a gateway refuses a connect for want of a free
/// tunnelling slot.
///
/// Names the clients that most often hold the slots, because the fix is almost
/// always "stop one of them", not "retry".
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

/// One KNXnet/IP tunnel held open for a whole command, closed on every exit path.
///
/// A management command that reads first and writes second (`flash`, `apply`)
/// used to open a tunnel for the read-only pre-flight, close it, and open a
/// second one for the write phase. Each open costs a CONNECT_REQUEST round trip
/// plus the tunnel's own-address setup, each close can wait out the DISCONNECT
/// timeout on a silent gateway, and a gateway with a single tunnel slot can
/// refuse the second connect outright.
///
/// This holds **one** tunnel across both phases — the transport's heartbeat keeps
/// the slot alive across the interactive confirmation — and closes it from
/// `Drop`, so every early return, refusal, declined confirmation and error path
/// releases the gateway slot exactly once (issue #31's guarantee, now on one
/// connection instead of two).
///
/// The session wraps a [`BusService`], so the write gate for its
/// [`WritePolicy`] is applied when it opens (issue #86).
pub struct BusSession {
    service: BusService,
    runtime: tokio::runtime::Handle,
}

impl BusSession {
    /// Opens the tunnel on `runtime` under `policy` (applying the write gate)
    /// and waits (bounded) for it to come up.
    ///
    /// A gateway that has not answered in time only warns: management traffic
    /// then presents the 0.0.255 fallback source, exactly as before.
    ///
    /// # Errors
    ///
    /// The write gate refused `policy` for this gateway; nothing is connected.
    pub fn open(
        runtime: &tokio::runtime::Runtime,
        config: ConnectionConfig,
        policy: WritePolicy,
    ) -> anyhow::Result<BusSession> {
        let service = runtime.block_on(open_service(config, policy))?;
        Ok(BusSession {
            service,
            runtime: runtime.handle().clone(),
        })
    }

    /// The bus service every phase of the command runs over, for its
    /// management sessions ([`BusService::with_l4`]).
    pub fn service(&self) -> &BusService {
        &self.service
    }
}

impl Drop for BusSession {
    fn drop(&mut self) {
        // Close the tunnel cleanly (release the gateway's slot) whichever way the
        // command exited. `run` is synchronous here, so blocking on the runtime
        // handle is safe; a gone actor makes this a no-op.
        self.runtime.block_on(self.service.close());
    }
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

/// The KNXnet/IP Secure tunnelling credentials of this invocation (issue #71
/// Phase B), set once by `main` from `--keyring` / `--secure-user` before the
/// subcommand runs, and attached to every tunnel [`resolve_config`] builds.
static SECURE_TUNNEL: std::sync::Mutex<Option<SecureTunnelConfig>> = std::sync::Mutex::new(None);

/// Sets the KNXnet/IP Secure tunnelling credentials for this invocation.
pub fn set_secure_tunnel(config: Option<SecureTunnelConfig>) {
    if let Ok(mut slot) = SECURE_TUNNEL.lock() {
        *slot = config;
    }
}

/// The KNXnet/IP Secure tunnelling credentials of this invocation, if any.
fn secure_tunnel() -> Option<SecureTunnelConfig> {
    SECURE_TUNNEL.lock().ok().and_then(|g| g.clone())
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
            reconnect: tunnel_reconnect(),
            secure: None,
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
        reconnect: tunnel_reconnect(),
        secure: secure_tunnel(),
    })
}

/// Environment variable that sets how many seconds a lost gateway tunnel is
/// re-established for before the pending bus operation fails (issue #177).
/// `0` turns re-establishing off. Unset means the default (60 s).
pub(crate) const TUNNEL_RECONNECT_SECS_ENV: &str = "BUSSARD_TUNNEL_RECONNECT_SECS";

/// Environment variable that sets the read deadline of a KNXnet/IP Secure
/// (TCP) tunnel in milliseconds (issue #192): after this long without inbound
/// traffic the tunnel probes the link and re-establishes it when the probe goes
/// unanswered. `0` turns the check off. Unset means the default (5000 ms).
pub(crate) const TCP_READ_DEADLINE_MS_ENV: &str = "BUSSARD_TCP_READ_DEADLINE_MS";

/// The tunnel re-establish policy, honouring [`TUNNEL_RECONNECT_SECS_ENV`] and
/// [`TCP_READ_DEADLINE_MS_ENV`].
fn tunnel_reconnect() -> TunnelReconnect {
    let policy = parse_reconnect_secs(std::env::var(TUNNEL_RECONNECT_SECS_ENV).ok().as_deref());
    apply_tcp_read_deadline(
        policy,
        std::env::var(TCP_READ_DEADLINE_MS_ENV).ok().as_deref(),
    )
}

/// Applies a [`TCP_READ_DEADLINE_MS_ENV`] value to `policy`; an absent or
/// unparsable value keeps the policy's deadline.
fn apply_tcp_read_deadline(policy: TunnelReconnect, value: Option<&str>) -> TunnelReconnect {
    match value.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(ms) => policy.with_tcp_read_deadline(std::time::Duration::from_millis(ms)),
        None => policy,
    }
}

/// Maps a [`TUNNEL_RECONNECT_SECS_ENV`] value to a policy; an absent or
/// unparsable value keeps the default.
fn parse_reconnect_secs(value: Option<&str>) -> TunnelReconnect {
    match value.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(secs) => TunnelReconnect::with_budget(std::time::Duration::from_secs(secs)),
        None => TunnelReconnect::default(),
    }
}

// The write-gate policy (issue #74) lives in `bussard_transport::write_gate` so
// the MCP programming tier applies the same rule; the CLI re-exports it.
pub use bussard_transport::write_gate::gateway_display;

/// Enforces the non-loopback write gate (issue #74).
///
/// A write command whose resolved gateway is **not** loopback refuses to run
/// unless the operator has explicitly opted in, either by passing
/// `--allow-remote-gateway` (`allow_flag = true`) or by setting
/// [`bussard_transport::write_gate::ALLOW_REAL_GATEWAY_ENV`] to `1`. Loopback gateways (the local simulator,
/// the test suite) are always permitted. On refusal this returns a loud error
/// naming the host and both ways to proceed. The policy itself is
/// [`bussard_transport::write_gate::check_write_gate`]; this adds the CLI's
/// stderr warning on an acknowledged opt-in.
pub fn enforce_write_gate(config: &ConnectionConfig, allow_flag: bool) -> anyhow::Result<()> {
    match BusService::check(config, WritePolicy::transmit(allow_flag))? {
        Some(WriteGate::OptedIn) => {
            eprintln!(
                "warning: writing to non-loopback gateway {} (opt-in acknowledged)",
                gateway_display(config)
            );
            Ok(())
        }
        Some(WriteGate::Loopback) | None => Ok(()),
    }
}

/// Opens a [`BusService`] under `policy` (which applies the write gate) and
/// waits, bounded, for the first connect.
///
/// A gateway that has not answered in time only warns: management traffic then
/// presents the 0.0.255 fallback source, exactly as a bare `Bus::connect` did.
/// Must run inside the command's tokio runtime.
pub async fn open_service(
    config: ConnectionConfig,
    policy: WritePolicy,
) -> anyhow::Result<BusService> {
    let service = BusService::open(config, policy)?;
    if !service
        .wait_connected(std::time::Duration::from_secs(10))
        .await
    {
        // A refusal retrying cannot fix (issue #182): stop here with that
        // cause, before any fallback-source warning or device hint.
        if let Some(fatal) = service.handle().fatal_error() {
            anyhow::bail!("{fatal}");
        }
        eprintln!(
            "warning: bus not connected yet; management traffic may use the 0.0.255 fallback source"
        );
    }
    Ok(service)
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
    fn test_parse_reconnect_secs_maps_env_values() {
        assert_eq!(parse_reconnect_secs(None), TunnelReconnect::default());
        assert_eq!(
            parse_reconnect_secs(Some("junk")),
            TunnelReconnect::default()
        );
        assert_eq!(
            parse_reconnect_secs(Some(" 120 ")).budget,
            std::time::Duration::from_secs(120)
        );
        assert!(!parse_reconnect_secs(Some("0")).enabled());
    }

    #[test]
    fn test_apply_tcp_read_deadline_maps_env_values() {
        let base = TunnelReconnect::default();
        assert_eq!(
            base.tcp_read_deadline,
            bussard_transport::config::TCP_READ_DEADLINE
        );
        assert_eq!(apply_tcp_read_deadline(base, None), base);
        assert_eq!(apply_tcp_read_deadline(base, Some("junk")), base);
        assert_eq!(
            apply_tcp_read_deadline(base, Some(" 1500 ")).tcp_read_deadline,
            std::time::Duration::from_millis(1500)
        );
        assert!(
            apply_tcp_read_deadline(base, Some("0"))
                .tcp_read_deadline
                .is_zero()
        );
    }
    use bussard_transport::write_gate::{ALLOW_REAL_GATEWAY_ENV, is_loopback_gateway};

    /// Builds a tunnel [`ConnectionConfig`] pointed at `host` for gate tests.
    fn tunnel_to(host: &str) -> ConnectionConfig {
        resolve_config(
            None,
            &ConnOverrides {
                gateway: Some(host.to_string()),
                ..Default::default()
            },
        )
        .expect("test fixture")
    }

    #[test]
    fn is_loopback_gateway_true_for_loopback() {
        assert!(is_loopback_gateway(&tunnel_to("127.0.0.1:1234")));
        assert!(is_loopback_gateway(&tunnel_to("127.0.0.5:3671")));
    }

    #[test]
    fn is_loopback_gateway_false_for_real_host_and_routing()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(!is_loopback_gateway(&tunnel_to("192.0.2.10")));
        let routing = resolve_config(
            None,
            &ConnOverrides {
                routing: true,
                ..Default::default()
            },
        )?;
        assert!(!is_loopback_gateway(&routing));
        Ok(())
    }

    #[test]
    fn enforce_write_gate_allows_loopback_without_optin() -> Result<(), Box<dyn std::error::Error>>
    {
        // Loopback (the local simulator, the test suite) is always permitted, no
        // flag or env needed.
        enforce_write_gate(&tunnel_to("127.0.0.1:3671"), false)?;
        Ok(())
    }

    #[test]
    fn enforce_write_gate_refuses_non_loopback_without_optin() {
        // Ensure the env opt-in is not accidentally set in this process.
        unsafe {
            std::env::remove_var(ALLOW_REAL_GATEWAY_ENV);
        }
        let err =
            enforce_write_gate(&tunnel_to("192.0.2.10"), false).expect_err("expected an error");
        let msg = err.to_string();
        assert!(msg.contains("192.0.2.10"), "must name the host; got {msg}");
        assert!(
            msg.contains("--allow-remote-gateway") && msg.contains(ALLOW_REAL_GATEWAY_ENV),
            "must state both ways to proceed; got {msg}"
        );
    }

    #[test]
    fn enforce_write_gate_allows_non_loopback_with_flag() -> Result<(), Box<dyn std::error::Error>>
    {
        enforce_write_gate(&tunnel_to("192.0.2.10"), true)?;
        Ok(())
    }

    #[test]
    fn enforce_write_gate_allows_non_loopback_with_env() -> Result<(), Box<dyn std::error::Error>> {
        // SAFETY: single-threaded test; nextest isolates each test in its own
        // process, so this env mutation cannot race another test.
        unsafe {
            std::env::set_var(ALLOW_REAL_GATEWAY_ENV, "1");
        }
        let out = enforce_write_gate(&tunnel_to("192.0.2.10"), false);
        unsafe {
            std::env::remove_var(ALLOW_REAL_GATEWAY_ENV);
        }
        out?;
        Ok(())
    }

    #[test]
    fn gateway_display_renders_host_and_multicast() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            gateway_display(&tunnel_to("10.0.0.5:1234")),
            "10.0.0.5:1234"
        );
        let routing = resolve_config(
            None,
            &ConnOverrides {
                routing: true,
                ..Default::default()
            },
        )?;
        assert!(gateway_display(&routing).starts_with("multicast "));
        Ok(())
    }

    #[test]
    fn parse_socket_adds_default_port() -> Result<(), Box<dyn std::error::Error>> {
        let a = parse_socket("127.0.0.1")?;
        assert_eq!(a.port(), DEFAULT_PORT);
        assert_eq!(a.ip().to_string(), "127.0.0.1");
        Ok(())
    }

    #[test]
    fn parse_socket_explicit_port() -> Result<(), Box<dyn std::error::Error>> {
        let a = parse_socket("10.0.0.5:1234")?;
        assert_eq!(a.port(), 1234);
        Ok(())
    }

    #[test]
    fn routing_override_forces_multicast() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = resolve_config(
            None,
            &ConnOverrides {
                routing: true,
                ..Default::default()
            },
        )?;
        assert_eq!(cfg.transport, TransportKind::Routing);
        assert_eq!(cfg.multicast.ip(), &DEFAULT_MULTICAST);
        Ok(())
    }

    #[test]
    fn gateway_override_forces_tunnel() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = resolve_config(
            None,
            &ConnOverrides {
                gateway: Some("192.0.2.10".to_string()),
                ..Default::default()
            },
        )?;
        assert_eq!(cfg.transport, TransportKind::Tunnel);
        assert_eq!(cfg.gateway.ok_or("expected a value")?.port(), DEFAULT_PORT);
        Ok(())
    }

    #[test]
    fn tunnel_without_gateway_errors() {
        let err = resolve_config(None, &ConnOverrides::default()).expect_err("expected an error");
        assert!(err.to_string().contains("no gateway"), "got {err}");
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bussard-conn-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test fixture")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn load_model_required_absent_dir_is_ok_none() -> Result<(), Box<dyn std::error::Error>> {
        // A fresh project: the directory does not exist. Required-load returns
        // Ok(None) so the caller may proceed unmodeled (issue #55).
        let dir = tmp_dir("absent");
        let out = load_model_required(&dir)?;
        assert!(out.is_none(), "absent dir must be Ok(None)");
        Ok(())
    }

    #[test]
    fn load_model_required_broken_model_is_hard_error() -> Result<(), Box<dyn std::error::Error>> {
        // A present-but-malformed groups.yaml must be a hard error, NOT a silent
        // None that would fail the protected-GA gate open (issue #55).
        let dir = tmp_dir("broken");
        std::fs::create_dir_all(&dir)?;
        // Duplicate keys make the YAML parse fail.
        std::fs::write(
            dir.join("groups.yaml"),
            "groups:\n  \"1/0/0\":\n    name: a\n  \"1/0/0\":\n    name: b\n",
        )?;
        let err = load_model_required(&dir).expect_err("expected an error");
        let msg = err.to_string();
        assert!(msg.contains("failed to load model"), "got {msg}");
        assert!(
            msg.contains("broken model") || msg.contains("protected"),
            "got {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn load_model_required_empty_dir_is_fresh_project() -> Result<(), Box<dyn std::error::Error>> {
        // An existing but empty project dir (no groups.yaml) loads to the default
        // empty model — a fresh project with nothing to protect.
        let dir = tmp_dir("empty");
        std::fs::create_dir_all(&dir)?;
        let out = load_model_required(&dir)?;
        assert!(out.is_some(), "empty dir loads the default model");
        assert!(out.ok_or("expected a value")?.groups.groups.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
