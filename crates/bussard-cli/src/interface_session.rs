//! The connection of a command that manages a KNX IP interface itself
//! (issue #523): `plan`/`apply` of an interface, `describe` and `interface
//! secure`.
//!
//! # Selection rule
//!
//! The tunnel stays the default. A KNXnet/IP device management connection
//! (connection type 03h, [`bussard_transport::DeviceManagement`]) is used
//!
//! 1. when `--device-management` is given (the only way for a factory-fresh
//!    interface, which names itself 15.15.255 rather than the model's
//!    address), or
//! 2. as a fallback when the tunnel is unavailable and the gateway is the
//!    interface being managed (its description names `target`):
//!    * the gateway refuses every tunnel with `E_NO_MORE_CONNECTIONS` (no free
//!      slot), or
//!    * the source-address check finds a device answering at the tunnel's
//!      address (a duplicated tunnel address).
//!
//! The fallback prints one `note:` line naming the cause. A gateway that is
//! some other device keeps the tunnel's error. A device management
//! connection reaches the server's own device whatever address a frame
//! names, so it is opened only to a gateway whose description names
//! `target` (or the factory default 15.15.255): any other answer, or none,
//! refuses. Inside KNXnet/IP Secure it authenticates as the management user
//! from the keyring ([`bussard_service::secure::with_management_user`]).
//!
//! The writes are the same functions on either carrier; only the frames
//! below the management layer differ (see the `bussard_transport::devmgmt`
//! module docs).

use std::path::Path;
use std::time::Duration;

use anyhow::bail;
use bussard_mgmt::SourceCheckError;
use bussard_model::IndividualAddress;
use bussard_service::{BusService, ServiceError, WritePolicy};
use bussard_transport::{ConnectionConfig, TransportKind};

use crate::conn_cmd::BusSession;

/// The individual address a factory-fresh KNXnet/IP server names itself.
const FACTORY_ADDRESS: u16 = 0xFFFF;

/// How long the gateway's description is waited for.
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the open loop looks at the tunnel's state.
const POLL: Duration = Duration::from_millis(100);

/// An open session for a command that manages the interface `target`.
pub(crate) struct InterfaceSession {
    /// The bus, closed on drop.
    pub bus: BusSession,
    /// The source the management sessions present: the checked tunnel
    /// address, or `0.0.0` on a device management connection.
    pub source: IndividualAddress,
    /// The configuration the bus runs on.
    pub config: ConnectionConfig,
}

/// Opens the connection for a command that manages `target` (see the module
/// docs for the rule).
///
/// # Errors
///
/// The write gate, a refused or failed connect, a gateway that is not
/// `target` on a device management connection, or the source-address check.
pub(crate) fn open(
    runtime: &tokio::runtime::Runtime,
    config: ConnectionConfig,
    policy: WritePolicy,
    target: IndividualAddress,
    keyring: Option<&Path>,
    skip_address_check: bool,
) -> anyhow::Result<InterfaceSession> {
    match config.transport {
        TransportKind::DeviceManagement => {
            return open_device_management(runtime, config, policy, target, keyring, None);
        }
        TransportKind::Routing => {
            let bus = BusSession::open(runtime, config.clone(), policy)?;
            let source = runtime.block_on(bus.service().checked_source(skip_address_check))?;
            return Ok(InterfaceSession {
                bus,
                source,
                config,
            });
        }
        TransportKind::Tunnel => {}
    }
    crate::timing::record("to tunnel open", crate::timing::since_start(), "");
    let started = std::time::Instant::now();
    let service = {
        let _guard = runtime.enter();
        BusService::open(config.clone(), policy)?
    };
    let connected = runtime.block_on(wait_for_tunnel(&service));
    crate::timing::record("tunnel", started.elapsed(), "");
    if !connected {
        if let Some(fatal) = service.handle().fatal_error() {
            runtime.block_on(service.close());
            bail!("{fatal}");
        }
        if bussard_transport::bus::no_free_tunnel_seen()
            && runtime.block_on(gateway_is(&config, target))
        {
            runtime.block_on(service.close());
            bussard_transport::bus::clear_no_free_tunnel_seen();
            return open_device_management(
                runtime,
                config,
                policy,
                target,
                keyring,
                Some("the interface has no free tunnelling connection".to_string()),
            );
        }
        eprintln!(
            "warning: bus not connected yet; management traffic may use the 0.0.255 fallback source"
        );
    }
    let bus = BusSession::from_service(runtime, service);
    match runtime.block_on(bus.service().checked_source(skip_address_check)) {
        Ok(source) => Ok(InterfaceSession {
            bus,
            source,
            config,
        }),
        Err(ServiceError::SourceCheck(SourceCheckError::Occupied { address, mask }))
            if runtime.block_on(gateway_is(&config, target)) =>
        {
            drop(bus);
            open_device_management(
                runtime,
                config,
                policy,
                target,
                keyring,
                Some(format!(
                    "a device (mask {mask:04X}) answers at the tunnel address {address}"
                )),
            )
        }
        Err(err) => Err(err.into()),
    }
}

/// Waits up to the command's connect budget for the tunnel, returning early
/// on a refusal retrying cannot fix or a gateway without a free slot.
async fn wait_for_tunnel(service: &BusService) -> bool {
    let deadline = tokio::time::Instant::now() + crate::conn_cmd::connect_wait();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        if service.wait_connected((deadline - now).min(POLL)).await {
            return true;
        }
        if service.handle().fatal_error().is_some() || bussard_transport::bus::no_free_tunnel_seen()
        {
            return false;
        }
    }
}

/// Whether the gateway of `config` describes itself as `target`.
async fn gateway_is(config: &ConnectionConfig, target: IndividualAddress) -> bool {
    match config.gateway {
        Some(gateway) => bussard_transport::describe_gateway(gateway, DESCRIBE_TIMEOUT)
            .await
            .is_ok_and(|d| d.individual_address == Some(target.raw())),
        None => false,
    }
}

/// Opens a device management connection to the gateway of `config`, which
/// must be `target` (or factory-fresh), printing `reason` when it replaces
/// the tunnel.
fn open_device_management(
    runtime: &tokio::runtime::Runtime,
    config: ConnectionConfig,
    policy: WritePolicy,
    target: IndividualAddress,
    keyring: Option<&Path>,
    reason: Option<String>,
) -> anyhow::Result<InterfaceSession> {
    let config = device_management_config(runtime, config, target, keyring)?;
    let Some(gateway) = config.gateway else {
        bail!("a device management connection needs --gateway host[:port]");
    };
    if let Some(reason) = reason {
        eprintln!(
            "note: {reason}; managing {target} over a KNXnet/IP device management connection \
             instead of a tunnel"
        );
    }
    let service = {
        let _guard = runtime.enter();
        BusService::open(config.clone(), policy)?
    };
    let connected = runtime.block_on(service.wait_connected(crate::conn_cmd::connect_wait()));
    if !connected {
        let why = service
            .handle()
            .fatal_error()
            .or_else(|| service.handle().diagnostics().last_error)
            .unwrap_or_else(|| "no answer".to_string());
        runtime.block_on(service.close());
        bail!("device management connection to {gateway}: {why}");
    }
    Ok(InterfaceSession {
        bus: BusSession::from_service(runtime, service),
        source: IndividualAddress::from_raw(0),
        config,
    })
}

/// `config` as a device management connection to its gateway, which must
/// describe itself as `target` or as factory-fresh (15.15.255), with the
/// management user of `target` from `keyring` when it has one.
///
/// # Errors
///
/// No gateway, a gateway that names another address or does not answer, or
/// an unreadable keyring.
pub(crate) fn device_management_config(
    runtime: &tokio::runtime::Runtime,
    config: ConnectionConfig,
    target: IndividualAddress,
    keyring: Option<&Path>,
) -> anyhow::Result<ConnectionConfig> {
    let Some(gateway) = config.gateway else {
        bail!("a device management connection needs --gateway host[:port]");
    };
    let description = runtime
        .block_on(bussard_transport::describe_gateway(
            gateway,
            DESCRIBE_TIMEOUT,
        ))
        .ok();
    match description.and_then(|d| d.individual_address) {
        Some(ia) if ia == target.raw() || ia == FACTORY_ADDRESS => {}
        Some(ia) => bail!(
            "{gateway} is the KNXnet/IP server {}; a device management connection reaches that \
             device only, not {target}",
            IndividualAddress::from_raw(ia)
        ),
        None => bail!(
            "{gateway} did not describe itself (DESCRIPTION_REQUEST unanswered); bussard opens a \
             device management connection only to an interface that names itself {target}"
        ),
    }
    Ok(bussard_service::secure::with_management_user(
        config.into_device_management(),
        keyring,
        target,
    )?)
}

/// Whether every tunnelling slot of the gateway of `config` is taken, by its
/// extended description; `false` when it does not say.
pub(crate) async fn tunnel_slots_full(config: &ConnectionConfig) -> bool {
    let Some(gateway) = config.gateway else {
        return false;
    };
    bussard_transport::describe_gateway_extended(gateway, DESCRIBE_TIMEOUT)
        .await
        .ok()
        .and_then(|d| d.tunnel_slots)
        .is_some_and(|slots| !slots.is_empty() && slots.iter().all(|slot| !slot.free))
}
