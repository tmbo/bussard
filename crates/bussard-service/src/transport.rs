//! The transport types the surfaces name: connection settings, the bus
//! handle and its state, the write gate, and the gateway description.
//!
//! The surfaces depend on `bussard-service` and `bussard-model` only
//! (issue #916). This module re-exports what they need from
//! `bussard-transport` by name; a flow that opens or drives a connection
//! belongs in a service module instead.

pub use bussard_transport::{
    ConnectionConfig, SecureIdleOutcome, SecureIdleReport, SecureSource, SecureTransport,
    SecureTunnelConfig, TimestampedFrame, TransportError, TransportKind, TunnelReconnect,
};

/// One-exchange gateway queries the CLI still calls directly: the gateway
/// description behind the device management gate of `bussard interface`
/// and the KNXnet/IP Secure idle probe of `bussard test --secure-idle`.
/// Neither has a second caller; moving them behind a service flow is left
/// to the interface-session work (issue #916).
pub use bussard_transport::{describe_gateway, describe_gateway_extended, probe_secure_idle};

/// The bus actor's handle and state (see `bussard_transport::bus`).
pub mod bus {
    pub use bussard_transport::bus::{
        BusDiagnostics, BusHandle, BusState, clear_no_free_tunnel_seen, fatal_connect_error,
        no_free_tunnel_seen,
    };
}

/// The cEMI message code a decoded telegram carries.
pub mod cemi {
    pub use bussard_transport::cemi::MessageCode;
}

/// Connection defaults.
pub mod config {
    pub use bussard_transport::config::{
        DEFAULT_MULTICAST, DEFAULT_MULTICAST_TTL, DEFAULT_PORT, SECURE_KEEPALIVE_INTERVAL,
        TCP_READ_DEADLINE,
    };
}

/// The non-loopback write gate (issue #74).
pub mod write_gate {
    pub use bussard_transport::write_gate::{
        ALLOW_REAL_GATEWAY_ENV, WriteGate, check_write_gate, gateway_display, is_loopback_gateway,
    };
}

/// KNXnet/IP gateway descriptions.
pub mod knxnet {
    pub use bussard_transport::knxnet::GatewayInfo;
}

/// The per-host lock of a tunnelling user (issue #287).
pub mod host_lock {
    pub use bussard_transport::host_lock::{Holder, HostLock, live_holders};
}
