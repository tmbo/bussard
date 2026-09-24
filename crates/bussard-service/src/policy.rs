//! What a [`BusService`](crate::BusService) may put on the bus.
//!
//! The policy is fixed when the service is opened and decides whether the
//! non-loopback write gate applies (issue #74). Reads (group reads, device
//! descriptor and property reads) are allowed under every policy: they cannot
//! change the installation, so they never needed the gate.

use bussard_transport::ConnectionConfig;
use bussard_transport::write_gate::{WriteGate, WriteGateRefused, check_write_gate};

/// The write policy a [`BusService`](crate::BusService) is opened under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// Reads only. The write gate does not apply, and
    /// [`write_group_checked`](crate::BusService::write_group_checked) refuses
    /// with [`WriteRefusal::WritesDisabled`](crate::WriteRefusal::WritesDisabled).
    ReadOnly,
    /// The service may write: group writes, management writes, broadcast
    /// probes. A non-loopback gateway is refused unless
    /// `allow_remote_gateway` is set or the operator exported
    /// [`ALLOW_REAL_GATEWAY_ENV`](bussard_transport::write_gate::ALLOW_REAL_GATEWAY_ENV).
    Transmit {
        /// The operator's explicit opt-in to a non-loopback gateway (the CLI's
        /// `--allow-remote-gateway`).
        allow_remote_gateway: bool,
    },
}

impl WritePolicy {
    /// A [`WritePolicy::Transmit`] with the given remote-gateway opt-in.
    pub fn transmit(allow_remote_gateway: bool) -> WritePolicy {
        WritePolicy::Transmit {
            allow_remote_gateway,
        }
    }

    /// Whether this policy permits writes.
    pub fn transmits(self) -> bool {
        matches!(self, WritePolicy::Transmit { .. })
    }

    /// Applies the write gate for this policy to `config`.
    ///
    /// Returns `Ok(None)` for [`WritePolicy::ReadOnly`] (no gate applies),
    /// `Ok(Some(gate))` when a transmitting policy passes, and the refusal when a
    /// non-loopback gateway was not opted into.
    pub fn check(self, config: &ConnectionConfig) -> Result<Option<WriteGate>, WriteGateRefused> {
        match self {
            WritePolicy::ReadOnly => Ok(None),
            WritePolicy::Transmit {
                allow_remote_gateway,
            } => check_write_gate(config, allow_remote_gateway).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn tunnel(ip: Ipv4Addr) -> ConnectionConfig {
        ConnectionConfig::tunnel(SocketAddrV4::new(ip, 3671))
    }

    #[test]
    fn test_check_read_only_never_gates() {
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(WritePolicy::ReadOnly.check(&real), Ok(None));
    }

    #[test]
    fn test_check_transmit_loopback_passes() {
        assert_eq!(
            WritePolicy::transmit(false).check(&tunnel(Ipv4Addr::LOCALHOST)),
            Ok(Some(WriteGate::Loopback))
        );
    }

    #[test]
    fn test_check_transmit_real_gateway_refused_without_opt_in() {
        let real = tunnel(Ipv4Addr::new(192, 0, 2, 10));
        // The environment opt-in would let it through; only assert the refusal
        // when the test process was not started with it.
        if !bussard_transport::write_gate::real_gateway_env_opt_in() {
            assert!(WritePolicy::transmit(false).check(&real).is_err());
        }
        assert_eq!(
            WritePolicy::transmit(true).check(&real),
            Ok(Some(WriteGate::OptedIn))
        );
    }
}
