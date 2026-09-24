//! The service error type.

use bussard_bus::BusError;
use bussard_mgmt::{MgmtError, SourceCheckError};
use bussard_transport::write_gate::WriteGateRefused;

use crate::secure::SecureKeyError;

/// Why a [`BusService`](crate::BusService) operation failed.
///
/// Group writes have their own, richer [`WriteRefusal`](crate::WriteRefusal);
/// this covers opening the service and management sessions.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The non-loopback write gate refused a transmitting policy (issue #74).
    #[error(transparent)]
    Gate(#[from] WriteGateRefused),

    /// The source-address check found a device answering at bussard's own
    /// source address, or could not run.
    #[error(transparent)]
    SourceCheck(#[from] SourceCheckError),

    /// The exclusive layer-4 lease on the bus could not be taken.
    #[error("leasing the bus")]
    Lease(#[source] BusError),

    /// The management connection (connect, authorize, a request) failed.
    #[error(transparent)]
    Mgmt(#[from] MgmtError),

    /// The KNX Data Secure tool key could not be resolved.
    #[error(transparent)]
    SecureKey(#[from] SecureKeyError),
}
