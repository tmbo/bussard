//! The service error type.

use bussard_bus::BusError;
use bussard_mgmt::{MgmtError, SourceCheckError};
use bussard_transport::write_gate::WriteGateRefused;

use crate::secure::SecureKeyError;

/// A boxed error from a callee the service layer does not distinguish.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Why a service flow failed.
///
/// One error for the layer (issue #909). The variants are what the surfaces
/// tell apart: a refusal sentence shown as-is, the callee errors they match
/// on, and a context line naming the stage that failed. Group writes have
/// their own, richer [`WriteRefusal`](crate::WriteRefusal); flows whose
/// stops carry structured data keep their own enums.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A policy or gate refusal; the sentence says why and is shown as-is.
    #[error("{0}")]
    Refused(String),

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

    /// A group telegram could not be sent or answered.
    #[error(transparent)]
    Bus(#[from] BusError),

    /// The management connection (connect, authorize, a request) failed.
    #[error(transparent)]
    Mgmt(#[from] MgmtError),

    /// The KNX Data Secure tool key could not be resolved.
    #[error(transparent)]
    SecureKey(#[from] SecureKeyError),

    /// A stage failed; `context` names it, `source` says why.
    #[error("{context}")]
    Context {
        /// The stage, as the surfaces show it.
        context: String,
        /// The callee error.
        #[source]
        source: BoxError,
    },

    /// A callee error passed through unchanged.
    #[error(transparent)]
    Other(BoxError),
}

impl ServiceError {
    /// A refusal with this sentence.
    pub fn refused(reason: impl Into<String>) -> Self {
        Self::Refused(reason.into())
    }

    /// `source` under the stage named by `context`.
    pub fn context(context: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Context {
            context: context.into(),
            source: source.into(),
        }
    }

    /// `source` under `context`, with its sentence after a colon in the
    /// message itself (`"<context>: <source>"`).
    pub fn because(context: impl std::fmt::Display, source: impl Into<BoxError>) -> Self {
        let source = source.into();
        Self::Context {
            context: format!("{context}: {source}"),
            source,
        }
    }

    /// `source` passed through unchanged.
    pub fn other(source: impl Into<BoxError>) -> Self {
        Self::Other(source.into())
    }
}

/// A service error as the one sentence the surfaces show: the message and its
/// causes joined with `": "` ([`chain`](crate::util::chain), anyhow's `{:#}`).
impl From<ServiceError> for String {
    fn from(err: ServiceError) -> Self {
        crate::util::chain(&err)
    }
}
