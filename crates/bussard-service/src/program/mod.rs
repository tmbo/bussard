//! Device programming, once for both surfaces (issue #901): the read of a
//! device ([`read`]), the plan of writing the model to it ([`plan`]), the
//! write with its independent read-back ([`apply`]) and the full application
//! download ([`flash`]), driven through one [`Observer`] (a [`ProgressSink`] and a [`Prompt`]).
//!
//! `bussard flash`, `plan`, `apply` and `restore` and the MCP tier's
//! `knx_plan_device`, `knx_apply_device` and `knx_restore_tables` call these
//! functions and only parse arguments, implement the observer and render the
//! outcome, so the CLI and the MCP server write a device through the same
//! code (CLAUDE.md "Device Writes"). The bytes the flows write are the
//! offline oracle's (`scripts/campaign/95-offline-oracle.sh`).

pub mod addressed;
pub mod adopt;
pub mod apply;
pub mod assign;
pub mod dump;
pub mod flash;
pub mod outcome;
pub mod params_only;
pub mod plan;
pub mod plan_outcome;
pub mod read;
pub mod report;
pub mod resident;

use crate::ServiceError;

pub use crate::observer::{
    Answer, Ask, Declined, Event, Note, Observer, ProgressSink, Prompt, Question, Step, ask,
};

pub use crate::util::chain;

/// Adds a [`ServiceError::Context`] to a failure.
pub(crate) trait Ctx<T> {
    /// The failure, under the context `what` names.
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T, ServiceError>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Ctx<T> for Result<T, E> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T, ServiceError> {
        self.map_err(|err| ServiceError::context(what(), err))
    }
}
