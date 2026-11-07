//! Device programming, once for both surfaces (issue #901): the read of a
//! device ([`read`]), the plan of writing the model to it ([`plan`]), the
//! write with its independent read-back ([`apply`]) and the full application
//! download ([`flash`]), driven through one [`Observer`].
//!
//! `bussard flash`, `plan`, `apply` and `restore` and the MCP tier's
//! `knx_plan_device`, `knx_apply_device` and `knx_restore_tables` call these
//! functions and only parse arguments, implement the observer and render the
//! outcome, so the CLI and the MCP server write a device through the same
//! code (CLAUDE.md "Device Writes"). The bytes the flows write are the
//! offline oracle's (`scripts/campaign/95-offline-oracle.sh`).

pub mod apply;
pub mod dump;
pub mod flash;
pub mod observer;
pub mod params_only;
pub mod plan;
pub mod read;
pub mod report;
pub mod resident;

pub use observer::{Answer, Declined, Note, Observer, Question, Step, ask};

/// An error and its sources, joined with `": "` (anyhow's `{:#}`).
pub fn chain(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// A file a dry run reads or writes that failed, with what was being done.
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct FileError {
    /// What was being done (`writing <path>`).
    pub context: String,
    /// The failure.
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

/// Adds a [`FileError`] context to a failure.
pub(crate) trait Ctx<T> {
    /// The failure, under the context `what` names.
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T, FileError>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Ctx<T> for Result<T, E> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T, FileError> {
        self.map_err(|err| FileError {
            context: what(),
            source: Box::new(err),
        })
    }
}
