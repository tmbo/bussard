//! Bus monitor and capture for bussard.
//!
//! This crate turns the live cEMI telegram stream from `bussard-transport` into
//! resolved, typed, human- and machine-readable output, and persists it.
//!
//! - [`decode`] — the pure decode pipeline: a cEMI frame plus an optional
//!   [`Model`](bussard_model::Model) becomes a [`DecodedTelegram`].
//! - [`acceptance`] — the scripted `tests.yaml` runner behind `bussard test`.
//! - [`infer`] — pure DPT inference and name proposal from observed payloads,
//!   the engine behind `bussard learn` and the `knx_infer_group` MCP tool.
//! - [`filter`] — a comma-separated address filter ([`Filter`]) shared by the
//!   CLI, the ring buffer and the store.
//! - [`format`] — a coloured pretty line and stable JSON Lines.
//! - [`store`] — a SQLite capture store keeping raw cEMI plus a decoded
//!   snapshot, with a background writer and a re-decoding reader.
//! - [`secure`] — KNX Data Secure group telegrams: verify and decrypt with
//!   the keyring's group keys ([`GroupKeyring`]) before decoding.
//! - [`ring`] — a bounded in-memory [`TelegramRing`] with a `wait_for`
//!   primitive that the MCP tools sit on.
//! - [`stream`] — the reconnecting connect-and-consume loop used by the CLI's
//!   `monitor` and `capture` commands.

#![warn(missing_docs)]

pub mod acceptance;
pub mod decode;
pub mod filter;
pub mod format;
pub mod infer;
pub mod ring;
pub mod secure;
pub mod store;
pub mod stream;
pub mod timefmt;

pub use acceptance::{
    ManualDecision, ManualStep, Report, RunOptions, SkipManual, Status, TestOutcome, run_suite,
};
pub use decode::{ApciKind, DecodedTelegram, DestinationRef};
pub use filter::{Filter, FilterParseError};
pub use format::{json_line, json_value, pretty_line};
pub use infer::{
    Confidence, DptCandidate, SendingObject, infer_dpt, propose_name, refine, sending_object,
};
pub use ring::{RingEvent, RingSubscription, TelegramRing};
pub use secure::{GroupKeyring, SecureInfo, SecureStatus};
pub use store::{
    CaptureRecord, CaptureStore, CaptureWriter, QueryFilter, StoreError, StoredTelegram,
};
pub use stream::{
    CancelToken, CancelWatch, StreamError, TelegramSink, run_stream, run_stream_cancellable,
    run_stream_secured_cancellable, run_stream_with_outbound, run_stream_with_outbound_cancellable,
};
