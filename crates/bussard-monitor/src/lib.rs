//! Bus monitor and capture for bussard.
//!
//! This crate turns the live cEMI telegram stream from `bussard-transport` into
//! resolved, typed, human- and machine-readable output, and persists it.
//!
//! - [`decode`] — the pure decode pipeline: a cEMI frame plus an optional
//!   [`Model`](bussard_model::Model) becomes a [`DecodedTelegram`].
//! - [`filter`] — a comma-separated address filter ([`Filter`]) shared by the
//!   CLI, the ring buffer and the store.
//! - [`format`] — a coloured pretty line and stable JSON Lines.
//! - [`store`] — a SQLite capture store keeping raw cEMI plus a decoded
//!   snapshot, with a background writer and a re-decoding reader.
//! - [`ring`] — a bounded in-memory [`TelegramRing`] with a `wait_for`
//!   primitive that the MCP tools sit on.
//! - [`stream`] — the reconnecting connect-and-consume loop used by the CLI's
//!   `monitor` and `capture` commands.

#![warn(missing_docs)]

pub mod decode;
pub mod filter;
pub mod format;
pub mod ring;
pub mod store;
pub mod stream;
pub mod timefmt;

pub use decode::{ApciKind, DecodedTelegram, DestinationRef};
pub use filter::{Filter, FilterParseError};
pub use format::{json_line, pretty_line};
pub use ring::{RingEvent, RingSubscription, TelegramRing};
pub use store::{
    CaptureRecord, CaptureStore, CaptureWriter, QueryFilter, StoreError, StoredTelegram,
};
pub use stream::{
    CancelToken, CancelWatch, StreamError, TelegramSink, run_stream, run_stream_cancellable,
    run_stream_with_outbound, run_stream_with_outbound_cancellable,
};
