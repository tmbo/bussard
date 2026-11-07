//! The bus monitor the surfaces drive: telegram decoding, the ring, the
//! capture store, filters, formatters and the live stream behind `bussard
//! monitor` and `bussard capture`.
//!
//! Re-exported from `bussard-monitor` by name so the surfaces depend on
//! `bussard-service` and `bussard-model` only (issue #916).

pub use bussard_model::timefmt;
pub use bussard_monitor::{
    ApciKind, CancelToken, CaptureRecord, CaptureStore, CaptureWriter, DecodedTelegram,
    DestinationRef, Filter, GroupKeyring, QueryFilter, SecureStatus, StreamOptions, TelegramRing,
    json_line, json_value, pretty_line, run_stream,
};

/// Telegram decoding.
pub mod decode {
    pub use bussard_monitor::decode::{ApciKind, DestinationRef};
}

/// The live stream.
pub mod stream {
    pub use bussard_monitor::stream::{Flow, TelegramSink};
}
