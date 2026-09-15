//! The `bussard read <ga>` subcommand: send a GroupValueRead and print the
//! typed response.
//!
//! This shares the outbound-send capability added to `bussard-monitor`'s
//! [`run_stream_with_outbound`](bussard_monitor::run_stream_with_outbound): the
//! command opens the bus, injects a single `GroupValueRead`, awaits the matching
//! response on a small ring, decodes it against the GA's DPT and prints it.
//! Exits non-zero on timeout so scripts can detect a non-responding object.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use bussard_model::GroupAddress;
use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{DecodedTelegram, Filter, TelegramRing, run_stream_with_outbound};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::{TimestampedFrame, TransportError};
use tokio::sync::mpsc;

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

/// How long to wait for a GroupValueResponse before giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// The source IA for outgoing reads (matches the MCP server's default).
const SOURCE_IA: &str = "0.0.255";

/// Runs `bussard read <ga>`.
pub fn run(ga_str: &str, dir: &Path, overrides: ConnOverrides) -> anyhow::Result<ExitCode> {
    let ga: GroupAddress = ga_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid group address {ga_str:?}"))?;

    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;
    let source_ia = SOURCE_IA.parse().expect("valid source IA");

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        let ring = TelegramRing::new();
        let (out_tx, out_rx) = mpsc::unbounded_channel();

        // A sink that pushes each telegram into the ring; it never stops the
        // stream on its own (we stop by aborting the task).
        let mut sink = RingSink { ring: ring.clone() };

        // Run the stream in the background; inject the read once it is up.
        let stream = tokio::spawn(async move {
            let _ =
                run_stream_with_outbound(&config, model.as_ref(), &mut sink, Some(out_rx)).await;
        });

        // Subscribe before sending so the response cannot be missed.
        let filter = Filter::parse(&ga.to_string()).expect("GA is a valid filter term");
        let waiter = {
            let ring = ring.clone();
            tokio::spawn(async move { ring.wait_for(&filter, READ_TIMEOUT).await })
        };

        // Give the connection a moment, then send the read. If it never sends
        // (bus down), the waiter still times out and we report that.
        let _ = out_tx.send(CemiFrame::group_read(ga, source_ia));

        let result = waiter.await.ok().flatten();
        stream.abort();
        result
    });

    match outcome {
        Some(t) if t.value.is_some() => {
            // Print the decoded value (and DPT/name context on stderr).
            if let Some(name) = &t.destination_name {
                eprintln!("{ga} {name}");
            }
            match (&t.value, &t.dpt) {
                (Some(v), Some(dpt)) => println!("{v} ({dpt})"),
                (Some(v), None) => println!("{v}"),
                _ => unreachable!("value is Some in this arm"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(t) => {
            // A response with no decodable value (e.g. unknown DPT): raw payload.
            let hex: String = t.payload.iter().map(|b| format!("{b:02x}")).collect();
            println!("0x{hex}");
            Ok(ExitCode::SUCCESS)
        }
        None => {
            eprintln!(
                "error: no response for {ga} within {}s",
                READ_TIMEOUT.as_secs()
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

/// A sink that pushes each decoded telegram into a shared ring.
struct RingSink {
    ring: TelegramRing,
}

impl TelegramSink for RingSink {
    fn on_telegram(&mut self, telegram: &DecodedTelegram, _frame: &TimestampedFrame) -> Flow {
        self.ring.push(telegram.clone());
        Flow::Continue
    }

    fn on_disconnect(&mut self, error: &TransportError, backoff: Duration) -> Flow {
        tracing::warn!(
            "bus connection issue: {error}; retrying in {}s",
            backoff.as_secs()
        );
        Flow::Continue
    }
}
