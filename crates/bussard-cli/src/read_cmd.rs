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

use bussard_model::{GroupAddress, IndividualAddress};
use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{
    ApciKind, CancelToken, DecodedTelegram, DestinationRef, TelegramRing,
    run_stream_with_outbound_cancellable,
};
use bussard_transport::cemi::{CemiFrame, MessageCode};
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
    let source_ia: IndividualAddress = SOURCE_IA.parse().expect("valid source IA");

    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async move {
        let ring = TelegramRing::new();
        let (out_tx, out_rx) = mpsc::unbounded_channel();

        // A sink that pushes each telegram into the ring; it never stops the
        // stream on its own (we stop via the cancel token).
        let mut sink = RingSink { ring: ring.clone() };

        // Run the stream in the background; inject the read once it is up. A
        // cancel token lets us stop it with a *clean* bus close (releasing the
        // gateway tunnel slot) instead of aborting the task — see issue #31.
        let (cancel, cancel_watch) = CancelToken::new();
        let stream = tokio::spawn(async move {
            let _ = run_stream_with_outbound_cancellable(
                &config,
                model.as_ref(),
                &mut sink,
                Some(out_rx),
                cancel_watch,
            )
            .await;
        });

        // Subscribe before sending so the response cannot be missed (the
        // subscription exists from this line on — no spawned-task race, #32).
        let mut sub = ring.subscribe();

        // Send the read. If it never transmits (bus down), the wait below still
        // times out and we report that.
        let _ = out_tx.send(CemiFrame::group_read(ga, source_ia));

        // Wait for a real answer: a GroupValueResponse or a GroupValueWrite to
        // our GA that is a bus indication (not the gateway's L_Data.con echo of
        // our own request) and not from our own source address — issue #32.
        let result = sub
            .wait_for_matching(READ_TIMEOUT, |t, code| {
                matches!(t.destination, DestinationRef::Group(g) if g == ga)
                    && matches!(t.apci, ApciKind::Response | ApciKind::Write)
                    && code != MessageCode::LDataCon
                    && t.source != source_ia
            })
            .await;
        // Cancel and wait for the stream to close the connection cleanly.
        cancel.cancel();
        let _ = stream.await;
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
    fn on_telegram(&mut self, telegram: &DecodedTelegram, frame: &TimestampedFrame) -> Flow {
        // Carry the cEMI message code so the waiter can skip L_Data.con echoes.
        self.ring
            .push_with_code(telegram.clone(), frame.frame.message_code);
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
