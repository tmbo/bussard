//! The `bussard capture` subcommand: stream decoded telegrams into SQLite.

use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{CaptureRecord, CaptureWriter, DecodedTelegram, Filter};
use bussard_transport::{TimestampedFrame, TransportError};

use crate::conn_cmd::{load_model_optional, resolve_config, ConnOverrides};

/// How often the running count is printed to stderr.
const COUNT_INTERVAL: Duration = Duration::from_secs(3);

/// Runs `bussard capture --to <db>`.
pub fn run(
    to: &Path,
    dir: &Path,
    filter_expr: Option<&str>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let filter = match filter_expr {
        Some(expr) => Filter::parse(expr)?,
        None => Filter::default(),
    };
    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;

    let writer = CaptureWriter::open(to)?;
    eprintln!("capturing to {} (Ctrl-C to stop)", to.display());

    let counter = Arc::new(AtomicU64::new(0));

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let mut sink = CaptureSink {
            writer: &writer,
            filter,
            counter: counter.clone(),
        };

        // Periodically print the running count to stderr.
        let ticker_counter = counter.clone();
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(COUNT_INTERVAL);
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                eprintln!(
                    "captured {} telegrams",
                    ticker_counter.load(Ordering::Relaxed)
                );
            }
        });

        tokio::select! {
            res = bussard_monitor::run_stream(&config, model.as_ref(), &mut sink) => {
                res.map_err(anyhow::Error::from)?;
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!();
                tracing::info!("interrupted; flushing capture");
            }
        }
        ticker.abort();
        Ok::<(), anyhow::Error>(())
    })?;

    // Flush and join the writer thread.
    let total = writer.finish()?;
    eprintln!(
        "capture finished: {total} telegrams written to {}",
        to.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// A sink that persists each (filtered) telegram to the capture store.
struct CaptureSink<'a> {
    writer: &'a CaptureWriter,
    filter: Filter,
    counter: Arc<AtomicU64>,
}

impl TelegramSink for CaptureSink<'_> {
    fn on_telegram(&mut self, telegram: &DecodedTelegram, frame: &TimestampedFrame) -> Flow {
        if !self.filter.matches(telegram) {
            return Flow::Continue;
        }
        let record = CaptureRecord::from_decoded(telegram, frame);
        if self.writer.record(record) {
            self.counter.fetch_add(1, Ordering::Relaxed);
            Flow::Continue
        } else {
            // The writer thread stopped (fatal DB error): end the stream.
            tracing::error!("capture writer stopped; ending capture");
            Flow::Stop
        }
    }

    fn on_connect(&mut self, reconnect: bool) -> Flow {
        if reconnect {
            eprintln!("-- reconnected --");
        }
        Flow::Continue
    }

    fn on_disconnect(&mut self, error: &TransportError, backoff: Duration) -> Flow {
        eprintln!(
            "-- connection lost: {error}; retrying in {}s --",
            backoff.as_secs()
        );
        Flow::Continue
    }
}
