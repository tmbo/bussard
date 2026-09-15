//! The `bussard monitor` subcommand: stream decoded telegrams to stdout.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{DecodedTelegram, Filter, json_line, pretty_line, run_stream};
use bussard_transport::{TimestampedFrame, TransportError};

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

/// Runs `bussard monitor`.
pub fn run(
    dir: &Path,
    json: bool,
    filter_expr: Option<&str>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let filter = match filter_expr {
        Some(expr) => Filter::parse(expr)?,
        None => Filter::default(),
    };
    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;

    // A dedicated multi-thread runtime; the transport and (later) store need it.
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let mut sink = PrintSink::new(json, filter);
        tokio::select! {
            res = run_stream(&config, model.as_ref(), &mut sink) => {
                res.map_err(anyhow::Error::from)?;
            }
            _ = tokio::signal::ctrl_c() => {
                // Print a newline so the shell prompt is clean after ^C.
                eprintln!();
                tracing::info!("interrupted; shutting down monitor");
            }
        }
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(ExitCode::SUCCESS)
}

/// A sink that prints each telegram to stdout, honouring the filter and format.
struct PrintSink {
    json: bool,
    filter: Filter,
    color: bool,
}

impl PrintSink {
    fn new(json: bool, filter: Filter) -> Self {
        // Colour only for the pretty format on a TTY without NO_COLOR.
        let color =
            !json && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
        PrintSink {
            json,
            filter,
            color,
        }
    }
}

impl TelegramSink for PrintSink {
    fn on_telegram(&mut self, telegram: &DecodedTelegram, _frame: &TimestampedFrame) -> Flow {
        if !self.filter.matches(telegram) {
            return Flow::Continue;
        }
        let line = if self.json {
            json_line(telegram)
        } else {
            pretty_line(telegram, self.color)
        };
        // A write failure (closed pipe) ends the stream cleanly.
        let mut stdout = std::io::stdout().lock();
        if writeln!(stdout, "{line}").is_err() {
            return Flow::Stop;
        }
        Flow::Continue
    }

    fn on_connect(&mut self, reconnect: bool) -> Flow {
        if reconnect {
            tracing::info!("reconnected to the bus; resuming monitor");
            eprintln!("-- reconnected --");
        }
        Flow::Continue
    }

    fn on_disconnect(&mut self, error: &TransportError, backoff: Duration) -> Flow {
        tracing::warn!("connection lost: {error}; retrying in {:?}", backoff);
        eprintln!(
            "-- connection lost: {error}; retrying in {}s --",
            backoff.as_secs()
        );
        Flow::Continue
    }
}
