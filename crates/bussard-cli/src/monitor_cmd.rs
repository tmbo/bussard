//! The `bussard monitor` subcommand: stream decoded telegrams to stdout.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{
    CancelToken, DecodedTelegram, Filter, GroupKeyring, json_line, pretty_line,
    run_stream_secured_cancellable,
};
use bussard_transport::{TimestampedFrame, TransportError};

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{load_model_optional, resolve_config};

/// `bussard monitor`.
#[derive(Debug, clap::Args)]
pub(crate) struct MonitorArgs {
    /// Only show telegrams matching this filter: a comma-separated list of
    /// GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`) or IAs (`1.1.30`).
    #[arg(long, value_name = "EXPR")]
    filter: Option<String>,
}

impl Run for MonitorArgs {
    fn spec(&self) -> Spec {
        Spec::BUS.json()
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(self.filter.as_deref(), g)
    }
}

/// Runs `bussard monitor`.
fn run(filter_expr: Option<&str>, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (dir, json, keyring, overrides) = (g.dir(), g.json, g.keyring(), g.group());
    let filter = match filter_expr {
        Some(expr) => Filter::parse(expr)?,
        None => Filter::default(),
    };
    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;
    // KNX Data Secure group telegrams (issue #172): decrypt with the keyring's
    // group keys. Loaded before connecting so a wrong password fails fast.
    let group_keys = keyring
        .map(|path| {
            bussard_service::secure::load_group_keys(path)
                .with_context(|| format!("loading group keys from {}", path.display()))
        })
        .transpose()?
        .map(|keys| {
            eprintln!(
                "keyring: {} group key(s) for secured group telegrams",
                keys.len()
            );
            GroupKeyring::new(keys)
        });

    // A dedicated multi-thread runtime; the transport and (later) store need it.
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let mut sink = PrintSink::new(json, filter);
        // On Ctrl-C, *cancel* the stream (which closes the bus connection
        // cleanly, releasing the gateway tunnel slot) rather than dropping it
        // mid-flight — see issue #31.
        let (cancel, cancel_watch) = CancelToken::new();
        let ctrl_c_cancel = cancel.clone();
        let signal = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                // Print a newline so the shell prompt is clean after ^C.
                eprintln!();
                tracing::info!("interrupted; shutting down monitor");
                ctrl_c_cancel.cancel();
            }
        });
        let res = run_stream_secured_cancellable(
            &config,
            model.as_ref(),
            &mut sink,
            group_keys,
            cancel_watch,
        )
        .await;
        // Stop the signal task (its own future is cheap to drop; the stream has
        // already closed the connection cleanly on cancel).
        signal.abort();
        res.map_err(anyhow::Error::from)?;
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
            crate::output::with_schema_line(crate::output::schema::MONITOR, &json_line(telegram))
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
