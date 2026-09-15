//! `bussard` — an open-source CLI for KNX.
//!
//! Phase 0 wires up the command surface; only `validate` is functional so far.

mod validate_cmd;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// bussard: manage a KNX installation as code.
#[derive(Debug, Parser)]
#[command(name = "bussard", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The output format for machine-readable commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable, rustc-style diagnostics.
    Text,
    /// A JSON array.
    Json,
}

/// The top-level subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Import an existing `.knxproj` into the YAML model (not implemented yet).
    Import,
    /// Validate the YAML model and report diagnostics.
    Validate {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Live-monitor the bus (not implemented yet).
    Monitor,
    /// Capture telegrams to SQLite (not implemented yet).
    Capture,
    /// Read a group value from the bus (not implemented yet).
    Read,
    /// Run the read-only MCP server (not implemented yet).
    Mcp,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run(cli.command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatches a subcommand, returning the process exit code on success.
fn run(command: Command) -> anyhow::Result<ExitCode> {
    match command {
        Command::Validate { dir, format } => validate_cmd::run(&dir, format == Format::Json),
        Command::Import => not_implemented("import"),
        Command::Monitor => not_implemented("monitor"),
        Command::Capture => not_implemented("capture"),
        Command::Read => not_implemented("read"),
        Command::Mcp => not_implemented("mcp"),
    }
}

/// Returns a uniform "not implemented yet" error for stubbed subcommands.
fn not_implemented(name: &str) -> anyhow::Result<ExitCode> {
    anyhow::bail!("`{name}` is not implemented yet")
}
