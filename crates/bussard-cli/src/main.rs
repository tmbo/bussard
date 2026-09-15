//! `bussard` — an open-source CLI for KNX.
//!
//! Phase 0 wires up the command surface; only `validate` is functional so far.

mod apply_cmd;
mod assign_cmd;
mod capture_cmd;
mod conn_cmd;
mod ha_config_cmd;
mod import_cmd;
mod import_product_cmd;
mod init_cmd;
mod mcp_cmd;
mod monitor_cmd;
mod plan_cmd;
mod read_cmd;
mod reconstruct_cmd;
mod scan_cmd;
mod validate_cmd;
mod write_cmd;

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
    /// Create a fresh model directory: discover the gateway, write the skeleton.
    Init {
        /// The directory to create the model in.
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Use this gateway `host[:port]` instead of discovering one.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Configure KNXnet/IP routing (multicast) instead of tunneling.
        #[arg(long)]
        routing: bool,
    },
    /// Import an existing `.knxproj` (or xknxproject JSON dump) into the model.
    Import {
        /// The `.knxproj` file to import (omit when using `--from-json`).
        #[arg(value_name = "PROJECT", required_unless_present = "from_json")]
        project: Option<PathBuf>,
        /// Import from an xknxproject JSON dump instead of a `.knxproj`.
        #[arg(long, value_name = "FILE", conflicts_with = "project")]
        from_json: Option<PathBuf>,
        /// Project password (else `BUSSARD_PROJECT_PASSWORD`, else prompt).
        #[arg(long)]
        password: Option<String>,
        /// The model directory to write (aligned with every other command).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
    },
    /// Scan a line for devices: mask version, manufacturer, order number.
    Scan {
        /// The line to scan, e.g. `1.1`.
        #[arg(value_name = "LINE", default_value = "1.1")]
        line: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the table format.
        #[arg(long)]
        json: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Assign an individual address to the device in programming mode.
    Assign {
        /// The address to assign, e.g. `1.1.47` (default: next free on the line).
        #[arg(value_name = "ADDRESS")]
        address: Option<String>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Read a device's tables back over the bus and diff them against the model.
    Reconstruct {
        /// The device to read, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the report format.
        #[arg(long)]
        json: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Import vendor product data (`.knxprod`): cache it and generate a model.
    ImportProduct {
        /// The `.knxprod` file to import.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
    },
    /// Read a device's live tables and show what `apply` would change.
    Plan {
        /// The device to plan for, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the report format.
        #[arg(long)]
        json: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Apply the model's link tables to a device (plan, confirm, write, verify).
    Apply {
        /// The device to program, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Validate the YAML model and report diagnostics.
    Validate {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Live-monitor the bus, decoding telegrams against the model.
    Monitor {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON Lines (for tooling) instead of the pretty text format.
        #[arg(long)]
        json: bool,
        /// Only show telegrams matching this filter: a comma-separated list of
        /// GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`) or IAs (`1.1.30`).
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Capture telegrams to a SQLite database.
    Capture {
        /// The database file to write (created if absent).
        #[arg(long, value_name = "DB")]
        to: PathBuf,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Only capture telegrams matching this filter (see `monitor --filter`).
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Read a group value from the bus (sends a GroupValueRead, prints the
    /// typed response; exits non-zero on timeout).
    Read {
        /// The group address to read, e.g. `3/2/0`.
        #[arg(value_name = "GA")]
        ga: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Write a group value to the bus, e.g. `bussard write 3/0/4 down`.
    Write {
        /// The group address to write, e.g. `3/0/4`.
        #[arg(value_name = "GA")]
        ga: String,
        /// The value: `on`/`off`, `up`/`down`, a number, a percentage like `75%`, …
        #[arg(value_name = "VALUE")]
        value: String,
        /// The DPT to encode as (default: the GA's DPT from `groups.yaml`).
        #[arg(long, value_name = "DPT")]
        dpt: Option<String>,
        /// Write even if the GA is marked `protected: true` in the model.
        #[arg(long)]
        force: bool,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Generate the Home Assistant KNX integration YAML from the model.
    HaConfig {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Output file (default: stdout).
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Run the read-only MCP server over stdio.
    Mcp {
        /// The directory containing the model (required for the MCP server).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Passive mode: never transmit on the bus (omits the `knx_read_group`
        /// tool). The server only observes.
        #[arg(long)]
        passive: bool,
        /// Allow bus writes: registers the `knx_write_group` tool. Off by
        /// default. Mutually exclusive with `--passive`.
        #[arg(long, conflicts_with = "passive")]
        allow_writes: bool,
        /// Path to a capture SQLite database to extend `knx_recent_telegrams`
        /// history beyond the in-memory ring window.
        #[arg(long, value_name = "PATH")]
        capture_db: Option<PathBuf>,
    },
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
        Command::Scan {
            line,
            dir,
            json,
            gateway,
            routing,
        } => scan_cmd::run(
            &line,
            &dir,
            json,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Assign {
            address,
            dir,
            gateway,
            routing,
        } => assign_cmd::run(
            address.as_deref(),
            &dir,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Reconstruct {
            address,
            dir,
            json,
            gateway,
            routing,
        } => reconstruct_cmd::run(
            &address,
            &dir,
            json,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::ImportProduct { file, dir } => import_product_cmd::run(&file, &dir),
        Command::Plan {
            address,
            dir,
            json,
            gateway,
            routing,
        } => plan_cmd::run(
            &address,
            &dir,
            json,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Apply {
            address,
            dir,
            yes,
            gateway,
            routing,
        } => apply_cmd::run(
            &address,
            &dir,
            yes,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Validate { dir, format } => validate_cmd::run(&dir, format == Format::Json),
        Command::Init {
            dir,
            gateway,
            routing,
        } => init_cmd::run(&dir, gateway.as_deref(), routing),
        Command::Import {
            project,
            from_json,
            password,
            dir,
        } => {
            if let Some(json) = from_json {
                import_cmd::run_json(&json, &dir)
            } else if let Some(project) = project {
                import_cmd::run_knxproj(&project, &dir, password)
            } else {
                anyhow::bail!("provide a .knxproj path or --from-json <file>")
            }
        }
        Command::Monitor {
            dir,
            json,
            filter,
            gateway,
            routing,
        } => monitor_cmd::run(
            &dir,
            json,
            filter.as_deref(),
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Capture {
            to,
            dir,
            filter,
            gateway,
            routing,
        } => capture_cmd::run(
            &to,
            &dir,
            filter.as_deref(),
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Read {
            ga,
            dir,
            gateway,
            routing,
        } => read_cmd::run(&ga, &dir, conn_cmd::ConnOverrides { gateway, routing }),
        Command::Write {
            ga,
            value,
            dpt,
            force,
            dir,
            gateway,
            routing,
        } => write_cmd::run(
            &ga,
            &value,
            dpt.as_deref(),
            force,
            &dir,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::HaConfig { dir, out } => ha_config_cmd::run(&dir, out.as_deref()),
        Command::Mcp {
            dir,
            gateway,
            routing,
            passive,
            allow_writes,
            capture_db,
        } => mcp_cmd::run(
            &dir,
            conn_cmd::ConnOverrides { gateway, routing },
            passive,
            allow_writes,
            capture_db,
        ),
    }
}
