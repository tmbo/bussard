//! `bussard` — an open-source CLI for KNX.
//!
//! Each subcommand lives in its own `*_cmd` module and is dispatched from `main`.

mod adopt_cmd;
mod apply_cmd;
mod assign_cmd;
mod capture_cmd;
mod conn_cmd;
mod flash_cmd;
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

/// How `bussard flash` verifies each memory write's read-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum VerifyModeArg {
    /// Read each 12-byte chunk back immediately after writing it (2 numbered
    /// messages per chunk). The conservative real-device default: a dropped or
    /// truncated chunk fails at that chunk, before more is streamed on top.
    #[default]
    PerChunk,
    /// Write the whole segment first, then read it all back and verify once.
    /// Roughly halves the flash's memory round-trips (and is the #50 KV stall
    /// discriminator), at the cost of catching a corrupt write only at the
    /// end-of-segment verify. The first mismatching address is still reported.
    Batched,
}

impl From<VerifyModeArg> for bussard_mgmt::VerifyMode {
    fn from(v: VerifyModeArg) -> Self {
        match v {
            VerifyModeArg::PerChunk => bussard_mgmt::VerifyMode::PerChunk,
            VerifyModeArg::Batched => bussard_mgmt::VerifyMode::Batched,
        }
    }
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
        /// The first device number to probe (0–255).
        #[arg(long, value_name = "N", default_value_t = 0)]
        from: u8,
        /// The last device number to probe (0–255).
        #[arg(long, value_name = "N", default_value_t = 255)]
        to: u8,
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
    /// Read a device's tables back over the bus and diff them against the model,
    /// or (with `--line`) sweep a whole line and synthesize a fresh model.
    Reconstruct {
        /// The single device to read, e.g. `1.1.4` (mutually exclusive with
        /// `--line`).
        #[arg(value_name = "ADDRESS", required_unless_present = "line")]
        address: Option<String>,
        /// Sweep a whole line, e.g. `1.1`, and synthesize a fresh model from
        /// every System B device's tables (requires `--out`).
        #[arg(long, value_name = "LINE", conflicts_with = "address")]
        line: Option<String>,
        /// The first device number to probe in line mode (0–255).
        #[arg(long, value_name = "N", default_value_t = 0, requires = "line")]
        from: u8,
        /// The last device number to probe in line mode (0–255).
        #[arg(long, value_name = "N", default_value_t = 255, requires = "line")]
        to: u8,
        /// Line mode only: the fresh model directory to synthesize into. Must be
        /// absent or empty — reconstruction never merges into an existing model.
        #[arg(long, value_name = "DIR", requires = "line")]
        out: Option<PathBuf>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        /// In line mode this only supplies connection defaults.
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the report format.
        #[arg(long)]
        json: bool,
        /// L4 SOAK PROBE (hidden diagnostic): connect ONCE to ADDRESS and issue N
        /// harmless descriptor reads on that single connection, reporting progress
        /// every 10 and the exact exchange count reached plus the error when the
        /// connection dies. This characterises a peer's per-connection exchange
        /// budget empirically — KNX Virtual drops the L4 connection after a
        /// varying number of exchanges (issue #52); this measures it so
        /// `flash --reconnect-every` can be set comfortably below it. Read-only on
        /// the bus. Requires ADDRESS; ignores `--line`/`--out`.
        #[arg(long, value_name = "N", hide = true, conflicts_with = "line")]
        l4_soak: Option<u32>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Import vendor product data (`.knxprod`): cache it and generate a model.
    ///
    /// Give a local `.knxprod` FILE, or `--order-number` to look the file up in
    /// the pointer index and download it from the vendor, or `--list` to show
    /// the index.
    ImportProduct {
        /// The `.knxprod` file to import (positional mode).
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Look the `.knxprod` up in the pointer index by order number and
        /// download it from the vendor (with confirmation).
        #[arg(long, value_name = "ORDER", conflicts_with = "file")]
        order_number: Option<String>,
        /// Skip the download confirmation prompt (assume yes). Only meaningful
        /// with `--order-number`.
        #[arg(long)]
        yes_download: bool,
        /// List the product-data pointer index and exit.
        #[arg(long, conflicts_with_all = ["file", "order_number"])]
        list: bool,
    },
    /// Guide a new device from programming mode into the model (assign +
    /// product data + links scaffolding).
    Adopt {
        /// The vendor `.knxprod` for the new device (else the cached model is used).
        #[arg(long, value_name = "FILE")]
        product: Option<PathBuf>,
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
    /// Flash an application program from vendor product data into a device.
    Flash {
        /// The device to program, e.g. `1.0.10`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The vendor `.knxprod` containing the application program.
        #[arg(long, value_name = "FILE")]
        product: PathBuf,
        /// The application program id (default: sole/matching application).
        #[arg(long, value_name = "REF", conflicts_with = "order_number")]
        application: Option<String>,
        /// Select the application program by hardware order number (e.g.
        /// `AKK-0216.03`) instead of a raw application ref. Resolved through the
        /// product's hardware catalogue; exactly one match is required.
        #[arg(long, value_name = "ORDER")]
        order_number: Option<String>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Accept a device that reports Loaded (instead of the conformant
        /// Loading) right after StartLoading. Off by default so real-device
        /// behaviour stays strict; intended for KNX Virtual, which snaps to
        /// Loaded and would otherwise fail on the first allocation.
        #[arg(long)]
        tolerate_nonconformant_load_states: bool,
        /// How memory writes are verified. `per-chunk` (default) reads each
        /// 12-byte chunk back right after writing it — conservative, the real-
        /// device behaviour. `batched` writes the whole segment first and reads it
        /// all back once, roughly halving the flash's memory round-trips (and
        /// serving as the #50 KV stall discriminator).
        #[arg(long, value_enum, default_value_t = VerifyModeArg::PerChunk)]
        verify: VerifyModeArg,
        /// Sleep N milliseconds between memory frames. Real gateways throttle
        /// the download to TP1 speed by themselves; simulators (KNX Virtual)
        /// ACK at loopback speed and can wedge under the burst — 25-50 is a
        /// TP1-like rate.
        #[arg(long, value_name = "MS")]
        pace: Option<u64>,
        /// Window the download across graceful connection windows: after ~N
        /// numbered exchanges, gracefully T_Disconnect, reconnect (fresh sequence
        /// window) and resume where the procedure left off. Off by default. Load
        /// states are persistent object state (not connection state), so this
        /// lands in the same device state as one unbroken run and is robust
        /// against a peer that drops the connection at a varying (sometimes very
        /// shallow) depth (e.g. KNX Virtual, issue #52). Cycling happens both
        /// between steps AND inside a long memory write (resuming at the current
        /// offset — writes are absolute-addressed and stateless), and an unexpected
        /// mid-write drop is auto-retried from the last-confirmed offset. Suggested
        /// N: comfortably below the peer's per-connection budget (probe it with
        /// `reconstruct <ia> --l4-soak <N>`). KV drops as early as 7 exchanges, so
        /// a SMALL window like 4-5 with the built-in retry is the safe choice.
        #[arg(long, value_name = "N")]
        reconnect_every: Option<u32>,
        /// Consecutive window-retries without forward progress to allow on an
        /// unexpected mid-write connection drop before giving up (default 8). Any
        /// newly-confirmed byte resets the count, so a peer making progress between
        /// drops retries indefinitely; a peer that never lands a byte fails after
        /// this many tries instead of looping forever. Only meaningful with
        /// --reconnect-every.
        #[arg(long, value_name = "N")]
        max_window_retries: Option<u32>,
        /// The device's BCU access key, in hex (e.g. `FFFFFFFF` or `0x11223344`),
        /// presented with A_Authorize on every management connect (issue #52).
        /// Unset presents the free-access key (FFFFFFFF) — correct for an unkeyed
        /// device (ETS uses free access by default). A keyed device needs its
        /// project key here or it will deny access.
        #[arg(long, value_name = "HEX")]
        bcu_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
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
    // Temporary speed telemetry: every invocation reports its wall time on
    // stderr. Speed is a core project goal; this keeps regressions visible
    // during development and will be removed (or demoted to --timing) later.
    let started = std::time::Instant::now();
    let code = match run(cli.command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    };
    eprintln!("took {:.2?}", started.elapsed());
    code
}

/// Dispatches a subcommand, returning the process exit code on success.
fn run(command: Command) -> anyhow::Result<ExitCode> {
    match command {
        Command::Scan {
            line,
            from,
            to,
            dir,
            json,
            gateway,
            routing,
        } => scan_cmd::run(
            &line,
            from,
            to,
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
            line,
            from,
            to,
            out,
            dir,
            json,
            l4_soak,
            gateway,
            routing,
        } => {
            let overrides = conn_cmd::ConnOverrides { gateway, routing };
            match (line, l4_soak) {
                (_, Some(exchanges)) => {
                    // clap requires ADDRESS unless --line, and --l4-soak conflicts
                    // with --line, so ADDRESS is present here.
                    let address = address.expect("clap requires ADDRESS with --l4-soak");
                    reconstruct_cmd::run_l4_soak(&address, exchanges, &dir, overrides)
                }
                (Some(line), None) => reconstruct_cmd::run_line(
                    &line,
                    from,
                    to,
                    out.as_deref(),
                    &dir,
                    json,
                    overrides,
                ),
                (None, None) => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    reconstruct_cmd::run(&address, &dir, json, overrides)
                }
            }
        }
        Command::ImportProduct {
            file,
            dir,
            order_number,
            yes_download,
            list,
        } => import_product_cmd::run(
            file.as_deref(),
            &dir,
            order_number.as_deref(),
            yes_download,
            list,
        ),
        Command::Adopt {
            product,
            dir,
            gateway,
            routing,
        } => adopt_cmd::run(
            product.as_deref(),
            &dir,
            conn_cmd::ConnOverrides { gateway, routing },
        ),
        Command::Flash {
            address,
            product,
            application,
            order_number,
            dir,
            yes,
            tolerate_nonconformant_load_states,
            verify,
            pace,
            reconnect_every,
            max_window_retries,
            bcu_key,
            gateway,
            routing,
        } => flash_cmd::run(
            &address,
            &product,
            application.as_deref(),
            order_number.as_deref(),
            &dir,
            yes,
            tolerate_nonconformant_load_states,
            verify.into(),
            pace,
            reconnect_every,
            max_window_retries,
            bcu_key.as_deref(),
            conn_cmd::ConnOverrides { gateway, routing },
        ),
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
