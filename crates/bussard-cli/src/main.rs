//! `bussard` — an open-source CLI for KNX.
//!
//! Each subcommand lives in its own `*_cmd` module and is dispatched from `main`.

mod adopt_cmd;
mod apply_cmd;
mod assign_cmd;
mod audit_cmd;
mod backup_cmd;
mod capture_cmd;
mod commission_cmd;
mod conn_cmd;
mod describe_cmd;
mod diff_cmd;
mod doc_cmd;
mod export_cmd;
mod export_groups_cmd;
mod flash_cmd;
mod flash_dump;
mod ha_config_cmd;
mod history_cmd;
mod import_bundle;
mod import_cmd;
mod import_product_cmd;
mod init_cmd;
mod keyring_cmd;
mod learn_cmd;
mod line_cmd;
mod mcp_cmd;
mod monitor_cmd;
mod plan_cmd;
mod read_cmd;
mod reconstruct_cmd;
mod replace_cmd;
mod restore_cmd;
mod scaffold_cmd;
mod scan_cmd;
mod secure_key;
mod test_cmd;
mod validate_cmd;
mod viz_cmd;
mod write_cmd;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// bussard: manage a KNX installation as code.
#[derive(Debug, Parser)]
#[command(name = "bussard", version, about, long_about = None)]
struct Cli {
    /// Increase log verbosity: `-v` = info, `-vv` = debug, `-vvv` = trace.
    /// An explicit `RUST_LOG` overrides this. Default (no flag) is `warn`.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Print the invocation's wall-clock time to stderr on exit.
    #[arg(long, global = true)]
    timing: bool,
    #[command(subcommand)]
    command: Command,
}

/// Maps a `-v` repeat count to a tracing `EnvFilter` directive string, unless an
/// explicit `RUST_LOG` is set (which always wins). `0` → `warn` (the default).
fn verbosity_filter(verbose: u8) -> tracing_subscriber::EnvFilter {
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
        return filter;
    }
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::EnvFilter::new(level)
}

/// The output format for machine-readable commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable, rustc-style diagnostics.
    Text,
    /// A JSON array.
    Json,
}

/// The group-address addressing scheme, as a CLI value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SchemeArg {
    /// `main` = floor, `middle` = trade.
    FloorTradeBlock,
    /// `main` = trade, `middle` = floor.
    FunctionFloor,
}

impl From<SchemeArg> for bussard_model::Scheme {
    fn from(value: SchemeArg) -> Self {
        match value {
            SchemeArg::FloorTradeBlock => bussard_model::Scheme::FloorTradeBlock,
            SchemeArg::FunctionFloor => bussard_model::Scheme::FunctionFloor,
        }
    }
}

/// The rendered format for `bussard doc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DocOutputFormat {
    /// Markdown, one `.md` file per section.
    Md,
    /// Self-contained HTML, one `.html` file per section.
    Html,
}

impl From<DocOutputFormat> for bussard_model::DocFormat {
    fn from(value: DocOutputFormat) -> Self {
        match value {
            DocOutputFormat::Md => bussard_model::DocFormat::Markdown,
            DocOutputFormat::Html => bussard_model::DocFormat::Html,
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
    /// Import a `.knxproj`, a `.bussard` bundle or an xknxproject JSON dump.
    Import {
        /// The `.knxproj` or `.bussard` file to import (omit with `--from-json`).
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
        /// On a re-import, keep this model's value for every hand-edited
        /// conflict and exit 0.
        #[arg(long, conflicts_with_all = ["theirs", "interactive"])]
        mine: bool,
        /// On a re-import, take the incoming value for every hand-edited conflict.
        #[arg(long, conflicts_with = "interactive")]
        theirs: bool,
        /// On a re-import, ask per conflict (needs a terminal).
        #[arg(long)]
        interactive: bool,
    },
    /// Write the model and its history as one `.bussard` file to hand over.
    Export {
        /// The bundle to write (default: next to the model directory, named
        /// after it and today's date).
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Leave the `.bussard/history` snapshots out.
        #[arg(long)]
        no_history: bool,
        /// Print the path and manifest as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain what changes between two projects, as plain sentences.
    Diff {
        /// The first side: a `.knxproj`, a `.bussard` bundle, an xknxproject
        /// `.json` dump or a model directory.
        #[arg(value_name = "A")]
        a: PathBuf,
        /// The second side, in any of the same forms.
        #[arg(value_name = "B")]
        b: PathBuf,
        /// Emit the change set as JSON.
        #[arg(long, conflicts_with = "raw")]
        json: bool,
        /// Print a file-level YAML diff instead of sentences.
        #[arg(long)]
        raw: bool,
        /// Project password for both sides (else `BUSSARD_PROJECT_PASSWORD`).
        #[arg(long)]
        password: Option<String>,
        /// Project password for the second side, when it differs.
        #[arg(long)]
        password_b: Option<String>,
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
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
    },
    /// Assign an individual address to the device in programming mode.
    Assign {
        /// The address to assign, e.g. `1.1.47` (default: next free on the line).
        #[arg(value_name = "ADDRESS")]
        address: Option<String>,
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
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
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
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
    },
    /// Introspect a device: enumerate its interface objects and each property's
    /// description (PID, type, element count, access levels) over the bus.
    Describe {
        /// The device to introspect, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the table format.
        #[arg(long)]
        json: bool,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #71). Required for a security-activated device; the keyring
        /// password comes from `BUSSARD_KEYRING_PASSWORD`, never a CLI argument.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
    },
    /// Inspect a KNX Secure keyring (`.knxkeys`): list the devices, interfaces
    /// and group addresses it carries (issue #71). Key material is NEVER printed.
    ///
    /// The keyring password is read from the `BUSSARD_KEYRING_PASSWORD`
    /// environment variable (mirroring `BUSSARD_PROJECT_PASSWORD`), never a CLI
    /// argument (spec §2.2).
    Keyring {
        /// The `.knxkeys` file to inspect.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Emit JSON instead of the text summary.
        #[arg(long)]
        json: bool,
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
        /// When the `.knxprod` is a ZIP wrapping several inner `.knxprod` files,
        /// select which one to import (by entry or file name). Ignored for a
        /// plain `.knxprod` or a single-inner wrapper.
        #[arg(long, value_name = "NAME")]
        inner: Option<String>,
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
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
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
        /// Flash a device that is NOT factory-fresh (issue #79). A flash takes no
        /// backup, so a device that already carries a different application is
        /// refused by default; this overrides that refusal and destroys the
        /// resident application, its parameters and its links. Re-flashing the
        /// same application does not need it.
        #[arg(long)]
        force: bool,
        /// Re-stream every object. By default an object whose resident image
        /// already matches (MCB size and CRC, object `Loaded`) is skipped when
        /// re-flashing the same application, so a parameter-only change does
        /// not re-download the code segment.
        #[arg(long)]
        full: bool,
        /// Skip the factory reset before the download. By default a System B
        /// flash that writes filled segments sparsely, or that replaces a device
        /// that is not factory-fresh, first sends a confirmed master reset (erase
        /// code 7): the device erases its application, parameters and links and
        /// keeps its individual address, so no octet of a previous image survives
        /// where the new one writes nothing (issue #117). Use this only when you
        /// know the device holds no stale image.
        #[arg(long)]
        no_factory_reset: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
        /// The device's BCU access key, in hex (e.g. `FFFFFFFF` or `0x11223344`),
        /// presented with A_Authorize on every management connect (issue #52).
        /// Unset presents the free-access key (FFFFFFFF) — correct for an unkeyed
        /// device (ETS uses free access by default). A keyed device needs its
        /// project key here or it will deny access.
        #[arg(long, value_name = "HEX")]
        bcu_key: Option<String>,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #71). Required for a security-activated device; the keyring
        /// password comes from `BUSSARD_KEYRING_PASSWORD`, never a CLI argument.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Emit the pre-flight plan as JSON (including the `parameters` array)
        /// instead of the human report.
        #[arg(long)]
        json: bool,
        /// Plan offline and stop: no gateway is resolved and no connection is
        /// opened. The plan is checked against the application's own mask.
        #[arg(long)]
        dry_run: bool,
        /// With `--dry-run`, write `plan.json` and the exact memory images the
        /// flash would stream (one `.bin` each, plus the table images) into DIR.
        #[arg(long, value_name = "DIR", requires = "dry_run")]
        dump_images: Option<PathBuf>,
    },
    /// Read a device's live tables and show what `apply` would change, or (with
    /// `--line`) plan every model device on a whole line.
    Plan {
        /// The device to plan for, e.g. `1.1.4` (mutually exclusive with
        /// `--line`).
        #[arg(value_name = "ADDRESS", required_unless_present = "line")]
        address: Option<String>,
        /// Plan every device the model has on this line, e.g. `1.1`, in address
        /// order, and print one summary table (issue #100).
        #[arg(long, value_name = "LINE", conflicts_with = "address")]
        line: Option<String>,
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
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
    },
    /// Apply the model's link tables to a device (plan, confirm, write, verify),
    /// or (with `--line`) to every model device on a whole line.
    Apply {
        /// The device to program, e.g. `1.1.4` (mutually exclusive with
        /// `--line`).
        #[arg(value_name = "ADDRESS", required_unless_present = "line")]
        address: Option<String>,
        /// Apply to every device the model has on this line, e.g. `1.1`, in
        /// address order: one confirmation for the run, one summary table, and a
        /// resumable state file (issue #100).
        #[arg(long, value_name = "LINE", conflicts_with = "address")]
        line: Option<String>,
        /// Line mode only: emit the JSON summary instead of the table.
        #[arg(long, requires = "line")]
        json: bool,
        /// Line mode only: continue the run recorded in
        /// `<dir>/captures/apply-line-<line>.json`, skipping the devices it
        /// already finished.
        #[arg(long, requires = "line")]
        resume: bool,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #71). Required for a security-activated device; the keyring
        /// password comes from `BUSSARD_KEYRING_PASSWORD`, never a CLI argument.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
    },
    /// Bench mode: walk the model's devices on a line, prompt for each device's
    /// programming button, verify its order number, assign its address, and
    /// print a label (issue #100).
    Commission {
        /// The line to commission, e.g. `1.1`.
        #[arg(long, value_name = "LINE")]
        line: String,
        /// Also flash each device's application program after assigning it.
        #[arg(long)]
        flash: bool,
        /// Also apply the model's link tables after assigning (and flashing).
        #[arg(long)]
        apply: bool,
        /// Append one label row per commissioned device to this CSV file
        /// (columns `address;name;order_number;floor;room`).
        #[arg(long, value_name = "FILE")]
        labels: Option<PathBuf>,
        /// The vendor `.knxprod` to flash from. Without it, `--flash` searches
        /// `<dir>/vendor/` for an archive carrying the device's order number.
        #[arg(long, value_name = "FILE", requires = "flash")]
        product: Option<PathBuf>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Emit the JSON summary instead of the table.
        #[arg(long)]
        json: bool,
        /// The ETS `.knxkeys` keyring holding each target's KNX Data Secure tool
        /// key (issue #71), used by `--flash` and `--apply`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch. Prefer `--keyring` for a real installation.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
    },
    /// Show what has changed in the model since the last history snapshot.
    Status {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit the change set as JSON instead of sentences.
        #[arg(long)]
        json: bool,
        /// Print the file-level diff instead of the plain-language rendering.
        #[arg(long)]
        raw: bool,
    },
    /// List the model's history snapshots, oldest first.
    History {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit the list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show what one snapshot changed (or the change between two snapshots).
    Show {
        /// The snapshot: its id, or its number from `bussard history`.
        #[arg(value_name = "SNAPSHOT")]
        snapshot: String,
        /// A second snapshot: show the change from the first one to this one.
        #[arg(value_name = "SNAPSHOT")]
        to: Option<String>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
    },
    /// Put the model files back to a history snapshot (files only, no devices).
    Undo {
        /// The snapshot to restore: its id, or its number from `bussard history`
        /// (default: the newest one that differs from the working files, which
        /// reverts the last change).
        #[arg(value_name = "SNAPSHOT")]
        snapshot: Option<String>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
    },
    /// Snapshot every device in the installation: tables, and where bussard can
    /// bound the read, the writable parameter memory (issue #96).
    ///
    /// Read-only on the bus. Writes one JSON file per device plus a
    /// `manifest.json` that lists every device considered, including the ones
    /// whose mask bussard cannot read.
    Backup {
        /// Back up only these devices, e.g. `1.1.4 1.1.7` (default: every device
        /// in the model).
        #[arg(value_name = "ADDRESS")]
        addresses: Vec<String>,
        /// Back up only the model devices on this line, e.g. `1.1`.
        #[arg(long, value_name = "LINE", conflicts_with = "addresses")]
        line: Option<String>,
        /// Where to write the snapshot (default:
        /// `<dir>/captures/backups/<UTC timestamp>/`).
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit the manifest as JSON instead of the text summary.
        #[arg(long)]
        json: bool,
        /// The ETS `.knxkeys` keyring holding the targets' KNX Data Secure tool
        /// keys (issue #71). The keyring password comes from
        /// `BUSSARD_KEYRING_PASSWORD`, never a CLI argument.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
    },
    /// Write a device's backed-up link tables back onto it (issue #96).
    ///
    /// Runs the same plan, confirm, back up, write and verify path as `apply`,
    /// with the backup as the desired state instead of the model.
    Restore {
        /// The backup directory: a `bussard backup` run, or
        /// `<dir>/captures/backups` for the per-device snapshots `apply` leaves.
        #[arg(value_name = "BACKUP_DIR")]
        backup_dir: PathBuf,
        /// The device to restore, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #71).
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
    },
    /// Replace a dead device: assign, flash, apply and record, in one guided
    /// flow with one confirmation (issue #98).
    Replace {
        /// The address of the device being replaced, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The vendor `.knxprod` for the replacement device.
        #[arg(long, value_name = "FILE")]
        product: PathBuf,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Proceed although the old device still answers, or although the
        /// pressed device's order number, mask or application does not match the
        /// model's device file.
        #[arg(long)]
        force: bool,
        /// Assign and apply, but leave the application image alone — for a spare
        /// that already carries the right application.
        #[arg(long)]
        no_flash: bool,
        /// The device's BCU access key, in hex, presented with A_Authorize on
        /// every management connect (issue #52).
        #[arg(long, value_name = "HEX")]
        bcu_key: Option<String>,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #71).
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
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
    /// Draft a group-address plan from a room and function list.
    Scaffold {
        /// The plan file: `rooms: [{floor, room, functions: [...]}]`.
        #[arg(value_name = "PLAN")]
        plan: PathBuf,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// The addressing scheme (default: `lint.groups.scheme`, else floor-trade-block).
        #[arg(long, value_enum)]
        scheme: Option<SchemeArg>,
        /// Write to this file instead of `<dir>/groups.yaml`.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Emit JSON instead of the table format.
        #[arg(long)]
        json: bool,
        /// Do not add a matching `lint:` block to `bussard.yaml`.
        #[arg(long)]
        no_lint_config: bool,
    },
    /// Export the group-address plan in a format ETS can import.
    ExportGroups {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// The export format.
        #[arg(long, value_enum)]
        format: export_groups_cmd::ExportFormat,
        /// The file to write.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Render the handover documentation folder from the model.
    Doc {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// The directory to write the rendered documentation into.
        #[arg(long, default_value = "docs/installation")]
        out: PathBuf,
        /// The rendered format.
        #[arg(long, value_enum, default_value_t = DocOutputFormat::Md)]
        format: DocOutputFormat,
        /// Print the structured document model as JSON instead of writing files.
        #[arg(long)]
        json: bool,
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
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Permit a write to a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
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
    /// Serve the KNX visualization website (topology, GA tree, live traffic).
    Viz {
        /// The address to bind the HTTP server to.
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Watch for devices in KNX programming mode and highlight them in the
        /// UI. This periodically broadcasts `A_IndividualAddress_Read` on the
        /// bus (active traffic), so it is off by default and must be enabled
        /// explicitly — never point it at a real installation unattended.
        #[arg(long)]
        watch_prog: bool,
        /// Arm `POST /api/group-write`, so the page can send test writes. Off
        /// by default: a bare `bussard viz` is a viewer and the endpoint
        /// answers 403.
        #[arg(long)]
        allow_writes: bool,
        /// Permit a non-loopback (real) gateway when this server may transmit
        /// (`--allow-writes` or `--watch-prog`). Same gate as `bussard write`
        /// (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
        /// Also answer requests whose `Host` is this name. Repeatable. Loopback
        /// names and bare IP literals are always accepted; any other name is
        /// refused because it is how DNS rebinding reaches this port.
        #[arg(long, value_name = "HOST")]
        allow_host: Vec<String>,
    },
    /// Name and type group addresses from live traffic (never transmits).
    Learn {
        /// Learn this group address (repeatable). Without it, `--unnamed` /
        /// `--untyped` pick targets from the model, and a bare `learn` takes
        /// whatever appears on the bus.
        #[arg(long = "ga", value_name = "GA")]
        gas: Vec<String>,
        /// Learn every group address in the model whose name is a placeholder.
        #[arg(long)]
        unnamed: bool,
        /// Learn every group address in the model that has no DPT.
        #[arg(long)]
        untyped: bool,
        /// Accept the top DPT candidate and the proposed name without asking
        /// (for scripted sessions).
        #[arg(long)]
        yes: bool,
        /// How long to wait for each telegram, in seconds.
        #[arg(long, value_name = "SECS", default_value_t = 30)]
        timeout: u64,
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
    /// Run the scripted acceptance tests in `tests.yaml` against the bus.
    Test {
        /// The test file to run (default: `<dir>/tests.yaml`).
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
        /// Emit the report as JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Together with `allow_protected: true` in the file, permit tests that
        /// write to a protected group address.
        #[arg(long)]
        force: bool,
        /// Report `manual:` steps as skipped instead of carrying them out.
        #[arg(long)]
        skip_manual: bool,
        /// Run only the named test (repeatable).
        #[arg(long, value_name = "NAME")]
        only: Vec<String>,
        /// Skip the confirmation prompt (required for a non-TTY run).
        #[arg(long)]
        yes: bool,
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Permit a run against a non-loopback (real) gateway. Required for any
        /// gateway that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
    },
    /// Audit the installation: model gaps, one-sided links, what bussard can do
    /// per device mask, KNX Secure coverage; with `--live`, the gateway's tunnel
    /// slots, a traffic sample and a scan of the modelled devices. Read-only.
    Audit {
        /// The directory containing the model (`bussard.yaml`, `groups.yaml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit one JSON object instead of the sectioned text report.
        #[arg(long)]
        json: bool,
        /// Add the live part: gateway description, traffic sample and a probe of
        /// every modelled device. Read tier only; never sends a group telegram.
        #[arg(long)]
        live: bool,
        /// Traffic-sample window in seconds for `--live`.
        #[arg(long, value_name = "SECS", default_value_t = 30, requires = "live")]
        window: u64,
        /// An ETS `.knxkeys` keyring to check Secure devices against (password in
        /// `BUSSARD_KEYRING_PASSWORD`). Key material is never printed.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
        /// Skip the pre-flight check that no bus device answers at bussard's own
        /// source individual address.
        ///
        /// That check is what stops two management clients sharing one source
        /// address, which interleaves their numbered telegrams inside a single
        /// layer-4 session at the device and can silently corrupt a download.
        /// Only pass this for a gateway that misbehaves on the probe itself.
        #[arg(long)]
        skip_address_check: bool,
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
        /// Programming tier: registers `knx_plan_device` and
        /// `knx_apply_device`, which write one device's link tables after a
        /// plan the human approved (issue #118). Off by default. Mutually
        /// exclusive with `--passive`; a non-loopback gateway also needs
        /// `--allow-remote-gateway` or BUSSARD_ALLOW_REAL_GATEWAY=1.
        #[arg(long, conflicts_with = "passive")]
        allow_programming: bool,
        /// How many minutes a `knx_plan_device` digest stays valid for
        /// `knx_apply_device`.
        #[arg(
            long,
            value_name = "MINUTES",
            default_value_t = 10,
            requires = "allow_programming"
        )]
        plan_ttl_minutes: u64,
        /// Permit `--allow-writes` or `--allow-programming` against a
        /// non-loopback (real) gateway. Same gate as `bussard write` (or set
        /// BUSSARD_ALLOW_REAL_GATEWAY=1).
        #[arg(long)]
        allow_remote_gateway: bool,
        /// Refuse model edits: omits the `knx_set_group`, `knx_add_link`,
        /// `knx_remove_link`, `knx_set_device`, `knx_set_parameter`, `knx_undo`
        /// and `knx_scaffold_groups` tools. The read tools stay available. Model edits only
        /// touch YAML files (never the bus), so they are on by default.
        #[arg(long)]
        no_model_edits: bool,
        /// Path to a capture SQLite database to extend `knx_recent_telegrams`
        /// history beyond the in-memory ring window.
        #[arg(long, value_name = "PATH")]
        capture_db: Option<PathBuf>,
    },
}

/// Stack size for the thread that runs the CLI body.
///
/// Windows gives the main thread a 1 MiB stack. In debug builds clap's derive
/// parser plus the large async state machines each command `block_on`s exceed
/// that, so every command (even `bussard` with no arguments) died with
/// "thread 'main' has overflowed its stack". A spawned thread gets an explicit,
/// generous stack on every platform; it is reserved virtual memory, so the
/// unused part costs nothing.
const MAIN_THREAD_STACK_BYTES: usize = 64 * 1024 * 1024;

fn main() -> ExitCode {
    let body = std::thread::Builder::new()
        .name("bussard-main".to_owned())
        .stack_size(MAIN_THREAD_STACK_BYTES)
        .spawn(cli_main);
    match body.map(|handle| handle.join()) {
        Ok(Ok(code)) => code,
        // The panic message was already printed by the panic hook.
        Ok(Err(_panic)) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: cannot start the bussard main thread: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The whole CLI: parse arguments, set up logging, run the subcommand. Runs on
/// the `bussard-main` thread spawned by [`main`].
fn cli_main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(verbosity_filter(cli.verbose))
        .with_writer(std::io::stderr)
        .init();

    // Opt-in wall-clock telemetry (issue #78): `--timing` reports the
    // invocation's elapsed time on stderr. Speed is a project goal, so this stays
    // available for regression spotting, but a plain 0.1.0 run is quiet.
    let started = std::time::Instant::now();
    let code = match run(cli.command, cli.verbose) {
        Ok(code) if code == ExitCode::SUCCESS => code,
        Ok(code) => no_free_tunnel_or(code),
        // A gateway with no free tunnel slot gets its own message and exit code
        // (issue #105); it is a capacity refusal, not a generic failure.
        Err(err) if is_no_free_tunnel(&err) => {
            eprintln!("{}", conn_cmd::no_free_tunnel_message("the gateway"));
            ExitCode::from(conn_cmd::EXIT_NO_FREE_TUNNEL)
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            no_free_tunnel_or(ExitCode::FAILURE)
        }
    };
    if cli.timing {
        eprintln!("took {:.2?}", started.elapsed());
    }
    code
}

/// Maps a failed run to the no-free-tunnel exit code when the bus actor saw the
/// gateway refuse every connect with `E_NO_MORE_CONNECTIONS` (the actor retries
/// such refusals, so the command itself only sees a bus that never came up).
fn no_free_tunnel_or(code: ExitCode) -> ExitCode {
    if bussard_bus::no_free_tunnel_seen() {
        eprintln!("{}", conn_cmd::no_free_tunnel_message("the gateway"));
        ExitCode::from(conn_cmd::EXIT_NO_FREE_TUNNEL)
    } else {
        code
    }
}

/// Whether an error chain carries the "no free tunnelling connection" refusal.
fn is_no_free_tunnel(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<bussard_transport::TransportError>(),
            Some(bussard_transport::TransportError::NoMoreConnections)
        )
    })
}

/// Dispatches a subcommand, returning the process exit code on success.
///
/// `verbose` is the global `-v` repeat count; `flash` uses it to unfold the
/// memory-level plan under the parameter-level one (issue #109).
fn run(command: Command, verbose: u8) -> anyhow::Result<ExitCode> {
    match command {
        Command::Scan {
            line,
            from,
            to,
            dir,
            json,
            gateway,
            routing,
            skip_address_check,
        } => scan_cmd::run(
            &line,
            from,
            to,
            &dir,
            json,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Assign {
            address,
            dir,
            yes,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => assign_cmd::run(
            address.as_deref(),
            &dir,
            yes,
            allow_remote_gateway,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Reconstruct {
            address,
            line,
            from,
            to,
            out,
            dir,
            json,
            gateway,
            routing,
            skip_address_check,
        } => {
            let overrides = conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            };
            match line {
                Some(line) => reconstruct_cmd::run_line(
                    &line,
                    from,
                    to,
                    out.as_deref(),
                    &dir,
                    json,
                    overrides,
                ),
                None => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    reconstruct_cmd::run(&address, &dir, json, overrides)
                }
            }
        }
        Command::Describe {
            address,
            dir,
            json,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
        } => describe_cmd::run(
            &address,
            &dir,
            json,
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Keyring { file, json } => keyring_cmd::run(&file, json),
        Command::ImportProduct {
            file,
            dir,
            order_number,
            yes_download,
            inner,
            list,
        } => import_product_cmd::run(
            file.as_deref(),
            &dir,
            order_number.as_deref(),
            yes_download,
            inner.as_deref(),
            list,
        ),
        Command::Adopt {
            product,
            dir,
            yes,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => adopt_cmd::run(
            product.as_deref(),
            &dir,
            yes,
            allow_remote_gateway,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Flash {
            address,
            product,
            application,
            order_number,
            dir,
            yes,
            force,
            full,
            no_factory_reset,
            allow_remote_gateway,
            bcu_key,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
            json,
            dry_run,
            dump_images,
        } => flash_cmd::run(
            &address,
            &product,
            application.as_deref(),
            order_number.as_deref(),
            &dir,
            yes,
            force,
            full,
            no_factory_reset,
            allow_remote_gateway,
            bcu_key.as_deref(),
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
            flash_cmd::FlashOutput {
                json,
                verbose,
                dry_run: dry_run.then_some(flash_cmd::DryRun { dump_images }),
            },
        ),
        Command::Plan {
            address,
            line,
            dir,
            json,
            gateway,
            routing,
            skip_address_check,
        } => {
            let overrides = conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            };
            match line {
                Some(line) => line_cmd::run_plan(&line, &dir, json, overrides),
                None => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    plan_cmd::run(&address, &dir, json, overrides)
                }
            }
        }
        Command::Apply {
            address,
            line,
            json,
            resume,
            dir,
            yes,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => {
            let overrides = conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            };
            let tool_key_source = secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            };
            match line {
                Some(line) => line_cmd::run_apply(
                    &line,
                    &dir,
                    yes,
                    json,
                    resume,
                    allow_remote_gateway,
                    tool_key_source,
                    overrides,
                ),
                None => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    apply_cmd::run(
                        &address,
                        &dir,
                        yes,
                        allow_remote_gateway,
                        tool_key_source,
                        overrides,
                    )
                }
            }
        }
        Command::Commission {
            line,
            flash,
            apply,
            labels,
            product,
            dir,
            yes,
            json,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => commission_cmd::run(
            &line,
            &dir,
            commission_cmd::CommissionOptions {
                flash,
                apply,
                labels: labels.as_deref(),
                product: product.as_deref(),
                yes,
                json,
                allow_remote_gateway,
            },
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Status { dir, json, raw } => history_cmd::run_status(&dir, json, raw),
        Command::History { dir, json } => history_cmd::run_history(&dir, json),
        Command::Show { snapshot, to, dir } => {
            history_cmd::run_show(&dir, &snapshot, to.as_deref())
        }
        Command::Undo { snapshot, dir } => history_cmd::run_undo(&dir, snapshot.as_deref()),
        Command::Backup {
            addresses,
            line,
            out,
            dir,
            json,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
        } => backup_cmd::run(
            &addresses,
            line.as_deref(),
            out.as_deref(),
            &dir,
            json,
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Restore {
            backup_dir,
            address,
            dir,
            yes,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => restore_cmd::run(
            &backup_dir,
            &address,
            &dir,
            yes,
            allow_remote_gateway,
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Replace {
            address,
            product,
            dir,
            yes,
            force,
            no_flash,
            bcu_key,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => replace_cmd::run(
            &address,
            &product,
            &dir,
            yes,
            force,
            no_flash,
            allow_remote_gateway,
            bcu_key.as_deref(),
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Validate { dir, format } => validate_cmd::run(&dir, format == Format::Json),
        Command::Scaffold {
            plan,
            dir,
            scheme,
            out,
            json,
            no_lint_config,
        } => scaffold_cmd::run(
            &plan,
            &dir,
            scheme.map(Into::into),
            out.as_deref(),
            json,
            no_lint_config,
        ),
        Command::ExportGroups { dir, format, out } => export_groups_cmd::run(&dir, format, &out),
        Command::Doc {
            dir,
            out,
            format,
            json,
        } => doc_cmd::run(&dir, &out, format.into(), json),
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
            mine,
            theirs,
            interactive,
        } => {
            let choice = import_bundle::ConflictChoice::from_flags(mine, theirs, interactive);
            if let Some(json) = from_json {
                import_cmd::run_json(&json, &dir, choice)
            } else if let Some(project) = project {
                if bussard_model::bundle::is_bundle_path(&project) {
                    import_bundle::run_bundle(&project, &dir, choice)
                } else {
                    import_cmd::run_knxproj(&project, &dir, password, choice)
                }
            } else {
                anyhow::bail!("provide a .knxproj path or --from-json <file>")
            }
        }
        Command::Export {
            file,
            dir,
            no_history,
            json,
        } => export_cmd::run(file.as_deref(), &dir, no_history, json),
        Command::Diff {
            a,
            b,
            json,
            raw,
            password,
            password_b,
        } => diff_cmd::run(&a, &b, json, raw, password, password_b),
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
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
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
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
        ),
        Command::Read {
            ga,
            dir,
            gateway,
            routing,
        } => read_cmd::run(
            &ga,
            &dir,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
        ),
        Command::Write {
            ga,
            value,
            dpt,
            force,
            yes,
            dir,
            gateway,
            routing,
            allow_remote_gateway,
        } => write_cmd::run(
            &ga,
            &value,
            dpt.as_deref(),
            force,
            yes,
            allow_remote_gateway,
            &dir,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
        ),
        Command::HaConfig { dir, out } => ha_config_cmd::run(&dir, out.as_deref()),
        Command::Viz {
            listen,
            dir,
            gateway,
            routing,
            watch_prog,
            allow_writes,
            allow_remote_gateway,
            allow_host,
        } => viz_cmd::run(
            listen,
            &dir,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
            viz_cmd::VizOptions {
                allow_writes,
                watch_prog,
                allow_remote_gateway,
                allowed_hosts: allow_host,
            },
        ),
        Command::Learn {
            gas,
            unnamed,
            untyped,
            yes,
            timeout,
            dir,
            gateway,
            routing,
        } => learn_cmd::run(
            &dir,
            learn_cmd::LearnOptions {
                gas,
                unnamed,
                untyped,
                yes,
                timeout_seconds: timeout,
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
        ),
        Command::Test {
            file,
            json,
            force,
            skip_manual,
            only,
            yes,
            dir,
            gateway,
            routing,
            allow_remote_gateway,
        } => test_cmd::run(
            &dir,
            test_cmd::TestOptions {
                file,
                json,
                force,
                skip_manual,
                only,
                yes,
                allow_remote_gateway,
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
        ),
        Command::Audit {
            dir,
            json,
            live,
            window,
            keyring,
            gateway,
            routing,
            skip_address_check,
        } => audit_cmd::run(
            &dir,
            audit_cmd::AuditOptions {
                json,
                live,
                window: std::time::Duration::from_secs(window),
                keyring: keyring.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
            },
        ),
        Command::Mcp {
            dir,
            gateway,
            routing,
            passive,
            allow_writes,
            allow_programming,
            plan_ttl_minutes,
            allow_remote_gateway,
            no_model_edits,
            capture_db,
        } => mcp_cmd::run(
            &dir,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
            },
            mcp_cmd::McpModes {
                passive,
                allow_writes,
                allow_programming,
                plan_ttl: std::time::Duration::from_secs(plan_ttl_minutes.saturating_mul(60)),
                allow_remote_gateway,
                no_model_edits,
            },
            capture_db,
        ),
    }
}
