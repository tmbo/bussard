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
mod confirm;
mod conn_cmd;
mod describe_cmd;
mod device_cmd;
mod device_facts;
mod device_plan;
mod diff_cmd;
mod doc_cmd;
mod export_cmd;
mod export_groups_cmd;
mod flash_cmd;
mod flash_dump;
mod flash_params;
mod groups_cmd;
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
mod param_readback;
mod plan_cmd;
mod product_cache;
mod product_fetch;
mod progress;
mod read_cmd;
mod reconstruct_cmd;
mod replace_cmd;
mod restore_cmd;

mod scan_cmd;
mod secure_key;
mod test_cmd;
mod timing;
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
    /// Print the invocation's wall-clock time to stderr on exit, with the
    /// start-up phases (model load, keyring, product parse, tunnel) before it.
    #[arg(long, global = true)]
    timing: bool,
    /// Never draw the live progress display on a terminal; print the plain
    /// progress lines a piped run prints.
    #[arg(long, global = true)]
    no_progress: bool,
    /// KNXnet/IP Secure: the tunnelling user id to authenticate as, with
    /// `--secure-password-env`. Without these flags a `--keyring` that lists the
    /// interface's tunnelling users picks one automatically (issue #71).
    #[arg(long, global = true, value_name = "ID")]
    secure_user: Option<u8>,
    /// KNXnet/IP Secure: the name of the environment variable that holds the
    /// `--secure-user` password (never the password itself).
    #[arg(long, global = true, value_name = "VAR")]
    secure_password_env: Option<String>,
    /// KNXnet/IP Secure: the carrier of the secure session. Default `auto`:
    /// TCP, and UDP when the interface refuses TCP but advertises Secure
    /// (issue #197). UDP is verified against knx-sim only.
    #[arg(long, global = true, value_enum, value_name = "TRANSPORT")]
    secure_transport: Option<SecureTransportArg>,
    #[command(subcommand)]
    command: Command,
}

/// The `--secure-transport` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SecureTransportArg {
    /// TCP first, UDP when TCP is refused and the interface advertises Secure.
    Auto,
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
}

impl From<SecureTransportArg> for bussard_transport::SecureTransport {
    fn from(arg: SecureTransportArg) -> Self {
        match arg {
            SecureTransportArg::Auto => bussard_transport::SecureTransport::Auto,
            SecureTransportArg::Tcp => bussard_transport::SecureTransport::Tcp,
            SecureTransportArg::Udp => bussard_transport::SecureTransport::Udp,
        }
    }
}

/// The `--keyring` slot of the subcommand, if it takes one: its tunnelling
/// users open a KNXnet/IP Secure tunnel to a secure interface (issue #71 Phase
/// B), and its device entries carry the tool keys for secured management.
fn command_keyring_slot(command: &mut Command) -> Option<&mut Option<PathBuf>> {
    match command {
        Command::Scan { keyring, .. }
        | Command::Assign { keyring, .. }
        | Command::Reconstruct { keyring, .. }
        | Command::Describe { keyring, .. }
        | Command::Flash { keyring, .. }
        | Command::Plan { keyring, .. }
        | Command::Apply { keyring, .. }
        | Command::Commission { keyring, .. }
        | Command::Backup { keyring, .. }
        | Command::Restore { keyring, .. }
        | Command::Replace { keyring, .. }
        | Command::Monitor { keyring, .. }
        | Command::Capture { keyring, .. }
        | Command::Read { keyring, .. }
        | Command::Write { keyring, .. }
        | Command::Viz { keyring, .. }
        | Command::Audit { keyring, .. }
        | Command::Learn { keyring, .. }
        | Command::Mcp { keyring, .. } => Some(keyring),
        _ => None,
    }
}

/// The model directory of a subcommand that talks to the bus, whose
/// `bussard.toml` may name a default keyring (`connection.keyring`, issue
/// #189). `init` is left out: it writes that file.
fn bus_command_dir(command: &Command) -> Option<&std::path::Path> {
    match command {
        Command::Scan { dir, .. }
        | Command::Assign { dir, .. }
        | Command::Reconstruct { dir, .. }
        | Command::Describe { dir, .. }
        | Command::Adopt { dir, .. }
        | Command::Flash { dir, .. }
        | Command::Plan { dir, .. }
        | Command::Apply { dir, .. }
        | Command::Commission { dir, .. }
        | Command::Backup { dir, .. }
        | Command::Restore { dir, .. }
        | Command::Replace { dir, .. }
        | Command::Monitor { dir, .. }
        | Command::Capture { dir, .. }
        | Command::Read { dir, .. }
        | Command::Write { dir, .. }
        | Command::Viz { dir, .. }
        | Command::Learn { dir, .. }
        | Command::Test { dir, .. }
        | Command::Audit { dir, .. }
        | Command::Mcp { dir, .. } => Some(dir),
        _ => None,
    }
}

/// Whether the subcommand was given `--tool-key`. A config default keyring
/// must not collide with it (the two are mutually exclusive tool-key
/// sources), so it then serves the tunnel only.
fn command_has_tool_key(command: &Command) -> bool {
    match command {
        Command::Assign { tool_key, .. }
        | Command::Reconstruct { tool_key, .. }
        | Command::Describe { tool_key, .. }
        | Command::Flash { tool_key, .. }
        | Command::Plan { tool_key, .. }
        | Command::Apply { tool_key, .. }
        | Command::Commission { tool_key, .. }
        | Command::Backup { tool_key, .. }
        | Command::Restore { tool_key, .. }
        | Command::Replace { tool_key, .. } => tool_key.is_some(),
        _ => false,
    }
}

/// The keyring this invocation uses, if any: the subcommand's `--keyring`,
/// else `connection.keyring` from its model's `bussard.toml` (issue #189). The
/// flag is `true` when the keyring came from the config.
///
/// A default from the config is written into the subcommand's `--keyring`
/// slot, so every consumer (tool keys, group keys, the tunnel) sees one
/// keyring. A subcommand without a slot (`adopt`, `test`), or one
/// given `--tool-key`, uses it for the tunnel only. A `bussard.toml` that does
/// not parse is left for the subcommand's own model load to report.
fn effective_keyring(command: &mut Command) -> Option<(PathBuf, bool)> {
    let configured = bus_command_dir(command).and_then(|dir| {
        let config = bussard_model::load_config(dir).ok()?;
        config.connection.keyring_path(dir)
    });
    if command_has_tool_key(command) {
        return configured.map(|path| (path, true));
    }
    match command_keyring_slot(command) {
        Some(slot) => match slot {
            Some(path) => Some((path.clone(), false)),
            None => {
                *slot = configured.clone();
                configured.map(|path| (path, true))
            }
        },
        None => configured.map(|path| (path, true)),
    }
}

/// Resolves the KNXnet/IP Secure tunnelling credentials once, before the
/// subcommand runs, so every connection it opens uses them.
fn setup_secure_tunnel(cli: &mut Cli) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let keyring = effective_keyring(&mut cli.command);
    // Without explicit flags, only a keyring can carry tunnelling users.
    if keyring.is_none() && cli.secure_user.is_none() && cli.secure_password_env.is_none() {
        if cli.secure_transport.is_some() {
            anyhow::bail!(
                "--secure-transport needs KNXnet/IP Secure tunnelling credentials: pass --keyring \
                 <file.knxkeys> or --secure-user <id> --secure-password-env <VAR>"
            );
        }
        return Ok(());
    }
    let config =
        bussard_service::secure::tunnel_config(bussard_service::secure::TunnelCredentialSource {
            keyring: keyring.as_ref().map(|(path, _)| path.as_path()),
            user: cli.secure_user,
            password_env: cli.secure_password_env.as_deref(),
        })
        .with_context(|| match &keyring {
            Some((path, true)) => format!(
                "the keyring {} comes from connection.keyring in bussard.toml (pass --keyring \
                 to use another one)",
                path.display()
            ),
            _ => "resolving the KNXnet/IP Secure tunnelling credentials".to_string(),
        })?;
    if let Some((path, true)) = &keyring {
        tracing::info!(
            "using the keyring {} from connection.keyring in bussard.toml",
            path.display()
        );
    }
    let config = match (config, cli.secure_transport) {
        (Some(config), Some(transport)) => Some(config.with_transport(transport.into())),
        (None, Some(_)) => anyhow::bail!(
            "--secure-transport needs KNXnet/IP Secure tunnelling credentials, and the keyring \
             lists no tunnelling user"
        ),
        (config, None) => config,
    };
    conn_cmd::set_secure_tunnel(config);
    Ok(())
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

/// The `bussard groups` subcommands.
#[derive(Debug, Subcommand)]
enum GroupsCommand {
    /// Append the conventional group-address block for a room and trade to
    /// `groups.toml` and print the addresses.
    ///
    /// The scheme is `[lint.groups] scheme` in `bussard.toml` (written on the
    /// first reservation). Re-running for a room and function that already
    /// have their block adds nothing.
    Reserve {
        /// The room, floor first, as one argument: `"EG Küche"`.
        #[arg(value_name = "FLOOR ROOM")]
        room: String,
        /// The functions the room needs: light, light-dim, blind, heating,
        /// socket.
        #[arg(value_name = "FUNCTION", required = true)]
        functions: Vec<String>,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// The addressing scheme for a project that has none yet (default
        /// floor-trade-block). Refused when it contradicts `bussard.toml`.
        #[arg(long, value_enum)]
        scheme: Option<SchemeArg>,
        /// Emit JSON instead of the address list.
        #[arg(long)]
        json: bool,
    },
}

/// The top-level subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a fresh model directory: discover the gateway, write the
    /// skeleton, then import the ETS project (the one given, or the one
    /// `.knxproj` next to the directory) or offer to scan the line.
    Init {
        /// The ETS project to import right away (`.knxproj`, or an
        /// xknxproject `.json` dump). Default: the one `.knxproj` next to the
        /// model directory, when there is exactly one.
        #[arg(value_name = "PROJECT")]
        project: Option<PathBuf>,
        /// The directory to create the model in.
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Use this gateway `host[:port]` instead of discovering one.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Configure KNXnet/IP routing (multicast) instead of tunneling.
        #[arg(long)]
        routing: bool,
        /// Project password (else `BUSSARD_PROJECT_PASSWORD`, else prompt).
        #[arg(long)]
        password: Option<String>,
        /// Download the missing product data without asking.
        #[arg(long, conflicts_with = "no_download")]
        yes: bool,
        /// Do not download missing product data; list it instead.
        #[arg(long)]
        no_download: bool,
        /// Without a project: scan this line after writing the skeleton and
        /// list what answers, without asking (for scripts).
        #[arg(long, value_name = "LINE", conflicts_with = "project")]
        scan: Option<String>,
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
        /// Download the missing product data without asking (the order
        /// numbers the pointer index knows).
        #[arg(long, conflicts_with = "no_download")]
        yes: bool,
        /// Do not look up or download missing product data; list it instead.
        #[arg(long)]
        no_download: bool,
    },
    /// Write the model and its history as one `.bussard` file to hand over.
    Export {
        /// The bundle to write (default: next to the model directory, named
        /// after it and today's date).
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// Print a file-level TOML diff instead of sentences.
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the table format.
        #[arg(long)]
        json: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// An ETS `.knxkeys` keyring: its KNXnet/IP Secure tunnelling users open
        /// the tunnel to a secure interface (issue #189), and a device it lists
        /// is identified over KNX Data Secure with its tool key, showing the real
        /// mask (issue #203). Unlisted devices are read in the clear. Default:
        /// `connection.keyring` in `bussard.toml`. The password comes from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// An ETS `.knxkeys` keyring: its KNXnet/IP Secure tunnelling users open
        /// the tunnel to a secure interface (issue #189), and the tool key it
        /// lists for the new (else the old) address verifies a Data
        /// Secure-activated device after the write (issue #203). Default:
        /// `connection.keyring` in `bussard.toml`. The password comes from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// A raw KNX Data Secure tool key (32 hex characters) to verify a
        /// security-activated device with after the address write (issue #203).
        /// Overrides the keyring, which lists devices by individual address and
        /// so only knows the new address once ETS re-exports it. For a test or
        /// bench device: process arguments are visible to other users.
        #[arg(long, value_name = "HEX")]
        tool_key: Option<String>,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        /// In line mode this only supplies connection defaults.
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// The device's vendor `.knxprod`, to read back and decode its parameter
        /// memory too (issue #119). Without it the archive in `<dir>/vendor/`
        /// whose catalogue carries the model's order number is used, when cached.
        #[arg(long, value_name = "FILE", conflicts_with = "line")]
        product: Option<PathBuf>,
        /// The application program id to decode the parameters with (default:
        /// the model's application ref, else the order number, else the sole one).
        #[arg(long, value_name = "REF", conflicts_with = "line")]
        application: Option<String>,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #170). Required for a security-activated device, which
        /// answers the plain descriptor read with mask FFFF; with the key every
        /// read, the descriptor included, is secured. The keyring password comes
        /// from `BUSSARD_KEYRING_PASSWORD`, never a CLI argument.
        #[arg(long, value_name = "FILE", conflicts_with = "line")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with_all = ["keyring", "line"])]
        tool_key: Option<String>,
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
        /// Ignore the stored device facts (`<dir>/.bussard/facts/<ia>.toml`)
        /// and read them from the device again (issue #209).
        #[arg(long)]
        refresh_facts: bool,
    },
    /// Introspect a device: enumerate its interface objects and each property's
    /// description (PID, type, element count, access levels) over the bus.
    Describe {
        /// The device to introspect, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON instead of the table format.
        #[arg(long)]
        json: bool,
        /// Walk every object's property descriptions again, even when the
        /// device facts (`<dir>/.bussard/facts/<ia>.toml`) already hold them.
        #[arg(long)]
        full: bool,
        /// Ignore the stored device facts and read them from the device again.
        #[arg(long)]
        refresh_facts: bool,
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
    /// the index. An ETS project export (`.knxproj`) FILE is read in place and
    /// not cached under `vendor/`.
    ImportProduct {
        /// The `.knxprod` or `.knxproj` file to import (positional mode).
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts). Also
        /// consents to downloading the product data the device's order number
        /// needs.
        #[arg(long)]
        yes: bool,
        /// Do not download product data for the device's order number; adopt
        /// it without (identity and links by number) and say where to get it.
        #[arg(long)]
        no_download: bool,
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
    /// Download the full application program into a device (a fresh device, or
    /// one whose application changes). Everyday changes go through `apply`.
    Flash {
        /// The device to program, e.g. `1.0.10`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The vendor `.knxprod` containing the application program. Default:
        /// the archive in `<dir>/vendor/` whose catalogue carries the device's
        /// order number.
        #[arg(long, value_name = "FILE")]
        product: Option<PathBuf>,
        /// The application program id (default: the program the lock pins,
        /// else the order number's, else the sole application).
        #[arg(long, value_name = "REF", conflicts_with = "order_number")]
        application: Option<String>,
        /// Select the application program by hardware order number (e.g.
        /// `AKK-0216.03`) instead of a raw application ref. Resolved through the
        /// product's hardware catalogue; exactly one match is required.
        #[arg(long, value_name = "ORDER")]
        order_number: Option<String>,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// Rewrite only the parameter memory of a device that already runs this
        /// application (issue #119): no unload, no segment allocation, no table
        /// write. Only the octets that differ from what the device holds are
        /// written, then the load completes and the device restarts. Refused when
        /// the device runs another application or is not Loaded, and when a
        /// changed parameter shows or hides a com-object (that needs a full flash).
        /// The parameter memory is backed up first. With `--dry-run`, prints the
        /// op sequence offline.
        #[arg(long, conflicts_with_all = ["full", "force", "no_factory_reset"])]
        parameters_only: bool,
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
        /// Also list this individual address (bussard's own tunnel address) as a
        /// secured sender, sequence 0, in the security individual address table
        /// (PID 54) the security object is reprogrammed with, so the device
        /// accepts `bussard write --keyring` to its secured group addresses.
        /// Off by default: without it the device drops bussard's secured group
        /// telegrams silently. See docs/SAFETY.md.
        #[arg(long, value_name = "IA")]
        secure_sender: Option<bussard_model::IndividualAddress>,
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
        /// Ignore the stored device facts (`<dir>/.bussard/facts/<ia>.toml`)
        /// and read them from the device again (issue #209).
        #[arg(long)]
        refresh_facts: bool,
    },
    /// Show what `apply` would write to a device (links and, with product
    /// data, parameters) without writing; or (with `--line`) plan every model
    /// device on a line. Read-only on the bus.
    Plan {
        /// The device to plan for, e.g. `1.1.4` (mutually exclusive with
        /// `--line`).
        #[arg(value_name = "ADDRESS", required_unless_present = "line")]
        address: Option<String>,
        /// Plan every device the model has on this line, e.g. `1.1`, in address
        /// order, and print one summary table (issue #100).
        #[arg(long, value_name = "LINE", conflicts_with = "address")]
        line: Option<String>,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// The device's vendor `.knxprod`, to read back and decode its parameter
        /// memory too (issue #119). Without it the archive in `<dir>/vendor/`
        /// whose catalogue carries the model's order number is used, when cached.
        #[arg(long, value_name = "FILE", conflicts_with = "line")]
        product: Option<PathBuf>,
        /// The application program id to decode the parameters with (default:
        /// the model's application ref, else the order number, else the sole one).
        #[arg(long, value_name = "REF", conflicts_with = "line")]
        application: Option<String>,
        /// The ETS `.knxkeys` keyring holding the target's KNX Data Secure tool
        /// key (issue #170). Required for a security-activated device, which
        /// answers the plain descriptor read with mask FFFF; with the key every
        /// read, the descriptor included, is secured. The keyring password comes
        /// from `BUSSARD_KEYRING_PASSWORD`, never a CLI argument.
        /// With `--line`, each device's key is looked up in the keyring.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
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
        /// Ignore the stored device facts (`<dir>/.bussard/facts/<ia>.toml`)
        /// and read them from the device again (issue #209).
        #[arg(long)]
        refresh_facts: bool,
    },
    /// Write the model to a device: validate, read the device, show the plan,
    /// ask once, back up, write only what differs (links and parameter
    /// octets), verify. With `--line`, every model device on a line.
    Apply {
        /// The device to write, e.g. `1.1.4` (mutually exclusive with
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// Refuse unless the device state still hashes to this `state_hash`
        /// from `bussard plan --json`: the plan a human approved is the plan
        /// written.
        #[arg(long = "plan", value_name = "HASH", conflicts_with = "line")]
        plan_hash: Option<String>,
        /// The device's vendor `.knxprod`, to compare and write its parameter
        /// memory. Without it the archive in `<dir>/vendor/` whose catalogue
        /// carries the device's order number is used, when cached.
        #[arg(long, value_name = "FILE", conflicts_with = "line")]
        product: Option<PathBuf>,
        /// The application program id to decode the parameters with (default:
        /// the program the lock pins, else the order number, else the sole one).
        #[arg(long, value_name = "REF", conflicts_with = "line")]
        application: Option<String>,
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
        /// Also list this individual address (bussard's own tunnel address) as a
        /// secured sender, sequence 0, in the security individual address table
        /// (PID 54) the security object is reprogrammed with, so the device
        /// accepts `bussard write --keyring` to its secured group addresses.
        /// Off by default: without it the device drops bussard's secured group
        /// telegrams silently. See docs/SAFETY.md.
        #[arg(long, value_name = "IA", conflicts_with = "line")]
        secure_sender: Option<bussard_model::IndividualAddress>,
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
        /// Ignore the stored device facts (`<dir>/.bussard/facts/<ia>.toml`)
        /// and read them from the device again (issue #209).
        #[arg(long)]
        refresh_facts: bool,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit the list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show what a device offers, in its device file's words: its channels,
    /// and for one channel its parameters (value, choices, default) and objects.
    Device {
        /// The device, e.g. `1.1.47`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// The channel to list in detail: its handle (`a-1`), id or number, or
        /// `device` for the device-level parameters and objects.
        #[arg(value_name = "CHANNEL")]
        channel: Option<String>,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Print the paste-ready device-file TOML, with commented lines for
        /// what the file does not set yet.
        #[arg(long, conflicts_with = "json")]
        toml: bool,
        /// Emit the view as JSON.
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
    /// Validate the model and report diagnostics.
    Validate {
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Work with the group-address plan (`groups.toml`): reserve the
    /// conventional addresses for a room.
    Groups {
        #[command(subcommand)]
        command: GroupsCommand,
    },
    /// Export the group-address plan in a format ETS can import.
    ExportGroups {
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Emit JSON Lines (for tooling) instead of the pretty text format.
        #[arg(long)]
        json: bool,
        /// Only show telegrams matching this filter: a comma-separated list of
        /// GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`) or IAs (`1.1.30`).
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
        /// An ETS `.knxkeys` keyring whose group keys verify and decrypt secured group
        /// telegrams; they are marked `secured` in the output (KNX Data Secure group
        /// communication, issue #172). The password is read from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// Only capture telegrams matching this filter (see `monitor --filter`).
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
        /// An ETS `.knxkeys` keyring whose group keys verify and decrypt secured group
        /// telegrams; the decoded snapshot carries the `secured` flag (KNX Data Secure
        /// group communication, issue #172). The password is read from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// An ETS `.knxkeys` keyring whose group keys secure the read of a secured GA
        /// and verify its response (KNX Data Secure group communication, issue #172).
        /// The password is read from `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// The DPT to encode as (default: the GA's DPT from `groups.toml`).
        #[arg(long, value_name = "DPT")]
        dpt: Option<String>,
        /// Write even if the GA is marked `protected: true` in the model.
        #[arg(long)]
        force: bool,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// An ETS `.knxkeys` keyring whose group keys secure the write of a secured GA
        /// (KNX Data Secure group communication, issue #172). The password is read from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// An ETS `.knxkeys` keyring whose group keys secure `POST /api/group-write` to
        /// a secured GA and decrypt secured telegrams in the live traffic (KNX Data
        /// Secure group communication, issue #172). The password is read from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
        #[arg(long, default_value = "knx")]
        dir: PathBuf,
        /// An ETS `.knxkeys` keyring whose group keys verify and decrypt secured
        /// group telegrams, so their values are learned and the group is marked
        /// `secure` (KNX Data Secure, issue #204). Defaults to
        /// `connection.keyring` in `bussard.toml`. The password is read from
        /// `BUSSARD_KEYRING_PASSWORD`.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
        /// Override the gateway `host[:port]` for tunneling.
        #[arg(long, value_name = "HOST")]
        gateway: Option<String>,
        /// Force KNXnet/IP routing (multicast) transport.
        #[arg(long)]
        routing: bool,
    },
    /// Run the scripted acceptance tests in `tests.toml` against the bus.
    Test {
        /// The test file to run (default: `<dir>/tests.toml`).
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
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
        /// Instead of running `tests.toml`: open a KNXnet/IP Secure session,
        /// stay idle (no keepalive, no tunnel) for SECS seconds, and report
        /// whether the interface dropped it (issue #197). Read-only: nothing
        /// is written to the bus and no tunnel slot is taken.
        #[arg(long, value_name = "SECS", conflicts_with_all = ["file", "force", "skip_manual", "only"])]
        secure_idle: Option<u64>,
    },
    /// Audit the installation: model gaps, one-sided links, what bussard can do
    /// per device mask, KNX Secure coverage; with `--live`, the gateway's tunnel
    /// slots, a traffic sample and a scan of the modelled devices. Read-only.
    Audit {
        /// The directory containing the model (`bussard.toml`, `groups.toml`, …).
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
    /// Run the MCP server over stdio: model tools and bus reads by default;
    /// bus writes and device programming only when their flags allow it.
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
        /// plan the human approved (issue #118); parameters stay with
        /// `bussard apply`. Off by default. Mutually
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
        /// `knx_remove_link`, `knx_set_device`, `knx_set_parameter`, `knx_undo`,
        /// `knx_scaffold_groups` and `knx_reserve_groups` tools. The read tools
        /// stay available. Model edits only
        /// touch the model files (never the bus), so they are on by default.
        #[arg(long)]
        no_model_edits: bool,
        /// Path to a capture SQLite database to extend `knx_recent_telegrams`
        /// history beyond the in-memory ring window.
        #[arg(long, value_name = "PATH")]
        capture_db: Option<PathBuf>,
        /// ETS keyring export (`.knxkeys`) for KNX Data Secure management:
        /// `knx_describe_device` looks the target's tool key up in it. The
        /// password comes from BUSSARD_KEYRING_PASSWORD.
        #[arg(long, value_name = "FILE")]
        keyring: Option<PathBuf>,
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
    timing::start();
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
    let mut cli = Cli::parse();

    // The live progress display (issue #147) is only possible on a terminal;
    // when it is, bus-layer events also feed its "last event" line, and log
    // lines hide the bar while they print. Off a terminal both are inert.
    let live_progress = progress::init(cli.no_progress);
    {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;
        let events = live_progress.then(|| {
            progress::EventLayer.with_filter(tracing_subscriber::filter::filter_fn(
                progress::is_bus_event,
            ))
        });
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(progress::LogWriter)
                    .with_filter(verbosity_filter(cli.verbose)),
            )
            .with(events)
            .init();
    }

    // Opt-in wall-clock telemetry (issue #78): `--timing` reports the
    // invocation's elapsed time on stderr. Speed is a project goal, so this stays
    // available for regression spotting, but a plain 0.1.0 run is quiet.
    let started = timing::start();
    if let Err(err) = timing::time("tunnel creds", || setup_secure_tunnel(&mut cli)) {
        eprintln!("error: {err:#}");
        return ExitCode::FAILURE;
    }
    let result = run(cli.command, cli.verbose);
    // A connect error that retrying cannot fix (a secure-only interface
    // without credentials, a refused KNXnet/IP Secure password; issue #182) is
    // the real cause of whatever the command reported next; name it alone.
    if let Some(fatal) = bussard_bus::fatal_connect_error() {
        eprintln!("error: {fatal}");
        if cli.timing {
            print_timing(started);
        }
        return ExitCode::FAILURE;
    }
    let code = match result {
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
        print_timing(started);
    }
    code
}

/// Prints the `--timing` report: the start-up phases (issue #214), then the
/// total.
fn print_timing(started: std::time::Instant) {
    for line in timing::report() {
        eprintln!("{line}");
    }
    eprintln!("took {:.2?}", started.elapsed());
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
            keyring,
            gateway,
            routing,
            skip_address_check,
        } => scan_cmd::run(
            &line,
            from,
            to,
            &dir,
            json,
            keyring.as_deref(),
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                ..Default::default()
            },
        ),
        Command::Assign {
            address,
            dir,
            yes,
            keyring,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
            tool_key,
        } => assign_cmd::run(
            address.as_deref(),
            &dir,
            yes,
            allow_remote_gateway,
            // `--tool-key` overrides the keyring's device entries; the keyring
            // still opens a KNXnet/IP Secure tunnel (issue #203).
            secure_key::ToolKeySource {
                keyring: keyring.as_deref().filter(|_| tool_key.is_none()),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                ..Default::default()
            },
        ),
        Command::Reconstruct {
            address,
            line,
            from,
            to,
            out,
            dir,
            product,
            application,
            keyring,
            tool_key,
            json,
            gateway,
            routing,
            skip_address_check,
            refresh_facts,
        } => {
            let overrides = conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                refresh_facts,
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
                    reconstruct_cmd::run(
                        &address,
                        &dir,
                        json,
                        overrides,
                        param_readback::Selection {
                            product: product.as_deref(),
                            application: application.as_deref(),
                        },
                        secure_key::ToolKeySource {
                            keyring: keyring.as_deref(),
                            tool_key: tool_key.as_deref(),
                        },
                    )
                }
            }
        }
        Command::Describe {
            address,
            dir,
            json,
            full,
            refresh_facts,
            keyring,
            tool_key,
            gateway,
            routing,
            skip_address_check,
        } => describe_cmd::run(
            &address,
            &dir,
            json,
            describe_cmd::FactsOptions {
                full,
                refresh: refresh_facts,
            },
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                ..Default::default()
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
            no_download,
            gateway,
            routing,
            skip_address_check,
            allow_remote_gateway,
        } => adopt_cmd::run(
            product.as_deref(),
            &dir,
            yes,
            no_download,
            allow_remote_gateway,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                ..Default::default()
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
            parameters_only,
            allow_remote_gateway,
            bcu_key,
            keyring,
            tool_key,
            secure_sender,
            gateway,
            routing,
            skip_address_check,
            refresh_facts,
            json,
            dry_run,
            dump_images,
        } => flash_cmd::run(
            &address,
            product.as_deref(),
            application.as_deref(),
            order_number.as_deref(),
            &dir,
            yes,
            force,
            full,
            no_factory_reset,
            parameters_only,
            allow_remote_gateway,
            bcu_key.as_deref(),
            secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            },
            secure_sender,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                refresh_facts,
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
            product,
            application,
            keyring,
            tool_key,
            json,
            gateway,
            routing,
            skip_address_check,
            refresh_facts,
        } => {
            let overrides = conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                refresh_facts,
            };
            let tool_key_source = secure_key::ToolKeySource {
                keyring: keyring.as_deref(),
                tool_key: tool_key.as_deref(),
            };
            match line {
                Some(line) => line_cmd::run_plan(&line, &dir, json, tool_key_source, overrides),
                None => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    plan_cmd::run(
                        &address,
                        &dir,
                        json,
                        overrides,
                        param_readback::Selection {
                            product: product.as_deref(),
                            application: application.as_deref(),
                        },
                        tool_key_source,
                        verbose,
                    )
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
            plan_hash,
            product,
            application,
            keyring,
            tool_key,
            secure_sender,
            gateway,
            routing,
            skip_address_check,
            refresh_facts,
            allow_remote_gateway,
        } => {
            let overrides = conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check,
                refresh_facts,
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
                        secure_sender,
                        overrides,
                        apply_cmd::ApplyInputs {
                            selection: param_readback::Selection {
                                product: product.as_deref(),
                                application: application.as_deref(),
                            },
                            plan_hash: plan_hash.as_deref(),
                        },
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
                ..Default::default()
            },
        ),
        Command::Status { dir, json, raw } => history_cmd::run_status(&dir, json, raw),
        Command::History { dir, json } => history_cmd::run_history(&dir, json),
        Command::Device {
            address,
            channel,
            dir,
            toml,
            json,
        } => device_cmd::run(&address, channel.as_deref(), &dir, toml, json),
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
            },
        ),
        Command::Validate { dir, format } => validate_cmd::run(&dir, format == Format::Json),
        Command::Groups { command } => match command {
            GroupsCommand::Reserve {
                room,
                functions,
                dir,
                scheme,
                json,
            } => groups_cmd::run_reserve(&dir, &room, &functions, scheme.map(Into::into), json),
        },
        Command::ExportGroups { dir, format, out } => export_groups_cmd::run(&dir, format, &out),
        Command::Doc {
            dir,
            out,
            format,
            json,
        } => doc_cmd::run(&dir, &out, format.into(), json),
        Command::Init {
            project,
            dir,
            gateway,
            routing,
            password,
            yes,
            no_download,
            scan,
        } => init_cmd::run(
            &dir,
            gateway.as_deref(),
            routing,
            init_cmd::FirstRun {
                project,
                password,
                consent: product_fetch::Consent { yes, no_download },
                scan,
            },
        ),
        Command::Import {
            project,
            from_json,
            password,
            dir,
            mine,
            theirs,
            interactive,
            yes,
            no_download,
        } => {
            let choice = import_bundle::ConflictChoice::from_flags(mine, theirs, interactive);
            let consent = product_fetch::Consent { yes, no_download };
            if let Some(json) = from_json {
                import_cmd::run_json(&json, &dir, choice, consent)
            } else if let Some(project) = project {
                if bussard_model::bundle::is_bundle_path(&project) {
                    import_bundle::run_bundle(&project, &dir, choice)
                } else {
                    import_cmd::run_knxproj(&project, &dir, password, choice, consent)
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
            keyring,
            gateway,
            routing,
        } => monitor_cmd::run(
            &dir,
            json,
            filter.as_deref(),
            keyring.as_deref(),
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
            },
        ),
        Command::Capture {
            to,
            dir,
            filter,
            keyring,
            gateway,
            routing,
        } => capture_cmd::run(
            &to,
            &dir,
            filter.as_deref(),
            keyring.as_deref(),
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
            },
        ),
        Command::Read {
            ga,
            dir,
            keyring,
            gateway,
            routing,
        } => read_cmd::run(
            &ga,
            &dir,
            keyring.as_deref(),
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
            },
        ),
        Command::Write {
            ga,
            value,
            dpt,
            force,
            yes,
            dir,
            keyring,
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
            keyring.as_deref(),
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
            },
        ),
        Command::HaConfig { dir, out } => ha_config_cmd::run(&dir, out.as_deref()),
        Command::Viz {
            listen,
            dir,
            keyring,
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
                ..Default::default()
            },
            viz_cmd::VizOptions {
                allow_writes,
                watch_prog,
                allow_remote_gateway,
                allowed_hosts: allow_host,
                keyring,
            },
        ),
        Command::Learn {
            gas,
            unnamed,
            untyped,
            yes,
            timeout,
            dir,
            keyring,
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
                keyring,
            },
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
            },
        ),
        Command::Test {
            json,
            dir,
            gateway,
            routing,
            secure_idle: Some(secs),
            ..
        } => test_cmd::run_secure_idle(
            &dir,
            std::time::Duration::from_secs(secs),
            json,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
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
            secure_idle: None,
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
                ..Default::default()
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
                ..Default::default()
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
            keyring,
        } => mcp_cmd::run(
            &dir,
            conn_cmd::ConnOverrides {
                gateway,
                routing,
                skip_address_check: false,
                ..Default::default()
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
            keyring,
        ),
    }
}
