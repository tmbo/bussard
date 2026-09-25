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
mod flash_handover;
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

use clap::{Args, Parser, Subcommand, ValueEnum};

/// bussard: manage a KNX installation as code.
#[derive(Debug, Parser)]
#[command(name = "bussard", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Command,
}

/// The options every subcommand shares (issue #228): declared once, accepted
/// before or after the subcommand, and printed once under "Global options".
/// A command that has no use for one accepts and ignores it, except `--json`,
/// which a command without machine output refuses.
///
/// `--yes`, `--force`, `--dry-run` and `--plan` are deliberately not here: they
/// stay on the command whose action they consent to, and never come from the
/// environment or `bussard.toml`.
#[derive(Debug, Args)]
#[command(next_help_heading = "Global options")]
struct Global {
    /// The model directory. Default: `BUSSARD_DIR`, else discovered: `.` when
    /// it holds `bussard.toml`, else `./knx`, else the nearest parent holding
    /// `bussard.toml` (or `knx/bussard.toml`), else `knx`. `init` and `import`
    /// create the model in `--dir`, `BUSSARD_DIR` or `knx` and never search.
    #[arg(long, global = true, value_name = "DIR")]
    dir: Option<PathBuf>,
    /// The KNXnet/IP gateway `host[:port]`; implies tunnelling. Default:
    /// `BUSSARD_GATEWAY`, else `connection.gateway` in `bussard.toml`. For
    /// `init`: use this gateway instead of discovering one.
    #[arg(long, global = true, value_name = "HOST[:PORT]")]
    gateway: Option<String>,
    /// Use KNXnet/IP routing (multicast) instead of tunnelling (for `init`:
    /// configure it). No environment variable can select it.
    #[arg(long, global = true)]
    routing: bool,
    /// An ETS `.knxkeys` keyring. Its tunnelling users open a KNXnet/IP Secure
    /// tunnel, its device entries carry the KNX Data Secure tool keys for
    /// management, and its group keys secure and decrypt group telegrams.
    /// Default: `BUSSARD_KEYRING`, else `connection.keyring` in
    /// `bussard.toml`. The password comes from `BUSSARD_KEYRING_PASSWORD`,
    /// never a CLI argument.
    #[arg(long, global = true, value_name = "FILE")]
    keyring: Option<PathBuf>,
    /// Emit machine-readable JSON instead of the text output (`monitor`: JSON
    /// Lines). A command without JSON output refuses it.
    #[arg(long, global = true)]
    json: bool,
    /// Permit a transmitting command (a write, programming, an armed `viz` or
    /// `mcp`) against a non-loopback (real) gateway. Required for any gateway
    /// that is not 127.0.0.0/8 or ::1 (or set BUSSARD_ALLOW_REAL_GATEWAY=1).
    /// Read-only commands ignore it.
    #[arg(long, global = true)]
    allow_remote_gateway: bool,
    /// Skip the pre-flight check that no bus device answers at bussard's own
    /// source individual address. That check stops two management clients
    /// sharing one source address, which interleaves their numbered telegrams
    /// inside one layer-4 session at the device and can silently corrupt a
    /// download. Only pass this for a gateway that misbehaves on the probe.
    /// Only management commands consult it.
    #[arg(long, global = true)]
    skip_address_check: bool,
    /// Ignore the stored device facts (`<dir>/.bussard/facts/<ia>.toml`) and
    /// read them from the device again (issue #209). Consulted by
    /// `reconstruct`, `describe`, `flash`, `plan` and `apply`.
    #[arg(long, global = true)]
    refresh_facts: bool,
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

/// What a subcommand does with the global options, as far as resolving them
/// is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Creates a model (`init`, `import`): the directory is `--dir`,
    /// `BUSSARD_DIR` or `knx`, never discovered upward.
    Creates,
    /// Talks to the bus; `slot` says whether the keyring also feeds the
    /// command itself (tool keys, group keys) or only the tunnel.
    Bus {
        /// The command consumes the keyring beyond opening the tunnel.
        slot: bool,
    },
    /// Works on the model files only (or on nothing: `diff`, `keyring`).
    Files,
}

impl Command {
    /// This subcommand's [`Role`].
    fn role(&self) -> Role {
        match self {
            Command::Init { .. } | Command::Import { .. } => Role::Creates,
            Command::Scan { .. }
            | Command::Assign { .. }
            | Command::Reconstruct { .. }
            | Command::Describe { .. }
            | Command::Flash { .. }
            | Command::Plan { .. }
            | Command::Apply { .. }
            | Command::Commission { .. }
            | Command::Backup { .. }
            | Command::Restore { .. }
            | Command::Replace { .. }
            | Command::Monitor { .. }
            | Command::Capture { .. }
            | Command::Read { .. }
            | Command::Write { .. }
            | Command::Viz { .. }
            | Command::Audit { .. }
            | Command::Learn { .. }
            | Command::Mcp { .. }
            // adopt takes a Data Secure device's tool key from it (#201).
            | Command::Adopt { .. } => Role::Bus { slot: true },
            Command::Test { .. } => Role::Bus { slot: false },
            _ => Role::Files,
        }
    }

    /// Whether the subcommand was given `--tool-key`. A keyring that did not
    /// come from `--keyring` then serves the tunnel only: the two are mutually
    /// exclusive tool-key sources.
    fn has_tool_key(&self) -> bool {
        match self {
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

    /// Whether the subcommand has a machine-readable output for `--json`.
    fn supports_json(&self) -> bool {
        matches!(
            self,
            Command::Export { .. }
                | Command::Diff { .. }
                | Command::Scan { .. }
                | Command::Reconstruct { .. }
                | Command::Describe { .. }
                | Command::Keyring { .. }
                | Command::Flash { .. }
                | Command::Plan { .. }
                | Command::Apply { .. }
                | Command::Commission { .. }
                | Command::Status { .. }
                | Command::History { .. }
                | Command::Device { .. }
                | Command::Backup { .. }
                | Command::Validate { .. }
                | Command::Groups { .. }
                | Command::Doc { .. }
                | Command::Monitor { .. }
                | Command::Test { .. }
                | Command::Audit { .. }
        )
    }
}

/// The global options, resolved once for the subcommand: flag, then
/// environment, then `bussard.toml`, then discovery or the built-in default.
#[derive(Debug)]
struct Resolved {
    /// The model directory.
    dir: PathBuf,
    /// `--gateway`, else `BUSSARD_GATEWAY`; `bussard.toml` is consulted later,
    /// by [`conn_cmd::resolve_config`].
    gateway: Option<String>,
    /// `--routing`.
    routing: bool,
    /// The keyring the command itself consumes (tool keys, group keys), when
    /// it has a use for one beyond the tunnel.
    keyring: Option<PathBuf>,
    /// `--json`.
    json: bool,
    /// `--allow-remote-gateway`.
    allow_remote_gateway: bool,
    /// `--skip-address-check`.
    skip_address_check: bool,
    /// `--refresh-facts`.
    refresh_facts: bool,
    /// The `-v` repeat count.
    verbose: u8,
}

impl Resolved {
    /// Connection overrides for a management command that consults the
    /// device facts (`reconstruct`, `describe`, `flash`, `plan`, `apply`).
    fn mgmt_with_facts(&self) -> conn_cmd::ConnOverrides {
        conn_cmd::ConnOverrides {
            refresh_facts: self.refresh_facts,
            ..self.mgmt()
        }
    }

    /// Connection overrides for a management command: the source-address
    /// check is consulted, the device facts are not.
    fn mgmt(&self) -> conn_cmd::ConnOverrides {
        conn_cmd::ConnOverrides {
            skip_address_check: self.skip_address_check,
            ..self.group()
        }
    }

    /// Connection overrides for a group-communication command (no
    /// source-address check, no device facts).
    fn group(&self) -> conn_cmd::ConnOverrides {
        conn_cmd::ConnOverrides {
            gateway: self.gateway.clone(),
            routing: self.routing,
            skip_address_check: false,
            refresh_facts: false,
        }
    }

    /// The keyring and tool key a management command identifies devices with.
    fn tool_keys<'a>(&'a self, tool_key: Option<&'a str>) -> secure_key::ToolKeySource<'a> {
        secure_key::ToolKeySource {
            keyring: self.keyring.as_deref(),
            tool_key,
        }
    }
}

/// Resolves the global options for `command` and sets up the KNXnet/IP Secure
/// tunnel credentials, once, before the subcommand runs, so every connection
/// it opens uses them.
fn resolve_globals(global: &Global, command: &Command) -> anyhow::Result<Resolved> {
    use anyhow::Context as _;
    if global.json && !command.supports_json() {
        anyhow::bail!(
            "`bussard {}` has no JSON output; drop --json",
            cli_name(command)
        );
    }
    let env = conn_cmd::EnvGlobals::from_process();
    let role = command.role();
    let dir = conn_cmd::resolve_model_dir(
        global.dir.as_deref(),
        env.dir.as_deref(),
        role == Role::Creates,
    );
    let gateway = conn_cmd::resolve_gateway(global.gateway.as_deref(), env.gateway.as_deref());
    let keyring = match role {
        // A keyring only ever serves a command that talks to the bus; a files
        // command must not ask for its password.
        Role::Bus { .. } => {
            conn_cmd::resolve_keyring(global.keyring.as_deref(), env.keyring.as_deref(), &dir)
        }
        Role::Creates | Role::Files => None,
    };
    let slot = match (role, &keyring) {
        (Role::Bus { slot: true }, Some(resolved))
            if !command.has_tool_key() || resolved.source == conn_cmd::KeyringSource::Flag =>
        {
            Some(resolved.path.clone())
        }
        _ => None,
    };

    // Without explicit flags, only a keyring can carry tunnelling users.
    if keyring.is_none() && global.secure_user.is_none() && global.secure_password_env.is_none() {
        if global.secure_transport.is_some() {
            anyhow::bail!(
                "--secure-transport needs KNXnet/IP Secure tunnelling credentials: pass --keyring \
                 <file.knxkeys> or --secure-user <id> --secure-password-env <VAR>"
            );
        }
    } else {
        let config = bussard_service::secure::tunnel_config(
            bussard_service::secure::TunnelCredentialSource {
                keyring: keyring.as_ref().map(|resolved| resolved.path.as_path()),
                user: global.secure_user,
                password_env: global.secure_password_env.as_deref(),
            },
        )
        .with_context(|| match &keyring {
            Some(resolved) if resolved.source != conn_cmd::KeyringSource::Flag => format!(
                "the keyring {} comes from {} (pass --keyring to use another one)",
                resolved.path.display(),
                resolved.source.describe()
            ),
            _ => "resolving the KNXnet/IP Secure tunnelling credentials".to_string(),
        })?;
        if let Some(resolved) = &keyring
            && resolved.source != conn_cmd::KeyringSource::Flag
        {
            tracing::info!(
                "using the keyring {} from {}",
                resolved.path.display(),
                resolved.source.describe()
            );
        }
        let config = match (config, global.secure_transport) {
            (Some(config), Some(transport)) => Some(config.with_transport(transport.into())),
            (None, Some(_)) => anyhow::bail!(
                "--secure-transport needs KNXnet/IP Secure tunnelling credentials, and the keyring \
                 lists no tunnelling user"
            ),
            (config, None) => config,
        };
        conn_cmd::set_secure_tunnel(config);
    }

    Ok(Resolved {
        dir,
        gateway,
        routing: global.routing,
        keyring: slot,
        json: global.json,
        allow_remote_gateway: global.allow_remote_gateway,
        skip_address_check: global.skip_address_check,
        refresh_facts: global.refresh_facts,
        verbose: global.verbose,
    })
}

/// The subcommand's name as typed (`export-groups`), for messages.
fn cli_name(command: &Command) -> String {
    let debug = format!("{command:?}");
    let variant = debug.split([' ', '{', '(']).next().unwrap_or_default();
    let mut name = String::new();
    for (i, c) in variant.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                name.push('-');
            }
            name.push(c.to_ascii_lowercase());
        } else {
            name.push(c);
        }
    }
    name
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
        /// The addressing scheme for a project that has none yet (default
        /// floor-trade-block). Refused when it contradicts `bussard.toml`.
        #[arg(long, value_enum)]
        scheme: Option<SchemeArg>,
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
        /// Leave the `.bussard/history` snapshots out.
        #[arg(long)]
        no_history: bool,
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
        /// Print a file-level TOML diff instead of sentences.
        #[arg(long, conflicts_with = "json")]
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
    },
    /// Assign an individual address to the device in programming mode.
    Assign {
        /// The address to assign, e.g. `1.1.47` (default: next free on the line).
        #[arg(value_name = "ADDRESS")]
        address: Option<String>,
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
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
        #[arg(long, value_name = "LINE", conflicts_with_all = ["address", "keyring"])]
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
        /// The device's vendor `.knxprod`, to read back and decode its parameter
        /// memory too (issue #119). Without it the archive in `<dir>/vendor/`
        /// whose catalogue carries the model's order number is used, when cached.
        #[arg(long, value_name = "FILE", conflicts_with = "line")]
        product: Option<PathBuf>,
        /// The application program id to decode the parameters with (default:
        /// the model's application ref, else the order number, else the sole one).
        #[arg(long, value_name = "REF", conflicts_with = "line")]
        application: Option<String>,
        /// Read the links and tables only: skip the parameter read-back and the
        /// product parse behind it (issue #215). On a large parameter segment
        /// that read-back is most of the command's time.
        #[arg(long, conflicts_with_all = ["line", "product", "application"])]
        no_parameters: bool,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with_all = ["keyring", "line"])]
        tool_key: Option<String>,
    },
    /// Introspect a device: enumerate its interface objects and each property's
    /// description (PID, type, element count, access levels) over the bus.
    Describe {
        /// The device to introspect, e.g. `1.1.4`.
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// Walk every object's property descriptions again, even when the
        /// device facts (`<dir>/.bussard/facts/<ia>.toml`) already hold them.
        #[arg(long)]
        full: bool,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
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
        /// Skip the interactive confirmation (dangerous; for scripts). Also
        /// consents to downloading the product data the device's order number
        /// needs.
        #[arg(long)]
        yes: bool,
        /// Do not download product data for the device's order number; adopt
        /// it without (identity and links by number) and say where to get it.
        #[arg(long)]
        no_download: bool,
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
        /// The device's BCU access key, in hex (e.g. `FFFFFFFF` or `0x11223344`),
        /// presented with A_Authorize on every management connect (issue #52).
        /// Unset presents the free-access key (FFFFFFFF) — correct for an unkeyed
        /// device (ETS uses free access by default). A keyed device needs its
        /// project key here or it will deny access.
        #[arg(long, value_name = "HEX")]
        bcu_key: Option<String>,
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
        /// Plan offline and stop: no gateway is resolved and no connection is
        /// opened. The plan is checked against the application's own mask.
        #[arg(long)]
        dry_run: bool,
        /// With `--dry-run`, write `plan.json` and the exact memory images the
        /// flash would stream (one `.bin` each, plus the table images) into DIR.
        #[arg(long, value_name = "DIR", requires = "dry_run")]
        dump_images: Option<PathBuf>,
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
        /// The device's vendor `.knxprod`, to read back and decode its parameter
        /// memory too (issue #119). Without it the archive in `<dir>/vendor/`
        /// whose catalogue carries the model's order number is used, when cached.
        #[arg(long, value_name = "FILE", conflicts_with = "line")]
        product: Option<PathBuf>,
        /// The application program id to decode the parameters with (default:
        /// the model's application ref, else the order number, else the sole one).
        #[arg(long, value_name = "REF", conflicts_with = "line")]
        application: Option<String>,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key. Prefer
        /// `--keyring` for a real installation: a process argument is visible to
        /// other users on the machine.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
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
        /// Line mode only: continue the run recorded in
        /// `<dir>/captures/apply-line-<line>.json`, skipping the devices it
        /// already finished.
        #[arg(long, requires = "line")]
        resume: bool,
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
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch. Prefer `--keyring` for a real installation.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
    },
    /// Show what has changed in the model since the last history snapshot.
    Status {
        /// Print the file-level diff instead of the plain-language rendering.
        #[arg(long)]
        raw: bool,
    },
    /// List the model's history snapshots, oldest first.
    History {},
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
        /// Print the paste-ready device-file TOML, with commented lines for
        /// what the file does not set yet.
        #[arg(long, conflicts_with = "json")]
        toml: bool,
    },
    /// Show what one snapshot changed (or the change between two snapshots).
    Show {
        /// The snapshot: its id, or its number from `bussard history`.
        #[arg(value_name = "SNAPSHOT")]
        snapshot: String,
        /// A second snapshot: show the change from the first one to this one.
        #[arg(value_name = "SNAPSHOT")]
        to: Option<String>,
    },
    /// Put the model files back to a history snapshot (files only, no devices).
    Undo {
        /// The snapshot to restore: its id, or its number from `bussard history`
        /// (default: the newest one that differs from the working files, which
        /// reverts the last change).
        #[arg(value_name = "SNAPSHOT")]
        snapshot: Option<String>,
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
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch for a simulator or a device with a synthetic key.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
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
        /// Skip the interactive confirmation (dangerous; for scripts).
        #[arg(long)]
        yes: bool,
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
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
        /// The raw 32-hex-character KNX Data Secure tool key — the test/bench
        /// escape hatch.
        #[arg(long, value_name = "HEX", conflicts_with = "keyring")]
        tool_key: Option<String>,
    },
    /// Validate the model and report diagnostics.
    Validate {
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
        /// The export format.
        #[arg(long, value_enum)]
        format: export_groups_cmd::ExportFormat,
        /// The file to write.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Render the handover documentation folder from the model.
    Doc {
        /// The directory to write the rendered documentation into.
        #[arg(long, default_value = "docs/installation")]
        out: PathBuf,
        /// The rendered format.
        #[arg(long, value_enum, default_value_t = DocOutputFormat::Md)]
        format: DocOutputFormat,
    },
    /// Live-monitor the bus, decoding telegrams against the model.
    Monitor {
        /// Only show telegrams matching this filter: a comma-separated list of
        /// GAs (`3/2/0`), GA prefixes (`3/` or `3/2/`) or IAs (`1.1.30`).
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
    },
    /// Capture telegrams to a SQLite database.
    Capture {
        /// The database file to write (created if absent).
        #[arg(long, value_name = "DB")]
        to: PathBuf,
        /// Only capture telegrams matching this filter (see `monitor --filter`).
        #[arg(long, value_name = "EXPR")]
        filter: Option<String>,
    },
    /// Read a group value from the bus (sends a GroupValueRead, prints the
    /// typed response; exits non-zero on timeout).
    Read {
        /// The group address to read, e.g. `3/2/0`.
        #[arg(value_name = "GA")]
        ga: String,
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
    },
    /// Generate the Home Assistant KNX integration YAML from the model.
    HaConfig {
        /// Output file (default: stdout).
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Serve the KNX visualization website (topology, GA tree, live traffic).
    Viz {
        /// The address to bind the HTTP server to.
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
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
    },
    /// Run the scripted acceptance tests in `tests.toml` against the bus.
    Test {
        /// The test file to run (default: `<dir>/tests.toml`).
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
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
        /// Add the live part: gateway description, traffic sample and a probe of
        /// every modelled device. Read tier only; never sends a group telegram.
        #[arg(long)]
        live: bool,
        /// Traffic-sample window in seconds for `--live`.
        #[arg(long, value_name = "SECS", default_value_t = 30, requires = "live")]
        window: u64,
    },
    /// Run the MCP server over stdio: model tools and bus reads by default;
    /// bus writes and device programming only when their flags allow it.
    Mcp {
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
    let cli = Cli::parse();

    // The live progress display (issue #147) is only possible on a terminal;
    // when it is, bus-layer events also feed its "last event" line, and log
    // lines hide the bar while they print. Off a terminal both are inert.
    let live_progress = progress::init(cli.global.no_progress);
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
                    .with_filter(verbosity_filter(cli.global.verbose)),
            )
            .with(events)
            .init();
    }

    // Opt-in wall-clock telemetry (issue #78): `--timing` reports the
    // invocation's elapsed time on stderr. Speed is a project goal, so this stays
    // available for regression spotting, but a plain 0.1.0 run is quiet.
    let started = timing::start();
    let globals = match timing::time("tunnel creds", || {
        resolve_globals(&cli.global, &cli.command)
    }) {
        Ok(globals) => globals,
        Err(err) => {
            eprintln!("error: {err:#}");
            return ExitCode::FAILURE;
        }
    };
    let result = run(cli.command, &globals);
    // A connect error that retrying cannot fix (a secure-only interface
    // without credentials, a refused KNXnet/IP Secure password; issue #182) is
    // the real cause of whatever the command reported next; name it alone.
    if let Some(fatal) = bussard_bus::fatal_connect_error() {
        eprintln!("error: {fatal}");
        if cli.global.timing {
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
    if cli.global.timing {
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
/// `g` holds the resolved global options; `flash` and `plan` use its `-v`
/// count to unfold the memory-level plan under the parameter-level one
/// (issue #109).
fn run(command: Command, g: &Resolved) -> anyhow::Result<ExitCode> {
    let dir = g.dir.as_path();
    let json = g.json;
    match command {
        Command::Scan { line, from, to } => {
            scan_cmd::run(&line, from, to, dir, json, g.keyring.as_deref(), g.mgmt())
        }
        Command::Assign {
            address,
            yes,
            tool_key,
        } => assign_cmd::run(
            address.as_deref(),
            dir,
            yes,
            g.allow_remote_gateway,
            // `--tool-key` overrides the keyring's device entries; the keyring
            // still opens a KNXnet/IP Secure tunnel (issue #203).
            secure_key::ToolKeySource {
                keyring: g.keyring.as_deref().filter(|_| tool_key.is_none()),
                tool_key: tool_key.as_deref(),
            },
            g.mgmt(),
        ),
        Command::Reconstruct {
            address,
            line,
            from,
            to,
            out,
            product,
            application,
            no_parameters,
            tool_key,
        } => {
            let overrides = g.mgmt_with_facts();
            match line {
                Some(line) => {
                    reconstruct_cmd::run_line(&line, from, to, out.as_deref(), dir, json, overrides)
                }
                None => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    reconstruct_cmd::run(
                        &address,
                        dir,
                        json,
                        overrides,
                        param_readback::Selection {
                            product: product.as_deref(),
                            application: application.as_deref(),
                        },
                        no_parameters,
                        g.tool_keys(tool_key.as_deref()),
                    )
                }
            }
        }
        Command::Describe {
            address,
            full,
            tool_key,
        } => describe_cmd::run(
            &address,
            dir,
            json,
            describe_cmd::FactsOptions {
                full,
                refresh: g.refresh_facts,
            },
            g.tool_keys(tool_key.as_deref()),
            g.mgmt(),
        ),
        Command::Keyring { file } => keyring_cmd::run(&file, json),
        Command::ImportProduct {
            file,
            order_number,
            yes_download,
            inner,
            list,
        } => import_product_cmd::run(
            file.as_deref(),
            dir,
            order_number.as_deref(),
            yes_download,
            inner.as_deref(),
            list,
        ),
        Command::Adopt {
            product,
            yes,
            no_download,
        } => adopt_cmd::run(
            product.as_deref(),
            dir,
            yes,
            no_download,
            g.allow_remote_gateway,
            g.keyring.as_deref(),
            g.mgmt(),
        ),
        Command::Flash {
            address,
            product,
            application,
            order_number,
            yes,
            force,
            full,
            no_factory_reset,
            parameters_only,
            bcu_key,
            tool_key,
            secure_sender,
            dry_run,
            dump_images,
        } => flash_cmd::run(
            &address,
            product.as_deref(),
            application.as_deref(),
            order_number.as_deref(),
            dir,
            yes,
            force,
            full,
            no_factory_reset,
            parameters_only,
            g.allow_remote_gateway,
            bcu_key.as_deref(),
            g.tool_keys(tool_key.as_deref()),
            secure_sender,
            g.mgmt_with_facts(),
            flash_cmd::FlashOutput {
                json,
                verbose: g.verbose,
                dry_run: dry_run.then_some(flash_cmd::DryRun { dump_images }),
            },
        ),
        Command::Plan {
            address,
            line,
            product,
            application,
            tool_key,
        } => {
            let overrides = g.mgmt_with_facts();
            let tool_key_source = g.tool_keys(tool_key.as_deref());
            match line {
                Some(line) => line_cmd::run_plan(&line, dir, json, tool_key_source, overrides),
                None => {
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    plan_cmd::run(
                        &address,
                        dir,
                        json,
                        overrides,
                        param_readback::Selection {
                            product: product.as_deref(),
                            application: application.as_deref(),
                        },
                        tool_key_source,
                        g.verbose,
                    )
                }
            }
        }
        Command::Apply {
            address,
            line,
            resume,
            yes,
            plan_hash,
            product,
            application,
            tool_key,
            secure_sender,
        } => {
            let overrides = g.mgmt_with_facts();
            let tool_key_source = g.tool_keys(tool_key.as_deref());
            match line {
                Some(line) => line_cmd::run_apply(
                    &line,
                    dir,
                    yes,
                    json,
                    resume,
                    g.allow_remote_gateway,
                    tool_key_source,
                    overrides,
                ),
                None => {
                    if json {
                        anyhow::bail!(
                            "`bussard apply --json` needs --line: a single-device apply has no \
                             JSON output"
                        );
                    }
                    // clap guarantees ADDRESS is present when --line is absent.
                    let address = address.expect("clap requires ADDRESS without --line");
                    apply_cmd::run(
                        &address,
                        dir,
                        yes,
                        g.allow_remote_gateway,
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
            yes,
            tool_key,
        } => commission_cmd::run(
            &line,
            dir,
            commission_cmd::CommissionOptions {
                flash,
                apply,
                labels: labels.as_deref(),
                product: product.as_deref(),
                yes,
                json,
                allow_remote_gateway: g.allow_remote_gateway,
            },
            g.tool_keys(tool_key.as_deref()),
            g.mgmt(),
        ),
        Command::Status { raw } => history_cmd::run_status(dir, json, raw),
        Command::History {} => history_cmd::run_history(dir, json),
        Command::Device {
            address,
            channel,
            toml,
        } => device_cmd::run(&address, channel.as_deref(), dir, toml, json),
        Command::Show { snapshot, to } => history_cmd::run_show(dir, &snapshot, to.as_deref()),
        Command::Undo { snapshot } => history_cmd::run_undo(dir, snapshot.as_deref()),
        Command::Backup {
            addresses,
            line,
            out,
            tool_key,
        } => backup_cmd::run(
            &addresses,
            line.as_deref(),
            out.as_deref(),
            dir,
            json,
            g.tool_keys(tool_key.as_deref()),
            g.mgmt(),
        ),
        Command::Restore {
            backup_dir,
            address,
            yes,
            tool_key,
        } => restore_cmd::run(
            &backup_dir,
            &address,
            dir,
            yes,
            g.allow_remote_gateway,
            g.tool_keys(tool_key.as_deref()),
            g.mgmt(),
        ),
        Command::Replace {
            address,
            product,
            yes,
            force,
            no_flash,
            bcu_key,
            tool_key,
        } => replace_cmd::run(
            &address,
            &product,
            dir,
            yes,
            force,
            no_flash,
            g.allow_remote_gateway,
            bcu_key.as_deref(),
            g.tool_keys(tool_key.as_deref()),
            g.mgmt(),
        ),
        Command::Validate { format } => validate_cmd::run(dir, json || format == Format::Json),
        Command::Groups { command } => match command {
            GroupsCommand::Reserve {
                room,
                functions,
                scheme,
            } => groups_cmd::run_reserve(dir, &room, &functions, scheme.map(Into::into), json),
        },
        Command::ExportGroups { format, out } => export_groups_cmd::run(dir, format, &out),
        Command::Doc { out, format } => doc_cmd::run(dir, &out, format.into(), json),
        Command::Init {
            project,
            password,
            yes,
            no_download,
            scan,
        } => init_cmd::run(
            dir,
            g.gateway.as_deref(),
            g.routing,
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
            mine,
            theirs,
            interactive,
            yes,
            no_download,
        } => {
            let choice = import_bundle::ConflictChoice::from_flags(mine, theirs, interactive);
            let consent = product_fetch::Consent { yes, no_download };
            if let Some(json) = from_json {
                import_cmd::run_json(&json, dir, choice, consent)
            } else if let Some(project) = project {
                if bussard_model::bundle::is_bundle_path(&project) {
                    import_bundle::run_bundle(&project, dir, choice)
                } else {
                    import_cmd::run_knxproj(&project, dir, password, choice, consent)
                }
            } else {
                anyhow::bail!("provide a .knxproj path or --from-json <file>")
            }
        }
        Command::Export { file, no_history } => {
            export_cmd::run(file.as_deref(), dir, no_history, json)
        }
        Command::Diff {
            a,
            b,
            raw,
            password,
            password_b,
        } => diff_cmd::run(&a, &b, json, raw, password, password_b),
        Command::Monitor { filter } => monitor_cmd::run(
            dir,
            json,
            filter.as_deref(),
            g.keyring.as_deref(),
            g.group(),
        ),
        Command::Capture { to, filter } => {
            capture_cmd::run(&to, dir, filter.as_deref(), g.keyring.as_deref(), g.group())
        }
        Command::Read { ga } => read_cmd::run(&ga, dir, g.keyring.as_deref(), g.group()),
        Command::Write {
            ga,
            value,
            dpt,
            force,
            yes,
        } => write_cmd::run(
            &ga,
            &value,
            dpt.as_deref(),
            force,
            yes,
            g.allow_remote_gateway,
            dir,
            g.keyring.as_deref(),
            g.group(),
        ),
        Command::HaConfig { out } => ha_config_cmd::run(dir, out.as_deref()),
        Command::Viz {
            listen,
            watch_prog,
            allow_writes,
            allow_host,
        } => viz_cmd::run(
            listen,
            dir,
            g.group(),
            viz_cmd::VizOptions {
                allow_writes,
                watch_prog,
                allow_remote_gateway: g.allow_remote_gateway,
                allowed_hosts: allow_host,
                keyring: g.keyring.clone(),
            },
        ),
        Command::Learn {
            gas,
            unnamed,
            untyped,
            yes,
            timeout,
        } => learn_cmd::run(
            dir,
            learn_cmd::LearnOptions {
                gas,
                unnamed,
                untyped,
                yes,
                timeout_seconds: timeout,
                keyring: g.keyring.clone(),
            },
            g.group(),
        ),
        Command::Test {
            secure_idle: Some(secs),
            ..
        } => test_cmd::run_secure_idle(dir, std::time::Duration::from_secs(secs), json, g.group()),
        Command::Test {
            file,
            force,
            skip_manual,
            only,
            yes,
            secure_idle: None,
        } => test_cmd::run(
            dir,
            test_cmd::TestOptions {
                file,
                json,
                force,
                skip_manual,
                only,
                yes,
                allow_remote_gateway: g.allow_remote_gateway,
            },
            g.group(),
        ),
        Command::Audit { live, window } => audit_cmd::run(
            dir,
            audit_cmd::AuditOptions {
                json,
                live,
                window: std::time::Duration::from_secs(window),
                keyring: g.keyring.as_deref(),
            },
            g.mgmt(),
        ),
        Command::Mcp {
            passive,
            allow_writes,
            allow_programming,
            plan_ttl_minutes,
            no_model_edits,
            capture_db,
        } => mcp_cmd::run(
            dir,
            g.group(),
            mcp_cmd::McpModes {
                passive,
                allow_writes,
                allow_programming,
                plan_ttl: std::time::Duration::from_secs(plan_ttl_minutes.saturating_mul(60)),
                allow_remote_gateway: g.allow_remote_gateway,
                no_model_edits,
            },
            capture_db,
            g.keyring.clone(),
        ),
    }
}
