//! `bussard` — an open-source CLI for KNX.
//!
//! Each subcommand lives in its own `*_cmd` module as an arguments struct that
//! runs itself ([`cli::Run`]); `main` parses, resolves the global options once
//! and hands them to it.

mod adopt_cmd;
mod apply_cmd;
mod assign_cmd;
mod audit_cmd;
mod backup_cmd;
mod capture_cmd;
mod certificate_view;
mod cli;
mod commission_cmd;
mod confirm;
mod conn_cmd;
mod console;
mod describe_cmd;
mod device_cmd;
mod diff_cmd;
mod doc_cmd;
mod enroll_cmd;
mod export_cmd;
mod export_groups_cmd;
mod flash_cmd;
mod flash_handover;
mod flash_params;
mod groups_cmd;
mod ha_config_cmd;
mod history_cmd;
mod import_bundle;
mod import_cmd;
mod import_product_cmd;
mod init_cmd;
mod interface_cmd;
mod interface_secure_cmd;
mod interface_session;
mod keys_cmd;
mod learn_cmd;
mod line_cmd;
mod lock_pin;
mod mcp_cmd;
mod monitor_cmd;
mod output;
mod param_readback;
mod plan_cmd;
mod plan_view;
mod product_store;
mod progress;
mod read_cmd;
mod reconstruct_cmd;
mod replace_cmd;
mod restart_cmd;
mod restore_cmd;

mod scan_cmd;
mod secure_diag_cmd;
mod secure_key;
mod status_cmd;
mod style;
mod test_cmd;
mod timing;
mod validate_cmd;
mod viz_cmd;
mod write_cmd;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use crate::cli::{Resolved, Role, Run, Spec};

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
    /// The project folder. Default: `BUSSARD_DIR`, else discovered: `.` when
    /// it holds `bussard.toml`, else `./knx`, else the nearest parent holding
    /// `bussard.toml` (or `knx/bussard.toml`), else `knx`. `init` and `import`
    /// create the project in `--dir`, `BUSSARD_DIR` or `knx` and never search.
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
    /// Manage the KNX IP interface at `--gateway` itself over a KNXnet/IP
    /// device management connection instead of a tunnel (issue #523): for
    /// `plan`/`apply` of an interface, `describe` of it and `interface
    /// secure`. Needs no tunnelling slot and no address of the
    /// tunnel, so it reaches an interface whose slots are taken, whose
    /// tunnel address is duplicated, or that is factory-fresh. Inside
    /// KNXnet/IP Secure it authenticates as the management user (the
    /// `ManagementPassword` the key store or keyring holds for the interface).
    #[arg(long, global = true)]
    device_management: bool,
    /// An ETS `.knxkeys` keyring. Its tunnelling users open a KNXnet/IP Secure
    /// tunnel, its device entries carry the KNX Data Secure tool keys for
    /// management, and its group keys secure and decrypt group telegrams.
    /// Default: `BUSSARD_KEYRING`, else the key store `bussard.keys`, else
    /// `connection.keyring` in `bussard.toml`. The password comes from `BUSSARD_KEYRING_PASSWORD`,
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
    /// source address. That check stops two management clients
    /// sharing one source address, which interleaves their numbered telegrams
    /// inside one layer-4 session at the device and can silently corrupt a
    /// download. Only pass this for a gateway that misbehaves on the probe.
    /// Only management commands consult it.
    #[arg(long, global = true)]
    skip_address_check: bool,
    /// Ignore the stored device facts (`<dir>/.bussard/facts/<ia>.toml`) and
    /// read them from the device again. Consulted by
    /// `reconstruct`, `describe`, `flash`, `plan` and `apply`.
    // Issue #209.
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
    /// interface's tunnelling users picks one automatically.
    // Issue #71.
    #[arg(long, global = true, value_name = "ID")]
    secure_user: Option<u8>,
    /// KNXnet/IP Secure: the name of the environment variable that holds the
    /// `--secure-user` password (never the password itself).
    #[arg(long, global = true, value_name = "VAR")]
    secure_password_env: Option<String>,
    /// KNXnet/IP Secure: how the secure session's TCP connect is handled.
    /// A unicast secure session runs over TCP only (KNX IP Secure 3/8/9
    /// §2.2.3.3). Default `auto`: an interface that refuses TCP
    /// but advertises Secure is reported with the likely causes; `tcp`
    /// reports the refusal as it is.
    // Issue #513.
    #[arg(long, global = true, value_enum, value_name = "TRANSPORT")]
    secure_transport: Option<SecureTransportArg>,
}

/// The `--secure-transport` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SecureTransportArg {
    /// TCP; explains a refused connect when the interface advertises Secure.
    Auto,
    /// TCP, a refused connect reported as it is.
    Tcp,
}

impl From<SecureTransportArg> for bussard_transport::SecureTransport {
    fn from(arg: SecureTransportArg) -> Self {
        match arg {
            SecureTransportArg::Auto => bussard_transport::SecureTransport::Auto,
            SecureTransportArg::Tcp => bussard_transport::SecureTransport::Tcp,
        }
    }
}

/// Resolves the global options for `command` (typed as `name`) and sets up
/// the KNXnet/IP Secure tunnel credentials, once, before the subcommand runs,
/// so every connection it opens uses them.
fn resolve_globals(global: &Global, name: &str, spec: Spec) -> anyhow::Result<Resolved> {
    use anyhow::Context as _;
    if global.json && !spec.json {
        anyhow::bail!("`bussard {name}` has no JSON output; drop --json");
    }
    // The `.env` (issue #251), in two steps: `BUSSARD_DIR` may come from the
    // working directory's `.env` and decides the model directory; the `.env`
    // the lookup order then finds for that directory supplies every other
    // `BUSSARD_*` variable, behind the process environment.
    if global.device_management && !spec.device_management {
        anyhow::bail!(
            "--device-management manages a KNX IP interface itself; only `plan`, `apply`, \
             `describe` and `interface secure` take it, not `bussard {name}`"
        );
    }
    let cwd = std::path::Path::new(".");
    let role = spec.role;
    let dir = conn_cmd::resolve_model_dir(
        global.dir.as_deref(),
        conn_cmd::dir_before_dotenv(cwd).as_deref(),
        role == Role::Creates,
    );
    conn_cmd::apply_dotenv(&dir, cwd);
    let env = conn_cmd::EnvGlobals::from_process();
    // The product store (issue #228): move an earlier `vendor/` into
    // `products/` and regenerate `.bussard/models/` when it is missing, before
    // the command reads the model. `init` creates, `import` does this itself.
    if role != Role::Creates && spec.products && dir.is_dir() {
        timing::time("product store", || {
            bussard_service::files::products::prepare(&dir, &mut console::Console)
        });
    }
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
            if !spec.tool_key || resolved.source == conn_cmd::KeyringSource::Flag =>
        {
            Some(resolved.path.clone())
        }
        _ => None,
    };

    // Without explicit flags, only a keyring can carry tunnelling users.
    if keyring.is_none() && global.secure_user.is_none() && global.secure_password_env.is_none() {
        if global.secure_transport.is_some() {
            anyhow::bail!(
                "--secure-transport needs KNXnet/IP Secure tunnelling credentials: {}",
                bussard_service::guidance::tunnel_credentials_hint()
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
        // Mark the tunnelling user a tunnel holds, so another bussard process
        // for this model picks a different one (issue #287).
        let config = match config {
            Some(config) if dir.is_dir() => {
                Some(config.with_user_lock_dir(dir.join(".bussard").join("tunnel-users")))
            }
            other => other,
        };
        conn_cmd::set_secure_tunnel(config);
    }

    Ok(Resolved {
        dir,
        gateway,
        routing: global.routing,
        device_management: global.device_management,
        keyring: slot,
        json: global.json,
        allow_remote_gateway: global.allow_remote_gateway,
        skip_address_check: global.skip_address_check,
        refresh_facts: global.refresh_facts,
        verbose: global.verbose,
    })
}

/// Maps a `-v` repeat count to a tracing `EnvFilter` directive string, unless an
/// explicit `RUST_LOG` is set (which always wins). `0` → `warn` (the default).
fn verbosity_filter(verbose: u8) -> tracing_subscriber::EnvFilter {
    let filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => {
            let level = match verbose {
                0 => "warn",
                1 => "info",
                2 => "debug",
                _ => "trace",
            };
            tracing_subscriber::EnvFilter::new(level)
        }
    };
    cap_rmcp(filter)
}

/// Caps the MCP SDK's own events at `info`, whatever `RUST_LOG` or `-v` say.
///
/// At `debug` rmcp logs every request with its raw arguments, which would put
/// a `password` argument of `knx_import_file` or `knx_export` in the log
/// (issue #743). bussard logs each `tools/call` itself, with string values
/// redacted (`bussard_mcp::args::redact_strings`).
fn cap_rmcp(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    match "rmcp=info".parse() {
        Ok(directive) => filter.add_directive(directive),
        Err(_) => filter,
    }
}

/// The top-level subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a fresh project: discover the gateway, write the
    /// skeleton, then import the ETS project (the one given, or the one
    /// `.knxproj` next to the directory) or offer to scan the line.
    Init(init_cmd::InitArgs),
    /// Import a `.knxproj`, a `.bussard` bundle or an xknxproject JSON dump.
    Import(import_cmd::ImportArgs),
    /// Write the project and its history as one `.bussard` file to hand over.
    Export(export_cmd::ExportArgs),
    /// Explain what changes between two projects, as plain sentences.
    Diff(diff_cmd::DiffArgs),
    /// Scan a line for devices: mask version, manufacturer, order number.
    Scan(scan_cmd::ScanArgs),
    /// Assign an address to the device in programming mode.
    Assign(assign_cmd::AssignArgs),
    /// Read a device's tables back over the bus and diff them against the project,
    /// or (with `--line`) sweep a whole line and synthesize a fresh project.
    Reconstruct(reconstruct_cmd::ReconstructArgs),
    /// Introspect a device: enumerate its interface objects and each property's
    /// description (PID, type, element count, access levels) over the bus.
    Describe(describe_cmd::DescribeArgs),
    /// Manage the KNX Secure key store, `bussard.keys` next to
    /// `bussard.lock`: import an ETS `.knxkeys`, export one for ETS, show a
    /// summary. Key material is NEVER printed.
    ///
    /// The store is encrypted with the password in
    /// `BUSSARD_KEYRING_PASSWORD` and meant to be committed with the project.
    // Issue #241.
    #[command(subcommand)]
    Keys(keys_cmd::KeysCommand),
    /// Import vendor product data (`.knxprod`): store it under `products/`,
    /// pin it in `bussard.lock` and generate its product models.
    ///
    /// Give a local `.knxprod` FILE, or `--order-number` to look the file up in
    /// the pointer index and download it from the vendor, or `--list` to show
    /// the index. From an ETS project export (`.knxproj`) FILE every
    /// application program is extracted once into `products/`.
    ImportProduct(import_product_cmd::ImportProductArgs),
    /// Guide a new device from programming mode into the project (assign +
    /// product data + links scaffolding).
    Adopt(adopt_cmd::AdoptArgs),
    /// Download the full application program into a device (a fresh device, or
    /// one whose application changes). Everyday changes go through `apply`.
    Flash(flash_cmd::FlashArgs),
    /// Show what `apply` would write to a device (links and, with product
    /// data, parameters) without writing; or (with `--line`) plan every
    /// device of the project on a line. Read-only on the bus.
    Plan(plan_cmd::PlanArgs),
    /// Write the project to a device: validate, read the device, show the plan,
    /// ask once, back up, write only what differs (links and parameter
    /// octets), verify. With `--line`, every device of the project on a line.
    Apply(apply_cmd::ApplyArgs),
    /// Bench mode: walk the project's devices on a line, prompt for each device's
    /// programming button, verify its order number, assign its address, and
    /// print a label.
    // Issue #100.
    Commission(commission_cmd::CommissionArgs),
    /// Show what has changed in the project since the last history snapshot,
    /// or, given a device ADDRESS, read that device's live state over the bus:
    /// its identity and, for a KNX IP interface, its IP settings, MAC address,
    /// tunnelling addresses and state.
    // Issue #391.
    Status(status_cmd::StatusArgs),
    /// List the project's history snapshots, oldest first.
    History(history_cmd::HistoryArgs),
    /// Show what a device can do, in its device file's words: its channels or
    /// ETS parameter pages (inactive ones marked with what enables them), and
    /// for one channel or page its parameters (value, choices, default) and
    /// objects.
    Device(device_cmd::DeviceArgs),
    /// Show what one snapshot changed (or the change between two snapshots).
    Show(history_cmd::ShowArgs),
    /// Put the project files back to a history snapshot (files only, no devices).
    Undo(history_cmd::UndoArgs),
    /// Snapshot every device in the installation: tables, and where bussard can
    /// bound the read, the writable parameter memory.
    ///
    /// Read-only on the bus. Writes one JSON file per device plus a
    /// `manifest.json` that lists every device considered, including the ones
    /// whose mask bussard cannot read.
    // Issue #96.
    Backup(backup_cmd::BackupArgs),
    /// Write a device's backed-up link tables back onto it, or
    /// with `--parameters` its backed-up parameter memory.
    ///
    /// `restore <BACKUP_DIR> <ADDRESS>` runs the same plan, confirm, back up,
    /// write and verify path as `apply`, with the backup as the desired state
    /// instead of the project. `restore --parameters <BACKUP_JSON> <ADDRESS>`
    /// replays a parameter backup with `apply`'s parameter-only download.
    // Issues #96, #290.
    Restore(restore_cmd::RestoreArgs),
    /// Restart a device (the application restarts, nothing is erased) in the
    /// form ETS uses for it: the confirmed restart for a System B application
    /// that supports Secure, else a bare `A_Restart`. Then wait until it
    /// answers again. The device may transmit its status objects as it starts.
    Restart(restart_cmd::RestartArgs),
    /// Replace a dead device: assign, flash, apply and record, in one guided
    /// flow with one confirmation.
    // Issue #98.
    Replace(replace_cmd::ReplaceArgs),
    /// Validate the project and report diagnostics (`--json` for the
    /// machine-readable report).
    Validate(validate_cmd::ValidateArgs),
    /// Work with the group-address plan (`groups.toml`): reserve the
    /// conventional addresses for a room.
    #[command(subcommand)]
    Groups(groups_cmd::GroupsCommand),
    /// KNX IP interface commands: `interface secure on|off <address>`.
    #[command(subcommand)]
    Interface(interface_secure_cmd::InterfaceCommand),
    /// KNX Data Secure device diagnostics: `secure diag <address>`.
    #[command(subcommand)]
    Secure(secure_diag_cmd::SecureCommand),
    /// Export the group-address plan in a format ETS can import.
    ExportGroups(export_groups_cmd::ExportGroupsArgs),
    /// Render the handover documentation folder from the project.
    Doc(doc_cmd::DocArgs),
    /// Live-monitor the bus, decoding telegrams against the project.
    Monitor(monitor_cmd::MonitorArgs),
    /// Capture telegrams to a SQLite database.
    Capture(capture_cmd::CaptureArgs),
    /// Read a group value from the bus (sends a GroupValueRead, prints the
    /// typed response; exits non-zero on timeout).
    Read(read_cmd::ReadArgs),
    /// Write a group value to the bus, e.g. `bussard write 3/0/4 down`.
    Write(write_cmd::WriteArgs),
    /// Generate the Home Assistant KNX integration YAML from the project.
    HaConfig(ha_config_cmd::HaConfigArgs),
    /// Serve the KNX visualization website (topology, GA tree, live traffic).
    Viz(viz_cmd::VizArgs),
    /// Name and type group addresses from live traffic (never transmits).
    Learn(learn_cmd::LearnArgs),
    /// Run the scripted acceptance tests in `tests.toml` against the bus.
    Test(test_cmd::TestArgs),
    /// Audit the installation: project gaps, one-sided links, what bussard can do
    /// per device mask, KNX Secure coverage; with `--live`, the gateway's tunnel
    /// slots, a traffic sample and a scan of the project's devices. Read-only.
    Audit(audit_cmd::AuditArgs),
    /// Run the MCP server over stdio (or streamable HTTP with `--listen`):
    /// project tools and bus reads by default; bus writes and device
    /// programming only when their flags allow it.
    // The tier flags' help and the tool counts are built from the registration
    // tables in `bussard_mcp::tier_help`, so they cannot drift (issue #704).
    #[command(after_help = bussard_mcp::tier_help::tier_counts_help())]
    Mcp(mcp_cmd::McpArgs),
}

impl Command {
    /// The subcommand's arguments, for resolving the global options.
    fn args(&self) -> &dyn Run {
        match self {
            Command::Init(args) => args,
            Command::Import(args) => args,
            Command::Export(args) => args,
            Command::Diff(args) => args,
            Command::Scan(args) => args,
            Command::Assign(args) => args,
            Command::Reconstruct(args) => args,
            Command::Describe(args) => args,
            Command::Keys(args) => args,
            Command::ImportProduct(args) => args,
            Command::Adopt(args) => args,
            Command::Flash(args) => args,
            Command::Plan(args) => args,
            Command::Apply(args) => args,
            Command::Commission(args) => args,
            Command::Status(args) => args,
            Command::History(args) => args,
            Command::Device(args) => args,
            Command::Show(args) => args,
            Command::Undo(args) => args,
            Command::Backup(args) => args,
            Command::Restore(args) => args,
            Command::Restart(args) => args,
            Command::Replace(args) => args,
            Command::Validate(args) => args,
            Command::Groups(args) => args,
            Command::Interface(args) => args,
            Command::Secure(args) => args,
            Command::ExportGroups(args) => args,
            Command::Doc(args) => args,
            Command::Monitor(args) => args,
            Command::Capture(args) => args,
            Command::Read(args) => args,
            Command::Write(args) => args,
            Command::HaConfig(args) => args,
            Command::Viz(args) => args,
            Command::Learn(args) => args,
            Command::Test(args) => args,
            Command::Audit(args) => args,
            Command::Mcp(args) => args,
        }
    }

    /// Runs the subcommand.
    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        match self {
            Command::Init(args) => args.run(g),
            Command::Import(args) => args.run(g),
            Command::Export(args) => args.run(g),
            Command::Diff(args) => args.run(g),
            Command::Scan(args) => args.run(g),
            Command::Assign(args) => args.run(g),
            Command::Reconstruct(args) => args.run(g),
            Command::Describe(args) => args.run(g),
            Command::Keys(args) => args.run(g),
            Command::ImportProduct(args) => args.run(g),
            Command::Adopt(args) => args.run(g),
            Command::Flash(args) => args.run(g),
            Command::Plan(args) => args.run(g),
            Command::Apply(args) => args.run(g),
            Command::Commission(args) => args.run(g),
            Command::Status(args) => args.run(g),
            Command::History(args) => args.run(g),
            Command::Device(args) => args.run(g),
            Command::Show(args) => args.run(g),
            Command::Undo(args) => args.run(g),
            Command::Backup(args) => args.run(g),
            Command::Restore(args) => args.run(g),
            Command::Restart(args) => args.run(g),
            Command::Replace(args) => args.run(g),
            Command::Validate(args) => args.run(g),
            Command::Groups(args) => args.run(g),
            Command::Interface(args) => args.run(g),
            Command::Secure(args) => args.run(g),
            Command::ExportGroups(args) => args.run(g),
            Command::Doc(args) => args.run(g),
            Command::Monitor(args) => args.run(g),
            Command::Capture(args) => args.run(g),
            Command::Read(args) => args.run(g),
            Command::Write(args) => args.run(g),
            Command::HaConfig(args) => args.run(g),
            Command::Viz(args) => args.run(g),
            Command::Learn(args) => args.run(g),
            Command::Test(args) => args.run(g),
            Command::Audit(args) => args.run(g),
            Command::Mcp(args) => args.run(g),
        }
    }
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
    let matches = Cli::command().get_matches();
    let name = matches.subcommand_name().unwrap_or_default().to_string();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => err.format(&mut Cli::command()).exit(),
    };

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
    // One confirmation rule (issue #228): these commands, run without a
    // terminal and without --yes, are refused here, before the model loads, a
    // keyring is decrypted or a connection opens.
    if let Some((yes, action)) = cli.command.args().early_consent()
        && let Err(err) = confirm::require_terminal_or_yes(yes, &action)
    {
        eprintln!("error: {err:#}");
        return ExitCode::FAILURE;
    }
    let globals = match timing::time("tunnel creds", || {
        resolve_globals(&cli.global, &name, cli.command.args().spec())
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

/// Runs a subcommand, returning the process exit code on success.
fn run(command: Command, g: &Resolved) -> anyhow::Result<ExitCode> {
    // One manufacturer lookup for every command (issue #788): the model's
    // list from the imported ETS master data, then the built-in table.
    bussard_mgmt::manufacturers::load_model_dir(g.dir());
    command.run(g)
}
