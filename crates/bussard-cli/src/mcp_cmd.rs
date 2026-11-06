//! The `bussard mcp` subcommand: run the MCP server over stdio, or over
//! streamable HTTP with `--listen` (issue #265).
//!
//! On a missing or empty `--dir` the server starts in its onboarding state
//! (issue #745): `knx_setup` and `knx_bus_status` only, until `knx_setup`
//! has written the model. Otherwise the model must load. The bus
//! connection is resolved from the model's `bussard.toml` plus overrides, but is
//! opened lazily by the server's stream task, which reconnects — so a bus that
//! is down at startup does not stop the server. All logging is on stderr
//! (configured in `main`); on stdio, stdout carries only the MCP wire.

use std::io::IsTerminal as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_mcp::McpConfig;
use bussard_mcp::http::{HttpOptions, TOKEN_ENV};
use bussard_model::Model;

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{ConnOverrides, resolve_config};

/// `bussard mcp`. The tier flags' help comes from `bussard_mcp::tier_help`.
#[derive(Debug, clap::Args)]
pub(crate) struct McpArgs {
    #[arg(long, help = bussard_mcp::tier_help::passive_help())]
    passive: bool,
    #[arg(
        long,
        conflicts_with = "passive",
        help = bussard_mcp::tier_help::allow_writes_help()
    )]
    allow_writes: bool,
    // The programming tools write one device after an approved plan
    // (issues #118, #717).
    #[arg(
        long,
        conflicts_with = "passive",
        help = bussard_mcp::tier_help::allow_programming_help()
    )]
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
    #[arg(long, help = bussard_mcp::tier_help::no_model_edits_help())]
    no_model_edits: bool,
    /// Path to a capture SQLite database to extend `knx_recent_telegrams`
    /// history beyond the in-memory ring window.
    #[arg(long, value_name = "PATH")]
    capture_db: Option<PathBuf>,
    // The Home Assistant tier needs a `[home_assistant]` table (issue #280).
    #[arg(long, help = bussard_mcp::tier_help::allow_home_assistant_help())]
    allow_home_assistant: bool,
    // `--listen`, `--allow-remote-clients` and `--allow-host`: issue #265.
    /// Serve MCP over streamable HTTP instead of stdio, at
    /// `http://<ADDR>/mcp`. Without a value it binds
    /// 127.0.0.1:0 (a free port) and prints the URL. Same tools and gates
    /// as stdio. bussard does not terminate TLS or authenticate clients on
    /// a loopback bind: a client that needs HTTPS goes through a reverse
    /// proxy or tunnel that does both. A non-loopback address is refused
    /// without `--allow-remote-clients`. `BUSSARD_MCP_TOKEN`, when set, is
    /// the bearer token every request must carry.
    #[arg(
        long,
        value_name = "ADDR",
        num_args = 0..=1,
        default_missing_value = bussard_mcp::http::DEFAULT_LISTEN
    )]
    listen: Option<SocketAddr>,
    /// Permit a non-loopback `--listen` address. Every request must then
    /// carry `Authorization: Bearer <token>`: the token is
    /// `BUSSARD_MCP_TOKEN`, or one generated at start and printed once.
    /// The `Host` header check is off, so a reverse proxy may forward any
    /// host name.
    #[arg(long, requires = "listen")]
    allow_remote_clients: bool,
    /// Accept this `Host` header on a loopback `--listen` too (repeatable),
    /// for a reverse proxy or tunnel that forwards its public host name.
    /// Without it only localhost, 127.0.0.1 and ::1 are accepted, which
    /// blocks DNS rebinding from a browser.
    #[arg(long, value_name = "HOST", requires = "listen")]
    allow_host: Vec<String>,
    /// Where `knx_viz` serves the browser page, read-only like a bare
    /// `bussard viz`. Without it the page binds 127.0.0.1:0, a free port,
    /// on the first `knx_viz`.
    #[arg(long, value_name = "ADDR")]
    viz_listen: Option<SocketAddr>,
}

impl Run for McpArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(
            g.dir(),
            g.group(),
            McpModes {
                passive: self.passive,
                allow_writes: self.allow_writes,
                allow_programming: self.allow_programming,
                plan_ttl: std::time::Duration::from_secs(self.plan_ttl_minutes.saturating_mul(60)),
                allow_remote_gateway: g.allow_remote_gateway,
                no_model_edits: self.no_model_edits,
                allow_home_assistant: self.allow_home_assistant,
                viz_listen: self.viz_listen,
            },
            self.capture_db,
            g.keyring.clone(),
            self.listen.map(|addr| Listen {
                addr,
                allow_remote_clients: self.allow_remote_clients,
                allow_host: self.allow_host,
            }),
        )
    }
}

/// Runs `bussard mcp`.
///
/// The model-edit tools (`knx_set_group`, `knx_add_link`, …) are registered
/// unless `--no-model-edits` is passed: they write model files behind a history
/// snapshot and never touch the bus, so they are safe in every tier.
///
/// With `--allow-writes` the server registers `knx_write_group`, so an LLM can
/// put telegrams on the bus for the whole session. That goes through the same
/// non-loopback gate as `bussard write` (issue #74), applied when the server
/// opens its [`bussard_service::BusService`]: against a real gateway the server
/// refuses to start unless the operator passed `--allow-remote-gateway` or set
/// `BUSSARD_ALLOW_REAL_GATEWAY=1`. `--allow-programming` (issue #118) hands
/// the LLM the table write of `bussard apply`, so it passes the same gate here,
/// and the programming tools check it again on every call. A read-only or
/// `--passive` server never writes, so it is allowed against any gateway.
/// `--allow-home-assistant` (issue #280) registers the Home Assistant tools
/// when `bussard.toml` has a `[home_assistant]` table; it never touches the
/// bus, so it combines with every tier.
/// The server's tier flags, bundled so the subcommand's five booleans do not
/// become five positional arguments.
#[derive(Debug, Clone, Copy)]
struct McpModes {
    /// Never transmit on the bus.
    pub passive: bool,
    /// Register `knx_write_group`.
    pub allow_writes: bool,
    /// Register the programming tier (`knx_plan_device`, `knx_apply_device`,
    /// `knx_restore_tables`, `knx_restart_device`, …).
    pub allow_programming: bool,
    /// How long a plan digest stays valid.
    pub plan_ttl: std::time::Duration,
    /// Permit `--allow-writes` against a non-loopback gateway.
    pub allow_remote_gateway: bool,
    /// Omit the model-edit tools.
    pub no_model_edits: bool,
    /// Register the Home Assistant tier (with a `[home_assistant]` table).
    pub allow_home_assistant: bool,
    /// Where `knx_viz` binds the browser page (`--viz-listen`).
    pub viz_listen: Option<SocketAddr>,
}

/// `--listen` and its companions: serve streamable HTTP instead of stdio.
#[derive(Debug, Clone)]
struct Listen {
    /// The address to bind (`127.0.0.1:0` when `--listen` has no value).
    pub addr: SocketAddr,
    /// `--allow-remote-clients`: permit a non-loopback bind, with a token.
    pub allow_remote_clients: bool,
    /// `--allow-host`: extra `Host` header values on a loopback bind.
    pub allow_host: Vec<String>,
}

/// Runs `bussard mcp`, over stdio or, with `listen`, over streamable HTTP.
fn run(
    dir: &Path,
    overrides: ConnOverrides,
    modes: McpModes,
    capture_db: Option<PathBuf>,
    keyring: Option<PathBuf>,
    listen: Option<Listen>,
) -> anyhow::Result<ExitCode> {
    let McpModes {
        passive,
        allow_writes,
        allow_programming,
        plan_ttl,
        allow_remote_gateway,
        no_model_edits,
        allow_home_assistant,
        viz_listen,
    } = modes;
    if bussard_mcp::onboarding::is_onboarding_dir(dir) {
        return run_onboarding(dir, overrides, modes, capture_db, keyring, listen);
    }
    if !dir.exists() {
        anyhow::bail!(
            "model directory {} not found; the MCP server needs a loaded model (pass --dir)",
            dir.display()
        );
    }
    // Load the model here to resolve the connection config; the server reloads
    // it from the same directory (cheap, and keeps the API uniform).
    let model = Model::load(dir)
        .map_err(|e| anyhow::anyhow!("failed to load model from {}: {e}", dir.display()))?;
    let connection = resolve_config(Some(&model), &overrides)?;

    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection,
        passive,
        allow_writes,
        no_model_edits,
        capture_db,
        allow_programming,
        allow_remote_gateway,
        plan_ttl,
        keyring,
        allow_home_assistant,
        viz_listen,
    };
    // The Home Assistant token the client must provide, by name only.
    let ha_token_env: Vec<String> = model
        .config
        .home_assistant
        .as_ref()
        .filter(|_| allow_home_assistant)
        .map(|table| table.token_env.clone())
        .into_iter()
        .collect();

    if let Some(listen) = listen {
        return run_http(&config, listen);
    }

    // Built before the server starts (the environment and the arguments do not
    // change), printed only once it is ready and only to a person: a client
    // that spawned the server with pipes gets the info log line alone.
    let hint = std::io::stderr()
        .is_terminal()
        .then(|| ConnectHint::for_this_process(dir, config.keyring.is_some(), &ha_token_env))
        .flatten();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        bussard_mcp::run_with_ready(&config, || {
            if let Some(hint) = &hint {
                eprint!("{}", hint.render());
            }
        })
        .await
    })?;

    Ok(ExitCode::SUCCESS)
}

/// Runs the server in its onboarding state (issue #745): `dir` is missing or
/// empty, so it starts with `knx_setup` and `knx_bus_status` only and
/// resolves the bus connection once `knx_setup` has written `bussard.toml`.
fn run_onboarding(
    dir: &Path,
    overrides: ConnOverrides,
    modes: McpModes,
    capture_db: Option<PathBuf>,
    keyring: Option<PathBuf>,
    listen: Option<Listen>,
) -> anyhow::Result<ExitCode> {
    let config = McpConfig {
        dir: dir.to_path_buf(),
        // A placeholder: no bus is opened before `knx_setup` wrote the model.
        connection: bussard_transport::ConnectionConfig::tunnel(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            bussard_transport::config::DEFAULT_PORT,
        )),
        passive: modes.passive,
        allow_writes: modes.allow_writes,
        no_model_edits: modes.no_model_edits,
        capture_db,
        allow_programming: modes.allow_programming,
        allow_remote_gateway: modes.allow_remote_gateway,
        plan_ttl: modes.plan_ttl,
        keyring: keyring.clone(),
        allow_home_assistant: modes.allow_home_assistant,
        viz_listen: modes.viz_listen,
    };
    let default_gateway = overrides.gateway.clone();
    let routing = overrides.routing;
    let model_dir = dir.to_path_buf();
    let started_keyring = keyring.clone();
    let resolve: bussard_mcp::onboarding::ResolveConnection =
        std::sync::Arc::new(move |model: &Model| {
            let mut connection = resolve_config(Some(model), &overrides)?;
            // The key store the import may have written (issue #241), unless
            // the server was started with a keyring.
            let store = crate::conn_cmd::resolve_keyring(None, None, &model_dir)
                .map(|resolved| resolved.path);
            // Its tunnelling users, read now rather than at start, when the
            // directory had none (issue #779). The server opens no bus before
            // this, so nothing needs a restart unless the keyring does not
            // open.
            let tunnel_note = match started_keyring.as_deref().or(store.as_deref()) {
                Some(path) => {
                    crate::conn_cmd::attach_keyring_tunnel(&mut connection, path, &model_dir)
                }
                None => None,
            };
            Ok(bussard_mcp::onboarding::ResolvedConnection {
                connection,
                keyring: store,
                tunnel_note,
            })
        });
    let onboarding = bussard_mcp::onboarding::Onboarding {
        config,
        resolve,
        default_gateway,
        routing,
    };

    if let Some(listen) = listen {
        let (options, generated) = http_options(listen)?;
        let has_token = options.bearer_token.is_some();
        let terminal = std::io::stderr().is_terminal();
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            bussard_mcp::run_onboarding_http_with_ready(onboarding, &options, |addr| {
                announce_http(addr, generated.as_deref(), has_token, terminal);
                eprintln!("{}", onboarding_note(dir));
            })
            .await
        })?;
        return Ok(ExitCode::SUCCESS);
    }

    let hint = std::io::stderr()
        .is_terminal()
        .then(|| ConnectHint::for_this_process(dir, keyring.is_some(), &[]))
        .flatten();
    let note = onboarding_note(dir);
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        bussard_mcp::run_onboarding_with_ready(onboarding, || {
            if let Some(hint) = &hint {
                eprint!("{}", hint.render());
                eprintln!("{note}");
            }
        })
        .await
    })?;
    Ok(ExitCode::SUCCESS)
}

/// The line a person at the terminal reads when the server starts in its
/// onboarding state.
fn onboarding_note(dir: &Path) -> String {
    format!(
        "No model in {} yet: the server starts with knx_setup and knx_bus_status only. Ask          the assistant to set up the house; after knx_setup the full tool set registers.",
        dir.display()
    )
}

/// Runs the server over streamable HTTP (issue #265): resolves the bearer
/// token, prints the URL once the listener is up, and serves until Ctrl-C.
fn run_http(config: &McpConfig, listen: Listen) -> anyhow::Result<ExitCode> {
    let (options, generated) = http_options(listen)?;
    let has_token = options.bearer_token.is_some();
    let terminal = std::io::stderr().is_terminal();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        bussard_mcp::run_http_with_ready(config, &options, |addr| {
            announce_http(addr, generated.as_deref(), has_token, terminal);
        })
        .await
    })?;
    Ok(ExitCode::SUCCESS)
}

/// The HTTP options for `listen`, and the bearer token generated for a
/// non-loopback bind without [`TOKEN_ENV`].
fn http_options(listen: Listen) -> anyhow::Result<(HttpOptions, Option<String>)> {
    let from_env = std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty());
    // A non-loopback bind needs a token; generate one when the operator opted
    // in without setting it. A loopback bind uses one only when it is set.
    let generated = match &from_env {
        None if listen.allow_remote_clients && !listen.addr.ip().is_loopback() => {
            Some(bussard_mcp::http::generate_token()?)
        }
        _ => None,
    };
    let options = HttpOptions {
        listen: listen.addr,
        allow_remote_clients: listen.allow_remote_clients,
        bearer_token: from_env.or_else(|| generated.clone()),
        allowed_hosts: listen.allow_host,
    };
    Ok((options, generated))
}

/// Prints where the HTTP server listens, the generated token once, and on a
/// terminal how to register it.
fn announce_http(addr: SocketAddr, generated: Option<&str>, has_token: bool, terminal: bool) {
    let url = bussard_mcp::http::url(addr);
    eprintln!("bussard mcp serving streamable HTTP on {url} (Ctrl-C to stop)");
    if let Some(token) = generated {
        eprintln!("bearer token, shown once (set {TOKEN_ENV} to choose your own): {token}");
    }
    if terminal {
        eprint!("{}", http_hint(&url, has_token));
    }
}

/// How to register an HTTP server at `url` with a client, for a person at a
/// terminal. `has_token`: requests must carry the bearer token, which the
/// hint names but never prints.
fn http_hint(url: &str, has_token: bool) -> String {
    let header = if has_token {
        " --header 'Authorization: Bearer <token>'"
    } else {
        ""
    };
    let mut out = format!(
        "\nClaude Code, register it:\n  claude mcp add --transport http {SERVER_NAME} {url}{header}\n\n\
         Clients that take a server URL use {url}{}. Port 0 picks a new port on every \
         start; pass a fixed one (--listen 127.0.0.1:8765) for a lasting registration.\n\n\
         Claude Desktop's custom connectors need an https:// URL. bussard does not \
         terminate TLS or authenticate clients: put a reverse proxy or tunnel that does \
         both in front of this port.\n",
        if has_token {
            " with the header Authorization: Bearer <token>"
        } else {
            ""
        }
    );
    out.push_str("\nPress Ctrl-C to stop.\n");
    out
}

/// The server name the registration uses; matches the docs
/// (`docs/getting-started/first-weekend.md`), which register the server as `knx`.
const SERVER_NAME: &str = "knx";

/// The placeholder printed in place of a secret the client must supply.
const SECRET_PLACEHOLDER: &str = "<password>";

/// Global and `mcp` flags that take a separate value, so the value is not
/// mistaken for the `mcp` subcommand token.
const VALUE_FLAGS: &[&str] = &[
    "--dir",
    "--gateway",
    "--keyring",
    "--secure-user",
    "--secure-password-env",
    "--secure-transport",
    "--plan-ttl-minutes",
    "--capture-db",
];

/// Flags whose value is a path: made absolute, so the registration does not
/// depend on the working directory the client starts the server in.
const PATH_FLAGS: &[&str] = &["--keyring", "--capture-db"];

/// The keyring password variable.
const KEYRING_PASSWORD_ENV: &str = "BUSSARD_KEYRING_PASSWORD";

/// The exported real-gateway opt-in.
const ALLOW_REAL_GATEWAY_ENV: &str = "BUSSARD_ALLOW_REAL_GATEWAY";

/// One environment variable the client has to set for the server.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientEnv {
    /// A plain value, safe to print (`BUSSARD_ALLOW_REAL_GATEWAY=1`).
    Plain(String, String),
    /// A secret: only the name is printed, with [`SECRET_PLACEHOLDER`].
    Secret(String),
}

/// Where a secret the server needs comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SecretSource {
    /// Exported in the process environment: the client must set it too.
    Exported,
    /// From the `.env` next to the model: the server reads it again itself.
    DotenvNextToModel,
}

/// How to register the running server with an MCP client: the Claude Code
/// command and the JSON entry for other clients, built from the real values.
#[derive(Debug, Clone)]
struct ConnectHint {
    /// The absolute path of the `bussard` binary.
    exe: PathBuf,
    /// The absolute model directory.
    dir: PathBuf,
    /// The user's flags, without `--dir` and the `mcp` token.
    flags: Vec<String>,
    /// Secrets the server needs, by variable name, and where they come from.
    secrets: Vec<(String, SecretSource)>,
    /// Plain variables the client must set.
    plain_env: Vec<(String, String)>,
}

impl ConnectHint {
    /// The hint for this process: its binary, its resolved model directory,
    /// its arguments and its environment. `None` when the binary path is
    /// unknown (nothing useful to print then).
    fn for_this_process(dir: &Path, has_keyring: bool, extra_secrets: &[String]) -> Option<Self> {
        let exe = std::env::current_exe().ok()?;
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        let dir = std::fs::canonicalize(dir)
            .or_else(|_| std::path::absolute(dir))
            .unwrap_or_else(|_| dir.to_path_buf());
        let args: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let flags = passthrough_flags(&args);

        let mut names: Vec<String> = Vec::new();
        if has_keyring {
            names.push(KEYRING_PASSWORD_ENV.to_owned());
        }
        if let Some(var) = flag_value(&args, "--secure-password-env") {
            names.push(var);
        }
        names.extend(extra_secrets.iter().cloned());
        let dotenv_next_to_model = bussard_model::dotenv::find(&dir, &dir).is_some();
        let secrets = names
            .into_iter()
            .filter_map(|name| {
                let source = secret_source(
                    std::env::var_os(&name).is_some(),
                    bussard_model::dotenv::var_os(&name).is_some(),
                    dotenv_next_to_model,
                )?;
                Some((name, source))
            })
            .collect();

        let mut plain_env = Vec::new();
        if std::env::var_os(ALLOW_REAL_GATEWAY_ENV).is_some_and(|v| v == "1")
            && !flags.iter().any(|f| f == "--allow-remote-gateway")
        {
            plain_env.push((ALLOW_REAL_GATEWAY_ENV.to_owned(), "1".to_owned()));
        }
        Some(Self {
            exe,
            dir,
            flags,
            secrets,
            plain_env,
        })
    }

    /// The variables the client must set, in print order.
    fn client_env(&self) -> Vec<ClientEnv> {
        let plain = self
            .plain_env
            .iter()
            .map(|(k, v)| ClientEnv::Plain(k.clone(), v.clone()));
        let secret = self
            .secrets
            .iter()
            .filter(|(_, source)| *source == SecretSource::Exported)
            .map(|(name, _)| ClientEnv::Secret(name.clone()));
        plain.chain(secret).collect()
    }

    /// The server's command line after the binary: `mcp --dir <dir> <flags>`.
    fn server_args(&self) -> Vec<String> {
        let mut args = vec![
            "mcp".to_owned(),
            "--dir".to_owned(),
            self.dir.to_string_lossy().into_owned(),
        ];
        args.extend(self.flags.iter().cloned());
        args
    }

    /// The Claude Code registration command, shell-quoted. Plain variables
    /// go in as `-e`; a secret never appears.
    fn claude_command(&self) -> String {
        let mut words = vec![
            "claude".to_owned(),
            "mcp".to_owned(),
            "add".to_owned(),
            SERVER_NAME.to_owned(),
        ];
        for (key, value) in &self.plain_env {
            words.push("-e".to_owned());
            words.push(format!("{key}={value}"));
        }
        words.push("--".to_owned());
        words.push(self.exe.to_string_lossy().into_owned());
        words.extend(self.server_args());
        words
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The `mcpServers` entry for `claude_desktop_config.json` and other
    /// clients, laid out as the docs show it (`command` first, `args` on one
    /// line). A secret is the [`SECRET_PLACEHOLDER`].
    fn json(&self) -> String {
        let quote = |text: &str| serde_json::Value::from(text).to_string();
        let args = self
            .server_args()
            .iter()
            .map(|arg| quote(arg))
            .collect::<Vec<_>>()
            .join(", ");
        let mut out = format!(
            "{{\n  \"mcpServers\": {{\n    {}: {{\n      \"command\": {},\n      \"args\": [{args}]",
            quote(SERVER_NAME),
            quote(&self.exe.to_string_lossy()),
        );
        let env = self.client_env();
        if !env.is_empty() {
            let pairs = env
                .iter()
                .map(|var| match var {
                    ClientEnv::Plain(k, v) => format!("{}: {}", quote(k), quote(v)),
                    ClientEnv::Secret(k) => format!("{}: {}", quote(k), quote(SECRET_PLACEHOLDER)),
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(",\n      \"env\": {{ {pairs} }}"));
        }
        out.push_str("\n    }\n  }\n}");
        out
    }

    /// The block printed to a terminal once the server is ready.
    fn render(&self) -> String {
        let mut out = String::from(
            "\nThis MCP server talks over stdin/stdout: an MCP client starts it as a \
             subprocess, nothing connects to it.\n\nClaude Code, register it once:\n  ",
        );
        out.push_str(&self.claude_command());
        out.push('\n');
        for (name, source) in &self.secrets {
            match source {
                SecretSource::Exported => out.push_str(&format!(
                    "  The client must provide {name} (claude mcp add -e {name}=..., or \
                     \"env\" in the JSON below); it is not printed here.\n"
                )),
                SecretSource::DotenvNextToModel => out.push_str(&format!(
                    "  {name} comes from the .env next to the model, which the server \
                     reads automatically.\n"
                )),
            }
        }
        out.push_str(
            "\nClaude Desktop: Settings > Developer > Edit Config opens \
             claude_desktop_config.json (macOS: ~/Library/Application \
             Support/Claude/claude_desktop_config.json). Paste this entry, restart \
             Claude Desktop, and the server shows under the tools icon in a chat, \
             not in the connector list. Other clients take the same entry:\n",
        );
        for line in self.json().lines() {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(
            "For a client that takes a server URL, run `bussard mcp --listen` \
             (streamable HTTP) instead.\n\nPress Ctrl-C to stop.\n",
        );
        out
    }
}

/// Where the secret `name` comes from, or `None` when it is set nowhere.
/// `exported`: in the process environment; `from_dotenv`: from the installed
/// `.env`; `dotenv_next_to_model`: that `.env` is one a client-started server
/// finds again (in or next to the model directory).
fn secret_source(
    exported: bool,
    from_dotenv: bool,
    dotenv_next_to_model: bool,
) -> Option<SecretSource> {
    if exported {
        Some(SecretSource::Exported)
    } else if from_dotenv && dotenv_next_to_model {
        Some(SecretSource::DotenvNextToModel)
    } else if from_dotenv {
        // A `.env` in the working directory only: the client starts the
        // server elsewhere, so it must provide the value itself.
        Some(SecretSource::Exported)
    } else {
        None
    }
}

/// The user's arguments (without the binary) minus `--dir <dir>` and the
/// `mcp` subcommand token, otherwise verbatim and in order; a relative path
/// value of a [`PATH_FLAGS`] flag is made absolute.
fn passthrough_flags(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen_mcp = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--dir" {
            iter.next();
            continue;
        }
        if arg.starts_with("--dir=") {
            continue;
        }
        if !seen_mcp && arg == "mcp" {
            seen_mcp = true;
            continue;
        }
        if let Some((flag, value)) = arg.split_once('=')
            && PATH_FLAGS.contains(&flag)
        {
            out.push(format!("{flag}={}", absolute(value)));
            continue;
        }
        out.push(arg.clone());
        if VALUE_FLAGS.contains(&arg.as_str())
            && let Some(value) = iter.next()
        {
            if PATH_FLAGS.contains(&arg.as_str()) {
                out.push(absolute(value));
            } else {
                out.push(value.clone());
            }
        }
    }
    out
}

/// The value of `flag` in `args` (`--flag value` or `--flag=value`).
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
        if let Some(value) = arg.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
            return Some(value.to_owned());
        }
    }
    None
}

/// `path` made absolute against the working directory, or unchanged when
/// that fails.
fn absolute(path: &str) -> String {
    std::path::absolute(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_owned())
}

/// `word` quoted for a POSIX shell when it needs it.
fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+%".contains(c));
    if safe {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    fn hint(secrets: Vec<(String, SecretSource)>, plain_env: Vec<(String, String)>) -> ConnectHint {
        ConnectHint {
            exe: PathBuf::from("/opt/bussard/bin/bussard"),
            dir: PathBuf::from("/home/nadia/house"),
            flags: strings(&["--allow-remote-gateway", "--allow-programming"]),
            secrets,
            plain_env,
        }
    }

    #[test]
    fn test_passthrough_flags_drops_dir_and_mcp_token() {
        let args = strings(&[
            "--dir",
            "mcp",
            "mcp",
            "--allow-remote-gateway",
            "--dir=x",
            "--gateway",
            "mcp",
            "--allow-programming",
            "-v",
        ]);
        assert_eq!(
            passthrough_flags(&args),
            strings(&[
                "--allow-remote-gateway",
                "--gateway",
                "mcp",
                "--allow-programming",
                "-v"
            ])
        );
    }

    #[test]
    fn test_passthrough_flags_makes_path_values_absolute() -> TestResult {
        let args = strings(&[
            "mcp",
            "--keyring",
            "/k/house.knxkeys",
            "--capture-db=rel.db",
        ]);
        let flags = passthrough_flags(&args);
        // `std::path::absolute` gives a drive and backslashes on Windows, so
        // the expected values are built the same way on every platform.
        let keyring = std::path::absolute("/k/house.knxkeys")?;
        let capture = std::path::absolute("rel.db")?;
        assert_eq!(flags.len(), 3);
        assert_eq!(flags[0], "--keyring");
        assert_eq!(PathBuf::from(&flags[1]), keyring);
        let value = flags[2]
            .strip_prefix("--capture-db=")
            .ok_or("no --capture-db=")?;
        assert_eq!(PathBuf::from(value), capture);
        assert!(capture.is_absolute());
        Ok(())
    }

    #[test]
    fn test_flag_value_both_spellings() {
        let args = strings(&["mcp", "--secure-password-env", "PW"]);
        assert_eq!(
            flag_value(&args, "--secure-password-env").as_deref(),
            Some("PW")
        );
        let args = strings(&["--secure-password-env=PW2", "mcp"]);
        assert_eq!(
            flag_value(&args, "--secure-password-env").as_deref(),
            Some("PW2")
        );
        assert_eq!(flag_value(&args, "--keyring"), None);
    }

    #[test]
    fn test_claude_command_plain() {
        assert_eq!(
            hint(Vec::new(), Vec::new()).claude_command(),
            "claude mcp add knx -- /opt/bussard/bin/bussard mcp --dir /home/nadia/house \
             --allow-remote-gateway --allow-programming"
        );
    }

    #[test]
    fn test_claude_command_quotes_and_plain_env() {
        let mut h = hint(
            Vec::new(),
            vec![(ALLOW_REAL_GATEWAY_ENV.to_owned(), "1".to_owned())],
        );
        h.dir = PathBuf::from("/home/nadia/my house");
        assert_eq!(
            h.claude_command(),
            "claude mcp add knx -e BUSSARD_ALLOW_REAL_GATEWAY=1 -- /opt/bussard/bin/bussard \
             mcp --dir '/home/nadia/my house' --allow-remote-gateway --allow-programming"
        );
    }

    #[test]
    fn test_json_exact_text() {
        let h = hint(
            vec![(KEYRING_PASSWORD_ENV.to_owned(), SecretSource::Exported)],
            Vec::new(),
        );
        assert_eq!(
            h.json(),
            "{\n  \"mcpServers\": {\n    \"knx\": {\n      \"command\": \"/opt/bussard/bin/bussard\",\n      \
             \"args\": [\"mcp\", \"--dir\", \"/home/nadia/house\", \"--allow-remote-gateway\", \
             \"--allow-programming\"],\n      \"env\": { \"BUSSARD_KEYRING_PASSWORD\": \"<password>\" }\n    \
             }\n  }\n}"
        );
    }

    #[test]
    fn test_json_parses_without_env() -> TestResult {
        let value: serde_json::Value = serde_json::from_str(&hint(Vec::new(), Vec::new()).json())?;
        assert_eq!(
            value,
            serde_json::json!({"mcpServers": {"knx": {
                "command": "/opt/bussard/bin/bussard",
                "args": ["mcp", "--dir", "/home/nadia/house",
                         "--allow-remote-gateway", "--allow-programming"]
            }}})
        );
        Ok(())
    }

    #[test]
    fn test_json_exported_secret_is_a_placeholder() -> TestResult {
        let h = hint(
            vec![(KEYRING_PASSWORD_ENV.to_owned(), SecretSource::Exported)],
            Vec::new(),
        );
        let value: serde_json::Value = serde_json::from_str(&h.json())?;
        assert_eq!(
            value["mcpServers"]["knx"]["env"],
            serde_json::json!({"BUSSARD_KEYRING_PASSWORD": "<password>"})
        );
        let text = h.render();
        assert!(text.contains(
            "The client must provide BUSSARD_KEYRING_PASSWORD (claude mcp add -e \
             BUSSARD_KEYRING_PASSWORD=..., or \"env\" in the JSON below)"
        ));
        assert!(!h.claude_command().contains("PASSWORD"));
        Ok(())
    }

    #[test]
    fn test_render_dotenv_secret_is_not_in_env() -> TestResult {
        let h = hint(
            vec![(
                KEYRING_PASSWORD_ENV.to_owned(),
                SecretSource::DotenvNextToModel,
            )],
            Vec::new(),
        );
        let value: serde_json::Value = serde_json::from_str(&h.json())?;
        assert!(value["mcpServers"]["knx"].get("env").is_none());
        assert!(h.render().contains(
            "BUSSARD_KEYRING_PASSWORD comes from the .env next to the model, which the \
             server reads automatically."
        ));
        Ok(())
    }

    #[test]
    fn test_render_has_the_command_and_the_stop_line() {
        // The hint holds variable names only, never values, so there is no
        // password to leak; the secret shows as a name or a placeholder.
        for source in [SecretSource::Exported, SecretSource::DotenvNextToModel] {
            let text = hint(vec![(KEYRING_PASSWORD_ENV.to_owned(), source)], Vec::new()).render();
            assert!(text.contains("Press Ctrl-C to stop."));
            assert!(text.contains("claude mcp add knx -- "));
        }
    }

    #[test]
    fn test_secret_source_rules() {
        assert_eq!(
            secret_source(true, true, true),
            Some(SecretSource::Exported)
        );
        assert_eq!(
            secret_source(false, true, true),
            Some(SecretSource::DotenvNextToModel)
        );
        assert_eq!(
            secret_source(false, true, false),
            Some(SecretSource::Exported)
        );
        assert_eq!(secret_source(false, false, true), None);
    }

    #[test]
    fn test_http_hint_names_the_url_and_the_tls_job() {
        let text = http_hint("http://127.0.0.1:8765/mcp", false);
        assert!(text.contains("claude mcp add --transport http knx http://127.0.0.1:8765/mcp\n"));
        assert!(text.contains("does not terminate TLS"));
        assert!(!text.contains("Bearer"));
        let text = http_hint("http://127.0.0.1:8765/mcp", true);
        assert!(text.contains("--header 'Authorization: Bearer <token>'"));
    }

    #[test]
    fn test_shell_quote() {
        assert_eq!(shell_quote("/a/b"), "/a/b");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
