//! The `bussard mcp` subcommand: run the read-only MCP server over stdio.
//!
//! The model is required (the server is useless without one). The bus
//! connection is resolved from the model's `bussard.toml` plus overrides, but is
//! opened lazily by the server's stream task, which reconnects — so a bus that
//! is down at startup does not stop the server. All logging is on stderr
//! (configured in `main`); stdout carries only the MCP wire.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bussard_mcp::McpConfig;
use bussard_model::Model;

use crate::conn_cmd::{ConnOverrides, resolve_config};

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
/// The server's tier flags, bundled so the subcommand's five booleans do not
/// become five positional arguments.
#[derive(Debug, Clone, Copy)]
pub struct McpModes {
    /// Never transmit on the bus.
    pub passive: bool,
    /// Register `knx_write_group`.
    pub allow_writes: bool,
    /// Register the programming tier (`knx_plan_device`, `knx_apply_device`).
    pub allow_programming: bool,
    /// How long a plan digest stays valid.
    pub plan_ttl: std::time::Duration,
    /// Permit `--allow-writes` against a non-loopback gateway.
    pub allow_remote_gateway: bool,
    /// Omit the model-edit tools.
    pub no_model_edits: bool,
}

pub fn run(
    dir: &Path,
    overrides: ConnOverrides,
    modes: McpModes,
    capture_db: Option<PathBuf>,
    keyring: Option<PathBuf>,
) -> anyhow::Result<ExitCode> {
    let McpModes {
        passive,
        allow_writes,
        allow_programming,
        plan_ttl,
        allow_remote_gateway,
        no_model_edits,
    } = modes;
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
    };

    // Built before the server starts (the environment and the arguments do not
    // change), printed only once it is ready and only to a person: a client
    // that spawned the server with pipes gets the info log line alone.
    let hint = std::io::stderr()
        .is_terminal()
        .then(|| ConnectHint::for_this_process(dir, config.keyring.is_some()))
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

/// The server name the registration uses; matches the docs
/// (`docs/getting-started-owner.md`), which register the server as `knx`.
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
    fn for_this_process(dir: &Path, has_keyring: bool) -> Option<Self> {
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
            "A custom connector URL would need an HTTP transport, which bussard does \
             not offer yet.\n\nPress Ctrl-C to stop.\n",
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
    fn test_passthrough_flags_makes_path_values_absolute() {
        let args = strings(&[
            "mcp",
            "--keyring",
            "/k/house.knxkeys",
            "--capture-db=rel.db",
        ]);
        let flags = passthrough_flags(&args);
        assert_eq!(flags[0], "--keyring");
        assert_eq!(flags[1], "/k/house.knxkeys");
        assert!(flags[2].starts_with("--capture-db=/"), "{}", flags[2]);
        assert!(flags[2].ends_with("rel.db"), "{}", flags[2]);
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
    fn test_shell_quote() {
        assert_eq!(shell_quote("/a/b"), "/a/b");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
