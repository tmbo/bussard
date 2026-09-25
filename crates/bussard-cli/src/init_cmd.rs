//! The `bussard init` subcommand — from-scratch onboarding.
//!
//! Creates a fresh `knx/` model directory: resolves a gateway (explicit,
//! routing, or by KNXnet/IP discovery across every local interface), writes the
//! TOML skeleton, and prints next steps. The result validates cleanly.
//!
//! The first run is one command. With a project (a `.knxproj`, or an
//! xknxproject `.json` dump) given as the argument, or exactly one `.knxproj`
//! found next to the model directory, `init` runs `import` right after
//! writing `bussard.toml` (product data and validation included). Without
//! one, on a terminal it offers to scan the gateway's line and lists what
//! answers; `--scan <LINE>` does that without asking, for scripts.
//!
//! A `.knxkeys` keyring exported next to the project is merged into the key
//! store `bussard.keys` by the import (issue #241). Without
//! `BUSSARD_KEYRING_PASSWORD` no store can be written, so `init` records the
//! keyring as the deprecated `connection.keyring` instead (issue #205) and
//! the import prints the command that creates the store.
//!
//! The `bussard.toml` content is constructed here by hand (three simple keys)
//! rather than via `Model::save`, so this command is decoupled from the model's
//! emission format.

use std::io::{IsTerminal, Write};
use std::net::{SocketAddrV4, ToSocketAddrs};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use bussard_model::IndividualAddress;
use bussard_transport::config::DEFAULT_PORT;
use bussard_transport::knxnet::{GatewayDescription, GatewayInfo};
use bussard_transport::{BusConnection, ConnectionConfig, Transport};

/// Per-interface discovery timeout.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for the unicast DESCRIPTION_REQUEST sent to the resolved gateway.
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How a gateway (if any) was resolved, which decides the emitted transport.
enum Resolution {
    /// Tunneling to a specific gateway endpoint.
    Tunnel(SocketAddrV4),
    /// Routing (multicast); no gateway needed.
    Routing,
    /// No gateway could be resolved; write a skeleton with a placeholder so the
    /// user can fill in the address later.
    Placeholder,
}

/// Injection point for discovery so tests never touch the network.
///
/// Defaults to the real transport discovery across all interfaces; tests swap
/// in a stub. Kept as a function pointer to avoid a trait-object dance.
type DiscoverFn = fn() -> anyhow::Result<Vec<GatewayInfo>>;

/// Injection point for the `--gateway` reachability probe so tests never touch
/// the network. Defaults to [`probe_reachability`]; tests swap in an instant
/// no-op so `init --gateway <dead-address>` does not spend the real ~5s connect
/// budget against an unreachable endpoint.
type ProbeFn = fn(SocketAddrV4);

/// What `init` does after the skeleton: import a project, or scan a line.
#[derive(Debug, Clone, Default)]
pub(crate) struct FirstRun {
    /// The project to import (`.knxproj`, or an xknxproject `.json` dump).
    pub project: Option<std::path::PathBuf>,
    /// The project password (`--password`).
    pub password: Option<String>,
    /// The product-data download answer for the import.
    pub consent: crate::product_fetch::Consent,
    /// `--scan <LINE>`: scan this line after writing, without asking.
    pub scan: Option<String>,
    /// `--yes`: initialise a non-empty directory without asking.
    pub yes: bool,
}

/// Creates a fresh `knx/` model directory, then imports the project given (or
/// the one `.knxproj` found next to it) or offers a line scan.
pub fn run(
    dir: &Path,
    gateway: Option<&str>,
    routing: bool,
    mut first: FirstRun,
) -> anyhow::Result<ExitCode> {
    if first.project.is_none() && first.scan.is_none() {
        first.project = find_project(dir);
    }
    run_with(
        dir,
        gateway,
        routing,
        real_discover,
        probe_reachability,
        first,
    )
}

/// The one `.knxproj` next to the model directory (in its parent), if there
/// is exactly one. Several are listed and none is picked.
fn find_project(dir: &Path) -> Option<std::path::PathBuf> {
    let parent = match dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(&parent)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("knxproj"))
        })
        .collect();
    found.sort();
    match found.len() {
        0 => None,
        1 => {
            let project = found.remove(0);
            println!("Found the ETS project {}; importing it.", project.display());
            Some(project)
        }
        _ => {
            println!("Found several ETS projects; name the one to import:");
            for p in &found {
                println!("  bussard init {} --dir {}", p.display(), dir.display());
            }
            None
        }
    }
}

/// The one `.knxkeys` keyring in the project's directory, to record as
/// `connection.keyring` when no key store can be written (no password).
/// Several are left to the import's message.
fn find_keyring(project: &Path) -> Option<std::path::PathBuf> {
    let mut found = crate::keys_cmd::neighbour_keyrings(project);
    (found.len() == 1).then(|| found.remove(0))
}

/// The `connection.keyring` value for `keyring`, as `bussard.toml` in `dir`
/// resolves it: relative to `dir` when the keyring sits in `dir`'s parent
/// (the usual layout: the ETS exports next to `knx/`), else absolute. The
/// separators are forward slashes on every platform, so the committed
/// `bussard.toml` reads the same on Windows (which accepts `/`).
fn keyring_setting(dir: &Path, keyring: &Path) -> String {
    let absolute = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let keyring = absolute(keyring);
    let dir = absolute(dir);
    match (keyring.parent(), dir.parent(), keyring.file_name()) {
        (Some(from), Some(parent), Some(name)) if from == parent => {
            format!("../{}", name.to_string_lossy())
        }
        _ => keyring.to_string_lossy().replace('\\', "/"),
    }
}

/// The testable core: same as [`run`] but with injectable discovery and probe
/// sources.
fn run_with(
    dir: &Path,
    gateway: Option<&str>,
    routing: bool,
    discover: DiscoverFn,
    probe: ProbeFn,
    first: FirstRun,
) -> anyhow::Result<ExitCode> {
    // 1. Refuse a directory that already holds a model; ask before writing
    // into any other non-empty one.
    if dir.join(bussard_model::loader::CONFIG_FILE).is_file() {
        eprintln!(
            "error: {} already holds a model (bussard.toml).",
            crate::conn_cmd::describe_dir(dir)
        );
        eprintln!("Try one of:");
        eprintln!("  bussard validate --dir {}", dir.display());
        eprintln!(
            "  bussard import <project.knxproj> --dir {}   (to (re)import from ETS)",
            dir.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    if !confirm_target(dir, first.yes, TargetVerb::Init)? {
        eprintln!("Not confirmed; nothing written.");
        return Ok(ExitCode::FAILURE);
    }

    // 2. Resolve the gateway.
    let resolution = resolve_gateway(gateway, routing, discover, probe)?;

    // 3. Write the skeleton. With a project to import, `groups.toml` is the
    // import's to write, so the import is a fresh one, not a merge. A keyring
    // exported next to the project goes into the key store (the import does
    // it); only without the password is it recorded as `connection.keyring`.
    let keyring = first
        .project
        .as_deref()
        .filter(|_| !crate::keys_cmd::password_available())
        .and_then(find_keyring)
        .map(|path| keyring_setting(dir, &path));
    write_skeleton(
        dir,
        &resolution,
        first.project.is_none(),
        keyring.as_deref(),
    )?;
    if let Some(keyring) = &keyring {
        println!(
            "Recorded the keyring as connection.keyring = {keyring:?} in {} (deprecated; \
             `bussard keys import` moves it into the key store).",
            dir.join("bussard.toml").display()
        );
    }

    // 4. The first run is one command: import the project, or scan the line.
    if let Some(project) = &first.project {
        println!();
        println!("Importing {} into {}:", project.display(), dir.display());
        let choice = crate::import_bundle::ConflictChoice::from_flags(false, false, false);
        let is_json = project
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let code = if is_json {
            crate::import_cmd::run_json(project, dir, choice, first.consent)?
        } else {
            crate::import_cmd::run_knxproj(
                project,
                dir,
                first.password.clone(),
                choice,
                first.consent,
            )?
        };
        print_next_steps(dir, true);
        return Ok(code);
    }
    let scan_line = match (&first.scan, &resolution) {
        (Some(line), _) => Some(line.clone()),
        (None, Resolution::Placeholder) => None,
        (None, _) if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() => {
            let line = DEFAULT_SCAN_LINE.to_string();
            crate::confirm::ask(&format!(
                "\nNo ETS project given. Scan line {line} now and list the devices that answer?"
            ))?
            .then_some(line)
        }
        (None, _) => None,
    };
    if let Some(line) = scan_line {
        println!();
        let code = crate::scan_cmd::run(
            &line,
            0,
            255,
            dir,
            false,
            None,
            crate::conn_cmd::ConnOverrides::default(),
        )?;
        print_next_steps(dir, false);
        return Ok(code);
    }

    // 5. Print next steps.
    print_next_steps(dir, false);

    Ok(ExitCode::SUCCESS)
}

/// The line the first-run scan offers: the first line of the first area, where
/// a single-line installation and most interfaces sit. `--scan <LINE>` names
/// another.
const DEFAULT_SCAN_LINE: &str = "1.1";

/// Entries that do not make a target directory "non-empty" for `init` and
/// `import`: a repository's own files and bussard's local data.
const IGNORED_ENTRIES: &[&str] = &[".git", ".env", ".gitignore", ".bussard"];

/// What is already in the target directory of `init` or `import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TargetState {
    /// Entries other than [`IGNORED_ENTRIES`].
    pub entries: usize,
    /// `knx/bussard.toml` exists below it: a model lives one level down.
    pub nested_model: bool,
}

impl TargetState {
    /// Whether `init` or `import` must ask before writing here.
    pub fn needs_confirmation(self) -> bool {
        self.entries > 0 || self.nested_model
    }

    /// `12 entries, a model exists in knx/`.
    fn describe(self) -> String {
        let mut out = match self.entries {
            1 => "1 entry".to_string(),
            n => format!("{n} entries"),
        };
        if self.nested_model {
            out.push_str(&format!(
                ", a model exists in {}/",
                bussard_model::NESTED_MODEL_DIR
            ));
        }
        out
    }
}

/// Reads what is in `dir`. An absent directory is empty.
///
/// # Errors
///
/// `dir` exists but is not a directory, or cannot be listed.
pub(crate) fn target_state(dir: &Path) -> anyhow::Result<TargetState> {
    if !dir.exists() {
        return Ok(TargetState::default());
    }
    if !dir.is_dir() {
        bail!("{} exists but is not a directory", dir.display());
    }
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .flatten()
        .filter(|e| !IGNORED_ENTRIES.contains(&e.file_name().to_string_lossy().as_ref()))
        .count();
    let nested_model = dir
        .join(bussard_model::NESTED_MODEL_DIR)
        .join(bussard_model::loader::CONFIG_FILE)
        .is_file();
    Ok(TargetState {
        entries,
        nested_model,
    })
}

/// Which command asks [`confirm_target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetVerb {
    /// `bussard init`.
    Init,
    /// `bussard import`.
    Import,
}

/// Asks before `init` or `import` writes a model into a non-empty `dir` that
/// holds no model yet (a directory with `bussard.toml` is the caller's case:
/// `init` refuses it; `import` re-imports into any model directory). `--yes` (`yes`) answers
/// yes; without a terminal and without `--yes` this fails with the standard
/// [`crate::confirm::refusal`]. Returns whether to go on.
///
/// # Errors
///
/// The refusal above, an unreadable `dir`, or a failure to read stdin.
pub(crate) fn confirm_target(dir: &Path, yes: bool, verb: TargetVerb) -> anyhow::Result<bool> {
    let existing = match verb {
        TargetVerb::Init => dir.join(bussard_model::loader::CONFIG_FILE).is_file(),
        // Any model file makes it the re-import path, which merges.
        TargetVerb::Import => bussard_model::discover::is_model_dir(dir),
    };
    if existing {
        return Ok(true);
    }
    let state = target_state(dir)?;
    if !state.needs_confirmation() {
        return Ok(true);
    }
    let place = crate::conn_cmd::describe_dir(dir);
    // `the current directory /abs` or the directory as given.
    let (here, non_empty) = match place.strip_prefix("the current directory ") {
        Some(path) => (
            "the current directory".to_string(),
            format!("the non-empty current directory {path}"),
        ),
        None => (place.clone(), format!("the non-empty directory {place}")),
    };
    let question = match verb {
        TargetVerb::Init => format!("initialise a model in {here}?"),
        TargetVerb::Import => format!("import into {here}?"),
    };
    let prompt = format!("{place} is not empty ({}); {question}", state.describe());
    let action = match verb {
        TargetVerb::Init => format!("initialise a model in {non_empty} ({})", state.describe()),
        TargetVerb::Import => format!("import into {non_empty} ({})", state.describe()),
    };
    crate::confirm::confirm(yes, &prompt, &action)
}

/// Decides which transport to emit, running discovery only when needed.
fn resolve_gateway(
    gateway: Option<&str>,
    routing: bool,
    discover: DiscoverFn,
    probe: ProbeFn,
) -> anyhow::Result<Resolution> {
    // --routing wins: no gateway needed.
    if routing {
        println!("Configuring KNXnet/IP routing (multicast 224.0.23.12:3671).");
        return Ok(Resolution::Routing);
    }

    // --gateway given: use it, skip discovery, but do a best-effort probe.
    if let Some(spec) = gateway {
        let endpoint = parse_gateway(spec)?;
        probe(endpoint);
        return Ok(Resolution::Tunnel(endpoint));
    }

    // Neither: discover across all local interfaces.
    println!("Searching for KNXnet/IP gateways on the local network...");
    let mut found = discover()?;
    // Deterministic ordering for a stable prompt / output.
    found.sort_by_key(|g| g.endpoint);
    found.dedup_by_key(|g| g.endpoint);

    match found.len() {
        0 => {
            eprintln!("No KNXnet/IP gateways responded to discovery.");
            eprintln!("Likely causes:");
            eprintln!("  - This machine is on a different subnet than the gateway ");
            eprintln!("    (KNX discovery is multicast and does not route across subnets).");
            eprintln!("  - The gateway has KNXnet/IP tunneling/discovery disabled.");
            eprintln!("Find the gateway's IP (from your router, or the Home Assistant KNX config)");
            eprintln!("and re-run:  bussard init --gateway <ip>   (or --routing for multicast).");
            eprintln!("Writing a skeleton with a placeholder gateway for now.");
            Ok(Resolution::Placeholder)
        }
        1 => {
            let gw = &found[0];
            println!("Found gateway: {}", describe_gateway(gw));
            Ok(Resolution::Tunnel(gw.endpoint))
        }
        _ => {
            if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                let chosen = prompt_choice(&found)?;
                println!("Using gateway: {}", describe_gateway(&found[chosen]));
                Ok(Resolution::Tunnel(found[chosen].endpoint))
            } else {
                eprintln!("Multiple KNXnet/IP gateways found:");
                for gw in &found {
                    eprintln!("  - {}", describe_gateway(gw));
                }
                eprintln!(
                    "Re-run with a specific one, e.g. bussard init --gateway {}",
                    found[0].endpoint.ip()
                );
                bail!("multiple gateways found; re-run with --gateway <ip>")
            }
        }
    }
}

/// Renders a gateway for human output: `name (ip:port, IA a.l.d, N tunnels, M in use)`.
///
/// The tunnel clause appears only when the gateway advertised its tunnelling
/// slots (issue #105); older interfaces send no such DIB and are rendered
/// exactly as before.
fn describe_gateway(gw: &GatewayInfo) -> String {
    let name = gw.name.as_deref().unwrap_or("KNXnet/IP gateway");
    let mut parts = vec![gw.endpoint.to_string()];
    if let Some(raw) = gw.individual_address {
        parts.push(format!("IA {}", IndividualAddress::from_raw(raw)));
    }
    if let Some(tunnels) = tunnel_clause(&gw.description) {
        parts.push(tunnels);
    }
    if gw.description.tunnelling_secure_only() {
        parts.push("KNXnet/IP Secure only".to_string());
    } else if gw.description.secure_capable() {
        parts.push("KNXnet/IP Secure capable".to_string());
    }
    format!("{name} ({})", parts.join(", "))
}

/// Renders the tunnel budget as `N tunnels, M in use`, or `None` when the
/// interface did not report its slots.
fn tunnel_clause(description: &GatewayDescription) -> Option<String> {
    let capacity = description.tunnel_capacity()?;
    if description.tunnel_slots.is_some() {
        Some(format!(
            "{} tunnel{}, {} in use",
            capacity.total,
            if capacity.total == 1 { "" } else { "s" },
            capacity.in_use
        ))
    } else {
        // Only the additional-individual-addresses DIB was present: the count is
        // the slot budget, but occupancy is unknown — do not claim "0 in use".
        Some(format!(
            "{} tunnel{} (usage not reported)",
            capacity.total,
            if capacity.total == 1 { "" } else { "s" }
        ))
    }
}

/// Prompts the user to pick one of several gateways on a TTY.
fn prompt_choice(gateways: &[GatewayInfo]) -> anyhow::Result<usize> {
    println!("Multiple KNXnet/IP gateways found:");
    for (i, gw) in gateways.iter().enumerate() {
        println!("  [{}] {}", i + 1, describe_gateway(gw));
    }
    loop {
        print!("Choose a gateway [1-{}]: ", gateways.len());
        std::io::stdout().flush().ok();
        let mut line = String::new();
        let n = std::io::stdin()
            .read_line(&mut line)
            .context("reading gateway choice")?;
        if n == 0 {
            bail!("no selection made (end of input)");
        }
        match line.trim().parse::<usize>() {
            Ok(choice) if (1..=gateways.len()).contains(&choice) => return Ok(choice - 1),
            _ => println!("Please enter a number between 1 and {}.", gateways.len()),
        }
    }
}

/// Parses `host[:port]` into a socket address, defaulting the port to 3671.
fn parse_gateway(spec: &str) -> anyhow::Result<SocketAddrV4> {
    let with_port = if spec.contains(':') {
        spec.to_string()
    } else {
        format!("{spec}:{DEFAULT_PORT}")
    };
    let addr = with_port
        .to_socket_addrs()
        .with_context(|| format!("resolving gateway address {spec:?}"))?
        .find_map(|a| match a {
            std::net::SocketAddr::V4(v4) => Some(v4),
            std::net::SocketAddr::V6(_) => None,
        })
        .with_context(|| format!("no IPv4 address for gateway {spec:?}"))?;
    Ok(addr)
}

/// Best-effort reachability probe: open a tunnel and immediately close it.
///
/// A failure only warns — the user may legitimately be offline while setting up
/// the repo. Runs on a short-lived tokio runtime with an overall timeout so a
/// black-holing address cannot hang `init`.
fn probe_reachability(endpoint: SocketAddrV4) {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            tracing::debug!("could not start runtime for reachability probe: {err}");
            return;
        }
    };
    // Ask the interface to describe itself first: it is a single unicast
    // exchange, costs no tunnel slot, and carries the tunnelling budget the
    // owner needs to see (issue #105).
    // The extended search (issue #182) also says whether the interface
    // requires KNXnet/IP Secure; it falls back to the plain description.
    let description = runtime
        .block_on(bussard_transport::describe_gateway_extended(
            endpoint,
            DESCRIBE_TIMEOUT,
        ))
        .ok();
    if let Some(description) = &description {
        print_description(endpoint, description);
        if description.tunnelling_secure_only() {
            println!(
                "Reachability check skipped: a plain tunnel is refused by this interface. \
                 Commands need its tunnelling credentials: {}.",
                bussard_service::guidance::tunnel_credentials_hint()
            );
            return;
        }
    }

    let config = ConnectionConfig::tunnel(endpoint);
    let result = runtime.block_on(async {
        let probe = async {
            let conn = Transport::connect(&config).await?;
            conn.close().await
        };
        tokio::time::timeout(Duration::from_secs(5), probe).await
    });
    match result {
        Ok(Ok(())) => println!("Reachability check: gateway {endpoint} responded."),
        Ok(Err(bussard_transport::TransportError::NoMoreConnections)) => {
            eprintln!("{}", crate::conn_cmd::no_free_tunnel_message(endpoint));
            eprintln!("Writing the config anyway; free a tunnel before the first command.");
        }
        Ok(Err(err)) => eprintln!(
            "warning: could not reach gateway {endpoint} ({err}); \
             writing the config anyway (you may be offline)."
        ),
        Err(_) => eprintln!(
            "warning: gateway {endpoint} did not respond within 5s; \
             writing the config anyway (you may be offline)."
        ),
    }
}

/// Prints what a DESCRIPTION_RESPONSE said about the interface.
fn print_description(endpoint: SocketAddrV4, description: &GatewayDescription) {
    let name = description.name.as_deref().unwrap_or("KNXnet/IP gateway");
    let ia = description
        .individual_address
        .map(|raw| format!(", IA {}", IndividualAddress::from_raw(raw)))
        .unwrap_or_default();
    println!("Gateway: {name} ({endpoint}{ia})");
    match tunnel_clause(description) {
        Some(clause) => println!("Tunnelling: {clause}."),
        None => println!(
            "Tunnelling: the interface does not report its slot count \
             (older KNXnet/IP interfaces do not)."
        ),
    }
    if let Some(summary) = description.security_summary() {
        println!("{summary}.");
    }
}

/// The real discovery source used outside tests.
fn real_discover() -> anyhow::Result<Vec<GatewayInfo>> {
    let runtime = tokio::runtime::Runtime::new().context("starting tokio runtime for discovery")?;
    runtime
        .block_on(bussard_transport::discover_all(DISCOVER_TIMEOUT))
        .context("discovering gateways")
}

/// Writes the full `knx/` skeleton for the resolved transport.
fn write_skeleton(
    dir: &Path,
    resolution: &Resolution,
    groups: bool,
    keyring: Option<&str>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut config = bussard_toml(resolution);
    if let Some(keyring) = keyring {
        // `[connection]` is the file's only table, so the key lands in it. The
        // path is written as a TOML basic string (escapes included).
        config.push_str(&format!(
            "# The ETS keyring export; its password goes in {}, never here.\nkeyring = {}\n",
            crate::secure_key::KEYRING_PASSWORD_ENV,
            toml_basic_string(keyring)
        ));
    }
    write_file(&dir.join("bussard.toml"), &config)?;
    if groups {
        write_new(&dir.join("groups.toml"), GROUPS_TOML)?;
    }

    let devices_dir = dir.join("devices");
    std::fs::create_dir_all(&devices_dir)
        .with_context(|| format!("creating {}", devices_dir.display()))?;
    write_new(&devices_dir.join(".gitkeep"), DEVICES_GITKEEP)?;

    let captures_dir = dir.join("captures");
    std::fs::create_dir_all(&captures_dir)
        .with_context(|| format!("creating {}", captures_dir.display()))?;
    write_new(&captures_dir.join(".gitignore"), CAPTURES_GITIGNORE)?;

    merge_gitignore(&dir.join(".gitignore"))?;
    write_new(&dir.join("README.md"), README_MD)?;

    Ok(())
}

/// `value` as a TOML basic string: quoted, with `\\` and `"` escaped (a
/// Windows path keeps its backslashes).
fn toml_basic_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Writes `content` to `path` unless a file is already there (`init` in a
/// non-empty directory keeps the repository's own `README.md` and the like).
fn write_new(path: &Path, content: &str) -> anyhow::Result<()> {
    if path.exists() {
        println!("Kept the existing {}.", path.display());
        return Ok(());
    }
    write_file(path, content)
}

/// Writes the model's `.gitignore`, or appends the lines of it an existing
/// `.gitignore` lacks, so `.bussard/` and `*.knxkeys` are always ignored.
fn merge_gitignore(path: &Path) -> anyhow::Result<()> {
    let Ok(existing) = std::fs::read_to_string(path) else {
        return write_file(path, GITIGNORE);
    };
    let present: std::collections::BTreeSet<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<&str> = GITIGNORE
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !present.contains(l.trim()))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str("\n# bussard: its local data and ETS keyring exports stay out of git.\n");
    for line in &missing {
        text.push_str(line);
        text.push('\n');
    }
    println!("Added {} to {}.", missing.join(", "), path.display());
    write_file(path, &text)
}

/// Writes `content` to `path`, erroring with the path for context.
fn write_file(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

/// Builds the `bussard.toml` body for the resolved transport.
fn bussard_toml(resolution: &Resolution) -> String {
    let header = "\
# bussard connection config. Edit `gateway` if your KNXnet/IP interface moves,
# or switch `transport` to \"routing\" to use multicast instead of a tunnel.
";
    match resolution {
        Resolution::Tunnel(endpoint) => {
            format!("{header}[connection]\ntransport = \"tunnel\"\ngateway = \"{endpoint}\"\n")
        }
        Resolution::Routing => format!(
            "{header}[connection]\ntransport = \"routing\"\nmulticast = \"224.0.23.12:3671\"\n"
        ),
        Resolution::Placeholder => format!(
            "{header}[connection]\ntransport = \"tunnel\"\n\
             # TODO: set your gateway's IP, e.g. \"192.0.2.10:3671\".\n\
             # Find it in your router or Home Assistant KNX config, then run\n\
             # `bussard validate --dir knx` to check it.\n\
             gateway = \"192.0.2.10:3671\"\n"
        ),
    }
}

/// `groups.toml` starter: valid and empty, with a header explaining its role.
const GROUPS_TOML: &str = "\
# Group-address plan. Each entry maps a KNX group address to a name and DPT so
# the monitor can decode telegrams. `bussard import` fills this from an ETS
# export; otherwise add entries by hand or as you learn them from `monitor`.
#
# groups = [
#   { address = \"3/0/4\", name = \"Living Room Blind Move\", dpt = \"1.008\" },
# ]
groups = []
";

/// `devices/.gitkeep`: keeps the empty directory in git and explains its use.
const DEVICES_GITKEEP: &str = "\
# Device files live here as `devices/<address>.toml` (one per KNX device): its
# name, location, parameter values and links (com object to group address).
# The vendor facts behind them live in the generated `bussard.lock`. This file
# just keeps the directory in git while it is empty.
";

/// `captures/.gitignore`: ignore everything, since captures are local artefacts.
const CAPTURES_GITIGNORE: &str = "\
# Telegram captures are local artefacts (SQLite databases) — never commit them.
*
!.gitignore
";

/// `knx/.gitignore`: keep bussard's own history (and the other local
/// artefacts) out of git. The history is bussard's, not the repository's: a git
/// user keeps one history in git and one in `.bussard/`, and `bussard undo`
/// reads bussard's.
const GITIGNORE: &str = "\
# bussard's own history and undo data, and data it regenerates (device facts,
# product models). Local to this machine; `bussard history` and `bussard undo`
# read it. Never commit it.
.bussard/

# ETS keyring exports hold key material under their own password. The key
# store bussard.keys is encrypted and meant to be committed; a .knxkeys dropped
# here is not (import it with `bussard keys import`).
*.knxkeys
";

/// `knx/README.md`: onboarding orientation.
const README_MD: &str = "\
# KNX model (bussard)

This directory is your KNX installation as a model. bussard reads it to decode
the bus and to program your devices. The files are plain TOML, but you never
have to edit them by hand: bussard and an assistant driving it write them for
you.

## History and undo are built in

bussard keeps its own history in `.bussard/history/`. Before bussard writes the
model or a device, it saves a full copy of these files, with a note saying which
command did it and when.

- `bussard status`: what has changed since the last save, in plain sentences.
- `bussard history`: every save, oldest first, one line each.
- `bussard show <n>`: what one save changed.
- `bussard undo`: put the files back to the previous save.

`undo` changes files only. Your devices keep working exactly as they are until
you run `bussard plan <device>` and `bussard apply <device>`, which is where you
confirm the change and it reaches the bus.

Edits made in a text editor are picked up too: the next bussard command records
them as an `external edit` save first, so nothing is lost.

## Backups

- `bussard backup`: read every device's tables into `captures/backups/`
  before your first change. It only reads, so it is safe on a live house.
- `bussard restore <backup-dir> <device>`: write one device back from a backup.
- `bussard export house.bussard`: the whole model and its history as one file.
  Keep a copy on a USB stick in the cabinet. `bussard import house.bussard`
  brings it back on another computer.

## Connect your assistant

    claude mcp add knx -- bussard mcp --dir <this directory>

The assistant can read the model, watch the bus, and edit the model; every edit
is saved to the history first. Only you program devices, with `plan` and `apply`.

## Getting started

1. You have an ETS export: `bussard import project.knxproj --dir .`
2. No ETS project: `bussard reconstruct --line 1.1 --out <new directory>` reads
   what the devices carry into a fresh model. Then ask the assistant to help
   you name the group addresses as you press buttons (`bussard learn` does the
   same in a terminal).
3. `bussard audit` reports what you have and what bussard can do with it.

## Files

- `bussard.toml`: connection config, transport (tunnel or routing) and gateway.
- `groups.toml`: the group-address plan, address to name and DPT.
- `devices/`: one file per device, `devices/<address>.toml` (name, location,
  parameter values, and the links from its com objects to group addresses).
- `bussard.lock`: generated by `bussard import` and `bussard adopt`; the vendor
  facts (product, com objects, parameter refs) behind the device files. Never
  edit it by hand.
- `tests.toml`: optional acceptance tests for `bussard test`.
- `captures/`: local telegram captures and device backups.
- `products/`: the product data (vendor `.knxprod` files, and programs
  extracted once from your ETS export) that `bussard.lock` pins. Keep it:
  bussard cannot regenerate it.
- `.bussard/`: bussard's history (`bussard undo` reads it) and data it
  regenerates.

## If you use git

You do not have to. If you do: commit `bussard.toml`, `groups.toml`,
`bussard.lock`, `devices/` and `tests.toml`. The generated `.gitignore` already
excludes `.bussard/`, which is local to this machine. `products/` holds
copyrighted vendor data: committing it is your decision (a private repository
is the usual case), and a clone without it cannot flash until it is restored. A git user then has two histories, one in git and one in bussard;
`bussard undo` reads bussard's.

Guide for new owners: https://github.com/tmbo/bussard/blob/main/docs/getting-started-owner.md
";

/// Prints crisp next steps to stdout.
fn print_next_steps(dir: &Path, imported: bool) {
    let place = crate::conn_cmd::describe_dir(dir);
    // In the current directory every command finds the model without `--dir`.
    let d = if place.starts_with("the current directory") {
        String::new()
    } else {
        format!(" --dir {}", dir.display())
    };
    println!();
    println!("Created a fresh KNX model in {place}.");
    println!();
    println!("Next steps:");
    println!("  - Watch the bus:            bussard monitor{d}");
    if imported {
        println!("  - See one device:           bussard device <address>{d}");
        println!("  - Preview a device write:   bussard plan <address>{d}");
    } else {
        println!("  - Import an ETS export:     bussard import project.knxproj{d}");
        println!("  - Reserve group addresses:  bussard groups reserve \"EG Küche\" light{d}");
    }
    println!("  - Connect Claude via MCP:   claude mcp add knx -- bussard mcp{d}");
    println!();
    println!("Check the model any time:     bussard validate{d}");
    println!("See what changed, and undo it: bussard status{d} / bussard undo{d}");
    println!("When it works, keep a copy:   bussard export{d} (one file to back up or hand over)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Builds a temp dir path unique to this test process/thread.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut base = std::env::temp_dir();
        let unique = format!(
            "bussard-init-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        base.push(unique);
        // Start clean.
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    fn gw(ip: [u8; 4], port: u16, ia: Option<u16>, name: Option<&str>) -> GatewayInfo {
        GatewayInfo {
            endpoint: SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port),
            individual_address: ia,
            name: name.map(str::to_string),
            description: Default::default(),
        }
    }

    fn no_gateways() -> anyhow::Result<Vec<GatewayInfo>> {
        Ok(Vec::new())
    }

    /// An instant no-op reachability probe: keeps `init --gateway` off the
    /// network (the real probe spends up to ~5s connecting to a dead address).
    fn no_probe(_endpoint: SocketAddrV4) {}

    fn one_gateway() -> anyhow::Result<Vec<GatewayInfo>> {
        Ok(vec![gw(
            [192, 0, 2, 10],
            3671,
            Some(0x1100),
            Some("MDT IP"),
        )])
    }

    /// Loads the freshly-written model and asserts it validates with no errors.
    fn assert_validates(dir: &Path) {
        let model = bussard_model::Model::load(dir).expect("model loads");
        let diags = bussard_model::validate(&model);
        assert!(
            !bussard_model::has_errors(&diags),
            "expected clean validation, got: {diags:?}"
        );
    }

    #[test]
    fn refuses_a_dir_that_holds_a_model() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("has-model");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("bussard.toml"), "# mine\n")?;
        let code = run_with(
            &dir,
            None,
            true,
            no_gateways,
            no_probe,
            FirstRun {
                yes: true,
                ..FirstRun::default()
            },
        )?;
        assert_eq!(code, ExitCode::FAILURE);
        assert_eq!(
            std::fs::read_to_string(dir.join("bussard.toml"))?,
            "# mine\n"
        );
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_run_with_non_empty_dir_without_terminal_refuses()
    -> Result<(), Box<dyn std::error::Error>> {
        // nextest runs tests with stdin not a terminal.
        let dir = temp_dir("nonempty");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("something.txt"), "hi")?;
        let result = run_with(&dir, None, true, no_gateways, no_probe, FirstRun::default());
        let err = result
            .err()
            .ok_or("a non-empty dir without --yes must be refused")?;
        let text = format!("{err:#}");
        assert!(
            text.contains("refusing to initialise a model in the non-empty")
                && text.contains("pass --yes to confirm non-interactively"),
            "{text}"
        );
        assert!(!dir.join("bussard.toml").exists());
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_run_with_non_empty_dir_yes_keeps_existing_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("nonempty-yes");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("README.md"), "repo readme\n")?;
        std::fs::write(dir.join(".gitignore"), "target/\n*.knxkeys\n")?;
        let code = run_with(
            &dir,
            None,
            true,
            no_gateways,
            no_probe,
            FirstRun {
                yes: true,
                ..FirstRun::default()
            },
        )?;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(dir.join("bussard.toml").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("README.md"))?,
            "repo readme\n"
        );
        let ignore = std::fs::read_to_string(dir.join(".gitignore"))?;
        assert!(ignore.starts_with("target/\n*.knxkeys\n"), "{ignore}");
        assert!(ignore.contains("\n.bussard/\n"), "{ignore}");
        assert_eq!(ignore.matches("*.knxkeys").count(), 1, "{ignore}");
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_target_state_ignores_repo_files_and_sees_nested_model()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("state");
        assert_eq!(target_state(&dir)?, TargetState::default());
        std::fs::create_dir_all(dir.join(".git"))?;
        std::fs::create_dir_all(dir.join(".bussard"))?;
        std::fs::write(dir.join(".env"), "")?;
        std::fs::write(dir.join(".gitignore"), "")?;
        let state = target_state(&dir)?;
        assert!(!state.needs_confirmation(), "{state:?}");
        std::fs::create_dir_all(dir.join("knx"))?;
        std::fs::write(dir.join("knx").join("bussard.toml"), "")?;
        let state = target_state(&dir)?;
        assert_eq!(
            state,
            TargetState {
                entries: 1,
                nested_model: true
            }
        );
        assert_eq!(state.describe(), "1 entry, a model exists in knx/");
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn empty_dir_proceeds() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("empty");
        std::fs::create_dir_all(&dir)?;

        let code = run_with(&dir, None, true, no_gateways, no_probe, FirstRun::default())?;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(dir.join("bussard.toml").exists());

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn gateway_skips_discovery_and_writes_tunnel() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("gateway");
        // A discovery source that would panic proves discovery is skipped, and an
        // instant no-op probe keeps the test off the network (the real probe
        // spends up to ~5s connecting to the dead address).
        fn boom() -> anyhow::Result<Vec<GatewayInfo>> {
            panic!("discovery must not run when --gateway is given");
        }
        let code = run_with(
            &dir,
            Some("192.0.2.50"),
            false,
            boom,
            no_probe,
            FirstRun::default(),
        )?;
        assert_eq!(code, ExitCode::SUCCESS);

        let text = std::fs::read_to_string(dir.join("bussard.toml"))?;
        assert!(text.contains("transport = \"tunnel\""), "{text}");
        assert!(text.contains("192.0.2.50:3671"), "{text}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    /// The reachability probe is invoked exactly once for the given endpoint when
    /// `--gateway` is used. A thread-local counter proves the wiring without a
    /// real connect (item 2: the probe is injectable).
    #[test]
    fn gateway_invokes_reachability_probe() -> Result<(), Box<dyn std::error::Error>> {
        use std::cell::Cell;
        thread_local! {
            static PROBED: Cell<Option<SocketAddrV4>> = const { Cell::new(None) };
        }
        fn record_probe(endpoint: SocketAddrV4) {
            PROBED.with(|p| p.set(Some(endpoint)));
        }
        fn boom() -> anyhow::Result<Vec<GatewayInfo>> {
            panic!("discovery must not run when --gateway is given");
        }

        let dir = temp_dir("gateway-probe");
        let code = run_with(
            &dir,
            Some("192.0.2.50:3671"),
            false,
            boom,
            record_probe,
            FirstRun::default(),
        )?;
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            PROBED.with(|p| p.get()),
            Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 50), 3671)),
            "the reachability probe must run once against the parsed endpoint"
        );

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn routing_writes_routing_config() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("routing");
        let code = run_with(&dir, None, true, no_gateways, no_probe, FirstRun::default())?;
        assert_eq!(code, ExitCode::SUCCESS);

        let text = std::fs::read_to_string(dir.join("bussard.toml"))?;
        assert!(text.contains("transport = \"routing\""), "{text}");
        assert!(text.contains("224.0.23.12:3671"), "{text}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn single_discovered_gateway_is_used() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("discovered");
        let code = run_with(
            &dir,
            None,
            false,
            one_gateway,
            no_probe,
            FirstRun::default(),
        )?;
        assert_eq!(code, ExitCode::SUCCESS);

        let text = std::fs::read_to_string(dir.join("bussard.toml"))?;
        assert!(text.contains("transport = \"tunnel\""), "{text}");
        assert!(text.contains("192.0.2.10:3671"), "{text}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn no_gateway_writes_placeholder_and_validates() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("placeholder");
        let code = run_with(
            &dir,
            None,
            false,
            no_gateways,
            no_probe,
            FirstRun::default(),
        )?;
        assert_eq!(code, ExitCode::SUCCESS);

        let text = std::fs::read_to_string(dir.join("bussard.toml"))?;
        assert!(text.contains("transport = \"tunnel\""), "{text}");
        assert!(text.contains("TODO"), "placeholder comment present: {text}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn skeleton_is_complete_and_validates() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("skeleton");
        run_with(&dir, None, true, no_gateways, no_probe, FirstRun::default())?;

        for f in ["bussard.toml", "groups.toml", "README.md", ".gitignore"] {
            assert!(dir.join(f).exists(), "missing {f}");
        }
        assert!(dir.join("devices").is_dir());
        assert!(dir.join("captures").is_dir());
        assert!(dir.join("devices/.gitkeep").exists());
        assert!(dir.join("captures/.gitignore").exists());
        assert!(
            !dir.join("links.yaml").exists(),
            "links live in the device files now"
        );
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn absent_dir_is_treated_as_empty() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("absent");
        // Deliberately do not create it.
        assert!(!dir.exists());
        let code = run_with(&dir, None, true, no_gateways, no_probe, FirstRun::default())?;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(dir.join("bussard.toml").exists());

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn parse_gateway_defaults_port() -> Result<(), Box<dyn std::error::Error>> {
        let addr = parse_gateway("192.0.2.10")?;
        assert_eq!(addr, SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 3671));
        let addr = parse_gateway("192.0.2.10:3672")?;
        assert_eq!(addr.port(), 3672);
        Ok(())
    }

    #[test]
    fn describe_gateway_formats_ia() {
        let g = gw([192, 0, 2, 10], 3671, Some(0x1104), Some("Gw"));
        let s = describe_gateway(&g);
        assert!(s.contains("Gw"), "{s}");
        assert!(s.contains("192.0.2.10:3671"), "{s}");
        assert!(s.contains("IA 1.1.4"), "{s}");
    }
}
