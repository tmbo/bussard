//! The `bussard init` subcommand — from-scratch onboarding.
//!
//! Creates a fresh `knx/` model directory: resolves a gateway (explicit,
//! routing, or by KNXnet/IP discovery across every local interface), writes the
//! YAML skeleton, and prints next steps. The result validates cleanly.
//!
//! The `bussard.yaml` content is constructed here by hand (three simple keys)
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
use bussard_transport::knxnet::GatewayInfo;
use bussard_transport::{BusConnection, ConnectionConfig, Transport};

/// Per-interface discovery timeout.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Creates a fresh `knx/` model directory.
pub fn run(dir: &Path, gateway: Option<&str>, routing: bool) -> anyhow::Result<ExitCode> {
    run_with(dir, gateway, routing, real_discover, probe_reachability)
}

/// The testable core: same as [`run`] but with injectable discovery and probe
/// sources.
fn run_with(
    dir: &Path,
    gateway: Option<&str>,
    routing: bool,
    discover: DiscoverFn,
    probe: ProbeFn,
) -> anyhow::Result<ExitCode> {
    // 1. Refuse a non-empty target directory.
    if dir_is_non_empty(dir)? {
        eprintln!("error: {} already exists and is not empty.", dir.display());
        eprintln!("It looks like a model already lives here. Try one of:");
        eprintln!("  bussard validate --dir {}", dir.display());
        eprintln!(
            "  bussard import <project.knxproj> --dir {}   (to (re)import from ETS)",
            dir.display()
        );
        return Ok(ExitCode::FAILURE);
    }

    // 2. Resolve the gateway.
    let resolution = resolve_gateway(gateway, routing, discover, probe)?;

    // 3. Write the skeleton.
    write_skeleton(dir, &resolution)?;

    // 4. Print next steps.
    print_next_steps(dir);

    Ok(ExitCode::SUCCESS)
}

/// A directory is "non-empty" if it exists and contains at least one entry. An
/// absent directory, or an existing empty one, is fine to initialise into.
fn dir_is_non_empty(dir: &Path) -> anyhow::Result<bool> {
    if !dir.exists() {
        return Ok(false);
    }
    if !dir.is_dir() {
        bail!("{} exists but is not a directory", dir.display());
    }
    let mut entries =
        std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    Ok(entries.next().is_some())
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

/// Renders a gateway for human output: `name (ip:port, IA a.l.d)`.
fn describe_gateway(gw: &GatewayInfo) -> String {
    let name = gw.name.as_deref().unwrap_or("KNXnet/IP gateway");
    match gw.individual_address {
        Some(raw) => {
            let ia = IndividualAddress::from_raw(raw);
            format!("{name} ({}, IA {ia})", gw.endpoint)
        }
        None => format!("{name} ({})", gw.endpoint),
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

/// The real discovery source used outside tests.
fn real_discover() -> anyhow::Result<Vec<GatewayInfo>> {
    let runtime = tokio::runtime::Runtime::new().context("starting tokio runtime for discovery")?;
    runtime
        .block_on(bussard_transport::discover_all(DISCOVER_TIMEOUT))
        .context("discovering gateways")
}

/// Writes the full `knx/` skeleton for the resolved transport.
fn write_skeleton(dir: &Path, resolution: &Resolution) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    write_file(&dir.join("bussard.yaml"), &bussard_yaml(resolution))?;
    write_file(&dir.join("groups.yaml"), GROUPS_YAML)?;
    write_file(&dir.join("links.yaml"), LINKS_YAML)?;

    let devices_dir = dir.join("devices");
    std::fs::create_dir_all(&devices_dir)
        .with_context(|| format!("creating {}", devices_dir.display()))?;
    write_file(&devices_dir.join(".gitkeep"), DEVICES_GITKEEP)?;

    let captures_dir = dir.join("captures");
    std::fs::create_dir_all(&captures_dir)
        .with_context(|| format!("creating {}", captures_dir.display()))?;
    write_file(&captures_dir.join(".gitignore"), CAPTURES_GITIGNORE)?;

    write_file(&dir.join(".gitignore"), GITIGNORE)?;
    write_file(&dir.join("README.md"), README_MD)?;

    Ok(())
}

/// Writes `content` to `path`, erroring with the path for context.
fn write_file(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

/// Builds the `bussard.yaml` body for the resolved transport.
fn bussard_yaml(resolution: &Resolution) -> String {
    let header = "\
# bussard connection config. Edit `gateway` if your KNXnet/IP interface moves,
# or switch `transport` to `routing` to use multicast instead of a tunnel.
";
    match resolution {
        Resolution::Tunnel(endpoint) => {
            format!("{header}connection:\n  transport: tunnel\n  gateway: \"{endpoint}\"\n")
        }
        Resolution::Routing => format!(
            "{header}connection:\n  transport: routing\n  multicast: \"224.0.23.12:3671\"\n"
        ),
        Resolution::Placeholder => format!(
            "{header}connection:\n  transport: tunnel\n  \
             # TODO: set your gateway's IP, e.g. \"192.0.2.10:3671\".\n  \
             # Find it in your router or Home Assistant KNX config, then run\n  \
             # `bussard validate --dir knx` to check it.\n  \
             gateway: \"192.0.2.10:3671\"\n"
        ),
    }
}

/// `groups.yaml` starter: valid and empty, with a header explaining its role.
const GROUPS_YAML: &str = "\
# Group-address plan. Each entry maps a KNX group address to a name and DPT so
# the monitor can decode telegrams. `bussard import` fills this from an ETS
# export; otherwise add entries by hand or as you learn them from `monitor`.
#
# groups:
#   \"3/0/4\":
#     name: \"Living Room Blind Move\"
#     dpt: \"1.008\"
groups: {}
";

/// `links.yaml` starter: valid and empty, with a header explaining its role.
const LINKS_YAML: &str = "\
# Com-object → group-address links, keyed by device individual address. These
# mirror KNX association semantics (one `send` GA, any number of `listen` GAs).
# `bussard import` fills this from an ETS export.
#
# links:
#   \"1.1.4\":
#     - object: 12
#       name: \"A: Behang Auf/Ab\"
#       listen: [\"3/0/4\"]
links: {}
";

/// `devices/.gitkeep`: keeps the empty directory in git and explains its use.
const DEVICES_GITKEEP: &str = "\
# Device files live here as `devices/<ia>-<slug>.yaml` (one per KNX device):
# identity, naming, and an import-generated com-object section. This file just
# keeps the directory in git while it is empty.
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
# bussard's own history and undo data. Local to this machine; `bussard history`
# and `bussard undo` read it. Never commit it.
.bussard/

# Local, vendor-derived or generated data (see docs/product-data.md).
models/
vendor/
";

/// `knx/README.md`: onboarding orientation.
const README_MD: &str = "\
# KNX model (bussard)

This directory is your KNX installation as code. bussard reads it to decode the
bus and to push changes to your devices. Everything here is plain YAML, but you
never have to edit it by hand: `bussard` and an assistant driving it write these
files for you.

## Undo is built in

bussard keeps its own history in `.bussard/history/`. Every time bussard writes
the model or the bus it first saves a full copy of these files, with a note
saying which command did it and when.

- `bussard status` — what has changed since the last save, in plain sentences.
- `bussard history` — every save, oldest first, one line each.
- `bussard show <n>` — what one of them changed.
- `bussard undo` — put the files back to the previous save.

`undo` changes files only. Your devices keep working exactly as they are until
you run `bussard plan <device>` and `bussard apply <device>`, which is where you
confirm the change and it reaches the bus.

Edits you make in a text editor are picked up too: the next bussard command
records them as an `external edit` save first, so nothing is lost.

## Files

- `bussard.yaml` — connection config: transport (tunnel or routing) and gateway.
- `groups.yaml` — the group-address plan: address → name + DPT.
- `links.yaml` — com-object → group-address links, keyed by device address.
- `devices/` — one YAML file per device (identity, naming, com-objects).
- `captures/` — local telegram captures (git-ignored).
- `.bussard/` — bussard's history (git-ignored; `bussard undo` reads it).

## Getting started

Two onboarding paths:

1. **You have an ETS export** — import it to populate the model:
   `bussard import project.knxproj --dir .`
2. **No ETS project** — watch the bus and build the model as you go:
   `bussard monitor --dir .`

## If you use git

You do not have to. If you do: commit `bussard.yaml`, `groups.yaml`,
`links.yaml` and `devices/`. The generated `.gitignore` already excludes
`.bussard/`, `models/`, `vendor/` and `captures/`, which are local to this
machine. A git user then has two histories, one in git and one in bussard;
`bussard undo` reads bussard's.

Docs: https://github.com/tmbo/bussard
";

/// Prints crisp next steps to stdout.
fn print_next_steps(dir: &Path) {
    let d = dir.display();
    println!();
    println!("Created a fresh KNX model in {d}.");
    println!();
    println!("Next steps:");
    println!("  - Watch the bus:            bussard monitor --dir {d}");
    println!("  - Import an ETS export:     bussard import project.knxproj --dir {d}");
    println!("  - Connect Claude via MCP:   claude mcp add knx -- bussard mcp --dir {d}");
    println!();
    println!("Check the model any time:     bussard validate --dir {d}");
    println!("See what changed, and undo it: bussard status --dir {d} / bussard undo --dir {d}");
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
    fn refuses_non_empty_dir() {
        let dir = temp_dir("nonempty");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("something.txt"), "hi").unwrap();

        let code = run_with(&dir, None, false, no_gateways, no_probe).unwrap();
        assert_eq!(code, ExitCode::FAILURE);
        // Original content untouched: we didn't write a skeleton.
        assert!(!dir.join("bussard.yaml").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_dir_proceeds() {
        let dir = temp_dir("empty");
        std::fs::create_dir_all(&dir).unwrap();

        let code = run_with(&dir, None, true, no_gateways, no_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(dir.join("bussard.yaml").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gateway_skips_discovery_and_writes_tunnel() {
        let dir = temp_dir("gateway");
        // A discovery source that would panic proves discovery is skipped, and an
        // instant no-op probe keeps the test off the network (the real probe
        // spends up to ~5s connecting to the dead address).
        fn boom() -> anyhow::Result<Vec<GatewayInfo>> {
            panic!("discovery must not run when --gateway is given");
        }
        let code = run_with(&dir, Some("192.0.2.50"), false, boom, no_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);

        let yaml = std::fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert!(yaml.contains("transport: tunnel"), "{yaml}");
        assert!(yaml.contains("192.0.2.50:3671"), "{yaml}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The reachability probe is invoked exactly once for the given endpoint when
    /// `--gateway` is used. A thread-local counter proves the wiring without a
    /// real connect (item 2: the probe is injectable).
    #[test]
    fn gateway_invokes_reachability_probe() {
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
        let code = run_with(&dir, Some("192.0.2.50:3671"), false, boom, record_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            PROBED.with(|p| p.get()),
            Some(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 50), 3671)),
            "the reachability probe must run once against the parsed endpoint"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn routing_writes_routing_config() {
        let dir = temp_dir("routing");
        let code = run_with(&dir, None, true, no_gateways, no_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);

        let yaml = std::fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert!(yaml.contains("transport: routing"), "{yaml}");
        assert!(yaml.contains("224.0.23.12:3671"), "{yaml}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn single_discovered_gateway_is_used() {
        let dir = temp_dir("discovered");
        let code = run_with(&dir, None, false, one_gateway, no_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);

        let yaml = std::fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert!(yaml.contains("transport: tunnel"), "{yaml}");
        assert!(yaml.contains("192.0.2.10:3671"), "{yaml}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_gateway_writes_placeholder_and_validates() {
        let dir = temp_dir("placeholder");
        let code = run_with(&dir, None, false, no_gateways, no_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);

        let yaml = std::fs::read_to_string(dir.join("bussard.yaml")).unwrap();
        assert!(yaml.contains("transport: tunnel"), "{yaml}");
        assert!(yaml.contains("TODO"), "placeholder comment present: {yaml}");
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skeleton_is_complete_and_validates() {
        let dir = temp_dir("skeleton");
        run_with(&dir, None, true, no_gateways, no_probe).unwrap();

        for f in [
            "bussard.yaml",
            "groups.yaml",
            "links.yaml",
            "README.md",
            ".gitignore",
        ] {
            assert!(dir.join(f).exists(), "missing {f}");
        }
        assert!(dir.join("devices").is_dir());
        assert!(dir.join("captures").is_dir());
        assert!(dir.join("devices/.gitkeep").exists());
        assert!(dir.join("captures/.gitignore").exists());
        assert_validates(&dir);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn absent_dir_is_treated_as_empty() {
        let dir = temp_dir("absent");
        // Deliberately do not create it.
        assert!(!dir.exists());
        let code = run_with(&dir, None, true, no_gateways, no_probe).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(dir.join("bussard.yaml").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_gateway_defaults_port() {
        let addr = parse_gateway("192.0.2.10").unwrap();
        assert_eq!(addr, SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 3671));
        let addr = parse_gateway("192.0.2.10:3672").unwrap();
        assert_eq!(addr.port(), 3672);
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
