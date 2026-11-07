//! The `bussard init` subcommand — from-scratch onboarding.
//!
//! Creates a fresh `knx/` model directory: resolves a gateway (explicit,
//! routing, or by KNXnet/IP discovery across every local interface), writes the
//! TOML skeleton, and prints next steps. The result validates cleanly.
//!
//! The first run is one command. With a project (a `.knxproj`) given as the
//! argument, or exactly one `.knxproj`
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
//! The steps live in [`bussard_service::setup`], which the MCP tool
//! `knx_setup` runs too (issue #745); this command answers the setup's
//! questions on the terminal and prints its lines.

use std::io::{IsTerminal, Write};
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use bussard_model::Model;
use bussard_service::observer::{Answer, Ask, ProgressSink, Prompt, Question};
use bussard_service::setup::gateway::describe_gateway;
use bussard_service::setup::{
    self, SetupError, SetupHooks, SetupOutcome, SetupRequest, TargetState,
};
use bussard_service::transport::knxnet::GatewayInfo;

use crate::cli::{Resolved, Run, Spec};
use crate::console::Console;

/// Injection point for discovery so tests never touch the network.
///
/// Defaults to the real transport discovery across all interfaces; tests swap
/// in a stub. Kept as a function pointer to avoid a trait-object dance.
type DiscoverFn = fn() -> anyhow::Result<Vec<GatewayInfo>>;

/// Injection point for the `--gateway` reachability probe so tests never touch
/// the network. Defaults to [`real_probe`]; tests swap in an instant
/// no-op so `init --gateway <dead-address>` does not spend the real ~5s connect
/// budget against an unreachable endpoint.
type ProbeFn = fn(SocketAddrV4);

/// `bussard init`: what it does after the skeleton, import a project or
/// scan a line.
#[derive(Debug, Clone, Default, clap::Args)]
pub(crate) struct InitArgs {
    /// The ETS project (`.knxproj`) to import right away. Default: the one
    /// `.knxproj` next to the project folder, when there is exactly one.
    #[arg(value_name = "PROJECT")]
    project: Option<PathBuf>,
    /// Project password (else `BUSSARD_PROJECT_PASSWORD`, else prompt).
    #[arg(long)]
    password: Option<String>,
    /// Download missing vendor product data without asking. Without a
    /// terminal and without this flag nothing is downloaded; the missing
    /// order numbers are listed.
    #[arg(long, conflicts_with = "no_download")]
    yes_download: bool,
    /// Do not download missing product data; list it instead.
    #[arg(long)]
    no_download: bool,
    /// Without a project: scan this line after writing the skeleton and
    /// list what answers, without asking (for scripts).
    #[arg(long, value_name = "LINE", conflicts_with = "project")]
    scan: Option<String>,
    /// Skip the confirmation prompt: initialise a non-empty directory.
    #[arg(long)]
    yes: bool,
}

impl Run for InitArgs {
    fn spec(&self) -> Spec {
        Spec::CREATES
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        let find_project = self.project.is_none() && self.scan.is_none();
        run_setup(
            g.dir(),
            g.gateway.as_deref(),
            g.routing,
            real_discover,
            real_probe,
            self,
            find_project,
        )
    }
}

/// The real discovery source used outside tests.
fn real_discover() -> anyhow::Result<Vec<GatewayInfo>> {
    Ok(setup::gateway::real_discover()?)
}

/// The real reachability probe used outside tests.
fn real_probe(endpoint: SocketAddrV4) {
    setup::gateway::probe_reachability(endpoint, &mut Console);
}

/// The terminal's answers to the setup's questions.
struct Terminal {
    /// The discovery source.
    discover: DiscoverFn,
    /// The reachability probe.
    probe: ProbeFn,
    /// `--yes`.
    yes: bool,
    /// The product-data download answer.
    consent: crate::confirm::Answers,
}

impl Prompt for Terminal {
    fn ask(&mut self, question: &Question) -> Answer {
        self.consent.ask(question)
    }

    fn can_ask(&self) -> bool {
        self.consent.can_ask()
    }

    fn skips(&self, kind: Ask) -> Option<String> {
        self.consent.skips(kind)
    }
}

impl SetupHooks for Terminal {
    fn discover(&mut self) -> Result<Vec<GatewayInfo>, SetupError> {
        (self.discover)().map_err(SetupError::source)
    }

    fn probe(&mut self, endpoint: SocketAddrV4, _out: &mut dyn ProgressSink) {
        (self.probe)(endpoint);
    }

    fn confirm_target(&mut self, dir: &Path, _state: TargetState) -> Result<bool, SetupError> {
        let confirmed =
            confirm_target(dir, self.yes, TargetVerb::Init).map_err(SetupError::source)?;
        if !confirmed {
            eprintln!("Not confirmed; nothing written.");
        }
        Ok(confirmed)
    }

    fn no_gateway(&mut self, out: &mut dyn ProgressSink) -> bool {
        out.warn("No KNXnet/IP gateways responded to discovery.");
        out.warn("Likely causes:");
        out.warn("  - This machine is on a different subnet than the gateway ");
        out.warn("    (KNX discovery is multicast and does not route across subnets).");
        out.warn("  - The gateway has KNXnet/IP tunneling/discovery disabled.");
        out.warn("Find the gateway's IP (from your router, or the Home Assistant KNX config)");
        out.warn("and re-run:  bussard init --gateway <ip>   (or --routing for multicast).");
        out.warn("Writing a skeleton with a placeholder gateway for now.");
        true
    }

    fn choose_gateway(
        &mut self,
        found: &[GatewayInfo],
        out: &mut dyn ProgressSink,
    ) -> Result<Option<usize>, SetupError> {
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            let chosen = prompt_choice(found).map_err(SetupError::source)?;
            out.say(&format!(
                "Using gateway: {}",
                describe_gateway(&found[chosen])
            ));
            return Ok(Some(chosen));
        }
        out.warn("Multiple KNXnet/IP gateways found:");
        for gw in found {
            out.warn(&format!("  - {}", describe_gateway(gw)));
        }
        if let Some(first) = found.first() {
            out.warn(&format!(
                "Re-run with a specific one, e.g. bussard init --gateway {}",
                first.endpoint.ip()
            ));
        }
        Err(SetupError::Message(
            "multiple gateways found; re-run with --gateway <ip>".to_string(),
        ))
    }

    fn several_projects(
        &mut self,
        dir: &Path,
        found: &[PathBuf],
        out: &mut dyn ProgressSink,
    ) -> bool {
        out.say("Found several ETS projects; name the one to import:");
        for p in found {
            out.say(&format!(
                "  bussard init {} --dir {}",
                p.display(),
                dir.display()
            ));
        }
        true
    }

    fn project_password(&mut self) -> Result<Option<String>, SetupError> {
        crate::import_cmd::ask_password()
    }

    fn write_import(
        &mut self,
        model: Model,
        dir: &Path,
        project: Option<&Path>,
        _out: &mut dyn ProgressSink,
    ) -> Result<u8, SetupError> {
        let choice = crate::import_bundle::ConflictChoice::from_flags(false, false, false);
        let code = crate::import_cmd::write_model(
            model,
            dir,
            choice,
            "project",
            Some(self.consent),
            project,
        )
        .map_err(SetupError::source)?;
        Ok(if code == ExitCode::SUCCESS {
            0
        } else {
            crate::import_cmd::EXIT_CONFLICTS
        })
    }
}

/// The testable core: same as [`run`] but with injectable discovery and probe
/// sources, and the project search on or off.
fn run_setup(
    dir: &Path,
    gateway: Option<&str>,
    routing: bool,
    discover: DiscoverFn,
    probe: ProbeFn,
    first: InitArgs,
    find_project: bool,
) -> anyhow::Result<ExitCode> {
    let request = SetupRequest {
        dir: dir.to_path_buf(),
        gateway: gateway.map(str::to_string),
        routing,
        project: first.project.clone(),
        find_project,
        password: first.password.clone(),
    };
    let mut hooks = Terminal {
        discover,
        probe,
        yes: first.yes,
        consent: crate::confirm::Answers {
            yes_download: first.yes_download,
            no_download: first.no_download,
            ..Default::default()
        },
    };
    let outcome = setup::run(&request, &mut hooks, &mut Console)?;
    let resolution = match outcome {
        SetupOutcome::HasModel => {
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
        SetupOutcome::NotConfirmed | SetupOutcome::Stopped => return Ok(ExitCode::FAILURE),
        SetupOutcome::Written {
            imported: Some((_, code)),
            ..
        } => {
            print_next_steps(dir, true);
            return Ok(ExitCode::from(code));
        }
        SetupOutcome::Written {
            resolution,
            imported: None,
        } => resolution,
    };

    // Without a project, the first run scans the line (asked on a terminal).
    let scan_line = match (&first.scan, &resolution) {
        (Some(line), _) => Some(line.clone()),
        (None, setup::Resolution::Placeholder) => None,
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

    // Print next steps.
    print_next_steps(dir, false);

    Ok(ExitCode::SUCCESS)
}

/// The tests' entry point: [`run_setup`] without the project search.
#[cfg(test)]
fn run_with(
    dir: &Path,
    gateway: Option<&str>,
    routing: bool,
    discover: DiscoverFn,
    probe: ProbeFn,
    first: InitArgs,
) -> anyhow::Result<ExitCode> {
    run_setup(dir, gateway, routing, discover, probe, first, false)
}

/// The line the first-run scan offers: the first line of the first area, where
/// a single-line installation and most interfaces sit. `--scan <LINE>` names
/// another.
const DEFAULT_SCAN_LINE: &str = "1.1";

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
    let state = setup::skeleton::target_state(dir)?;
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
            anyhow::bail!("no selection made (end of input)");
        }
        match line.trim().parse::<usize>() {
            Ok(choice) if (1..=gateways.len()).contains(&choice) => return Ok(choice - 1),
            _ => println!("Please enter a number between 1 and {}.", gateways.len()),
        }
    }
}

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
    use bussard_service::setup::gateway::parse_gateway;
    use bussard_service::setup::skeleton::target_state;

    fn merge_gitignore(path: &Path) -> anyhow::Result<()> {
        Ok(setup::skeleton::merge_gitignore(path, &mut Console)?)
    }
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
            InitArgs {
                yes: true,
                ..InitArgs::default()
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
        let result = run_with(&dir, None, true, no_gateways, no_probe, InitArgs::default());
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
            InitArgs {
                yes: true,
                ..InitArgs::default()
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
    fn test_run_with_fresh_dir_ignores_env() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("fresh-env");
        run_with(&dir, None, true, no_gateways, no_probe, InitArgs::default())?;
        let ignore = std::fs::read_to_string(dir.join(".gitignore"))?;
        assert!(
            ignore.contains("# passwords for bussard, read automatically; never commit\n.env\n"),
            "{ignore}"
        );
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_merge_gitignore_adds_env_once() -> Result<(), Box<dyn std::error::Error>> {
        let dir = temp_dir("merge-env");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(".gitignore");
        std::fs::write(&path, "target/\n.bussard/\n*.knxkeys\n")?;
        merge_gitignore(&path)?;
        let once = std::fs::read_to_string(&path)?;
        assert!(
            once.starts_with("target/\n.bussard/\n*.knxkeys\n"),
            "{once}"
        );
        assert_eq!(once.lines().filter(|l| *l == ".env").count(), 1, "{once}");
        merge_gitignore(&path)?;
        assert_eq!(std::fs::read_to_string(&path)?, once);
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn test_merge_gitignore_with_env_present_is_unchanged() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = temp_dir("merge-env-present");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(".gitignore");
        let before = "node_modules/\n.env\n.bussard/\n*.knxkeys\n";
        std::fs::write(&path, before)?;
        merge_gitignore(&path)?;
        assert_eq!(std::fs::read_to_string(&path)?, before);
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

        let code = run_with(&dir, None, true, no_gateways, no_probe, InitArgs::default())?;
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
            InitArgs::default(),
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
            InitArgs::default(),
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
        let code = run_with(&dir, None, true, no_gateways, no_probe, InitArgs::default())?;
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
            InitArgs::default(),
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
            InitArgs::default(),
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
        run_with(&dir, None, true, no_gateways, no_probe, InitArgs::default())?;

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
        let code = run_with(&dir, None, true, no_gateways, no_probe, InitArgs::default())?;
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
