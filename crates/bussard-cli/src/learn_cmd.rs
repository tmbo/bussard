//! The `bussard learn` subcommand: name and type group addresses from live
//! traffic (issue #95).
//!
//! Learn mode is the terminal half of a loop an LLM assistant also drives over
//! MCP (`knx_wait_for_telegram` then `knx_infer_group`). It asks the operator to
//! trigger the object they want to name, waits for the telegram, shows who sent
//! it and what the payload could mean, proposes a name, and writes the accepted
//! answer into `groups.toml` (and the device file's links when the sending com object can
//! be identified).
//!
//! # It never transmits
//!
//! Learn mode only ever *listens*. It opens the bus connection the monitor uses
//! and subscribes to inbound frames; it never calls a send path, so no
//! `GroupValueRead`, no write, no management traffic. `crates/bussard-cli/tests/
//! learn_mock.rs` proves it by counting the tunnelling requests a mock gateway
//! receives during a full scripted session (zero).
//!
//! # Secured group telegrams
//!
//! With a keyring (`--keyring`, or `connection.keyring` in `bussard.toml`)
//! learn decodes like `monitor` does (issue #204): a KNX Data Secure group
//! telegram is verified and decrypted with its GA's group key, the inner APDU
//! feeds the inference, and the learned group is marked `secure`. The
//! sequence-freshness warning is shown with the observation. A secured
//! telegram that cannot be verified (no keyring, no key for the GA, a MAC
//! failure) is reported and skipped, never guessed at. Decrypting is local; it
//! sends nothing.

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bussard_model::{Dpt, GroupAddress, IndividualAddress, Model};
use bussard_monitor::{ApciKind, DecodedTelegram, Filter, TelegramRing};
use bussard_service::{BusService, WritePolicy, learn};

use crate::cli::{Resolved, Run, Spec};
use crate::conn_cmd::{gateway_display, load_model_required, resolve_config};

/// `bussard learn`.
#[derive(Debug, Clone, Default, clap::Args)]
pub(crate) struct LearnArgs {
    /// Learn this group address (repeatable). Without it, `--unnamed` /
    /// `--untyped` pick targets from the project, and a bare `learn` takes
    /// whatever appears on the bus.
    #[arg(long = "ga", value_name = "GA")]
    gas: Vec<String>,
    /// Learn every group address in the project whose name is a placeholder.
    #[arg(long)]
    unnamed: bool,
    /// Learn every group address in the project that has no DPT.
    #[arg(long)]
    untyped: bool,
    /// Skip the confirmation prompt: accept the top DPT candidate and the
    /// proposed name. Without a terminal the command is refused unless
    /// this is given.
    #[arg(long)]
    yes: bool,
    /// How long to wait for each telegram, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    timeout: u64,
}

impl Run for LearnArgs {
    fn spec(&self) -> Spec {
        Spec::BUS
    }

    fn early_consent(&self) -> Option<(bool, String)> {
        Some((self.yes, "learn group addresses".to_string()))
    }

    fn run(self, g: &Resolved) -> anyhow::Result<ExitCode> {
        run(self, g)
    }
}

/// The APCI of `A_SecureData`, the envelope of a KNX Data Secure telegram.
const APCI_SECURE_DATA: u16 = 0x03F1;

/// Runs `bussard learn`.
fn run(options: LearnArgs, g: &Resolved) -> anyhow::Result<ExitCode> {
    let (dir, overrides) = (g.dir(), g.group());
    // Learn writes the model, so a present-but-broken model is a hard error
    // (the same rule the write commands follow); an absent directory is a fresh
    // project we are about to populate.
    let mut model = load_model_required(dir)?.unwrap_or_else(empty_model);

    // A run without a terminal and without --yes was refused before this, by
    // `confirm::require_terminal_or_yes` in `main`.
    let interactive = std::io::stdin().is_terminal();

    let targets = resolve_targets(&model, &options)?;
    let timeout = Duration::from_secs(options.timeout.clamp(1, 3600));

    let config = resolve_config(Some(&model), &overrides)?;
    // KNX Data Secure group telegrams (issue #204): the same group keys and
    // decode path as `monitor`. Loaded before connecting so a wrong password
    // fails fast.
    let group_keys = crate::secure_key::group_keyring(g.keyring())?;
    eprintln!(
        "gateway: {} (listening only, never transmits)",
        gateway_display(&config)
    );

    let runtime = tokio::runtime::Runtime::new()?;
    // Listening only: a read-only service, never gated.
    let service = {
        let _context = runtime.enter();
        BusService::open(config, WritePolicy::ReadOnly)?
    };
    let session = runtime.block_on(async move {
        let handle = service.handle().clone();
        let ring = TelegramRing::new();

        // Feed the ring from the inbound frames, decoded against the model as
        // it was when the session started, secured group telegrams unwrapped
        // with the keyring. Nothing here ever sends.
        let feeder_ring = ring.clone();
        let feeder_model = model.clone();
        let feeder_handle = handle.clone();
        let mut feeder_keys = group_keys;
        let feeder = tokio::spawn(async move {
            let mut sub = feeder_handle.subscribe();
            while let Some(inbound) = sub.recv().await {
                let decoded = DecodedTelegram::from_frame_secured(
                    &inbound.frame,
                    Some(&feeder_model),
                    feeder_keys.as_mut(),
                );
                feeder_ring.push_with_code(decoded, inbound.message_code);
            }
        });

        if !handle.wait_connected(crate::conn_cmd::connect_wait()).await {
            eprintln!("warning: not connected to the bus yet; still waiting for telegrams");
        }

        let outcome = learn_loop(&mut model, &ring, &targets, &options, timeout, interactive).await;

        // Close cleanly so the gateway's tunnel slot is released (issue #31).
        let _ = handle.close().await;
        feeder.abort();
        outcome.map(|changes| (model, changes))
    })?;

    let (model, changes) = session;
    if changes.groups == 0 && changes.links == 0 {
        eprintln!("nothing learned; the model is unchanged.");
        return Ok(ExitCode::SUCCESS);
    }
    // History (issue #110): keep the pre-learn files so `bussard undo` can put
    // them back, recording any edit made outside bussard first.
    crate::history_cmd::capture_external_edit(dir);
    crate::history_cmd::snapshot(
        dir,
        bussard_model::history::SnapshotReason::new("learn")
            .with_result("before writing the learned names and DPTs"),
    );
    model
        .save(dir)
        .with_context(|| format!("saving the learned model to {}", dir.display()))?;
    println!(
        "learned {} group address(es) and {} link(s); wrote {}",
        changes.groups,
        changes.links,
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// What one session changed.
#[derive(Debug, Default, Clone, Copy)]
struct Changes {
    groups: usize,
    links: usize,
}

/// What the session should wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// A specific group address.
    Ga(GroupAddress),
    /// Whatever appears on the bus next.
    Any,
}

/// Resolves the list of things to learn from the flags and the model.
fn resolve_targets(model: &Model, options: &LearnArgs) -> anyhow::Result<Vec<Target>> {
    if !options.gas.is_empty() {
        return options
            .gas
            .iter()
            .map(|s| {
                s.parse::<GroupAddress>()
                    .map(Target::Ga)
                    .map_err(|_| anyhow!("invalid group address {s:?}"))
            })
            .collect();
    }
    if options.unnamed || options.untyped {
        let mut targets: Vec<Target> = Vec::new();
        for (ga, group) in &model.groups.groups {
            let wanted = (options.unnamed && learn::is_placeholder_name(*ga, &group.name))
                || (options.untyped && group.dpt.is_none());
            if wanted {
                targets.push(Target::Ga(*ga));
            }
        }
        if targets.is_empty() {
            eprintln!("no group address in the model matches --unnamed/--untyped; nothing to do.");
        }
        return Ok(targets);
    }
    // Open-ended: learn whatever shows up until the operator quits.
    Ok(vec![Target::Any])
}

/// The interactive loop over the resolved targets.
async fn learn_loop(
    model: &mut Model,
    ring: &TelegramRing,
    targets: &[Target],
    options: &LearnArgs,
    timeout: Duration,
    interactive: bool,
) -> anyhow::Result<Changes> {
    let mut changes = Changes::default();
    let open_ended = targets.first() == Some(&Target::Any);
    let mut handled: Vec<GroupAddress> = Vec::new();

    let mut index = 0usize;
    loop {
        let target = if open_ended {
            Target::Any
        } else {
            match targets.get(index) {
                Some(t) => *t,
                None => break,
            }
        };
        index += 1;

        let (filter, label) = match target {
            Target::Ga(ga) => (Filter::parse(&ga.to_string())?, ga.to_string()),
            Target::Any => (Filter::default(), "any group address".to_string()),
        };

        if !open_ended {
            eprintln!(
                "\n[{}/{}] {label}: trigger the object you want to name (waiting up to {}s)",
                index,
                targets.len(),
                timeout.as_secs()
            );
        } else {
            eprintln!(
                "\ntrigger an object you want to name (waiting up to {}s)",
                timeout.as_secs()
            );
        }

        // Telegrams already buffered for this GA sharpen the inference.
        let earlier: Vec<Vec<u8>> = ring
            .recent(&filter, None)
            .into_iter()
            .rev()
            .filter(|t| secure_block(t).is_none())
            .filter_map(|t| t.destination.group().map(|_| t.payload))
            .filter(|p| !p.is_empty())
            .collect();

        let Some(telegram) = ring.wait_for(&filter, timeout).await else {
            eprintln!("  nothing arrived within {}s; skipping.", timeout.as_secs());
            if open_ended {
                break;
            }
            continue;
        };

        let Some(ga) = telegram.destination.group() else {
            continue;
        };
        if open_ended && handled.contains(&ga) {
            // Already dealt with in this session; keep listening.
            index = index.saturating_sub(1);
            continue;
        }
        handled.push(ga);

        if let Some(reason) = secure_block(&telegram) {
            eprintln!("  {ga} sender {}: {reason}; skipping.", telegram.source);
            continue;
        }

        match consider(model, ga, &telegram, &earlier, options, interactive)? {
            Decision::Quit => break,
            Decision::Skipped => continue,
            Decision::Accepted { made_link } => {
                changes.groups += 1;
                if made_link {
                    changes.links += 1;
                }
            }
        }
    }
    Ok(changes)
}

/// Why a secured telegram cannot be learned from, or `None` when its payload
/// is usable: a plain telegram, or a secured one whose MAC verified (its
/// payload is then the decrypted inner APDU's).
fn secure_block(telegram: &DecodedTelegram) -> Option<String> {
    use bussard_monitor::SecureStatus;
    match &telegram.secure {
        Some(info) => match info.status {
            SecureStatus::Verified => None,
            SecureStatus::NoKey => Some(
                "secured telegram (KNX Data Secure) but the keyring has no group key for this GA; \
                 export a current keyring from ETS"
                    .to_string(),
            ),
            SecureStatus::MacFailed => Some(
                "secured telegram whose MAC did not verify under the keyring's group key (a \
                 stale keyring or a forged frame)"
                    .to_string(),
            ),
        },
        None if telegram.apci == ApciKind::Other(APCI_SECURE_DATA) => Some(format!(
            "secured telegram (KNX Data Secure), not decrypted: {}",
            bussard_service::guidance::group_key_hint()
        )),
        None => None,
    }
}

/// What the operator decided about one group address.
enum Decision {
    /// The group (and possibly a link) was written into the model.
    Accepted {
        /// Whether a link in the device file was added too.
        made_link: bool,
    },
    /// Left alone.
    Skipped,
    /// End the session.
    Quit,
}

/// Shows one observation, asks about it, and applies the answer to the model.
fn consider(
    model: &mut Model,
    ga: GroupAddress,
    telegram: &DecodedTelegram,
    earlier: &[Vec<u8>],
    options: &LearnArgs,
    interactive: bool,
) -> anyhow::Result<Decision> {
    let sender = telegram.source;
    let payloads: Vec<Vec<u8>> = std::iter::once(telegram.payload.clone())
        .chain(earlier.iter().cloned())
        .collect();
    let observation = learn::observe(model, ga, Some(sender), &payloads);
    print_observation(model, ga, telegram, &observation);

    let mut name = observation.name(model, ga);
    let mut dpt = match observation.candidates.first() {
        Some(c) => c.dpt,
        None => {
            eprintln!(
                "  no DPT candidate for a {}-byte payload; skipping.",
                telegram.payload.len()
            );
            return Ok(Decision::Skipped);
        }
    };

    if !options.yes && interactive {
        loop {
            eprint!("  accept as {name:?} / {dpt}? [a]ccept, [e]dit name, [d]pt, [s]kip, [q]uit: ");
            let _ = std::io::stderr().flush();
            match read_line()?.trim().to_lowercase().as_str() {
                "" | "a" | "accept" | "y" | "yes" => break,
                "s" | "skip" => return Ok(Decision::Skipped),
                "q" | "quit" => return Ok(Decision::Quit),
                "e" | "edit" => {
                    eprint!("  name: ");
                    let _ = std::io::stderr().flush();
                    let entered = read_line()?.trim().to_string();
                    if !entered.is_empty() {
                        name = entered;
                    }
                }
                "d" | "dpt" => {
                    eprint!("  dpt (e.g. 1.001): ");
                    let _ = std::io::stderr().flush();
                    let entered = read_line()?;
                    match entered.trim().parse::<Dpt>() {
                        Ok(parsed) => dpt = parsed,
                        Err(err) => eprintln!("  not a DPT: {err}"),
                    }
                }
                other => eprintln!("  did not understand {other:?}"),
            }
        }
    }

    let secured = telegram.secure.as_ref().is_some_and(|s| s.verified());
    let mut decision = learn::Decision {
        name,
        dpt,
        secured,
        link: None,
    };
    learn::accept(model, ga, &decision);
    if secured {
        println!("{ga} {} ({dpt}, secured)", decision.name);
    } else {
        println!("{ga} {} ({dpt})", decision.name);
    }

    let chosen = match observation.object {
        Some(_) => None,
        None => choose_link(model, sender, ga, options, interactive)?,
    };
    let Some(index) = chosen else {
        return Ok(Decision::Accepted { made_link: false });
    };
    decision.link = Some((sender, index));
    learn::accept(model, ga, &decision);
    println!("  linked {sender} com object {index} → {ga}");
    Ok(Decision::Accepted { made_link: true })
}

/// The sending com object to link a learned GA to, when it can be pinned
/// down: the one candidate the model leaves, or the one the operator names.
fn choose_link(
    model: &Model,
    sender: IndividualAddress,
    ga: GroupAddress,
    options: &LearnArgs,
    interactive: bool,
) -> anyhow::Result<Option<u16>> {
    let Some(candidates) = learn::link_candidates(model, sender) else {
        eprintln!("  sender {sender} is not in the model, so no link was written.");
        return Ok(None);
    };
    Ok(match candidates.as_slice() {
        [only] => Some(*only),
        [] => None,
        many if options.yes || !interactive => {
            eprintln!(
                "  {} transmit-capable com objects on {sender} could send {ga}; run without --yes \
                 to pick one.",
                many.len()
            );
            None
        }
        many => {
            eprint!("  which com object on {sender} sends {ga}? {many:?} (blank to skip): ");
            let _ = std::io::stderr().flush();
            let entered = read_line()?;
            match entered.trim() {
                "" => None,
                text => match text.parse::<u16>() {
                    Ok(index) => Some(index),
                    Err(_) => {
                        eprintln!("  not a com-object number; no link written.");
                        None
                    }
                },
            }
        }
    })
}

/// Prints the evidence for one observation on stderr, so stdout stays a clean
/// record of what was learned.
fn print_observation(
    model: &Model,
    ga: GroupAddress,
    telegram: &DecodedTelegram,
    observation: &learn::Observation,
) {
    let (object, candidates) = (observation.object.as_ref(), &observation.candidates);
    let device = model.devices.get(&telegram.source).map(|d| &d.device);
    let where_ = device
        .and_then(|d| d.location.as_ref())
        .and_then(|l| l.room.clone().or_else(|| l.floor.clone()))
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    eprintln!(
        "  {ga}  sender {} {}{where_}",
        telegram.source,
        device
            .map(|d| d.name.as_str())
            .unwrap_or("(not in the model)"),
    );
    if let Some(object) = object {
        eprintln!(
            "  com object {} {}{}{}",
            object.index,
            object.name.as_deref().unwrap_or("(unnamed)"),
            object
                .channel_name
                .as_ref()
                .map(|c| format!(", channel {c}"))
                .unwrap_or_default(),
            object
                .declared_dpt
                .map(|d| format!(", declares {d}"))
                .unwrap_or_default(),
        );
    }
    if let Some(info) = telegram.secure.as_ref().filter(|s| s.verified()) {
        eprintln!(
            "  secured (KNX Data Secure), verified and decrypted, sequence {}",
            info.sequence
        );
        if let Some(warning) = &info.warning {
            eprintln!("  warning: {warning}");
        }
    }
    eprintln!(
        "  payload {} ({} byte(s))",
        telegram
            .payload
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        telegram.payload.len()
    );
    for (rank, candidate) in candidates.iter().take(4).enumerate() {
        eprintln!(
            "    {}. {} [{}] {}",
            rank + 1,
            candidate.dpt,
            candidate.confidence,
            candidate.reason
        );
    }
    if let Some(name) = &observation.proposed_name {
        eprintln!("  proposed name: {name}");
    }
}

/// Reads one line from stdin.
fn read_line() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading from stdin")?;
    Ok(line)
}

/// An empty model, used when learning into a directory that does not exist yet.
fn empty_model() -> Model {
    bussard_service::history::empty_model()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_model::schema::Group;
    use std::error::Error;

    type R = Result<(), Box<dyn Error>>;

    #[test]
    fn test_resolve_targets_from_explicit_gas() -> R {
        let model = empty_model();
        let options = LearnArgs {
            gas: vec!["1/0/1".to_string(), "1/0/2".to_string()],
            ..Default::default()
        };
        let targets = resolve_targets(&model, &options)?;
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], Target::Ga("1/0/1".parse()?));
        Ok(())
    }

    #[test]
    fn test_resolve_targets_rejects_a_bad_ga() {
        let model = empty_model();
        let options = LearnArgs {
            gas: vec!["nope".to_string()],
            ..Default::default()
        };
        assert!(resolve_targets(&model, &options).is_err());
    }

    #[test]
    fn test_resolve_targets_untyped_picks_gas_without_a_dpt() -> R {
        let mut model = empty_model();
        model.groups.groups.insert(
            "1/0/1".parse()?,
            Group {
                name: "Typed".to_string(),
                dpt: Some("1.001".parse()?),
                ..Default::default()
            },
        );
        model.groups.groups.insert(
            "1/0/2".parse()?,
            Group {
                name: "Untyped".to_string(),
                ..Default::default()
            },
        );
        let options = LearnArgs {
            untyped: true,
            ..Default::default()
        };
        let targets = resolve_targets(&model, &options)?;
        assert_eq!(targets, vec![Target::Ga("1/0/2".parse()?)]);
        Ok(())
    }

    #[test]
    fn test_resolve_targets_defaults_to_open_ended() -> R {
        let model = empty_model();
        let targets = resolve_targets(&model, &LearnArgs::default())?;
        assert_eq!(targets, vec![Target::Any]);
        Ok(())
    }
}
