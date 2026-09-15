//! The `bussard write <ga> <value>` subcommand: encode a human value and send a
//! `GroupValueWrite` on the bus.
//!
//! This mirrors [`read_cmd`](crate::read_cmd)'s use of the outbound channel on
//! [`run_stream_with_outbound`](bussard_monitor::run_stream_with_outbound): the
//! command opens the bus, injects a single `GroupValueWrite`, waits for the
//! local `L_Data.con` echo (or a short settle), then confirms what it wrote.
//!
//! Safety: a GA marked `protected: true` in `groups.yaml` is refused unless
//! `--force` is given (see the design document §8).

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bussard_model::{Dpt, GroupAddress, Model, encode, parse_value};
use bussard_monitor::stream::{Flow, TelegramSink};
use bussard_monitor::{
    CancelToken, DecodedTelegram, DestinationRef, Filter, TelegramRing,
    run_stream_with_outbound_cancellable,
};
use bussard_transport::cemi::CemiFrame;
use bussard_transport::{TimestampedFrame, TransportError};
use tokio::sync::mpsc;

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

/// How long to wait for the local `L_Data.con` echo before settling.
const CONFIRM_TIMEOUT: Duration = Duration::from_millis(1500);

/// The source IA for outgoing writes (matches the read/MCP default).
const SOURCE_IA: &str = "0.0.255";

/// Sends a `GroupValueWrite` to the bus.
///
/// Resolves the DPT (`--dpt` wins, else the GA's DPT from the model), refuses
/// protected GAs without `--force`, encodes the human value, transmits, and
/// confirms. Returns a failure exit code on parse/encode/connect errors.
pub fn run(
    ga_str: &str,
    value: &str,
    dpt_override: Option<&str>,
    force: bool,
    dir: &Path,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let ga: GroupAddress = ga_str
        .parse()
        .map_err(|_| anyhow!("invalid group address {ga_str:?}"))?;

    let model = load_model_optional(dir);

    // Resolve the DPT: --dpt wins, else the GA's dpt from groups.yaml.
    let dpt = resolve_dpt(dpt_override, model.as_ref(), ga)?;

    // Refuse a protected GA unless --force.
    if let Some(reason) = protected_refusal(model.as_ref(), ga, force) {
        bail!("{reason}");
    }

    // Parse the human value and encode it against the DPT.
    let typed =
        parse_value(&dpt, value).with_context(|| format!("parsing value {value:?} for GA {ga}"))?;
    let payload = encode(&dpt, &typed)
        .with_context(|| format!("encoding {typed} as DPT {dpt} for GA {ga}"))?;

    // A friendly name for the confirmation line, if the model knows it.
    let ga_name = model
        .as_ref()
        .and_then(|m| m.groups.groups.get(&ga))
        .map(|g| g.name.clone());

    let config = resolve_config(model.as_ref(), &overrides)?;
    let source_ia = SOURCE_IA.parse().expect("valid source IA");

    let runtime = tokio::runtime::Runtime::new()?;
    let confirmed = runtime.block_on(async move {
        let ring = TelegramRing::new();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let mut sink = RingSink { ring: ring.clone() };

        // A cancel token stops the stream with a clean bus close (releasing the
        // gateway tunnel slot) instead of aborting the task — see issue #31.
        let (cancel, cancel_watch) = CancelToken::new();
        let stream = tokio::spawn(async move {
            let _ = run_stream_with_outbound_cancellable(
                &config,
                model.as_ref(),
                &mut sink,
                Some(out_rx),
                cancel_watch,
            )
            .await;
        });

        // Subscribe before sending so the con echo cannot be missed.
        let filter = Filter::parse(&ga.to_string()).expect("GA is a valid filter term");
        let waiter = {
            let ring = ring.clone();
            tokio::spawn(async move { ring.wait_for(&filter, CONFIRM_TIMEOUT).await })
        };

        // Send the write. A send failure surfaces as a settle-timeout below; we
        // never leave the user without a clear result.
        let sent = out_tx
            .send(CemiFrame::group_write(ga, source_ia, &payload))
            .is_ok();

        let echo = waiter.await.ok().flatten();
        // Cancel and wait for the stream to close the connection cleanly.
        cancel.cancel();
        let _ = stream.await;
        // Confirmed if we saw an echo for our GA; otherwise "sent" (fire-and-
        // forget) as long as the frame was queued onto a live-or-reconnecting
        // connection.
        (sent, echo)
    });

    let (sent, echo) = confirmed;
    if !sent {
        eprintln!("error: could not queue the write for {ga} (bus channel closed)");
        return Ok(ExitCode::FAILURE);
    }

    // Confirmation line, e.g.
    // `3/0/4 Jalousie Wohnen Süd — Auf/Ab ← Down (1.008)`.
    let value_display = typed.to_string();
    let confirmed_echo = echo
        .as_ref()
        .is_some_and(|t| matches!(t.destination, DestinationRef::Group(g) if g == ga));

    match &ga_name {
        Some(name) => println!("{ga} {name} ← {value_display} ({dpt})"),
        None => println!("{ga} ← {value_display} ({dpt})"),
    }
    if !confirmed_echo {
        // Not an error: KNX group writes are fire-and-forget. Note the missing
        // confirmation on stderr so scripts still see success on stdout.
        eprintln!("note: sent (no bus confirmation observed within {CONFIRM_TIMEOUT:?})");
    }

    Ok(ExitCode::SUCCESS)
}

/// Returns a refusal message if `ga` is protected in the model and `force` is
/// not set; otherwise `None` (the write may proceed).
fn protected_refusal(model: Option<&Model>, ga: GroupAddress, force: bool) -> Option<String> {
    if force {
        return None;
    }
    let group = model?.groups.groups.get(&ga)?;
    if group.protected {
        Some(format!(
            "refusing to write to protected GA {ga} ({:?}); pass --force to override",
            group.name
        ))
    } else {
        None
    }
}

/// Resolves the DPT to encode against: `--dpt` wins, else the GA's DPT from the
/// model. Errors (suggesting `--dpt`) when neither is available.
fn resolve_dpt(
    dpt_override: Option<&str>,
    model: Option<&Model>,
    ga: GroupAddress,
) -> anyhow::Result<Dpt> {
    if let Some(s) = dpt_override {
        return s.parse().map_err(|e| anyhow!("invalid --dpt {s:?}: {e}"));
    }
    let group = model.and_then(|m| m.groups.groups.get(&ga));
    match group.and_then(|g| g.dpt) {
        Some(dpt) => Ok(dpt),
        None => {
            if model.is_none() {
                bail!(
                    "no model loaded and no --dpt given for {ga}; pass --dpt <dpt> (e.g. --dpt 1.001)"
                );
            }
            bail!("GA {ga} has no DPT in groups.yaml; pass --dpt <dpt> (e.g. --dpt 1.001)")
        }
    }
}

/// A sink that pushes each decoded telegram into a shared ring.
struct RingSink {
    ring: TelegramRing,
}

impl TelegramSink for RingSink {
    fn on_telegram(&mut self, telegram: &DecodedTelegram, frame: &TimestampedFrame) -> Flow {
        // Carry the cEMI message code; the write confirmation deliberately
        // accepts the L_Data.con echo (that IS the confirmation), so its waiter
        // keeps the plain GA filter.
        self.ring
            .push_with_code(telegram.clone(), frame.frame.message_code);
        Flow::Continue
    }

    fn on_disconnect(&mut self, error: &TransportError, backoff: Duration) -> Flow {
        tracing::warn!(
            "bus connection issue: {error}; retrying in {}s",
            backoff.as_secs()
        );
        Flow::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};

    fn ga(s: &str) -> GroupAddress {
        s.parse().unwrap()
    }

    fn model_with(protected: bool, dpt: Option<&str>) -> Model {
        let mut groups = BTreeMap::new();
        groups.insert(
            ga("3/0/4"),
            Group {
                name: "Jalousie Wohnen Süd — Auf/Ab".to_string(),
                dpt: dpt.map(|d| d.parse().unwrap()),
                description: None,
                protected,
            },
        );
        Model {
            config: BussardConfig::default(),
            groups: Groups {
                project: None,
                imported_from: None,
                ranges: BTreeMap::new(),
                groups,
            },
            links: Links {
                links: BTreeMap::new(),
            },
            devices: BTreeMap::new(),
        }
    }

    #[test]
    fn protected_ga_refused_without_force() {
        let m = model_with(true, Some("1.008"));
        let msg = protected_refusal(Some(&m), ga("3/0/4"), false).expect("must refuse");
        assert!(msg.contains("protected"));
        assert!(msg.contains("--force"));
        assert!(msg.contains("Jalousie"));
    }

    #[test]
    fn protected_ga_allowed_with_force() {
        let m = model_with(true, Some("1.008"));
        assert!(protected_refusal(Some(&m), ga("3/0/4"), true).is_none());
    }

    #[test]
    fn unprotected_ga_not_refused() {
        let m = model_with(false, Some("1.008"));
        assert!(protected_refusal(Some(&m), ga("3/0/4"), false).is_none());
    }

    #[test]
    fn dpt_override_wins() {
        let m = model_with(false, Some("1.008"));
        let d = resolve_dpt(Some("5.001"), Some(&m), ga("3/0/4")).unwrap();
        assert_eq!(d.to_string(), "5.001");
    }

    #[test]
    fn dpt_from_model_when_no_override() {
        let m = model_with(false, Some("1.008"));
        let d = resolve_dpt(None, Some(&m), ga("3/0/4")).unwrap();
        assert_eq!(d.to_string(), "1.008");
    }

    #[test]
    fn dpt_missing_errors_with_suggestion() {
        let m = model_with(false, None);
        let err = resolve_dpt(None, Some(&m), ga("3/0/4")).unwrap_err();
        assert!(err.to_string().contains("--dpt"), "got {err}");
        // No model at all also errors and suggests --dpt.
        let err = resolve_dpt(None, None, ga("3/0/4")).unwrap_err();
        assert!(err.to_string().contains("--dpt"), "got {err}");
    }
}
