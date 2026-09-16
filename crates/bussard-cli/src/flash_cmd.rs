//! The `bussard flash` subcommand — first application download into a
//! factory-fresh device (phase 3).
//!
//! The flow mirrors `bussard apply`'s ladder, adapted for an application
//! download:
//! 1. Read the vendor `.knxprod`, select the application program (by `--application`
//!    id, or the sole candidate).
//! 2. Read the device descriptor (mask). Gate on System B (07B0); refuse others.
//! 3. Build a pre-flight [`FlashPlan`] — this also refuses a mask mismatch or any
//!    unsupported op — and show it. A refused plan exits non-zero before any write.
//! 4. State that **no backup is possible** for a first flash (the device is
//!    assumed factory-fresh; recovery is re-flashing) and confirm on a TTY unless
//!    `--yes`.
//! 5. Execute with a progress line, then verify: the application object must be
//!    `Loaded`, and a sample of each written segment is read back.
//! 6. On any failure, print recovery guidance and exit non-zero.
//!
//! # Safety
//!
//! This is a device-mutating command. Per the phase-3 spec the first real flash
//! must happen against the thelsing virtual device or KNX Virtual, not the live
//! reference bus; the mask gate and the pre-flight validation are the guard-rails
//! that keep it from touching an unsupported or mismatched device.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, bail};
use bussard_bus::{Bus, BusHandle, ops};
use bussard_download::{
    FlashPlan, FlashStep, Progress, flash, plan_flash, select_application, trace,
};
use bussard_mgmt::load::WriteError;
use bussard_mgmt::{DeviceConnection, Layer4Connection, LeaseChannel, MgmtError};
use bussard_model::IndividualAddress;
use bussard_prod::{ApplicationProgram, ProductData, normalize_order_number};

use crate::conn_cmd::{ConnOverrides, load_model_optional, resolve_config};

/// Flashes an application program from vendor product data into a device.
///
/// The argument list mirrors the `flash` subcommand's flags 1:1; bundling them
/// would only obscure that mapping, so the clippy arity lint is allowed here.
#[allow(clippy::too_many_arguments)]
pub fn run(
    address: &str,
    product: &Path,
    application: Option<&str>,
    order_number: Option<&str>,
    dir: &Path,
    yes: bool,
    tolerate_nonconformant_load_states: bool,
    verify: bussard_mgmt::VerifyMode,
    pace_ms: Option<u64>,
    reconnect_every: Option<u32>,
    max_window_retries: Option<u32>,
    bcu_key: Option<&str>,
    overrides: ConnOverrides,
) -> anyhow::Result<ExitCode> {
    let target: IndividualAddress = address
        .parse()
        .with_context(|| format!("parsing device address {address:?}"))?;

    // Parse the optional BCU access key (hex, e.g. `FFFFFFFF` or `0x11223344`).
    // Unset means present the free-access key on every management connect — the
    // capture used free access; keyed devices need the project BCU key here.
    let bcu_key = match bcu_key {
        Some(raw) => Some(parse_bcu_key(raw)?),
        None => None,
    };

    // Load the product data and pick the application program.
    let product_data = bussard_prod::read_knxprod(product)
        .with_context(|| format!("reading product data from {}", product.display()))?;

    // Resolve the application program. Three modes, in precedence order:
    //   --order-number : look the order number up in the hardware catalogue and
    //                    require exactly one matching application (clap already
    //                    rejects combining it with --application);
    //   --application  : an explicit application ref, looked up directly;
    //   neither        : the sole application in a single-app archive.
    let app = if let Some(order) = order_number {
        match resolve_by_order_number(&product_data, order) {
            Ok(app) => app,
            Err(err) => {
                eprintln!("{err}");
                return Ok(ExitCode::FAILURE);
            }
        }
    } else {
        let candidates: Vec<&ApplicationProgram> = product_data.applications.iter().collect();
        match select_application(&candidates, application) {
            Ok(app) => app,
            Err(err) => {
                eprintln!("cannot select an application program: {err}");
                return Ok(ExitCode::FAILURE);
            }
        }
    };

    // Parameter overrides come from the target device's `parameters:` block in
    // the model (`devices/*.yaml`), re-keyed to the app-relative ParameterRef id
    // the flash engine expects (the #46 contract: keys are `<slug>@<ref-id>`; the
    // part after `@` is the ETS-stable identity). The model is also the source of
    // the connection config.
    let model = load_model_optional(dir);
    let config = resolve_config(model.as_ref(), &overrides)?;
    let overrides_map = collect_parameter_overrides(model.as_ref(), target);
    // Module-instance base offsets persisted by the importer (issue #48): the
    // keys are module-instance selectors, byte-identical to what
    // compute_parameter_image expects, so per-channel parameter overrides place
    // at their real per-instance offsets.
    let base_offsets = model
        .as_ref()
        .and_then(|m| m.devices.get(&target))
        .map(|d| d.device.module_bases.clone())
        .unwrap_or_default();

    // Phase A (read-only): read the device descriptor.
    let runtime = tokio::runtime::Runtime::new()?;
    let device_mask = {
        let config = config.clone();
        runtime.block_on(async move {
            let (handle, _task) = Bus::connect(config);
            if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
                eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
            }
            let source = ops::group_source(&handle);
            let lease = handle.lease().await.context("leasing the bus")?;
            let channel = LeaseChannel::new(lease);
            // Track whether the T_Connect established before the first read: a
            // connect-then-disconnect on the descriptor read is the diagnostic
            // pattern (see `descriptor_read_error`).
            let (connected, result) = match DeviceConnection::connect(channel, target, source).await
            {
                Ok(mut dev) => {
                    // Authorize the read-only descriptor probe too (best-effort):
                    // ETS authorizes every management session, so a keyed device
                    // that would otherwise drop the descriptor read is unlocked
                    // first. Tolerate a device that does not implement authorize.
                    let key = bcu_key.unwrap_or(bussard_mgmt::apci::FREE_ACCESS_KEY);
                    let r = match dev.authorize(key).await {
                        Ok(_) => dev.device_descriptor().await,
                        Err(err) => Err(err),
                    };
                    let _ = dev.disconnect().await;
                    (true, r)
                }
                Err(err) => (false, Err(err)),
            };
            let _ = handle.close().await;
            anyhow::Ok((connected, result))
        })?
    };

    let (connected, device_mask) = device_mask;
    let device_mask = match device_mask {
        Ok(mask) => mask,
        Err(err) => {
            return Err(descriptor_read_error(target, connected, err));
        }
    };

    // Pre-flight: build and validate the plan (System B gate, mask match,
    // unsupported-op refusal all happen here).
    let plan = match plan_flash(app, address, device_mask, &overrides_map, &base_offsets) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("cannot flash: {err}");
            return Ok(ExitCode::FAILURE);
        }
    };

    print_plan(target, device_mask, &plan, &overrides_map);

    // No backup is possible for a first flash — state it plainly.
    eprintln!(
        "\nNOTE: a first flash assumes the device is factory-fresh; no backup is \n\
         possible (there is no prior application to save). Recovery from a failed \n\
         flash is re-running `bussard flash`."
    );

    // Confirm unless --yes.
    if !confirm(target, yes, &plan)? {
        eprintln!("aborted — nothing written.");
        return Ok(ExitCode::FAILURE);
    }

    // Phase B (write): execute the flash with a progress line.
    let plan_ref = &plan;
    let options = bussard_download::FlashOptions {
        tolerate_nonconformant_load_states,
        verify,
        pace: pace_ms.map(std::time::Duration::from_millis),
        reconnect_every,
        // 0 = the crate default (DEFAULT_MAX_WINDOW_RETRIES); the flag overrides it.
        max_window_retries: max_window_retries.unwrap_or(0),
        bcu_key,
    };
    if let Some(n) = reconnect_every {
        eprintln!(
            "note: --reconnect-every {n} — the download is chunked across graceful connection \
             windows: after ~{n} numbered exchanges the L4 connection is cycled (T_Disconnect + \
             reconnect), both between steps AND inside a long memory write (resuming at the current \
             offset — memory writes are absolute-addressed and stateless). Load states are \
             persistent object state, so this lands in the same device state as one unbroken run. \
             It also auto-retries an unexpected mid-write connection drop, so the download completes \
             against a peer (e.g. KNX Virtual) that drops the connection at any depth."
        );
    }
    if let Some(ms) = pace_ms {
        eprintln!(
            "note: --pace {ms} — sleeping {ms}ms between memory frames. Real gateways              throttle to TP1 speed on their own; pacing keeps simulators (KNX Virtual)              from wedging under loopback-speed bursts."
        );
    }
    if tolerate_nonconformant_load_states {
        eprintln!(
            "note: --tolerate-nonconformant-load-states is on — a device that reports Loaded \
             (instead of Loading) after StartLoading will be accepted. Intended for KNX Virtual; \
             leave off for real hardware."
        );
    }
    if verify == bussard_mgmt::VerifyMode::Batched {
        eprintln!(
            "note: --verify batched — the whole segment is written before it is read back and \
             verified once, roughly halving the flash's memory round-trips. A corrupt write is \
             caught at the end-of-segment verify (the first mismatching address is reported), not \
             at the offending chunk."
        );
    }
    let outcome = runtime.block_on(async move {
        let (handle, _task) = Bus::connect(config);
        if !handle.wait_connected(std::time::Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; management traffic may use the 0.0.255 fallback source");
        }
        let source = ops::group_source(&handle);
        let result = execute(&handle, target, source, plan_ref, options).await;
        let _ = handle.close().await;
        anyhow::Ok(result)
    })?;

    match outcome {
        Ok(verify) if verify.ok() => {
            println!(
                "\nflash verified: application program {} is {} on {target}",
                plan.identity.id, verify.load_state,
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(verify) => {
            eprintln!("\nERROR: flash did not verify: {verify:?}");
            recovery_notice(target);
            Ok(ExitCode::FAILURE)
        }
        Err(err) => {
            eprintln!("\nERROR: flash failed: {err}");
            // A mid-download connection death with no windowing set: name the flag
            // that makes the download robust against a fragile peer, and the KV
            // context. Do NOT auto-enable — the operator opts in.
            if reconnect_every.is_none() && is_mid_download_disconnect(&err) {
                eprintln!(
                    "\nHINT: the connection dropped mid-download. Some peers — notably KNX Virtual \
                     — drop the L4\n\
                     connection at a varying (and sometimes very shallow) depth (issue #52). Retry\n\
                     with `--reconnect-every <N>` to window the download across graceful connection\n\
                     windows — it cycles between steps AND inside a long memory write, and auto-retries\n\
                     an unexpected drop, resuming from the last-confirmed offset (so it lands in the\n\
                     same state as one unbroken run). KV has been observed to drop as early as 7\n\
                     exchanges, so pick a SMALL window like `--reconnect-every 4`. Probe the peer's\n\
                     per-connection budget first with `bussard reconstruct {target} --l4-soak <N>`."
                );
            }
            recovery_notice(target);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Whether a flash error is a connection death that struck *mid-download* (after
/// at least one exchange), as opposed to the device being absent from the start.
///
/// The L4 layer distinguishes these: a silence after the first acknowledged
/// exchange surfaces as [`MgmtError::MidSessionSilence`]; a bare
/// `Disconnected`/`NoResponse` can also strike mid-procedure once the flash body
/// is under way. All three are cases where windowing would have helped.
fn is_mid_download_disconnect(err: &WriteError) -> bool {
    matches!(
        err,
        WriteError::Mgmt(MgmtError::MidSessionSilence { .. })
            | WriteError::Mgmt(MgmtError::Disconnected { .. })
            | WriteError::Mgmt(MgmtError::NoResponse { .. })
    )
}

/// Collects the target device's parameter overrides from the model, re-keyed
/// from the device-file `<slug>@<ref-id>` form to the bare app-relative
/// `ParameterRef` id the flash engine consumes (the part after `@`).
///
/// The slug before `@` is a human aid and is dropped. A key with no `@` is
/// malformed for this contract and skipped with a warning (rather than fed to the
/// engine as a bogus ref id). Returns an empty map when the model is absent or
/// the device has no `parameters:` block.
fn collect_parameter_overrides(
    model: Option<&bussard_model::Model>,
    target: IndividualAddress,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(model) = model else { return out };
    let Some(loaded) = model.devices.get(&target) else {
        return out;
    };
    for (key, value) in &loaded.device.parameters {
        match key.split_once('@') {
            Some((_slug, ref_id)) if !ref_id.is_empty() => {
                out.insert(ref_id.to_string(), value.clone());
            }
            _ => {
                eprintln!(
                    "warning: ignoring parameter key {key:?} on {target}: it has no \
                     `<slug>@<ref-id>` form, so its ETS-stable identity is undetermined"
                );
            }
        }
    }
    out
}

/// Resolves an application program from a hardware order number, requiring
/// exactly one match.
///
/// Matching is index-style normalized (trim + upper-case, interior separators
/// preserved — the same rule the product pointer index uses), so `akk-0216.03 `
/// resolves to `AKK-0216.03`. Every order number in the archive's hardware
/// catalogue is normalized and compared; the applications the matching order
/// numbers map to are collected and de-duplicated by id.
///
/// - Exactly one distinct application → returned.
/// - Zero → an error naming the order number and (up to a few) known order
///   numbers as candidates.
/// - More than one → an error listing the candidate application ids so the user
///   can fall back to `--application`.
fn resolve_by_order_number<'a>(
    product: &'a ProductData,
    order_number: &str,
) -> anyhow::Result<&'a ApplicationProgram> {
    let want = normalize_order_number(order_number);

    // Every order-number key that normalizes to the wanted value, and the
    // application refs each maps to (joined, de-duplicated by ref).
    let mut app_refs: Vec<&str> = Vec::new();
    for (order, refs) in &product.hardware.order_to_apps {
        if normalize_order_number(order) == want {
            for r in refs {
                if !app_refs.contains(&r.as_str()) {
                    app_refs.push(r.as_str());
                }
            }
        }
    }

    // Resolve refs to the parsed applications present in the archive, keeping
    // them distinct by id (a ref may repeat across hardware rows).
    let mut apps: Vec<&ApplicationProgram> = Vec::new();
    for r in &app_refs {
        if let Some(app) = product.application_by_id(r) {
            if !apps.iter().any(|a| a.id == app.id) {
                apps.push(app);
            }
        }
    }

    match apps.as_slice() {
        [only] => Ok(only),
        [] => {
            let mut known: Vec<&str> = product
                .hardware
                .order_to_apps
                .keys()
                .map(String::as_str)
                .collect();
            known.sort_unstable();
            let candidates = if known.is_empty() {
                "the archive lists no order numbers".to_string()
            } else {
                let shown: Vec<&str> = known.iter().take(10).copied().collect();
                let suffix = if known.len() > shown.len() {
                    format!(", … ({} total)", known.len())
                } else {
                    String::new()
                };
                format!("known order numbers: {}{suffix}", shown.join(", "))
            };
            bail!(
                "no application matches order number {order_number:?} in {}; {candidates}. \
                 Pass --application <ref> to select by application id instead.",
                product_display(product),
            )
        }
        many => {
            let ids: Vec<&str> = many.iter().map(|a| a.id.as_str()).collect();
            bail!(
                "order number {order_number:?} maps to {} applications ({}); \
                 disambiguate with --application <ref>.",
                many.len(),
                ids.join(", "),
            )
        }
    }
}

/// Parses a `--bcu-key` value: a 32-bit access key in hex, with or without a
/// `0x` prefix (e.g. `FFFFFFFF`, `0x11223344`).
///
/// The key is presented with `A_Authorize_Request` on every management connect
/// (issue #52 finding #1). A malformed value is a hard error rather than a
/// silent fall back to free access, so a typo cannot flash a keyed device with
/// the wrong (unprivileged) key and get a confusing access-denied later.
fn parse_bcu_key(raw: &str) -> anyhow::Result<u32> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(hex, 16).with_context(|| {
        format!("parsing --bcu-key {raw:?} as a 32-bit hex access key (e.g. FFFFFFFF)")
    })
}

/// Turns a failed device-descriptor read into a helpful error.
///
/// The KNX Virtual IP-medium devices (order `*.ip`, e.g. a binary output at
/// `1.0.10`) accept the `T_Connect` but `T_Disconnect` on the very first
/// descriptor read, while their TP-medium siblings answer fully. When we see
/// exactly that shape — the connection established, then the first read
/// disconnected — name the pattern so the user gets guidance instead of a bare
/// "disconnected". Any other failure is passed through with context.
fn descriptor_read_error(
    target: IndividualAddress,
    connected: bool,
    err: MgmtError,
) -> anyhow::Error {
    if connected && matches!(err, MgmtError::Disconnected { .. }) {
        return anyhow::anyhow!(
            "{target} accepted the connection but disconnected on the first read: typical for \
             devices whose management is gated on a loaded application or a different medium \
             profile (e.g. KNX Virtual IP-medium `*.ip` devices, which disconnect on descriptor \
             reads while their `*.tp` siblings answer). Flash targets the application download, \
             which this device is not accepting management for over this connection."
        );
    }
    anyhow::Error::new(err).context("reading the device descriptor")
}

/// A short label for the product in an error message: its manufacturer id(s).
fn product_display(product: &ProductData) -> String {
    if product.manufacturers.is_empty() {
        "the product archive".to_string()
    } else {
        format!("the product archive ({})", product.manufacturers.join(", "))
    }
}

/// Opens a fresh L4 connection to the flash target by leasing the bus.
///
/// A windowed download ([`bussard_download::Session`]) calls this once per
/// connection window: each call takes a fresh [`bussard_bus::BusLease`] and builds
/// a [`LeaseChannel`] over it, so every window observes the bus without stealing
/// frames from other subscribers, and starts with fresh L4 sequence counters.
struct LeaseConnector<'a> {
    handle: &'a BusHandle,
    target: IndividualAddress,
    source: IndividualAddress,
}

impl bussard_download::Connector for LeaseConnector<'_> {
    type Channel = LeaseChannel;

    async fn connect(&mut self) -> Result<Layer4Connection<LeaseChannel>, WriteError> {
        let lease = self.handle.lease().await.map_err(|_| {
            // Leasing fails only if the bus actor is gone or the connection went
            // stale; either way the L4 session is unusable.
            WriteError::Mgmt(MgmtError::Transport(
                bussard_transport::TransportError::Closed,
            ))
        })?;
        let channel = LeaseChannel::new(lease);
        Layer4Connection::connect(channel, self.target, self.source)
            .await
            .map_err(WriteError::Mgmt)
    }
}

/// Runs the on-bus flash sequence with a progress line.
async fn execute(
    handle: &BusHandle,
    target: IndividualAddress,
    source: IndividualAddress,
    plan: &FlashPlan,
    options: bussard_download::FlashOptions,
) -> Result<bussard_download::FlashOutcome, WriteError> {
    let connector = LeaseConnector {
        handle,
        target,
        source,
    };
    // Authorize every (re)connect with the project BCU key (or free access when
    // unset) — issue #52 finding #1. The session re-authorizes each fresh window.
    let mut session = bussard_download::Session::open_with_key(connector, options.bcu_key).await?;
    // The session owns the open connection; from here the flash body runs and its
    // result is captured, then the session is disconnected unconditionally below —
    // regardless of whether the flash succeeded or failed mid-procedure. `flash`
    // borrows the session (never consumes it), and there is no `?` between here and
    // the disconnect, so a mid-flash WriteError can never skip the T_Disconnect that
    // releases the L4 session. (finding 3: a stuck session after a failed flash
    // traces to a skipped disconnect; keeping the disconnect on every arm is the
    // guarantee.) With `--reconnect-every`, the session cycles the connection at
    // window boundaries and this final disconnect closes whichever window is open.
    let result = flash(&mut session, plan, options, |p| match p {
        Progress::Step {
            index,
            total,
            label,
        } => {
            eprintln!("  [{index}/{total}] {label}");
        }
        Progress::Bytes { written, total } => {
            eprint!("\r      {written}/{total} bytes");
            let _ = std::io::stderr().flush();
            if written == total {
                eprintln!();
            }
        }
        Progress::Reconnect { window, exchanges } => {
            eprintln!("  — reconnecting (window {window}; {exchanges} exchange(s) so far) —");
        }
    })
    .await;
    let _ = session.into_disconnect().await;
    result
}

/// Prints the pre-flight plan: application identity, mask compatibility, the
/// applied parameter overrides, and the ordered step list with byte counts and
/// time estimate.
fn print_plan(
    target: IndividualAddress,
    device_mask: u16,
    plan: &FlashPlan,
    overrides: &BTreeMap<String, String>,
) {
    println!("Flash plan for {target}");
    println!(
        "  application : {} {}",
        plan.identity.id,
        plan.identity.name.as_deref().unwrap_or(""),
    );
    if let (Some(num), Some(ver)) = (
        plan.identity.application_number,
        plan.identity.application_version,
    ) {
        println!("  app number  : {num} (version {ver})");
    }
    println!(
        "  mask        : app {} vs device {device_mask:04X} — compatible",
        plan.identity.mask_version,
    );
    // The parameter overrides that deviate from the vendor defaults, so the user
    // confirms exactly what this flash changes. Keyed by the app-relative
    // ParameterRef id (the #46 contract identity).
    if overrides.is_empty() {
        println!("  parameters  : none (flashing vendor defaults)");
    } else {
        println!(
            "  parameters  : {} override(s) applied over vendor defaults:",
            overrides.len()
        );
        for (key, value) in overrides {
            println!("      {key} = {value}");
        }
    }
    println!(
        "  writes      : {} byte(s) across {} step(s), ~{} memory frame(s), est. {:.1}s on TP1",
        plan.total_write_bytes(),
        plan.steps.len(),
        plan.estimated_write_frames(),
        plan.estimated_duration().as_secs_f64(),
    );
    println!("  procedure   :");
    for line in trace(plan) {
        println!("    {line}");
    }
}

/// Confirms on a TTY (y/N). Non-interactive without `--yes` is refused.
fn confirm(target: IndividualAddress, yes: bool, plan: &FlashPlan) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!(
            "refusing to flash {target} without a terminal to confirm on; \
             pass --yes to flash non-interactively"
        );
    }
    let writes = plan
        .steps
        .iter()
        .filter(|s| {
            matches!(
                s,
                FlashStep::WriteRelMem { .. } | FlashStep::WriteMem { .. }
            )
        })
        .count();
    eprint!(
        "flash {} ({writes} memory write(s)) to {target}? [y/N] ",
        plan.identity.id
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Prints loud recovery guidance on any flash failure.
fn recovery_notice(target: IndividualAddress) {
    eprintln!(
        "\nThe device may be left with a partially-written or unloaded application.\n\
         Because this was a first flash there is no prior state to restore.\n\
         Recover by re-running `bussard flash {target}` (the download is idempotent —\n\
         it re-unloads and rewrites the application wholesale), or by downloading the\n\
         device with ETS. Do not assume the device is functional until a re-flash\n\
         reports the application is Loaded and verified.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bussard_prod::parse_application_program;

    #[test]
    fn mid_download_disconnect_is_detected_for_windowing_hint() {
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        // A mid-session silence, a mid-procedure disconnect and a mid-procedure
        // no-response all warrant the --reconnect-every hint.
        assert!(is_mid_download_disconnect(&WriteError::Mgmt(
            MgmtError::MidSessionSilence {
                address: target,
                kind: bussard_mgmt::SilenceKind::Disconnected,
                exchanges: 20,
                wraps: 1,
            }
        )));
        assert!(is_mid_download_disconnect(&WriteError::Mgmt(
            MgmtError::Disconnected { address: target }
        )));
        assert!(is_mid_download_disconnect(&WriteError::Mgmt(
            MgmtError::NoResponse { address: target }
        )));
        // A load-state error is NOT a connection death — windowing would not help,
        // so the hint must not fire.
        assert!(!is_mid_download_disconnect(
            &WriteError::UnexpectedLoadState {
                address: target,
                object_index: 3,
                control: bussard_mgmt::LoadControl::StartLoading,
                expected: bussard_mgmt::LoadState::Loading,
                actual: bussard_mgmt::LoadState::Loaded,
                context: bussard_mgmt::LoadStateContext::default(),
            }
        ));
    }

    /// Builds a one-device model whose device at `addr` carries `params`.
    fn model_with_params(addr: &str, params: &[(&str, &str)]) -> bussard_model::Model {
        use bussard_model::schema::Device;
        let address: IndividualAddress = addr.parse().unwrap();
        let device = Device {
            address,
            name: "test".to_string(),
            description: None,
            location: None,
            product: None,
            channels: Default::default(),
            parameters: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            module_bases: Default::default(),
            com_objects: Default::default(),
        };
        let mut devices = std::collections::BTreeMap::new();
        devices.insert(
            address,
            bussard_model::loader::LoadedDevice {
                device,
                file_stem: "test".to_string(),
            },
        );
        bussard_model::Model {
            config: Default::default(),
            groups: Default::default(),
            links: Default::default(),
            devices,
        }
    }

    #[test]
    fn parameter_overrides_are_rekeyed_to_ref_id() {
        // A device file keys parameters `<slug>@<ref-id>`; collection drops the
        // slug and keys by the ETS-stable ref id (the part after @).
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        let model = model_with_params(
            "1.1.4",
            &[
                ("windalarm-1@MD-1_M-3_MI-1_P-3_R-45", "1"),
                ("nachtabsenkung@P-1312_R-2140", "18"),
            ],
        );
        let out = collect_parameter_overrides(Some(&model), target);
        assert_eq!(
            out.get("MD-1_M-3_MI-1_P-3_R-45").map(String::as_str),
            Some("1")
        );
        assert_eq!(out.get("P-1312_R-2140").map(String::as_str), Some("18"));
        // The human slug is gone from the key entirely.
        assert!(!out.keys().any(|k| k.contains('@')));
    }

    #[test]
    fn malformed_parameter_key_without_at_is_skipped() {
        // A key with no `@` has no determinable ref-id identity; it is skipped
        // rather than fed to the engine as a bogus ref id.
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        let model = model_with_params("1.1.4", &[("bogus_no_at_sign", "5")]);
        let out = collect_parameter_overrides(Some(&model), target);
        assert!(out.is_empty());
    }

    #[test]
    fn no_model_or_unknown_device_yields_no_overrides() {
        let target: IndividualAddress = "1.1.4".parse().unwrap();
        assert!(collect_parameter_overrides(None, target).is_empty());
        // A model that has no device at the target address contributes nothing.
        let model = model_with_params("1.1.9", &[("x@P-1_R-1", "1")]);
        assert!(collect_parameter_overrides(Some(&model), target).is_empty());
    }

    /// A minimal parseable single-segment System B application under id `id`.
    fn app(id: &str) -> ApplicationProgram {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
             <ApplicationProgram Id="{id}" ApplicationNumber="1" ApplicationVersion="1"
                MaskVersion="MV-07B0" Name="Fab" LoadProcedureStyle="ProductDefault">
              <Static>
               <Code>
                <RelativeSegment Id="{id}_RS-1" Size="1" LoadStateMachine="4" Offset="0"><Data>AA==</Data></RelativeSegment>
               </Code>
               <LoadProcedures>
                <LoadProcedure><LdCtrlConnect /><LdCtrlDisconnect /></LoadProcedure>
               </LoadProcedures>
              </Static>
             </ApplicationProgram></KNX>"#
        );
        parse_application_program(id, xml.as_bytes()).unwrap()
    }

    /// Builds a [`ProductData`] from `(order_number, [app_ref…])` rows and the
    /// application ids present in the archive.
    fn product(rows: &[(&str, &[&str])], app_ids: &[&str]) -> ProductData {
        let mut data = ProductData {
            manufacturers: vec!["M-0083".to_string()],
            ..ProductData::default()
        };
        for id in app_ids {
            data.applications.push(app(id));
        }
        for (order, refs) in rows {
            data.hardware.order_to_apps.insert(
                order.to_string(),
                refs.iter().map(|r| r.to_string()).collect(),
            );
        }
        data
    }

    #[test]
    fn resolves_exactly_one_match() {
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-000D-23-5BFD"])],
            &["M-0083_A-000D-23-5BFD"],
        );
        let app = resolve_by_order_number(&data, "AKK-0216.03").unwrap();
        assert_eq!(app.id, "M-0083_A-000D-23-5BFD");
    }

    #[test]
    fn resolution_normalizes_case_and_whitespace() {
        // Index-style normalization: trim + upper-case, interior separators kept.
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-000D-23-5BFD"])],
            &["M-0083_A-000D-23-5BFD"],
        );
        let app = resolve_by_order_number(&data, "  akk-0216.03 ").unwrap();
        assert_eq!(app.id, "M-0083_A-000D-23-5BFD");
    }

    #[test]
    fn zero_matches_lists_known_order_numbers() {
        let data = product(
            &[
                ("AKK-0216.03", &["M-0083_A-1"]),
                ("AKK-0416.03", &["M-0083_A-1"]),
            ],
            &["M-0083_A-1"],
        );
        let err = resolve_by_order_number(&data, "NOPE-9").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no application matches order number"), "{msg}");
        assert!(
            msg.contains("AKK-0216.03"),
            "should list known order numbers: {msg}"
        );
        assert!(
            msg.contains("--application"),
            "should point at the fallback: {msg}"
        );
    }

    #[test]
    fn multiple_matches_lists_candidate_ids() {
        // One order number mapping to two distinct applications is ambiguous.
        let data = product(
            &[("AKK-0216.03", &["M-0083_A-1", "M-0083_A-2"])],
            &["M-0083_A-1", "M-0083_A-2"],
        );
        let err = resolve_by_order_number(&data, "AKK-0216.03").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("maps to 2 applications"), "{msg}");
        assert!(
            msg.contains("M-0083_A-1") && msg.contains("M-0083_A-2"),
            "{msg}"
        );
        assert!(msg.contains("--application"), "{msg}");
    }

    #[test]
    fn descriptor_disconnect_after_connect_names_the_pattern() {
        let target: IndividualAddress = "1.0.10".parse().unwrap();
        let err = descriptor_read_error(
            target,
            true, // the T_Connect established before the read
            MgmtError::Disconnected { address: target },
        );
        let msg = err.to_string();
        assert!(
            msg.contains("accepted the connection but disconnected on the first read"),
            "{msg}"
        );
        assert!(msg.contains("*.ip") && msg.contains("*.tp"), "{msg}");
    }

    #[test]
    fn descriptor_disconnect_without_connect_is_passed_through() {
        // A disconnect that happened before the connection established is not the
        // IP-medium pattern; it passes through with the generic context.
        let target: IndividualAddress = "1.0.10".parse().unwrap();
        let err = descriptor_read_error(target, false, MgmtError::Disconnected { address: target });
        let msg = err.to_string();
        assert!(msg.contains("reading the device descriptor"), "{msg}");
        assert!(
            !msg.contains("accepted the connection but disconnected"),
            "{msg}"
        );
    }

    #[test]
    fn descriptor_other_error_is_passed_through() {
        let target: IndividualAddress = "1.0.10".parse().unwrap();
        let err = descriptor_read_error(target, true, MgmtError::NoResponse { address: target });
        let msg = err.to_string();
        assert!(msg.contains("reading the device descriptor"), "{msg}");
    }

    #[test]
    fn duplicate_refs_across_rows_collapse_to_one() {
        // Two order-number rows pointing at the same application resolve cleanly.
        let data = product(
            &[
                ("AKK-0216.03", &["M-0083_A-1"]),
                ("AKK-0216.03 ", &["M-0083_A-1"]),
            ],
            &["M-0083_A-1"],
        );
        let app = resolve_by_order_number(&data, "AKK-0216.03").unwrap();
        assert_eq!(app.id, "M-0083_A-1");
    }
}
