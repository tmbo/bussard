//! Live progress display for the long-running bus commands (issue #147).
//!
//! `flash` (also `--parameters-only`), `apply`, `reconstruct --line` and `scan`
//! run for seconds to minutes. On an interactive terminal they render a compact
//! live view on **stderr**: the step `k/n` and its label, a byte bar for the
//! segment being streamed, elapsed time, an ETA from the plan's frame estimate,
//! and the last event the bus layers logged (reconnect, retry, reboot wait).
//!
//! The live view is strictly opt-out-safe. It is only drawn when stdout and
//! stderr are both terminals, `TERM` is not `dumb`, `BUSSARD_WIRE_TRACE` is off,
//! the command was not asked for `--json`, and `--no-progress` was not given.
//! In every other case each display falls back to the exact plain lines the
//! commands printed before this module existed, byte for byte, because the
//! campaign wrapper's `step.log`, the MCP server and LLM-driven runs parse them.
//! Nothing here ever writes to stdout.

use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bussard_download::{FlashPlan, FlashStep, Progress};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle};

/// The environment switch that turns on the raw wire trace; the live view stays
/// off while it is set so the trace lines are not interleaved with redraws.
const WIRE_TRACE_ENV: &str = "BUSSARD_WIRE_TRACE";

/// How often the live view redraws on its own (spinner, elapsed time).
const TICK: Duration = Duration::from_millis(200);

/// The longest last-event text shown, so the line never wraps on a normal
/// terminal (a wrapped line breaks the in-place redraw).
const EVENT_MAX_CHARS: usize = 96;

/// Everything that decides whether the live view may be drawn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gate {
    /// stdout is a terminal (a piped stdout means a script is reading).
    pub stdout_tty: bool,
    /// stderr is a terminal (the live view is drawn there).
    pub stderr_tty: bool,
    /// `TERM=dumb`: the terminal cannot move the cursor.
    pub dumb_term: bool,
    /// `BUSSARD_WIRE_TRACE=1` is set.
    pub wire_trace: bool,
    /// The global `--no-progress` flag.
    pub no_progress: bool,
}

impl Gate {
    /// Reads the gate from the process environment.
    fn from_env(no_progress: bool) -> Self {
        Self {
            stdout_tty: std::io::stdout().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
            dumb_term: std::env::var("TERM").is_ok_and(|t| t == "dumb"),
            wire_trace: std::env::var(WIRE_TRACE_ENV).is_ok_and(|v| v == "1"),
            no_progress,
        }
    }

    /// Whether any command in this process may draw the live view.
    fn allows_any(&self) -> bool {
        self.stdout_tty
            && self.stderr_tty
            && !self.dumb_term
            && !self.wire_trace
            && !self.no_progress
    }

    /// Whether a command with the given `--json` switch draws the live view.
    pub(crate) fn allows_live(&self, json: bool) -> bool {
        self.allows_any() && !json
    }
}

/// The process-wide gate, fixed once by [`init`] before the command runs.
static GATE: OnceLock<Gate> = OnceLock::new();

/// Fixes the gate from the environment and the global `--no-progress` flag.
/// Returns whether the live view is possible at all, so `main` can skip wiring
/// the event capture when it is not. Later calls keep the first gate.
pub(crate) fn init(no_progress: bool) -> bool {
    GATE.get_or_init(|| Gate::from_env(no_progress))
        .allows_any()
}

/// Whether a command with the given `--json` switch draws the live view.
fn live(json: bool) -> bool {
    GATE.get().is_some_and(|gate| gate.allows_live(json))
}

/// The live bar currently on screen, if any. The log writer suspends it around
/// each log line, and the event layer only records while it is set.
static ACTIVE: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// The last event the bus layers logged while a live bar was on screen.
static LAST_EVENT: Mutex<String> = Mutex::new(String::new());

fn active() -> Option<ProgressBar> {
    ACTIVE.lock().ok().and_then(|guard| guard.clone())
}

fn set_active(bar: Option<ProgressBar>) {
    if let Ok(mut guard) = ACTIVE.lock() {
        *guard = bar;
    }
    if let Ok(mut event) = LAST_EVENT.lock() {
        event.clear();
    }
}

fn last_event() -> String {
    LAST_EVENT.lock().map(|e| e.clone()).unwrap_or_default()
}

/// A stderr writer for the tracing `fmt` layer that hides the live bar while a
/// log line is written and redraws it after, so `-v` logs and the bar do not
/// garble each other. Without a live bar it writes straight to stderr.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match active() {
            Some(bar) => bar.suspend(|| std::io::stderr().write(buf)),
            None => std::io::stderr().write(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match active() {
            Some(bar) => bar.suspend(|| std::io::stderr().write_all(buf)),
            None => std::io::stderr().write_all(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

/// A tracing layer that records the message of each bus-layer event (download,
/// management, bus actor) as the live view's "last event" line: the reboot
/// wait, the reconnect, the connect retry. It records nothing unless a live bar
/// is on screen.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EventLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if active().is_none() {
            return;
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        if visitor.0.is_empty() {
            return;
        }
        if let Ok(mut last) = LAST_EVENT.lock() {
            *last = visitor.0;
        }
    }
}

/// Collects an event's `message` field.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// Whether an event is one the live view shows as its last event: DEBUG and
/// above from the bus layers, never the per-frame transport trace.
pub(crate) fn is_bus_event(meta: &tracing::Metadata<'_>) -> bool {
    let target = meta.target();
    *meta.level() <= tracing::Level::DEBUG
        && (target.starts_with("bussard_download")
            || target.starts_with("bussard_mgmt")
            || target.starts_with("bussard_bus"))
}

/// Formats a duration as `m:ss`.
fn clock(d: Duration) -> String {
    let secs = d.as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// Truncates `text` to [`EVENT_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    if text.chars().count() <= EVENT_MAX_CHARS {
        return text.to_string();
    }
    let mut out: String = text.chars().take(EVENT_MAX_CHARS - 1).collect();
    out.push('…');
    out
}

/// The `{event}` template key: the last bus event, dimmed by a leading arrow.
fn event_key(_: &ProgressState, w: &mut dyn std::fmt::Write) {
    let event = last_event();
    if !event.is_empty() {
        let _ = write!(w, "↳ {}", clip(&event));
    }
}

/// The `{clock}` template key: elapsed time since the bar appeared.
fn clock_key(state: &ProgressState, w: &mut dyn std::fmt::Write) {
    let _ = write!(w, "{}", clock(state.elapsed()));
}

/// Creates a live bar with `style`, registered as the active bar.
fn start_bar(style: ProgressStyle) -> ProgressBar {
    let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
    bar.set_style(style);
    bar.enable_steady_tick(TICK);
    set_active(Some(bar.clone()));
    bar
}

/// Removes `bar` from the screen and the active slot; `keep` leaves its last
/// frame drawn (a failure keeps the step it died on visible).
fn stop_bar(bar: &ProgressBar, keep: bool) {
    set_active(None);
    if keep {
        bar.abandon();
    } else {
        bar.finish_and_clear();
    }
}

/// The byte accounting and ETA of a flash: which segment is streaming, how far
/// it is, and the remaining time from the plan's TP1 frame estimate until
/// enough bytes have streamed to measure the real rate.
///
/// A write step may stream its segment as several runs (a sparse image over a
/// filled segment writes only the non-fill runs), each reported as its own
/// `written/total` sequence; the runs are summed into the step's progress.
#[derive(Debug, Clone, Default)]
struct FlashEta {
    /// Bytes the plan streams in total ([`FlashPlan::total_write_bytes`]).
    total_bytes: usize,
    /// The plan's time estimate for those bytes ([`FlashPlan::estimated_duration`]).
    estimate: Duration,
    /// The image length of each plan step (0 for a step that writes nothing).
    step_lens: Vec<usize>,
    /// The current step's image length, when the step index maps onto the plan.
    step_len: Option<usize>,
    /// Bytes of the completed steps.
    done_before: usize,
    /// Bytes of the completed runs of the current step.
    step_runs: usize,
    /// Bytes written of the run streaming now, and that run's length.
    current: usize,
    run_total: usize,
    /// Time spent streaming the completed steps.
    streamed: Duration,
    /// When the current step started streaming.
    stream_start: Option<Instant>,
}

impl FlashEta {
    /// The accounting for executing `plan`.
    fn for_plan(plan: &FlashPlan) -> Self {
        let step_lens = plan
            .steps
            .iter()
            .map(|step| match step {
                FlashStep::WriteRelMem { image, .. } | FlashStep::WriteMem { image, .. } => {
                    image.len
                }
                FlashStep::Sys7AbsSegment {
                    image: Some(image), ..
                } => image.len,
                _ => 0,
            })
            .collect();
        Self {
            total_bytes: plan.total_write_bytes(),
            estimate: plan.estimated_duration(),
            step_lens,
            ..Self::default()
        }
    }

    /// Bytes written of the current step.
    fn step_written(&self) -> usize {
        self.step_runs + self.current
    }

    /// Bytes done overall.
    fn done(&self) -> usize {
        (self.done_before + self.step_written()).min(self.total_bytes)
    }

    /// The bar for the current step: (position, length).
    fn step_bar(&self) -> (u64, u64) {
        let written = self.step_written();
        let len = self.step_len.filter(|&l| l > 0).unwrap_or(self.run_total);
        (written as u64, len.max(written) as u64)
    }

    /// Records a `written/total` event of the current step's run at `now`.
    fn bytes(&mut self, written: usize, total: usize, now: Instant) {
        self.stream_start.get_or_insert(now);
        if self.run_total > 0 && self.current >= self.run_total {
            // The previous run completed: this event starts the next one.
            self.step_runs += self.current;
        }
        self.current = written;
        self.run_total = total;
    }

    /// Closes the current step at `now` as step `index` of `total` starts. A
    /// completed write step counts its whole image, including fill the sparse
    /// runs skipped or a segment skipped as already resident.
    fn next_step(&mut self, index: usize, total: usize, now: Instant) {
        if let Some(start) = self.stream_start.take() {
            self.streamed += now.saturating_duration_since(start);
        }
        let written = self.step_written();
        self.done_before += self.step_len.map_or(written, |len| len.max(written));
        self.step_runs = 0;
        self.current = 0;
        self.run_total = 0;
        self.step_len = if total == self.step_lens.len() {
            index
                .checked_sub(1)
                .and_then(|i| self.step_lens.get(i))
                .copied()
        } else {
            None
        };
    }

    /// Time spent streaming so far, as of `now`.
    fn streaming_time(&self, now: Instant) -> Duration {
        self.streamed
            + self
                .stream_start
                .map_or(Duration::ZERO, |start| now.saturating_duration_since(start))
    }

    /// The remaining streaming time after `streaming` spent streaming, or
    /// `None` when the plan streams nothing. The plan's TP1 estimate until 5 %
    /// of the bytes are through, then the measured streaming rate (the time in
    /// non-write steps, such as a reboot wait, is in neither).
    fn remaining(&self, streaming: Duration) -> Option<Duration> {
        if self.total_bytes == 0 {
            return None;
        }
        let done = self.done();
        let left = (self.total_bytes - done) as f64;
        let per_byte = if done * 20 >= self.total_bytes && done > 0 {
            streaming.as_secs_f64() / done as f64
        } else {
            self.estimate.as_secs_f64() / self.total_bytes as f64
        };
        Some(Duration::from_secs_f64(left * per_byte))
    }
}

/// Mutable state shared between the flash callback and the template keys.
#[derive(Debug, Default)]
pub(crate) struct FlashState {
    step: String,
    eta: FlashEta,
}

/// The progress renderer of `flash` and `flash --parameters-only`.
pub(crate) enum FlashDisplay {
    /// Today's plain lines: `  [k/n] label` and a `\r`-rewritten byte counter.
    Plain,
    /// The live view.
    Live {
        /// The bar on screen.
        bar: ProgressBar,
        /// Shared with the template keys.
        state: Arc<Mutex<FlashState>>,
        /// The two templates: a step without a byte stream, and a stream.
        styles: Box<(ProgressStyle, ProgressStyle)>,
        /// Whether the streaming style is on screen.
        streaming: bool,
    },
}

impl FlashDisplay {
    /// The renderer for executing `plan`; plain unless the live view is allowed
    /// (see the module docs) for a command run with `json`.
    pub(crate) fn new(plan: &FlashPlan, json: bool) -> Self {
        if !live(json) {
            return Self::Plain;
        }
        let state = Arc::new(Mutex::new(FlashState {
            step: String::new(),
            eta: FlashEta::for_plan(plan),
        }));
        let Some(styles) = flash_styles(&state) else {
            return Self::Plain;
        };
        let bar = start_bar(styles.0.clone());
        Self::Live {
            bar,
            state,
            styles: Box::new(styles),
            streaming: false,
        }
    }

    /// Renders one executor event.
    pub(crate) fn on_progress(&mut self, progress: Progress) {
        match self {
            Self::Plain => plain_flash_line(progress),
            Self::Live {
                bar,
                state,
                styles,
                streaming,
            } => match progress {
                Progress::Step {
                    index,
                    total,
                    label,
                } => {
                    if let Ok(mut s) = state.lock() {
                        s.step = format!("{index}/{total}");
                        s.eta.next_step(index, total, Instant::now());
                    }
                    if *streaming {
                        bar.set_style(styles.0.clone());
                        *streaming = false;
                    }
                    bar.set_message(label);
                }
                Progress::Bytes { written, total } => {
                    let (pos, len) = match state.lock() {
                        Ok(mut s) => {
                            s.eta.bytes(written, total, Instant::now());
                            s.eta.step_bar()
                        }
                        Err(_) => (written as u64, total as u64),
                    };
                    // Length and position first, so the streaming style never
                    // draws the previous segment's counts.
                    bar.set_length(len);
                    bar.set_position(pos);
                    if !*streaming {
                        bar.set_style(styles.1.clone());
                        *streaming = true;
                    }
                }
            },
        }
    }

    /// Takes the live view off the screen: cleared on `success`, left drawn on
    /// a failure so the step it stopped at stays visible. Plain is a no-op.
    pub(crate) fn finish(self, success: bool) {
        if let Self::Live { bar, .. } = &self {
            stop_bar(bar, !success);
        }
    }
}

impl Drop for FlashDisplay {
    fn drop(&mut self) {
        if let Self::Live { bar, .. } = self {
            if !bar.is_finished() {
                stop_bar(bar, true);
            }
        }
    }
}

/// The exact pre-#147 flash progress output (issue #147 keeps it byte-identical).
fn plain_flash_line(progress: Progress) {
    match progress {
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
    }
}

/// The flash templates: (step without a stream, streaming segment).
fn flash_styles(state: &Arc<Mutex<FlashState>>) -> Option<(ProgressStyle, ProgressStyle)> {
    let step_state = Arc::clone(state);
    let step_key = move |_: &ProgressState, w: &mut dyn std::fmt::Write| {
        if let Ok(s) = step_state.lock() {
            let _ = write!(w, "{}", s.step);
        }
    };
    let eta_state = Arc::clone(state);
    let eta_key = move |_: &ProgressState, w: &mut dyn std::fmt::Write| {
        let remaining = eta_state
            .lock()
            .ok()
            .and_then(|s| s.eta.remaining(s.eta.streaming_time(Instant::now())));
        if let Some(r) = remaining {
            let _ = write!(w, "  eta ~{}", clock(r));
        }
    };
    let build = |template: &str| -> Option<ProgressStyle> {
        Some(
            ProgressStyle::with_template(template)
                .ok()?
                .progress_chars("=> ")
                .with_key("step", step_key.clone())
                .with_key("eta", eta_key.clone())
                .with_key("clock", clock_key)
                .with_key("event", event_key),
        )
    };
    let step = build("{spinner} [{step}] {wide_msg}\n  elapsed {clock}{eta}\n  {event}")?;
    let stream = build(
        "{spinner} [{step}] {wide_msg}\n  [{bar:32}] {pos}/{len} bytes  elapsed {clock}{eta}\n  {event}",
    )?;
    Some((step, stream))
}

/// The progress renderer of an address sweep (`scan`, `reconstruct --line`).
pub(crate) enum SweepDisplay {
    /// Today's `\r`-rewritten `<verb> <addr>…  <n> found` line.
    Plain {
        /// `scanning` or `reconstructing`.
        verb: &'static str,
    },
    /// The live view: a bar over the address range.
    Live {
        /// The bar on screen.
        bar: ProgressBar,
        /// `scanning` or `reconstructing`.
        verb: &'static str,
    },
}

impl SweepDisplay {
    /// The renderer for a sweep over `count` addresses; `verb` names the probe.
    pub(crate) fn new(verb: &'static str, count: usize, json: bool) -> Self {
        if !live(json) {
            return Self::Plain { verb };
        }
        let Ok(style) = ProgressStyle::with_template(
            "{spinner} {wide_msg}\n  [{bar:32}] {pos}/{len} addresses  elapsed {clock}  eta ~{eta}\n  {event}",
        ) else {
            return Self::Plain { verb };
        };
        let style = style
            .progress_chars("=> ")
            .with_key("clock", clock_key)
            .with_key("event", event_key);
        let bar = start_bar(style);
        bar.set_length(count as u64);
        Self::Live { bar, verb }
    }

    /// Reports that `addr` is being probed, with `found` responders so far.
    pub(crate) fn probing(&self, addr: impl std::fmt::Display, found: usize) {
        match self {
            Self::Plain { verb } => {
                eprint!("\r{verb} {addr}…  {found} found   ");
                let _ = std::io::stderr().flush();
            }
            Self::Live { bar, verb } => {
                bar.set_message(format!("{verb} {addr}…  {found} found"));
            }
        }
    }

    /// Reports that one address was probed.
    pub(crate) fn advance(&self) {
        if let Self::Live { bar, .. } = self {
            bar.inc(1);
        }
    }

    /// Takes the live view off the screen before the summary line is printed.
    pub(crate) fn finish(&self) {
        if let Self::Live { bar, .. } = self {
            stop_bar(bar, false);
        }
    }
}

impl Drop for SweepDisplay {
    fn drop(&mut self) {
        if let Self::Live { bar, .. } = self {
            if !bar.is_finished() {
                stop_bar(bar, false);
            }
        }
    }
}

/// A spinner for a step without finer progress events (`apply`'s table write):
/// the label, elapsed time and the last bus event. Plain mode prints nothing.
pub(crate) struct TaskDisplay(Option<ProgressBar>);

impl TaskDisplay {
    /// A spinner labelled `label`; nothing unless the live view is allowed.
    pub(crate) fn new(label: String, json: bool) -> Self {
        if !live(json) {
            return Self(None);
        }
        let Ok(style) =
            ProgressStyle::with_template("{spinner} {wide_msg}  elapsed {clock}\n  {event}")
        else {
            return Self(None);
        };
        let bar = start_bar(
            style
                .with_key("clock", clock_key)
                .with_key("event", event_key),
        );
        bar.set_message(label);
        Self(Some(bar))
    }

    /// Takes the spinner off the screen: cleared on `success`, left drawn on a
    /// failure.
    pub(crate) fn finish(mut self, success: bool) {
        if let Some(bar) = self.0.take() {
            stop_bar(&bar, !success);
        }
    }
}

impl Drop for TaskDisplay {
    fn drop(&mut self) {
        if let Some(bar) = self.0.take() {
            stop_bar(&bar, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tty() -> Gate {
        Gate {
            stdout_tty: true,
            stderr_tty: true,
            ..Gate::default()
        }
    }

    #[test]
    fn test_allows_live_on_an_interactive_terminal() {
        assert!(tty().allows_live(false));
    }

    #[test]
    fn test_allows_live_disabled_for_non_tty() {
        let piped_stdout = Gate {
            stdout_tty: false,
            ..tty()
        };
        assert!(!piped_stdout.allows_live(false));
        let piped_stderr = Gate {
            stderr_tty: false,
            ..tty()
        };
        assert!(!piped_stderr.allows_live(false));
        assert!(!Gate::default().allows_live(false));
    }

    #[test]
    fn test_allows_live_disabled_for_json() {
        assert!(!tty().allows_live(true));
    }

    #[test]
    fn test_allows_live_disabled_for_wire_trace_no_progress_and_dumb_term() {
        for gate in [
            Gate {
                wire_trace: true,
                ..tty()
            },
            Gate {
                no_progress: true,
                ..tty()
            },
            Gate {
                dumb_term: true,
                ..tty()
            },
        ] {
            assert!(!gate.allows_live(false), "{gate:?}");
        }
    }

    #[test]
    fn test_displays_are_plain_without_a_live_gate() {
        // Under nextest stdout is captured, so the process gate never allows the
        // live view; with `--json` it is refused regardless.
        init(false);
        assert!(!live(false));
        assert!(matches!(
            SweepDisplay::new("scanning", 3, false),
            SweepDisplay::Plain { .. }
        ));
        assert!(matches!(
            SweepDisplay::new("scanning", 3, true),
            SweepDisplay::Plain { .. }
        ));
        assert!(TaskDisplay::new("apply".to_string(), true).0.is_none());
    }

    #[test]
    fn test_flash_eta_uses_the_plan_estimate_then_the_measured_rate() -> Result<(), String> {
        let mut eta = FlashEta {
            total_bytes: 1000,
            estimate: Duration::from_secs(10),
            ..FlashEta::default()
        };
        let before = eta.remaining(Duration::ZERO).ok_or("no eta")?;
        assert_eq!(before, Duration::from_secs(10));
        // Half the bytes in 20 s: the measured rate (twice the estimate) wins.
        eta.done_before = 400;
        eta.current = 100;
        let measured = eta.remaining(Duration::from_secs(20)).ok_or("no eta")?;
        assert_eq!(measured.as_secs(), 20);
        assert!(FlashEta::default().remaining(Duration::ZERO).is_none());
        Ok(())
    }

    #[test]
    fn test_flash_eta_counts_only_streaming_time() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut eta = FlashEta {
            total_bytes: 100,
            estimate: Duration::from_secs(4),
            step_lens: vec![0, 100],
            ..FlashEta::default()
        };
        // A 30 s non-write step (a reboot wait) streams nothing.
        eta.next_step(1, 2, t0);
        eta.next_step(2, 2, at(30));
        eta.bytes(0, 50, at(30));
        eta.bytes(50, 50, at(32));
        assert_eq!(eta.done(), 50);
        assert_eq!(eta.streaming_time(at(32)), Duration::from_secs(2));
    }

    #[test]
    fn test_flash_eta_sums_sparse_runs_into_the_step() {
        let t0 = Instant::now();
        let mut eta = FlashEta {
            total_bytes: 1936,
            step_lens: vec![1936, 0],
            ..FlashEta::default()
        };
        eta.next_step(1, 2, t0);
        // Three runs of 1, 4 and 8 octets over a 1936-octet filled segment.
        for (written, total) in [(1, 1), (4, 4), (8, 8)] {
            eta.bytes(0, total, t0);
            eta.bytes(written, total, t0);
        }
        assert_eq!(eta.step_bar(), (13, 1936));
        // The completed step counts its whole image (the fill is done too).
        eta.next_step(2, 2, t0);
        assert_eq!(eta.done(), 1936);
    }

    #[test]
    fn test_event_layer_records_bus_events_while_a_bar_is_active() {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;
        let subscriber = tracing_subscriber::registry()
            .with(EventLayer.with_filter(tracing_subscriber::filter::filter_fn(is_bus_event)));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "bussard_download::flash", "ignored: no bar");
            assert_eq!(last_event(), "");
            set_active(Some(ProgressBar::hidden()));
            tracing::debug!(target: "bussard_download::flash", "waiting out the reboot");
            assert_eq!(last_event(), "waiting out the reboot");
            tracing::debug!(target: "bussard_transport::tunnel", "frame");
            tracing::trace!(target: "bussard_mgmt::connection", "too chatty");
            assert_eq!(last_event(), "waiting out the reboot");
            tracing::warn!(target: "bussard_bus", "bus connect failed; retrying");
            assert_eq!(last_event(), "bus connect failed; retrying");
            set_active(None);
            assert_eq!(last_event(), "");
        });
    }

    #[test]
    fn test_clip_truncates_long_events() {
        assert_eq!(clip("short"), "short");
        let long = "x".repeat(200);
        assert_eq!(clip(&long).chars().count(), EVENT_MAX_CHARS);
    }

    #[test]
    fn test_clock_formats_minutes_and_seconds() {
        assert_eq!(clock(Duration::from_secs(65)), "1:05");
        assert_eq!(clock(Duration::from_secs(5)), "0:05");
    }
}
