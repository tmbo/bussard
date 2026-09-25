//! The `--timing` start-up breakdown (issue #214): how long the phases before
//! the first bus frame took, so a start-up regression is visible in every
//! timed run. Phases are recorded process-wide as they happen and printed by
//! `main` next to the total.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// When the process started timing (set first thing in `main`).
static STARTED: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// The recorded phases, in order: name, duration, optional detail.
static PHASES: Mutex<Vec<(&'static str, Duration, String)>> = Mutex::new(Vec::new());

/// Marks the process start. Later calls keep the first instant.
pub fn start() -> Instant {
    *STARTED.get_or_init(Instant::now)
}

/// The time since [`start`] (zero if it was never called).
pub fn since_start() -> Duration {
    STARTED.get().map(Instant::elapsed).unwrap_or_default()
}

/// Records one phase.
pub fn record(phase: &'static str, took: Duration, detail: impl Into<String>) {
    if let Ok(mut phases) = PHASES.lock() {
        phases.push((phase, took, detail.into()));
    }
}

/// Runs `f`, recording its duration as `phase`.
pub fn time<T>(phase: &'static str, f: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let out = f();
    record(phase, started.elapsed(), "");
    out
}

/// The breakdown lines `--timing` prints: every recorded phase, then the
/// model-parse and keyring-decrypt counts of the process.
pub fn report() -> Vec<String> {
    let mut lines: Vec<String> = PHASES
        .lock()
        .map(|phases| {
            phases
                .iter()
                .map(|(phase, took, detail)| {
                    if detail.is_empty() {
                        format!("  {phase:<16} {took:>9.2?}")
                    } else {
                        format!("  {phase:<16} {took:>9.2?}  ({detail})")
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let decrypts = bussard_service::secure::keyring_decrypt_count();
    if decrypts > 0 {
        // Part of `tunnel creds` / `tool keys` when those ran it.
        lines.push(format!(
            "  {:<16} {:>9.2?}  (PBKDF2 decrypt)",
            "keyring",
            bussard_service::secure::keyring_decrypt_time()
        ));
    }
    lines.push(format!(
        "  model parses     {}   keyring decrypts {decrypts}",
        bussard_model::Model::parse_count(),
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_lists_recorded_phases() {
        record("unit phase", Duration::from_millis(5), "detail");
        let lines = report();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("unit phase") && l.contains("(detail)"))
        );
        assert!(lines.iter().any(|l| l.contains("model parses")));
    }
}
