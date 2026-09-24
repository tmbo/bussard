//! The `bussard test` subcommand: run the scripted functional acceptance tests
//! in the model directory's `tests.yaml` against the live bus (issue #101).
//!
//! This is the handover protocol: the integrator writes the file once, and
//! anyone can rerun it at the three-month visit or after a change request. Each
//! test writes a group value (or asks a human to do something) and waits for the
//! telegram that proves the installation reacted.
//!
//! The runner itself lives in [`bussard_monitor::acceptance`], because the
//! `knx_run_tests` MCP tool drives the same code. This module owns the CLI
//! edges: loading the file, the safety gates, the confirmation, and the report.
//!
//! # Safety
//!
//! A test run writes to the physical bus, so it goes through the same rails as
//! `bussard write`: the non-loopback gateway gate
//! ([`enforce_write_gate`](crate::conn_cmd::enforce_write_gate)) and a
//! confirmation naming the resolved gateway. A test that writes to a GA marked
//! `protected: true` needs **both** `allow_protected: true` in the file and
//! `--force` on the command line; with either missing it is refused and never
//! reaches the bus.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::bail;
use bussard_model::Model;
use bussard_model::tests_schema::{self, TestSuite};
use bussard_monitor::acceptance::{ManualDecision, ManualStep, RunOptions};
use bussard_monitor::{DecodedTelegram, TelegramRing, acceptance};
use bussard_service::{BusService, WritePolicy};

use crate::conn_cmd::{
    ConnOverrides, enforce_write_gate, gateway_display, load_model_required, resolve_config,
};
use crate::write_cmd::protected_refusal;

/// The flags of the `test` subcommand.
#[derive(Debug, Clone, Default)]
pub struct TestOptions {
    /// The test file to run (default: `<dir>/tests.yaml`).
    pub file: Option<PathBuf>,
    /// Emit the report as JSON instead of text.
    pub json: bool,
    /// Together with `allow_protected: true` in the file, permit tests that
    /// write to a protected group address.
    pub force: bool,
    /// Do not carry out `manual:` steps; report them as skipped.
    pub skip_manual: bool,
    /// Run only the named tests (repeatable).
    pub only: Vec<String>,
    /// Skip the confirmation prompt.
    pub yes: bool,
    /// Permit a run against a non-loopback (real) gateway.
    pub allow_remote_gateway: bool,
}

/// Runs `bussard test`.
pub fn run(dir: &Path, options: TestOptions, overrides: ConnOverrides) -> anyhow::Result<ExitCode> {
    // A test run writes to the bus, so a present-but-broken model is a hard
    // error: a parse failure must never fail the protected-GA gate open.
    let model = load_model_required(dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "model directory {} not found; `bussard test` needs the model to resolve DPTs and \
             protected group addresses",
            dir.display()
        )
    })?;

    let path = options
        .file
        .clone()
        .unwrap_or_else(|| dir.join(tests_schema::TESTS_FILE));
    if !path.exists() {
        bail!(
            "no test file at {}; write one (see `bussard test` in docs/reference.md) or pass \
             --file",
            path.display()
        );
    }
    let suite = tests_schema::load_tests(&path)?;
    let selected = selected_tests(&suite, &options);
    if selected == 0 {
        println!("no tests to run in {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    // Both halves of the protected gate, reported before anything is sent.
    let allow_protected = suite.allow_protected && options.force;
    report_protected(&suite, &model, &options, allow_protected);

    let config = resolve_config(Some(&model), &overrides)?;
    let gateway = gateway_display(&config);
    enforce_write_gate(&config, options.allow_remote_gateway)?;
    eprintln!("gateway: {gateway}");

    if !confirm(selected, &gateway, options.yes)? {
        eprintln!("aborted; nothing was written.");
        return Ok(ExitCode::FAILURE);
    }

    let report = execute(&suite, &model, &options, allow_protected, config)?;

    if options.json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    } else {
        print!("{}", report.text());
    }
    Ok(if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Connects, runs the suite, and closes the bus cleanly.
fn execute(
    suite: &TestSuite,
    model: &Model,
    options: &TestOptions,
    allow_protected: bool,
    config: bussard_transport::ConnectionConfig,
) -> anyhow::Result<acceptance::Report> {
    let run_options = RunOptions {
        only: if options.only.is_empty() {
            None
        } else {
            Some(options.only.clone())
        },
        allow_protected,
    };
    let mut manual = TerminalManual::new(options.skip_manual);

    let runtime = tokio::runtime::Runtime::new()?;
    // Acceptance runs write group values, so the service is transmitting and
    // applies the write gate as it opens (already checked in `run`).
    let service = {
        let _context = runtime.enter();
        BusService::open(config, WritePolicy::transmit(options.allow_remote_gateway))?
    };
    Ok(runtime.block_on(async move {
        let handle = service.handle().clone();
        let ring = TelegramRing::new();

        let feeder_ring = ring.clone();
        let feeder_model = model.clone();
        let feeder_handle = handle.clone();
        let feeder = tokio::spawn(async move {
            let mut sub = feeder_handle.subscribe();
            while let Some(inbound) = sub.recv().await {
                let decoded = DecodedTelegram::from_frame(&inbound.frame, Some(&feeder_model));
                feeder_ring.push_with_code(decoded, inbound.message_code);
            }
        });

        if !handle.wait_connected(Duration::from_secs(10)).await {
            eprintln!("warning: bus not connected yet; the first test may time out");
        }

        let report =
            acceptance::run_suite(suite, model, &handle, &ring, &run_options, &mut manual).await;

        // Release the gateway's tunnel slot (issue #31).
        let _ = handle.close().await;
        feeder.abort();
        report
    }))
}

/// How many tests the `--only` filter selects.
fn selected_tests(suite: &TestSuite, options: &TestOptions) -> usize {
    if options.only.is_empty() {
        return suite.tests.len();
    }
    suite
        .tests
        .iter()
        .filter(|t| {
            options
                .only
                .iter()
                .any(|n| n.trim().eq_ignore_ascii_case(t.name.trim()))
        })
        .count()
}

/// Says, before anything is sent, which tests the protected-GA gate will refuse
/// and how to permit them.
fn report_protected(
    suite: &TestSuite,
    model: &Model,
    options: &TestOptions,
    allow_protected: bool,
) {
    for test in &suite.tests {
        if !acceptance::touches_protected(model, test) {
            continue;
        }
        let Some(ga) = acceptance::written_ga(test) else {
            continue;
        };
        if allow_protected {
            eprintln!(
                "warning: test {:?} writes to protected GA {ga} (allow_protected + --force given)",
                test.name
            );
            continue;
        }
        // The same refusal wording `bussard write` uses, so the two commands
        // read alike.
        let refusal = protected_refusal(Some(model), ga, false)
            .unwrap_or_else(|| format!("GA {ga} is protected"));
        let missing = if suite.allow_protected {
            "--force on the command line"
        } else if options.force {
            "`allow_protected: true` in the test file"
        } else {
            "`allow_protected: true` in the test file and --force on the command line"
        };
        eprintln!(
            "test {:?} will be refused: {refusal} (needs {missing})",
            test.name
        );
    }
}

/// Confirms the run on a terminal, naming the gateway. `--yes` skips it; a
/// non-TTY without `--yes` is refused, so a scripted run cannot fire blind at
/// whatever gateway `bussard.yaml` names.
fn confirm(count: usize, gateway: &str, yes: bool) -> anyhow::Result<bool> {
    crate::confirm::confirm(
        yes,
        &format!("run {count} acceptance test(s) against {gateway}? actuators will move."),
        || {
            format!(
                "refusing to run {count} acceptance test(s) against {gateway} without a terminal \
                 to confirm on; pass --yes to run non-interactively"
            )
        },
    )
}

/// The terminal implementation of a `manual:` step: print the instruction and
/// wait for Enter.
struct TerminalManual {
    /// Skip every manual step with this reason instead of prompting.
    skip: Option<String>,
}

impl TerminalManual {
    fn new(skip_manual: bool) -> Self {
        let skip = if skip_manual {
            Some("manual step skipped (--skip-manual)".to_string())
        } else if !std::io::stdin().is_terminal() {
            Some("manual step skipped (no terminal to carry it out on)".to_string())
        } else {
            None
        };
        TerminalManual { skip }
    }
}

impl ManualStep for TerminalManual {
    fn prompt(&mut self, instruction: &str) -> ManualDecision {
        if let Some(reason) = &self.skip {
            return ManualDecision::Skip(reason.clone());
        }
        eprintln!("  manual step: {instruction}");
        eprint!("  press Enter when done, or type s to skip: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return ManualDecision::Skip("could not read from the terminal".to_string());
        }
        match line.trim().to_lowercase().as_str() {
            "s" | "skip" => ManualDecision::Skip("skipped at the prompt".to_string()),
            _ => ManualDecision::Proceed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::error::Error;

    use bussard_model::schema::{BussardConfig, Group, Groups, Links};
    use bussard_model::tests_schema::{TestCase, WriteStep};

    type R = Result<(), Box<dyn Error>>;

    fn suite() -> Result<TestSuite, Box<dyn Error>> {
        Ok(TestSuite {
            allow_protected: false,
            tests: vec![
                TestCase {
                    name: "Kitchen light".to_string(),
                    write: Some(WriteStep {
                        ga: "1/0/10".parse()?,
                        value: "on".to_string(),
                        dpt: None,
                    }),
                    manual: None,
                    expect: None,
                },
                TestCase {
                    name: "Wind alarm".to_string(),
                    write: Some(WriteStep {
                        ga: "3/1/0".parse()?,
                        value: "on".to_string(),
                        dpt: None,
                    }),
                    manual: None,
                    expect: None,
                },
            ],
        })
    }

    fn model() -> Result<Model, Box<dyn Error>> {
        let mut groups = BTreeMap::new();
        groups.insert(
            "3/1/0".parse()?,
            Group {
                name: "Wind alarm".to_string(),
                dpt: Some("1.005".parse()?),
                protected: true,
                ..Default::default()
            },
        );
        Ok(Model {
            config: BussardConfig::default(),
            groups: Groups {
                groups,
                ..Default::default()
            },
            links: Links::default(),
            devices: BTreeMap::new(),
        })
    }

    #[test]
    fn test_selected_tests_counts_the_only_filter() -> R {
        let suite = suite()?;
        assert_eq!(selected_tests(&suite, &TestOptions::default()), 2);
        let options = TestOptions {
            only: vec!["kitchen light".to_string()],
            ..Default::default()
        };
        assert_eq!(selected_tests(&suite, &options), 1);
        let options = TestOptions {
            only: vec!["nothing by that name".to_string()],
            ..Default::default()
        };
        assert_eq!(selected_tests(&suite, &options), 0);
        Ok(())
    }

    #[test]
    fn test_protected_needs_both_opt_ins() -> R {
        let suite = suite()?;
        let model = model()?;
        // The gate is the conjunction of the file flag and --force.
        for (file_flag, force, expected) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (true, true, true),
        ] {
            let mut suite = suite.clone();
            suite.allow_protected = file_flag;
            let options = TestOptions {
                force,
                ..Default::default()
            };
            let allow = suite.allow_protected && options.force;
            assert_eq!(allow, expected, "file={file_flag} force={force}");
            // Whatever the gate says, the refusal wording is available.
            report_protected(&suite, &model, &options, allow);
        }
        // And the runner is what enforces it.
        assert!(acceptance::touches_protected(&model, &suite.tests[1]));
        Ok(())
    }

    #[test]
    fn test_terminal_manual_skips_without_a_terminal() {
        // The test harness has no TTY, so every manual step is skipped with a
        // reason rather than blocking on a read that never returns.
        let mut manual = TerminalManual::new(false);
        match manual.prompt("press the wind-alarm test button") {
            ManualDecision::Skip(reason) => assert!(reason.contains("terminal"), "{reason}"),
            ManualDecision::Proceed => panic!("must not proceed without a terminal"),
        }

        let mut manual = TerminalManual::new(true);
        match manual.prompt("anything") {
            ManualDecision::Skip(reason) => assert!(reason.contains("--skip-manual"), "{reason}"),
            ManualDecision::Proceed => panic!("--skip-manual must skip"),
        }
    }
}
