//! End-to-end tests of `bussard plan --line` and `bussard apply --line` against
//! an in-process mock KNX gateway hosting a three-device line (issue #100).
//!
//! The line is deliberately mixed, because the whole point of a batch command is
//! what it does when one device misbehaves:
//!
//! * `1.1.4` — a System B device with writable, loadable tables (happy path);
//! * `1.1.5` — a System 1 (BCU1) device whose mask no table reader speaks, so it
//!   must be reported and **skipped** while the run continues;
//! * `1.1.6` — a System B device that persistently NAKs memory writes into its
//!   association-table segment, so its apply must **fail** while the run continues.
//!
//! The devices are `bussard-testkit` System B devices (load-state machine,
//! `LdCtrlRelSegment` allocation, `PID_TABLE_REFERENCE`, tables stored in memory
//! segments, written from the KNX spec semantics, not from bussard's own
//! encoder), with a small hook for the few places this line answers differently
//! from the testkit defaults (see [`line_hook`]).
//! Every device counts the connected-mode telegrams and write services it sees,
//! which is how the resume test proves a finished device is never touched again.
//!
//! **No test here ever reaches a real gateway**: the testkit mock binds
//! `127.0.0.1:0`.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use bussard_mgmt::apci;
use bussard_mgmt::tables::{OT_ASSOCIATION_TABLE, OT_DEVICE};
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::device::{decode_prop_header, prop_response};
use bussard_testkit::{MemoryWritePolicy, MockDevice, MockGateway, Reaction};

const CHANNEL: u8 = 0x55;

const PID_LOAD_STATE_CONTROL: u8 = 5;
const PID_TABLE_REFERENCE: u8 = 7;

fn ga(s: &str) -> anyhow::Result<GroupAddress> {
    Ok(s.parse()?)
}

fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// Where this line's devices differ from the testkit defaults. They leave
/// `A_Restart` and `A_PropertyDescription_Read` unanswered, serve
/// `PID_LOAD_STATE_CONTROL` and `PID_TABLE_REFERENCE` on every object index
/// (not only on table objects), and refuse a `PID_PROGMODE` write with a
/// zero-count response like any other non-load-control property write.
fn line_hook(dev: &mut MockDevice, req_apci: u16, data: &[u8]) -> Option<Reaction> {
    match req_apci {
        apci::A_RESTART | apci::A_PROPERTY_DESCRIPTION_READ => Some(Reaction::Silent),
        apci::A_PROPERTY_VALUE_READ => {
            let (oi, pid, _count, start) = decode_prop_header(data)?;
            let is_table_object = dev
                .object_types
                .get(usize::from(oi))
                .is_some_and(|&ot| ot != OT_DEVICE);
            if is_table_object {
                return None;
            }
            let value = match pid {
                PID_LOAD_STATE_CONTROL => vec![dev.load_state(oi)],
                PID_TABLE_REFERENCE => {
                    let base = dev.segments.get(&oi).map(|&(b, _)| b).unwrap_or(0);
                    base.to_be_bytes().to_vec()
                }
                _ => return None,
            };
            Some(Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 1, start, &value),
            ))
        }
        apci::A_PROPERTY_VALUE_WRITE => {
            let (oi, pid, _count, start) = decode_prop_header(data)?;
            if oi != 0 || pid != apci::PID_PROGMODE {
                return None;
            }
            dev.writes += 1;
            Some(Reaction::Answer(
                apci::A_PROPERTY_VALUE_RESPONSE,
                prop_response(oi, pid, 0, start, &[]),
            ))
        }
        _ => None,
    }
}

/// A System B device carrying the tables the model will diff against: GAs
/// 1/2/0, 1/2/1 and 4/2/12, and associations (1,20), (2,21), (3,59). Object 59
/// → 4/2/12 is the ghost the model drops; object 22 → 1/2/2 is what it adds.
fn system_b_device(addr: &str, nak_assoc_writes: bool) -> anyhow::Result<MockDevice> {
    let mut addresses = be16(3);
    for g in ["1/2/0", "1/2/1", "4/2/12"] {
        addresses.extend_from_slice(&ga(g)?.raw().to_be_bytes());
    }
    let mut associations = be16(3);
    for (tsap, asap) in [(1u16, 20u16), (2, 21), (3, 59)] {
        associations.extend_from_slice(&tsap.to_be_bytes());
        associations.extend_from_slice(&asap.to_be_bytes());
    }
    let mut dev = MockDevice::system_b(addr.parse()?)
        .with_mask(0x07B0)
        .with_go_count(60)
        .with_table(1, &addresses)
        .with_table(2, &associations)
        .with_hook(line_hook);
    if nak_assoc_writes {
        dev = dev.with_nak_writes_into(OT_ASSOCIATION_TABLE);
    }
    Ok(dev)
}

/// A System 1 (BCU1) device: it answers the descriptor and nothing else, so the
/// table readers refuse its mask.
fn system_1_device(addr: &str) -> anyhow::Result<MockDevice> {
    Ok(MockDevice::new(addr.parse()?)
        .with_mask(0x0012)
        .with_object_types(&[])
        .with_memory_write_policy(MemoryWritePolicy::WithinSegments)
        .with_hook(line_hook))
}

/// The scripted line: one good System B device, one unsupported mask, one
/// System B device that refuses association-table writes.
fn scripted_line() -> anyhow::Result<Vec<MockDevice>> {
    Ok(vec![
        system_b_device("1.1.4", false)?,
        system_1_device("1.1.5")?,
        system_b_device("1.1.6", true)?,
    ])
}

/// Writes the model: three devices on 1.1 and a link set that adds object 22 and
/// drops the ghost object 59 on both System B devices.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    for (addr, name) in [
        ("1.1.4", "Jalousie Wohnen"),
        ("1.1.5", "Alter Dimmer"),
        ("1.1.6", "Schaltaktor Kueche"),
    ] {
        std::fs::write(
            dir.join("devices").join(format!("{addr}.yaml")),
            format!("address: {addr}\nname: {name}\n"),
        )?;
    }
    let links = "links:\n".to_string()
        + &["1.1.4", "1.1.5", "1.1.6"]
            .iter()
            .map(|a| {
                format!(
                    "  {a}:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n  - object: 22\n    listen:\n    - 1/2/2\n"
                )
            })
            .collect::<String>();
    std::fs::write(dir.join("links.yaml"), links)?;
    Ok(())
}

/// A unique temporary directory for one test.
fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bussard-line-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// Starts the mock line. It keeps serving after a `DisconnectRequest`, so a
/// second `bussard` run (the resume test) still finds the same devices with the
/// same state.
fn spawn_line(rt: &tokio::runtime::Runtime) -> anyhow::Result<MockGateway> {
    let line = scripted_line()?;
    Ok(rt.block_on(
        MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .devices(line)
            .start(),
    )?)
}

/// Runs the built `bussard` binary against the mock gateway.
fn run_bussard(port: u16, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let gw = format!("127.0.0.1:{port}");
    let mut all: Vec<&str> = args.to_vec();
    all.push("--gateway");
    all.push(&gw);
    Ok(Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(&all)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?)
}

/// The per-device `(telegrams, writes)` counters.
fn counters(gw: &MockGateway, addr: &str) -> anyhow::Result<(usize, usize)> {
    let want: IndividualAddress = addr.parse()?;
    Ok(gw.with_device(want, |dev| (dev.telegrams, dev.writes))?)
}

/// Finds one device row in a `--json` summary.
fn row<'a>(json: &'a serde_json::Value, address: &str) -> anyhow::Result<&'a serde_json::Value> {
    json["devices"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no devices array in {json}"))?
        .iter()
        .find(|d| d["address"] == address)
        .ok_or_else(|| anyhow::anyhow!("no row for {address} in {json}"))
}

#[test]
fn test_plan_line_reports_every_device_and_skips_an_unsupported_mask() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = spawn_line(&rt)?;
    let port = gw.port();

    let tmp = tmp_dir("plan");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;

    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?;
    let output = run_bussard(
        port,
        &["plan", "--line", "1.1", "--json", "--dir", model_arg],
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        success,
        "plan --line is read-only and must exit 0; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["line"], "1.1");
    assert_eq!(json["mode"], "plan");
    assert_eq!(json["total"], 3);

    // The good device has the one addition and the one removal.
    let good = row(&json, "1.1.4")?;
    assert_eq!(good["status"], "changes");
    assert_eq!(good["changes"], 2);
    assert_eq!(good["mask"], "07B0");

    // The unsupported mask is reported, skipped, and named.
    let old = row(&json, "1.1.5")?;
    assert_eq!(old["status"], "skipped");
    let detail = old["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("0012") && detail.contains("System 1"),
        "the skip must name the mask and family: {detail}"
    );

    // The run continued past it: the third device was planned too.
    assert_eq!(row(&json, "1.1.6")?["status"], "changes");
    assert_eq!(json["failed"], 0);
    Ok(())
}

#[test]
fn test_apply_line_continues_past_a_failure_and_resumes_without_rewriting() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = spawn_line(&rt)?;
    let port = gw.port();

    let tmp = tmp_dir("apply");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();
    let state_file = model_dir.join("captures").join("apply-line-1.1.json");

    // --- Run 1: 1.1.4 applies, 1.1.5 is skipped, 1.1.6 fails. ---
    let first = run_bussard(
        port,
        &[
            "apply", "--line", "1.1", "--yes", "--json", "--dir", &model_arg,
        ],
    )?;
    let first_out = String::from_utf8_lossy(&first.stdout).to_string();
    let first_err = String::from_utf8_lossy(&first.stderr).to_string();
    assert!(
        !first.status.success(),
        "a run with a failed device must exit non-zero; stdout:\n{first_out}\nstderr:\n{first_err}"
    );
    let json: serde_json::Value = serde_json::from_str(&first_out)?;
    assert_eq!(row(&json, "1.1.4")?["status"], "applied");
    assert_eq!(row(&json, "1.1.4")?["changes"], 2);
    assert_eq!(row(&json, "1.1.5")?["status"], "skipped");
    assert_eq!(row(&json, "1.1.6")?["status"], "failed");
    assert_eq!(json["failed"], 1);
    assert!(
        state_file.exists(),
        "an unfinished run must leave its state file at {}",
        state_file.display()
    );

    // The good device really was written.
    let (_, writes_before) = counters(&gw, "1.1.4")?;
    assert!(writes_before > 0, "1.1.4 must have been written");

    // --- Between the runs: the bad device is fixed and the counters reset. ---
    for addr in ["1.1.4", "1.1.5", "1.1.6"] {
        gw.with_device(addr.parse()?, |dev| {
            dev.nak_writes_into = None;
            dev.telegrams = 0;
            dev.writes = 0;
        })?;
    }

    // --- Run 2: --resume must not touch the finished devices at all. ---
    let second = run_bussard(
        port,
        &[
            "apply", "--line", "1.1", "--yes", "--resume", "--json", "--dir", &model_arg,
        ],
    )?;
    let second_out = String::from_utf8_lossy(&second.stdout).to_string();
    let second_err = String::from_utf8_lossy(&second.stderr).to_string();
    let second_ok = second.status.success();
    let counters_4 = counters(&gw, "1.1.4")?;
    let counters_6 = counters(&gw, "1.1.6")?;
    let state_left = state_file.exists();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        second_ok,
        "the resumed run must exit 0; stdout:\n{second_out}\nstderr:\n{second_err}"
    );
    let json: serde_json::Value = serde_json::from_str(&second_out)?;
    let done = row(&json, "1.1.4")?;
    assert_eq!(done["status"], "skipped");
    assert!(
        done["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("earlier run"),
        "the resume skip must say why: {done}"
    );
    assert_eq!(
        counters_4,
        (0, 0),
        "a finished device must see no telegrams and no writes on a --resume run"
    );

    // Only the previously-failed device was retried, and it succeeded.
    assert_eq!(row(&json, "1.1.6")?["status"], "applied");
    assert!(
        counters_6.1 > 0,
        "the retried device must be written on the resumed run"
    );
    assert!(
        !state_left,
        "a run that finishes cleanly must retire its state file"
    );
    Ok(())
}

#[test]
fn test_apply_line_refuses_without_a_tty_or_yes() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let gw = spawn_line(&rt)?;
    let port = gw.port();

    let tmp = tmp_dir("confirm");
    let model_dir = tmp.join("knx");
    write_model(&model_dir)?;
    let model_arg = model_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 temp path"))?
        .to_string();

    let output = run_bussard(port, &["apply", "--line", "1.1", "--dir", &model_arg])?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(!success, "a non-TTY run without --yes must fail");
    assert!(
        stderr.contains("without a terminal") && stderr.contains("127.0.0.1"),
        "the refusal must name the gateway: {stderr}"
    );
    Ok(())
}
