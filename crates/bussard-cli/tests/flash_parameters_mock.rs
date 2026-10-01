//! End-to-end tests of `bussard flash --parameters-only` and the parameter
//! read-back of `bussard plan` / `bussard reconstruct` (issue #119), against an
//! in-process mock KNX gateway on loopback.
//!
//! The mock device is a System B device (mask 07B0) that already runs a small
//! synthetic application: a six-octet code segment and a two-octet parameter
//! segment (an 8-bit threshold, and a 1-bit switch that shows com-object 2).
//! It implements, from the KNX spec semantics, the interface-object walk, the
//! load-state machines, `PID_TABLE_REFERENCE` / `PID_PROGRAM_VERSION`, the two
//! link tables (`PID_TABLE`), and `A_Memory_Read` / `A_Memory_Write`. Every
//! load event and memory write is recorded, which is how the tests prove a
//! parameter-only download unloads nothing, allocates nothing, touches no table
//! and writes only the changed octet.
//!
//! The synthetic `.knxprod` is zipped with the `zip` CLI at test time; the
//! tests skip green when `zip` is unavailable, like `flash_dry_run.rs`. The
//! `bussard` binary always runs with an explicit loopback `--gateway`.

include!("support/param_mock.rs");

#[test]
fn test_flash_parameters_only_writes_only_the_changed_octet() -> TestResult {
    let Some(bench) = Bench::start(
        "params-only",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Threshold: 7 to 12"), "{stdout}");
    assert!(stdout.contains("1 of 2 octet(s) change"), "{stdout}");
    assert!(stdout.contains("parameters verified"), "{stdout}");

    let dev = bench.device();
    // One memory write: the threshold octet. Code and tables untouched.
    assert_eq!(dev.memory_writes, vec![(PARAM_BASE, 1)], "{stderr}");
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    assert_eq!(dev.memory.get(&(PARAM_BASE + 1)).copied(), Some(0));
    // StartLoading + LoadCompleted on the app object only: no Unload, no
    // segment allocation, no table object.
    assert_eq!(
        dev.load_events,
        vec![
            (APP_OBJECT, LE_START_LOADING),
            (APP_OBJECT, LE_LOAD_COMPLETED)
        ],
        "{stderr}"
    );
    assert!(!dev.load_events.iter().any(|(_, e)| *e == LE_ADDITIONAL));
    assert!(dev.property_writes.is_empty(), "{:?}", dev.property_writes);
    assert_eq!(dev.restarts, 1, "the device restarts");
    assert_eq!(dev.load_states.get(&APP_OBJECT).copied(), Some(LS_LOADED));

    // A backup of the parameter memory was written before the download.
    let dir = bench.tmp.join("knx/captures/backups/parameters");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let backup: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&files[0])?)?;
    assert_eq!(backup["regions"][0]["bytes"], "0700");
    assert_eq!(backup["regions"][0]["base"], PARAM_BASE);
    Ok(())
}

/// Issue #215: `--parameters-only` reads the parameters on the pre-flight
/// connection and reads them back on the write session's post-restart
/// connection, instead of a read-only session before the prompt and another
/// after the flash. The written octet and the verdict are unchanged.
#[test]
fn test_flash_parameters_only_reads_on_the_preflight_and_write_sessions() -> TestResult {
    let Some(bench) = Bench::start(
        "params-sessions",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("parameters verified"), "{stdout}");
    let connects = bench._gw.with_device("1.1.4".parse()?, |d| d.connects)?;
    let dev = bench.device();
    let memory_reads = dev
        .wire_apcis
        .iter()
        .filter(|a| **a & 0x3C0 == 0x200 || **a == 0x1FD)
        .count();
    println!(
        "parameters-only: {connects} T_Connect, {} requests, {memory_reads} memory reads",
        dev.wire_apcis.len()
    );
    assert_eq!(dev.memory_writes, vec![(PARAM_BASE, 1)], "{stderr}");
    // The pre-flight, the write session, and the write session's
    // reconnect after the restart (whose first probe finds the device up).
    assert_eq!(connects, 4, "{stderr}");
    Ok(())
}

/// What one `flash --yes` run did to the device.
#[derive(Debug)]
struct FlashRun {
    /// Whether the command succeeded. The mock's segment layout does not
    /// survive a full re-flash's spot check, so a full flash fails the same way
    /// on both paths; what matters here is that both paths agree.
    success: bool,
    /// The last line of stderr, for a failed run.
    stderr_tail: String,
    t_connects: usize,
    requests: usize,
    authorizes: usize,
    memory_writes: Vec<(u32, usize)>,
    load_events: Vec<(u8, u8)>,
    property_writes: Vec<(u8, u8)>,
    memory: Vec<(u32, u8)>,
}

/// Runs `flash 1.1.4 --yes <extra>` against a fresh bench and records what the
/// device saw; `handover` false sets `BUSSARD_FLASH_NO_HANDOVER=1`.
fn flash_yes_run(
    tag: &str,
    extra: &[&str],
    handover: bool,
) -> Result<Option<FlashRun>, Box<dyn Error>> {
    let Some(bench) = Bench::start(
        tag,
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(None);
    };
    let mut args = vec!["flash", "1.1.4", "--product", bench.product()?, "--yes"];
    args.extend_from_slice(extra);
    // The synthetic application is a KNX Virtual one (M-00FA), whose flashes
    // cycle the connection every 10 exchanges (issue #116); 0 holds one
    // connection, as for every other device.
    let mut env = vec![("BUSSARD_FLASH_RECONNECT_EXCHANGES", "0")];
    if !handover {
        env.push(("BUSSARD_FLASH_NO_HANDOVER", "1"));
    }
    let out = bench.bussard_env(&args, &env)?;
    let t_connects = bench._gw.with_device("1.1.4".parse()?, |d| d.connects)?;
    let dev = bench.device();
    let mut memory: Vec<(u32, u8)> = dev.memory.iter().map(|(a, b)| (*a, *b)).collect();
    memory.sort_unstable();
    let (_, stderr) = text(&out);
    Ok(Some(FlashRun {
        success: out.status.success(),
        stderr_tail: stderr
            .lines()
            .rev()
            .find(|l| l.contains("ERROR"))
            .unwrap_or_default()
            .to_string(),
        t_connects,
        requests: dev.wire_apcis.len(),
        authorizes: dev
            .served_apcis
            .iter()
            .filter(|a| **a == apci::A_AUTHORIZE_REQUEST)
            .count(),
        memory_writes: dev.memory_writes,
        load_events: dev.load_events,
        property_writes: dev.property_writes,
        memory,
    }))
}

/// Issue #213: under `--yes` the write phase takes over the pre-flight's
/// connection instead of disconnecting and connecting again: one `T_Connect`
/// and one `A_Authorize_Request` fewer, and the device receives the same
/// writes (memory, load events, property writes) and ends with the same
/// memory. Checked for a full flash and for `--parameters-only`.
#[test]
fn test_flash_yes_takes_over_the_preflight_connection() -> TestResult {
    for (tag, extra) in [("full", &[][..]), ("params", &["--parameters-only"][..])] {
        let Some(before) = flash_yes_run(&format!("handover-{tag}-off"), extra, false)? else {
            return Ok(());
        };
        let Some(after) = flash_yes_run(&format!("handover-{tag}-on"), extra, true)? else {
            return Ok(());
        };
        println!(
            "flash --yes {tag}: T_Connect {} -> {}, requests {} -> {}, A_Authorize {} -> {}",
            before.t_connects,
            after.t_connects,
            before.requests,
            after.requests,
            before.authorizes,
            after.authorizes
        );
        assert_eq!(after.success, before.success, "{tag}: {before:?} {after:?}");
        assert_eq!(after.stderr_tail, before.stderr_tail, "{tag}");
        if tag == "params" {
            assert!(after.success, "{after:?}");
        }
        assert_eq!(after.t_connects + 1, before.t_connects, "{tag}");
        assert_eq!(after.authorizes + 1, before.authorizes, "{tag}");
        assert_eq!(after.requests + 1, before.requests, "{tag}");
        assert_eq!(after.memory_writes, before.memory_writes, "{tag}");
        assert_eq!(after.load_events, before.load_events, "{tag}");
        assert_eq!(after.property_writes, before.property_writes, "{tag}");
        assert_eq!(after.memory, before.memory, "{tag}");
    }
    Ok(())
}

/// Issue #147: a piped run (stdout and stderr not a TTY) keeps today's plain,
/// line-oriented progress output byte for byte, with no cursor-control codes
/// beyond the `\r` the byte counter has always used.
#[test]
fn test_flash_parameters_only_piped_output_is_unchanged() -> TestResult {
    let Some(bench) = Bench::start(
        "params-piped",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    // No escape sequence (cursor movement, colour, line erase) anywhere.
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
    assert!(!stderr.contains('\x1b'), "{stderr:?}");

    // stdout, with the temp-dir backup path normalised, is today's report.
    let backup_marker = "parameter backup written to ";
    let normalised: String = stdout
        .lines()
        .map(|line| match line.find(backup_marker) {
            Some(at) => format!("{}<backup>\n", &line[..at + backup_marker.len()]),
            None => format!("{line}\n"),
        })
        .collect();
    assert_eq!(
        normalised,
        "Parameter-only download for 1.1.4\n\
         \x20 application : M-00FA_A-0002 bussard parameter test app\n\
         \x20 parameters  : 1 change(s):\n\
         \x20     Threshold: 7 to 12\n\
         \x20 memory      :\n\
         \x20     M-00FA_A-0002_RS-2 at 0x004006: 1 of 2 octet(s) change\n\
         \x20 procedure   : open for loading (obj 4); write the differing parameter octets \
         (segment of 2 bytes) at 0x4006; complete load (obj 4); restart device (no unload, no \
         table write)\n\
         parameter backup written to <backup>\n\
         \n\
         parameters verified: 1 changed octet(s) read back from 1.1.4; the application is Loaded\n"
    );

    // stderr after the history line is the exact step / byte-counter trace.
    let (history, progress) = stderr.split_once('\n').ok_or("stderr has no lines")?;
    assert!(
        history.starts_with("recorded the current model"),
        "{stderr:?}"
    );
    assert_eq!(
        progress,
        "  [1/4] open for loading (obj 4)\n\
         \x20 [2/4] write the differing parameter octets (segment of 2 bytes) at 0x4006\n\
         \r      1/1 bytes\n\
         \x20 [3/4] complete load (obj 4)\n\
         \x20 [4/4] restart device\n"
    );
    Ok(())
}

#[test]
fn test_flash_parameters_only_with_nothing_to_change_touches_nothing() -> TestResult {
    let Some(bench) = Bench::start(
        "params-noop",
        MockDevice::running([12, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("nothing to do"), "{stdout}");
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    Ok(())
}

#[test]
fn test_flash_parameters_only_refuses_another_application() -> TestResult {
    let mut device = MockDevice::running([7, 0]);
    device.program_version = [0x00, 0x83, 0x00, 0x42, 0x10];
    let Some(bench) = Bench::start("params-other-app", device, "\"thr@P-0_R-1\" = \"12\"\n")?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("runs application M-0083 A-0042 v16"),
        "{stderr}"
    );
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    Ok(())
}

#[test]
fn test_flash_parameters_only_refuses_an_unloaded_device() -> TestResult {
    let mut device = MockDevice::running([7, 0]);
    device.load_states.insert(APP_OBJECT, LS_UNLOADED);
    let Some(bench) = Bench::start("params-unloaded", device, "\"thr@P-0_R-1\" = \"12\"\n")? else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("not Loaded"), "{stderr}");
    assert!(bench.device().load_events.is_empty());
    Ok(())
}

#[test]
fn test_flash_parameters_only_refuses_a_group_object_change() -> TestResult {
    let Some(bench) = Bench::start(
        "params-visibility",
        MockDevice::running([7, 0]),
        "\"obj2@P-1_R-2\" = \"1\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--parameters-only",
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("group-object table (shows object(s) 2)"),
        "{stderr}"
    );
    assert!(stderr.contains("full `bussard flash 1.1.4`"), "{stderr}");
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    Ok(())
}

#[test]
fn test_plan_and_reconstruct_read_back_the_parameters() -> TestResult {
    let Some(bench) = Bench::start(
        "params-readback",
        MockDevice::running([9, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["reconstruct", "1.1.4", "--product", bench.product()?])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("parameters (application M-00FA_A-0002)"),
        "{stdout}"
    );
    assert!(stdout.contains("Threshold: 9 (default 7)"), "{stdout}");
    assert!(stdout.contains("Threshold: device 9, model 12"), "{stdout}");

    let out = bench.bussard(&["plan", "1.1.4", "--product", bench.product()?, "--json"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    let diffs = json["parameters"]["differences"]
        .as_array()
        .ok_or("no parameter differences in the plan")?;
    assert_eq!(diffs.len(), 1, "{json}");
    assert_eq!(diffs[0]["device"], "9");
    assert_eq!(diffs[0]["model"], "12");
    // Both commands are read-only.
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    assert!(dev.property_writes.is_empty());
    // The plain path carries no KNX Data Secure frame at all (issue #170).
    assert!(!dev.wire_apcis.contains(&bussard_secure::A_SECURE_DATA));
    Ok(())
}

/// Issue #285: `reconstruct` names an internal ETS selector whose octet
/// differs from the model's image, with both values and what it means.
#[test]
fn test_reconstruct_prints_differing_internal_selectors() -> TestResult {
    let Some(bench) = Bench::start(
        "params-internal",
        MockDevice::running([12, 0x03]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["reconstruct", "1.1.4", "--product", bench.product()?])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(
            "  internal ETS values that differ from the model (never shown; a run marked not \
             written is one ETS's download leaves alone, and so does `apply`):\n      1 octet at offset 1 of segment RS-2: _AppInstanz 1 (internal \
             ETS selector, P-3), device Light, model no application\n      an internal ETS \
             selector differs: the device's function assignment differs from the project"
        ),
        "{stdout}"
    );

    let out = bench.bussard(&[
        "reconstruct",
        "1.1.4",
        "--product",
        bench.product()?,
        "--json",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    let internal = &json["parameters"]["internal"][0]["parameters"][0];
    assert_eq!(internal["role"], "internal", "{json}");
    assert_eq!(internal["device"], "Light", "{json}");
    assert_eq!(internal["model"], "no application", "{json}");
    Ok(())
}

/// Issue #215: `reconstruct --no-parameters` reads the links and tables only:
/// no parameter memory is read and the report's tables are the ones the full
/// run reports.
#[test]
fn test_reconstruct_no_parameters_reads_the_tables_only() -> TestResult {
    let mut runs = Vec::new();
    for no_parameters in [false, true] {
        let Some(bench) = Bench::start(
            if no_parameters {
                "recon-noparams"
            } else {
                "recon-params"
            },
            MockDevice::running([9, 0]),
            "\"thr@P-0_R-1\" = \"12\"\n",
        )?
        else {
            return Ok(());
        };
        let mut args = vec!["reconstruct", "1.1.4", "--json"];
        if no_parameters {
            args.push("--no-parameters");
        } else {
            args.extend_from_slice(&["--product", bench.product()?]);
        }
        let started = std::time::Instant::now();
        let out = bench.bussard(&args)?;
        let elapsed = started.elapsed();
        let (stdout, stderr) = text(&out);
        assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
        let mut json: serde_json::Value = serde_json::from_str(&stdout)?;
        let parameters = json
            .as_object_mut()
            .and_then(|o| o.remove("parameters"))
            .unwrap_or(serde_json::Value::Null);
        let dev = bench.device();
        let memory_reads = dev
            .served_apcis
            .iter()
            .filter(|a| **a & 0x3C0 == apci::A_MEMORY_READ || **a == apci::A_MEMORY_EXTENDED_READ)
            .count();
        println!(
            "reconstruct no_parameters={no_parameters}: {} requests, {memory_reads} memory \
             reads, {:.2} s",
            dev.wire_apcis.len(),
            elapsed.as_secs_f64()
        );
        runs.push((json, parameters, memory_reads, dev.wire_apcis.len()));
    }
    let (full, full_params, full_reads, full_requests) = &runs[0];
    let (tables_only, no_params, reads, requests) = &runs[1];
    assert_eq!(tables_only, full, "the tables report is the same");
    assert!(full_params.is_object(), "{full_params}");
    assert!(no_params.is_null(), "{no_params}");
    assert!(*full_reads > 0);
    assert_eq!(*reads, 0);
    assert!(requests < full_requests);
    Ok(())
}

#[test]
fn test_reconstruct_tool_key_reads_back_a_secure_device() -> TestResult {
    let Some(bench) = Bench::start(
        "params-secure",
        MockDevice::running([9, 0]).activated(),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "reconstruct",
        "1.1.4",
        "--product",
        bench.product()?,
        "--tool-key",
        TOOL_KEY_HEX,
        "--json",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    // The secured descriptor read returns the real mask, not FFFF.
    assert_eq!(json["mask"], "07B0", "{json}");
    assert_eq!(json["addresses"], serde_json::json!(["1/2/0"]), "{json}");
    assert_eq!(json["objects"]["1"], serde_json::json!(["1/2/0"]), "{json}");
    assert_eq!(json["parameters"]["application"], "M-00FA_A-0002", "{json}");
    let diffs = json["parameters"]["differences"]
        .as_array()
        .ok_or("no parameter differences in the reconstruct report")?;
    assert_eq!(diffs.len(), 1, "{json}");
    assert_eq!(diffs[0]["device"], "9");
    // Every numbered frame rode A_SecureData; nothing was refused or written.
    let dev = bench.device();
    assert!(dev.secured_requests > 0);
    assert_eq!(dev.plain_refused, 0);
    assert!(
        dev.wire_apcis
            .iter()
            .all(|&a| a == bussard_secure::A_SECURE_DATA),
        "a plain frame reached the secure device: {:03X?}",
        dev.wire_apcis
    );
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    assert!(dev.property_writes.is_empty());
    Ok(())
}

#[test]
fn test_plan_tool_key_reads_back_a_secure_device() -> TestResult {
    let Some(bench) = Bench::start(
        "plan-secure",
        MockDevice::running([9, 0]).activated(),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "plan",
        "1.1.4",
        "--product",
        bench.product()?,
        "--tool-key",
        TOOL_KEY_HEX,
        "--json",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(json["mask"], "07B0", "{json}");
    let diffs = json["parameters"]["differences"]
        .as_array()
        .ok_or("no parameter differences in the plan")?;
    assert_eq!(diffs.len(), 1, "{json}");
    assert_eq!(bench.device().plain_refused, 0);
    Ok(())
}

#[test]
fn test_reconstruct_without_key_on_a_secure_device_fails_with_hint() -> TestResult {
    let Some(bench) = Bench::start(
        "params-secure-nokey",
        MockDevice::running([9, 0]).activated(),
        "",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["reconstruct", "1.1.4", "--product", bench.product()?])?;
    let (stdout, stderr) = text(&out);
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("mask FFFF") && stderr.contains("describe only"),
        "the unsupported-mask refusal: {stderr}"
    );
    assert!(
        stderr.contains("--keyring") && stderr.contains("--tool-key"),
        "the Data Secure hint: {stderr}"
    );
    let dev = bench.device();
    assert_eq!(dev.secured_requests, 0);
    assert!(!dev.wire_apcis.contains(&bussard_secure::A_SECURE_DATA));
    Ok(())
}

/// The synthetic application with a `size`-octet parameter segment (a multiple
/// of 3, so its zero `Data` is `AAAA` repeated). The two parameters stay at
/// offsets 0 and 1.
fn large_app_xml(size: usize) -> String {
    let data = "AAAA".repeat(size / 3);
    APP_XML
        .replace(
            r#"<RelativeSegment Id="M-00FA_A-0002_RS-2" Size="2" LoadStateMachine="4" Offset="0"><Data>AAA=</Data>"#,
            &format!(
                r#"<RelativeSegment Id="M-00FA_A-0002_RS-2" Size="{size}" LoadStateMachine="4" Offset="0"><Data>{data}</Data>"#
            ),
        )
        .replace(
            r#"<LdCtrlRelSegment LsmIdx="4" Size="2" AppliesTo="par" />"#,
            &format!(r#"<LdCtrlRelSegment LsmIdx="4" Size="{size}" AppliesTo="par" />"#),
        )
        .replace(
            r#"<LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="2" AppliesTo="par" />"#,
            &format!(r#"<LdCtrlWriteRelMem ObjIdx="0" Offset="0" Size="{size}" AppliesTo="par" />"#),
        )
}

/// The 1.1.5 shape of issue #194: a 19 155-octet parameter segment.
const LARGE_SEGMENT: usize = 19_155;
/// Above `0xFFFF`, where the 07B0 actuators keep their segments, so the read
/// goes out as `A_MemoryExtended_Read`.
const LARGE_BASE: u32 = 0x1_0000;

/// What a pre-flight run left: the device state, stdout and stderr.
type Preflight = (MockDevice, String, String);

/// Runs the flash pre-flight against the large-segment device without
/// `--yes` (so it stops at the confirmation) and returns the device and the
/// output.
fn large_preflight(tag: &str, extra: &[&str]) -> Result<Option<Preflight>, Box<dyn Error>> {
    let Some(bench) = Bench::start_with_app(
        tag,
        MockDevice::running_large([7, 0], LARGE_SEGMENT, LARGE_BASE, 233).activated(),
        "\"thr@P-0_R-1\" = \"12\"\n",
        &large_app_xml(LARGE_SEGMENT),
    )?
    else {
        return Ok(None);
    };
    let mut args = vec![
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--tool-key",
        TOOL_KEY_HEX,
    ];
    args.extend_from_slice(extra);
    let out = bench.bussard(&args)?;
    let (stdout, stderr) = text(&out);
    // No terminal to confirm on: the pre-flight runs, nothing is written.
    assert!(
        !out.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let dev = bench.device();
    assert!(dev.memory_writes.is_empty() && dev.load_events.is_empty());
    Ok(Some((dev, stdout, stderr)))
}

/// How many memory reads (plain `A_Memory_Read`, whose APCI carries the count,
/// or `A_MemoryExtended_Read`) the device served.
fn memory_reads(dev: &MockDevice) -> usize {
    dev.served_apcis
        .iter()
        .filter(|&&a| a & 0x3C0 == apci::A_MEMORY_READ || a == apci::A_MEMORY_EXTENDED_READ)
        .count()
}

/// How many numbered requests of `service` the device served.
fn served(dev: &MockDevice, service: u16) -> usize {
    dev.served_apcis.iter().filter(|&&a| a == service).count()
}

/// Issue #194: the System B pre-flight reads a 19 KB parameter segment of a
/// Data Secure device on the probe connection, in APDU-sized chunks
/// (`233 - 13` secure overhead `- 5` = 215 octets per
/// `A_MemoryExtended_Read`), not 12-octet chunks on a second connection.
#[test]
fn test_flash_preflight_reads_a_large_parameter_segment_in_apdu_sized_chunks() -> TestResult {
    let Some((dev, stdout, stderr)) = large_preflight("preflight-large", &[])? else {
        return Ok(());
    };
    let reads = memory_reads(&dev);
    eprintln!(
        "pre-flight: {} numbered request(s) on the wire, {reads} memory read(s)",
        dev.wire_apcis.len(),
    );
    assert!(stdout.contains("Threshold: 7 to 12"), "{stdout}\n{stderr}");
    assert_eq!(reads, LARGE_SEGMENT.div_ceil(215), "{stderr}");
    assert_eq!(served(&dev, apci::A_MEMORY_EXTENDED_READ), reads);
    // Everything rode one connection: the probe's Data Secure sync is the only one.
    assert_eq!(dev.plain_refused, 0);
    assert!(
        dev.wire_apcis.len() < 150,
        "{} requests",
        dev.wire_apcis.len()
    );
    Ok(())
}

/// Issue #194 item 2: with `--force` the current-parameter read is skipped;
/// the plan says so instead of showing a diff.
#[test]
fn test_flash_preflight_with_force_skips_the_parameter_read() -> TestResult {
    let Some((dev, stdout, stderr)) = large_preflight("preflight-force", &["--force"])? else {
        return Ok(());
    };
    assert_eq!(memory_reads(&dev), 0, "{stderr}");
    assert!(stdout.contains("current values not read back"), "{stdout}");
    Ok(())
}

/// Issue #194 item 6: `flash -v` ends with the wall-clock time per phase.
#[test]
fn test_flash_verbose_reports_phase_timings() -> TestResult {
    let Some(bench) = Bench::start(
        "flash-timing",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&[
        "flash",
        "1.1.4",
        "--product",
        bench.product()?,
        "--yes",
        "-v",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(
        stderr.contains("timing: pre-flight "),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("restart + verification") || stderr.contains("did not reach"),
        "{stderr}"
    );
    if let Some(line) = stderr.lines().find(|l| l.starts_with("timing:")) {
        eprintln!("{line}");
    }
    Ok(())
}

/// `apply` is the one verb that writes a device: with product data it compares
/// the parameter memory too, and writes only the octet that differs. The
/// tables already match the model, so no table object is touched.
#[test]
fn test_apply_writes_only_the_differing_parameter_octet() -> TestResult {
    let Some(bench) = Bench::start(
        "apply-params",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["apply", "1.1.4", "--product", bench.product()?, "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("1.1.4 Parameter test\n"), "{stdout}");
    assert!(stdout.contains("  ~ thr@P-0_R-1 = 12, was 7\n"), "{stdout}");
    assert!(
        stdout.contains("  unchanged: 1 object, 0 parameters\n"),
        "{stdout}"
    );
    assert!(stdout.contains("  writes: 1 parameter octet\n"), "{stdout}");
    assert!(stdout.contains("parameters verified"), "{stdout}");

    let dev = bench.device();
    assert_eq!(dev.memory_writes, vec![(PARAM_BASE, 1)], "{stderr}");
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    // Only the application object loads: the link tables are left alone.
    assert_eq!(
        dev.load_events,
        vec![
            (APP_OBJECT, LE_START_LOADING),
            (APP_OBJECT, LE_LOAD_COMPLETED)
        ],
        "{stderr}"
    );
    assert!(dev.property_writes.is_empty(), "{:?}", dev.property_writes);
    // Both backups are written before the first write.
    assert!(bench.tmp.join("knx/captures/backups/parameters").is_dir());
    Ok(())
}

/// A device that already holds what the model says gets no question and no
/// write.
#[test]
fn test_apply_with_an_empty_plan_writes_nothing() -> TestResult {
    let Some(bench) = Bench::start(
        "apply-noop",
        MockDevice::running([12, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    // No --yes and no terminal: an empty plan must not even ask.
    let out = bench.bussard(&["apply", "1.1.4", "--product", bench.product()?])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("1.1.4 matches the model; nothing to write"),
        "{stdout}"
    );
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());
    assert!(dev.property_writes.is_empty());
    Ok(())
}

/// `plan --json` carries the plan and the `state_hash` of the state it read;
/// `apply --plan <hash>` refuses once the device has moved on.
#[test]
fn test_apply_refuses_when_the_plan_hash_no_longer_matches() -> TestResult {
    let Some(bench) = Bench::start(
        "apply-hash",
        MockDevice::running([7, 0]),
        "\"thr@P-0_R-1\" = \"12\"\n",
    )?
    else {
        return Ok(());
    };
    let out = bench.bussard(&["plan", "1.1.4", "--product", bench.product()?, "--json"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout)?;
    let hash = json["state_hash"]
        .as_str()
        .ok_or("no state_hash in the plan")?
        .to_string();
    assert_eq!(hash.len(), 64, "{json}");
    assert_eq!(json["changes"][0]["mark"], "~", "{json}");
    assert_eq!(json["changes"][0]["subject"], "parameter", "{json}");
    assert_eq!(
        json["changes"][0]["sentence"], "thr@P-0_R-1 = 12, was 7",
        "{json}"
    );
    assert_eq!(json["writes"]["parameter_octets"], 1, "{json}");
    assert_eq!(
        json["question"],
        format!(
            "apply this change to 1.1.4 through 127.0.0.1:{}?",
            bench.port
        ),
        "{json}"
    );

    // Someone else writes the device in between.
    lock(&bench.shared).memory.insert(PARAM_BASE, 9);
    let out = bench.bussard(&[
        "apply",
        "1.1.4",
        "--product",
        bench.product()?,
        "--plan",
        &hash,
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(!out.status.success(), "must refuse:\n{stdout}\n{stderr}");
    assert!(
        stderr.contains("the device state no longer matches the plan"),
        "{stderr}"
    );
    let dev = bench.device();
    assert!(dev.load_events.is_empty() && dev.memory_writes.is_empty());

    // With the current hash the same apply goes through.
    let out = bench.bussard(&["plan", "1.1.4", "--product", bench.product()?, "--json"])?;
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let fresh = json["state_hash"]
        .as_str()
        .ok_or("no state_hash")?
        .to_string();
    assert_ne!(fresh, hash);
    let out = bench.bussard(&[
        "apply",
        "1.1.4",
        "--product",
        bench.product()?,
        "--plan",
        &fresh,
        "--yes",
    ])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(bench.device().memory.get(&PARAM_BASE).copied(), Some(12));
    Ok(())
}
