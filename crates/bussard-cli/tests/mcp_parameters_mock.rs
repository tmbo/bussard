//! `knx_plan_device` / `knx_apply_device` with a parameter change (issue
//! #274), driven over real stdio JSON-RPC against the System B parameter-test
//! device of `flash_parameters_mock.rs` on a loopback mock gateway.
//!
//! - The plan lists the differing parameter by key, vendor text, device value
//!   and model value, with one sentence, the octet count and a digest; the
//!   apply writes only that octet and reads it back.
//! - A plan with no parameter change is unchanged (nothing to write).
//! - The digest binds the parameter image: a parameter edited between plan
//!   and apply retires the plan.
//! - The MCP path writes what the CLI writes: the same model change applied
//!   through `bussard apply` and through `knx_apply_device` leaves two
//!   identical devices with identical write sequences, from the same plan.
//!
//! The product archive is pinned in `bussard.lock` (the MCP tier takes no
//! `--product`). The `bussard` binary always runs with an explicit loopback
//! `--gateway`.

// The shared bench carries helpers only the flash suite uses.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin};
use std::sync::mpsc::{Receiver, channel};

use serde_json::{Value, json};

include!("support/param_mock.rs");

/// The lowercase hex SHA-256 of a file.
fn sha256_hex(path: &Path) -> Result<String, Box<dyn Error>> {
    use sha2::Digest as _;
    Ok(sha2::Sha256::digest(std::fs::read(path)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

impl Bench {
    /// The model directory.
    fn model(&self) -> PathBuf {
        self.tmp.join("knx")
    }

    /// Stores the synthetic archive in `products/` and pins it for 1.1.4 in
    /// `bussard.lock`, as `bussard import-product` would.
    fn pin_product(&self) -> TestResult {
        let store = self.model().join("products");
        std::fs::create_dir_all(&store)?;
        let file = store.join("param-test.knxprod");
        std::fs::copy(&self.product, &file)?;
        let sha = sha256_hex(&file)?;
        std::fs::write(
            self.model().join("bussard.lock"),
            format!(
                "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \
                 \"products/param-test.knxprod\"\nfilename = \"param-test.knxprod\"\n\
                 origin = {{ kind = \"file\", path = \"param-test.knxprod\" }}\n\
                 applications = [\"M-00FA_A-0002\"]\n\n[[device]]\naddress = \"1.1.4\"\n\
                 application = \"M-00FA_A-0002\"\nproduct_sha256 = \"{sha}\"\nmask = \"07B0\"\n"
            ),
        )?;
        Ok(())
    }

    /// Replaces the device file's `[parameters]` table.
    fn set_parameters(&self, params: &str) -> TestResult {
        let lock = std::fs::read_to_string(self.model().join("bussard.lock"))?;
        write_model(&self.model(), params)?;
        std::fs::write(self.model().join("bussard.lock"), lock)?;
        Ok(())
    }

    /// Starts `bussard mcp --allow-programming` on the model against the mock.
    fn mcp(&self) -> Result<Server, Box<dyn Error>> {
        Server::start(&self.model(), self.port, false)
    }

    /// [`Bench::mcp`] with the model-edit tools registered.
    fn mcp_with_edits(&self) -> Result<Server, Box<dyn Error>> {
        Server::start(&self.model(), self.port, true)
    }
}

/// A `bussard mcp` child process spoken to over stdio JSON-RPC.
struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl Server {
    fn start(dir: &Path, port: u16, edits: bool) -> Result<Server, Box<dyn Error>> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bussard"));
        command
            .arg("mcp")
            .arg("--dir")
            .arg(dir)
            .arg("--gateway")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--allow-programming");
        if !edits {
            command.arg("--no-model-edits");
        }
        let mut child = command
            .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
            .env_remove("BUSSARD_KEYRING")
            .env("BUSSARD_FLASH_L4_TIMEOUT_MS", "300")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or("no stdin pipe")?;
        let stdout = child.stdout.take().ok_or("no stdout pipe")?;
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Server {
            child,
            stdin,
            lines,
            next_id: 1,
        };
        server.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-parameters-mock", "version": "0"}
            }),
        )?;
        server.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        Ok(server)
    }

    fn send(&mut self, message: &Value) -> TestResult {
        writeln!(self.stdin, "{message}")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Sends a request and returns its `result`, skipping notifications.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, Box<dyn Error>> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let line = self.lines.recv_timeout(Duration::from_secs(90))?;
            let message: Value = serde_json::from_str(&line)?;
            if message["id"] == id {
                if let Some(error) = message.get("error") {
                    return Err(format!("{method} failed: {error}").into());
                }
                return Ok(message["result"].clone());
            }
        }
    }

    /// Calls a tool and returns its structured result.
    fn call(&mut self, tool: &str, args: Value) -> Result<Value, Box<dyn Error>> {
        let result = self.request("tools/call", json!({"name": tool, "arguments": args}))?;
        Ok(result["structuredContent"].clone())
    }

    /// `knx_plan_device` for 1.1.4, retried while the server's tunnel comes up.
    fn plan(&mut self) -> Result<Value, Box<dyn Error>> {
        let mut plan = Value::Null;
        for _ in 0..50 {
            plan = self.call("knx_plan_device", json!({"address": "1.1.4"}))?;
            let waiting = plan["reason"]
                .as_str()
                .is_some_and(|r| r.contains("is not connected"));
            if !waiting {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(plan)
    }

    /// `knx_apply_device` for 1.1.4 with `plan`'s digest.
    fn apply(&mut self, plan: &Value) -> Result<Value, Box<dyn Error>> {
        let digest = plan["plan_digest"].as_str().ok_or("no plan_digest")?;
        self.call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A bench with the product pinned, or `None` when `zip` is unavailable.
fn pinned(tag: &str, params: [u8; 2], model: &str) -> Result<Option<Bench>, Box<dyn Error>> {
    let Some(bench) = Bench::start(tag, MockDevice::running(params), model)? else {
        return Ok(None);
    };
    bench.pin_product()?;
    Ok(Some(bench))
}

#[test]
fn test_mcp_plan_and_apply_write_the_differing_parameter_octet() -> TestResult {
    let Some(bench) = pinned("mcp-params", [7, 0], "\"thr@P-0_R-1\" = \"12\"\n")? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    assert_eq!(
        plan["parameters"]["changed"],
        json!([{"key": "thr@P-0_R-1", "name": "Threshold", "device": "7", "model": "12"}]),
        "plan: {plan}"
    );
    assert_eq!(plan["parameters"]["octets"], 1, "plan: {plan}");
    assert_eq!(plan["writes"]["parameter_octets"], 1, "plan: {plan}");
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.contains("  ~ thr@P-0_R-1 = 12, was 7\n"),
        "{sentences}"
    );
    assert!(
        sentences.contains("  writes: 1 parameter octet\n"),
        "{sentences}"
    );
    assert!(
        plan["identity"]
            .as_str()
            .is_some_and(|l| l.starts_with("identity of 1.1.4: matches bussard.lock")),
        "plan: {plan}"
    );
    assert!(
        bench.device().memory_writes.is_empty(),
        "planning writes nothing"
    );

    let applied = server.apply(&plan)?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["written"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["octets"], 1, "apply: {applied}");
    let backup = applied["parameter_backup"].as_str().unwrap_or_default();
    assert!(Path::new(backup).is_file(), "parameter backup {backup}");

    let dev = bench.device();
    assert_eq!(dev.memory_writes, vec![(PARAM_BASE, 1)]);
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    // Only the application object loads: the link tables are left alone.
    assert_eq!(
        dev.load_events,
        vec![
            (APP_OBJECT, LE_START_LOADING),
            (APP_OBJECT, LE_LOAD_COMPLETED)
        ]
    );
    assert!(dev.property_writes.is_empty(), "{:?}", dev.property_writes);

    // Read back: a fresh plan has nothing to do.
    let replan = server.plan()?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert!(replan["plan_digest"].is_null(), "replan: {replan}");
    Ok(())
}

#[test]
fn test_mcp_plan_without_a_parameter_change_is_unchanged() -> TestResult {
    let Some(bench) = pinned("mcp-noop", [12, 0], "\"thr@P-0_R-1\" = \"12\"\n")? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], true, "plan: {plan}");
    assert!(plan["plan_digest"].is_null(), "plan: {plan}");
    assert_eq!(plan["parameters"]["changed"], json!([]), "plan: {plan}");
    assert_eq!(plan["writes"]["parameter_octets"], 0, "plan: {plan}");
    assert_eq!(
        plan["next_step"], "nothing to write: the device already matches the model",
        "plan: {plan}"
    );
    let dev = bench.device();
    assert!(dev.memory_writes.is_empty() && dev.load_events.is_empty());
    Ok(())
}

#[test]
fn test_mcp_apply_refuses_when_a_parameter_changed_since_the_plan() -> TestResult {
    let Some(bench) = pinned("mcp-moved", [7, 0], "\"thr@P-0_R-1\" = \"12\"\n")? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    assert_eq!(plan["noop"], false, "plan: {plan}");

    // The model's value moves between plan and apply: the image differs.
    bench.set_parameters("\"thr@P-0_R-1\" = \"13\"\n")?;
    let refused = server.apply(&plan)?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .is_some_and(|r| r.contains("parameter values")),
        "{refused}"
    );

    // The device's memory moves between plan and apply.
    let plan = server.plan()?;
    assert_ne!(plan["plan_digest"], Value::Null, "plan: {plan}");
    lock(&bench.shared).memory.insert(PARAM_BASE, 9);
    let refused = server.apply(&plan)?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .is_some_and(|r| r.contains("parameter memory")),
        "{refused}"
    );
    assert!(bench.device().memory_writes.is_empty(), "nothing written");
    Ok(())
}

/// The offline oracle rule for the MCP path: the same model change, planned
/// and applied through the CLI and through MCP on two identical devices,
/// reads the same state, plans the same sentences and writes the same octets
/// in the same load sequence.
#[test]
fn test_mcp_and_cli_write_the_same_parameter_image() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    let Some(cli) = pinned("image-cli", [7, 0], model)? else {
        return Ok(());
    };
    let Some(mcp) = pinned("image-mcp", [7, 0], model)? else {
        return Ok(());
    };

    let out = cli.bussard(&["plan", "1.1.4", "--json"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let cli_plan: Value = serde_json::from_str(&stdout)?;
    let out = cli.bussard(&["apply", "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("parameters verified"), "{stdout}");

    let mut server = mcp.mcp()?;
    let mcp_plan = server.plan()?;
    assert_eq!(mcp_plan["ok"], true, "plan: {mcp_plan}");
    assert_eq!(mcp_plan["state_hash"], cli_plan["state_hash"]);
    assert_eq!(mcp_plan["changes"], cli_plan["changes"]);
    assert_eq!(mcp_plan["writes"], cli_plan["writes"]);
    let applied = server.apply(&mcp_plan)?;
    assert_eq!(applied["ok"], true, "apply: {applied}");

    let (a, b) = (cli.device(), mcp.device());
    assert_eq!(a.memory_writes, b.memory_writes, "the octets written");
    assert_eq!(a.memory, b.memory, "the resulting memory");
    assert_eq!(a.load_events, b.load_events, "the load sequence");
    assert_eq!(a.property_writes, b.property_writes);
    assert_eq!(a.restarts, b.restarts);
    Ok(())
}

/// Issue #279: `pending_model_changes` lists only this session's unapplied
/// edits of the planned device. A labelled device file (`"Off"` for code 0)
/// is not a change, an edit is listed exactly, and an apply clears it.
#[test]
fn test_mcp_pending_model_changes_lists_only_this_sessions_edits() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    let Some(bench) = pinned("mcp-pending", [12, 0], model)? else {
        return Ok(());
    };
    let mut server = bench.mcp_with_edits()?;
    let plan = server.plan()?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], true, "plan: {plan}");
    assert_eq!(plan["pending_model_changes"], json!([]), "plan: {plan}");

    let edit = server.call(
        "knx_set_parameter",
        json!({"address": "1.1.4", "parameter": "thr@P-0_R-1", "value": "13"}),
    )?;
    assert_eq!(edit["ok"], true, "edit: {edit}");
    let threshold = "Threshold on Parameter test (1.1.4): 12 to 13.";
    assert!(
        edit["changes"]
            .as_array()
            .is_some_and(|c| c.iter().any(|s| s == threshold)),
        "edit: {edit}"
    );
    assert_eq!(
        edit["validation"]["new_warnings"],
        json!([]),
        "edit: {edit}"
    );

    let plan = server.plan()?;
    assert_eq!(plan["noop"], false, "plan: {plan}");
    let pending = plan["pending_model_changes"]
        .as_array()
        .ok_or("no pending_model_changes")?;
    assert_eq!(pending.len(), 1, "plan: {plan}");
    assert_eq!(pending[0]["tool"], "knx_set_parameter", "plan: {plan}");
    // Only what reaches the device: the group address the edit declared in
    // groups.toml is not pending on 1.1.4.
    assert_eq!(pending[0]["sentences"], json!([threshold]), "plan: {plan}");

    let applied = server.apply(&plan)?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    let replan = server.plan()?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert_eq!(
        replan["pending_model_changes"],
        json!([]),
        "replan: {replan}"
    );
    Ok(())
}

/// Issue #279: every written parameter octet is attributed. A device whose
/// memory differs from the model's image outside any parameter writes an
/// octet that changes no parameter, and the plan says so; a changed
/// parameter names its octet.
#[test]
fn test_mcp_plan_attributes_every_written_parameter_octet() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    // (the device's parameter octets, the changed keys, the written octet,
    // its owners, whether the plan explains unattributed octets)
    type Case<'a> = ([u8; 2], Vec<&'a str>, usize, Vec<(&'a str, &'a str)>, bool);
    let cases: [Case<'_>; 2] = [
        // Bit 1 of octet 1 belongs to no parameter (obj2 is bit 0).
        ([12, 0x40], vec![], 1, vec![], true),
        (
            [7, 0],
            vec!["thr@P-0_R-1"],
            0,
            vec![("thr@P-0_R-1", "changed")],
            false,
        ),
    ];
    for (memory, changed, offset, owners, explained) in cases {
        let Some(bench) = pinned("mcp-octets", memory, model)? else {
            return Ok(());
        };
        let mut server = bench.mcp()?;
        let plan = server.plan()?;
        assert_eq!(plan["ok"], true, "plan: {plan}");
        let parameters = &plan["parameters"];
        assert_eq!(parameters["octets"], 1, "plan: {plan}");
        let keys: Vec<&str> = parameters["changed"]
            .as_array()
            .map(|a| a.iter().filter_map(|c| c["key"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(keys, changed, "plan: {plan}");
        let ranges = parameters["octet_ranges"]
            .as_array()
            .ok_or("no octet_ranges")?;
        assert_eq!(ranges.len(), 1, "plan: {plan}");
        assert_eq!(ranges[0]["offset"], offset, "plan: {plan}");
        assert_eq!(ranges[0]["length"], 1, "plan: {plan}");
        let got: Vec<(&str, &str)> = ranges[0]["parameters"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| Some((p["key"].as_str()?, p["role"].as_str()?)))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(got, owners, "plan: {plan}");
        let sentences = plan["sentences"].as_str().unwrap_or_default();
        assert_eq!(
            sentences.contains("no parameter the device file shows"),
            explained,
            "{sentences}"
        );
        assert_eq!(
            sentences.contains(
                "1 octet at offset 1 of segment RS-2: device memory differs from the model's \
                 defaults there, not covered by a shown parameter"
            ),
            explained,
            "{sentences}"
        );
    }
    Ok(())
}

/// Issue #285: an octet no shown parameter covers is attributed to the
/// internal ETS selector or the hidden parameter placed there, with the
/// device's and the model's value; a differing selector carries the one
/// sentence on what it means.
#[test]
fn test_mcp_plan_attributes_internal_and_hidden_octets() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    const SELECTOR_NOTE: &str = "an internal ETS selector differs: the device's function \
         assignment differs from the project (the project changed after the device's last \
         download, or the device was downloaded from another project state); writing makes \
         the device match the model";
    // (octet 1 as the device holds it, the owner's key and role, the device
    // and model values, the run's sentence, whether the selector note follows)
    type Case<'a> = (u8, (&'a str, &'a str), (&'a str, &'a str), &'a str, bool);
    let cases: [Case<'_>; 2] = [
        (
            0x03,
            ("P-3", "internal"),
            ("Light", "no application"),
            "1 octet at offset 1 of segment RS-2: _AppInstanz 1 (internal ETS selector, P-3), \
             device Light, model no application",
            true,
        ),
        (
            0x10,
            ("P-2", "hidden"),
            ("1", "0"),
            "1 octet at offset 1 of segment RS-2: Delay (hidden by the configuration, P-2), \
             device 1, model 0",
            false,
        ),
    ];
    for (octet, (key, role), (device, model_value), sentence, noted) in cases {
        let Some(bench) = pinned("mcp-internal", [12, octet], model)? else {
            return Ok(());
        };
        let mut server = bench.mcp()?;
        let plan = server.plan()?;
        assert_eq!(plan["ok"], true, "plan: {plan}");
        let parameters = &plan["parameters"];
        assert_eq!(parameters["changed"], json!([]), "plan: {plan}");
        let ranges = parameters["octet_ranges"]
            .as_array()
            .ok_or("no octet_ranges")?;
        assert_eq!(ranges.len(), 1, "plan: {plan}");
        assert_eq!(ranges[0]["offset"], 1, "plan: {plan}");
        assert_eq!(
            ranges[0]["parameters"],
            json!([{"key": key, "name": ranges[0]["parameters"][0]["name"], "role": role,
                    "device": device, "model": model_value}]),
            "plan: {plan}"
        );
        assert_eq!(ranges[0]["sentence"], sentence, "plan: {plan}");
        assert_eq!(
            ranges[0]["explanation"].as_str(),
            noted.then_some(SELECTOR_NOTE),
            "plan: {plan}"
        );
        let sentences = plan["sentences"].as_str().unwrap_or_default();
        assert!(sentences.contains(sentence), "{sentences}");
        assert_eq!(sentences.contains(SELECTOR_NOTE), noted, "{sentences}");
    }
    Ok(())
}

/// The synthetic application with a Download-Flag (issue #289): an
/// `Access="None"` parameter the configuration reaches, in the free bit 1 of
/// octet 1, default 0. The application sets it at runtime, so it always
/// differs from the model's image after a download.
fn flag_app_xml() -> String {
    APP_XML
        .replace(
            "              <Parameter Id=\"M-00FA_A-0002_P-3\"",
            "              <Parameter Id=\"M-00FA_A-0002_P-4\" Name=\"dlflag\" \
             Text=\"Download-Flag\" ParameterType=\"M-00FA_A-0002_PT-1\" Access=\"None\" \
             Value=\"0\"><Memory CodeSegment=\"M-00FA_A-0002_RS-2\" Offset=\"1\" \
             BitOffset=\"1\" /></Parameter>\n              <Parameter Id=\"M-00FA_A-0002_P-3\"",
        )
        .replace(
            "              <ParameterRef Id=\"M-00FA_A-0002_P-3_R-4\"",
            "              <ParameterRef Id=\"M-00FA_A-0002_P-4_R-5\" \
             RefId=\"M-00FA_A-0002_P-4\" />\n              <ParameterRef \
             Id=\"M-00FA_A-0002_P-3_R-4\"",
        )
        .replace(
            "                <ComObjectRefRef RefId=\"M-00FA_A-0002_O-1_R-1\" />",
            "                <ParameterRefRef RefId=\"M-00FA_A-0002_P-4_R-5\" />\n                \
             <ComObjectRefRef RefId=\"M-00FA_A-0002_O-1_R-1\" />",
        )
}

/// The Download-Flag set by the application: bit 1 of octet 1.
const FLAG_SET: u8 = 0x40;

/// A bench on [`flag_app_xml`] with the product pinned, or `None` when `zip`
/// is unavailable.
fn flag_bench(tag: &str, params: [u8; 2], model: &str) -> Result<Option<Bench>, Box<dyn Error>> {
    let xml = flag_app_xml();
    assert!(xml.contains("P-4_R-5\" />"), "the flag was not spliced in");
    let Some(bench) = Bench::start_with_app(tag, MockDevice::running(params), model, &xml)? else {
        return Ok(None);
    };
    bench.pin_product()?;
    Ok(Some(bench))
}

/// The roles of a plan's parameter octet runs, run by run.
fn octet_roles(plan: &Value) -> Vec<Vec<String>> {
    plan["parameters"]["octet_ranges"]
        .as_array()
        .map(|runs| {
            runs.iter()
                .map(|run| {
                    run["parameters"]
                        .as_array()
                        .map(|ps| {
                            ps.iter()
                                .filter_map(|p| p["role"].as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Issue #289: a device whose only difference is the device-managed
/// Download-Flag plans as `noop` over MCP and as "nothing to write" at the
/// CLI; the flag is still listed with its role, and neither `apply` writes.
#[test]
fn test_download_flag_only_difference_plans_as_noop() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    let Some(bench) = flag_bench("mcp-flag-noop", [12, FLAG_SET], model)? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], true, "plan: {plan}");
    assert!(plan["plan_digest"].is_null(), "plan: {plan}");
    assert_eq!(plan["writes"]["parameter_octets"], 0, "plan: {plan}");
    assert_eq!(plan["parameters"]["written"], false, "plan: {plan}");
    assert_eq!(plan["parameters"]["changed"], json!([]), "plan: {plan}");
    assert_eq!(
        octet_roles(&plan),
        vec![vec!["device_managed".to_string()]],
        "plan: {plan}"
    );
    let next = plan["next_step"].as_str().unwrap_or_default();
    assert!(next.starts_with("nothing to write"), "{next}");
    assert!(next.contains("device-managed"), "{next}");
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.starts_with("1.1.4 matches the model; nothing to write\n"),
        "{sentences}"
    );
    assert!(
        sentences.contains("1 device-managed parameter octet differs"),
        "{sentences}"
    );
    drop(server);

    // The CLI plans and applies through the same engine.
    let out = bench.bussard(&["plan", "1.1.4"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("1.1.4 matches the model; nothing to write"),
        "{stdout}"
    );
    assert!(stdout.contains("Download-Flag"), "{stdout}");
    let out = bench.bussard(&["apply", "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let dev = bench.device();
    assert!(dev.memory_writes.is_empty(), "{:?}", dev.memory_writes);
    assert!(dev.load_events.is_empty(), "{:?}", dev.load_events);
    assert_eq!(dev.memory.get(&(PARAM_BASE + 1)).copied(), Some(FLAG_SET));
    Ok(())
}

/// Issue #289: with a real parameter change the Download-Flag is written
/// alongside, at the model's value, as ETS does at a download; once the
/// application sets it again the device plans as `noop`.
#[test]
fn test_real_parameter_change_still_writes_the_download_flag_alongside() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    let Some(bench) = flag_bench("mcp-flag-write", [7, FLAG_SET], model)? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    assert_eq!(plan["writes"]["parameter_octets"], 2, "plan: {plan}");
    assert_eq!(
        octet_roles(&plan),
        vec![
            vec!["changed".to_string()],
            vec!["device_managed".to_string()]
        ],
        "plan: {plan}"
    );

    let applied = server.apply(&plan)?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["written"], true, "apply: {applied}");
    let dev = bench.device();
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    assert_eq!(
        dev.memory.get(&(PARAM_BASE + 1)).copied(),
        Some(0),
        "the flag is written at the model's value"
    );

    // The application sets its flag again after the download.
    lock(&bench.shared).memory.insert(PARAM_BASE + 1, FLAG_SET);
    let replan = server.plan()?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert!(replan["plan_digest"].is_null(), "replan: {replan}");
    Ok(())
}

/// The synthetic application with an unreached octet (issue #290): the
/// parameter segment grows to three octets, the internal selector
/// `_AppInstanz 1` (`P-3`, `Access="None"`, reached by no Dynamic section)
/// moves to the high nibble of octet 2, where no other parameter is placed,
/// and the application prefers a partial download, so (like the Jung F50)
/// a hidden parameter keeps the segment template instead of its default.
fn unreached_app_xml() -> String {
    APP_XML
        .replace(
            "          <Static>\n",
            "          <Static>\n            <Options DownloadInvisibleParameters=\"None\" \
             PreferPartialDownloadIfApplicationLoaded=\"true\" />\n",
        )
        .replace(
            "<RelativeSegment Id=\"M-00FA_A-0002_RS-2\" Size=\"2\" LoadStateMachine=\"4\" \
             Offset=\"0\"><Data>AAA=</Data>",
            "<RelativeSegment Id=\"M-00FA_A-0002_RS-2\" Size=\"3\" LoadStateMachine=\"4\" \
             Offset=\"0\"><Data>AAAA</Data>",
        )
        .replace(
            "<Memory CodeSegment=\"M-00FA_A-0002_RS-2\" Offset=\"1\" BitOffset=\"4\" />",
            "<Memory CodeSegment=\"M-00FA_A-0002_RS-2\" Offset=\"2\" BitOffset=\"4\" />",
        )
        .replace(
            "<LdCtrlRelSegment LsmIdx=\"4\" Size=\"2\" AppliesTo=\"par\" />",
            "<LdCtrlRelSegment LsmIdx=\"4\" Size=\"3\" AppliesTo=\"par\" />",
        )
        .replace(
            "<LdCtrlWriteRelMem ObjIdx=\"0\" Offset=\"0\" Size=\"2\" AppliesTo=\"par\" />",
            "<LdCtrlWriteRelMem ObjIdx=\"0\" Offset=\"0\" Size=\"3\" AppliesTo=\"par\" />",
        )
}

/// `Light` in the selector's nibble of octet 2.
const SELECTOR_LIGHT: u8 = 0x03;

/// A bench on [`unreached_app_xml`] with the product pinned and the device's
/// three parameter octets, or `None` when `zip` is unavailable.
fn unreached_bench(
    tag: &str,
    params: [u8; 3],
    model: &str,
) -> Result<Option<Bench>, Box<dyn Error>> {
    let xml = unreached_app_xml();
    assert!(
        xml.contains("Offset=\"2\" BitOffset=\"4\"")
            && xml.contains("Size=\"3\" AppliesTo")
            && xml.contains("PreferPartialDownloadIfApplicationLoaded"),
        "the unreached selector was not moved"
    );
    let mut device = MockDevice::running([params[0], params[1]]);
    device.memory.insert(PARAM_BASE + 2, params[2]);
    let Some(bench) = Bench::start_with_app(tag, device, model, &xml)? else {
        return Ok(None);
    };
    bench.pin_product()?;
    Ok(Some(bench))
}

/// Issue #290 (option b, ETS parity): an octet no parameter the
/// configuration reaches is placed in differs on the device. The plan lists
/// it with `written: false`, its role, both values and the "ETS does not
/// write this octet" sentence, and does not count it; the apply writes only
/// the reached octet and leaves the unreached one as the device holds it.
#[test]
fn test_partial_write_leaves_an_unreached_octet_alone() -> TestResult {
    let model = "\"thr@P-0_R-1\" = \"12\"\n\"obj2@P-1_R-2\" = \"Off\"\n";
    let Some(bench) = unreached_bench("mcp-unreached", [7, 0, SELECTOR_LIGHT], model)? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    assert_eq!(plan["writes"]["parameter_octets"], 1, "plan: {plan}");
    assert_eq!(plan["parameters"]["octets"], 1, "plan: {plan}");
    let ranges = plan["parameters"]["octet_ranges"]
        .as_array()
        .ok_or("no octet_ranges")?;
    assert_eq!(ranges.len(), 2, "plan: {plan}");
    assert_eq!(
        (&ranges[0]["offset"], &ranges[0]["written"]),
        (&json!(0), &json!(true)),
        "plan: {plan}"
    );
    assert_eq!(
        ranges[0]["parameters"][0]["role"], "changed",
        "plan: {plan}"
    );
    let unreached = &ranges[1];
    assert_eq!(unreached["offset"], 2, "plan: {plan}");
    assert_eq!(unreached["written"], false, "plan: {plan}");
    assert_eq!(
        unreached["parameters"],
        json!([{"key": "P-3", "name": "_AppInstanz 1", "role": "internal",
                "device": "Light", "model": "no application"}]),
        "plan: {plan}"
    );
    assert_eq!(
        unreached["sentence"],
        "1 octet at offset 2 of segment RS-2, not written (ETS does not write this octet in a \
         download): _AppInstanz 1 (internal ETS selector, P-3), device Light, model no \
         application",
        "plan: {plan}"
    );
    assert_eq!(
        unreached["explanation"],
        "ETS does not write this octet in a download; a full download leaves the segment fill \
         (0x00) there; the device holds Light from an earlier state",
        "plan: {plan}"
    );
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.contains(
            "ETS does not write it in a download, so this plan leaves the device's value"
        ),
        "{sentences}"
    );

    let applied = server.apply(&plan)?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["octets"], 1, "apply: {applied}");
    let dev = bench.device();
    assert_eq!(dev.memory_writes, vec![(PARAM_BASE, 1)]);
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    assert_eq!(
        dev.memory.get(&(PARAM_BASE + 2)).copied(),
        Some(SELECTOR_LIGHT)
    );

    // Only the unreached octet differs now: nothing to write, still listed.
    let replan = server.plan()?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert!(replan["plan_digest"].is_null(), "replan: {replan}");
    assert_eq!(
        replan["parameters"]["octet_ranges"][0]["written"], false,
        "replan: {replan}"
    );
    assert!(
        replan["next_step"]
            .as_str()
            .is_some_and(|s| s.contains("ETS does not write in a download either")),
        "replan: {replan}"
    );
    Ok(())
}

/// The one parameter backup under the model's backup directory.
fn only_parameter_backup(bench: &Bench) -> Result<PathBuf, Box<dyn Error>> {
    let dir = bench.model().join("captures/backups/parameters");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    match files.as_slice() {
        [one] => Ok(one.clone()),
        other => Err(format!(
            "expected one parameter backup in {}, found {other:?}",
            dir.display()
        )
        .into()),
    }
}

/// Issue #290: `apply` keeps the pre-write parameter memory, and `restore
/// --parameters` puts it back on the mock device with the same download,
/// verified by read-back; a second restore finds nothing to write.
#[test]
fn test_restore_parameters_round_trip() -> TestResult {
    let Some(bench) = pinned("restore-roundtrip", [12, 0], "\"thr@P-0_R-1\" = \"13\"\n")? else {
        return Ok(());
    };
    let out = bench.bussard(&["apply", "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "apply: {stdout}\n{stderr}");
    assert_eq!(bench.device().memory.get(&PARAM_BASE).copied(), Some(13));
    let backup = only_parameter_backup(&bench)?;
    // Keep the backup apart: the restore writes its own backup into the
    // same directory.
    let kept = bench.tmp.join("kept-backup.json");
    std::fs::copy(&backup, &kept)?;
    let kept = kept.to_str().ok_or("non-UTF-8 temp path")?;

    let writes_before = bench.device().memory_writes.len();
    let out = bench.bussard(&["restore", "--parameters", kept, "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "restore: {stdout}\n{stderr}");
    assert!(
        stdout.contains("writes 1 parameter octet(s) to 1.1.4:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("parameters restored and verified: 1 octet(s) read back"),
        "{stdout}"
    );
    let dev = bench.device();
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    assert_eq!(&dev.memory_writes[writes_before..], &[(PARAM_BASE, 1)]);

    let out = bench.bussard(&["restore", "--parameters", kept, "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "second restore: {stdout}\n{stderr}");
    assert!(
        stdout.contains("already holds the backup's parameter octets; nothing to write"),
        "{stdout}"
    );
    assert_eq!(bench.device().memory_writes.len(), dev.memory_writes.len());
    Ok(())
}

/// Issue #290: a backup of another application, mask or device is refused
/// before anything is written.
#[test]
fn test_restore_parameters_refuses_another_identity() -> TestResult {
    let Some(bench) = pinned("restore-identity", [12, 0], "\"thr@P-0_R-1\" = \"13\"\n")? else {
        return Ok(());
    };
    let backup = |field: &str, value: &str| -> Result<PathBuf, Box<dyn Error>> {
        let mut body = json!({
            "address": "1.1.4",
            "mask": "07B0",
            "application": "M-00FA_A-0002",
            "unix_timestamp": 1,
            "read_time": "1970-01-01T00:00:01Z",
            "regions": [{"base": PARAM_BASE, "length": 2, "bytes": "0700",
                         "source": "parameter segment M-00FA_A-0002_RS-2"}],
        });
        body[field] = json!(value);
        let path = bench.tmp.join(format!("backup-{field}.json"));
        std::fs::write(&path, serde_json::to_string(&body)?)?;
        Ok(path)
    };
    let cases = [
        (
            "application",
            "M-00FA_A-0003",
            "the backup holds the parameters of application M-00FA_A-0003",
        ),
        (
            "mask",
            "0705",
            "the backup was read from a device with mask 0705",
        ),
        ("address", "1.1.5", "the backup is of 1.1.5, not 1.1.4"),
    ];
    for (field, value, reason) in cases {
        let path = backup(field, value)?;
        let path = path.to_str().ok_or("non-UTF-8 temp path")?;
        let out = bench.bussard(&["restore", "--parameters", path, "1.1.4", "--yes"])?;
        let (stdout, stderr) = text(&out);
        assert!(!out.status.success(), "{field}: {stdout}\n{stderr}");
        assert!(stderr.contains(reason), "{field}: {stderr}");
        assert!(bench.device().memory_writes.is_empty(), "{field}: wrote");
    }
    // The same backup with the device's identity restores.
    let path = backup("application", "M-00FA_A-0002")?;
    let path = path.to_str().ok_or("non-UTF-8 temp path")?;
    let out = bench.bussard(&["restore", "--parameters", path, "1.1.4", "--yes"])?;
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert_eq!(bench.device().memory.get(&PARAM_BASE).copied(), Some(7));
    Ok(())
}

/// Issue #290: `knx_restore_parameters` plans the replay of an apply's
/// backup (octets, roles, digest; nothing written), refuses a digest it did
/// not produce, and with the plan's digest writes and verifies.
#[test]
fn test_mcp_restore_parameters_plans_then_writes() -> TestResult {
    let Some(bench) = pinned("mcp-restore", [12, 0], "\"thr@P-0_R-1\" = \"13\"\n")? else {
        return Ok(());
    };
    let mut server = bench.mcp()?;
    let plan = server.plan()?;
    let applied = server.apply(&plan)?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    let backup = only_parameter_backup(&bench)?;
    let name = backup
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("no backup file name")?
        .to_string();
    let writes_before = bench.device().memory_writes.len();

    let planned = server.call(
        "knx_restore_parameters",
        json!({"address": "1.1.4", "backup": name}),
    )?;
    assert_eq!(planned["ok"], true, "restore plan: {planned}");
    assert_eq!(planned["octets"], 1, "restore plan: {planned}");
    let ranges = planned["octet_ranges"]
        .as_array()
        .ok_or("no octet_ranges")?;
    assert_eq!(ranges.len(), 1, "restore plan: {planned}");
    assert_eq!(ranges[0]["written"], true, "restore plan: {planned}");
    assert_eq!(
        ranges[0]["parameters"][0]["key"], "thr@P-0_R-1",
        "restore plan: {planned}"
    );
    assert_eq!(
        (
            &ranges[0]["parameters"][0]["device"],
            &ranges[0]["parameters"][0]["model"]
        ),
        (&json!("13"), &json!("12")),
        "restore plan: {planned}"
    );
    assert!(
        ranges[0]["sentence"]
            .as_str()
            .is_some_and(|s| s.ends_with("device 13, backup 12")),
        "restore plan: {planned}"
    );
    assert_eq!(bench.device().memory_writes.len(), writes_before);
    let digest = planned["plan_digest"].as_str().ok_or("no plan_digest")?;

    let refused = server.call(
        "knx_restore_parameters",
        json!({"address": "1.1.4", "backup": name, "plan_digest": "00"}),
    )?;
    assert_eq!(refused["refused"], true, "refused: {refused}");
    assert_eq!(bench.device().memory_writes.len(), writes_before);

    let written = server.call(
        "knx_restore_parameters",
        json!({"address": "1.1.4", "backup": name, "plan_digest": digest}),
    )?;
    assert_eq!(written["ok"], true, "restore: {written}");
    assert_eq!(written["verified"], true, "restore: {written}");
    assert_eq!(written["parameters"]["octets"], 1, "restore: {written}");
    assert!(
        written["parameter_backup"]
            .as_str()
            .is_some_and(|p| Path::new(p).is_file()),
        "restore: {written}"
    );
    let dev = bench.device();
    assert_eq!(dev.memory.get(&PARAM_BASE).copied(), Some(12));
    assert_eq!(&dev.memory_writes[writes_before..], &[(PARAM_BASE, 1)]);

    // Single use: the digest is spent.
    let again = server.call(
        "knx_restore_parameters",
        json!({"address": "1.1.4", "backup": name, "plan_digest": digest}),
    )?;
    assert_eq!(again["refused"], true, "again: {again}");
    Ok(())
}
