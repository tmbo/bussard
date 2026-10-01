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
