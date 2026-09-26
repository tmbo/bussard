//! End-to-end subprocess test of `bussard mcp` over real stdio.
//!
//! Spawns the built binary, speaks a JSON-RPC `initialize` + `tools/list`
//! handshake on its stdin/stdout, and asserts:
//!
//! - stdout carries **only** valid JSON-RPC (nothing else may print there), and
//! - `tools/list` returns exactly the expected tool set (13 in `--passive`: the
//!   nine model/bus read tools, the two file-only history tools and the two
//!   bundle/diff tools).
//!
//! This is the stdout-purity guard the design brief calls for.
//!
//! A second test (issue #267) starts the server on a model whose
//! `.bussard/models/` is empty although `bussard.lock` pins the archive in
//! `products/`: `knx_show_device` must see the product data, also after the
//! model file is deleted mid-session and the model reloads.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Writes a minimal model directory.
fn write_model(dir: &std::path::Path) -> TestResult {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"192.0.2.1:3671\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "project = \"Demo\"\ngroups = [{ address = \"3/2/0\", name = \"Windalarm\", dpt = \"1.005\" }]\n",
    )?;
    Ok(())
}

#[test]
fn mcp_stdio_handshake_is_pure_json_and_lists_the_passive_tools() -> TestResult {
    let tmp = std::env::temp_dir().join(format!("bussard-mcp-stdio-{}", std::process::id()));
    let knx = tmp.join("knx");
    write_model(&knx)?;

    let bin = env!("CARGO_BIN_EXE_bussard");
    let mut child = Command::new(bin)
        .args(["mcp", "--dir"])
        .arg(&knx)
        .arg("--passive")
        .arg("--no-model-edits")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let mut reader = BufReader::new(stdout);

    // initialize.
    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"}
        }
    });
    writeln!(stdin, "{init}")?;
    stdin.flush()?;

    // Read the initialize response line.
    let init_line = read_line(&mut reader);
    let init_resp: serde_json::Value = serde_json::from_str(&init_line)?;
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "bussard");

    // initialized notification, then tools/list.
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )?;
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    )?;
    stdin.flush()?;

    // Read lines until we get the tools/list response (id == 2). Every line we
    // read from stdout must be valid JSON — that is the purity guarantee.
    let mut tools: Option<Vec<String>> = None;
    for _ in 0..10 {
        let line = read_line(&mut reader);
        if line.is_empty() {
            break;
        }
        let v: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("non-JSON on stdout: {line:?} ({e})"));
        if v["id"] == 2 {
            let names = v["result"]["tools"]
                .as_array()
                .ok_or("tools array")?
                .iter()
                .map(|t| t["name"].as_str().map(str::to_string).ok_or("tool name"))
                .collect::<Result<Vec<_>, _>>()?;
            tools = Some(names);
            break;
        }
    }

    // Close stdin so the server exits on EOF, then reap. The assertion above
    // already has the tools/list response, so this is only a graceful-exit grace
    // window: a short poll (the server exits near-instantly on EOF) followed by
    // an unconditional kill, rather than a fixed 3s wait.
    drop(stdin);
    let _ = child.wait_timeout(Duration::from_millis(500));
    let _ = child.kill();

    let mut tools = tools.ok_or("received no tools/list response")?;
    tools.sort();
    let mut expected = vec![
        "knx_audit",
        "knx_describe_change",
        "knx_diff_project",
        "knx_export_bundle",
        "knx_get_device",
        "knx_get_group",
        "knx_history",
        "knx_infer_group",
        "knx_model_lookup",
        "knx_project_summary",
        "knx_recent_telegrams",
        "knx_show_device",
        "knx_validate",
        "knx_wait_for_telegram",
    ];
    expected.sort_unstable();
    assert_eq!(
        tools, expected,
        "passive mode exposes exactly 14 tools: no bus tools, and no model edits \
         because this server runs with --no-model-edits"
    );

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

const APP_ID: &str = "M-0083_A-1234-11-ABCD-O000A";

const HARDWARE_XML: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <ManufacturerData><Manufacturer RefId="M-0083">
    <Hardware>
      <Products><Product OrderNumber="MDT-BE-04001.02" /></Products>
      <Hardware2Programs><Hardware2Program>
        <ApplicationProgramRef RefId="M-0083_A-1234-11-ABCD-O000A" />
      </Hardware2Program></Hardware2Programs>
    </Hardware>
  </Manufacturer></ManufacturerData>
</KNX>"#;

const APP_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
 <ManufacturerData><Manufacturer RefId="M-0083"><ApplicationPrograms>
  <ApplicationProgram Id="M-0083_A-1234-11-ABCD-O000A" ApplicationNumber="1" ApplicationVersion="17" MaskVersion="MV-07B0" Name="Taster BE 04001" LoadProcedureStyle="MergedProcedure">
   <Static>
    <ComObjectTable>
     <ComObject Id="M-0083_A-1234-11-ABCD-O000A_O-0" Number="0" Text="Taste 1" ObjectSize="1 Bit" CommunicationFlag="Enabled" TransmitFlag="Enabled" />
    </ComObjectTable>
    <ComObjectRefs>
     <ComObjectRef Id="M-0083_A-1234-11-ABCD-O000A_O-0_R-1" RefId="M-0083_A-1234-11-ABCD-O000A_O-0" DatapointType="DPST-1-1" />
    </ComObjectRefs>
   </Static>
  </ApplicationProgram>
 </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

/// A model with device 1.1.4 whose archive `products/taster.knxprod` the
/// lock pins, and an empty `.bussard/models/`.
fn write_pinned_model(dir: &std::path::Path) -> TestResult {
    use sha2::Digest as _;
    use zip::write::SimpleFileOptions;

    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join("products"))?;
    std::fs::create_dir_all(dir.join(".bussard/models"))?;
    let archive = dir.join("products/taster.knxprod");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive)?);
    for (name, body) in [
        ("knx_master.xml", "<KNX/>"),
        ("M-0083/Hardware.xml", HARDWARE_XML),
        (&format!("M-0083/{APP_ID}.xml") as &str, APP_XML),
    ] {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(body.as_bytes())?;
    }
    zip.finish()?;
    let sha: String = sha2::Sha256::digest(std::fs::read(&archive)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        dir.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/0/0\", name = \"Licht\", dpt = \"1.001\" },\n]\n",
    )?;
    std::fs::write(
        dir.join("devices/1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Taster\"\nproduct = \"MDT-BE-04001.02\"\n\n[links]\n0.send = \"1/0/0\"\n",
    )?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 2\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/taster.knxprod\"\n\
             filename = \"taster.knxprod\"\norigin = {{ kind = \"index\", order_number = \
             \"MDT-BE-04001.02\" }}\napplications = [\"{APP_ID}\"]\norder_numbers = \
             [\"MDT-BE-04001.02\"]\n\n[[device]]\naddress = \"1.1.4\"\nproduct = \
             \"MDT-BE-04001.02\"\napplication = \"{APP_ID}\"\nproduct_sha256 = \"{sha}\"\n\
             mask = \"07B0\"\n"
        ),
    )?;
    Ok(())
}

/// Sends one `tools/call` and returns the tool's JSON result (the first text
/// content, parsed).
fn call_tool(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    id: u64,
    name: &str,
    arguments: serde_json::Value,
) -> TestResult<serde_json::Value> {
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":name,"arguments":arguments}})
    )?;
    stdin.flush()?;
    for _ in 0..10 {
        let line = read_line(reader);
        if line.is_empty() {
            break;
        }
        let v: serde_json::Value = serde_json::from_str(&line)?;
        if v["id"] == id {
            let text = v["result"]["content"][0]["text"]
                .as_str()
                .ok_or_else(|| format!("no text content in {v}"))?;
            return Ok(serde_json::from_str(text)?);
        }
    }
    Err(format!("no response to {name}").into())
}

#[test]
fn test_mcp_show_device_sees_product_data_with_an_empty_models_directory() -> TestResult {
    let tmp = std::env::temp_dir().join(format!("bussard-mcp-regen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let knx = tmp.join("knx");
    write_pinned_model(&knx)?;
    let model_file = knx.join(format!(".bussard/models/{APP_ID}.yaml"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["mcp", "--dir"])
        .arg(&knx)
        .args(["--gateway", "127.0.0.1:9", "--passive", "--no-model-edits"])
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout pipe")?);

    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"}
        }
    });
    writeln!(stdin, "{init}")?;
    stdin.flush()?;
    let init_resp: serde_json::Value = serde_json::from_str(&read_line(&mut reader))?;
    assert_eq!(init_resp["id"], 1);
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )?;

    let args = serde_json::json!({"address": "1.1.4"});
    let first = call_tool(&mut stdin, &mut reader, 2, "knx_show_device", args.clone())?;
    assert_eq!(first["product_model"], true, "{first}");
    assert!(model_file.is_file(), "the model was regenerated at start");

    // Deleted mid-session: the next model reload (an edit under knx/, seen
    // after the one-second recheck debounce) regenerates it.
    std::fs::remove_file(&model_file)?;
    let groups = knx.join("groups.toml");
    let text = std::fs::read_to_string(&groups)?;
    std::fs::write(&groups, format!("{text}# edited\n"))?;
    std::thread::sleep(Duration::from_millis(1200));
    let second = call_tool(&mut stdin, &mut reader, 3, "knx_show_device", args)?;
    assert_eq!(second["product_model"], true, "{second}");
    assert!(model_file.is_file(), "the reload regenerated the model");

    drop(stdin);
    let _ = child.wait_timeout(Duration::from_millis(500));
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// Reads one line, returning it trimmed (empty string on EOF).
fn read_line(reader: &mut impl BufRead) -> String {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => String::new(),
        Ok(_) => line.trim_end().to_string(),
        Err(_) => String::new(),
    }
}

/// A tiny `wait_timeout` shim so we don't pull in the `wait-timeout` crate: it
/// polls `try_wait` for up to `dur`.
trait WaitTimeout {
    fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
        let deadline = std::time::Instant::now() + dur;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
