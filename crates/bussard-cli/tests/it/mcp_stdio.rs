//! End-to-end subprocess test of `bussard mcp` over real stdio.
//!
//! Spawns the built binary, speaks a JSON-RPC `initialize` + `tools/list`
//! handshake on its stdin/stdout, and asserts:
//!
//! - stdout carries **only** valid JSON-RPC (nothing else may print there), and
//! - `tools/list` returns exactly the expected tool set (17 in `--passive`: the
//!   eleven model/bus read tools, the two file-only history tools, the two
//!   bundle/diff tools and `knx_export`).
//!
//! This is the stdout-purity guard the design brief calls for. It also checks
//! that a server spawned with piped stderr (as a client spawns it) logs the
//! plain "mcp: serving on stdio" line and not the terminal-only connect hint.
//!
//! A second test (issue #267) starts the server on a model whose
//! `.bussard/model-cache/` is empty although `bussard.lock` pins the archive in
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
        .arg("-v")
        .env("BUSSARD_NO_DOTENV", "1")
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
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        std::io::Read::read_to_string(&mut pipe, &mut stderr)?;
    }
    let _ = child.wait();
    assert!(
        stderr.contains("mcp: serving on stdio"),
        "the info line is logged: {stderr}"
    );
    assert!(
        !stderr.contains("claude mcp add") && !stderr.contains("mcpServers"),
        "a piped stderr gets no connect hint: {stderr}"
    );

    let mut tools = tools.ok_or("received no tools/list response")?;
    tools.sort();
    let mut expected = vec![
        "knx_audit",
        "knx_bus_status",
        "knx_describe_change",
        "knx_diff_project",
        "knx_export",
        "knx_export_bundle",
        "knx_get_device",
        "knx_get_group",
        "knx_history",
        "knx_infer_group",
        "knx_job_status",
        "knx_model_lookup",
        "knx_project_summary",
        "knx_recent_telegrams",
        "knx_show_device",
        "knx_validate",
        "knx_viz",
        "knx_wait_for_telegram",
    ];
    expected.sort_unstable();
    assert_eq!(
        tools, expected,
        "passive mode exposes exactly 18 tools: no bus-transmitting tools, and no model edits \
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
/// lock pins, and an empty `.bussard/model-cache/`.
fn write_pinned_model(dir: &std::path::Path) -> TestResult {
    use sha2::Digest as _;
    use zip::write::SimpleFileOptions;

    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join("products"))?;
    std::fs::create_dir_all(dir.join(".bussard/model-cache"))?;
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
            "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/taster.knxprod\"\n\
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
    let model_file = knx.join(format!(".bussard/model-cache/{APP_ID}.json"));

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

/// The fabricated program of issue #276: an enable flag whose ref turns
/// channel 1 on, a second enable flag at its default hiding a data length and
/// object 2.
const DEFAULTS_APP_ID: &str = "M-00FA_A-00D2-10-0001";
const DEFAULTS_APP_XML: &[u8] =
    include_bytes!("../../../bussard-product/tests/fixtures/default_params.app.xml");

/// Imports a project with device 1.1.9 running [`DEFAULTS_APP_XML`] (no
/// stored parameter) into `knx`, and pins the extracted archive for it.
fn import_defaults(tmp: &std::path::Path, knx: &std::path::Path) -> TestResult {
    use sha2::Digest as _;
    let project = r#"<KNX xmlns="http://knx.org/xml/project/21">
 <Project Id="P-9998">
  <Installations><Installation>
   <Topology><Area Address="1"><Line Address="1">
    <DeviceInstance Id="P-9998-0_DI-1" Address="9" Name="Mapper" Hardware2ProgramRefId="M-00FA_H-1_HP-00D2-10-0001" />
   </Line></Area></Topology>
  </Installation></Installations>
 </Project>
</KNX>"#;
    std::fs::create_dir_all(tmp)?;
    let knxproj = tmp.join("defaults.knxproj");
    let mut zw = zip::ZipWriter::new(std::fs::File::create(&knxproj)?);
    let opts = zip::write::SimpleFileOptions::default();
    zw.start_file("knx_master.xml", opts)?;
    zw.write_all(br#"<KNX xmlns="http://knx.org/xml/project/21"/>"#)?;
    zw.start_file("P-9998/0.xml", opts)?;
    zw.write_all(project.as_bytes())?;
    zw.start_file(format!("M-00FA/{DEFAULTS_APP_ID}.xml"), opts)?;
    zw.write_all(DEFAULTS_APP_XML)?;
    zw.finish()?;
    let out = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .arg("import")
        .arg(&knxproj)
        .arg("--no-download")
        .arg("--dir")
        .arg(knx)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The project names no catalogue entry, so the import pins nothing for
    // the device; pin the extracted archive the way `import-product` would.
    let archive = knx.join(format!("products/{DEFAULTS_APP_ID}.knxprod"));
    let sha: String = sha2::Sha256::digest(std::fs::read(&archive)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let lock = std::fs::read_to_string(knx.join("bussard.lock"))?;
    let pinned = lock.replacen(
        "address = \"1.1.9\"\n",
        &format!("address = \"1.1.9\"\nproduct_sha256 = \"{sha}\"\n"),
        1,
    );
    assert_ne!(pinned, lock, "{lock}");
    std::fs::write(knx.join("bussard.lock"), pinned)?;
    std::fs::write(
        knx.join("bussard.toml"),
        "[connection]\ntransport = \"tunnel\"\ngateway = \"127.0.0.1:9\"\n",
    )?;
    Ok(())
}

#[test]
fn test_mcp_set_parameter_at_default_reveals_dependent_parameters() -> TestResult {
    let tmp = std::env::temp_dir().join(format!("bussard-mcp-defaults-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let knx = tmp.join("knx");
    import_defaults(&tmp, &knx)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["mcp", "--dir"])
        .arg(&knx)
        .args(["--gateway", "127.0.0.1:9", "--passive"])
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

    let keys = |view: &serde_json::Value| -> Vec<String> {
        view["scope"]["parameters"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p["key"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let show = serde_json::json!({"address": "1.1.9", "channel": "mapper-1"});
    let before = call_tool(&mut stdin, &mut reader, 2, "knx_show_device", show.clone())?;
    assert_eq!(
        keys(&before),
        [
            "enable-channel-1",
            "enable-channel-2",
            "data-length-1",
            "polarity"
        ],
        "{before}"
    );

    // A key at its vendor default (no stored value) is settable, and the
    // block it enables appears at once.
    let set = call_tool(
        &mut stdin,
        &mut reader,
        3,
        "knx_set_parameter",
        serde_json::json!({"address": "1.1.9", "parameter": "enable-channel-2", "value": "On"}),
    )?;
    assert_eq!(set["ok"], true, "{set}");
    let note = set["note"].as_str().unwrap_or_default();
    assert!(note.contains("shows object(s) 2"), "{set}");
    assert!(note.contains("`bussard flash 1.1.9`"), "{set}");
    let after = call_tool(&mut stdin, &mut reader, 4, "knx_show_device", show)?;
    assert!(keys(&after).iter().any(|k| k == "data-length-2"), "{after}");
    let objects: Vec<u64> = after["scope"]["objects"]
        .as_array()
        .map(|a| a.iter().filter_map(|o| o["number"].as_u64()).collect())
        .unwrap_or_default();
    assert_eq!(objects, [1, 2], "{after}");

    drop(stdin);
    let _ = child.wait_timeout(Duration::from_millis(500));
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// Sends one JSON-RPC request and reads stdout until its response, counting
/// the `notifications/tools/list_changed` seen on the way. Every line must be
/// JSON.
fn request(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    id: u64,
    method: &str,
    params: serde_json::Value,
    list_changed: &mut usize,
) -> TestResult<serde_json::Value> {
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
    )?;
    stdin.flush()?;
    for _ in 0..20 {
        let line = read_line(reader);
        if line.is_empty() {
            break;
        }
        let v: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| format!("non-JSON on stdout: {line:?} ({e})"))?;
        if v["method"] == "notifications/tools/list_changed" {
            *list_changed += 1;
            continue;
        }
        if v["id"] == id {
            return Ok(v);
        }
    }
    Err(format!("no response to {method}").into())
}

/// The sorted tool names of a `tools/list` response.
fn tool_list(response: &serde_json::Value) -> TestResult<Vec<String>> {
    let mut names = response["result"]["tools"]
        .as_array()
        .ok_or("tools array")?
        .iter()
        .map(|t| t["name"].as_str().map(str::to_string).ok_or("tool name"))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

/// Issue #745: on a missing directory the server starts with `knx_setup`
/// and `knx_bus_status` only; `knx_setup` against a mock gateway writes the
/// model, the server says the tool list changed and lists the full default
/// tier. The password argument appears nowhere in the output.
#[test]
fn test_mcp_knx_setup_on_an_empty_directory_registers_the_full_tool_set() -> TestResult {
    use bussard_testkit::MockGateway;

    const PASSWORD: &str = "pw-never-echoed-745";
    let tmp = std::env::temp_dir().join(format!("bussard-mcp-setup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let knx = tmp.join("knx");

    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockGateway::builder()
            .channel(7)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .start(),
    )?;
    let gateway = format!("127.0.0.1:{}", gw.port());

    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["mcp", "--dir"])
        .arg(&knx)
        .current_dir(&tmp)
        .env("BUSSARD_NO_DOTENV", "1")
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_PROJECT_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout pipe")?);
    let mut changed = 0;

    let init = request(
        &mut stdin,
        &mut reader,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"}
        }),
        &mut changed,
    )?;
    assert_eq!(
        init["result"]["capabilities"]["tools"]["listChanged"], true,
        "{init}"
    );
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )?;

    let before = request(
        &mut stdin,
        &mut reader,
        2,
        "tools/list",
        serde_json::json!({}),
        &mut changed,
    )?;
    assert_eq!(tool_list(&before)?, ["knx_bus_status", "knx_setup"]);

    let setup = request(
        &mut stdin,
        &mut reader,
        3,
        "tools/call",
        serde_json::json!({"name": "knx_setup",
            "arguments": {"gateway": gateway, "password": PASSWORD}}),
        &mut changed,
    )?;
    let text = setup["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| format!("no text content in {setup}"))?;
    let result: serde_json::Value = serde_json::from_str(text)?;
    assert_eq!(result["done"], true, "{result}");

    let after = request(
        &mut stdin,
        &mut reader,
        4,
        "tools/list",
        serde_json::json!({}),
        &mut changed,
    )?;
    let mut expected: Vec<String> = bussard_mcp::tool_names(false, false, false)
        .into_iter()
        .map(str::to_string)
        .collect();
    expected.sort();
    assert_eq!(tool_list(&after)?, expected);
    assert_eq!(result["tools"], expected.len(), "{result}");
    assert!(
        changed >= 1,
        "the server sent notifications/tools/list_changed"
    );

    let config = std::fs::read_to_string(knx.join("bussard.toml"))?;
    assert!(
        config.contains(&format!("gateway = \"{gateway}\"")),
        "{config}"
    );
    assert!(knx.join("groups.toml").is_file());

    drop(stdin);
    let _ = child.wait_timeout(Duration::from_millis(500));
    let _ = child.kill();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        std::io::Read::read_to_string(&mut pipe, &mut stderr)?;
    }
    let _ = child.wait();
    drop(gw);
    assert!(
        !text.contains(PASSWORD),
        "the result never echoes the password"
    );
    assert!(
        !stderr.contains(PASSWORD),
        "the log never echoes the password"
    );

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// Issue #779: the keyring exported next to the project goes into the key
/// store during `knx_setup`, and the server reads its KNXnet/IP Secure
/// tunnelling users then, not at start: the bus opens a secure tunnel to a
/// secure-only interface without a restart, and the summary says which
/// credentials it uses. The keyring is the committed SYNTHETIC one (made-up
/// passwords); the interface is a loopback [`MockSecureGateway`].
#[test]
fn test_mcp_knx_setup_uses_the_keyring_tunnel_users_without_a_restart() -> TestResult {
    use bussard_secure::{Password, salt};
    use bussard_testkit::MockSecureGateway;

    let tmp = std::env::temp_dir().join(format!("bussard-mcp-setup-ips-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let knx = tmp.join("knx");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let project = tmp.join("project.knxproj");
    super::tiny_project::write(&project)?;
    std::fs::copy(
        root.join("../../knx-sim/examples/secure/synthetic.knxkeys"),
        tmp.join("Site.knxkeys"),
    )?;
    // An empty product index: the setup never reaches the network.
    let index = tmp.join("index.json");
    std::fs::write(&index, r#"{"entries": []}"#)?;

    // Secure-only: a plain tunnel is refused, user 2 of the keyring accepted.
    let rt = tokio::runtime::Runtime::new()?;
    let gw = rt.block_on(
        MockSecureGateway::builder()
            .individual_address(0x1100)
            .device_auth(Password::new("device-auth-pw").derive(salt::DEVICE_AUTHENTICATION_CODE))
            .user(
                2,
                Password::new("tunnel-user-pw").derive(salt::USER_PASSWORD),
                0x11C8,
            )
            .start(),
    )?;
    let gateway = gw.addr().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_bussard"))
        .args(["mcp", "--dir"])
        .arg(&knx)
        .current_dir(&tmp)
        .env("BUSSARD_NO_DOTENV", "1")
        .env("BUSSARD_KEYRING_PASSWORD", "synthetic-keyring-pw")
        .env("BUSSARD_PRODUCT_INDEX", &index)
        .env_remove("BUSSARD_GATEWAY")
        .env_remove("BUSSARD_KEYRING")
        .env_remove("BUSSARD_ALLOW_REAL_GATEWAY")
        .env_remove("BUSSARD_PROJECT_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout pipe")?);
    let mut changed = 0;
    let mut next_id = 1;
    let mut call = |stdin: &mut std::process::ChildStdin,
                    reader: &mut BufReader<std::process::ChildStdout>,
                    method: &str,
                    params: serde_json::Value,
                    changed: &mut usize|
     -> TestResult<serde_json::Value> {
        next_id += 1;
        request(stdin, reader, next_id, method, params, changed)
    };
    call(
        &mut stdin,
        &mut reader,
        "initialize",
        serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"}
        }),
        &mut changed,
    )?;
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )?;

    let setup = call(
        &mut stdin,
        &mut reader,
        "tools/call",
        serde_json::json!({"name": "knx_setup",
            "arguments": {"gateway": gateway, "project_file": project}}),
        &mut changed,
    )?;
    let text = setup["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| format!("no text content in {setup}"))?;
    let result: serde_json::Value = serde_json::from_str(text)?;
    assert_eq!(result["done"], true, "{result}");
    assert!(knx.join("bussard.keys").is_file(), "{result}");
    let summary = result["summary"].as_str().ok_or("no summary")?;
    assert!(
        summary.contains("KNXnet/IP Secure") && summary.contains("no restart"),
        "{summary}"
    );

    // The bus connects lazily: ask until it is up.
    let mut status = serde_json::Value::Null;
    for _ in 0..40 {
        let response = call(
            &mut stdin,
            &mut reader,
            "tools/call",
            serde_json::json!({"name": "knx_bus_status", "arguments": {}}),
            &mut changed,
        )?;
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .ok_or_else(|| format!("no text content in {response}"))?;
        status = serde_json::from_str(text)?;
        if status["connected"] == true {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(status["connected"], true, "{status}");
    let stats = gw.stats()?;
    assert_eq!(stats.users, vec![2], "the keyring's user opened the tunnel");

    drop(stdin);
    let _ = child.wait_timeout(Duration::from_millis(500));
    let _ = child.kill();
    let _ = child.wait();
    drop(gw);
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
