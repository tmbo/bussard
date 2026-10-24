//! What a device can do, over MCP (issue #298): `knx_show_device` groups an
//! application without channels of its own by ETS parameter page and marks
//! the inactive ones, and `knx_model_lookup` finds a function on an inactive
//! page through the parameter and choice texts of the product model.
//!
//! The product model is the importer's output for the fabricated System 7
//! application in `crates/bussard-prod/tests/fixtures/blocks_app.xml`.
//! No bus is opened: the connection points at a loopback port nothing
//! listens on, and these tools read files only.

use std::net::SocketAddrV4;
use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type TestResult = anyhow::Result<()>;

const APP: &str = "M-00FA_A-0298-10-0000";

const PRODUCT: &str = include_str!("../../bussard-model/tests/fixtures/blocks_app.yaml");

const LOCK: &str = r#"version = 3

[[device]]
address = "1.1.30"
product = "WS-298"
application = "M-00FA_A-0298-10-0000"
mask = "0701"
channels = [
  { key = "generic-0", id = "CH-0", number = 0 },
]
objects = [
  { number = 0, key = "brightness", channel = "generic-0", text = "Brightness", function = "Physical value", dpt = "9.004", flags = "CRT", ref = "O-0_R-0" },
]
parameters = [
  { key = "universal-channel-a-enable", channel = "generic-0", ref = "P-1_R-1", param = "P-1" },
  { key = "universal-channel-b-enable", channel = "generic-0", ref = "P-2_R-2", param = "P-2" },
  { key = "channel-function", channel = "generic-0", ref = "P-11_R-11", param = "P-11" },
]
"#;

const DEVICE: &str = r#"address = "1.1.30"
name = "Weather station"
product = "WS-298"

[channel.generic-0]
universal-channel-a-enable = "yes"
channel-function = "Temperature sensor"
brightness.send = "4/1/5"
"#;

fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join(".bussard/models"))?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"4/1/5\", name = \"Brightness\", dpt = \"9.004\" },\n]\n",
    )?;
    std::fs::write(dir.join("devices/1.1.30.toml"), DEVICE)?;
    std::fs::write(dir.join("bussard.lock"), LOCK)?;
    std::fs::write(dir.join(format!(".bussard/models/{APP}.yaml")), PRODUCT)?;
    Ok(())
}

async fn serve(
    dir: &Path,
) -> anyhow::Result<(
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
)> {
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), 9)),
        passive: false,
        allow_writes: false,
        no_model_edits: false,
        capture_db: None,
        allow_programming: false,
        allow_remote_gateway: false,
        plan_ttl: Duration::from_secs(600),
        keyring: None,
        allow_home_assistant: false,
    };
    let state = bussard_mcp::build_state(&config)?;
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state);
    let task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, task))
}

async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    args: Value,
) -> anyhow::Result<Value> {
    let mut params = CallToolRequestParams::new(name);
    if let Some(map) = args.as_object() {
        params = params.with_arguments(map.clone());
    }
    client
        .call_tool(params)
        .await?
        .structured_content
        .ok_or_else(|| anyhow::anyhow!("{name} returned no structured content"))
}

#[tokio::test]
async fn test_show_device_lists_pages_and_marks_the_inactive_ones() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let (client, task) = serve(dir.path()).await?;

    let view = call(&client, "knx_show_device", json!({"address": "1.1.30"})).await?;
    let blocks = view["blocks"].as_array().cloned().unwrap_or_default();
    let rows: Vec<(String, bool)> = blocks
        .iter()
        .map(|b| {
            (
                b["handle"].as_str().unwrap_or_default().to_string(),
                b["active"].as_bool().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("general".to_string(), true),
            ("universal-channel-a-function".to_string(), true),
            ("universal-channel-b-function".to_string(), false),
            ("universal-channel-c-function".to_string(), false),
        ],
        "{view}"
    );
    let b = &blocks[2]["inactive"];
    assert_eq!(
        b["enable"][0]["key"], "universal-channel-b-enable",
        "{view}"
    );
    assert_eq!(b["enable"][0]["set_to"], "yes", "{view}");
    assert_eq!(b["would_show"][0]["number"], 2, "{view}");
    assert!(
        b["needs"]
            .as_str()
            .is_some_and(|n| n.contains("bussard flash 1.1.30")),
        "{view}"
    );
    assert!(
        view["summary"]
            .as_str()
            .is_some_and(|s| s.starts_with("2 of 4 pages inactive")),
        "{view}"
    );

    // A page handle selects the page; an inactive one lists what it would
    // show.
    let page = call(
        &client,
        "knx_show_device",
        json!({"address": "1.1.30", "channel": "universal-channel-b-function"}),
    )
    .await?;
    assert_eq!(
        page["scope"]["block"], "universal-channel-b-function",
        "{page}"
    );
    assert_eq!(
        page["scope"]["parameters"][0]["key"], "channel-function",
        "{page}"
    );
    assert_eq!(page["scope"]["objects"][0]["number"], 2, "{page}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_model_lookup_finds_a_function_on_an_inactive_page() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let (client, task) = serve(dir.path()).await?;

    let found = call(
        &client,
        "knx_model_lookup",
        json!({"query": "Brightness sensor"}),
    )
    .await?;
    let caps = found["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let got: Vec<(String, String)> = caps
        .iter()
        .map(|c| {
            (
                c["block_or_channel"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                c["status"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "Universal channel B: function".to_string(),
                "could provide".to_string()
            ),
            (
                "Universal channel C: function".to_string(),
                "could provide".to_string()
            ),
            (
                "Universal channel A: function".to_string(),
                "could provide".to_string()
            ),
        ],
        "{found}"
    );
    let b = &caps[0];
    assert_eq!(b["device_ia"], "1.1.30", "{found}");
    assert_eq!(b["parameter"], "Channel function", "{found}");
    assert_eq!(b["choice"], "Brightness sensor 1 .. 100 000 lx", "{found}");
    assert_eq!(b["active"], false, "{found}");
    assert_eq!(b["handle"], "universal-channel-b-function", "{found}");
    assert_eq!(
        b["enable"][0]["key"], "universal-channel-b-enable",
        "{found}"
    );
    assert!(
        dir.path()
            .join(format!(".bussard/lookup/{APP}.json"))
            .is_file(),
        "the lookup caches the product model"
    );

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// A Meteodata-like application (issue #304): twelve universal channels,
/// each a function page and an objects page behind an enable switch on the
/// "Allgemein" page, C5 .. C12 behind the switches of every channel from C5
/// up to their own (C10 needs C5 .. C10). C1 .. C4 are enabled. Like the
/// real Theben application (`P-7305_R-7305` and `P-7305_R-7330`), each
/// function page holds its brightness threshold twice, in the "Helligkeit"
/// and the "Wind" branch of "Funktion des Kanals" (issue #315). The "Wind"
/// branch shows the wind threshold behind the union member "Wenn
/// Temperatur" = Windsensor, which only its ETS ref value (4) satisfies: the
/// parameter's default is 2 (issue #326, `UP-2248_R-2262`).
const METEO_APP: &str = "M-0004_A-0304-10-0000";
const METEO_CHANNELS: u32 = 12;
const METEO_ON: u32 = 4;

fn meteo_product() -> String {
    let id = |s: String| format!("{METEO_APP}_{s}");
    let enum_yes_no = "  type: !enum\n    values:\n    - value: 0\n      text: nein\n    - value: 1\n      text: ja\n  default: '0'\n";
    let mut objects = String::from("com_objects:\n");
    let mut params = String::from("parameters:\n");
    let mut ref_values = String::from("ref_values:\n");
    let mut blocks = String::from(
        "blocks:\n- id: CH-0\n  kind: channel\n  text: Generic\n  number: 0\n- id: PB-1\n  text: Allgemein\n  parent: CH-0\n  channel: CH-0\n  parameters:\n",
    );
    for k in 1..=METEO_CHANNELS {
        blocks.push_str(&format!("  - P-{k}_R-{k}\n"));
        params.push_str(&format!(
            "- id: {}\n  name: Enable{k}\n  text: Universalkanal C{k} aktivieren\n{enum_yes_no}",
            id(format!("P-{k}"))
        ));
    }
    for k in 1..=METEO_CHANNELS {
        let first = if k >= 5 { 5 } else { k };
        let when: String = (first..=k)
            .map(|j| format!("  - ref: P-{j}_R-{j}\n    test: '1'\n"))
            .collect();
        let (f, s, h) = (1000 + 10 * k, 1001 + 10 * k, 1002 + 10 * k);
        params.push_str(&format!(
            "- id: {}\n  name: Function{k}\n  text: Funktion des Kanals\n  type: !enum\n    values:\n    - value: 1\n      text: Helligkeit\n    - value: 2\n      text: Temperatur\n    - value: 3\n      text: Wind\n  default: '1'\n",
            id(format!("P-{f}"))
        ));
        params.push_str(&format!(
            "- id: {}\n  name: Threshold{k}\n  text: Schwellwert in lx\n  type: !int\n    min: 1\n    max: 1000\n    size: 16\n  default: '100'\n",
            id(format!("P-{s}"))
        ));
        params.push_str(&format!(
            "- id: {}\n  name: Brightness{k}\n  text: Helligkeitsschwelle C{k}\n  type: !int\n    min: 1\n    max: 1000\n    size: 16\n  default: '200'\n",
            id(format!("P-{h}"))
        ));
        for (n, text) in [(2 * k, "Schaltausgang"), (2 * k + 1, "Messwert")] {
            objects.push_str(&format!(
                "  {n}:\n    text: C{k} {text}\n    function_text: Ausgang\n    dpt: '1.001'\n    flags: CRT\n    ref_id: {}\n",
                id(format!("O-{n}_R-{n}"))
            ));
        }
        // "Wenn Temperatur" (a union member in the real application) and
        // the wind threshold behind it.
        let (u, w) = (1006 + 10 * k, 1008 + 10 * k);
        params.push_str(&format!(
            "- id: {}\n  name: Source{k}\n  text: Wenn Temperatur\n  type: !enum\n    values:\n    - value: 1\n      text: Helligkeitssensor\n    - value: 2\n      text: Temperatursensor\n    - value: 4\n      text: Windsensor\n  default: '2'\n",
            id(format!("UP-{u}"))
        ));
        params.push_str(&format!(
            "- id: {}\n  name: Wind{k}\n  text: Windgeschwindigkeit\n  type: !int\n    min: 1\n    max: 40\n    size: 8\n  default: '4'\n",
            id(format!("P-{w}"))
        ));
        ref_values.push_str(&format!("  UP-{u}_R-{v}: '4'\n", v = u + 1));
        let wind = 1005 + 10 * k;
        blocks.push_str(&format!(
            "- id: PB-{k}0\n  text: 'Universalkanal C{k}: Funktion'\n  parent: CH-0\n  channel: CH-0\n  when:\n{when}  parameters:\n  - P-{f}_R-{f}\n  - P-{s}_R-{s}\n  - P-{h}_R-{h}\n  - P-{h}_R-{wind}\n  - UP-{u}_R-{v}\n  - P-{w}_R-{w}\n  parameter_when:\n    P-{h}_R-{h}:\n    - ref: P-{f}_R-{f}\n      test: '1'\n    P-{h}_R-{wind}:\n    - ref: P-{f}_R-{f}\n      test: '3'\n    UP-{u}_R-{v}:\n    - ref: P-{f}_R-{f}\n      test: '3'\n    P-{w}_R-{w}:\n    - ref: P-{f}_R-{f}\n      test: '3'\n    - ref: UP-{u}_R-{v}\n      test: '4'\n  objects:\n  - O-{n}_R-{n}\n",
            n = 2 * k,
            v = u + 1
        ));
        blocks.push_str(&format!(
            "- id: PB-{k}1\n  text: Objekte zu C{k}\n  parent: CH-0\n  channel: CH-0\n  when:\n{when}  objects:\n  - O-{n}_R-{n}\n",
            n = 2 * k + 1
        ));
    }
    let format = bussard_model::param_model::MODEL_FORMAT;
    format!(
        "model_format: {format}\nidentity:\n  id: {METEO_APP}\n  name: meteo test app\n  application_number: 304\n  application_version: 16\n  mask_version: '0701'\n  load_procedure_style: ProductProcedure\n  schema_version: '23'\n{objects}{params}load_procedure:\n- connect\n- restart\n- disconnect\n{blocks}{ref_values}"
    )
}

fn write_meteo(dir: &Path) -> anyhow::Result<()> {
    let mut objects = String::new();
    let mut params = String::new();
    let mut file = String::from(
        "address = \"1.1.202\"\nname = \"Meteodata\"\nproduct = \"MD-304\"\n\n[channel.generic-0]\n",
    );
    for k in 1..=METEO_CHANNELS {
        params.push_str(&format!(
            "  {{ key = \"universalkanal-c{k}-aktivieren\", channel = \"generic-0\", ref = \"P-{k}_R-{k}\", param = \"P-{k}\" }},\n"
        ));
    }
    for k in 1..=METEO_ON {
        file.push_str(&format!("universalkanal-c{k}-aktivieren = \"ja\"\n"));
        let (f, s, h) = (1000 + 10 * k, 1001 + 10 * k, 1002 + 10 * k);
        let page = format!("universalkanal-c{k}-funktion");
        params.push_str(&format!(
            "  {{ key = \"{page}.funktion-des-kanals\", channel = \"generic-0\", ref = \"P-{f}_R-{f}\", param = \"P-{f}\" }},\n  {{ key = \"{page}.schwellwert-in-lx\", channel = \"generic-0\", ref = \"P-{s}_R-{s}\", param = \"P-{s}\" }},\n  {{ key = \"helligkeitsschwelle-c{k}\", channel = \"generic-0\", ref = \"P-{h}_R-{h}\", param = \"P-{h}\" }},\n"
        ));
        for n in [2 * k, 2 * k + 1] {
            objects.push_str(&format!(
                "  {{ number = {n}, key = \"o{n}\", channel = \"generic-0\", text = \"C{k}\", function = \"Ausgang\", dpt = \"1.001\", flags = \"CRT\", ref = \"O-{n}_R-{n}\" }},\n"
            ));
        }
    }
    let lock = format!(
        "version = 3\n\n[[device]]\naddress = \"1.1.202\"\nproduct = \"MD-304\"\napplication = \"{METEO_APP}\"\nmask = \"0701\"\nchannels = [\n  {{ key = \"generic-0\", id = \"CH-0\", number = 0 }},\n]\nobjects = [\n{objects}]\nparameters = [\n{params}]\n"
    );
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join(".bussard/models"))?;
    std::fs::write(dir.join("groups.toml"), "groups = []\n")?;
    std::fs::write(dir.join("devices/1.1.202.toml"), file)?;
    std::fs::write(dir.join("bussard.lock"), lock)?;
    std::fs::write(
        dir.join(format!(".bussard/models/{METEO_APP}.yaml")),
        meteo_product(),
    )?;
    Ok(())
}

#[tokio::test]
async fn test_show_device_scoped_on_a_meteodata_like_model_stays_small() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    let (client, task) = serve(dir.path()).await?;

    let full = call(&client, "knx_show_device", json!({"address": "1.1.202"})).await?;
    let blocks = full["blocks"].as_array().cloned().unwrap_or_default();
    let c10 = blocks
        .iter()
        .find(|b| b["handle"] == "universalkanal-c10-funktion")
        .ok_or_else(|| anyhow::anyhow!("no C10 page: {full}"))?;
    // C10's chain names only its own switch; C5 .. C9 are `also_needs`.
    let enable = c10["inactive"]["enable"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(enable.len(), 1, "{c10}");
    assert_eq!(enable[0]["reference"], "P-10_R-10", "{c10}");
    let also: Vec<&str> = c10["inactive"]["also_needs"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(
        also,
        (5..=9)
            .map(|k| format!("universalkanal-c{k}-funktion"))
            .collect::<Vec<_>>(),
        "{c10}"
    );
    assert!(full["how_to_change"].is_string(), "{full}");

    let scoped = call(
        &client,
        "knx_show_device",
        json!({"address": "1.1.202", "channel": "universalkanal-c4-funktion"}),
    )
    .await?;
    let size = serde_json::to_string(&scoped)?.len();
    assert!(size < 8 * 1024, "scoped view is {size} bytes: {scoped}");
    assert_eq!(scoped["scope"]["block"], "universalkanal-c4-funktion");
    assert!(scoped.get("how_to_change").is_none(), "{scoped}");
    assert!(scoped.get("inactive_pages").is_none(), "{scoped}");
    let lines = scoped["blocks"].as_array().cloned().unwrap_or_default();
    assert!(
        lines.iter().all(Value::is_string) && lines.len() == blocks.len(),
        "{scoped}"
    );
    assert!(
        lines.iter().any(|l| l.as_str().is_some_and(|l| l
            .starts_with("universalkanal-c12-funktion")
            && l.contains("inactive"))),
        "{scoped}"
    );

    // Counts are pluralised: "Objekte zu C4" shows one object.
    assert!(
        lines.iter().any(|l| l
            .as_str()
            .is_some_and(|l| l.starts_with("objekte-zu-c4") && l.ends_with(", 1 object"))),
        "{scoped}"
    );
    assert!(
        !lines.iter().any(|l| l
            .as_str()
            .is_some_and(|l| l.contains(" 1 objects") || l.contains(" 1 parameters"))),
        "{scoped}"
    );

    // `inactive: true` adds the enable detail of the inactive pages.
    let detail = call(
        &client,
        "knx_show_device",
        json!({"address": "1.1.202", "channel": "objekte-zu-c4", "inactive": true}),
    )
    .await?;
    let pages = detail["inactive_pages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(pages.len(), 8, "{detail}");
    assert!(
        pages.iter().all(|p| p["inactive"]["enable"].is_array()),
        "{detail}"
    );

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_set_parameter_takes_every_key_shape_and_page_scope() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    let (client, task) = serve(dir.path()).await?;
    let page = "universalkanal-c4-funktion";
    let file = dir.path().join("devices/1.1.202.toml");

    for (args, value) in [
        (
            json!({"parameter": "helligkeitsschwelle-c4", "channel": page}),
            "301",
        ),
        (
            json!({"parameter": format!("{page}.helligkeitsschwelle-c4")}),
            "302",
        ),
        (
            json!({"parameter": "helligkeitsschwelle-c4@P-1042_R-1042"}),
            "303",
        ),
        (json!({"parameter": "P-1042_R-1042"}), "304"),
        (
            json!({"parameter": "funktion-des-kanals", "channel": page}),
            "Wind",
        ),
    ] {
        let mut args = args;
        args["address"] = json!("1.1.202");
        args["value"] = json!(value);
        let mut params = CallToolRequestParams::new("knx_set_parameter");
        if let Some(map) = args.as_object() {
            params = params.with_arguments(map.clone());
        }
        let result = client.call_tool(params).await?;
        let body = result.structured_content.clone().unwrap_or_default();
        assert_ne!(body["refused"], true, "{args}: {body}");
        let text = std::fs::read_to_string(&file)?;
        let expect = if value == "Wind" {
            "\"Wind\"".to_string()
        } else {
            value.to_string()
        };
        assert!(text.contains(&expect), "{args}: {text}");
    }

    // A misspelling names the closest keys with their page.
    let mut params = CallToolRequestParams::new("knx_set_parameter");
    if let Some(map) =
        json!({"address": "1.1.202", "parameter": "helligkeitschwelle-c4", "value": "1"})
            .as_object()
    {
        params = params.with_arguments(map.clone());
    }
    let body = client
        .call_tool(params)
        .await?
        .structured_content
        .unwrap_or_default();
    assert_eq!(body["refused"], true, "{body}");
    assert!(
        body["reason"].as_str().is_some_and(
            |r| r.contains("Closest: `helligkeitsschwelle-c4` on universalkanal-c4-funktion")
        ),
        "{body}"
    );

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// One parameter row `knx_show_device` prints: page handle, key, reference.
type Printed = (String, String, String);

/// Every parameter row the scoped views of `ia`'s pages print.
fn printed_keys(dir: &Path, ia: &str) -> anyhow::Result<Vec<Printed>> {
    let ia: bussard_model::IndividualAddress = ia.parse()?;
    let model = bussard_model::Model::load(dir)?;
    let products = bussard_model::ProductModels::load(dir);
    let view = bussard_model::device_view::device_view(&model, &products, ia, None)?;
    let mut out = Vec::new();
    for row in &view.blocks {
        let scoped =
            bussard_model::device_view::device_view(&model, &products, ia, Some(&row.handle))?;
        for p in scoped.scope.map(|s| s.parameters).unwrap_or_default() {
            out.push((row.handle.clone(), p.key, p.reference));
        }
    }
    Ok(out)
}

/// Asserts that each of `rows` resolves to its reference on `ia` in every
/// key shape: `page.key`, `key` in `channel: page`, `key@reference`, the
/// bare reference, and the bare key (or a refusal naming the page-qualified
/// keys when it repeats). With `pages: false` the page-qualified shapes are
/// skipped (for rows of a page the view no longer lists).
fn assert_resolves(dir: &Path, ia: &str, rows: &[Printed], pages: bool) -> anyhow::Result<()> {
    use bussard_mcp::param_keys::{KeyContext, resolve_parameter_key};
    let ia: bussard_model::IndividualAddress = ia.parse()?;
    let model = bussard_model::Model::load(dir)?;
    let products = bussard_model::ProductModels::load(dir);
    let ctx = KeyContext::new(&model, &products, ia);
    let device = &model
        .devices
        .get(&ia)
        .ok_or_else(|| anyhow::anyhow!("no device {ia}"))?
        .device;
    for (page, key, reference) in rows {
        let with_ref = if key.contains('@') {
            key.clone()
        } else {
            format!("{key}@{reference}")
        };
        let mut shapes = vec![(with_ref, None), (reference.clone(), None)];
        if pages {
            shapes.push((format!("{page}.{key}"), None));
            shapes.push((key.clone(), Some(page.as_str())));
        }
        for (wanted, channel) in shapes {
            let got = resolve_parameter_key(device, &ctx, &wanted, channel)
                .map_err(|e| anyhow::anyhow!("{wanted} in {channel:?}: {e}"))?;
            anyhow::ensure!(
                got.split_once('@').map(|(_, r)| r) == Some(reference.as_str()),
                "{wanted} in {channel:?} resolved to {got}, not {reference}"
            );
        }
        match resolve_parameter_key(device, &ctx, key, None) {
            Ok(got) => anyhow::ensure!(
                got.split_once('@').map(|(_, r)| r) == Some(reference.as_str()),
                "bare {key} resolved to {got}, not {reference}"
            ),
            Err(e) => anyhow::ensure!(
                e.contains("several places") && (!pages || e.contains(&format!("`{page}."))),
                "bare {key} on {page}: {e}"
            ),
        }
    }
    Ok(())
}

/// Sets every enable step of every inactive page of `ia` over MCP, the way
/// an assistant would, until no page has one left.
async fn enable_every_page(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    ia: &str,
) -> anyhow::Result<()> {
    for _ in 0..32 {
        let full = call(client, "knx_show_device", json!({"address": ia})).await?;
        let blocks = full["blocks"].as_array().cloned().unwrap_or_default();
        let Some(step) = blocks
            .iter()
            .filter_map(|b| b["inactive"]["enable"].as_array())
            .flatten()
            .next()
            .cloned()
        else {
            return Ok(());
        };
        let parameter = step["key"]
            .as_str()
            .or_else(|| step["reference"].as_str())
            .ok_or_else(|| anyhow::anyhow!("an enable step without key: {step}"))?;
        let body = call(
            client,
            "knx_set_parameter",
            json!({"address": ia, "parameter": parameter, "value": step["set_to"]}),
        )
        .await?;
        anyhow::ensure!(body["refused"] != true, "{parameter}: {body}");
    }
    anyhow::bail!("pages of {ia} stay inactive")
}

/// Every key the device view prints resolves in every shape, on active and
/// inactive pages, and still after the inactive pages are enabled (the
/// keys of a page the lock did not index at import, issue #310 session).
async fn check_every_printed_key(dir: &Path, ia: &str) -> TestResult {
    let before = printed_keys(dir, ia)?;
    anyhow::ensure!(!before.is_empty(), "no parameters printed");
    assert_resolves(dir, ia, &before, true)?;

    let (client, task) = serve(dir).await?;
    enable_every_page(&client, ia).await?;
    client.cancel().await?;
    task.abort();

    let after = printed_keys(dir, ia)?;
    assert_resolves(dir, ia, &after, true)?;
    // The rows printed while their page was inactive still resolve, under
    // the page handle they were printed with.
    assert_resolves(dir, ia, &before, true)?;
    Ok(())
}

#[tokio::test]
async fn test_every_printed_key_resolves_on_the_blocks_fixture() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    check_every_printed_key(dir.path(), "1.1.30").await
}

#[tokio::test]
async fn test_every_printed_key_resolves_on_a_meteodata_like_model() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    check_every_printed_key(dir.path(), "1.1.202").await
}

/// The 2026-10-23 session: enable a channel, then set the threshold on its
/// page, which the lock did not index, by page-qualified key and by bare
/// reference. The set indexes it, so the file names it like its neighbours
/// and the view lists its value.
#[tokio::test]
async fn test_set_parameter_on_a_page_enabled_since_import() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    let (client, task) = serve(dir.path()).await?;
    let ia = "1.1.202";
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "universalkanal-c5-aktivieren", "value": "ja"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");

    let page = "universalkanal-c5-funktion";
    for (parameter, value) in [
        (format!("{page}.helligkeitsschwelle-c5"), "333"),
        ("P-1052_R-1052".to_string(), "334"),
        ("helligkeitsschwelle-c5".to_string(), "335"),
    ] {
        let body = call(
            &client,
            "knx_set_parameter",
            json!({"address": ia, "parameter": parameter, "value": value}),
        )
        .await?;
        assert_ne!(body["refused"], true, "{parameter}: {body}");
        let text = std::fs::read_to_string(dir.path().join("devices/1.1.202.toml"))?;
        assert!(
            text.contains(&format!("helligkeitsschwelle-c5 = \"{value}\"")),
            "{parameter}: {text}"
        );
    }
    let lock = std::fs::read_to_string(dir.path().join("bussard.lock"))?;
    assert!(
        lock.contains(r#"key = "helligkeitsschwelle-c5", channel = "generic-0", ref = "P-1052_R-1052", param = "P-1052""#),
        "{lock}"
    );
    let shown = call(
        &client,
        "knx_show_device",
        json!({"address": ia, "channel": page}),
    )
    .await?;
    let rows = shown["scope"]["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        rows.iter()
            .any(|r| r["key"] == "helligkeitsschwelle-c5" && r["value"] == "335"),
        "{shown}"
    );

    // A reference the application does not have is named as such.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-7305_R-7305", "value": "1"}),
    )
    .await?;
    assert_eq!(body["refused"], true, "{body}");
    assert!(
        body["reason"].as_str().is_some_and(
            |r| r.contains("no parameter with reference P-7305_R-7305 in its application")
        ),
        "{body}"
    );

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Issue #315: the C4 page holds its threshold in the "Helligkeit" and the
/// "Wind" branch of "Funktion des Kanals". The page-qualified and the bare
/// key name the ref the current function shows; with neither shown, the
/// refusal lists each ref once, by `key@reference` with its condition.
#[tokio::test]
async fn test_set_parameter_prefers_the_ref_the_function_shows() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    let (client, task) = serve(dir.path()).await?;
    let ia = "1.1.202";
    let page = "universalkanal-c4-funktion";
    let qualified = format!("{page}.helligkeitsschwelle-c4");
    let set = |parameter: String, value: &str| json!({"address": ia, "parameter": parameter, "value": value});

    // Helligkeit (the default) shows P-1042_R-1042.
    for (parameter, value) in [
        (qualified.clone(), "401"),
        ("helligkeitsschwelle-c4".to_string(), "402"),
    ] {
        let body = call(&client, "knx_set_parameter", set(parameter.clone(), value)).await?;
        assert_ne!(body["refused"], true, "{parameter}: {body}");
        assert_eq!(
            field_ref(&body),
            Some("P-1042_R-1042"),
            "{parameter}: {body}"
        );
    }

    // Wind shows the other ref.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "funktion-des-kanals", "channel": page, "value": "Wind"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let body = call(&client, "knx_set_parameter", set(qualified.clone(), "403")).await?;
    assert_ne!(body["refused"], true, "{body}");
    assert_eq!(field_ref(&body), Some("P-1042_R-1045"), "{body}");

    // Temperatur shows neither: ambiguous, each ref named once.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "funktion-des-kanals", "channel": page, "value": "Temperatur"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let body = call(&client, "knx_set_parameter", set(qualified.clone(), "404")).await?;
    assert_eq!(body["refused"], true, "{body}");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("several places"), "{reason}");
    for named in [
        "`helligkeitsschwelle-c4@P-1042_R-1042` (Funktion des Kanals = Helligkeit)",
        "`helligkeitsschwelle-c4@P-1042_R-1045` (Funktion des Kanals = Wind)",
    ] {
        assert!(reason.contains(named), "{reason}");
    }
    let keys: Vec<&str> = reason.split('`').skip(1).step_by(2).collect();
    let mut unique = keys.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(keys.len(), unique.len(), "{reason}");
    // The suggested keys resolve; neither ref is shown under Temperatur, so
    // storing a value takes `force` (issue #321).
    let body = call(
        &client,
        "knx_set_parameter",
        set("helligkeitsschwelle-c4@P-1042_R-1045".to_string(), "405"),
    )
    .await?;
    assert_eq!(body["refused"], true, "{body}");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("Funktion des Kanals = Wind; Funktion des Kanals is Temperatur"),
        "{reason}"
    );
    assert!(
        reason.contains("Set Funktion des Kanals = Wind first"),
        "{reason}"
    );
    let mut forced = set("helligkeitsschwelle-c4@P-1042_R-1045".to_string(), "405");
    forced["force"] = json!(true);
    let body = call(&client, "knx_set_parameter", forced).await?;
    assert_ne!(body["refused"], true, "{body}");
    assert_eq!(field_ref(&body), Some("P-1042_R-1045"), "{body}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// The reference in the `field` of a `knx_set_parameter` result's change.
fn field_ref(body: &Value) -> Option<&str> {
    body["detail"]
        .as_array()?
        .iter()
        .find_map(|d| d["field"].as_str())
        .and_then(|f| f.rsplit_once('@'))
        .map(|(_, r)| r)
}

/// The ignored-override lines the plan of `ia` carries (issue #321).
fn ignored_notes(dir: &Path, ia: &str) -> anyhow::Result<Vec<String>> {
    let ia: bussard_model::IndividualAddress = ia.parse()?;
    let model = bussard_model::Model::load(dir)?;
    Ok(bussard_service::params::ignored_override_notes(
        &model, ia, dir,
    ))
}

/// The row of `reference` in `knx_show_device`'s view of `page`.
async fn shown_row(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    ia: &str,
    page: &str,
    reference: &str,
) -> anyhow::Result<Value> {
    let shown = call(
        client,
        "knx_show_device",
        json!({"address": ia, "channel": page}),
    )
    .await?;
    shown["scope"]["parameters"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["reference"] == reference))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no row {reference} on {page}: {shown}"))
}

/// Issue #321: a value set on the "Wind" ref of the C4 threshold while the
/// function is "Helligkeit" would be stored and never written. It is refused
/// with the branch in words and the shown ref named; `force` stores it, the
/// view marks it ignored and the plan lists it; switching the function to
/// "Wind" makes it a live value.
#[tokio::test]
async fn test_set_parameter_refuses_a_ref_the_configuration_does_not_show() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    let (client, task) = serve(dir.path()).await?;
    let ia = "1.1.202";
    let page = "universalkanal-c4-funktion";
    let file = dir.path().join("devices/1.1.202.toml");

    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-1042_R-1045", "value": "500"}),
    )
    .await?;
    assert_eq!(body["refused"], true, "{body}");
    let reason = body["reason"].as_str().unwrap_or_default();
    for part in [
        "`helligkeitsschwelle-c4@P-1042_R-1045` belongs to the branch Funktion des Kanals = \
         Wind; Funktion des Kanals is Helligkeit",
        "never written",
        "The shown parameter is `helligkeitsschwelle-c4` (P-1042_R-1042)",
        "`force: true`",
    ] {
        assert!(reason.contains(part), "{part}: {reason}");
    }
    assert!(!std::fs::read_to_string(&file)?.contains("500"));

    // A bare parameter id and the vendor text name the shown ref.
    for (parameter, value) in [("P-1042", "410"), ("Helligkeitsschwelle C4", "411")] {
        let body = call(
            &client,
            "knx_set_parameter",
            json!({"address": ia, "parameter": parameter, "value": value}),
        )
        .await?;
        assert_ne!(body["refused"], true, "{parameter}: {body}");
        assert_eq!(
            field_ref(&body),
            Some("P-1042_R-1042"),
            "{parameter}: {body}"
        );
    }

    // `force` keeps the old behaviour: stored, marked ignored, listed.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-1042_R-1045", "value": "500", "force": true}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    assert!(std::fs::read_to_string(&file)?.contains("500"));
    let why = "not shown under the current values (needs Funktion des Kanals = Wind)";
    let row = shown_row(&client, ia, page, "P-1042_R-1045").await?;
    assert_eq!(row["value"], "500", "{row}");
    assert_eq!(row["ignored"], why, "{row}");
    let live = shown_row(&client, ia, page, "P-1042_R-1042").await?;
    assert!(live.get("ignored").is_none(), "{live}");
    assert_eq!(
        ignored_notes(dir.path(), ia)?,
        vec![format!(
            "`helligkeitsschwelle-c4@P-1042_R-1045` = 500 ignored: {why}"
        )]
    );

    // Switching the function to Wind shows the ref: the value is live, and
    // the one stored for the Helligkeit ref is now the ignored one.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "funktion-des-kanals", "channel": page, "value": "Wind"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let row = shown_row(&client, ia, page, "P-1042_R-1045").await?;
    assert!(row.get("ignored").is_none(), "{row}");
    assert_eq!(
        ignored_notes(dir.path(), ia)?,
        vec![
            "`helligkeitsschwelle-c4` = 411 ignored: not shown under the current values (needs \
             Funktion des Kanals = Helligkeit)"
                .to_string()
        ]
    );
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-1042_R-1045", "value": "501"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");

    // A ref on a page the configuration does not show names what enables
    // the page.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-1062_R-1062", "value": "600"}),
    )
    .await?;
    assert_eq!(body["refused"], true, "{body}");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("sits on a page"), "{reason}");
    assert!(
        reason.contains("Universalkanal C5 aktivieren = ja and Universalkanal C6 aktivieren = ja"),
        "{reason}"
    );

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Issue #326: the wind threshold sits behind "Funktion des Kanals" = Wind
/// and "Wenn Temperatur" = Windsensor, which only the ETS ref value of the
/// union member satisfies. Once the function is Wind the threshold is shown,
/// so `knx_set_parameter` takes it without "Wenn Temperatur" being set, and
/// the plan calls nothing ignored: what the image builder writes.
#[tokio::test]
async fn test_set_parameter_takes_a_condition_the_ref_value_satisfies() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_meteo(dir.path())?;
    let (client, task) = serve(dir.path()).await?;
    let ia = "1.1.202";
    let page = "universalkanal-c1-funktion";
    let file = dir.path().join("devices/1.1.202.toml");

    // Under "Helligkeit" the refusal names the function only: the union
    // member's ref value already holds.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-1018_R-1018", "value": "8"}),
    )
    .await?;
    assert_eq!(body["refused"], true, "{body}");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(
        reason
            .contains("(Funktion des Kanals is Helligkeit): it needs Funktion des Kanals = Wind. "),
        "{reason}"
    );

    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "funktion-des-kanals", "channel": page, "value": "Wind"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "P-1018_R-1018", "value": "8"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let row = shown_row(&client, ia, page, "P-1018_R-1018").await?;
    assert_eq!(row["value"], "8", "{row}");
    assert!(row.get("ignored").is_none(), "{row}");
    assert!(ignored_notes(dir.path(), ia)?.is_empty());
    assert!(!std::fs::read_to_string(&file)?.contains("wenn-temperatur"));

    // Setting the member itself indexes it in the lock with its ref value
    // as the default, as the facts refresh writes the row.
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "UP-1016_R-1017", "value": "Windsensor"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let lock = std::fs::read_to_string(dir.path().join("bussard.lock"))?;
    let row = lock
        .lines()
        .find(|l| l.contains("ref = \"UP-1016_R-1017\""))
        .unwrap_or_default();
    assert!(row.contains("default = \"4\""), "{row}");

    client.cancel().await?;
    task.abort();
    Ok(())
}

/// Corpus-gated (issue #326): on a copy of the owner's model snapshot
/// (`BUSSARD_METEO_SNAPSHOT`, e.g.
/// `knx/.bussard/history/20261023T190946Z-001`, with the archive at
/// `BUSSARD_METEO_KNXPROD` or `<snapshot>/../../../products/`), the C4
/// brightness threshold `helligkeitsschwelle@P-7305_R-7305` is taken once the
/// function is "Helligkeitssensor": "Wenn Temperatur" = Helligkeitssensor
/// holds through its ref value and is never written to the file.
#[tokio::test]
async fn test_meteodata_snapshot_takes_the_c4_brightness_threshold() -> TestResult {
    let Some(snapshot) = std::env::var_os("BUSSARD_METEO_SNAPSHOT").map(std::path::PathBuf::from)
    else {
        eprintln!("skipping: BUSSARD_METEO_SNAPSHOT is not set");
        return Ok(());
    };
    let archive = std::env::var_os("BUSSARD_METEO_KNXPROD")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| snapshot.join("../../../products/M-0048_A-140C-14-EB70.knxprod"));
    if !snapshot.join("bussard.lock").is_file() || !archive.is_file() {
        eprintln!("skipping: no snapshot or archive at hand");
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    std::fs::create_dir_all(dir.path().join("devices"))?;
    std::fs::create_dir_all(dir.path().join("products"))?;
    for name in ["bussard.lock", "bussard.toml", "groups.toml"] {
        std::fs::copy(snapshot.join(name), dir.path().join(name))?;
    }
    for entry in std::fs::read_dir(snapshot.join("devices"))? {
        let path = entry?.path();
        if let Some(name) = path.file_name() {
            std::fs::copy(&path, dir.path().join("devices").join(name))?;
        }
    }
    std::fs::copy(
        &archive,
        dir.path().join("products/M-0048_A-140C-14-EB70.knxprod"),
    )?;
    let (client, task) = serve(dir.path()).await?;
    let ia = "1.1.202";
    let file = dir.path().join("devices/1.1.202.toml");

    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "funktion-des-kanals",
               "channel": "universalkanal-c4-funktion",
               "value": "Helligkeitssensor 1 .. 100 000 lx"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let body = call(
        &client,
        "knx_set_parameter",
        json!({"address": ia, "parameter": "helligkeitsschwelle@P-7305_R-7305",
               "value": "unter 5 lx"}),
    )
    .await?;
    assert_ne!(body["refused"], true, "{body}");
    let text = std::fs::read_to_string(&file)?;
    assert!(text.contains("unter 5 lx"), "{text}");
    assert!(!text.contains("wenn-temperatur"), "{text}");

    client.cancel().await?;
    task.abort();
    Ok(())
}
