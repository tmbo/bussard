//! Guard tests for the tier-aware guidance (issue #272).
//!
//! An assistant repeated what bussard told it: that a human must run `bussard
//! plan` and `bussard apply`, even on a server that pushes links itself. These
//! tests list every tool description through the router, run every model-edit
//! tool in a session at each tier and read the server instructions, and check
//! that no string sends the assistant to the CLI without naming the MCP tool
//! that does the same at the programming tier. The instructions for the read
//! and programming tiers are pinned verbatim.
//!
//! No bus is opened: the connection points at a loopback port and the bus is
//! never wired; every tool exercised here reads or edits files only.

use std::net::SocketAddrV4;
use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

type TestResult = anyhow::Result<()>;

/// One server configuration under test.
#[derive(Debug, Clone, Copy)]
struct Tier {
    /// A label for assertion messages.
    name: &'static str,
    /// `--passive`.
    passive: bool,
    /// `--allow-writes`.
    writes: bool,
    /// `--allow-programming`.
    programming: bool,
}

const TIERS: [Tier; 5] = [
    Tier {
        name: "passive",
        passive: true,
        writes: false,
        programming: false,
    },
    Tier {
        name: "read",
        passive: false,
        writes: false,
        programming: false,
    },
    Tier {
        name: "write",
        passive: false,
        writes: true,
        programming: false,
    },
    Tier {
        name: "programming",
        passive: false,
        writes: false,
        programming: true,
    },
    Tier {
        name: "write+programming",
        passive: false,
        writes: true,
        programming: true,
    },
];

const LOCK: &str = r#"version = 2

[[device]]
address = "1.1.47"
product = "230021SU"
application = "M-0004_A-20DE-22-C7D8-O000A"
mask = "07B0"
channels = [
  { key = "a-1", id = "MD-3_M-18_MI-1_CH-25", number = 1, text = "Jalousie 1", base = 2915 },
]
objects = [
  { number = 138, key = "in-betrieb", text = "Allgemein", function = "In Betrieb", dpt = "1.002", flags = "CRT" },
  { number = 144, key = "langzeitbetrieb", channel = "a-1", text = "Jalousie 1", function = "Langzeitbetrieb", dpt = "1.008", flags = "CWU" },
]
parameters = [
  { key = "fahrzeit", channel = "a-1", ref = "MD-3_M-18_MI-1_P-15_R-15", param = "MD-3_P-15" },
]
"#;

const DEVICE: &str = r#"address = "1.1.47"
name = "Jalousieaktor Kind 2"
product = "230021SU"

[links]
in-betrieb.send = "4/1/2"

[channel.a-1]
name = "Fenster Süd"
"#;

const PRODUCT: &str = r#"identity:
  id: M-0004_A-20DE-22-C7D8-O000A
parameters:
  - id: M-0004_A-20DE-22-C7D8-O000A_MD-3_P-15
    text: Fahrzeit
    type: !int
      min: 1
      max: 600
    default: "60"
"#;

/// Writes a model with one keyed device and its product model.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::create_dir_all(dir.join(".bussard/models"))?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"3/0/1\", name = \"Central down\", dpt = \"1.008\" },\n  \
         { address = \"4/1/2\", name = \"In Betrieb\", dpt = \"1.002\" },\n]\n",
    )?;
    std::fs::write(dir.join("devices").join("1.1.47.toml"), DEVICE)?;
    std::fs::write(dir.join("bussard.lock"), LOCK)?;
    std::fs::write(
        dir.join(".bussard/models/M-0004_A-20DE-22-C7D8-O000A.yaml"),
        PRODUCT,
    )?;
    Ok(())
}

/// Serves the model directory at `tier` over a duplex transport. The bus is
/// never wired, and the connection is a loopback port nothing listens on.
async fn serve(
    dir: &Path,
    tier: Tier,
) -> anyhow::Result<(
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
)> {
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), 9)),
        passive: tier.passive,
        allow_writes: tier.writes,
        no_model_edits: false,
        capture_db: None,
        allow_programming: tier.programming,
        allow_remote_gateway: false,
        plan_ttl: Duration::from_secs(600),
        keyring: None,
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

/// Calls one tool and returns its structured content.
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

/// The guard: no string says a human runs something, and a string naming
/// `bussard plan` or `bussard apply` also names the MCP tool that pushes at
/// the programming tier.
fn assert_guided(label: &str, text: &str) {
    assert!(
        !text.to_lowercase().contains("human runs"),
        "{label} says a human runs something: {text}"
    );
    if text.contains("bussard plan") || text.contains("bussard apply") {
        assert!(
            text.contains("knx_plan_device") || text.contains("knx_apply_device"),
            "{label} names the CLI push without the MCP tool: {text}"
        );
    }
}

/// The server instructions the client received at `tier`.
fn instructions(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
) -> anyhow::Result<String> {
    client
        .peer_info()
        .and_then(|info| info.instructions.clone())
        .ok_or_else(|| anyhow::anyhow!("the server sent no instructions"))
}

#[tokio::test]
async fn test_guidance_every_description_next_step_and_instruction_names_the_mcp_push() -> TestResult
{
    for tier in TIERS {
        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let (client, task) = serve(dir.path(), tier).await?;

        assert_guided(
            &format!("{} instructions", tier.name),
            &instructions(&client)?,
        );
        for tool in client.list_all_tools().await? {
            let description = tool.description.as_deref().unwrap_or_default();
            assert_guided(&format!("{} {}", tier.name, tool.name), description);
        }

        let edits: [(&'static str, Value); 6] = [
            (
                "knx_set_group",
                json!({"ga": "3/0/1", "name": "Central down all"}),
            ),
            (
                "knx_add_link",
                json!({"address": "1.1.47", "com_object": 144, "ga": "3/0/1", "role": "listen"}),
            ),
            (
                "knx_remove_link",
                json!({"address": "1.1.47", "com_object": 144, "ga": "3/0/1", "role": "listen"}),
            ),
            (
                "knx_set_device",
                json!({"address": "1.1.47", "name": "Jalousieaktor Kinderzimmer"}),
            ),
            (
                "knx_set_parameter",
                json!({"address": "1.1.47", "parameter": "fahrzeit", "channel": "a-1", "value": "90"}),
            ),
            ("knx_undo", json!({})),
        ];
        for (tool, args) in edits {
            let res = call(&client, tool, args).await?;
            assert_eq!(res["ok"], true, "{} {tool}: {res}", tier.name);
            let next = res["next_step"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("{} {tool} has no next_step: {res}", tier.name))?;
            assert_guided(&format!("{} {tool} next_step", tier.name), next);
            match tool {
                "knx_set_group" | "knx_set_device" => {
                    assert!(next.starts_with("Nothing to push"), "{tool}: {next}");
                }
                "knx_add_link" | "knx_remove_link" if tier.programming => {
                    assert!(
                        next.contains("knx_plan_device for 1.1.47"),
                        "{tool}: {next}"
                    );
                    assert!(!next.contains("bussard plan"), "{tool}: {next}");
                }
                "knx_add_link" | "knx_remove_link" => {
                    assert!(next.contains("--allow-programming"), "{tool}: {next}");
                    assert!(next.contains("`bussard plan 1.1.47`"), "{tool}: {next}");
                }
                "knx_set_parameter" | "knx_undo" => {
                    assert!(next.contains("1.1.47"), "{tool}: {next}");
                    assert!(next.contains("knx_apply_device"), "{tool}: {next}");
                    // Parameters are pushed over MCP (issue #274): with the
                    // programming tier, no CLI step is named.
                    if tier.programming {
                        assert!(
                            next.contains("knx_plan_device for 1.1.47"),
                            "{tool}: {next}"
                        );
                        assert!(!next.contains("bussard apply"), "{tool}: {next}");
                    }
                }
                _ => {}
            }
        }

        client.cancel().await?;
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_project_summary_reports_the_server_tiers() -> TestResult {
    for tier in TIERS {
        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let (client, task) = serve(dir.path(), tier).await?;
        let summary = call(&client, "knx_project_summary", json!({})).await?;
        let server = &summary["server"];
        assert_eq!(server["passive"], tier.passive, "{}: {summary}", tier.name);
        assert_eq!(server["writes"], tier.writes, "{}: {summary}", tier.name);
        assert_eq!(
            server["programming"], tier.programming,
            "{}: {summary}",
            tier.name
        );
        let tiers: Vec<&str> = server["tiers"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("no tiers: {summary}"))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let expected = match tier.name {
            "passive" | "read" => tier.name.to_string(),
            other => format!("read+{other}"),
        };
        assert_eq!(tiers.join("+"), expected, "{summary}");
        let capabilities = summary["capabilities"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no capabilities: {summary}"))?;
        assert_guided(&format!("{} capabilities", tier.name), capabilities);
        client.cancel().await?;
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_show_device_says_how_to_change_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let tier = TIERS[3];
    let (client, task) = serve(dir.path(), tier).await?;
    let view = call(
        &client,
        "knx_show_device",
        json!({"address": "1.1.47", "channel": "a-1"}),
    )
    .await?;
    assert_eq!(view["product_model"], true, "{view}");
    let how = view["how_to_change"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no how_to_change: {view}"))?;
    assert!(how.contains("knx_set_parameter"), "{how}");
    assert!(
        how.contains("knx_plan_device then knx_apply_device"),
        "{how}"
    );
    assert_guided("how_to_change", how);

    // Without the product model the parameters are not editable, and the
    // string says what to do about it.
    std::fs::remove_dir_all(dir.path().join(".bussard/models"))?;
    std::fs::write(
        dir.path().join("bussard.lock"),
        LOCK.replace(
            "application = \"M-0004_A-20DE-22-C7D8-O000A\"\n",
            "application = \"M-0004_A-FFFF\"\n",
        ),
    )?;
    let view = call(&client, "knx_show_device", json!({"address": "1.1.47"})).await?;
    assert_eq!(view["product_model"], false, "{view}");
    let how = view["how_to_change"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no how_to_change: {view}"))?;
    assert!(how.contains("not editable yet"), "{how}");
    assert!(how.contains("import-product"), "{how}");
    assert_guided("how_to_change without a product model", how);

    client.cancel().await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn test_instructions_read_and_programming_tiers_snapshot() -> TestResult {
    for (tier, expected) in [
        (TIERS[3], PROGRAMMING_INSTRUCTIONS),
        (TIERS[1], READ_INSTRUCTIONS),
    ] {
        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let (client, task) = serve(dir.path(), tier).await?;
        let got = instructions(&client)?;
        if got != expected {
            println!("{} => {got}", tier.name);
        }
        assert_eq!(got, expected, "{}", tier.name);
        client.cancel().await?;
        task.abort();
    }
    Ok(())
}

/// The instructions at the default (read) tier.
const READ_INSTRUCTIONS: &str = "bussard: KNX as code over MCP. The installation lives as TOML files (groups.toml, \
    devices/*.toml, bussard.lock); this server reads and edits them and works with the live \
    bus. Active tiers: read. Start with knx_project_summary (its `server` and `capabilities` \
    fields say what this server may do), then knx_model_lookup, knx_get_group, \
    knx_get_device and knx_show_device to explore, and knx_validate and knx_audit to check \
    the model. Observe with knx_recent_telegrams and knx_wait_for_telegram (the latter \
    enables 'press the button now' debugging); knx_read_group reads a value and \
    knx_describe_device introspects a device's interface objects over the bus. Change the \
    model with the edit tools, never by writing files: knx_set_group, knx_add_link, \
    knx_remove_link, knx_set_device, knx_set_parameter and knx_undo. Parameters are edited \
    with knx_set_parameter using the keys knx_show_device lists (the device needs its \
    product model). Every edit snapshots the files first and returns the change as \
    sentences: quote them to the human, and follow the result's next_step. Group writes are \
    off: restart with --allow-writes for knx_write_group. This server runs without \
    --allow-programming, so edits stay in the files. Restarted with that flag, \
    knx_plan_device and knx_apply_device push a device's links and parameter values; without \
    it, the push is `bussard plan <ia>` and `bussard apply <ia>` at the CLI. Still needs the \
    CLI: `bussard \
    flash` to load a new application program, `bussard adopt`, `bussard replace` and \
    `bussard commission`. Still needs ETS: the Secure activation of a fresh device, and any \
    setting the device's product model does not expose.";

/// The instructions with `--allow-programming`.
const PROGRAMMING_INSTRUCTIONS: &str = "bussard: KNX as code over MCP. The installation lives as TOML files (groups.toml, \
    devices/*.toml, bussard.lock); this server reads and edits them and works with the live \
    bus. Active tiers: read, programming. Start with knx_project_summary (its `server` and \
    `capabilities` fields say what this server may do), then knx_model_lookup, \
    knx_get_group, knx_get_device and knx_show_device to explore, and knx_validate and \
    knx_audit to check the model. Observe with knx_recent_telegrams and \
    knx_wait_for_telegram (the latter enables 'press the button now' debugging); \
    knx_read_group reads a value and knx_describe_device introspects a device's interface \
    objects over the bus. Change the model with the edit tools, never by writing files: \
    knx_set_group, knx_add_link, knx_remove_link, knx_set_device, knx_set_parameter and \
    knx_undo. Parameters are edited with knx_set_parameter using the keys knx_show_device \
    lists (the device needs its product model). Every edit snapshots the files first and \
    returns the change as sentences: quote them to the human, and follow the result's \
    next_step. Group writes are off: restart with --allow-writes for knx_write_group. Push a \
    device with knx_plan_device, show the plan to the human in full, and call \
    knx_apply_device only after an explicit yes in this conversation. It writes the device's \
    links (group-address and association tables) and the parameter values that differ from \
    the model (one plan sentence each), over KNX Data Secure when the server's keyring lists \
    the device. A plan without the device's product data writes the links only and says \
    why. Still needs the CLI: `bussard flash` to load a new \
    application program, `bussard adopt`, `bussard replace` and `bussard commission`. Still \
    needs ETS: the Secure activation of a fresh device, and any setting the device's product \
    model does not expose.";
