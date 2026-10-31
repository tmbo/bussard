//! Mock-gateway tests of the safety-net tools (issue #717):
//! `knx_backup_device` and `knx_reconstruct_device` in the default tier,
//! `knx_restart_device` and `knx_restore_tables` in the programming tier.
//!
//! The device is the writable System B mock of `bussard-testkit`
//! ([`MockDevice::system_b`]) on a loopback [`MockGateway`]; the full MCP
//! server runs in process over a duplex transport against it.
//!
//! **No test here ever reaches a real gateway**: the mock binds
//! `127.0.0.1:0`.

use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::{MockDevice, MockGateway};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

const CHANNEL: u8 = 0x56;

fn ga(s: &str) -> anyhow::Result<GroupAddress> {
    Ok(s.parse()?)
}

fn device_ia() -> anyhow::Result<IndividualAddress> {
    Ok("1.1.4".parse()?)
}

fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// An address-table image (count word plus GAs).
fn address_table(gas: &[&str]) -> anyhow::Result<Vec<u8>> {
    let mut image = be16(gas.len() as u16);
    for g in gas {
        image.extend_from_slice(&ga(g)?.raw().to_be_bytes());
    }
    Ok(image)
}

/// An association-table image (count word plus `(tsap, asap)` pairs).
fn association_table(pairs: &[(u16, u16)]) -> Vec<u8> {
    let mut image = be16(pairs.len() as u16);
    for (tsap, asap) in pairs {
        image.extend_from_slice(&tsap.to_be_bytes());
        image.extend_from_slice(&asap.to_be_bytes());
    }
    image
}

/// The device: GAs 1/2/0, 1/2/1, 4/2/12 and associations (1,20), (2,21),
/// (3,59). The model drops object 59 -> 4/2/12 and adds object 22 -> 1/2/2.
fn system_b_device() -> anyhow::Result<MockDevice> {
    Ok(MockDevice::system_b(device_ia()?)
        .with_table(1, &address_table(&["1/2/0", "1/2/1", "4/2/12"])?)
        .with_table(2, &association_table(&[(1, 20), (2, 21), (3, 59)]))
        .with_go_count(60))
}

/// The model: device 1.1.4 linked 20 -> 1/2/0, 21 -> 1/2/1, 22 -> 1/2/2.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Jalousie Wohnen\"\n\n[links]\n\
         20.send = \"1/2/0\"\n21.listen = [\"1/2/1\"]\n22.listen = [\"1/2/2\"]\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Blind move\" },\n  \
         { address = \"1/2/1\", name = \"Blind stop\" },\n  \
         { address = \"1/2/2\", name = \"Blind position\" },\n]\n",
    )?;
    Ok(())
}

/// One running server plus its mock line.
struct Harness {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    server_task: tokio::task::JoinHandle<()>,
    gateway: MockGateway,
    dir: tempfile::TempDir,
}

impl Harness {
    /// Starts the mock device and a server against it; `programming` turns
    /// the programming tier on.
    async fn start(programming: bool) -> anyhow::Result<Harness> {
        let gateway = MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .device(system_b_device()?)
            .start()
            .await?;
        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let connection = ConnectionConfig::tunnel(gateway.addr());
        let (client, server_task) = serve(dir.path(), connection, programming).await?;
        Ok(Harness {
            client,
            server_task,
            gateway,
            dir,
        })
    }

    async fn call(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        let Value::Object(map) = args else {
            anyhow::bail!("tool arguments must be an object");
        };
        let res = tokio::time::timeout(
            Duration::from_secs(60),
            self.client
                .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
        )
        .await??;
        res.structured_content
            .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
    }

    /// Calls a job tool and, when it answers `started`, polls
    /// `knx_apply_status` until the job is done; returns the final result.
    async fn call_job(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        let first = self.call(tool, args).await?;
        if first["started"] != true {
            return Ok(first);
        }
        let job = first["job"].as_str().unwrap_or_default().to_string();
        for _ in 0..120 {
            let status = self.call("knx_apply_status", json!({"job": job})).await?;
            if status["done"] == true {
                return Ok(status["result"].clone());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        anyhow::bail!("job {job} did not finish")
    }

    /// The device's `(address table, association table)` as the mock holds them.
    fn tables(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        Ok(self.gateway.with_device(device_ia()?, |dev| {
            (
                dev.table_image(1).unwrap_or_default(),
                dev.table_image(2).unwrap_or_default(),
            )
        })?)
    }

    fn writes(&self) -> anyhow::Result<usize> {
        Ok(self.gateway.with_device(device_ia()?, |dev| dev.writes)?)
    }

    fn restarts(&self) -> anyhow::Result<usize> {
        Ok(self.gateway.with_device(device_ia()?, |dev| dev.restarts)?)
    }

    async fn names(&self) -> anyhow::Result<Vec<String>> {
        Ok(self
            .client
            .list_all_tools()
            .await?
            .into_iter()
            .map(|t| t.name.to_string())
            .collect())
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.client.cancel().await?;
        self.server_task.abort();
        drop(self.gateway);
        Ok(())
    }
}

/// Shrinks the management timeouts and the source-address probe for the
/// mock device on loopback, as the other mock-device tests do.
fn fast_mock_timeouts() {
    // SAFETY: nextest runs each test in its own process, and every test in
    // this binary sets the same values before the server starts; they are
    // read when a management connection or probe is set up.
    unsafe {
        std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
        std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
    }
}

/// Builds the state from a model directory, wires the bus and serves it
/// over a duplex transport.
async fn serve(
    dir: &Path,
    connection: ConnectionConfig,
    programming: bool,
) -> anyhow::Result<(
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
)> {
    fast_mock_timeouts();
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: connection.clone(),
        passive: false,
        allow_writes: false,
        no_model_edits: true,
        capture_db: None,
        allow_programming: programming,
        allow_remote_gateway: false,
        plan_ttl: bussard_mcp::tools_program::DEFAULT_PLAN_TTL,
        keyring: None,
        allow_home_assistant: false,
    };
    let state = bussard_mcp::build_state(&config)?;
    let service = bussard_service::BusService::open(connection, config.write_policy())?;
    if !service.wait_connected(Duration::from_secs(5)).await {
        anyhow::bail!("the mock tunnel did not come up");
    }
    state.bus.wire(service);
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = bussard_mcp::server::BussardMcp::new(state);
    let server_task = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await?;
    Ok((client, server_task))
}

#[tokio::test]
async fn test_knx_backup_device_writes_one_device_and_never_writes_it() -> anyhow::Result<()> {
    let h = Harness::start(false).await?;
    let names = h.names().await?;
    assert!(names.iter().any(|n| n == "knx_backup_device"), "{names:?}");

    let done = h
        .call("knx_backup_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(done["ok"], true, "backup: {done}");
    assert_eq!(done["totals"]["backed_up"], 1, "{done}");
    assert_eq!(done["devices"][0]["status"], "backed_up", "{done}");
    let out_dir = Path::new(done["out_dir"].as_str().unwrap_or_default()).to_path_buf();
    assert!(out_dir.starts_with(h.dir.path().join("captures").join("backups")));
    assert!(out_dir.join("manifest.json").is_file(), "{done}");
    let file = done["devices"][0]["file"].as_str().unwrap_or_default();
    let backup: Value = serde_json::from_str(&std::fs::read_to_string(out_dir.join(file))?)?;
    assert_eq!(backup["addresses"], json!(["1/2/0", "1/2/1", "4/2/12"]));
    assert_eq!(h.writes()?, 0, "a backup must never write");

    // `all: true` backs up every model device; both at once is refused.
    let all = h.call("knx_backup_device", json!({"all": true})).await?;
    assert_eq!(all["totals"]["backed_up"], 1, "{all}");
    let both = h
        .call(
            "knx_backup_device",
            json!({"address": "1.1.4", "all": true}),
        )
        .await?;
    assert_eq!(both["refused"], true, "{both}");
    assert_eq!(h.writes()?, 0);
    h.stop().await
}

#[tokio::test]
async fn test_knx_reconstruct_device_diffs_the_tables_against_the_model() -> anyhow::Result<()> {
    let h = Harness::start(false).await?;
    let report = h
        .call("knx_reconstruct_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(report["ok"], true, "reconstruct: {report}");
    assert_eq!(report["mask"], "07B0", "{report}");
    assert_eq!(report["addresses"], json!(["1/2/0", "1/2/1", "4/2/12"]));
    let diff = &report["diff"];
    assert_eq!(diff["count"], 2, "{diff}");
    assert_eq!(diff["matches"], 2, "{diff}");
    assert_eq!(diff["touches_protected"], false);
    let sentences: Vec<&str> = diff["sentences"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        sentences
            .iter()
            .any(|s| s.contains("Object 59") && s.contains("4/2/12")),
        "{sentences:?}"
    );
    assert!(
        sentences
            .iter()
            .any(|s| s.contains("Object 22") && s.contains("1/2/2 (Blind position)")),
        "{sentences:?}"
    );
    assert_eq!(diff["changes"][0]["kind"], "on_device_not_in_model");
    assert_eq!(h.writes()?, 0, "a reconstruct must never write");
    h.stop().await
}

#[tokio::test]
async fn test_knx_restart_device_asks_then_restarts() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let question = h
        .call("knx_restart_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(question["ok"], true, "{question}");
    // No product data pinned: the basic form every device accepts.
    assert_eq!(question["form"], "basic", "{question}");
    assert_eq!(h.restarts()?, 0, "the question sends nothing");
    let digest = question["plan_digest"].as_str().unwrap_or_default();

    let done = h
        .call_job(
            "knx_restart_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(done["ok"], true, "restart: {done}");
    assert_eq!(
        done["confirmed"], false,
        "a basic restart is never confirmed"
    );
    assert_eq!(done["mask"], "07B0", "{done}");
    assert_eq!(h.restarts()?, 1);

    // Single use.
    let again = h
        .call(
            "knx_restart_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(again["refused"], true, "{again}");
    assert_eq!(h.restarts()?, 1);
    h.stop().await
}

#[tokio::test]
async fn test_knx_restore_tables_puts_a_backup_back_and_reads_it_back() -> anyhow::Result<()> {
    let h = Harness::start(true).await?;
    let before = h.tables()?;
    let backup = h
        .call("knx_backup_device", json!({"address": "1.1.4"}))
        .await?;
    let name = backup["backup"].as_str().unwrap_or_default().to_string();

    // Change the device: write the model's tables.
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = plan["plan_digest"].as_str().unwrap_or_default();
    let applied = h
        .call_job(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["verified"], true, "apply: {applied}");
    assert_ne!(h.tables()?, before);
    let writes = h.writes()?;

    // The restore plan shows the way back, writes nothing.
    let restore = h
        .call(
            "knx_restore_tables",
            json!({"address": "1.1.4", "backup": name}),
        )
        .await?;
    assert_eq!(restore["ok"], true, "restore plan: {restore}");
    assert_eq!(restore["noop"], false, "{restore}");
    let text = restore["plan"].as_str().unwrap_or_default();
    assert!(text.contains("object   59 → 4/2/12"), "{text}");
    assert!(restore["question"].is_string(), "{restore}");
    assert_eq!(h.writes()?, writes, "planning must not write");
    let digest = restore["plan_digest"].as_str().unwrap_or_default();

    // A digest of this tool is no apply digest.
    let crossed = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(crossed["refused"], true, "{crossed}");

    let restored = h
        .call_job(
            "knx_restore_tables",
            json!({"address": "1.1.4", "backup": name, "plan_digest": digest}),
        )
        .await?;
    assert_eq!(restored["ok"], true, "restore: {restored}");
    assert_eq!(restored["verified"], true, "{restored}");
    assert_eq!(restored["method"], "restore");
    assert_eq!(restored["readback"]["verified"], true, "{restored}");
    assert!(
        Path::new(restored["backup"].as_str().unwrap_or_default()).is_file(),
        "the pre-restore backup: {restored}"
    );
    assert_eq!(h.tables()?, before, "the device holds the backup's tables");

    // The audit line names the restore.
    let latest = bussard_model::history::History::open(h.dir.path())
        .latest()?
        .ok_or_else(|| anyhow::anyhow!("no history snapshot recorded"))?;
    assert_eq!(latest.manifest.reason.command, "mcp knx_restore_tables");

    // Nothing left to restore, and a spent digest is refused.
    let replan = h
        .call(
            "knx_restore_tables",
            json!({"address": "1.1.4", "backup": name}),
        )
        .await?;
    assert_eq!(replan["noop"], true, "{replan}");
    let again = h
        .call(
            "knx_restore_tables",
            json!({"address": "1.1.4", "backup": name, "plan_digest": digest}),
        )
        .await?;
    assert_eq!(again["refused"], true, "{again}");
    h.stop().await
}

#[tokio::test]
async fn test_restart_and_restore_tables_refused_outside_the_programming_tier() -> anyhow::Result<()>
{
    let h = Harness::start(false).await?;
    let names = h.names().await?;
    for tool in ["knx_restart_device", "knx_restore_tables"] {
        assert!(!names.iter().any(|n| n == tool), "{tool} in {names:?}");
        let Value::Object(args) = json!({"address": "1.1.4"}) else {
            anyhow::bail!("not an object");
        };
        let res = h
            .client
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
            .await;
        let refused = match res {
            Err(_) => true,
            Ok(result) => result.is_error == Some(true),
        };
        assert!(
            refused,
            "{tool} must be refused outside the programming tier"
        );
    }
    assert_eq!(h.restarts()?, 0);
    assert_eq!(h.writes()?, 0);
    h.stop().await
}

#[tokio::test]
async fn test_passive_mode_omits_the_device_reads() -> anyhow::Result<()> {
    let mut names = bussard_mcp::tool_names(true, false, true);
    names.sort_unstable();
    for tool in bussard_mcp::tools_device::DEVICE_TOOLS {
        assert!(!names.contains(&tool), "{tool} in passive mode");
        assert!(bussard_mcp::tool_names(false, false, true).contains(&tool));
    }
    Ok(())
}
