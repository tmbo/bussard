//! Mock-gateway tests of the MCP programming tier (issue #118):
//! `knx_plan_device` and `knx_apply_device`.
//!
//! The mock is the writable System B device of `bussard-testkit`
//! ([`MockDevice::system_b`]: load-state machine, `LdCtrlRelSegment`
//! allocation, `PID_TABLE_REFERENCE`, tables in memory segments, written from
//! the KNX spec semantics), hosted on a loopback [`MockGateway`] tunnel. The
//! full MCP server runs in process over a duplex transport against it.
//!
//! **No test here ever reaches a real gateway**: the mock binds `127.0.0.1:0`,
//! and the non-loopback case never opens a bus at all.

use std::net::SocketAddrV4;
use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::consts::OT_ASSOCIATION_TABLE;
use bussard_testkit::{MockDevice, MockGateway};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

const CHANNEL: u8 = 0x55;

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

/// A System B device carrying the tables the model will diff against: GAs
/// 1/2/0, 1/2/1 and 4/2/12, and associations (1,20), (2,21), (3,59). Object 59
/// → 4/2/12 is the ghost the model drops; object 22 → 1/2/2 is what it adds.
/// With `nak_assoc_writes`, every memory write into the association segment is
/// NAKed.
fn system_b_device(nak_assoc_writes: bool) -> anyhow::Result<MockDevice> {
    let dev = MockDevice::system_b(device_ia()?)
        .with_table(1, &address_table(&["1/2/0", "1/2/1", "4/2/12"])?)
        .with_table(2, &association_table(&[(1, 20), (2, 21), (3, 59)]))
        .with_go_count(60);
    Ok(if nak_assoc_writes {
        dev.with_nak_writes_into(OT_ASSOCIATION_TABLE)
    } else {
        dev
    })
}

/// Writes the model: device 1.1.4 with links that add object 22 → 1/2/2 and
/// drop the device's ghost object 59 → 4/2/12.
fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join("1.1.4.yaml"),
        "address: 1.1.4\nname: Jalousie Wohnen\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups:\n  1/2/0:\n    name: Blind move\n  1/2/1:\n    name: Blind stop\n  1/2/2:\n    name: Blind position\n",
    )?;
    std::fs::write(
        dir.join("links.yaml"),
        "links:\n  1.1.4:\n  - object: 20\n    send: 1/2/0\n  - object: 21\n    listen:\n    - 1/2/1\n  - object: 22\n    listen:\n    - 1/2/2\n",
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
    /// Starts the mock device and a programming-tier server against it.
    async fn start(plan_ttl: Duration) -> anyhow::Result<Harness> {
        // Keep serving after a DISCONNECT so a second connection finds the
        // same device with the same state.
        let gateway = MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .device(system_b_device(false)?)
            .start()
            .await?;

        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let connection = ConnectionConfig::tunnel(gateway.addr());
        let (client, server_task) = serve(dir.path(), connection.clone(), plan_ttl, true).await?;
        Ok(Harness {
            client,
            server_task,
            gateway,
            dir,
        })
    }

    async fn call(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        call(&self.client, tool, args).await
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

    /// The gateway's bound port.
    fn port(&self) -> u16 {
        self.gateway.port()
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.client.cancel().await?;
        self.server_task.abort();
        drop(self.gateway);
        Ok(())
    }
}

/// Builds the state from a model directory and serves it over a duplex
/// transport, spawning the bus actor only when `with_bus` is set.
async fn serve(
    dir: &Path,
    connection: ConnectionConfig,
    plan_ttl: Duration,
    with_bus: bool,
) -> anyhow::Result<(
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
)> {
    let config = McpConfig {
        dir: dir.to_path_buf(),
        connection: connection.clone(),
        passive: false,
        allow_writes: false,
        no_model_edits: true,
        capture_db: None,
        allow_programming: true,
        allow_remote_gateway: false,
        plan_ttl,
        keyring: None,
    };
    let state = bussard_mcp::build_state(&config)?;
    if with_bus {
        let service = bussard_service::BusService::open(connection, config.write_policy())?;
        if !service.wait_connected(Duration::from_secs(5)).await {
            anyhow::bail!("the mock tunnel did not come up");
        }
        state.bus.wire(service);
    }
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

/// Calls one tool and returns its structured result.
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let Value::Object(map) = args else {
        anyhow::bail!("tool arguments must be an object");
    };
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        client.call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
    )
    .await??;
    res.structured_content
        .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
}

fn digest_of(plan: &Value) -> anyhow::Result<String> {
    plan["plan_digest"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no plan_digest in {plan}"))
}

#[tokio::test]
async fn test_knx_apply_device_round_trip_plans_writes_and_verifies() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false);
    let text = plan["plan"].as_str().unwrap_or_default();
    assert!(
        text.contains("1 addition(s), 1 removal(s), 2 unchanged:"),
        "{text}"
    );
    assert!(text.contains("+ add:    object   22 → 1/2/2"), "{text}");
    assert!(text.contains("- remove: object   59 → 4/2/12"), "{text}");
    assert!(text.contains("load operations"), "{text}");
    let digest = digest_of(&plan)?;
    assert_eq!(digest.len(), 64);
    assert!(plan["planned_at"].is_string());
    assert_eq!(h.writes()?, 0, "planning must not write");

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true);
    let gateway = format!("127.0.0.1:{}", h.port());
    assert_eq!(applied["gateway"], gateway.as_str());
    let backup = applied["backup"].as_str().unwrap_or_default();
    assert!(Path::new(backup).is_file(), "backup {backup} must exist");

    // The device now holds the model's tables: 1/2/0, 1/2/1, 1/2/2 and the
    // associations (1,20), (2,21), (3,22).
    let (addresses, associations) = h.tables()?;
    assert_eq!(addresses, address_table(&["1/2/0", "1/2/1", "1/2/2"])?);
    assert_eq!(
        associations,
        association_table(&[(1, 20), (2, 21), (3, 22)])
    );

    // The audit line: a history snapshot naming the device and the gateway.
    let latest = bussard_model::history::History::open(h.dir.path())
        .latest()?
        .ok_or_else(|| anyhow::anyhow!("no history snapshot recorded"))?;
    assert_eq!(latest.manifest.reason.command, "mcp knx_apply_device");
    assert_eq!(
        latest.manifest.reason.args.first().map(String::as_str),
        Some("1.1.4")
    );
    assert_eq!(latest.manifest.gateway.as_deref(), Some(gateway.as_str()));

    // A digest is single use.
    let again = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(
        again["refused"], true,
        "a spent digest must be refused: {again}"
    );

    // A fresh plan now has nothing to do.
    let replan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    assert!(replan["plan_digest"].is_null());

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_without_fresh_digest_is_refused() -> anyhow::Result<()> {
    // A zero lifetime: every plan is already stale when apply looks at it.
    let h = Harness::start(Duration::ZERO).await?;

    let unknown = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": "00".repeat(32)}),
        )
        .await?;
    assert_eq!(unknown["refused"], true, "{unknown}");
    assert!(
        unknown["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no fresh plan"),
        "{unknown}"
    );

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let stale = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(
        stale["refused"], true,
        "an expired plan must be refused: {stale}"
    );
    assert_eq!(h.writes()?, 0, "a refused apply must not write");

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_refuses_when_live_tables_changed() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;

    // Someone (ETS, another tool) rewrites the device's address table between
    // the plan and the apply.
    let addresses = address_table(&["1/2/0", "1/2/1", "5/0/0"])?;
    h.gateway
        .with_device(device_ia()?, |dev| dev.preload_table(1, &addresses))?;

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["refused"], true, "{applied}");
    assert!(
        applied["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("live tables changed"),
        "{applied}"
    );
    assert_eq!(h.writes()?, 0, "a refused apply must not write");

    h.stop().await
}

#[tokio::test]
async fn test_knx_plan_device_refuses_non_loopback_gateway_without_gate() -> anyhow::Result<()> {
    // The environment opt-in would legitimately open the gate; this case is
    // about its absence, so it has nothing to prove when a developer set it.
    if bussard_transport::write_gate::real_gateway_env_opt_in() {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    // TEST-NET-1: never contacted, because no bus actor is spawned.
    let connection = ConnectionConfig::tunnel(SocketAddrV4::new([192, 0, 2, 10].into(), 3671));
    let (client, server_task) =
        serve(dir.path(), connection, Duration::from_secs(600), false).await?;

    for (tool, args) in [
        ("knx_plan_device", json!({"address": "1.1.4"})),
        (
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": "00".repeat(32)}),
        ),
    ] {
        let res = call(&client, tool, args).await?;
        assert_eq!(res["refused"], true, "{tool}: {res}");
        let reason = res["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("refusing to write to non-loopback gateway 192.0.2.10:3671"),
            "{tool}: {reason}"
        );
    }

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn test_programming_tools_registered_only_with_the_tier() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_model(dir.path())?;
    let connection = ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), 9));
    let (client, server_task) =
        serve(dir.path(), connection, Duration::from_secs(600), false).await?;
    let names: Vec<String> = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for tool in bussard_mcp::tools_program::PROGRAMMING_TOOLS {
        assert!(
            names.iter().any(|n| n == tool),
            "{tool} missing from {names:?}"
        );
    }
    let mut expected = bussard_mcp::tool_names_for(false, false, true, true);
    expected.sort_unstable();
    let mut got: Vec<&str> = names.iter().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, expected);
    assert!(
        !bussard_mcp::tool_names(false, true, false)
            .iter()
            .any(|n| n.starts_with("knx_plan_device") || n.starts_with("knx_apply_device"))
    );
    client.cancel().await?;
    server_task.abort();
    Ok(())
}
