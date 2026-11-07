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
use bussard_mgmt::apci::A_DEVICE_DESCRIPTOR_READ;
use bussard_model::{GroupAddress, IndividualAddress};
use bussard_testkit::consts::{OT_ASSOCIATION_TABLE, TUNNEL_IA_RAW};
use bussard_testkit::{MockDevice, MockGateway};
use bussard_transport::ConnectionConfig;
use bussard_transport::cemi::{Apdu, Destination};
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

/// The individual address the mock gateway assigns the tunnel, which the
/// server speaks from.
fn own_address() -> IndividualAddress {
    IndividualAddress::from_raw(TUNNEL_IA_RAW)
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
    /// Starts the mock device and a programming-tier server against it.
    async fn start(plan_ttl: Duration) -> anyhow::Result<Harness> {
        Harness::start_with(plan_ttl, None).await
    }

    /// [`Harness::start`] with the apply reply wait set (issue #289).
    async fn start_with(
        plan_ttl: Duration,
        reply_wait: Option<Duration>,
    ) -> anyhow::Result<Harness> {
        Harness::start_waits(plan_ttl, reply_wait, None).await
    }

    /// [`Harness::start_with`] with the read wait set too (issue #332).
    async fn start_waits(
        plan_ttl: Duration,
        reply_wait: Option<Duration>,
        read_wait: Option<Duration>,
    ) -> anyhow::Result<Harness> {
        Harness::start_line(plan_ttl, reply_wait, read_wait, Vec::new()).await
    }

    /// [`Harness::start_waits`] with `extra` devices on the line next to
    /// 1.1.4.
    async fn start_line(
        plan_ttl: Duration,
        reply_wait: Option<Duration>,
        read_wait: Option<Duration>,
        extra: Vec<MockDevice>,
    ) -> anyhow::Result<Harness> {
        Harness::start_full(plan_ttl, (reply_wait, read_wait), extra, true).await
    }

    /// [`Harness::start_line`] with the `--no-model-edits` switch chosen.
    async fn start_full(
        plan_ttl: Duration,
        (reply_wait, read_wait): (Option<Duration>, Option<Duration>),
        extra: Vec<MockDevice>,
        no_model_edits: bool,
    ) -> anyhow::Result<Harness> {
        // Keep serving after a DISCONNECT so a second connection finds the
        // same device with the same state.
        let gateway = MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .device(system_b_device(false)?)
            .devices(extra)
            .start()
            .await?;

        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        let connection = ConnectionConfig::tunnel(gateway.addr());
        let (client, server_task) = serve_config(
            dir.path(),
            connection.clone(),
            plan_ttl,
            true,
            (reply_wait, read_wait),
            no_model_edits,
        )
        .await?;
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

    /// How many source-address probes reached the gateway: an
    /// `A_DeviceDescriptor_Read` addressed to the tunnel's own individual
    /// address (issue #341).
    fn probes(&self) -> anyhow::Result<usize> {
        let own = Destination::Individual(own_address());
        Ok(self
            .gateway
            .sent()?
            .iter()
            .filter(|frame| {
                frame.destination == own
                    && matches!(frame.apdu, Apdu::Other { apci, .. } if apci == A_DEVICE_DESCRIPTOR_READ)
            })
            .count())
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

/// Shrinks the management timeouts and the source-address probe for the mock
/// device on loopback, as the CLI mock-device tests do.
fn fast_mock_timeouts() {
    // SAFETY: nextest runs each test in its own process, and every test in
    // this binary sets the same values before the server starts; they are
    // read when a management connection or probe is set up.
    unsafe {
        std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
        std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
    }
}

/// Builds the state from a model directory and serves it over a duplex
/// transport, spawning the bus actor only when `with_bus` is set.
async fn serve(
    dir: &Path,
    connection: ConnectionConfig,
    plan_ttl: Duration,
    with_bus: bool,
    waits: (Option<Duration>, Option<Duration>),
) -> anyhow::Result<(
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tokio::task::JoinHandle<()>,
)> {
    serve_config(dir, connection, plan_ttl, with_bus, waits, true).await
}

/// [`serve`] with the `--no-model-edits` switch chosen.
async fn serve_config(
    dir: &Path,
    connection: ConnectionConfig,
    plan_ttl: Duration,
    with_bus: bool,
    (reply_wait, read_wait): (Option<Duration>, Option<Duration>),
    no_model_edits: bool,
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
        no_model_edits,
        capture_db: None,
        allow_programming: true,
        allow_remote_gateway: false,
        plan_ttl,
        keyring: None,
        allow_home_assistant: false,
        viz_listen: None,
    };
    let state = bussard_mcp::build_state(&config)?;
    if let (Some(wait), Some(tier)) = (reply_wait, state.programming.as_ref()) {
        tier.set_reply_wait(wait);
    }
    if let (Some(wait), Some(tier)) = (read_wait, state.programming.as_ref()) {
        tier.set_read_wait(wait);
    }
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
    let (client, server_task) = serve(
        dir.path(),
        connection,
        Duration::from_secs(600),
        false,
        (None, None),
    )
    .await?;

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
    let (client, server_task) = serve(
        dir.path(),
        connection,
        Duration::from_secs(600),
        false,
        (None, None),
    )
    .await?;
    let names: Vec<String> = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for tool in bussard_mcp::tools_of(bussard_mcp::Tier::Programming) {
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

/// The plan carries the model's sentences and a `state_hash`; an apply whose
/// `plan_hash` does not match a fresh read is refused and writes nothing.
#[tokio::test]
async fn test_knx_apply_device_refuses_a_mismatched_plan_hash() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.contains("+ object 22 now listens on 1/2/2"),
        "{plan}"
    );
    assert!(
        sentences.contains("- object 59 no longer uses 4/2/12"),
        "{plan}"
    );
    let hash = plan["state_hash"].as_str().unwrap_or_default().to_string();
    assert_eq!(hash.len(), 64, "{plan}");
    assert!(
        plan["question"]
            .as_str()
            .is_some_and(|q| q.starts_with("apply these 2 changes to 1.1.4 through")),
        "{plan}"
    );
    let digest = digest_of(&plan)?;
    let refused = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest, "plan_hash": "00".repeat(32)}),
        )
        .await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("plan_hash"),
        "{refused}"
    );
    assert_eq!(h.writes()?, 0, "a refused apply must not write");

    // The matching hash goes through (with a fresh digest: the refusal retired
    // the old one).
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;
    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest, "plan_hash": hash}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    h.stop().await
}

/// A device whose product data is missing (bussard.lock pins an archive that
/// is not in `products/`): the plan refuses the parameter part with the
/// recovery line and still plans the links, and the approved links-only plan
/// applies (issue #274).
#[tokio::test]
async fn test_knx_apply_device_missing_product_data_applies_the_links_only() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;
    // The lock pins an archive that was never stored, and the device file
    // carries a parameter value.
    let sha = "ab".repeat(32);
    std::fs::write(
        h.dir.path().join("bussard.lock"),
        format!(
            "version = 3\n\n[[product]]\nsha256 = \"{sha}\"\nfile = \"products/gone.knxprod\"\n\
             origin = {{ kind = \"index\", order_number = \"TST-1\" }}\napplications = \
             [\"M-00FA_A-0002\"]\norder_numbers = [\"TST-1\"]\n\n[[device]]\naddress = \
             \"1.1.4\"\nproduct = \"TST-1\"\napplication = \"M-00FA_A-0002\"\n\
             product_sha256 = \"{sha}\"\nmask = \"07B0\"\n"
        ),
    )?;
    std::fs::write(
        h.dir.path().join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Jalousie Wohnen\"\nproduct = \"TST-1\"\n\n\
         [parameters]\n\"thr@P-0_R-1\" = \"12\"\n\n[links]\n\
         20.send = \"1/2/0\"\n21.listen = [\"1/2/1\"]\n22.listen = [\"1/2/2\"]\n",
    )?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["noop"], false, "plan: {plan}");
    let skipped = plan["parameters"]["skipped"].as_str().unwrap_or_default();
    assert!(skipped.contains("is missing"), "{plan}");
    assert!(
        skipped.contains("bussard import-product --order-number TST-1"),
        "the recovery line: {plan}"
    );
    assert_eq!(plan["parameters"]["written"], false, "{plan}");
    assert_eq!(plan["writes"]["parameter_octets"], 0, "{plan}");
    let next = plan["next_step"].as_str().unwrap_or_default();
    assert!(next.contains("only the links are written"), "{next}");

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest_of(&plan)?}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    assert_eq!(applied["parameters"]["written"], false, "apply: {applied}");
    let (addresses, associations) = h.tables()?;
    assert_eq!(addresses, address_table(&["1/2/0", "1/2/1", "1/2/2"])?);
    assert_eq!(
        associations,
        association_table(&[(1, 20), (2, 21), (3, 22)])
    );
    h.stop().await
}

/// Polls `knx_apply_status` for `job` until it reports `done`.
async fn poll_until_done(h: &Harness, job: &str) -> anyhow::Result<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let status = h.call("knx_apply_status", json!({"job": job})).await?;
        if status["done"] == true {
            return Ok(status);
        }
        assert_eq!(status["state"], "running", "status: {status}");
        if std::time::Instant::now() > deadline {
            anyhow::bail!("job {job} did not finish: {status}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Issue #289: an apply that outlasts the reply wait answers `started` with a
/// job id once the pre-flight is through; a second apply and a plan are
/// refused with that id while it runs; `knx_apply_status` reports it to
/// completion with the full result, also recorded next to the snapshot.
#[tokio::test]
async fn test_knx_apply_device_slow_write_returns_started_and_completes_under_status()
-> anyhow::Result<()> {
    let h = Harness::start_with(Duration::from_secs(600), Some(Duration::ZERO)).await?;
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;
    // A slow device: every answer comes 80 ms late, so the write takes
    // seconds while the call answers at once.
    h.gateway.with_device(device_ia()?, |dev| {
        dev.response_delay = Some(Duration::from_millis(80));
    })?;

    let started = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(started["started"], true, "apply: {started}");
    assert_eq!(started["done"], false, "apply: {started}");
    assert_eq!(started["address"], "1.1.4");
    assert!(started.get("ok").is_none(), "no outcome yet: {started}");
    let job = started["job"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no job in {started}"))?
        .to_string();
    let next = started["next_step"].as_str().unwrap_or_default();
    assert!(next.contains("knx_apply_status"), "{next}");
    assert!(next.contains(&job), "{next}");
    assert!(
        Path::new(started["backup"].as_str().unwrap_or_default()).is_file(),
        "the backup is written before the call answers: {started}"
    );

    // One apply at a time, and no plan while the bus is the job's.
    let second = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(second["refused"], true, "{second}");
    assert!(
        second["reason"]
            .as_str()
            .is_some_and(|r| r.contains(&job) && r.contains("already running")),
        "{second}"
    );
    let replan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(replan["refused"], true, "{replan}");
    assert!(
        replan["reason"].as_str().is_some_and(|r| r.contains(&job)),
        "{replan}"
    );

    let done = poll_until_done(&h, &job).await?;
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(done["result"]["ok"], true, "{done}");
    assert_eq!(done["result"]["verified"], true, "{done}");
    assert_eq!(done["progress"]["tables"], "verified", "{done}");
    let (addresses, associations) = h.tables()?;
    assert_eq!(addresses, address_table(&["1/2/0", "1/2/1", "1/2/2"])?);
    assert_eq!(
        associations,
        association_table(&[(1, 20), (2, 21), (3, 22)])
    );

    // The record sits next to the audit snapshot.
    let record = done["record"].as_str().unwrap_or_default();
    let latest = bussard_model::history::History::open(h.dir.path())
        .latest()?
        .ok_or_else(|| anyhow::anyhow!("no history snapshot recorded"))?;
    assert_eq!(done["snapshot"], latest.id.as_str(), "{done}");
    assert!(
        record.contains(latest.id.as_str()) && Path::new(record).is_file(),
        "{record}"
    );
    let saved: Value = serde_json::from_slice(&std::fs::read(record)?)?;
    assert_eq!(saved["state"], "done");
    assert_eq!(saved["result"]["verified"], true);

    // The slot is free again: a fresh plan has nothing to do.
    h.gateway.with_device(device_ia()?, |dev| {
        dev.response_delay = None;
    })?;
    let replan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(replan["noop"], true, "replan: {replan}");
    h.stop().await
}

/// The plan with the fields that name the moment it was made removed.
fn timeless(plan: &Value) -> Value {
    let mut plan = plan.clone();
    if let Some(map) = plan.as_object_mut() {
        map.remove("planned_at");
        map.remove("expires_at");
    }
    plan
}

/// The `job` id of a `started` answer.
fn job_of(started: &Value) -> anyhow::Result<String> {
    started["job"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no job in {started}"))
}

/// Issue #332: a plan whose device read outlasts the read wait answers
/// `started` with a plan job; a second plan of the device joins it, an apply
/// is refused naming it, and `knx_apply_status` returns the plan exactly as
/// the synchronous call returned it on the fast device, digest included.
#[tokio::test]
async fn test_knx_plan_device_slow_read_runs_as_a_job_equal_to_the_inline_plan()
-> anyhow::Result<()> {
    let h = Harness::start_waits(
        Duration::from_secs(600),
        None,
        Some(Duration::from_millis(300)),
    )
    .await?;
    // The fast device answers within the read wait: the plan comes inline.
    let inline = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(inline["ok"], true, "inline: {inline}");
    assert!(inline.get("started").is_none(), "inline: {inline}");
    let digest = digest_of(&inline)?;

    // Every answer 80 ms late: the read takes seconds, past the read wait.
    h.gateway.with_device(device_ia()?, |dev| {
        dev.response_delay = Some(Duration::from_millis(80));
    })?;
    let started = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(started["started"], true, "plan: {started}");
    assert_eq!(started["done"], false, "plan: {started}");
    assert_eq!(started["kind"], "plan", "plan: {started}");
    assert!(
        started.get("plan_digest").is_none(),
        "no plan yet: {started}"
    );
    let job = job_of(&started)?;
    assert!(job.starts_with("plan-"), "{job}");
    let next = started["next_step"].as_str().unwrap_or_default();
    assert!(
        next.contains("knx_apply_status") && next.contains(&job),
        "{next}"
    );

    // A second plan of the device joins the running job; an apply waits.
    let joined = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(job_of(&joined)?, job, "joined: {joined}");
    let apply = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(apply["refused"], true, "{apply}");
    assert!(
        apply["reason"]
            .as_str()
            .is_some_and(|r| r.contains(&job) && r.contains("already running")),
        "{apply}"
    );
    assert_eq!(h.writes()?, 0, "a plan job never writes");

    let done = poll_until_done(&h, &job).await?;
    assert_eq!(done["kind"], "plan", "{done}");
    assert_eq!(done["state"], "done", "{done}");
    assert!(
        done["next_step"]
            .as_str()
            .is_some_and(|n| n.contains("result.plan_digest")),
        "{done}"
    );
    let plan = &done["result"];
    assert_eq!(
        digest_of(plan)?,
        digest,
        "same device, same model, same digest"
    );
    assert_eq!(timeless(plan), timeless(&inline));
    // A plan is not an apply.
    let last = h
        .call("knx_last_apply", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(last["found"], false, "{last}");

    // The digest the job produced is good for the apply.
    h.gateway.with_device(device_ia()?, |dev| {
        dev.response_delay = None;
    })?;
    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["verified"], true, "{applied}");
    h.stop().await
}

/// Issue #332: an apply whose pre-flight read outlasts the read wait answers
/// `started` before the backups exist, and completes under
/// `knx_apply_status`; a pre-flight that refuses after that ends the job
/// with `result.refused` and nothing written.
#[tokio::test]
async fn test_knx_apply_device_slow_preflight_answers_started_and_reports_a_late_refusal()
-> anyhow::Result<()> {
    let h = Harness::start_waits(
        Duration::from_secs(600),
        None,
        Some(Duration::from_millis(300)),
    )
    .await?;
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let digest = digest_of(&plan)?;
    h.gateway.with_device(device_ia()?, |dev| {
        dev.response_delay = Some(Duration::from_millis(80));
    })?;

    // The device moved since the plan: the slow pre-flight refuses late.
    let moved = address_table(&["1/2/0", "1/2/1", "5/0/0"])?;
    h.gateway
        .with_device(device_ia()?, |dev| dev.preload_table(1, &moved))?;
    let started = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(started["started"], true, "apply: {started}");
    let job = job_of(&started)?;
    let refused = poll_until_done(&h, &job).await?;
    assert_eq!(refused["result"]["refused"], true, "{refused}");
    assert!(
        refused["result"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("live tables changed")),
        "{refused}"
    );
    assert!(
        refused["next_step"]
            .as_str()
            .is_some_and(|n| n.contains("nothing was written")),
        "{refused}"
    );
    assert_eq!(h.writes()?, 0, "a refused pre-flight must not write");

    // A fresh plan (as a job) and its apply (started in the pre-flight)
    // complete under knx_apply_status.
    let started = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let plan = poll_until_done(&h, &job_of(&started)?).await?;
    let digest = digest_of(&plan["result"])?;
    let started = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(started["started"], true, "apply: {started}");
    let done = poll_until_done(&h, &job_of(&started)?).await?;
    assert_eq!(done["kind"], "apply", "{done}");
    assert_eq!(done["result"]["ok"], true, "{done}");
    assert_eq!(done["result"]["verified"], true, "{done}");
    h.stop().await
}

/// Issue #746: `knx_job_status` reads the same job as `knx_apply_status`, with
/// the same payload plus `question` (`null`: an apply waits on no human), and
/// refuses a job it does not know.
#[tokio::test]
async fn test_knx_job_status_reads_an_apply_job_like_knx_apply_status() -> anyhow::Result<()> {
    let h = Harness::start_with(Duration::from_secs(600), Some(Duration::ZERO)).await?;
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let started = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest_of(&plan)?}),
        )
        .await?;
    assert_eq!(started["started"], true, "apply: {started}");
    let job = started["job"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no job in {started}"))?
        .to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        let status = h.call("knx_job_status", json!({"job": job})).await?;
        assert_eq!(status["job"], job.as_str(), "{status}");
        assert_eq!(status["question"], Value::Null, "{status}");
        assert!(status["step"].is_string(), "{status}");
        if status["done"] == true {
            break status;
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("job {job} did not finish: {status}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status["kind"], "apply", "{status}");
    assert_eq!(status["result"]["verified"], true, "{status}");
    let mut legacy = h.call("knx_apply_status", json!({"job": job})).await?;
    assert!(legacy.get("question").is_none(), "{legacy}");
    legacy["question"] = Value::Null;
    let (mut a, mut b) = (status.clone(), legacy);
    for v in [&mut a, &mut b] {
        if let Some(map) = v.as_object_mut() {
            map.remove("elapsed_s");
        }
    }
    assert_eq!(a, b, "knx_job_status and knx_apply_status differ");
    let unknown = h
        .call("knx_job_status", json!({"job": "apply-0-1.1.9"}))
        .await?;
    assert_eq!(unknown["refused"], true, "{unknown}");
    h.stop().await
}

/// Issue #289: a reply the client lost is recoverable: `knx_last_apply`
/// returns the job's result in the session, and a restarted server reads it
/// from the record under `.bussard/history`, by address and by job.
#[tokio::test]
async fn test_knx_last_apply_recovers_a_lost_reply_across_a_restart() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;
    let none = h
        .call("knx_last_apply", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(none["found"], false, "{none}");

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest_of(&plan)?}),
        )
        .await?;
    // The mock is fast: the write ends within the reply wait, inline.
    assert_eq!(applied["started"], false, "apply: {applied}");
    assert_eq!(applied["done"], true, "apply: {applied}");
    assert_eq!(applied["ok"], true, "apply: {applied}");
    let job = applied["job"].as_str().unwrap_or_default().to_string();
    assert!(!job.is_empty(), "apply: {applied}");

    // The reply is "lost": the session still has it.
    let last = h
        .call("knx_last_apply", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(last["found"], true, "{last}");
    assert_eq!(last["job"], job.as_str(), "{last}");
    assert_eq!(last["state"], "done", "{last}");
    assert_eq!(last["result"]["verified"], true, "{last}");
    assert_eq!(last["result"]["backup"], applied["backup"], "{last}");

    // A server restart: a fresh session on the same model reads the record.
    let dir = h.dir.path().to_path_buf();
    let connection = ConnectionConfig::tunnel(h.gateway.addr());
    let (client, task) = serve(
        &dir,
        connection,
        Duration::from_secs(600),
        false,
        (None, None),
    )
    .await?;
    let restored = call(&client, "knx_last_apply", json!({"address": "1.1.4"})).await?;
    assert_eq!(restored["found"], true, "{restored}");
    assert_eq!(restored["from_record"], true, "{restored}");
    assert_eq!(restored["job"], job.as_str(), "{restored}");
    assert_eq!(restored["result"]["ok"], true, "{restored}");
    let by_job = call(&client, "knx_apply_status", json!({"job": job})).await?;
    assert_eq!(by_job["state"], "done", "{by_job}");
    let unknown = call(&client, "knx_apply_status", json!({"job": "apply-0-1.1.9"})).await?;
    assert_eq!(unknown["refused"], true, "{unknown}");
    client.cancel().await?;
    task.abort();
    h.stop().await
}

/// Issue #321: a value the file stores for a ref the configuration does not
/// show (the "Wind" threshold while the function is "Helligkeit") is never
/// written, and the plan says so instead of dropping it silently.
#[tokio::test]
async fn test_knx_plan_device_lists_a_value_on_an_unshown_ref_as_ignored() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;
    let app = "M-00FA_A-0321-10-0000";
    let dir = h.dir.path();
    // The product model, written by the importer from this application XML
    // (issue #345): the threshold's `P-2_R-2` under "Helligkeit", its
    // `P-2_R-5` under "Wind".
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KNX xmlns=\"http://knx.org/xml/project/23\">\
         <ManufacturerData><Manufacturer RefId=\"M-00FA\"><ApplicationPrograms>\
         <ApplicationProgram Id=\"{app}\" ApplicationNumber=\"321\" ApplicationVersion=\"16\" \
         MaskVersion=\"MV-07B0\" Name=\"branch test app\" LoadProcedureStyle=\"ProductProcedure\">\
         <Static><ParameterTypes>\
         <ParameterType Id=\"{app}_PT-F\" Name=\"function\"><TypeRestriction Base=\"Value\" SizeInBit=\"4\">\
         <Enumeration Text=\"Helligkeit\" Value=\"1\" Id=\"{app}_PT-F_EN-1\" />\
         <Enumeration Text=\"Wind\" Value=\"3\" Id=\"{app}_PT-F_EN-3\" /></TypeRestriction></ParameterType>\
         <ParameterType Id=\"{app}_PT-L\" Name=\"lux\"><TypeNumber SizeInBit=\"16\" Type=\"unsignedInt\" \
         minInclusive=\"1\" maxInclusive=\"1000\" /></ParameterType></ParameterTypes><Parameters>\
         <Parameter Id=\"{app}_P-1\" Name=\"Function\" Text=\"Funktion des Kanals\" ParameterType=\"{app}_PT-F\" Value=\"1\" />\
         <Parameter Id=\"{app}_P-2\" Name=\"Threshold\" Text=\"Schwelle\" ParameterType=\"{app}_PT-L\" Value=\"200\" />\
         </Parameters><ParameterRefs>\
         <ParameterRef Id=\"{app}_P-1_R-1\" RefId=\"{app}_P-1\" />\
         <ParameterRef Id=\"{app}_P-2_R-2\" RefId=\"{app}_P-2\" />\
         <ParameterRef Id=\"{app}_P-2_R-5\" RefId=\"{app}_P-2\" /></ParameterRefs>\
         <LoadProcedures><LoadProcedure><LdCtrlConnect /><LdCtrlDisconnect /></LoadProcedure></LoadProcedures>\
         </Static><Dynamic><ParameterBlock Id=\"{app}_PB-1\" Text=\"Funktion\">\
         <ParameterRefRef RefId=\"{app}_P-1_R-1\" /><choose ParamRefId=\"{app}_P-1_R-1\">\
         <when test=\"1\"><ParameterRefRef RefId=\"{app}_P-2_R-2\" /></when>\
         <when test=\"3\"><ParameterRefRef RefId=\"{app}_P-2_R-5\" /></when></choose>\
         </ParameterBlock></Dynamic></ApplicationProgram></ApplicationPrograms></Manufacturer>\
         </ManufacturerData></KNX>\n"
    );
    let program = bussard_prod::parse_application_program(app, xml.as_bytes())?;
    let product = bussard_prod::ProductData {
        applications: vec![program.clone()],
        ..bussard_prod::ProductData::default()
    };
    bussard_prod::product_model::write_product_models(&product, dir)?;
    std::fs::write(
        dir.join("bussard.lock"),
        format!(
            "version = 3\n\n[[device]]\naddress = \"1.1.4\"\nproduct = \"TST-1\"\n\
             application = \"{app}\"\nmask = \"07B0\"\nparameters = [\n  \
             {{ key = \"funktion-des-kanals\", ref = \"P-1_R-1\", param = \"P-1\" }},\n  \
             {{ key = \"schwelle\", ref = \"P-2_R-2\", param = \"P-2\" }},\n  \
             {{ key = \"schwelle@P-2_R-5\", ref = \"P-2_R-5\", param = \"P-2\" }},\n]\n"
        ),
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.4.toml"),
        "address = \"1.1.4\"\nname = \"Jalousie Wohnen\"\nproduct = \"TST-1\"\n\n\
         [parameters]\n\"schwelle@P-2_R-5\" = \"500\"\n\n[links]\n\
         20.send = \"1/2/0\"\n21.listen = [\"1/2/1\"]\n22.listen = [\"1/2/2\"]\n",
    )?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let line = "`schwelle@P-2_R-5` = 500 ignored: not shown under the current values (needs \
                Funktion des Kanals = Wind)";
    let notes: Vec<&str> = plan["notes"]
        .as_array()
        .map(|n| n.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(notes.contains(&line), "{plan}");
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(sentences.contains(line), "{sentences}");
    h.stop().await
}

/// A plan for a device the model links, without KNX Data Secure, as sender on
/// a group address a Secure receiver takes secured is refused before the bus
/// is touched (E035, issue #330).
#[tokio::test]
async fn test_knx_plan_device_refuses_plain_sender_on_secured_ga() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir_all(dir.path().join("devices"))?;
    std::fs::write(
        dir.path().join("groups.toml"),
        "groups = [\n  { address = \"1/0/4\", name = \"Licht\", dpt = \"1.001\", secure = true },\n]\n",
    )?;
    std::fs::write(
        dir.path().join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Actuator\"\n\n[links]\nschalten.listen = [\"1/0/4\"]\n",
    )?;
    std::fs::write(
        dir.path().join("devices").join("1.1.202.toml"),
        "address = \"1.1.202\"\nname = \"Weather station\"\n\n[links]\nc18.send = \"1/0/4\"\n",
    )?;
    std::fs::write(
        dir.path().join("bussard.lock"),
        "version = 3\n\n[[device]]\naddress = \"1.1.5\"\nsecure_capable = true\n\
         objects = [\n  { number = 3, key = \"schalten\", dpt = \"1.001\", flags = \"CWU\", secure = true },\n]\n\n\
         [[device]]\naddress = \"1.1.202\"\n\
         objects = [\n  { number = 18, key = \"c18\", dpt = \"1.001\", flags = \"CRT\" },\n]\n",
    )?;
    // Loopback discard port: the refusal comes before any bus access.
    let connection = ConnectionConfig::tunnel(SocketAddrV4::new([127, 0, 0, 1].into(), 9));
    let (client, server_task) = serve(
        dir.path(),
        connection,
        Duration::from_secs(600),
        false,
        (None, None),
    )
    .await?;

    let res = call(&client, "knx_plan_device", json!({"address": "1.1.202"})).await?;
    assert_eq!(res["refused"], true, "{res}");
    let reason = res["reason"].as_str().unwrap_or_default();
    for needle in ["E035", "1.1.202 object 18", "1/0/4", "1.1.5 object 3"] {
        assert!(reason.contains(needle), "{needle}: {reason}");
    }

    client.cancel().await?;
    server_task.abort();
    Ok(())
}

/// Two plans on one tunnel probe the source address once (issue #341): the
/// second reuses the probe that passed on the same, unbroken connection.
#[tokio::test]
async fn test_knx_plan_device_probes_once_per_tunnel() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;

    let first = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(first["ok"], true, "first plan: {first}");
    assert_eq!(h.probes()?, 1, "the first plan probes");

    let second = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(second["ok"], true, "second plan: {second}");
    assert_eq!(
        h.probes()?,
        1,
        "the second plan on the same tunnel does not"
    );
    assert_eq!(h.writes()?, 0, "planning must not write");

    h.stop().await
}

/// A reconnect starts a new tunnel instance, so the next plan probes again.
#[tokio::test]
async fn test_knx_plan_device_probes_again_after_a_reconnect() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;

    let first = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(first["ok"], true, "first plan: {first}");
    assert_eq!(h.probes()?, 1);

    let reconnected = h.call("knx_bus_reconnect", json!({})).await?;
    assert_eq!(reconnected["ok"], true, "reconnect: {reconnected}");
    assert_eq!(reconnected["bus"]["connected"], true, "{reconnected}");

    let second = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(second["ok"], true, "second plan: {second}");
    assert_eq!(h.probes()?, 2, "the plan after a reconnect probes again");

    h.stop().await
}

/// A device answering at the server's own address refuses the first plan,
/// as before issue #341, and the refusal is not remembered as a pass: the
/// next plan probes and refuses again. Nothing is written.
#[tokio::test]
async fn test_knx_plan_device_refuses_an_occupied_source_on_every_call() -> anyhow::Result<()> {
    let occupant = MockDevice::system_b(own_address());
    let h = Harness::start_line(Duration::from_secs(600), None, None, vec![occupant]).await?;

    for attempt in 1..=2 {
        let plan = h
            .call("knx_plan_device", json!({"address": "1.1.4"}))
            .await?;
        assert_eq!(plan["refused"], true, "attempt {attempt}: {plan}");
        let reason = plan["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains(&format!("already answers at {}", own_address())),
            "attempt {attempt}: {reason}"
        );
        assert_eq!(h.probes()?, attempt, "attempt {attempt} probes");
    }
    assert_eq!(h.writes()?, 0, "a refused plan must not write");

    h.stop().await
}

// ---------------------------------------------------------------------------
// The line form (issue #748): `line` on knx_plan_device, knx_apply_device and
// knx_reconstruct_device, through the functions `bussard plan --line`,
// `apply --line` and `reconstruct --line` call.
// ---------------------------------------------------------------------------

/// 1.1.5: already holds its model links (1/3/0 on object 10).
fn unchanged_device() -> anyhow::Result<MockDevice> {
    Ok(MockDevice::system_b("1.1.5".parse()?)
        .with_table(1, &address_table(&["1/3/0"])?)
        .with_table(2, &association_table(&[(1, 10)]))
        .with_go_count(40))
}

/// 1.1.6: holds 1/4/0 on object 30; the model adds 1/4/1 on object 31.
fn changed_device() -> anyhow::Result<MockDevice> {
    Ok(MockDevice::system_b("1.1.6".parse()?)
        .with_table(1, &address_table(&["1/4/0"])?)
        .with_table(2, &association_table(&[(1, 30)]))
        .with_go_count(40))
}

/// Adds 1.1.5 and 1.1.6 to the model next to 1.1.4, with every group they use.
fn write_line_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Licht Flur\"\n\n[links]\n10.listen = [\"1/3/0\"]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.6.toml"),
        "address = \"1.1.6\"\nname = \"Heizung Bad\"\n\n[links]\n\
         30.listen = [\"1/4/0\"]\n31.listen = [\"1/4/1\"]\n",
    )?;
    std::fs::write(
        dir.join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Blind move\" },\n  \
         { address = \"1/2/1\", name = \"Blind stop\" },\n  \
         { address = \"1/2/2\", name = \"Blind position\" },\n  \
         { address = \"1/3/0\", name = \"Flur switch\" },\n  \
         { address = \"1/4/0\", name = \"Bad setpoint\" },\n  \
         { address = \"1/4/1\", name = \"Bad mode\" },\n]\n",
    )?;
    Ok(())
}

/// A server on line 1.1 with three devices: 1.1.4 and 1.1.6 differ from the
/// model, 1.1.5 matches it.
async fn line_harness() -> anyhow::Result<Harness> {
    let h = Harness::start_line(
        Duration::from_secs(600),
        None,
        None,
        vec![unchanged_device()?, changed_device()?],
    )
    .await?;
    write_line_model(h.dir.path())?;
    Ok(h)
}

/// One device's `(address table, association table)` as the mock holds them.
fn tables_of(h: &Harness, ia: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    Ok(h.gateway.with_device(ia.parse()?, |dev| {
        (
            dev.table_image(1).unwrap_or_default(),
            dev.table_image(2).unwrap_or_default(),
        )
    })?)
}

/// How many writes reached one device.
fn writes_of(h: &Harness, ia: &str) -> anyhow::Result<usize> {
    Ok(h.gateway.with_device(ia.parse()?, |dev| dev.writes)?)
}

/// The finished result of a call that may answer `started`.
async fn finished(h: &Harness, answer: Value) -> anyhow::Result<Value> {
    if answer["started"] == true {
        let job = job_of(&answer)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let status = h.call("knx_job_status", json!({"job": job})).await?;
            if status["done"] == true {
                return Ok(status["result"].clone());
            }
            if std::time::Instant::now() > deadline {
                anyhow::bail!("job {job} did not finish: {status}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(answer)
}

/// The row of `ia` in a line result.
fn row<'a>(result: &'a Value, ia: &str) -> anyhow::Result<&'a Value> {
    result["devices"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["address"] == ia))
        .ok_or_else(|| anyhow::anyhow!("no row for {ia} in {result}"))
}

#[tokio::test]
async fn test_knx_apply_device_line_plans_writes_and_verifies_every_device() -> anyhow::Result<()> {
    let h = line_harness().await?;

    let plan = finished(&h, h.call("knx_plan_device", json!({"line": "1.1"})).await?).await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    assert_eq!(plan["line"], "1.1");
    assert_eq!(row(&plan, "1.1.4")?["status"], "changes", "{plan}");
    assert_eq!(row(&plan, "1.1.5")?["status"], "unchanged", "{plan}");
    assert_eq!(row(&plan, "1.1.6")?["status"], "changes", "{plan}");
    assert_eq!(plan["totals"]["changed"], 2, "{plan}");
    let sentences = plan["sentences"].to_string();
    assert!(
        sentences.contains("Heizung Bad object 31 now on 1/4/1 (Bad mode)"),
        "{sentences}"
    );
    assert!(
        plan["question"]
            .as_str()
            .is_some_and(|q| q.contains("2 device(s) on line 1.1"))
    );
    let digest = digest_of(&plan)?;
    for ia in ["1.1.4", "1.1.5", "1.1.6"] {
        assert_eq!(writes_of(&h, ia)?, 0, "planning must not write {ia}");
    }

    let applied = finished(
        &h,
        h.call(
            "knx_apply_device",
            json!({"line": "1.1", "plan_digest": digest}),
        )
        .await?,
    )
    .await?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    let r4 = row(&applied, "1.1.4")?;
    assert_eq!(r4["status"], "applied", "{applied}");
    assert_eq!(r4["verified"], true, "{applied}");
    assert!(
        r4["backup"]
            .as_str()
            .is_some_and(|b| Path::new(b).is_file()),
        "{applied}"
    );
    assert_eq!(row(&applied, "1.1.5")?["status"], "unchanged", "{applied}");
    assert_eq!(row(&applied, "1.1.6")?["status"], "applied", "{applied}");
    assert_eq!(
        writes_of(&h, "1.1.5")?,
        0,
        "an unchanged device is not written"
    );

    // Every device now holds the model's tables.
    assert_eq!(
        tables_of(&h, "1.1.4")?,
        (
            address_table(&["1/2/0", "1/2/1", "1/2/2"])?,
            association_table(&[(1, 20), (2, 21), (3, 22)])
        )
    );
    assert_eq!(
        tables_of(&h, "1.1.6")?,
        (
            address_table(&["1/4/0", "1/4/1"])?,
            association_table(&[(1, 30), (2, 31)])
        )
    );

    // The audit line names the line and the gateway.
    let latest = bussard_model::history::History::open(h.dir.path())
        .latest()?
        .ok_or_else(|| anyhow::anyhow!("no history snapshot recorded"))?;
    assert_eq!(latest.manifest.reason.command, "mcp knx_apply_device");
    assert_eq!(
        latest.manifest.reason.args.get(..2),
        Some(&["--line".to_string(), "1.1".to_string()][..])
    );

    // The digest is single use, and a fresh plan has nothing to do.
    let again = h
        .call(
            "knx_apply_device",
            json!({"line": "1.1", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(again["refused"], true, "{again}");
    let replan = finished(&h, h.call("knx_plan_device", json!({"line": "1.1"})).await?).await?;
    assert_eq!(replan["noop"], true, "{replan}");
    assert!(replan["plan_digest"].is_null(), "{replan}");

    h.stop().await
}

/// The latest history snapshot's result line and its `groups.toml`.
fn latest_snapshot(dir: &Path) -> anyhow::Result<(String, String)> {
    let history = bussard_model::history::History::open(dir);
    let latest = history
        .latest()?
        .ok_or_else(|| anyhow::anyhow!("no history snapshot recorded"))?;
    let groups = std::fs::read_to_string(history.snapshot_dir(&latest.id).join("groups.toml"))?;
    Ok((latest.manifest.result, groups))
}

#[tokio::test]
async fn test_knx_apply_device_declares_an_undeclared_group_address() -> anyhow::Result<()> {
    let h = Harness::start_full(Duration::from_secs(600), (None, None), Vec::new(), false).await?;
    // 1/2/2 is linked by object 22 but groups.toml does not define it.
    std::fs::write(
        h.dir.path().join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Blind move\" },\n  \
         { address = \"1/2/1\", name = \"Blind stop\" },\n]\n",
    )?;
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let digest = digest_of(&plan)?;

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    let declared = applied["declared"].to_string();
    assert!(
        declared.contains("added 1/2/2") && declared.contains("first used by 1.1.4 object 22"),
        "{applied}"
    );
    assert!(
        applied["next_step"]
            .as_str()
            .is_some_and(|n| n.contains("result.declared")),
        "{applied}"
    );
    let groups = std::fs::read_to_string(h.dir.path().join("groups.toml"))?;
    assert!(groups.contains("1/2/2"), "{groups}");
    // The audit snapshot names the addition and holds the declared file.
    let (result, snapshot_groups) = latest_snapshot(h.dir.path())?;
    assert!(result.contains("added 1/2/2"), "{result}");
    assert!(snapshot_groups.contains("1/2/2"), "{snapshot_groups}");
    assert_eq!(h.tables()?.0, address_table(&["1/2/0", "1/2/1", "1/2/2"])?);

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_line_declares_an_undeclared_group_address() -> anyhow::Result<()> {
    let h = Harness::start_full(
        Duration::from_secs(600),
        (None, None),
        vec![unchanged_device()?, changed_device()?],
        false,
    )
    .await?;
    write_line_model(h.dir.path())?;
    // 1/4/1 is linked by 1.1.6 object 31 but groups.toml does not define it;
    // `bussard apply --line` declares it, so the MCP form does too.
    std::fs::write(
        h.dir.path().join("groups.toml"),
        "groups = [\n  { address = \"1/2/0\", name = \"Blind move\" },\n  \
         { address = \"1/2/1\", name = \"Blind stop\" },\n  \
         { address = \"1/2/2\", name = \"Blind position\" },\n  \
         { address = \"1/3/0\", name = \"Flur switch\" },\n  \
         { address = \"1/4/0\", name = \"Bad setpoint\" },\n]\n",
    )?;
    let plan = finished(&h, h.call("knx_plan_device", json!({"line": "1.1"})).await?).await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let digest = digest_of(&plan)?;

    let applied = finished(
        &h,
        h.call(
            "knx_apply_device",
            json!({"line": "1.1", "plan_digest": digest}),
        )
        .await?,
    )
    .await?;
    assert_eq!(applied["ok"], true, "apply: {applied}");
    assert_eq!(applied["verified"], true, "apply: {applied}");
    let declared = applied["declared"].to_string();
    assert!(
        declared.contains("added 1/4/1") && declared.contains("first used by 1.1.6 object 31"),
        "{applied}"
    );
    let groups = std::fs::read_to_string(h.dir.path().join("groups.toml"))?;
    assert!(groups.contains("1/4/1"), "{groups}");
    let (result, snapshot_groups) = latest_snapshot(h.dir.path())?;
    assert!(result.contains("added 1/4/1"), "{result}");
    assert!(snapshot_groups.contains("1/4/1"), "{snapshot_groups}");
    assert_eq!(
        tables_of(&h, "1.1.6")?.0,
        address_table(&["1/4/0", "1/4/1"])?
    );

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_line_without_model_edits_leaves_groups_toml_alone()
-> anyhow::Result<()> {
    // `--no-model-edits`: the apply writes nothing to the project, so an
    // undeclared address stays undeclared (validation only warns, E001).
    let h = line_harness().await?;
    let groups = h.dir.path().join("groups.toml");
    let text = std::fs::read_to_string(&groups)?
        .replace("  { address = \"1/4/1\", name = \"Bad mode\" },\n", "");
    assert!(!text.contains("1/4/1"), "{text}");
    std::fs::write(&groups, &text)?;
    let plan = finished(&h, h.call("knx_plan_device", json!({"line": "1.1"})).await?).await?;
    let digest = digest_of(&plan)?;
    let applied = finished(
        &h,
        h.call(
            "knx_apply_device",
            json!({"line": "1.1", "plan_digest": digest}),
        )
        .await?,
    )
    .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["declared"], json!([]), "{applied}");
    assert_eq!(std::fs::read_to_string(&groups)?, text);
    assert_eq!(row(&applied, "1.1.6")?["status"], "applied", "{applied}");

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_line_does_not_write_a_device_that_changed_since_the_plan()
-> anyhow::Result<()> {
    let h = line_harness().await?;
    let plan = finished(&h, h.call("knx_plan_device", json!({"line": "1.1"})).await?).await?;
    let digest = digest_of(&plan)?;

    // Someone rewrites 1.1.6's address table between the plan and the apply.
    let moved = address_table(&["1/4/0", "5/0/0"])?;
    h.gateway
        .with_device("1.1.6".parse()?, |dev| dev.preload_table(1, &moved))?;

    let applied = finished(
        &h,
        h.call(
            "knx_apply_device",
            json!({"line": "1.1", "plan_digest": digest}),
        )
        .await?,
    )
    .await?;
    assert_eq!(applied["ok"], false, "{applied}");
    assert_eq!(applied["verified"], false, "{applied}");
    assert_eq!(row(&applied, "1.1.4")?["status"], "applied", "{applied}");
    let r6 = row(&applied, "1.1.6")?;
    assert_eq!(r6["status"], "failed", "{applied}");
    assert!(
        r6["detail"]
            .as_str()
            .is_some_and(|d| d.contains("changed since the line was planned")),
        "{applied}"
    );
    assert_eq!(
        writes_of(&h, "1.1.6")?,
        0,
        "a moved device must not be written"
    );
    assert_eq!(applied["totals"]["failed"], 1, "{applied}");

    h.stop().await
}

#[tokio::test]
async fn test_knx_apply_device_line_refuses_when_the_model_changed() -> anyhow::Result<()> {
    let h = line_harness().await?;
    let plan = finished(&h, h.call("knx_plan_device", json!({"line": "1.1"})).await?).await?;
    let digest = digest_of(&plan)?;

    std::fs::write(
        h.dir.path().join("devices").join("1.1.6.toml"),
        "address = \"1.1.6\"\nname = \"Heizung Bad\"\n\n[links]\n30.listen = [\"1/4/0\"]\n",
    )?;

    let applied = h
        .call(
            "knx_apply_device",
            json!({"line": "1.1", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["refused"], true, "{applied}");
    assert!(
        applied["reason"]
            .as_str()
            .is_some_and(|r| r.contains("changed since the plan")),
        "{applied}"
    );
    for ia in ["1.1.4", "1.1.5", "1.1.6"] {
        assert_eq!(writes_of(&h, ia)?, 0, "a refused apply must not write {ia}");
    }

    h.stop().await
}

#[tokio::test]
async fn test_knx_plan_device_refuses_address_and_line_together() -> anyhow::Result<()> {
    let h = line_harness().await?;
    let both = h
        .call(
            "knx_plan_device",
            json!({"address": "1.1.4", "line": "1.1"}),
        )
        .await?;
    assert_eq!(both["refused"], true, "{both}");
    let neither = h.call("knx_plan_device", json!({})).await?;
    assert_eq!(neither["refused"], true, "{neither}");
    let empty_line = h.call("knx_plan_device", json!({"line": "2.3"})).await?;
    assert_eq!(empty_line["refused"], true, "{empty_line}");
    assert!(
        empty_line["reason"]
            .as_str()
            .is_some_and(|r| r.contains("no devices on line 2.3")),
        "{empty_line}"
    );
    h.stop().await
}

#[tokio::test]
async fn test_knx_reconstruct_device_line_synthesizes_a_fresh_model() -> anyhow::Result<()> {
    let h = line_harness().await?;
    let result = finished(
        &h,
        h.call(
            "knx_reconstruct_device",
            json!({"line": "1.1", "from": 4, "to": 7, "out": "recon"}),
        )
        .await?,
    )
    .await?;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["devices_found"], 3, "{result}");
    assert_eq!(result["devices_read"], 3, "{result}");
    let out = h.dir.path().join("recon");
    let groups = std::fs::read_to_string(out.join("groups.toml"))?;
    assert!(groups.contains("RECONSTRUCTED"), "{groups}");
    assert!(groups.contains("1/4/0"), "{groups}");
    assert!(out.join("devices").join("1.1.6.toml").is_file());
    let rebuilt = bussard_model::Model::load(&out)?;
    assert_eq!(rebuilt.devices.len(), 3);
    for ia in ["1.1.4", "1.1.5", "1.1.6"] {
        assert_eq!(writes_of(&h, ia)?, 0, "reconstruct is read-only on the bus");
    }

    // A non-empty or escaping `out` is refused before the bus is touched.
    let again = h
        .call(
            "knx_reconstruct_device",
            json!({"line": "1.1", "from": 4, "to": 4, "out": "recon"}),
        )
        .await?;
    assert_eq!(again["refused"], true, "{again}");
    let escape = h
        .call(
            "knx_reconstruct_device",
            json!({"line": "1.1", "out": "../elsewhere"}),
        )
        .await?;
    assert_eq!(escape["refused"], true, "{escape}");

    h.stop().await
}

/// The ids a homeowner should not have to read (issue #306) in `text`: group
/// addresses (`1/2/3`), individual addresses (`1.1.4`), ETS references
/// (`MD-…`) and parameter keys (`key@ref`).
fn ids_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in text.split(|c: char| c.is_whitespace() || "(),;:\"`{}[]".contains(c)) {
        let word = word.trim_end_matches('.');
        let three = |sep: char| {
            let p: Vec<&str> = word.split(sep).collect();
            p.len() == 3
                && p.iter()
                    .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        };
        if three('/') || three('.') || word.contains("MD-") || word.contains('@') {
            out.push(word.to_string());
        }
    }
    out
}

/// `knx_plan_device` and `knx_apply_device` speak to the homeowner in names
/// (issue #306): the plan's `summary` and `what_you_will_notice` and the
/// apply's `summary` carry no id but the one group address the model has no
/// name for, and the plan keeps its sentences, digest and question.
#[tokio::test]
async fn test_knx_plan_device_summary_and_notice_speak_in_names() -> anyhow::Result<()> {
    let h = Harness::start(Duration::from_secs(600)).await?;
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(plan["ok"], true, "plan: {plan}");
    let summary = plan["summary"].as_str().unwrap_or_default();
    assert!(summary.contains("Jalousie Wohnen"), "{summary}");
    assert!(summary.contains("Blind position"), "{summary}");
    let notice = &plan["what_you_will_notice"];
    assert_eq!(notice["device"], "Jalousie Wohnen", "{notice}");
    assert!(notice["takes"].is_string(), "{notice}");
    assert!(
        notice["meanwhile"]
            .as_str()
            .is_some_and(|m| m.contains("keep working")),
        "{notice}"
    );
    let to_test = notice["to_test"].as_array().cloned().unwrap_or_default();
    assert!(
        to_test
            .iter()
            .any(|t| t.as_str().is_some_and(|t| t.contains("Blind position"))),
        "{notice}"
    );
    // 4/2/12 is the one address groups.toml does not name: it may stay.
    for text in [summary.to_string(), notice.to_string()] {
        let ids: Vec<String> = ids_in(&text)
            .into_iter()
            .filter(|id| id != "4/2/12")
            .collect();
        assert!(ids.is_empty(), "ids {ids:?} in {text}");
    }
    // What the integrator and the explicit-yes rule rely on is unchanged.
    assert!(plan["sentences"].is_string(), "{plan}");
    assert!(plan["question"].is_string(), "{plan}");
    let digest = digest_of(&plan)?;

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.4", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["verified"], true, "apply: {applied}");
    let summary = applied["summary"].as_str().unwrap_or_default();
    assert!(summary.contains("Jalousie Wohnen"), "{summary}");
    assert!(summary.contains("checked"), "{summary}");
    assert!(ids_in(summary).is_empty(), "{summary}");
    // The backup path stays in the payload.
    assert!(applied["backup"].is_string(), "{applied}");

    let last = h
        .call("knx_last_apply", json!({"address": "1.1.4"}))
        .await?;
    let summary = last["summary"].as_str().unwrap_or_default();
    assert!(summary.contains("checked"), "{last}");
    assert!(ids_in(summary).is_empty(), "{summary}");
    // The one job table's status tool speaks the same way (#746).
    let job = last["job"].as_str().unwrap_or_default().to_string();
    let status = h.call("knx_job_status", json!({"job": job})).await?;
    let summary = status["summary"].as_str().unwrap_or_default();
    assert!(summary.contains("checked"), "{status}");
    assert!(ids_in(summary).is_empty(), "{summary}");

    let replan = h
        .call("knx_plan_device", json!({"address": "1.1.4"}))
        .await?;
    assert_eq!(
        replan["summary"], "Jalousie Wohnen already matches your project; nothing to write.",
        "{replan}"
    );
    h.stop().await
}
