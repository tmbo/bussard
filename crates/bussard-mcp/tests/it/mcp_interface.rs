//! The MCP side of the KNX IP interface write (issue #391, sub-task b):
//! `knx_set_interface` edits the `[knxnet]` table with validation, and
//! `knx_plan_device` / `knx_apply_device` plan and write it to a mock
//! interface's KNXnet/IP parameter object through the same service functions
//! as `bussard plan` / `bussard apply`, refusing a change to the interface the
//! server tunnels through.
//!
//! The mock binds `127.0.0.1:0`; no test here reaches a real gateway.

use std::path::Path;
use std::time::Duration;

use bussard_mcp::McpConfig;
use bussard_model::IndividualAddress;
use bussard_testkit::{MockDevice, MockGateway, MockKnxnet};
use bussard_transport::ConnectionConfig;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::{Value, json};

const CHANNEL: u8 = 0x56;

/// The mock interface at 1.1.200: DHCP at `ip`, tunnels 1.1.22 to 1.1.29,
/// "Bocklisch Alpha", writable.
fn interface(ip: [u8; 4]) -> anyhow::Result<MockDevice> {
    let knxnet = MockKnxnet {
        tunnels: (22..=29)
            .map(|n| format!("1.1.{n}").parse())
            .collect::<Result<Vec<IndividualAddress>, _>>()?,
        friendly_name: "Bocklisch Alpha".to_string(),
        current: [ip, [255, 255, 255, 0], [192, 168, 1, 1]],
        ..MockKnxnet::default()
    };
    Ok(MockDevice::new("1.1.200".parse()?)
        .with_mask(0x0021)
        .with_knxnet_writable(&knxnet, 8))
}

fn write_model(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("devices"))?;
    std::fs::write(
        dir.join("devices").join("1.1.200.toml"),
        "address = \"1.1.200\"\nname = \"KNX IP Interface\"\n\n[knxnet]\n\
         assignment = \"dhcp\"\nfriendly_name = \"Bocklisch Alpha\"\n\
         tunnels = [\"1.1.22\", \"1.1.23\", \"1.1.24\", \"1.1.25\", \"1.1.26\", \"1.1.27\", \
         \"1.1.28\", \"1.1.29\"]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Aktor\"\n",
    )?;
    Ok(())
}

struct Harness {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    server_task: tokio::task::JoinHandle<()>,
    gateway: MockGateway,
    dir: tempfile::TempDir,
}

impl Harness {
    async fn start(ip: [u8; 4]) -> anyhow::Result<Harness> {
        Harness::start_on(ip, false).await
    }

    /// [`Harness::start`]; with `remote` the programming tier believes it
    /// writes through the non-loopback `192.0.2.10:3671` (opted in) while its
    /// bus is wired to the loopback mock, so no real gateway is contacted.
    async fn start_on(ip: [u8; 4], remote: bool) -> anyhow::Result<Harness> {
        let gateway = MockGateway::builder()
            .channel(CHANNEL)
            .keep_serving()
            .idle_timeout(Duration::from_secs(60))
            .device(interface(ip)?)
            .start()
            .await?;
        let dir = tempfile::tempdir()?;
        write_model(dir.path())?;
        // SAFETY: nextest runs each test in its own process; read when a
        // management connection or probe is set up.
        unsafe {
            std::env::set_var(bussard_mgmt::MGMT_TIMEOUT_MS_ENV, "300");
            std::env::set_var(bussard_mgmt::probe::ADDRESS_PROBE_MS_ENV, "200");
        }
        let connection = ConnectionConfig::tunnel(gateway.addr());
        let tier_connection = if remote {
            ConnectionConfig::tunnel(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(192, 0, 2, 10),
                3671,
            ))
        } else {
            connection.clone()
        };
        let config = McpConfig {
            dir: dir.path().to_path_buf(),
            connection: tier_connection,
            passive: false,
            allow_writes: false,
            no_model_edits: false,
            capture_db: None,
            allow_programming: true,
            allow_remote_gateway: remote,
            plan_ttl: Duration::from_secs(600),
            keyring: None,
            allow_home_assistant: false,
            viz_listen: None,
        };
        let state = bussard_mcp::build_state(&config)?;
        let service = bussard_service::BusService::open(
            connection,
            bussard_service::WritePolicy::transmit(false),
        )?;
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
            Duration::from_secs(30),
            self.client
                .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(map)),
        )
        .await??;
        res.structured_content
            .ok_or_else(|| anyhow::anyhow!("{tool} returned no structured content"))
    }

    fn device<R>(&self, f: impl FnOnce(&MockDevice) -> R) -> anyhow::Result<R> {
        Ok(self.gateway.with_device("1.1.200".parse()?, |dev| f(dev))?)
    }

    fn device_file(&self) -> anyhow::Result<String> {
        Ok(std::fs::read_to_string(
            self.dir.path().join("devices").join("1.1.200.toml"),
        )?)
    }

    async fn stop(self) -> anyhow::Result<()> {
        self.client.cancel().await?;
        self.server_task.abort();
        drop(self.gateway);
        Ok(())
    }
}

#[tokio::test]
async fn test_knx_set_interface_then_plan_and_apply_round_trip() -> anyhow::Result<()> {
    let h = Harness::start([192, 168, 1, 74]).await?;

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    assert_eq!(plan["ok"], true, "{plan}");
    assert_eq!(
        plan["noop"], true,
        "the model matches the interface: {plan}"
    );

    let edit = h
        .call(
            "knx_set_interface",
            json!({
                "address": "1.1.200",
                "friendly_name": "Bocklisch Beta",
                "add_tunnels": ["1.1.30"],
                "remove_tunnels": ["1.1.29"],
            }),
        )
        .await?;
    assert_eq!(edit["ok"], true, "{edit}");
    let file = h.device_file()?;
    assert!(
        file.contains("friendly_name = \"Bocklisch Beta\""),
        "{file}"
    );
    assert!(file.contains("\"1.1.30\""), "{file}");
    assert!(!file.contains("\"1.1.29\""), "{file}");

    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    assert_eq!(plan["ok"], true, "{plan}");
    assert_eq!(plan["noop"], false);
    let sentences = plan["sentences"].as_str().unwrap_or_default();
    assert!(
        sentences.contains("~ friendly name = \"Bocklisch Beta\", was \"Bocklisch Alpha\""),
        "{sentences}"
    );
    assert!(
        sentences.contains("+ tunnel address 1.1.30 added"),
        "{sentences}"
    );
    assert_eq!(h.device(|d| d.writes)?, 0, "planning writes nothing");
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no digest: {plan}"))?
        .to_string();

    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.200", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["verified"], true, "{applied}");
    assert_eq!(applied["properties_written"], 2, "{applied}");
    let name = h.device(|d| d.knxnet_property(76).map(<[u8]>::to_vec))?;
    assert_eq!(
        name.as_deref().and_then(|n| n.get(..14)),
        Some(&b"Bocklisch Beta"[..])
    );

    let again = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    assert_eq!(again["noop"], true, "{again}");
    h.stop().await
}

#[tokio::test]
async fn test_knx_set_interface_refuses_an_invalid_table() -> anyhow::Result<()> {
    let h = Harness::start([192, 168, 1, 74]).await?;
    let before = h.device_file()?;
    for (args, needle) in [
        (
            json!({"address": "1.1.200", "assignment": "static"}),
            "E043",
        ),
        (
            json!({"address": "1.1.200", "add_tunnels": ["1.2.30"]}),
            "E045",
        ),
        (
            json!({"address": "1.1.200", "add_tunnels": ["1.1.5"]}),
            "E046",
        ),
        (
            json!({"address": "1.1.200", "friendly_name": "x".repeat(31)}),
            "E043",
        ),
        (
            json!({"address": "1.1.5", "friendly_name": "Alpha"}),
            "no [knxnet] table",
        ),
    ] {
        let res = h.call("knx_set_interface", args.clone()).await?;
        assert_eq!(res["ok"], false, "{args}: {res}");
        let reason = res["reason"].as_str().unwrap_or_default();
        assert!(reason.contains(needle), "{args}: {reason}");
    }
    assert_eq!(h.device_file()?, before, "a refused edit writes nothing");
    h.stop().await
}

#[tokio::test]
async fn test_knx_plan_device_refuses_to_reconfigure_its_own_interface() -> anyhow::Result<()> {
    // The interface is the gateway the server tunnels through.
    let h = Harness::start([127, 0, 0, 1]).await?;
    let edit = h
        .call(
            "knx_set_interface",
            json!({
                "address": "1.1.200",
                "assignment": "static",
                "ip_address": "192.168.1.80",
                "netmask": "255.255.255.0",
            }),
        )
        .await?;
    assert_eq!(edit["ok"], true, "{edit}");
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    assert_ne!(plan["ok"], true, "{plan}");
    let reason = plan["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("the tunnel drops"), "{reason}");
    assert!(reason.contains("--allow-self-reconfigure"), "{reason}");
    assert!(plan["plan_digest"].is_null());
    assert_eq!(h.device(|d| d.writes)?, 0);
    h.stop().await
}

/// `knx_interface_secure` (issue #398): without a digest it returns the
/// steps, the generated credentials (names only) and a digest; a wrong
/// digest is refused; without a key store the call is refused.
#[tokio::test]
async fn test_knx_interface_secure_plans_and_checks_the_digest() -> anyhow::Result<()> {
    let h = Harness::start([192, 168, 1, 74]).await?;
    // SAFETY: nextest runs each test in its own process.
    unsafe {
        std::env::set_var("BUSSARD_KEYRING_PASSWORD", "synthetic-store-password");
    }
    let refused = h
        .call(
            "knx_interface_secure",
            json!({"address": "1.1.200", "state": "on"}),
        )
        .await?;
    assert_eq!(refused["refused"], true, "{refused}");
    assert!(
        refused["reason"]
            .as_str()
            .unwrap_or("")
            .contains("no key store"),
        "{refused}"
    );

    let mut store = bussard_project::KeyStore::new("Synthetic");
    store.devices.insert(
        "1.1.200".parse()?,
        bussard_project::keystore::StoreDevice {
            fdsk: Some(bussard_secure::Key16::new([0x24; 16])),
            ..bussard_project::keystore::StoreDevice::default()
        },
    );
    store.save(h.dir.path(), "synthetic-store-password")?;
    let plan = h
        .call(
            "knx_interface_secure",
            json!({"address": "1.1.200", "state": "on"}),
        )
        .await?;
    assert_eq!(plan["ok"], true, "{plan}");
    assert_eq!(plan["steps"].as_array().map(Vec::len), Some(10), "{plan}");
    assert_eq!(
        plan["generated"].as_array().map(Vec::len),
        Some(11),
        "tool key, code, management password, 8 users: {plan}"
    );
    let digest = plan["plan_digest"].as_str().unwrap_or("").to_string();
    assert_eq!(digest.len(), 16, "{plan}");
    let text = plan.to_string();
    assert!(
        !text.contains("2424"),
        "no key material in the plan: {text}"
    );

    let wrong = h
        .call(
            "knx_interface_secure",
            json!({"address": "1.1.200", "state": "on", "plan_digest": "0000000000000000"}),
        )
        .await?;
    assert_eq!(wrong["refused"], true, "{wrong}");
    assert!(
        wrong["reason"]
            .as_str()
            .unwrap_or("")
            .contains("does not match"),
        "{wrong}"
    );
    // Nothing was written: the store still has no tool key.
    let store = bussard_project::KeyStore::load(h.dir.path(), "synthetic-store-password")?
        .ok_or_else(|| anyhow::anyhow!("no key store"))?;
    assert!(store.devices[&"1.1.200".parse()?].tool_key.is_none());
    h.stop().await
}

/// An IP interface's KNXnet/IP parameter object is not gated by the
/// supported-device list in this version (#1093): on a real gateway its
/// write goes through although its application is not on the list, as
/// `bussard apply` does.
#[tokio::test]
async fn test_knx_apply_device_writes_an_interface_on_a_real_gateway_ungated() -> anyhow::Result<()>
{
    let h = Harness::start_on([192, 168, 1, 74], true).await?;
    let edit = h
        .call(
            "knx_set_interface",
            json!({"address": "1.1.200", "friendly_name": "Bocklisch Beta"}),
        )
        .await?;
    assert_eq!(edit["ok"], true, "{edit}");
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    let digest = plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no digest: {plan}"))?
        .to_string();
    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.200", "plan_digest": digest}),
        )
        .await?;
    assert!(applied["code"].is_null(), "{applied}");
    assert_eq!(applied["ok"], true, "{applied}");
    h.stop().await
}
