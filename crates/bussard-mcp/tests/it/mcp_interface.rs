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
use std::sync::{Arc, Mutex};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientConfig, ElicitRequestParams,
    ElicitResult, ElicitationAction, ElicitationCapability, FormElicitationCapability,
    Implementation, InputRequest, ProtocolVersion, RequestMetaObject,
};
use rmcp::service::RequestContext;
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::{Value, json};

const CHANNEL: u8 = 0x56;

/// The mock interface at 1.1.200: DHCP at `ip`, tunnels 1.1.22 to 1.1.29,
/// "Demohouse Alpha", writable.
fn interface(ip: [u8; 4]) -> anyhow::Result<MockDevice> {
    let knxnet = MockKnxnet {
        tunnels: (22..=29)
            .map(|n| format!("1.1.{n}").parse())
            .collect::<Result<Vec<IndividualAddress>, _>>()?,
        friendly_name: "Demohouse Alpha".to_string(),
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
         assignment = \"dhcp\"\nfriendly_name = \"Demohouse Alpha\"\n\
         tunnels = [\"1.1.22\", \"1.1.23\", \"1.1.24\", \"1.1.25\", \"1.1.26\", \"1.1.27\", \
         \"1.1.28\", \"1.1.29\"]\n",
    )?;
    std::fs::write(
        dir.join("devices").join("1.1.5.toml"),
        "address = \"1.1.5\"\nname = \"Aktor\"\n",
    )?;
    Ok(())
}

struct Harness<H: ClientHandler = ()> {
    client: rmcp::service::RunningService<rmcp::RoleClient, H>,
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
        Harness::start_with(ip, remote, ()).await
    }
}

impl<H: ClientHandler> Harness<H> {
    /// [`Harness::start_on`] with `client` as the chat app.
    async fn start_with(ip: [u8; 4], remote: bool, client: H) -> anyhow::Result<Harness<H>> {
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
        let client = client.serve(client_io).await?;
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
    let h = Harness::start([192, 0, 2, 74]).await?;

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
                "friendly_name": "Demohouse Beta",
                "add_tunnels": ["1.1.30"],
                "remove_tunnels": ["1.1.29"],
            }),
        )
        .await?;
    assert_eq!(edit["ok"], true, "{edit}");
    let file = h.device_file()?;
    assert!(
        file.contains("friendly_name = \"Demohouse Beta\""),
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
        sentences.contains("~ friendly name = \"Demohouse Beta\", was \"Demohouse Alpha\""),
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
        Some(&b"Demohouse Beta"[..])
    );

    let again = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    assert_eq!(again["noop"], true, "{again}");
    h.stop().await
}

#[tokio::test]
async fn test_knx_set_interface_refuses_an_invalid_table() -> anyhow::Result<()> {
    let h = Harness::start([192, 0, 2, 74]).await?;
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
    let h = Harness::start([192, 0, 2, 74]).await?;
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

/// An IP interface's KNXnet/IP parameter object is gated by the
/// supported-device list like every device write (#1093): on a real gateway
/// an interface whose application is not on the list is refused, nothing is
/// written, the digest stays valid, and the override writes it.
#[tokio::test]
async fn test_knx_apply_device_refuses_an_unsupported_interface_then_forces_it()
-> anyhow::Result<()> {
    let h = Harness::start_on([192, 168, 1, 74], true).await?;
    let digest = plan_name_change(&h).await?;
    let refused = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.200", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(refused["code"], "unsupported_device", "{refused}");
    assert_eq!(refused["override"], "allow_unsupported: true", "{refused}");
    assert_eq!(h.device(|d| d.writes)?, 0, "nothing written");
    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.200", "plan_digest": digest, "allow_unsupported": true}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["support"], "forced", "{applied}");
    assert_eq!(friendly_name(&h)?, "Demohouse Gamma");
    h.stop().await
}

/// Edits the interface's name and plans it; the plan reports the interface
/// unsupported. Returns the digest.
async fn plan_name_change<H: ClientHandler>(h: &Harness<H>) -> anyhow::Result<String> {
    let edit = h
        .call(
            "knx_set_interface",
            json!({"address": "1.1.200", "friendly_name": "Demohouse Gamma"}),
        )
        .await?;
    assert_eq!(edit["ok"], true, "{edit}");
    let plan = h
        .call("knx_plan_device", json!({"address": "1.1.200"}))
        .await?;
    assert_eq!(plan["support"]["status"], "unsupported", "{plan}");
    assert_eq!(plan["support"]["override_needed"], true, "{plan}");
    Ok(plan["plan_digest"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no digest: {plan}"))?
        .to_string())
}

/// The friendly name the mock interface holds (PID 76).
fn friendly_name<H: ClientHandler>(h: &Harness<H>) -> anyhow::Result<String> {
    let name = h.device(|d| d.knxnet_property(76).map(<[u8]>::to_vec))?;
    Ok(bussard_mgmt::knxnet::decode_friendly_name(
        &name.unwrap_or_default(),
    ))
}

/// The chat app with its human (#1093): declares form-mode elicitation and
/// answers bussard's question with `action`, recording each question.
#[derive(Clone)]
struct Human {
    action: ElicitationAction,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Human {
    fn new(action: ElicitationAction) -> Self {
        Human {
            action,
            asked: Arc::default(),
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().map(|a| a.clone()).unwrap_or_default()
    }

    fn capabilities(&self) -> ClientCapabilities {
        let mut capabilities = ClientCapabilities::default();
        capabilities.elicitation =
            Some(ElicitationCapability::new().with_form(FormElicitationCapability::new()));
        capabilities
    }

    fn answer(&self, request: ElicitRequestParams) -> ElicitResult {
        if let ElicitRequestParams::FormElicitationParams { message, .. } = request
            && let Ok(mut asked) = self.asked.lock()
        {
            asked.push(message);
        }
        ElicitResult::new(self.action.clone())
    }
}

impl ClientHandler for Human {
    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        Ok(self.answer(request))
    }

    fn get_info(&self) -> ClientConfig {
        ClientConfig::new(
            self.capabilities(),
            Implementation::new("fake-chat", "0.0.0"),
        )
    }
}

/// With elicitation the human answers bussard's own question (#1093): a yes
/// writes the interface without `allow_unsupported`.
#[tokio::test]
async fn test_knx_apply_device_asks_the_human_and_writes_on_yes() -> anyhow::Result<()> {
    let human = Human::new(ElicitationAction::Accept);
    let h = Harness::start_with([192, 168, 1, 74], true, human.clone()).await?;
    let digest = plan_name_change(&h).await?;
    let applied = h
        .call(
            "knx_apply_device",
            json!({"address": "1.1.200", "plan_digest": digest}),
        )
        .await?;
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(applied["support"], "forced", "{applied}");
    let asked = human.asked();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(
        asked[0].contains("not on bussard's list of supported devices")
            && asked[0].ends_with("Write anyway?"),
        "{asked:?}"
    );
    assert_eq!(friendly_name(&h)?, "Demohouse Gamma");
    h.stop().await
}

/// With elicitation the assistant cannot answer for the human (#1093): a
/// declined question refuses although the assistant passed
/// `allow_unsupported: true`; nothing is written and the digest is kept.
#[tokio::test]
async fn test_knx_apply_device_refuses_when_the_human_declines() -> anyhow::Result<()> {
    let human = Human::new(ElicitationAction::Decline);
    let h = Harness::start_with([192, 168, 1, 74], true, human.clone()).await?;
    let digest = plan_name_change(&h).await?;
    for _ in 0..2 {
        let refused = h
            .call(
                "knx_apply_device",
                json!({"address": "1.1.200", "plan_digest": digest, "allow_unsupported": true}),
            )
            .await?;
        assert_eq!(refused["code"], "unsupported_device", "{refused}");
        assert!(refused["override"].is_null(), "{refused}");
        let reason = refused["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("The human declined") && reason.contains("stays valid"),
            "{refused}"
        );
    }
    // The digest stayed valid: the second call asked again.
    assert_eq!(human.asked().len(), 2);
    assert_eq!(h.device(|d| d.writes)?, 0, "nothing written");
    h.stop().await
}

/// The `_meta` of a request from a client speaking protocol 2026-07-28.
fn meta_2026(human: &Human) -> RequestMetaObject {
    let mut meta = RequestMetaObject::default();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    meta.set_client_info(Implementation::new("fake-chat", "0.0.0"));
    meta.set_client_capabilities(human.capabilities());
    meta
}

/// From protocol 2026-07-28 the question travels as an `InputRequiredResult`
/// and the client calls again with the human's answer (#1093); the answer
/// counts once, for the write it was asked for.
#[tokio::test]
async fn test_knx_apply_device_asks_over_multi_round_trip() -> anyhow::Result<()> {
    let human = Human::new(ElicitationAction::Accept);
    let h = Harness::start_with([192, 168, 1, 74], true, human.clone()).await?;
    let digest = plan_name_change(&h).await?;
    let mut args = serde_json::Map::new();
    args.insert("address".to_string(), json!("1.1.200"));
    args.insert("plan_digest".to_string(), json!(digest));
    let mut params = CallToolRequestParams::new("knx_apply_device").with_arguments(args.clone());
    params.meta = Some(meta_2026(&human));
    let first = h.client.call_tool_once(params).await?;
    let CallToolResponse::InputRequired(input) = first else {
        anyhow::bail!("expected input_required, got {first:?}");
    };
    assert!(
        human.asked().is_empty(),
        "the server sent no request itself"
    );
    assert_eq!(h.device(|d| d.writes)?, 0, "nothing written yet");
    let state = input
        .request_state
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no request state"))?;
    let mut responses = rmcp::model::InputResponses::new();
    for (key, request) in input
        .input_requests
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no input requests"))?
    {
        let InputRequest::Elicitation(request) = request else {
            anyhow::bail!("not an elicitation");
        };
        responses.insert(key, serde_json::to_value(human.answer(request.params))?);
    }
    let mut params = CallToolRequestParams::new("knx_apply_device")
        .with_arguments(args)
        .with_input_responses(responses)
        .with_request_state(state);
    params.meta = Some(meta_2026(&human));
    let second = h.client.call_tool_once(params).await?;
    let CallToolResponse::Complete(result) = second else {
        anyhow::bail!("expected a result, got {second:?}");
    };
    let value = result
        .structured_content
        .ok_or_else(|| anyhow::anyhow!("no structured content"))?;
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(value["support"], "forced", "{value}");
    assert_eq!(friendly_name(&h)?, "Demohouse Gamma");
    h.stop().await
}
